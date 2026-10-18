#!/usr/bin/env python3
"""
sync_files.py - Smart incremental file sync: remote Windows server (UNC share) -> this server's drive.

Features
  - Folder mappings, with {Token} wildcards that auto-discover source folders and map them to target folders
      "Source": "\\\\SRV-OLD01\\D$\\Data\\{Dept}\\Reports"  ->  "Target": "E:\\Reports\\{Dept}"
  - Optional regex PathRules to reshape the target layout (e.g. 20260115_x.csv -> 2026\\01\\x.csv)
  - Change tracking through a per-mapping state manifest (size + last-write time, optional SHA256)
  - Detects New / Modified / Repair (target drifted) / Relocate (rules changed) / Deleted
  - Adopts files already at the target (same size + time) without recopying them
  - Before every copy, checks whether the target already matches the source and skips it if so
      CompareMode: Content = same size and (same time or same SHA256)
                   Version = exe/dll file version (Windows), content check for other files
                   None    = always copy when the source changed
  - Existing target files are never written over: renamed to <name>.old_<RunId>, then the source copy
    lands as a brand-new file (inherits the target folder's permissions). KeepReplacedFiles=false removes
    the renamed file afterwards when permitted.
  - Copy goes to <name>.synctmp first, so the target never holds a partial file
  - Retries locked files, skips files still being written (MinFileAgeSeconds)
  - Safe deletes: only files this tool copied, never after an incomplete scan, capped by MaxDeletePercent
  - Parallel copies (Workers), long-path support, dry run, single-instance lock,
    run log + change audit CSV, checkpointed state, exit codes for schedulers

Usage
  python sync_files.py --config D:\\FileSync\\sync-config.json --dry-run
  python sync_files.py --config D:\\FileSync\\sync-config.json
  python sync_files.py --config D:\\FileSync\\sync-config.json --only Finance DeptReports
  python sync_files.py --config D:\\FileSync\\sync-config.json --allow-mass-delete

Exit codes
  0 = success
  1 = completed, but some files failed (retried automatically next run)
  2 = fatal: bad config, already running, or a whole mapping failed (source unreachable)

Requires Python 3.8+ and nothing outside the standard library.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import stat
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

IS_WINDOWS = os.name == "nt"
SEP = "\\" if IS_WINDOWS else "/"
TIME_TOLERANCE_NS = 2 * 1_000_000_000          # FAT/SMB timestamps can differ by up to 2s
STATE_COLUMNS = ["Rel", "TargetRel", "Size", "MTime", "Hash", "SyncedUtc"]

RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
log = logging.getLogger("filesync")


# =====================================================================================
# Settings
# =====================================================================================
DEFAULTS = {
    "Include": ["*"],
    "Exclude": [],
    "ExcludeDirs": [],
    "PathRules": [],
    "DeleteMode": "None",          # None | Archive | Mirror
    "MinFileAgeSeconds": 60,
    "VerifyHash": False,
    "VerifyTarget": True,
    "RetryCount": 3,
    "RetryDelaySeconds": 5,
    "MaxDeletePercent": 20,
    "CheckpointEvery": 500,
    "KeepReplacedFiles": True,
    "CompareMode": "Content",      # Content | Version | None
    "Workers": 4,
}


@dataclass
class Settings:
    Include: List[str]
    Exclude: List[str]
    ExcludeDirs: List[str]
    PathRules: List[dict]
    DeleteMode: str
    MinFileAgeSeconds: int
    VerifyHash: bool
    VerifyTarget: bool
    RetryCount: int
    RetryDelaySeconds: int
    MaxDeletePercent: float
    CheckpointEvery: int
    KeepReplacedFiles: bool
    CompareMode: str
    Workers: int

    @classmethod
    def build(cls, mapping: dict, defaults: dict) -> "Settings":
        def get(name):
            if name in mapping:
                return mapping[name]
            if name in defaults:
                return defaults[name]
            return DEFAULTS[name]

        s = cls(
            Include=list(get("Include")), Exclude=list(get("Exclude")),
            ExcludeDirs=list(get("ExcludeDirs")), PathRules=list(get("PathRules")),
            DeleteMode=str(get("DeleteMode")), MinFileAgeSeconds=int(get("MinFileAgeSeconds")),
            VerifyHash=bool(get("VerifyHash")), VerifyTarget=bool(get("VerifyTarget")),
            RetryCount=max(1, int(get("RetryCount"))), RetryDelaySeconds=int(get("RetryDelaySeconds")),
            MaxDeletePercent=float(get("MaxDeletePercent")), CheckpointEvery=max(1, int(get("CheckpointEvery"))),
            KeepReplacedFiles=bool(get("KeepReplacedFiles")), CompareMode=str(get("CompareMode")),
            Workers=max(1, int(get("Workers"))),
        )
        name = mapping.get("Name", "?")
        if s.DeleteMode not in ("None", "Mirror", "Archive"):
            raise ValueError(f"Mapping '{name}': DeleteMode must be None, Mirror or Archive")
        if s.CompareMode not in ("Content", "Version", "None"):
            raise ValueError(f"Mapping '{name}': CompareMode must be Content, Version or None")
        for r in s.PathRules:
            re.compile(r["Match"])   # fail early on a bad regex
        return s


def load_config(path: str) -> dict:
    """Read the JSON config. Windows paths may be written with single backslashes (E:\\Shares)
    or JSON-escaped ones (E:\\\\Shares): every lone backslash is treated as a literal backslash."""
    raw = Path(path).read_text(encoding="utf-8-sig")
    raw = re.sub(r'\\\\|\\(?!")', lambda m: m.group(0) if len(m.group(0)) == 2 else "\\\\", raw)
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Config file '{path}' is not valid JSON: {e}") from None
    for req in ("StateDir", "LogDir", "Mappings"):
        if req not in cfg:
            raise ValueError(f"Config is missing '{req}'")
    return cfg


def fix_unc(p: str) -> str:
    # "\\SRV\share" typed with single backslashes arrives as "\SRV\share"; restore the UNC prefix
    if IS_WINDOWS and re.match(r"^\\[^\\]", p):
        return "\\" + p
    return p


# =====================================================================================
# Path helpers
# =====================================================================================
def lp(path: str) -> str:
    """Long-path form on Windows (\\\\?\\ prefix) so paths over 260 characters work."""
    if not IS_WINDOWS:
        return path
    if path.startswith("\\\\?\\"):
        return path
    path = os.path.abspath(path)
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def plain(path: str) -> str:
    """Strip the long-path prefix (for messages and APIs that don't accept it)."""
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def norm_rel(rel: str) -> str:
    return re.sub(r"[\\/]+", lambda m: SEP, rel).strip(SEP)


def key_of(rel: str) -> str:
    # Windows paths are case-insensitive
    return rel.casefold() if IS_WINDOWS else rel


def name_match(name: str, patterns: List[str]) -> bool:
    n = name.lower()
    return any(fnmatch.fnmatchcase(n, p.lower()) for p in patterns)


# =====================================================================================
# Smart mapping: {Token} expansion and PathRules
# =====================================================================================
TOKEN_RX = re.compile(r"\{(\w+)\}")


def expand_token_path(path: str, tokens: Dict[str, str], results: List[Tuple[str, Dict[str, str]]]) -> None:
    """Expand "\\\\SRV\\D$\\Data\\{Dept}\\Reports" into one entry per matching folder, capturing token
    values. Tokens may be partial ("App_{Name}") and may appear in several segments."""
    parts = re.split(r"[\\/]", path)
    idx = next((i for i, p in enumerate(parts) if TOKEN_RX.search(p)), -1)
    if idx < 0:
        results.append((path, tokens))
        return
    if idx < 1:
        raise ValueError(f"A {{Token}} cannot be the first path segment: {path}")

    base = SEP.join(parts[:idx]) or SEP
    seg = parts[idx]
    rest = SEP.join(parts[idx + 1:])

    rx, last, names = "^", 0, []
    for m in TOKEN_RX.finditer(seg):
        rx += re.escape(seg[last:m.start()]) + f"(?P<{m.group(1)}>.+?)"
        last = m.end()
        names.append(m.group(1))
    rx += re.escape(seg[last:]) + "$"
    seg_rx = re.compile(rx, re.IGNORECASE)

    if not os.path.isdir(lp(base)):
        raise FileNotFoundError(f"Source base folder not reachable: {base}")

    with os.scandir(lp(base)) as it:
        entries = sorted((e for e in it if e.is_dir(follow_symlinks=False)), key=lambda e: e.name.lower())
    for e in entries:
        m = seg_rx.match(e.name)
        if not m:
            continue
        t = dict(tokens)
        for n in names:
            t[n] = m.group(n)
        nxt = base.rstrip(SEP) + SEP + e.name
        if rest:
            nxt += SEP + rest
        expand_token_path(nxt, t, results)


def resolve_tokens(text: str, tokens: Dict[str, str]) -> str:
    def rep(m):
        n = m.group(1)
        if n not in tokens:
            raise ValueError(f"Target uses token {{{n}}} that is not defined in Source")
        return tokens[n]
    return TOKEN_RX.sub(rep, text)


def apply_rules(rel: str, rules: List[dict]) -> str:
    """First matching rule wins. Replacement uses $1 / ${name} like PowerShell/.NET."""
    for r in rules:
        rx = re.compile(r["Match"], re.IGNORECASE)
        m = rx.search(rel)
        if not m:
            continue

        def expand(mm, m=m):
            g = mm.group(1).strip("{}")
            v = m.group(int(g)) if g.isdigit() else m.group(g)
            return v or ""

        replaced = re.sub(r"\$(\d+|\{\w+\})", expand, r["Replace"])
        return norm_rel(rel[:m.start()] + replaced + rel[m.end():])
    return rel


# =====================================================================================
# Scan
# =====================================================================================
@dataclass
class SrcFile:
    rel: str
    full: str
    size: int
    mtime: int   # ns since epoch (UTC)


def scan_source(root: str, s: Settings) -> Tuple[Dict[str, SrcFile], int]:
    """Iterative walk: one unreadable folder is logged and counted, not fatal.
    Symlinks and junctions are skipped."""
    files: Dict[str, SrcFile] = {}
    errors = 0
    root_l = lp(root).rstrip(SEP)
    prefix = len(root_l) + 1
    stack = [root_l]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink() or getattr(e, "is_junction", lambda: False)():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            if not name_match(e.name, s.ExcludeDirs):
                                stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            if not name_match(e.name, s.Include) or name_match(e.name, s.Exclude):
                                continue
                            st = e.stat(follow_symlinks=False)
                            rel = e.path[prefix:]
                            files[key_of(rel)] = SrcFile(rel, e.path, st.st_size, st.st_mtime_ns)
                    except OSError as ex:
                        errors += 1
                        log.warning("Cannot read '%s': %s", plain(e.path), ex)
        except OSError as ex:
            errors += 1
            log.warning("Cannot read folder '%s': %s", plain(d), ex)
    return files, errors


# =====================================================================================
# State manifest
# =====================================================================================
@dataclass
class StateEntry:
    Rel: str
    TargetRel: str
    Size: int
    MTime: int
    Hash: str = ""
    SyncedUtc: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"))


def read_state(path: str) -> Dict[str, StateEntry]:
    state: Dict[str, StateEntry] = {}
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                e = StateEntry(row["Rel"], row["TargetRel"], int(row["Size"]), int(row["MTime"]),
                               row.get("Hash", "") or "", row.get("SyncedUtc", "") or "")
                state[key_of(e.Rel)] = e
    return state


def write_state(path: str, state: Dict[str, StateEntry]) -> None:
    """Written to a temp file then swapped in, so a crash never leaves a half-written manifest."""
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(STATE_COLUMNS)
        for e in sorted(state.values(), key=lambda x: x.Rel.lower()):
            w.writerow([e.Rel, e.TargetRel, e.Size, e.MTime, e.Hash, e.SyncedUtc])
    os.replace(tmp, path)


# =====================================================================================
# Same-file check
# =====================================================================================
def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def file_version(path: str) -> Optional[Tuple[str, str]]:
    """(FileVersion, ProductVersion) from a Windows version resource, or None if the file has none."""
    if not IS_WINDOWS:
        return None
    import ctypes
    from ctypes import wintypes

    class VS_FIXEDFILEINFO(ctypes.Structure):
        _fields_ = [(n, wintypes.DWORD) for n in (
            "dwSignature", "dwStrucVersion", "dwFileVersionMS", "dwFileVersionLS",
            "dwProductVersionMS", "dwProductVersionLS", "dwFileFlagsMask", "dwFileFlags",
            "dwFileOS", "dwFileType", "dwFileSubtype", "dwFileDateMS", "dwFileDateLS")]

    ver = ctypes.WinDLL("version")
    ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    ver.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
    ver.GetFileVersionInfoW.restype = wintypes.BOOL
    ver.VerQueryValueW.argtypes = [wintypes.LPCVOID, wintypes.LPCWSTR,
                                   ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.UINT)]
    ver.VerQueryValueW.restype = wintypes.BOOL

    p = plain(path)
    size = ver.GetFileVersionInfoSizeW(p, None)
    if not size:
        return None
    buf = ctypes.create_string_buffer(size)
    if not ver.GetFileVersionInfoW(p, 0, size, buf):
        return None
    ptr, ln = wintypes.LPVOID(), wintypes.UINT()
    if not ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(ln)) or not ln.value:
        return None
    fi = ctypes.cast(ptr, ctypes.POINTER(VS_FIXEDFILEINFO)).contents

    def fmt(ms, ls):
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    return fmt(fi.dwFileVersionMS, fi.dwFileVersionLS), fmt(fi.dwProductVersionMS, fi.dwProductVersionLS)


def same_file(src: str, dst: str, mode: str) -> Optional[str]:
    """Return a short reason if the target already holds the same file as the source, else None."""
    if mode == "None":
        return None
    try:
        ds = os.stat(dst)
    except OSError:
        return None
    ss = os.stat(src)

    if mode == "Version":
        try:
            sv = file_version(src)
            if sv:
                return f"same version {sv[0]}" if file_version(dst) == sv else None
        except OSError:
            pass   # unreadable version info: fall back to content

    if ss.st_size != ds.st_size:
        return None
    if abs(ss.st_mtime_ns - ds.st_mtime_ns) <= TIME_TOLERANCE_NS:
        return "same size and timestamp"
    try:
        if sha256(src) == sha256(dst):
            return "same content (SHA256)"
    except OSError:
        pass
    return None


# =====================================================================================
# File operations
# =====================================================================================
@dataclass
class CopyResult:
    size: int
    mtime: int
    hash: str
    attempts: int
    renamed_to: str = ""
    old_removed: bool = False


def _clear_readonly(path: str) -> None:
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass


def copy_file_safe(src: str, dst: str, s: Settings) -> CopyResult:
    """Copy to <dst>.synctmp, verify, then put in place.
    An existing target is renamed to <name>.old_<RunId> first (never written over), so the new file
    is created fresh and inherits the target folder's permissions."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".synctmp"
    attempt = 0
    while True:
        attempt += 1
        try:
            before = os.stat(src)
            shutil.copyfile(src, tmp)   # data only: no ACLs carried over
            after = os.stat(src)
            if after.st_size != before.st_size or after.st_mtime_ns != before.st_mtime_ns:
                raise OSError("Source changed while copying")

            digest = ""
            if s.VerifyHash:
                h1, h2 = sha256(src), sha256(tmp)
                if h1 != h2:
                    raise OSError("SHA256 mismatch after copy")
                digest = h2

            renamed_to, old_removed = "", False
            if os.path.exists(dst):
                # 1. Rename the existing target out of the way
                old = f"{dst}.old_{RUN_ID}"
                n = 1
                while os.path.exists(old):
                    old = f"{dst}.old_{RUN_ID}_{n}"
                    n += 1
                try:
                    os.rename(dst, old)
                except OSError as ex:
                    raise OSError(f"Cannot rename existing target file (check Delete permission): {ex}") from ex

                # 2. Put the new copy in its place; if that fails, put the old file back
                try:
                    os.rename(tmp, dst)
                except OSError:
                    try:
                        os.rename(old, dst)
                    except OSError:
                        pass
                    raise
                renamed_to = os.path.basename(old)

                # 3. Optionally remove the renamed old file; leave it if not permitted
                if not s.KeepReplacedFiles:
                    try:
                        _clear_readonly(old)
                        os.remove(old)
                        old_removed = True
                    except OSError:
                        pass
            else:
                os.rename(tmp, dst)

            # Keep the source timestamp; not fatal if the target folder doesn't allow it
            try:
                os.utime(dst, ns=(time.time_ns(), before.st_mtime_ns))
            except OSError:
                pass
            return CopyResult(before.st_size, before.st_mtime_ns, digest, attempt, renamed_to, old_removed)

        except OSError:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            if attempt >= s.RetryCount:
                raise
            time.sleep(s.RetryDelaySeconds)


def remove_empty_parents(folder: str, stop_at: str) -> None:
    stop = os.path.normcase(stop_at.rstrip(SEP))
    while folder and os.path.normcase(folder.rstrip(SEP)) != stop and len(folder) > len(stop):
        try:
            if any(os.scandir(folder)):
                break
            os.rmdir(folder)
            folder = os.path.dirname(folder)
        except OSError:
            break


def remove_target_file(target_root: str, target_rel: str, mode: str, archive_root: str) -> str:
    full = os.path.join(target_root, target_rel)
    if not os.path.exists(full):
        return "AlreadyGone"
    _clear_readonly(full)
    if mode == "Mirror":
        os.remove(full)
        result = "Deleted"
    else:
        dest = os.path.join(archive_root, RUN_ID, target_rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.move(full, dest)
        result = "Archived"
    remove_empty_parents(os.path.dirname(full), target_root)
    return result


# =====================================================================================
# Run context (shared across mappings)
# =====================================================================================
class Run:
    def __init__(self, dry_run: bool, allow_mass_delete: bool):
        self.dry_run = dry_run
        self.allow_mass_delete = allow_mass_delete
        self.changes: List[dict] = []
        self.file_errors = 0
        self.mapping_failures = 0
        self.fatal = False
        self._lock = threading.Lock()

    def change(self, mapping, action, path, result, detail=""):
        with self._lock:
            self.changes.append({"Time": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"), "Mapping": mapping,
                                 "Action": action, "Path": path, "Result": result, "Detail": detail})

    def file_error(self):
        with self._lock:
            self.file_errors += 1


@dataclass
class PlanItem:
    action: str
    file: SrcFile
    target_rel: str
    target_full: str
    old_target_rel: Optional[str]
    same_reason: Optional[str] = None


# =====================================================================================
# Sync one mapping instance
# =====================================================================================
def sync_mapping(run: Run, name: str, source: str, target: str, state_file: str,
                 archive_root: str, s: Settings) -> None:
    log.info("=== [%s] %s  ->  %s", name, source, target)
    if not os.path.isdir(lp(source)):
        log.error("[%s] Source not reachable; mapping skipped, nothing changed.", name)
        run.mapping_failures += 1
        return

    t0 = time.monotonic()
    files, scan_errors = scan_source(source, s)
    state = read_state(state_file)
    log.info("[%s] Scanned %d files in %.1fs (%d unreadable); %d tracked in state",
             name, len(files), time.monotonic() - t0, scan_errors, len(state))

    target_l = lp(target)
    now_ns = time.time_ns()
    min_age_ns = s.MinFileAgeSeconds * 1_000_000_000
    counts = dict.fromkeys(["New", "Modified", "Repair", "Relocate", "Adopt", "Same",
                            "Unchanged", "Deferred", "Delete"], 0)
    plan: List[PlanItem] = []

    # ---- 1. Diff source vs. state (and target) ----
    for k, f in files.items():
        target_rel = apply_rules(f.rel, s.PathRules)
        target_full = os.path.join(target_l, target_rel)
        old = state.get(k)

        action = None
        if old is None:
            try:
                ts = os.stat(target_full)
                if ts.st_size == f.size and abs(ts.st_mtime_ns - f.mtime) <= TIME_TOLERANCE_NS:
                    action = "Adopt"
            except OSError:
                pass
            action = action or "New"
        elif old.Size != f.size or old.MTime != f.mtime:
            action = "Modified"
        elif key_of(old.TargetRel) != key_of(target_rel):
            action = "Relocate"
        elif s.VerifyTarget:
            try:
                if os.stat(target_full).st_size != f.size:
                    action = "Repair"
            except OSError:
                action = "Repair"

        if not action:
            counts["Unchanged"] += 1
            continue

        if action != "Adopt" and (now_ns - f.mtime) < min_age_ns:
            counts["Deferred"] += 1
            run.change(name, action, f.rel, "Deferred", "File modified too recently; will retry next run")
            continue

        # Before copying, check whether the target already has the same file/version
        same = None
        if action in ("New", "Modified", "Repair"):
            same = same_file(f.full, target_full, s.CompareMode)
            if same:
                action = "Same"

        counts[action] += 1
        plan.append(PlanItem(action, f, target_rel, target_full, old.TargetRel if old else None, same))

    # ---- 2. Deletions: tracked files no longer in source ----
    deletes = [e for k, e in state.items() if k not in files]
    counts["Delete"] = len(deletes)

    allow_deletes = True
    if deletes:
        pct = 100.0 * len(deletes) / max(1, len(state))
        if scan_errors:
            allow_deletes = False
            log.warning("[%s] %d deletions suppressed: source scan was incomplete.", name, len(deletes))
        elif (s.DeleteMode != "None" and len(deletes) > 10 and pct > s.MaxDeletePercent
              and not run.allow_mass_delete):
            allow_deletes = False
            log.warning("[%s] %d deletions (%.1f%% of tracked files) exceed MaxDeletePercent=%g. "
                        "Suppressed; rerun with --allow-mass-delete if intended.",
                        name, len(deletes), pct, s.MaxDeletePercent)

    log.info("[%s] Plan: New=%d Modified=%d Repair=%d Relocate=%d Adopt=%d SameSkipped=%d "
             "Delete=%d Unchanged=%d Deferred=%d", name, counts["New"], counts["Modified"],
             counts["Repair"], counts["Relocate"], counts["Adopt"], counts["Same"],
             counts["Delete"], counts["Unchanged"], counts["Deferred"])

    if run.dry_run:
        for p in plan:
            detail = (f"Target already up to date ({p.same_reason}); no copy"
                      if p.same_reason else p.target_rel)
            run.change(name, p.action, p.file.rel, "DryRun", detail)
        for d in deletes:
            run.change(name, f"Delete({s.DeleteMode})", d.Rel,
                       "DryRun" if allow_deletes else "Suppressed", d.TargetRel)
        return

    # ---- 3. Execute: records first, then copies (in parallel) ----
    state_lock = threading.Lock()
    copies = []
    for p in plan:
        f = p.file
        if p.action == "Adopt":
            state[key_of(f.rel)] = StateEntry(f.rel, p.target_rel, f.size, f.mtime)
            run.change(name, "Adopt", f.rel, "OK", "Already present at target")
        elif p.action == "Same":
            state[key_of(f.rel)] = StateEntry(f.rel, p.target_rel, f.size, f.mtime)
            run.change(name, "SameSkipped", f.rel, "OK", f"Not copied: {p.same_reason}")
        else:
            copies.append(p)

    def do_copy(p: PlanItem):
        f = p.file
        r = copy_file_safe(f.full, p.target_full, s)
        detail = f"{r.size:,} bytes"
        if r.attempts > 1:
            detail += f" after {r.attempts} attempts"
        if r.renamed_to:
            if r.old_removed:
                detail += f"; previous version renamed to {r.renamed_to} then removed"
            else:
                detail += f"; previous version kept as {r.renamed_to}"
                if not s.KeepReplacedFiles:
                    log.warning("[%s] Could not remove '%s' (no delete permission); left in place",
                                name, r.renamed_to)
        if p.action == "Relocate" and p.old_target_rel and s.DeleteMode != "None":
            remove_target_file(target_l, p.old_target_rel, s.DeleteMode, archive_root)
            detail += f"; old location {s.DeleteMode.lower()}d"
        with state_lock:
            state[key_of(f.rel)] = StateEntry(f.rel, p.target_rel, r.size, r.mtime, r.hash)
        return detail

    done = 0
    with ThreadPoolExecutor(max_workers=s.Workers) as pool:
        futures = {pool.submit(do_copy, p): p for p in copies}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                run.change(name, p.action, p.file.rel, "OK", fut.result())
            except Exception as ex:   # noqa: BLE001 - one bad file must not stop the run
                run.file_error()
                log.warning("[%s] FAILED %s '%s': %s", name, p.action, p.file.rel, ex)
                run.change(name, p.action, p.file.rel, "FAILED", str(ex))
                # State is left as-is, so the file is picked up again next run.
            done += 1
            if done % s.CheckpointEvery == 0:
                with state_lock:
                    write_state(state_file, state)
                log.info("[%s] Checkpoint: %d / %d copied", name, done, len(copies))

    # ---- 4. Execute deletes ----
    if allow_deletes:
        for d in deletes:
            try:
                if s.DeleteMode == "None":
                    run.change(name, "Delete(None)", d.Rel, "Untracked", "Removed from source; target copy kept")
                else:
                    res = remove_target_file(target_l, d.TargetRel, s.DeleteMode, archive_root)
                    run.change(name, f"Delete({s.DeleteMode})", d.Rel, res, d.TargetRel)
                state.pop(key_of(d.Rel), None)
            except OSError as ex:
                run.file_error()
                log.warning("[%s] FAILED delete '%s': %s", name, d.TargetRel, ex)
                run.change(name, f"Delete({s.DeleteMode})", d.Rel, "FAILED", str(ex))

    write_state(state_file, state)
    log.info("[%s] Done in %.1fs", name, time.monotonic() - t0)


# =====================================================================================
# Single-instance lock
# =====================================================================================
class RunLock:
    def __init__(self, path: str):
        self.path = path
        self.fh = None

    def acquire(self) -> bool:
        self.fh = open(self.path, "a+")
        try:
            if IS_WINDOWS:
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self.fh.close()
            self.fh = None
            return False

    def release(self):
        if self.fh:
            try:
                if IS_WINDOWS:
                    import msvcrt
                    self.fh.seek(0)
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            self.fh.close()


# =====================================================================================
# Main
# =====================================================================================
def setup_logging(log_file: Optional[str]) -> None:
    log.setLevel(logging.INFO)
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    log.addHandler(console)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Smart incremental file sync (source share -> local drive).")
    ap.add_argument("--config", "-c", required=True, help="Path to the JSON config")
    ap.add_argument("--dry-run", action="store_true", help="Report what would happen; change nothing")
    ap.add_argument("--only", nargs="+", metavar="NAME", help="Run only the named mapping(s)")
    ap.add_argument("--allow-mass-delete", action="store_true", help="Bypass the MaxDeletePercent guard")
    args = ap.parse_args(argv)

    setup_logging(None)
    run = Run(args.dry_run, args.allow_mass_delete)
    lock = None
    log_file = None
    log_dir = None
    cfg = None
    try:
        cfg = load_config(args.config)
        state_dir, log_dir = cfg["StateDir"], cfg["LogDir"]
        archive_dir = cfg.get("ArchiveDir") or os.path.join(os.path.dirname(state_dir.rstrip(SEP)), "archive")
        defaults = cfg.get("Defaults") or {}
        os.makedirs(state_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"sync_{RUN_ID}.log")
        setup_logging(log_file)

        lock = RunLock(os.path.join(state_dir, "sync.lock"))
        if not lock.acquire():
            lock = None
            log.error("Another sync run is in progress (lock held). Exiting.")
            run.fatal = True
            return 2

        user = os.environ.get("USERNAME") or os.environ.get("USER") or "?"
        host = os.environ.get("COMPUTERNAME") or platform.node() or "?"
        log.info("Sync run %s started (%s) as %s on %s", RUN_ID, "DRY RUN" if args.dry_run else "LIVE", user, host)

        seen = set()
        for m in cfg["Mappings"]:
            mname = m.get("Name")
            if not mname:
                raise ValueError("Every mapping needs a Name")
            if mname in seen:
                raise ValueError(f"Duplicate mapping name '{mname}'")
            seen.add(mname)
            if args.only and mname not in args.only:
                continue

            m["Source"] = fix_unc(m["Source"])
            m["Target"] = fix_unc(m["Target"])
            settings = Settings.build(m, defaults)

            instances: List[Tuple[str, Dict[str, str]]] = []
            try:
                expand_token_path(m["Source"], {}, instances)
            except (OSError, ValueError) as ex:
                log.error("[%s] %s", mname, ex)
                run.mapping_failures += 1
                continue
            if TOKEN_RX.search(m["Source"]):
                log.info("[%s] Token pattern matched %d source folder(s)", mname, len(instances))

            for src, tokens in instances:
                inst = mname
                if tokens:
                    inst += "[" + ",".join(tokens[k] for k in sorted(tokens)) + "]"
                    if not os.path.isdir(lp(src)):
                        log.info("[%s] %s does not exist under this match; skipped", inst, src)
                        continue
                safe = re.sub(r"[^\w\-.]", "_", inst)
                sync_mapping(run, inst, src, resolve_tokens(m["Target"], tokens),
                             os.path.join(state_dir, f"{safe}.state.csv"),
                             os.path.join(archive_dir, safe), settings)

    except Exception as ex:   # noqa: BLE001
        run.fatal = True
        log.error("FATAL: %s", ex)
    finally:
        if run.changes and log_file:
            csv_path = log_file[:-4] + ".changes.csv"
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["Time", "Mapping", "Action", "Path", "Result", "Detail"],
                                   quoting=csv.QUOTE_ALL)
                w.writeheader()
                w.writerows(run.changes)
            summary = {}
            for c in run.changes:
                summary[c["Result"]] = summary.get(c["Result"], 0) + 1
            log.info("Change audit: %s  (%s)", csv_path, " ".join(f"{k}={v}" for k, v in summary.items()))
        if cfg and log_dir and cfg.get("LogRetentionDays"):
            cutoff = time.time() - timedelta(days=int(cfg["LogRetentionDays"])).total_seconds()
            for p in Path(log_dir).glob("sync_*"):
                try:
                    if p.is_file() and p.stat().st_mtime < cutoff:
                        p.unlink()
                except OSError:
                    pass
        if lock:
            lock.release()

    code = 0
    if run.file_errors:
        code = 1
    if run.fatal or run.mapping_failures:
        code = 2
    log.info("Finished. FileErrors=%d MappingFailures=%d ExitCode=%d", run.file_errors, run.mapping_failures, code)
    return code


if __name__ == "__main__":
    sys.exit(main())
