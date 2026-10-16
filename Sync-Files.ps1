#Requires -Version 5.1
<#
.SYNOPSIS
    Smart incremental file sync: remote Windows server (UNC share) -> this server's drive.

.DESCRIPTION
    - Folder mappings, with {Token} wildcards that auto-discover source folders and map them to target folders
    - Optional regex PathRules to reshape the target layout (e.g. sort files into yyyy\MM folders)
    - Change tracking through a per-mapping state manifest (size + last-write time, optional SHA256)
    - Detects New / Modified / Repair (target drifted) / Relocate (rules changed) / Deleted
    - Adopts files already at the target (same size + time) without recopying them, so a pre-seeded target is reused
    - Atomic copy (temp file + replace), retries locked files, skips files still being written
    - Safe deletes: only files this tool copied, never after an incomplete scan, capped by MaxDeletePercent
    - Dry run, single-instance lock, run log + change audit CSV, checkpointed state, exit codes for schedulers

.PARAMETER ConfigPath      Path to the JSON config.
.PARAMETER DryRun          Report what would happen; copy/delete nothing and leave state untouched.
.PARAMETER OnlyMapping     Run only the named mapping(s).
.PARAMETER AllowMassDelete Bypass the MaxDeletePercent guard for this run.

.EXAMPLE
    .\Sync-Files.ps1 -ConfigPath D:\FileSync\sync-config.json -DryRun
.EXAMPLE
    .\Sync-Files.ps1 -ConfigPath D:\FileSync\sync-config.json -OnlyMapping DeptReports

.NOTES
    Exit codes: 0 = success
                1 = completed, but some files failed (retried automatically next run)
                2 = fatal: bad config, already running, or a whole mapping failed (source unreachable)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [switch]$DryRun,
    [string[]]$OnlyMapping,
    [switch]$AllowMassDelete
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:RunId           = (Get-Date).ToString('yyyyMMdd_HHmmss')
$script:LogFile         = $null
$script:Changes         = New-Object System.Collections.Generic.List[object]
$script:FileErrors      = 0
$script:MappingFailures = 0
$script:Fatal           = $false
$script:Lock            = $null

#region ---------------- Logging ----------------
function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 }
}

function Add-Change {
    param([string]$Mapping, [string]$Action, [string]$Path, [string]$Result, [string]$Detail = '')
    $script:Changes.Add([pscustomobject]@{
        Time = (Get-Date).ToString('s'); Mapping = $Mapping; Action = $Action
        Path = $Path; Result = $Result; Detail = $Detail
    })
}
#endregion

#region ---------------- Config helpers ----------------
function Get-Setting {
    param($Mapping, $Defaults, [string]$Name, $Fallback)
    if ($Mapping.PSObject.Properties[$Name]) { return $Mapping.$Name }
    if ($null -ne $Defaults -and $Defaults.PSObject.Properties[$Name]) { return $Defaults.$Name }
    return $Fallback
}

function Test-NameMatch {
    param([string]$Name, [object[]]$Patterns)
    foreach ($p in $Patterns) { if ($Name -like $p) { return $true } }
    return $false
}
#endregion

#region ---------------- Smart mapping ----------------
# Expands "\\SRV\D$\Data\{Dept}\Reports" into one entry per matching folder, capturing token values.
# Tokens may be partial ("App_{Name}") and may appear in several segments.
function Expand-TokenPath {
    param([string]$Path, [hashtable]$Tokens, [System.Collections.Generic.List[object]]$Results)

    $parts = $Path -split '\\'
    $idx = -1
    for ($i = 0; $i -lt $parts.Count; $i++) { if ($parts[$i] -match '\{\w+\}') { $idx = $i; break } }

    if ($idx -lt 0) { $Results.Add(@{ Path = $Path; Tokens = $Tokens }); return }
    if ($idx -lt 1) { throw "A {Token} cannot be the first path segment: $Path" }

    $base = ($parts[0..($idx - 1)] -join '\').TrimEnd('\') + '\'
    $seg  = $parts[$idx]
    $rest = ''
    if ($idx -lt $parts.Count - 1) { $rest = ($parts[($idx + 1)..($parts.Count - 1)] -join '\') }

    # Build a wildcard for enumeration and a regex with named groups for capture
    $wild  = [regex]::Replace($seg, '\{\w+\}', '*')
    $rx    = '^'; $last = 0; $names = @()
    foreach ($m in [regex]::Matches($seg, '\{(\w+)\}')) {
        $rx   += [regex]::Escape($seg.Substring($last, $m.Index - $last)) + '(?<' + $m.Groups[1].Value + '>.+?)'
        $last  = $m.Index + $m.Length
        $names += $m.Groups[1].Value
    }
    $rx += [regex]::Escape($seg.Substring($last)) + '$'

    if (-not [IO.Directory]::Exists($base)) { throw "Source base folder not reachable: $base" }

    foreach ($dir in [IO.Directory]::GetDirectories($base, $wild)) {
        $leaf = [IO.Path]::GetFileName($dir)
        $m = [regex]::Match($leaf, $rx, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $m.Success) { continue }
        $t = $Tokens.Clone()
        foreach ($n in $names) { $t[$n] = $m.Groups[$n].Value }
        $next = $dir
        if ($rest) { $next = $dir + '\' + $rest }
        Expand-TokenPath -Path $next -Tokens $t -Results $Results
    }
}

function Resolve-TokenString {
    param([string]$Text, [hashtable]$Tokens)
    $out = $Text
    foreach ($m in [regex]::Matches($Text, '\{(\w+)\}')) {
        $n = $m.Groups[1].Value
        if (-not $Tokens.ContainsKey($n)) { throw "Target uses token {$n} that is not defined in Source" }
        $out = $out.Replace($m.Value, [string]$Tokens[$n])
    }
    return $out
}

function Get-TargetRel {
    param([string]$Rel, [object[]]$Rules)
    foreach ($r in $Rules) {
        if ($Rel -match $r.Match) { return ($Rel -replace $r.Match, $r.Replace) }
    }
    return $Rel
}
#endregion

#region ---------------- Scan ----------------
# Iterative walk: one unreadable folder is logged and counted, not fatal. Junctions/symlinks are skipped.
function Get-SourceInventory {
    param([string]$Root, [object[]]$Include, [object[]]$Exclude, [object[]]$ExcludeDirs)

    $files  = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $errors = 0
    $rootFull = [IO.Path]::GetFullPath($Root)
    if ($rootFull.EndsWith('\')) { $prefixLen = $rootFull.Length } else { $prefixLen = $rootFull.Length + 1 }

    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($rootFull)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            $di = New-Object System.IO.DirectoryInfo $dir
            foreach ($sub in $di.EnumerateDirectories()) {
                if (($sub.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                if (Test-NameMatch $sub.Name $ExcludeDirs) { continue }
                $stack.Push($sub.FullName)
            }
            foreach ($f in $di.EnumerateFiles()) {
                if (-not (Test-NameMatch $f.Name $Include)) { continue }
                if (Test-NameMatch $f.Name $Exclude) { continue }
                $rel = $f.FullName.Substring($prefixLen)
                $files[$rel] = [pscustomobject]@{
                    Rel = $rel; Full = $f.FullName; Size = $f.Length; MTime = $f.LastWriteTimeUtc.Ticks
                }
            }
        }
        catch {
            $errors++
            Write-Log "Cannot read folder '$dir': $($_.Exception.Message)" 'WARN'
        }
    }
    return @{ Files = $files; Errors = $errors }
}
#endregion

#region ---------------- State manifest ----------------
$script:StateColumns = 'Rel', 'TargetRel', 'Size', 'MTime', 'Hash', 'SyncedUtc'

function Read-State {
    param([string]$Path)
    $state = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    if (Test-Path -LiteralPath $Path) {
        foreach ($row in (Import-Csv -LiteralPath $Path -Encoding UTF8)) {
            $state[$row.Rel] = New-StateEntry $row.Rel $row.TargetRel ([long]$row.Size) ([long]$row.MTime) $row.Hash $row.SyncedUtc
        }
    }
    return $state
}

function New-StateEntry {
    param([string]$Rel, [string]$TargetRel, [long]$Size, [long]$MTime, [string]$Hash, [string]$SyncedUtc)
    if (-not $SyncedUtc) { $SyncedUtc = [DateTime]::UtcNow.ToString('s') }
    return [pscustomobject]@{ Rel = $Rel; TargetRel = $TargetRel; Size = $Size; MTime = $MTime; Hash = $Hash; SyncedUtc = $SyncedUtc }
}

# Written to a temp file then swapped in, so a crash never leaves a half-written manifest.
function Write-State {
    param([string]$Path, $State)
    $tmp = "$Path.tmp"
    if ($State.Count -eq 0) {
        Set-Content -LiteralPath $tmp -Value (($script:StateColumns | ForEach-Object { '"' + $_ + '"' }) -join ',') -Encoding UTF8
    }
    else {
        $State.Values | Sort-Object Rel | Select-Object $script:StateColumns |
            Export-Csv -LiteralPath $tmp -NoTypeInformation -Encoding UTF8
    }
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}
#endregion

#region ---------------- File operations ----------------
# Copy to <dest>.synctmp, verify, then swap in. The target never holds a partial file.
function Copy-FileAtomic {
    param([string]$Src, [string]$Dst, [bool]$VerifyHash, [int]$RetryCount, [int]$RetryDelay)

    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Dst))
    $tmp = $Dst + '.synctmp'
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $before = New-Object IO.FileInfo $Src
            $size = $before.Length; $mtime = $before.LastWriteTimeUtc

            [IO.File]::Copy($Src, $tmp, $true)

            $after = New-Object IO.FileInfo $Src
            if ($after.Length -ne $size -or $after.LastWriteTimeUtc -ne $mtime) {
                throw 'Source changed while copying'
            }

            $hash = ''
            if ($VerifyHash) {
                $h1 = (Get-FileHash -LiteralPath $Src -Algorithm SHA256).Hash
                $h2 = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash
                if ($h1 -ne $h2) { throw 'SHA256 mismatch after copy' }
                $hash = $h2
            }

            if ([IO.File]::Exists($Dst)) {
                [IO.File]::SetAttributes($Dst, [IO.FileAttributes]::Normal)
                # [NullString] is required: PowerShell turns $null into "" for string args, which Replace rejects
                [IO.File]::Replace($tmp, $Dst, [NullString]::Value)
            }
            else {
                [IO.File]::Move($tmp, $Dst)
            }
            [IO.File]::SetLastWriteTimeUtc($Dst, $mtime)

            return [pscustomobject]@{ Size = $size; MTime = $mtime.Ticks; Hash = $hash; Attempts = $attempt }
        }
        catch {
            try { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } } catch { }
            if ($attempt -ge $RetryCount) { throw }
            Start-Sleep -Seconds $RetryDelay
        }
    }
}

function Remove-TargetFile {
    param([string]$TargetRoot, [string]$TargetRel, [string]$Mode, [string]$ArchiveRoot)
    $full = [IO.Path]::Combine($TargetRoot, $TargetRel)
    if (-not [IO.File]::Exists($full)) { return 'AlreadyGone' }
    [IO.File]::SetAttributes($full, [IO.FileAttributes]::Normal)

    if ($Mode -eq 'Mirror') {
        [IO.File]::Delete($full)
        $result = 'Deleted'
    }
    else {
        $dest = [IO.Path]::Combine($ArchiveRoot, $script:RunId, $TargetRel)
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest))
        [IO.File]::Move($full, $dest)
        $result = 'Archived'
    }
    Remove-EmptyParents -Folder ([IO.Path]::GetDirectoryName($full)) -StopAt $TargetRoot
    return $result
}

function Remove-EmptyParents {
    param([string]$Folder, [string]$StopAt)
    $stop = $StopAt.TrimEnd('\')
    while ($Folder -and $Folder.TrimEnd('\') -ne $stop -and $Folder.Length -gt $stop.Length) {
        try {
            if ([IO.Directory]::EnumerateFileSystemEntries($Folder).GetEnumerator().MoveNext()) { break }
            [IO.Directory]::Delete($Folder)
            $Folder = [IO.Path]::GetDirectoryName($Folder)
        }
        catch { break }
    }
}
#endregion

#region ---------------- Sync one mapping instance ----------------
function Invoke-MappingSync {
    param([hashtable]$Inst)

    $s    = $Inst.Settings
    $name = $Inst.Name
    Write-Log "=== [$name] $($Inst.Source)  ->  $($Inst.Target)"

    if (-not [IO.Directory]::Exists($Inst.Source)) {
        Write-Log "[$name] Source not reachable; mapping skipped, nothing changed." 'ERROR'
        $script:MappingFailures++
        return
    }

    $sw    = [Diagnostics.Stopwatch]::StartNew()
    $scan  = Get-SourceInventory -Root $Inst.Source -Include $s.Include -Exclude $s.Exclude -ExcludeDirs $s.ExcludeDirs
    $state = Read-State $Inst.StateFile
    Write-Log ("[{0}] Scanned {1} files in {2:n1}s ({3} unreadable folders); {4} tracked in state" -f `
        $name, $scan.Files.Count, $sw.Elapsed.TotalSeconds, $scan.Errors, $state.Count)

    $nowTicks    = [DateTime]::UtcNow.Ticks
    $minAgeTicks = [TimeSpan]::FromSeconds($s.MinFileAgeSeconds).Ticks
    $tolerance   = [TimeSpan]::FromSeconds(2).Ticks
    $counts = @{ New = 0; Modified = 0; Repair = 0; Relocate = 0; Adopt = 0; Unchanged = 0; Busy = 0; Delete = 0 }
    $plan   = New-Object System.Collections.Generic.List[object]

    # ---- 1. Diff source vs. state (and target) ----
    foreach ($f in $scan.Files.Values) {
        $targetRel  = Get-TargetRel $f.Rel $s.PathRules
        $targetFull = [IO.Path]::Combine($Inst.Target, $targetRel)
        $old = $null
        if ($state.ContainsKey($f.Rel)) { $old = $state[$f.Rel] }

        $action = $null
        if ($null -eq $old) {
            $tfi = New-Object IO.FileInfo $targetFull
            if ($tfi.Exists -and $tfi.Length -eq $f.Size -and
                [Math]::Abs($tfi.LastWriteTimeUtc.Ticks - $f.MTime) -le $tolerance) { $action = 'Adopt' }
            else { $action = 'New' }
        }
        elseif ($old.Size -ne $f.Size -or $old.MTime -ne $f.MTime) { $action = 'Modified' }
        elseif ($old.TargetRel -ne $targetRel)                     { $action = 'Relocate' }
        elseif ($s.VerifyTarget) {
            $tfi = New-Object IO.FileInfo $targetFull
            if (-not $tfi.Exists -or $tfi.Length -ne $f.Size) { $action = 'Repair' }
        }

        if (-not $action) { $counts.Unchanged++; continue }

        if ($action -ne 'Adopt' -and ($nowTicks - $f.MTime) -lt $minAgeTicks) {
            $counts.Busy++
            Add-Change $name $action $f.Rel 'Deferred' 'File modified too recently; will retry next run'
            continue
        }

        $counts[$action]++
        $oldTargetRel = $null
        if ($null -ne $old) { $oldTargetRel = $old.TargetRel }
        $plan.Add([pscustomobject]@{
            Action = $action; File = $f; TargetRel = $targetRel; TargetFull = $targetFull; OldTargetRel = $oldTargetRel
        })
    }

    # ---- 2. Deletions: tracked files no longer in source ----
    $deletes = New-Object System.Collections.Generic.List[object]
    foreach ($k in $state.Keys) { if (-not $scan.Files.ContainsKey($k)) { $deletes.Add($state[$k]) } }
    $counts.Delete = $deletes.Count

    $allowDeletes = $true
    if ($deletes.Count -gt 0) {
        $pct = 100.0 * $deletes.Count / [Math]::Max(1, $state.Count)
        if ($scan.Errors -gt 0) {
            $allowDeletes = $false
            Write-Log "[$name] $($deletes.Count) deletions suppressed: source scan was incomplete." 'WARN'
        }
        elseif ($s.DeleteMode -ne 'None' -and $deletes.Count -gt 10 -and $pct -gt $s.MaxDeletePercent -and -not $AllowMassDelete) {
            $allowDeletes = $false
            Write-Log ("[{0}] {1} deletions ({2:n1}% of tracked files) exceed MaxDeletePercent={3}. Suppressed; rerun with -AllowMassDelete if intended." -f `
                $name, $deletes.Count, $pct, $s.MaxDeletePercent) 'WARN'
        }
    }

    Write-Log ("[{0}] Plan: New={1} Modified={2} Repair={3} Relocate={4} Adopt={5} Delete={6} Unchanged={7} Deferred={8}" -f `
        $name, $counts.New, $counts.Modified, $counts.Repair, $counts.Relocate, $counts.Adopt, $counts.Delete, $counts.Unchanged, $counts.Busy)

    if ($DryRun) {
        foreach ($p in $plan) { Add-Change $name $p.Action $p.File.Rel 'DryRun' $p.TargetRel }
        foreach ($d in $deletes) {
            $r = 'DryRun'; if (-not $allowDeletes) { $r = 'Suppressed' }
            Add-Change $name "Delete($($s.DeleteMode))" $d.Rel $r $d.TargetRel
        }
        return
    }

    # ---- 3. Execute copies ----
    $done = 0
    foreach ($p in $plan) {
        $f = $p.File
        try {
            if ($p.Action -eq 'Adopt') {
                $state[$f.Rel] = New-StateEntry $f.Rel $p.TargetRel $f.Size $f.MTime '' ''
                Add-Change $name 'Adopt' $f.Rel 'OK' 'Already present at target'
            }
            else {
                $r = Copy-FileAtomic -Src $f.Full -Dst $p.TargetFull -VerifyHash $s.VerifyHash `
                                     -RetryCount $s.RetryCount -RetryDelay $s.RetryDelaySeconds
                $state[$f.Rel] = New-StateEntry $f.Rel $p.TargetRel $r.Size $r.MTime $r.Hash ''
                $detail = '{0:n0} bytes' -f $r.Size
                if ($r.Attempts -gt 1) { $detail += " after $($r.Attempts) attempts" }

                if ($p.Action -eq 'Relocate' -and $p.OldTargetRel -and $s.DeleteMode -ne 'None') {
                    $null = Remove-TargetFile $Inst.Target $p.OldTargetRel $s.DeleteMode $Inst.ArchiveRoot
                    $detail += "; old location $($s.DeleteMode.ToLower())d"
                }
                Add-Change $name $p.Action $f.Rel 'OK' $detail
            }
        }
        catch {
            $script:FileErrors++
            Write-Log "[$name] FAILED $($p.Action) '$($f.Rel)': $($_.Exception.Message)" 'WARN'
            Add-Change $name $p.Action $f.Rel 'FAILED' $_.Exception.Message
            # State is left as-is, so the file is picked up again next run.
        }
        $done++
        if ($done % $s.CheckpointEvery -eq 0) {
            Write-State $Inst.StateFile $state
            Write-Log "[$name] Checkpoint: $done / $($plan.Count) processed"
        }
    }

    # ---- 4. Execute deletes ----
    if ($allowDeletes) {
        foreach ($d in $deletes) {
            try {
                if ($s.DeleteMode -eq 'None') {
                    Add-Change $name 'Delete(None)' $d.Rel 'Untracked' 'Removed from source; target copy kept'
                }
                else {
                    $res = Remove-TargetFile $Inst.Target $d.TargetRel $s.DeleteMode $Inst.ArchiveRoot
                    Add-Change $name "Delete($($s.DeleteMode))" $d.Rel $res $d.TargetRel
                }
                [void]$state.Remove($d.Rel)
            }
            catch {
                $script:FileErrors++
                Write-Log "[$name] FAILED delete '$($d.TargetRel)': $($_.Exception.Message)" 'WARN'
                Add-Change $name "Delete($($s.DeleteMode))" $d.Rel 'FAILED' $_.Exception.Message
            }
        }
    }

    Write-State $Inst.StateFile $state
    Write-Log ("[{0}] Done in {1:n1}s" -f $name, $sw.Elapsed.TotalSeconds)
}
#endregion

#region ---------------- Main ----------------
try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    foreach ($req in 'StateDir', 'LogDir', 'Mappings') {
        if (-not $config.PSObject.Properties[$req]) { throw "Config is missing '$req'" }
    }
    $stateDir = $config.StateDir
    $logDir   = $config.LogDir
    $archiveDir = [IO.Path]::Combine($stateDir, '..', 'archive')
    if ($config.PSObject.Properties['ArchiveDir']) { $archiveDir = $config.ArchiveDir }
    $defaults = $null
    if ($config.PSObject.Properties['Defaults']) { $defaults = $config.Defaults }

    foreach ($d in $stateDir, $logDir) { [void][IO.Directory]::CreateDirectory($d) }
    $script:LogFile = [IO.Path]::Combine($logDir, "sync_$($script:RunId).log")

    # Single-instance lock: held open exclusively for the whole run
    try {
        $script:Lock = [IO.File]::Open([IO.Path]::Combine($stateDir, 'sync.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    }
    catch {
        Write-Log 'Another sync run is in progress (lock held). Exiting.' 'ERROR'
        $script:Fatal = $true
        return
    }

    $mode = 'LIVE'; if ($DryRun) { $mode = 'DRY RUN' }
    Write-Log "Sync run $($script:RunId) started ($mode) as $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"

    $names = @{}
    foreach ($m in $config.Mappings) {
        if ($names.ContainsKey($m.Name)) { throw "Duplicate mapping name '$($m.Name)'" }
        $names[$m.Name] = $true
        if ($OnlyMapping -and ($OnlyMapping -notcontains $m.Name)) { continue }

        $settings = @{
            Include           = @(Get-Setting $m $defaults 'Include' @('*'))
            Exclude           = @(Get-Setting $m $defaults 'Exclude' @())
            ExcludeDirs       = @(Get-Setting $m $defaults 'ExcludeDirs' @())
            PathRules         = @(Get-Setting $m $defaults 'PathRules' @())
            DeleteMode        = [string](Get-Setting $m $defaults 'DeleteMode' 'None')
            MinFileAgeSeconds = [int](Get-Setting $m $defaults 'MinFileAgeSeconds' 60)
            VerifyHash        = [bool](Get-Setting $m $defaults 'VerifyHash' $false)
            VerifyTarget      = [bool](Get-Setting $m $defaults 'VerifyTarget' $true)
            RetryCount        = [int](Get-Setting $m $defaults 'RetryCount' 3)
            RetryDelaySeconds = [int](Get-Setting $m $defaults 'RetryDelaySeconds' 5)
            MaxDeletePercent  = [double](Get-Setting $m $defaults 'MaxDeletePercent' 20)
            CheckpointEvery   = [int](Get-Setting $m $defaults 'CheckpointEvery' 500)
        }
        if (@('None', 'Mirror', 'Archive') -notcontains $settings.DeleteMode) {
            throw "Mapping '$($m.Name)': DeleteMode must be None, Mirror or Archive"
        }

        # Expand {Token} folders into concrete source->target pairs
        $instances = New-Object System.Collections.Generic.List[object]
        try { Expand-TokenPath -Path $m.Source -Tokens @{} -Results $instances }
        catch {
            Write-Log "[$($m.Name)] $($_.Exception.Message)" 'ERROR'
            $script:MappingFailures++
            continue
        }
        if ($m.Source -match '\{\w+\}') {
            Write-Log "[$($m.Name)] Token pattern matched $($instances.Count) source folder(s)"
        }

        foreach ($i in $instances) {
            $instName = $m.Name
            if ($i.Tokens.Count -gt 0) {
                $instName += '[' + (($i.Tokens.Keys | Sort-Object | ForEach-Object { $i.Tokens[$_] }) -join ',') + ']'
                if (-not [IO.Directory]::Exists($i.Path)) {
                    Write-Log "[$instName] $($i.Path) does not exist under this match; skipped"
                    continue
                }
            }
            $safe = $instName -replace '[^\w\-\.]', '_'
            Invoke-MappingSync @{
                Name        = $instName
                Source      = $i.Path
                Target      = Resolve-TokenString $m.Target $i.Tokens
                StateFile   = [IO.Path]::Combine($stateDir, "$safe.state.csv")
                ArchiveRoot = [IO.Path]::Combine($archiveDir, $safe)
                Settings    = $settings
            }
        }
    }
}
catch {
    $script:Fatal = $true
    Write-Log "FATAL: $($_.Exception.Message)" 'ERROR'
}
finally {
    if ($script:Changes.Count -gt 0 -and $script:LogFile) {
        $csv = [IO.Path]::ChangeExtension($script:LogFile, '.changes.csv')
        $script:Changes | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        $summary = ($script:Changes | Group-Object Result | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '
        Write-Log "Change audit: $csv  ($summary)"
    }
    if ($script:LogFile -and $config -and $config.PSObject.Properties['LogRetentionDays']) {
        $cutoff = (Get-Date).AddDays(-[int]$config.LogRetentionDays)
        Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff } | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    if ($script:Lock) { $script:Lock.Dispose() }
}

$exitCode = 0
if ($script:FileErrors -gt 0) { $exitCode = 1 }
if ($script:Fatal -or $script:MappingFailures -gt 0) { $exitCode = 2 }
Write-Log "Finished. FileErrors=$($script:FileErrors) MappingFailures=$($script:MappingFailures) ExitCode=$exitCode"
exit $exitCode
#endregion
