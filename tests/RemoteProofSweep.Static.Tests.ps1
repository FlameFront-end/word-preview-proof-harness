$ErrorActionPreference = "Stop"

$projectDir = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $projectDir "Invoke-RemoteProofSweep.ps1"

if (-not (Test-Path $scriptPath)) {
    throw "Invoke-RemoteProofSweep.ps1 is missing"
}

$scriptText = Get-Content $scriptPath -Raw
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) {
    throw "Invoke-RemoteProofSweep.ps1 has PowerShell parser errors"
}

function Assert-Contains {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Message
    )

    if ($Text -notmatch $Pattern) {
        throw $Message
    }
}

Assert-Contains $scriptText '\[string\]\$ComputerName\s*=\s*"192\.168\.200\.132"' "ComputerName default is missing"
Assert-Contains $scriptText '\[pscredential\]\$Credential' "Credential parameter is missing"
Assert-Contains $scriptText '\[int\[\]\]\$SprayCounts\s*=\s*@\(2000,\s*10000\)' "SprayCounts default is missing"
Assert-Contains $scriptText 'New-PSSession' "Remote session creation is missing"
Assert-Contains $scriptText 'Copy-Item[\s\S]*-ToSession' "Script copy to VM is missing"
Assert-Contains $scriptText 'tests\\RemoteProofSweep\.Static\.Tests\.ps1' "Remote sweep static test is not copied to the VM"
Assert-Contains $scriptText 'Register-ScheduledTask' "Interactive scheduled task registration is missing"
Assert-Contains $scriptText 'Start-ScheduledTask' "Interactive scheduled task start is missing"
Assert-Contains $scriptText 'Get-ScheduledTaskInfo' "Remote sweep does not capture scheduled task result metadata"
Assert-Contains $scriptText 'TaskLastTaskResult' "Remote report is missing scheduled task LastTaskResult"
Assert-Contains $scriptText 'TaskLastRunTime' "Remote report is missing scheduled task LastRunTime"
Assert-Contains $scriptText 'Write-RemoteFailureDiagnostics' "Remote sweep does not collect diagnostics when scheduled task completion fails"
Assert-Contains $scriptText 'New-RemoteTaskFailureResult' "Remote sweep does not synthesize a failed result for crashed scheduled tasks"
Assert-Contains $scriptText 'FailureKind\s*=\s*"scheduled-task"' "Remote scheduled task crashes are not classified as scheduled-task failures"
Assert-Contains $scriptText '\$taskInfoDuringWait\.LastTaskResult\s+-ne\s+0' "Remote wait loop does not detect nonzero scheduled task completion before the done marker"
Assert-Contains $scriptText 'Microsoft-Windows-TaskScheduler/Operational' "Remote timeout diagnostics do not inspect Task Scheduler events"
Assert-Contains $scriptText 'Application Error|Windows Error Reporting' "Remote timeout diagnostics do not inspect application crash events"
Assert-Contains $scriptText 'proof-remote-done' "Remote completion marker is missing"
Assert-Contains $scriptText 'run-proof\.ps1' "Remote run-proof invocation is missing"
Assert-Contains $scriptText 'attempt-summary-remote-\$RemoteRunIndex-\$runStamp\.csv' "Remote attempt does not use a unique per-run attempt summary"
Assert-Contains $scriptText 'attempt-ranking-remote-\$RemoteRunIndex-\$runStamp\.csv' "Remote attempt does not use a unique per-run attempt ranking"
Assert-Contains $scriptText '-AttemptSummaryPath\s+"\$runSummaryPath"' "Remote run-proof invocation does not pass the unique summary path"
Assert-Contains $scriptText '-RankingPath\s+"\$runRankingPath"' "Remote run-proof invocation does not pass the unique ranking path"
Assert-Contains $scriptText 'HasExactReuseRuntime|HasWatchHit|MarkerFound' "Success signal parsing is missing"
Assert-Contains $scriptText 'CDB_POST_PAYLOAD_ALLOC20_RETURN' "Post-payload allocation event extraction is missing"
Assert-Contains $scriptText 'BestPostPayloadAllocSize' "Remote best allocation size ranking field is missing"
Assert-Contains $scriptText 'BestPostPayloadAllocDelta' "Remote best allocation delta ranking field is missing"
Assert-Contains $scriptText 'PostPayloadAllocSummary' "Remote allocation summary field is missing"
Assert-Contains $scriptText 'ObserveMode\s*=\s*"allocdiag"' "Remote sweep does not support allocdiag mode"
Assert-Contains $scriptText 'Export-Clixml' "Machine-readable result export is missing"
Assert-Contains $scriptText '\[int\]\$DelayBetweenRunsSeconds' "Remote sweep does not expose a bounded cooldown between runs"
Assert-Contains $scriptText 'Start-Sleep\s+-Seconds\s+\$DelayBetweenRunsSeconds' "Remote sweep does not pause between scheduled task runs"
Assert-Contains $scriptText '&\s+\.\\tests\\RemoteProofSweep\.Static\.Tests\.ps1' "Remote validation does not run RemoteProofSweep.Static.Tests.ps1 on the VM"
Assert-Contains $scriptText '\$shouldStopSweep\s*=\s*\$false' "Remote sweep does not track StopOnExactReuse across all spray groups"
Assert-Contains $scriptText 'if\s*\(\$shouldStopSweep\)\s*\{\s*break\s*\}' "Remote sweep does not break the outer spray loop after StopOnExactReuse"

Write-Host "Static remote proof sweep checks passed"
