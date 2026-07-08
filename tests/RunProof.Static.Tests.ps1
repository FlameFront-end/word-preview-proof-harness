$ErrorActionPreference = "Stop"

$projectDir = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $projectDir "run-proof.ps1"
$scriptText = Get-Content $scriptPath -Raw
$fridaScriptPath = Join-Path $projectDir "tools\frida\frida-placement.js"
$fridaScriptText = Get-Content $fridaScriptPath -Raw
$triggerPreviewPath = Join-Path $projectDir "tools\preview\trigger-preview.ps1"
$triggerPreviewText = if (Test-Path $triggerPreviewPath) {
    Get-Content $triggerPreviewPath -Raw
} else {
    ""
}
$invokePreviewTriggerPath = Join-Path $projectDir "tools\preview\Invoke-PreviewTrigger.ps1"
$invokePreviewTriggerText = if (Test-Path $invokePreviewTriggerPath) {
    Get-Content $invokePreviewTriggerPath -Raw
} else {
    ""
}
$automatedPreviewPath = Join-Path $projectDir "tools\frida\Start-FridaPreviewRun.ps1"
$automatedPreviewText = if (Test-Path $automatedPreviewPath) {
    Get-Content $automatedPreviewPath -Raw
} else {
    ""
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

function Assert-NotContains {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Message
    )

    if ($Text -match $Pattern) {
        throw $Message
    }
}

function Assert-CaseSensitiveNotContains {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Message
    )

    if ($Text -cmatch $Pattern) {
        throw $Message
    }
}

$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) {
    throw "run-proof.ps1 has PowerShell parser errors"
}

Assert-Contains $scriptText '\[ValidateSet\("telemetry","full"\)\]\s*\[string\]\$Mode\s*=\s*"full"' "Mode parameter is missing"
Assert-Contains $scriptText '\[ValidateSet\("fast","deep","allocdiag"\)\]\s*\[string\]\$ObserveMode\s*=\s*"fast"' "ObserveMode parameter is missing allocdiag"
Assert-Contains $scriptText '\[ValidateRange\(1,1440\)\]\s*\[int\]\$ObserveMinutes\s*=\s*30' "ObserveMinutes ValidateRange parameter is missing"
Assert-Contains $scriptText '\[ValidateRange\(1,\s*\[int\]::MaxValue\)\]\s*\[int\]\$MaxAttempts\s*=\s*0' "MaxAttempts guard parameter is missing"
Assert-Contains $scriptText '\[ValidateRange\(1,\s*\[int\]::MaxValue\)\]\s*\[int\]\$StartFromAttempt\s*=\s*1' "StartFromAttempt parameter is missing"
Assert-Contains $scriptText '\[ValidateRange\(1,\s*\[int\]::MaxValue\)\]\s*\[int\]\$RepeatCount\s*=\s*1' "RepeatCount parameter is missing"
Assert-Contains $scriptText '\[ValidateScript\(\{\s*\$_\s+-ge\s+1\s*\}\)\]\s*\[int\[\]\]\$TableCountsOverride\s*=\s*@\(\)' "TableCountsOverride parameter validation is missing"
Assert-Contains $scriptText '\[ValidateScript\(\{\s*\$_\s+-ge\s+0\s*\}\)\]\s*\[int\[\]\]\$SprayCountsOverride\s*=\s*@\(\)' "SprayCountsOverride parameter validation is missing"
Assert-Contains $scriptText '\[string\]\$AttemptSummaryPath\s*=\s*""' "AttemptSummaryPath parameter is missing"
Assert-Contains $scriptText '\[string\]\$RankingPath\s*=\s*""' "RankingPath parameter is missing"
Assert-Contains $scriptText '\[switch\]\$AnalyzeLogs' "AnalyzeLogs parameter is missing"
Assert-Contains $scriptText '\[switch\]\$LogMemoryMetrics' "LogMemoryMetrics parameter is missing"
Assert-Contains $scriptText '\[switch\]\$DryRunPlan' "DryRunPlan parameter is missing"
Assert-Contains $scriptText '\[switch\]\$KeepArtifactsOnFailure' "KeepArtifactsOnFailure parameter is missing"
Assert-Contains $scriptText '\[switch\]\$CleanArtifactsOnSuccess' "CleanArtifactsOnSuccess parameter is missing"
Assert-Contains $scriptText '\[switch\]\$StopOnFirstRootCause' "StopOnFirstRootCause parameter is missing"
Assert-Contains $scriptText '\[switch\]\$AllowKillingExistingWord' "AllowKillingExistingWord parameter is missing"
Assert-Contains $scriptText '\[switch\]\$IUnderstandThisKillsWord' "IUnderstandThisKillsWord parameter is missing"
Assert-Contains $scriptText '\[ValidateRange\(1,1440\)\]\s*\[int\]\$HeartbeatMinutes\s*=\s*5' "HeartbeatMinutes parameter is missing"
Assert-Contains $scriptText '\[ValidateRange\(0,\s*10000\)\]\s*\[int\]\$PostPayloadAllocTraceCount\s*=\s*0' "PostPayloadAllocTraceCount diagnostic parameter is missing"
Assert-Contains $scriptText '\[ValidateRange\(0,\s*1000\)\]\s*\[int\]\$PostPayloadAllocStackCount\s*=\s*3' "PostPayloadAllocStackCount diagnostic parameter is missing"
Assert-Contains $scriptText 'if\s*\(\$ObserveMode\s+-eq\s+"allocdiag"\s+-and\s+\$PostPayloadAllocTraceCount\s+-eq\s+0\)\s*\{[\s\S]*\$PostPayloadAllocTraceCount\s*=\s*100' "Allocdiag mode does not auto-enable allocation tracing when trace count is omitted"
Assert-CaseSensitiveNotContains $scriptText '\$mode\s*=\s*"full"' "Hardcoded mode remains"
Assert-NotContains $scriptText 'Read-Host\s+"CDB finished\. Press Enter to close"' "Generated attach-helper still contains Read-Host"
Assert-Contains $scriptText '\$attachProc\s*=\s*Start-Process\s+powershell\.exe[\s\S]*?-RedirectStandardOutput\s+\$attachOut\s+-RedirectStandardError\s+\$attachErr\s+-PassThru' "Attach-helper is not started with redirected output and -PassThru into `$attachProc"
Assert-Contains $scriptText '\$attachProc\.HasExited' "Ready wait does not fail fast when attach-helper exits"
Assert-Contains $scriptText '\$attachProc\.Refresh\(\)' "Ready wait does not refresh attach-helper state"
Assert-Contains $scriptText 'CDB attach helper exited before ready flag' "Missing attach-helper early-exit error"
Assert-Contains $scriptText 'Timeout waiting for CDB ready flag' "Missing ready timeout error"
Assert-Contains $scriptText 'function\s+Write-LogTail' "Missing log tail helper"
Assert-Contains $scriptText 'function\s+Release-ComObjectQuietly' "COM release helper is missing"
Assert-Contains $scriptText 'function\s+New-WordApplicationWithRetry' "Shared Word COM retry helper is missing"
Assert-Contains $scriptText 'function\s+Invoke-PreflightCheck' "Preflight helper is missing"
Assert-Contains $scriptText 'function\s+Get-WordProcessMetrics' "Word process metrics helper is missing"
Assert-Contains $scriptText 'function\s+Write-WordMemoryMetrics' "Word memory metrics logger is missing"
Assert-Contains $scriptText 'function\s+Show-AttemptLogAnalysis' "AnalyzeLogs helper is missing"
Assert-Contains $scriptText 'function\s+Write-AttemptRanking' "Attempt ranking writer is missing"
Assert-Contains $scriptText 'function\s+Write-EffectiveConfig' "Effective config writer is missing"
Assert-Contains $scriptText 'function\s+Write-DryRunPlan' "DryRunPlan writer is missing"
Assert-Contains $scriptText 'function\s+Write-DiagnosticBundle' "Diagnostic bundle helper is missing"
Assert-Contains $scriptText 'function\s+Write-RuntimeEventSummary' "Runtime event summary helper is missing"
Assert-Contains $scriptText 'function\s+Get-PostPayloadAllocSummary' "Post-payload allocation summary helper is missing"
Assert-Contains $scriptText '\$allParsedDeltas' "Post-payload allocation summary does not parse deltas across all monitored allocation sizes"
Assert-Contains $scriptText 'ClosestAbsoluteDelta\s*=\s*if\s*\(\$allParsedDeltas\.Count\s+-gt\s+0\)' "Closest absolute allocation delta is still restricted to legacy 0x20 events"
Assert-Contains $scriptText 'BestDelta\s*=\s*if\s*\(\$bestDelta\)\s*\{\s*\$bestDelta\.Text' "Best allocation delta is not selected using parsed absolute delta ordering"
Assert-Contains $scriptText '\$sizeGroups\[\$size\]\.ToArray\(\)' "Post-payload allocation size groups are not materialized safely before sorting"
Assert-Contains $scriptText 'function\s+Get-DocxCachePath' "DOCX cache path helper is missing"
Assert-Contains $scriptText 'function\s+Copy-DocxFromCache' "DOCX cache copy helper is missing"
Assert-Contains $scriptText 'function\s+Remove-AttemptArtifacts' "Artifact cleanup helper is missing"
Assert-Contains $scriptText 'function\s+Cleanup-AttemptProcesses' "Missing attempt cleanup helper"
Assert-Contains $scriptText 'Lab-only global cleanup: this intentionally terminates all WINWORD/cdb instances to avoid dirty proof state\.' "Cleanup global lab behavior is not documented"
Assert-Contains $scriptText 'Cleanup-AttemptProcesses[\s\S]*Stop-AttemptProcess\s+-Process\s+\$AttachProcess[\s\S]*Get-Process\s+cdb' "Cleanup does not terminate attach-helper and cdb"
Assert-Contains $scriptText 'finally\s*\{[\s\S]*Cleanup-AttemptProcesses\s+-TriggerProcess\s+\$triggerProc\s+-AttachProcess\s+\$attachProc' "Run-Test does not cleanup trigger and attach-helper in finally"
Assert-Contains $scriptText '\$hasCleanedUp\s*=\s*\$false' "Run-Test does not track cleanup state"
Assert-Contains $scriptText 'if\s*\(-not\s+\$hasCleanedUp\)\s*\{[\s\S]*Cleanup-AttemptProcesses[\s\S]*\$hasCleanedUp\s*=\s*\$true' "Cleanup is not guarded by hasCleanedUp"
Assert-Contains $scriptText 'finally\s*\{[\s\S]*ReleaseComObject\(\$doc\)[\s\S]*ReleaseComObject\(\$word\)[\s\S]*\[GC\]::Collect\(\)[\s\S]*\[GC\]::WaitForPendingFinalizers\(\)' "Run-Test finally does not release Word COM objects"
Assert-Contains $scriptText 'finally\s*\{[\s\S]*ReleaseComObject\(\$sprayDoc\)' "Run-Test finally does not release sprayDoc"
Assert-Contains $scriptText 'Generate-Docx[\s\S]*ReleaseComObject\(\$doc\)[\s\S]*ReleaseComObject\(\$word\)' "Generate-Docx does not release COM objects"
Assert-Contains $scriptText '\$baselineWordPids' "Missing baseline WINWORD PID tracking"
Assert-NotContains $scriptText '\[regex\]::Replace\(' "Trigger path is still patched with regex"
Assert-Contains $scriptText '"-Path",\s*\$targetDoc' "Trigger path is not passed as an argument"
Assert-NotContains $scriptText '\$tableCells\s*\+=' "DOCX generation still appends cells with array +="
Assert-Contains $scriptText 'if\s*\(\$Rpr\)\s*\{\s*\$tableCells\s*=' "Generate-Docx keeps table cells even when Rpr is false"
Assert-NotContains $scriptText 'Runtime wait reached 30 minutes' "Runtime timeout text still hardcodes 30 minutes"
Assert-Contains $scriptText 'Runtime wait reached \$ObserveMinutes minutes without terminal CDB event\. ObserveMode=\$ObserveMode' "Runtime timeout text does not include ObserveMode and ObserveMinutes"
Assert-Contains $scriptText 'Test-IsCdbReadyLine' "Strict CDB ready-line helper is missing"
Assert-Contains $scriptText 'function\s+Get-CdbReadyLines' "CDB ready-line scanner helper is missing"
Assert-Contains $scriptText 'Get-CdbReadyLines\s+-Paths\s+@\(\$cdbLog,\s*\$attachOut\)' "Ready flag detection does not scan both cdb log and attach-helper stdout"
Assert-NotContains $scriptText '\$logContent\s*=.*Get-Content\s+\$cdbLog\s+-Raw[\s\S]*\[CDB_READY_FLAG\]' "Ready flag detection still scans raw log broadly"
Assert-Contains $scriptText '\$attachTrace\s*=\s*Join-Path\s+\$scriptDir\s+"attach-helper-\$stamp\.trace\.log"' "Attach-helper sidecar trace path is missing"
Assert-Contains $scriptText 'Add-Content\s+-LiteralPath\s+`?\$tracePath' "Generated attach-helper does not write a sidecar trace"
Assert-Contains $scriptText '`?\$readyFlagPath\s*=\s*".*?\$breakpointReadyFlag' "Generated attach-helper does not receive the CDB ready flag path"
Assert-Contains $scriptText 'Set-Content\s+-LiteralPath\s+`?\$readyFlagPath\s+-Value\s+"ready"\s+-Encoding\s+ASCII' "Generated attach-helper does not create the ready flag from CDB stdout"
Assert-Contains $scriptText 'Write-LogTail\s+-Path\s+\$AttachTrace\s+-Label\s+"attach-helper trace tail"' "Attach-helper trace tail is not printed"
Assert-Contains $scriptText '\$hasRetriedDirectCdbAttach\s*=\s*\$false' "Direct CDB fallback guard is missing"
Assert-Contains $scriptText 'Attach helper exited without startup evidence; retrying with direct cdb launch' "Direct CDB fallback message is missing"
Assert-Contains $scriptText 'Start-Process\s+-FilePath\s+\$cdb\s+-ArgumentList\s+@\("-p",\s*\[string\]\$wordPid,\s*"-cf",\s*\$cdbCmd,\s*"-logo",\s*\$cdbLog\)' "Direct CDB fallback launch is missing"
Assert-Contains $scriptText '\$triggerOut\s*=\s*Join-Path\s+\$scriptDir\s+"preview-trigger-\$stamp\.out\.log"' "PreviewTrigger stdout log path is missing"
Assert-Contains $scriptText '\$triggerErr\s*=\s*Join-Path\s+\$scriptDir\s+"preview-trigger-\$stamp\.err\.log"' "PreviewTrigger stderr log path is missing"
Assert-Contains $scriptText '\$triggerProc\s*=\s*Start-Process\s+powershell\.exe[\s\S]*?-RedirectStandardOutput\s+\$triggerOut\s+-RedirectStandardError\s+\$triggerErr\s+-PassThru' "PreviewTrigger is not started with redirected output and -PassThru"
Assert-Contains $scriptText 'Write-PreviewTriggerDiagnostics\s+-TriggerProcess\s+\$triggerProc\s+-TriggerOut\s+\$triggerOut\s+-TriggerErr\s+\$triggerErr' "PreviewTrigger diagnostics are not emitted"
Assert-Contains $scriptText '\$lastRuntimeLineIndex\s*=\s*0' "Runtime polling does not track line offset"
Assert-Contains $scriptText '\$newRuntimeLines\s*=[^\r\n]*Select-Object\s+-Skip\s+\$lastRuntimeLineIndex' "Runtime polling does not process only new lines"
Assert-NotContains $scriptText 'Get-Content\s+\$cdbLog\s+-Tail\s+1200' "Runtime polling still depends on tail window"
Assert-Contains $scriptText 'CDB_WRITE_SEARCH_ASCII' "Write search ASCII tag is missing"
Assert-Contains $scriptText 'CDB_WRITE_SEARCH_HEX' "Write search HEX tag is missing"
Assert-Contains $scriptText 'CDB_POST_PAYLOAD_ALLOC20_RETURN' "Post-payload allocation return diagnostic tag is missing"
Assert-Contains $scriptText 'CDB_POST_PAYLOAD_ALLOC_STACK' "Post-payload allocation stack diagnostic tag is missing"
Assert-NotContains $scriptText 'CDB_POST_PAYLOAD_ALLOC20_STACK' "Generic allocation stack diagnostics are mislabeled as 0x20-only"
Assert-Contains $scriptText 'CDB_POST_PAYLOAD_ALLOC_RETURN' "Multi-size post-payload allocation diagnostic tag is missing"
Assert-Contains $scriptText 'CDB_ALLOC_DIAG_COMPLETE' "Allocdiag completion tag is missing"
Assert-Contains $scriptText 'heap=%p flags=%p caller=%p tid=%x' "Post-payload allocation diagnostics do not include heap, flags, caller, and thread"
Assert-Contains $scriptText 'CDB_FRIDA_MATCHED_ALLOC20_RETURN' "Frida-matched 0x20 allocation target diagnostic tag is missing"
Assert-Contains $scriptText 'CDB_FRIDA_MATCHED_ALLOC20_STACK' "Frida-matched 0x20 allocation stack diagnostic tag is missing"
Assert-Contains $scriptText '0x00007ffeaa6850d9' "Frida-matched 0x20 allocation caller is not targeted"
Assert-Contains $scriptText 'CDB_NEAR_MISS_ALLOC30_RETURN' "Near-miss 0x30 allocation target diagnostic tag is missing"
Assert-Contains $scriptText 'CDB_NEAR_MISS_ALLOC30_STACK' "Near-miss 0x30 allocation stack diagnostic tag is missing"
Assert-Contains $scriptText '0x00007ffe4bed4a57' "Near-miss 0x30 allocation caller is not targeted"
Assert-Contains $scriptText 'r\s+@\$t14\s*=\s*0' "Frida-matched allocation stack counter is not initialized"
Assert-Contains $scriptText 'r\s+@\$t15\s*=\s*0' "Near-miss allocation stack counter is not initialized"
$rtlAllocateHeapBreakpointCount = [regex]::Matches($scriptText, 'bu\s+ntdll!RtlAllocateHeap').Count
if ($rtlAllocateHeapBreakpointCount -ne 1) {
    throw "run-proof.ps1 must keep a single RtlAllocateHeap breakpoint; duplicate breakpoints redefine CDB breakpoint 5"
}
Assert-NotContains $scriptText 'be 5;\s*be 7' "Payload release enables a duplicate targeted RtlAllocateHeap breakpoint"
Assert-NotContains $scriptText '@\$\w+\s*==\s*0x20[\s\S]{0,300}CDB_EXACT_REUSE_RUNTIME' "Exact reuse detector is still restricted to 0x20 allocations"
Assert-NotContains $scriptText '@r8\s*==\s*0x10\s*\|\|' "CDB allocation size filter uses unsupported || syntax"
Assert-Contains $scriptText "Numeric expression missing" "Runtime parser does not exclude CDB syntax error lines from evidence"
Assert-Contains $scriptText '\$hasCdbCommandError' "CDB command syntax errors are not tracked as a failure signal"
Assert-Contains $scriptText '0x10,0x20,0x30,0x40,0x50,0x60' "Allocation diagnostic size list is missing"
Assert-Contains $scriptText 'PostPayloadAllocTraceCount' "Post-payload allocation trace setting is missing from run-proof"
Assert-Contains $scriptText 'PostPayloadAllocStackCount' "Post-payload allocation stack setting is missing from run-proof"
Assert-Contains $scriptText 'CDB_PAYLOAD_RELEASE_STACK' "Payload release stack diagnostic tag is missing"
Assert-Contains $scriptText '\$searchOutputBlocks' "Parser does not inspect CDB search output blocks"
Assert-Contains $scriptText 'Run-Test\s+-DocPath\s+\$runDoc\s+-LogSuffix\s+"telemetry"\s+-SprayCount\s+0' "Telemetry mode does not run with SprayCount 0"
Assert-Contains $scriptText '\$sprayCounts\s*=\s*@\(0\)' "Default full sweep still enables spray counts"
Assert-NotContains $scriptText 'HEAP GROOMING' "Spray block still uses heap grooming wording"
Assert-Contains $scriptText 'optional pre-observation table spray' "Spray block is not documented as passive observation setup"
Assert-Contains $scriptText '\[ValidateRange\(0,\s*\[int\]::MaxValue\)\]\s*\[int\]\$SprayCount\s*=\s*0' "Run-Test SprayCount is not range validated"
Assert-NotContains $scriptText '\$sprayDoc\.ActiveWindow' "Spray block still materializes ActiveWindow COM wrappers"
Assert-NotContains $scriptText '\$sprayDoc\.Visible' "Spray block still writes unsupported Document.Visible property"
Assert-Contains $scriptText '\$sprayCompleted\s*=\s*0' "Spray block does not track completed table count"
Assert-Contains $scriptText '\$sprayCompleted\+\+' "Spray block does not increment completed table count"
Assert-Contains $scriptText 'Spray failed after \$sprayCompleted/\$SprayCount tables' "Spray failure does not report completed table count"
Assert-Contains $scriptText '\$wordMetricsBeforeSpray\s*=\s*Get-WordProcessMetrics' "Spray block does not capture Word metrics before spray"
Assert-Contains $scriptText '\$wordMetricsAfterSpray\s*=\s*Get-WordProcessMetrics' "Spray block does not capture Word metrics after spray"
Assert-Contains $scriptText 'Release-ComObjectQuietly\s+-ComObject\s+\$cellRange' "Spray loop does not release cell range COM wrapper"
Assert-Contains $scriptText 'Release-ComObjectQuietly\s+-ComObject\s+\$cell' "Spray loop does not release cell COM wrapper"
Assert-Contains $scriptText 'Release-ComObjectQuietly\s+-ComObject\s+\$table' "Spray loop does not release table COM wrapper"
Assert-Contains $scriptText 'Release-ComObjectQuietly\s+-ComObject\s+\$r' "Spray loop does not release range COM wrapper"
Assert-Contains $scriptText 'Generate-Docx[\s\S]*\$cellRange\s*=\s*\$cell\.Range[\s\S]*Release-ComObjectQuietly\s+-ComObject\s+\$cellRange' "Generate-Docx does not release table cell range wrappers"
Assert-Contains $scriptText 'Generate-Docx[\s\S]*\$font\s*=\s*\$cellRange\.Font[\s\S]*Release-ComObjectQuietly\s+-ComObject\s+\$font' "Generate-Docx does not release font wrappers"
Assert-Contains $scriptText 'Generate-Docx[\s\S]*Release-ComObjectQuietly\s+-ComObject\s+\$comment[\s\S]*Release-ComObjectQuietly\s+-ComObject\s+\$range' "Generate-Docx does not release initial range/comment wrappers"
Assert-Contains $scriptText 'Spray failed[\s\S]*throw' "Spray failure does not fail the attempt after logging"
Assert-Contains $scriptText 'try\s*\{[\s\S]*Run-Test\s+-DocPath\s+\$runDoc[\s\S]*\}\s*catch\s*\{' "Full sweep does not catch per-attempt failures"
Assert-Contains $scriptText "WINWORD cleanup failed after retry'\s*\)\s*\{\s*throw" "Full sweep does not abort on fail-closed cleanup errors"
Assert-Contains $scriptText 'Write-AttemptSummary' "Per-attempt summary writer is missing"
Assert-Contains $scriptText 'attempt-summary-schema-backup' "Attempt summary does not preserve old CSV when schema changes"
Assert-Contains $scriptText 'Attempt summary schema changed' "Attempt summary does not report schema changes"
Assert-Contains $scriptText 'AttemptId' "AttemptId is missing from attempt workflow"
Assert-Contains $scriptText 'RepeatIndex' "RepeatIndex is missing from attempt workflow"
Assert-Contains $scriptText 'effective-config\.json' "Effective config default path is missing"
Assert-Contains $scriptText 'attempt-ranking\.csv' "Attempt ranking default path is missing"
foreach ($summaryField in @(
    "DocPath",
    "CdbCommandPath",
    "TriggerOut",
    "TriggerErr",
    "AttachOut",
    "AttachErr",
    "AttachTrace",
    "DurationSeconds",
    "SprayCompleted",
    "HasBadCleanup",
    "HasBorrowedDOD",
    "HasPayloadRelease",
    "HasExactReuseRuntime",
    "HasWatchHit",
    "MarkerFound",
    "FailureKind",
    "WordPrivateBytesBeforeSpray",
    "WordPrivateBytesAfterSpray",
    "WordWorkingSetBeforeSpray",
    "WordWorkingSetAfterSpray",
    "WordVirtualBytesBeforeSpray",
    "WordVirtualBytesAfterSpray",
    "SprayDurationSeconds",
    "SprayTablesPerSecond",
    "PreviewInitializeHr",
    "PreviewTriggerExitCode",
    "PreviewTriggerHasExited",
    "PostPayloadAlloc20Count",
    "FirstPostPayloadAlloc20Delta",
    "LastPostPayloadAlloc20Delta",
    "ClosestPostPayloadAlloc20Delta",
    "PostPayloadAllocSummary",
    "BestPostPayloadAllocSize",
    "BestPostPayloadAllocDelta",
    "ClosestPositivePostPayloadAllocDelta",
    "ClosestNegativePostPayloadAllocDelta",
    "ClosestAbsolutePostPayloadAllocDelta",
    "RootCauseToExactReuseLines",
    "ExactReuseToWriteLines"
)) {
    Assert-Contains $scriptText $summaryField "Attempt summary/result is missing $summaryField"
}
Assert-Contains $scriptText 'Show-AttemptLogAnalysis\s+-SummaryPath\s+\$AttemptSummaryPath' "AnalyzeLogs mode is not wired to attempt summary"
Assert-Contains $scriptText 'Format-Table\s+Attempt,Tables,CustomXml,Rpr,Order,SprayCount,SprayCompleted,HasBadCleanup,HasExactReuseRuntime,HasWatchHit,MarkerFound,PostPayloadAlloc20Count,DurationSeconds,FailureKind' "AnalyzeLogs does not print the requested table columns"
Assert-Contains $scriptText 'Write-WordMemoryMetrics\s+-Label\s+"before-spray"' "Memory metrics before spray are not logged"
Assert-Contains $scriptText 'Write-WordMemoryMetrics\s+-Label\s+"after-spray"' "Memory metrics after spray are not logged"
Assert-Contains $scriptText 'Write-WordMemoryMetrics\s+-Label\s+"before-trigger"' "Memory metrics before trigger are not logged"
Assert-Contains $scriptText 'Write-WordMemoryMetrics\s+-Label\s+"after-cleanup"' "Memory metrics after cleanup are not logged"
Assert-NotContains $scriptText '\[switch\]\$UseFridaPlacement' "Active Frida placement mode must not be implemented in wrapper"
Assert-NotContains $scriptText '\[switch\]\$EnableDynamicGrooming' "Dynamic controlled grooming mode must not be implemented in wrapper"
Assert-NotContains $scriptText '\[switch\]\$RepeatBest' "RepeatBest mode must not be implemented in wrapper"
Assert-Contains $scriptText 'Get-FirstRuntimeEventIndex' "Runtime parser does not derive first event line indices"
Assert-Contains $scriptText 'Write-AttemptRanking\s+-SummaryPath\s+\$AttemptSummaryPath\s+-RankingPath\s+\$RankingPath' "Attempt ranking is not written after full sweep"
Assert-Contains $scriptText 'Write-DryRunPlan[\s\S]*return' "DryRunPlan path does not exit before execution"
Assert-Contains $scriptText 'Invoke-PreflightCheck' "Preflight is not invoked"
Assert-Contains $scriptText 'Write-EffectiveConfig' "Effective config is not written"
Assert-Contains $scriptText 'Write-DiagnosticBundle' "Diagnostic bundle is not used"
Assert-Contains $scriptText 'Write-RuntimeEventSummary\s+-CdbLog\s+\$cdbLog' "Runtime event summary is not emitted"
Assert-Contains $scriptText 'Get-PostPayloadAllocSummary\s+-RuntimeEventLines\s+\$runtimeEventLines' "Post-payload allocation summary is not parsed"
Assert-Contains $scriptText 'Copy-DocxFromCache\s+-Tables\s+\$tables\s+-CustomXml\s+\$custom\s+-Rpr\s+\$rpr\s+-Order\s+\$order\s+-OutputPath\s+\$runDoc' "Full sweep does not use DOCX cache"
Assert-Contains $scriptText 'CDB_ALLOC_DIAG_COMPLETE' "Allocdiag completion event is not used"
Assert-Contains $scriptText 'Heartbeat' "Runtime heartbeat logging is missing"
Assert-Contains $scriptText 'CleanArtifactsOnSuccess' "Success artifact cleanup knob is not used"
Assert-Contains $scriptText 'KeepArtifactsOnFailure' "Failure artifact retention knob is not used"
Assert-Contains $scriptText 'StopOnFirstRootCause' "StopOnFirstRootCause knob is not used"

if (-not (Test-Path $invokePreviewTriggerPath)) {
    throw "Invoke-PreviewTrigger.ps1 is missing"
}

$invokePreviewTokens = $null
$invokePreviewErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($invokePreviewTriggerPath, [ref]$invokePreviewTokens, [ref]$invokePreviewErrors) | Out-Null
if ($invokePreviewErrors.Count -gt 0) {
    throw "Invoke-PreviewTrigger.ps1 has PowerShell parser errors"
}

Assert-Contains $invokePreviewTriggerText 'Add-Ole32NativeTypes' "Invoke-PreviewTrigger.ps1 does not use a stable native type loader"
Assert-Contains $invokePreviewTriggerText 'PreviewTrigger\.Ole32Native\.dll' "Invoke-PreviewTrigger.ps1 does not compile native helper to a stable assembly path"
Assert-Contains $invokePreviewTriggerText 'Add-Type\s+-Path\s+\$assemblyPath' "Invoke-PreviewTrigger.ps1 does not load native helper from stable assembly path"
Assert-Contains $invokePreviewTriggerText 'Add-Type\s+-TypeDefinition\s+\$Source\s+-OutputAssembly\s+\$assemblyPath' "Invoke-PreviewTrigger.ps1 does not compile native helper with OutputAssembly"

$attachHelperMatches = [regex]::Matches(
    $scriptText,
    '(?s)@"\r?\n(?<body>.*?)\r?\n"@\s*\|\s*Set-Content\s+\$cdbAttachPs1'
)
if ($attachHelperMatches.Count -ne 1) {
    throw "Expected exactly one generated attach-helper heredoc"
}

$attachHelperText = $attachHelperMatches[0].Groups["body"].Value
Assert-NotContains $attachHelperText '\bRead-Host\b' "Generated attach-helper heredoc contains Read-Host"
Assert-NotContains $attachHelperText '\bWrite-Host\b' "Generated attach-helper heredoc contains Write-Host"
Assert-NotContains $attachHelperText '(?m)^\s*Pause\s*$' "Generated attach-helper heredoc contains Pause"
Assert-NotContains $attachHelperText '(?i)\bcmd(?:\.exe)?\s+/k\b' "Generated attach-helper heredoc contains cmd /k"
Assert-Contains $attachHelperText '\bWrite-Output\b' "Generated attach-helper heredoc does not use Write-Output"
Assert-Contains $attachHelperText 'Get-Date\s+-Format\s+o' "Generated attach-helper heredoc does not log timestamp"
Assert-Contains $attachHelperText 'Get-Process\s+-Id\s+`?\$targetPid' "Generated attach-helper heredoc does not check target PID"
Assert-Contains $attachHelperText 'exit\s+2' "Generated attach-helper heredoc does not exit 2 when target PID is missing"
Assert-Contains $attachHelperText 'Test-Path\s+-LiteralPath\s+`?\$cdbPath' "Generated attach-helper heredoc does not check cdb path"
Assert-Contains $attachHelperText 'Test-Path\s+-LiteralPath\s+`?\$commandFilePath' "Generated attach-helper heredoc does not check command file path"
Assert-Contains $attachHelperText 'System\.Diagnostics\.ProcessStartInfo' "Generated attach-helper heredoc does not start cdb through ProcessStartInfo"
Assert-Contains $attachHelperText 'StandardOutput\.ReadLine\(\)' "Generated attach-helper heredoc does not monitor cdb stdout"
Assert-Contains $attachHelperText '`?\$cdbProcess\.ExitCode' "Generated attach-helper heredoc does not report cdb exit code"
Assert-Contains $attachHelperText 'exit\s+`?\$cdbProcess\.ExitCode' "Generated attach-helper heredoc does not exit with cdb exit code"
Assert-Contains $attachHelperText '`?\$_\.Exception\.ToString\(\)' "Generated attach-helper heredoc does not print full exception"
Assert-Contains $attachHelperText 'exit\s+1' "Generated attach-helper heredoc does not exit 1 from catch"

$fastTerminalMatch = [regex]::Match(
    $scriptText,
    '(?s)\$fastTerminalPatterns\s*=\s*@\((?<body>.*?)\)'
)
if (-not $fastTerminalMatch.Success) {
    throw "Fast terminal pattern list is missing"
}
$fastTerminalText = $fastTerminalMatch.Groups["body"].Value
foreach ($eventName in @(
    "CDB_BAD_CLEANUP_FDISPOSE",
    "CDB_PAYLOAD_RELEASE_ENTER",
    "CDB_PAYLOAD_AFTER",
    "CDB_BAD_CLEANUP_RET",
    "CDB_EXACT_REUSE_RUNTIME",
    "CDB_WRITE_TO_REUSED_SLOT",
    "Access violation"
)) {
    Assert-Contains $fastTerminalText ([regex]::Escape($eventName)) "Fast terminal patterns missing $eventName"
}

$deepTerminalMatch = [regex]::Match(
    $scriptText,
    '(?s)\$deepTerminalPatterns\s*=\s*@\((?<body>.*?)\)'
)
if (-not $deepTerminalMatch.Success) {
    throw "Deep terminal pattern list is missing"
}
$deepTerminalText = $deepTerminalMatch.Groups["body"].Value
foreach ($eventName in @(
    "CDB_WRITE_TO_REUSED_SLOT",
    "Access violation"
)) {
    Assert-Contains $deepTerminalText ([regex]::Escape($eventName)) "Deep terminal patterns missing $eventName"
}
foreach ($eventName in @(
    "CDB_BAD_CLEANUP_FDISPOSE",
    "CDB_PAYLOAD_RELEASE_ENTER",
    "CDB_PAYLOAD_AFTER",
    "CDB_BAD_CLEANUP_RET",
    "CDB_EXACT_REUSE_RUNTIME"
)) {
    Assert-NotContains $deepTerminalText ([regex]::Escape($eventName)) "Deep terminal patterns include fast-only event $eventName"
}

$deepProgressMatch = [regex]::Match(
    $scriptText,
    '(?s)\$deepProgressPatterns\s*=\s*@\((?<body>.*?)\)'
)
if (-not $deepProgressMatch.Success) {
    throw "Deep progress pattern list is missing"
}
$deepProgressText = $deepProgressMatch.Groups["body"].Value
foreach ($eventName in @(
    "CDB_BAD_CLEANUP_FDISPOSE",
    "CDB_PAYLOAD_RELEASE_ENTER",
    "CDB_PAYLOAD_AFTER",
    "CDB_BAD_CLEANUP_RET",
    "CDB_EXACT_REUSE_RUNTIME"
)) {
    Assert-Contains $deepProgressText ([regex]::Escape($eventName)) "Deep progress patterns missing $eventName"
}

Assert-Contains $scriptText 'CDB_HROPEN_PREVIEWER_DOC_ENTER' "CDB event name missing: CDB_HROPEN_PREVIEWER_DOC_ENTER"
Assert-Contains $scriptText 'CDB_DOC_LOOKUP_ENTER' "CDB event name missing: CDB_DOC_LOOKUP_ENTER"
Assert-Contains $scriptText 'CDB_DOC_LOOKUP_RET' "CDB event name missing: CDB_DOC_LOOKUP_RET"
Assert-Contains $scriptText 'CDB_FDISPOSE_ANY' "CDB event name missing: CDB_FDISPOSE_ANY"
Assert-Contains $scriptText 'wwlib\+0xd96c80' "CDB command offset missing: wwlib+0xd96c80"
Assert-Contains $scriptText 'wwlib\+0x508bc0' "CDB command offset missing: wwlib+0x508bc0"
Assert-Contains $scriptText 'wwlib\+0x8cc38' "CDB command offset missing: wwlib+0x8cc38"
Assert-Contains $scriptText 'wwlib\+0xd971cf' "CDB command offset missing: wwlib+0xd971cf"
Assert-Contains $scriptText 'wwlib\+0x7a140' "CDB command offset missing: wwlib+0x7a140"
Assert-Contains $scriptText 'ntdll!RtlAllocateHeap' "CDB command string missing: ntdll!RtlAllocateHeap"

Assert-Contains $fridaScriptText 'var MAX_REUSE_ATTEMPTS\s*=\s*' "Frida placement script is missing a reuse attempt limit"
Assert-Contains $fridaScriptText 'Process\.getCurrentThreadId\(\)' "Frida placement script does not track current thread"
Assert-Contains $fridaScriptText 'freedPayloadHeap' "Frida placement script does not store payload free heap"
Assert-Contains $fridaScriptText 'freedPayloadThreadId' "Frida placement script does not store payload free thread"
Assert-Contains $fridaScriptText 'PayloadVtable\s*=\s*wwlibBase\.add\(0x2281f60\)' "Frida placement script does not use the confirmed payload vtable offset"
Assert-Contains $fridaScriptText 'readPointerValue\(ptr\)' "Frida placement script does not read candidate free vtable"
Assert-Contains $fridaScriptText 'function\s+readPointerValue' "Frida placement script does not use a Frida 17-compatible pointer read helper"
Assert-Contains $fridaScriptText 'vt\.equals\(PayloadVtable\)' "Frida placement script does not filter frees by payload vtable"
Assert-NotContains $fridaScriptText 'freedCandidateDOD' "Frida placement script still uses DOD as payload-free identity"
Assert-Contains $fridaScriptText 'retval\.toInt32\(\)\s*!==\s*0' "Frida placement script does not confirm successful RtlFreeHeap completion"
Assert-Contains $fridaScriptText 'allocationState\.heap\.equals\(freedPayloadHeap\)' "Frida placement script does not match allocation heap to free heap"
Assert-Contains $fridaScriptText 'allocationState\.threadId\s*!==\s*freedPayloadThreadId' "Frida placement script does not match allocation thread to free thread"
Assert-Contains $fridaScriptText 'pushCallState' "Frida placement script does not store per-call hook state outside Frida callback context"
Assert-Contains $fridaScriptText 'popCallState' "Frida placement script does not restore per-call hook state outside Frida callback context"
Assert-NotContains $fridaScriptText 'this\.\w+\s*=' "Frida placement script writes to Frida callback context properties"
Assert-Contains $fridaScriptText 'isFreedPayloadSlotReadable' "Frida placement script does not verify the freed slot before replacement"
Assert-Contains $fridaScriptText 'writeUtf8StringValue\(reusedPtr,\s*"TBL_41414141"\)' "Frida placement script does not write marker through a Frida 17-compatible helper"
Assert-Contains $fridaScriptText 'function\s+writeUtf8StringValue' "Frida placement script does not define marker write helper"
Assert-NotContains $fridaScriptText 'Memory\.writeUtf8String' "Frida placement script still uses unsupported Memory.writeUtf8String"
Assert-Contains $fridaScriptText 'console\.log\("\[STACK\]"\)' "Frida placement script does not print a stack marker after reuse"
Assert-Contains $fridaScriptText 'Thread\.backtrace\(' "Frida placement script does not capture a backtrace after reuse"
Assert-Contains $fridaScriptText 'Backtracer\.ACCURATE' "Frida placement script does not use the accurate backtracer"
Assert-Contains $fridaScriptText 'Backtracer\.FUZZY' "Frida placement script does not fall back to fuzzy backtracing"
Assert-Contains $fridaScriptText '\.slice\(0,\s*20\)' "Frida placement script does not limit reuse stack frames to 20"
Assert-Contains $fridaScriptText 'DebugSymbol\.fromAddress' "Frida placement script does not symbolize reuse stack frames"
Assert-Contains $fridaScriptText 'moduleName' "Frida placement script does not include frame module names"
Assert-Contains $fridaScriptText 'hasLoggedReuseStack' "Frida placement script does not guard stack output against duplication"
Assert-Contains $fridaScriptText 'FRIDA_SCRIPT_VERSION payload-release-stack-v7' "Frida placement script does not print its stack-scan version"
Assert-Contains $fridaScriptText 'STACK_SCAN_WWLIB' "Frida placement script does not print scanned wwlib stack frames"
Assert-Contains $fridaScriptText 'scanWwlibStackFrames' "Frida placement script does not scan raw stack memory for wwlib return addresses"
Assert-Contains $fridaScriptText 'installMallocBaseDiagnostics' "Frida placement script does not hook malloc_base for caller stack capture"
Assert-Contains $fridaScriptText 'WINWORD\.EXE!malloc_base' "Frida placement script does not resolve WINWORD.EXE malloc_base"
Assert-Contains $fridaScriptText 'MALLOC_BASE' "Frida placement script does not log malloc_base hook status"
Assert-Contains $fridaScriptText 'installMallocBaseFromAllocatorCaller' "Frida placement script does not learn malloc_base from allocator caller frames"
Assert-Contains $fridaScriptText 'MALLOC_BASE_CAPTURE' "Frida placement script does not log malloc_base stack capture"
Assert-Contains $fridaScriptText 'installCoTaskMemAllocDiagnostics' "Frida placement script does not hook CoTaskMemAlloc for caller stack capture"
Assert-Contains $fridaScriptText 'COTASKMEMALLOC_CAPTURE' "Frida placement script does not log CoTaskMemAlloc stack capture"
Assert-Contains $fridaScriptText 'Stalker\.follow' "Frida placement script does not trace wwlib calls after payload free"
Assert-Contains $fridaScriptText 'WWLIB_CALL_TRACE' "Frida placement script does not print wwlib call trace diagnostics"
Assert-Contains $fridaScriptText 'Stalker\.unfollow' "Frida placement script does not stop wwlib call tracing"
Assert-Contains $fridaScriptText 'PAYLOAD_FREE_STACK' "Frida placement script does not print payload free stack diagnostics"
Assert-Contains $fridaScriptText 'PAYLOAD_FREE_STACK_SCAN_WWLIB' "Frida placement script does not print payload free wwlib stack scan diagnostics"
Assert-Contains $fridaScriptText 'freedPayloadStackFrames' "Frida placement script does not preserve payload free stack frames"
Assert-Contains $fridaScriptText 'PAYLOAD_RELEASE_STACK' "Frida placement script does not print payload release stack diagnostics"
Assert-Contains $fridaScriptText 'PAYLOAD_RELEASE_STACK_SCAN_WWLIB' "Frida placement script does not print payload release wwlib stack scan diagnostics"
Assert-Contains $fridaScriptText 'payloadReleaseStackFrames' "Frida placement script does not preserve payload release stack frames"
Assert-Contains $fridaScriptText 'count=' "Frida placement script does not print diagnostic frame counts"
Assert-Contains $fridaScriptText 'function\s+logTraceFrame' "Frida placement script does not use a shared trace frame formatter"
Assert-Contains $fridaScriptText 'wwlib\+0x' "Frida placement script does not print wwlib-relative offsets"
Assert-Contains $fridaScriptText 'reuseAttempts\s*>?=\s*MAX_REUSE_ATTEMPTS' "Frida placement script does not fail after max reuse attempts"
Assert-Contains $fridaScriptText 'Process\.exit\(1\)' "Frida placement script does not exit on failed reuse attempts"
Assert-Contains $fridaScriptText 'Process\.id' "Frida placement script does not print the attached PID"
Assert-Contains $fridaScriptText 'FRIDA_HEARTBEAT' "Frida placement script does not emit hook heartbeat diagnostics"
Assert-Contains $fridaScriptText 'freeCallCount' "Frida placement script does not count RtlFreeHeap calls"
Assert-Contains $fridaScriptText 'alloc20CallCount' "Frida placement script does not count 0x20 allocations"
Assert-Contains $fridaScriptText 'fDisposeCallCount' "Frida placement script does not count FDisposeDocCore calls"
Assert-Contains $fridaScriptText 'FDISPOSE_ANY' "Frida placement script does not show broad FDispose diagnostics"
Assert-Contains $fridaScriptText 'FRIDA_HROPEN_PREVIEWER_DOC_ENTER' "Frida placement script is missing previewer entry diagnostics"
Assert-Contains $fridaScriptText 'FRIDA_DOC_LOOKUP_ENTER' "Frida placement script is missing document lookup diagnostics"
Assert-Contains $fridaScriptText 'FRIDA_DOC_LOOKUP_RET' "Frida placement script is missing document lookup return diagnostics"
Assert-Contains $fridaScriptText 'FRIDA_PAYLOAD_RELEASE_ENTER' "Frida placement script is missing payload release diagnostics"
Assert-Contains $fridaScriptText 'badCleanupDepth' "Frida placement script does not track the bad cleanup window"
Assert-Contains $fridaScriptText 'FRIDA_PAYLOAD_RELEASE_WINDOW' "Frida placement script does not log payload release candidates during bad cleanup"
Assert-Contains $fridaScriptText 'FRIDA_PAYLOAD_RELEASE_UNREADABLE' "Frida placement script does not log unreadable payload release candidates"
Assert-Contains $fridaScriptText 'payloadReleaseAfterBadCleanupLogBudget' "Frida placement script does not log payload release candidates after bad cleanup"
Assert-Contains $fridaScriptText 'lastBadCleanupDOD' "Frida placement script does not record the bad cleanup DOD"
Assert-Contains $fridaScriptText 'Interceptor\.attach\(badCleanupRet' "Frida placement script does not reset the bad cleanup window"

if (-not (Test-Path $triggerPreviewPath)) {
    throw "trigger-preview.ps1 is missing"
}

$triggerTokens = $null
$triggerErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($triggerPreviewPath, [ref]$triggerTokens, [ref]$triggerErrors) | Out-Null
if ($triggerErrors.Count -gt 0) {
    throw "trigger-preview.ps1 has PowerShell parser errors"
}

Assert-Contains $triggerPreviewText '\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[ValidateScript\(\{\s*Test-Path\s+-LiteralPath\s+\$_\s+-PathType\s+Leaf\s*\}\)\]\s*\[string\]\$Path' "trigger-preview.ps1 does not require an existing DOCX path"
Assert-Contains $triggerPreviewText '\[ValidateRange\(5,\s*10\)\]\s*\[int\]\$WaitSeconds\s*=\s*8' "trigger-preview.ps1 does not wait 5-10 seconds for Frida"
Assert-Contains $triggerPreviewText '\[ValidateRange\(1,\s*30\)\]\s*\[int\]\$CoCreateRetryCount\s*=\s*10' "trigger-preview.ps1 does not retry transient CoCreateInstance failures"
Assert-Contains $triggerPreviewText '\[ValidateRange\(100,\s*5000\)\]\s*\[int\]\$CoCreateRetryDelayMs\s*=\s*1000' "trigger-preview.ps1 does not delay between CoCreateInstance retries"
Assert-Contains $triggerPreviewText '\$ErrorActionPreference\s*=\s*"Stop"' "trigger-preview.ps1 does not stop on errors"
Assert-Contains $triggerPreviewText '84F66100-FF7C-4FB4-B0C0-02CD7FB668FE' "trigger-preview.ps1 uses the wrong preview handler CLSID"
Assert-Contains $triggerPreviewText 'B7D14566-0509-4CCE-A71F-0A554233BD9B' "trigger-preview.ps1 does not request IInitializeWithFile"
Assert-Contains $triggerPreviewText 'CoCreateInstance' "trigger-preview.ps1 does not use CoCreateInstance"
Assert-Contains $triggerPreviewText 'for\s*\(\$attempt\s*=\s*1;\s*\$attempt\s*-le\s*\$RetryCount' "trigger-preview.ps1 does not loop over CoCreateInstance attempts"
Assert-Contains $triggerPreviewText 'Start-Sleep\s+-Milliseconds\s+\$RetryDelayMs' "trigger-preview.ps1 does not sleep between CoCreateInstance attempts"
Assert-Contains $triggerPreviewText 'InitializeWithFileDelegate' "trigger-preview.ps1 does not call IInitializeWithFile.Initialize"
Assert-Contains $triggerPreviewText 'ReadIntPtr\(\$vtbl,\s*3\s*\*\s*\[IntPtr\]::Size\)' "trigger-preview.ps1 does not call vtable slot 3"
Assert-Contains $triggerPreviewText 'Start-Sleep\s+-Seconds\s+\$WaitSeconds' "trigger-preview.ps1 does not wait for Frida after Initialize"
Assert-Contains $triggerPreviewText 'Marshal\]::Release\(\$ppv\)' "trigger-preview.ps1 does not release the COM pointer"
Assert-NotContains $triggerPreviewText '\$ReadyFile|\$GoFile' "trigger-preview.ps1 still contains run-proof synchronization parameters"
Assert-NotContains $triggerPreviewText 'New-Object\s+-ComObject\s+Word\.Application|Get-Process\s+WINWORD|Stop-Process|Documents\.Open|Documents\.Add' "trigger-preview.ps1 manages Word processes or documents"

if (-not (Test-Path $automatedPreviewPath)) {
    throw "Start-FridaPreviewRun.ps1 is missing"
}

$automatedTokens = $null
$automatedErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($automatedPreviewPath, [ref]$automatedTokens, [ref]$automatedErrors) | Out-Null
if ($automatedErrors.Count -gt 0) {
    throw "Start-FridaPreviewRun.ps1 has PowerShell parser errors"
}

Assert-Contains $automatedPreviewText '\[ValidateScript\(\{\s*Test-Path\s+-LiteralPath\s+\$_\s+-PathType\s+Leaf\s*\}\)\]\s*\[string\]\$DocPath' "Start-FridaPreviewRun.ps1 does not require an existing DOCX path"
Assert-Contains $automatedPreviewText '\[string\]\$WordPath\s*=\s*"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD\.EXE"' "Start-FridaPreviewRun.ps1 does not default to Office16 WINWORD.EXE"
Assert-Contains $automatedPreviewText '\[string\]\$FridaScriptPath\s*=\s*""' "Start-FridaPreviewRun.ps1 does not accept a Frida script path"
Assert-Contains $automatedPreviewText '\[string\]\$TriggerScriptPath\s*=\s*""' "Start-FridaPreviewRun.ps1 does not accept a trigger script path"
Assert-Contains $automatedPreviewText '\$scriptDirectory\s*=\s*if\s*\(\$PSScriptRoot\)' "Start-FridaPreviewRun.ps1 does not resolve script directory after parameter binding"
Assert-Contains $automatedPreviewText 'Join-Path\s+\$scriptDirectory\s+"frida-placement\.js"' "Start-FridaPreviewRun.ps1 does not default Frida script from script directory"
Assert-Contains $automatedPreviewText 'Join-Path\s+\(Split-Path\s+-Parent\s+\$scriptDirectory\)\s+"preview\\trigger-preview\.ps1"' "Start-FridaPreviewRun.ps1 does not default trigger script from tools preview directory"
Assert-Contains $automatedPreviewText 'function\s+Copy-ItemUnlessSamePath' "Start-FridaPreviewRun.ps1 does not avoid copying a file over itself"
Assert-Contains $automatedPreviewText '\$resolvedSourcePath\s+-ieq\s+\$resolvedDestinationPath' "Start-FridaPreviewRun.ps1 does not detect identical source and destination paths"
Assert-Contains $automatedPreviewText 'Copy-ItemUnlessSamePath\s+-SourcePath\s+\$FridaScriptPath\s+-DestinationPath\s+\$labFridaScriptPath' "Start-FridaPreviewRun.ps1 does not stage the Frida script"
Assert-Contains $automatedPreviewText 'Copy-ItemUnlessSamePath\s+-SourcePath\s+\$TriggerScriptPath\s+-DestinationPath\s+\$labTriggerScriptPath' "Start-FridaPreviewRun.ps1 does not stage the trigger script"
Assert-Contains $automatedPreviewText 'Stop-Process\s+-Force' "Start-FridaPreviewRun.ps1 does not close existing Word processes"
Assert-Contains $automatedPreviewText 'New-WordApplicationWithRetry' "Start-FridaPreviewRun.ps1 does not start Word through COM"
Assert-Contains $automatedPreviewText '\$word\.Documents\.Open\(\$resolvedDocPath\)' "Start-FridaPreviewRun.ps1 does not open the DOCX through Word COM"
Assert-Contains $automatedPreviewText 'Get-TargetWordProcessId' "Start-FridaPreviewRun.ps1 does not identify the COM-started Word PID"
Assert-Contains $automatedPreviewText 'Release-ComObjectQuietly' "Start-FridaPreviewRun.ps1 does not release Word COM wrappers"
Assert-Contains $automatedPreviewText 'Start-Process\s+`?\s*-FilePath\s+"frida"' "Start-FridaPreviewRun.ps1 does not start Frida"
Assert-Contains $automatedPreviewText '"-p"' "Start-FridaPreviewRun.ps1 does not attach Frida by PID"
Assert-Contains $automatedPreviewText 'FRIDA_HEARTBEAT|Frida placement control script fully loaded' "Start-FridaPreviewRun.ps1 does not wait for Frida readiness"
Assert-Contains $automatedPreviewText 'FRIDA_BAD_CLEANUP_RET' "Start-FridaPreviewRun.ps1 does not summarize bad cleanup return diagnostics"
Assert-Contains $automatedPreviewText 'STACK_SCAN_WWLIB' "Start-FridaPreviewRun.ps1 does not summarize scanned wwlib stack frames"
Assert-Contains $automatedPreviewText 'FRIDA_SCRIPT_VERSION' "Start-FridaPreviewRun.ps1 does not summarize the Frida script version"
Assert-Contains $automatedPreviewText 'MALLOC_BASE' "Start-FridaPreviewRun.ps1 does not summarize malloc_base hook status"
Assert-Contains $automatedPreviewText 'COTASKMEMALLOC' "Start-FridaPreviewRun.ps1 does not summarize CoTaskMemAlloc hook status"
Assert-Contains $automatedPreviewText 'WWLIB_CALL_TRACE' "Start-FridaPreviewRun.ps1 does not summarize wwlib call trace diagnostics"
Assert-Contains $automatedPreviewText 'PAYLOAD_FREE_STACK' "Start-FridaPreviewRun.ps1 does not summarize payload free stack diagnostics"
Assert-Contains $automatedPreviewText 'PAYLOAD_RELEASE_STACK' "Start-FridaPreviewRun.ps1 does not summarize payload release stack diagnostics"
Assert-Contains $automatedPreviewText 'trigger-preview\.ps1' "Start-FridaPreviewRun.ps1 does not invoke trigger-preview.ps1"
Assert-Contains $automatedPreviewText 'CoCreateRetryCount' "Start-FridaPreviewRun.ps1 does not pass CoCreate retry settings to trigger-preview.ps1"
Assert-Contains $automatedPreviewText '\[ValidateRange\(1,\s*50\)\]\s*\[int\]\$MaxAttempts\s*=\s*5' "Start-FridaPreviewRun.ps1 does not retry full proof attempts"
Assert-Contains $automatedPreviewText 'if\s*\(\$MaxAttempts\s+-gt\s+1\)' "Start-FridaPreviewRun.ps1 does not run retry controller mode"
Assert-Contains $automatedPreviewText 'attempt \$attempt/\$MaxAttempts' "Start-FridaPreviewRun.ps1 does not log retry attempt numbers"
Assert-Contains $automatedPreviewText '"-MaxAttempts",\s*"1"' "Start-FridaPreviewRun.ps1 retry controller does not run child attempts one at a time"
Assert-Contains $automatedPreviewText 'proof succeeded on attempt' "Start-FridaPreviewRun.ps1 does not stop on first successful proof"
Assert-Contains $automatedPreviewText '\$triggerFailure\s*=' "Start-FridaPreviewRun.ps1 does not preserve trigger failure for post-observation reporting"
Assert-Contains $automatedPreviewText 'function\s+Test-FridaMarkerWritten' "Start-FridaPreviewRun.ps1 does not detect Frida marker writes"
Assert-Contains $automatedPreviewText 'TBL_41414141' "Start-FridaPreviewRun.ps1 does not use marker write as proof success"
Assert-Contains $automatedPreviewText 'proof achieved: Frida marker write observed' "Start-FridaPreviewRun.ps1 does not report proof success"
Assert-Contains $automatedPreviewText '\$triggerFailure\s*=\s*\$null' "Start-FridaPreviewRun.ps1 does not suppress trigger failure after proof success"
Assert-Contains $automatedPreviewText 'if\s*\(\$triggerFailure\)\s*\{\s*throw\s+\$triggerFailure\s*\}' "Start-FridaPreviewRun.ps1 does not throw trigger failure after Frida summary"
Assert-Contains $automatedPreviewText '\$triggerErrorLogPath\s*=\s*Join-Path' "Start-FridaPreviewRun.ps1 does not keep trigger stderr separate"
Assert-Contains $automatedPreviewText 'RedirectStandardError\s+\$triggerErrorLogPath' "Start-FridaPreviewRun.ps1 redirects trigger stderr to the stdout log"
Assert-Contains $automatedPreviewText 'Get-Content\s+-LiteralPath\s+\$FridaLogPath' "Start-FridaPreviewRun.ps1 does not read the Frida log"

Write-Host "Static run-proof checks passed"
