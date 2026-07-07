param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$DocPath,

    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$WordPath = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",

    [string]$FridaScriptPath = "",

    [string]$TriggerScriptPath = "",

    [string]$LabDirectory = "C:\CVELAB\final",

    [ValidateRange(10, 120)]
    [int]$ReadyTimeoutSeconds = 40,

    [ValidateRange(5, 60)]
    [int]$ObserveSeconds = 15,

    [ValidateRange(1, 30)]
    [int]$CoCreateRetryCount = 15,

    [ValidateRange(1, 50)]
    [int]$MaxAttempts = 5,

    [switch]$KeepWordOpen
)

$ErrorActionPreference = "Stop"

$scriptDirectory = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($PSCommandPath) {
    Split-Path -Parent $PSCommandPath
} else {
    (Get-Location).ProviderPath
}

if ([string]::IsNullOrWhiteSpace($FridaScriptPath)) {
    $FridaScriptPath = Join-Path $scriptDirectory "frida-placement.js"
}

if ([string]::IsNullOrWhiteSpace($TriggerScriptPath)) {
    $TriggerScriptPath = Join-Path (Split-Path -Parent $scriptDirectory) "preview\trigger-preview.ps1"
}

if (-not (Test-Path -LiteralPath $FridaScriptPath -PathType Leaf)) {
    throw "Frida script not found: $FridaScriptPath"
}

if (-not (Test-Path -LiteralPath $TriggerScriptPath -PathType Leaf)) {
    throw "Trigger script not found: $TriggerScriptPath"
}

if ($MaxAttempts -gt 1) {
    $scriptPath = if ($PSCommandPath) {
        $PSCommandPath
    } else {
        Join-Path $scriptDirectory "Start-FridaPreviewRun.ps1"
    }

    $lastExitCode = 1
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Host "[AUTO_STAGE] attempt $attempt/$MaxAttempts"
        $arguments = @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $scriptPath,
            "-DocPath",
            $DocPath,
            "-WordPath",
            $WordPath,
            "-FridaScriptPath",
            $FridaScriptPath,
            "-TriggerScriptPath",
            $TriggerScriptPath,
            "-LabDirectory",
            $LabDirectory,
            "-ReadyTimeoutSeconds",
            [string]$ReadyTimeoutSeconds,
            "-ObserveSeconds",
            [string]$ObserveSeconds,
            "-CoCreateRetryCount",
            [string]$CoCreateRetryCount,
            "-MaxAttempts",
            "1"
        )

        if ($KeepWordOpen) {
            $arguments += "-KeepWordOpen"
        }

        & powershell.exe @arguments
        $lastExitCode = $LASTEXITCODE
        if ($lastExitCode -eq 0) {
            Write-Host "[AUTO_STAGE] proof succeeded on attempt $attempt/$MaxAttempts"
            exit 0
        }

        Write-Host "[AUTO_STAGE] attempt $attempt/$MaxAttempts failed with exit code $lastExitCode"
        Start-Sleep -Seconds 2
    }

    Write-Host "[AUTO_STAGE] proof failed after $MaxAttempts attempts"
    exit $lastExitCode
}

function Write-Stage {
    param([string]$Message)

    Write-Host "[AUTO_STAGE] $Message"
}

function Wait-ForCondition {
    param(
        [scriptblock]$Condition,
        [int]$TimeoutSeconds,
        [string]$TimeoutMessage
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) {
            return
        }
        Start-Sleep -Milliseconds 250
    }

    throw $TimeoutMessage
}

function Stop-WordProcesses {
    Get-Process WINWORD -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction Stop
}

function Release-ComObjectQuietly {
    param([object]$ComObject)

    if ($null -eq $ComObject) {
        return
    }

    try {
        [Runtime.InteropServices.Marshal]::ReleaseComObject($ComObject) | Out-Null
    } catch { }
}

function New-WordApplicationWithRetry {
    $lastError = $null
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            return New-Object -ComObject Word.Application
        } catch {
            $lastError = $_
            Start-Sleep -Seconds 1
        }
    }

    throw "Failed to create Word.Application COM object: $lastError"
}

function Get-TargetWordProcessId {
    param([int[]]$BaselineProcessIds)

    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        $wordProcess = Get-Process WINWORD -ErrorAction SilentlyContinue |
            Where-Object { $BaselineProcessIds -notcontains $_.Id } |
            Sort-Object StartTime -Descending |
            Select-Object -First 1

        if ($wordProcess) {
            return $wordProcess.Id
        }

        Start-Sleep -Milliseconds 250
    }

    throw "Timed out waiting for COM-started WINWORD.EXE"
}

function Copy-ItemUnlessSamePath {
    param(
        [string]$SourcePath,
        [string]$DestinationPath
    )

    $resolvedSourcePath = (Resolve-Path -LiteralPath $SourcePath).ProviderPath
    $resolvedDestinationPath = if (Test-Path -LiteralPath $DestinationPath) {
        (Resolve-Path -LiteralPath $DestinationPath).ProviderPath
    } else {
        $DestinationPath
    }

    if ($resolvedSourcePath -ieq $resolvedDestinationPath) {
        Write-Stage "skip copy; source already at $DestinationPath"
        return
    }

    Copy-Item -LiteralPath $resolvedSourcePath -Destination $DestinationPath -Force
}

function Wait-ForFridaReady {
    param(
        [string]$FridaLogPath,
        [int]$TimeoutSeconds
    )

    Wait-ForCondition `
        -TimeoutSeconds $TimeoutSeconds `
        -TimeoutMessage "Timed out waiting for Frida readiness in $FridaLogPath" `
        -Condition {
            if (-not (Test-Path -LiteralPath $FridaLogPath)) {
                return $false
            }

            $text = Get-Content -LiteralPath $FridaLogPath -Raw
            return $text -match "Frida placement control script fully loaded|FRIDA_HEARTBEAT"
        }
}

function Show-FridaSummary {
    param([string]$FridaLogPath)

    if (-not (Test-Path -LiteralPath $FridaLogPath)) {
        Write-Stage "Frida log is missing: $FridaLogPath"
        return
    }

    Write-Stage "Frida key events:"
    Get-Content -LiteralPath $FridaLogPath |
        Where-Object {
            $_ -match "FRIDA_SCRIPT_VERSION|MALLOC_BASE|COTASKMEMALLOC|WWLIB_CALL_TRACE|PAYLOAD_FREE_STACK|PAYLOAD_RELEASE_STACK|FRIDA_HEARTBEAT|FRIDA_HROPEN|FRIDA_DOC_LOOKUP|FRIDA_PAYLOAD_RELEASE|FRIDA_BAD_CLEANUP_RET|FDISPOSE|FREE|ALLOC|WRITE|STACK|STACK_SCAN_WWLIB|wwlib\.dll|Freed payload|Exact reuse|forcing reuse"
        } |
        Select-Object -Last 80 |
        ForEach-Object { Write-Host $_ }
}

function Test-FridaMarkerWritten {
    param([string]$FridaLogPath)

    if (-not (Test-Path -LiteralPath $FridaLogPath)) {
        return $false
    }

    $text = Get-Content -LiteralPath $FridaLogPath -Raw
    return $text -match "\[WRITE\] Marker 'TBL_41414141' written"
}

$labDirectoryPath = New-Item -ItemType Directory -Path $LabDirectory -Force
$resultDirectory = New-Item -ItemType Directory -Path (Join-Path $labDirectoryPath.FullName "results") -Force
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$fridaLogPath = Join-Path $resultDirectory.FullName "frida-preview-$stamp.log"
$fridaErrorLogPath = Join-Path $resultDirectory.FullName "frida-preview-$stamp.err.log"
$triggerLogPath = Join-Path $resultDirectory.FullName "trigger-preview-$stamp.log"
$triggerErrorLogPath = Join-Path $resultDirectory.FullName "trigger-preview-$stamp.err.log"
$labFridaScriptPath = Join-Path $labDirectoryPath.FullName "frida-placement.js"
$labTriggerScriptPath = Join-Path $labDirectoryPath.FullName "trigger-preview.ps1"
$word = $null
$doc = $null
$wordPid = 0
$fridaProcess = $null
$triggerFailure = $null

try {
    $resolvedDocPath = (Resolve-Path -LiteralPath $DocPath).ProviderPath
    Write-Stage "doc=$resolvedDocPath"
    Write-Stage "lab=$($labDirectoryPath.FullName)"

    Copy-ItemUnlessSamePath -SourcePath $FridaScriptPath -DestinationPath $labFridaScriptPath
    Copy-ItemUnlessSamePath -SourcePath $TriggerScriptPath -DestinationPath $labTriggerScriptPath

    Write-Stage "closing existing WINWORD.EXE"
    Stop-WordProcesses

    $baselineWordPids = @(
        Get-Process WINWORD -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Id
    )

    Write-Stage "starting Word through COM"
    $word = New-WordApplicationWithRetry
    $word.Visible = $true
    $word.DisplayAlerts = 0
    $wordPid = Get-TargetWordProcessId -BaselineProcessIds $baselineWordPids

    Write-Stage "opening DOCX through Word COM"
    $doc = $word.Documents.Open($resolvedDocPath)

    Write-Stage "word pid=$wordPid"
    Start-Sleep -Seconds 5

    Write-Stage "starting Frida"
    $fridaArguments = @(
        "-p",
        [string]$wordPid,
        "-l",
        $labFridaScriptPath
    )
    $fridaProcess = Start-Process `
        -FilePath "frida" `
        -ArgumentList $fridaArguments `
        -RedirectStandardOutput $fridaLogPath `
        -RedirectStandardError $fridaErrorLogPath `
        -NoNewWindow `
        -PassThru

    Wait-ForFridaReady -FridaLogPath $fridaLogPath -TimeoutSeconds $ReadyTimeoutSeconds
    Write-Stage "Frida ready"

    Write-Stage "running trigger-preview.ps1"
    $triggerArguments = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $labTriggerScriptPath,
        "-Path",
        $resolvedDocPath,
        "-CoCreateRetryCount",
        [string]$CoCreateRetryCount
    )
    $triggerProcess = Start-Process `
        -FilePath "powershell.exe" `
        -ArgumentList $triggerArguments `
        -RedirectStandardOutput $triggerLogPath `
        -RedirectStandardError $triggerErrorLogPath `
        -NoNewWindow `
        -Wait `
        -PassThru

    Write-Stage "trigger exit code=$($triggerProcess.ExitCode)"
    if ($triggerProcess.ExitCode -ne 0) {
        if (Test-Path -LiteralPath $triggerLogPath) {
            Get-Content -LiteralPath $triggerLogPath | Select-Object -Last 80
        }
        if (Test-Path -LiteralPath $triggerErrorLogPath) {
            Get-Content -LiteralPath $triggerErrorLogPath | Select-Object -Last 80
        }
        $triggerFailure = "trigger-preview.ps1 failed with exit code $($triggerProcess.ExitCode)"
    }

    Write-Stage "observing Frida for $ObserveSeconds seconds"
    Start-Sleep -Seconds $ObserveSeconds
    Show-FridaSummary -FridaLogPath $fridaLogPath

    Write-Stage "frida log=$fridaLogPath"
    Write-Stage "trigger log=$triggerLogPath"
    Write-Stage "trigger error log=$triggerErrorLogPath"

    $hasMarkerWrite = Test-FridaMarkerWritten -FridaLogPath $fridaLogPath
    if ($hasMarkerWrite) {
        Write-Stage "proof achieved: Frida marker write observed"
        $triggerFailure = $null
    }

    if ($triggerFailure) {
        throw $triggerFailure
    }
} finally {
    if ($fridaProcess -and -not $fridaProcess.HasExited) {
        Write-Stage "stopping Frida"
        Stop-Process -Id $fridaProcess.Id -Force -ErrorAction SilentlyContinue
    }

    if (-not $KeepWordOpen) {
        Write-Stage "closing Word"
        if ($doc) {
            try {
                $doc.Close($false)
            } catch { }
            Release-ComObjectQuietly -ComObject $doc
        }
        if ($word) {
            try {
                $word.Quit()
            } catch { }
            Release-ComObjectQuietly -ComObject $word
        }
        Stop-WordProcesses
    } else {
        Release-ComObjectQuietly -ComObject $doc
        Release-ComObjectQuietly -ComObject $word
    }
}
