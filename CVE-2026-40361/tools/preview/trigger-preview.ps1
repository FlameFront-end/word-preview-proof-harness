param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Path,

    [ValidateRange(5, 10)]
    [int]$WaitSeconds = 8,

    [ValidateRange(1, 30)]
    [int]$CoCreateRetryCount = 10,

    [ValidateRange(100, 5000)]
    [int]$CoCreateRetryDelayMs = 1000
)

$ErrorActionPreference = "Stop"

function Format-HResult {
    param([int]$HResult)

    return "0x{0:X8}" -f ($HResult -band 0xffffffff)
}

function Throw-IfFailed {
    param(
        [int]$HResult,
        [string]$Operation
    )

    if ($HResult -ne 0) {
        throw "$Operation failed with HRESULT $(Format-HResult $HResult)"
    }
}

function Add-PreviewTriggerNativeTypes {
    if ("PreviewTrigger.NativeMethods" -as [type]) {
        return
    }

    $source = @"
using System;
using System.Runtime.InteropServices;

namespace PreviewTrigger
{
    public static class NativeMethods
    {
        [DllImport("ole32.dll")]
        public static extern int CoCreateInstance(
            ref Guid rclsid,
            IntPtr pUnkOuter,
            uint dwClsContext,
            ref Guid riid,
            out IntPtr ppv
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int InitializeWithFileDelegate(
            IntPtr self,
            [MarshalAs(UnmanagedType.LPWStr)] string pszFilePath,
            uint grfMode
        );
    }
}
"@

    Add-Type -TypeDefinition $source
}

function New-InitializeWithFilePointer {
    param(
        [Guid]$ClassId,
        [Guid]$InterfaceId,
        [uint32]$ClassContext,
        [int]$RetryCount,
        [int]$RetryDelayMs
    )

    $previewHandlerPointer = [IntPtr]::Zero
    $lastHResult = 0

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        Write-Host "[TRIGGER_STAGE] CoCreateInstance attempt $attempt/$RetryCount"
        $lastHResult = [PreviewTrigger.NativeMethods]::CoCreateInstance(
            [ref]$ClassId,
            [IntPtr]::Zero,
            $ClassContext,
            [ref]$InterfaceId,
            [ref]$previewHandlerPointer
        )

        Write-Host ("CoCreateInstance hr={0} ppv=0x{1:X}" -f (Format-HResult $lastHResult), $previewHandlerPointer.ToInt64())
        if ($lastHResult -eq 0 -and $previewHandlerPointer -ne [IntPtr]::Zero) {
            return $previewHandlerPointer
        }

        if ($previewHandlerPointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::Release($previewHandlerPointer) | Out-Null
            $previewHandlerPointer = [IntPtr]::Zero
        }

        if ($attempt -lt $RetryCount) {
            Start-Sleep -Milliseconds $RetryDelayMs
        }
    }

    Throw-IfFailed -HResult $lastHResult -Operation "CoCreateInstance"
    throw "CoCreateInstance returned a null IInitializeWithFile pointer"
}

$resolvedPath = (Resolve-Path -LiteralPath $Path).ProviderPath
$clsid = [Guid]"{84F66100-FF7C-4FB4-B0C0-02CD7FB668FE}"
$iidInitializeWithFile = [Guid]"{B7D14566-0509-4CCE-A71F-0A554233BD9B}"
$CLSCTX_LOCAL_SERVER = 4
$ppv = [IntPtr]::Zero

try {
    Write-Host "[TRIGGER_STAGE] start"
    Write-Host "[TRIGGER_STAGE] target=$resolvedPath"
    Write-Host "[TRIGGER_STAGE] using existing Word session; this script will not open or close Word"

    Add-PreviewTriggerNativeTypes

    Write-Host "[TRIGGER_STAGE] before CoCreateInstance"
    $ppv = New-InitializeWithFilePointer `
        -ClassId $clsid `
        -InterfaceId $iidInitializeWithFile `
        -ClassContext $CLSCTX_LOCAL_SERVER `
        -RetryCount $CoCreateRetryCount `
        -RetryDelayMs $CoCreateRetryDelayMs

    $vtbl = [Runtime.InteropServices.Marshal]::ReadIntPtr($ppv)
    $slot3 = [Runtime.InteropServices.Marshal]::ReadIntPtr($vtbl, 3 * [IntPtr]::Size)

    Write-Host ("INIT_VTBL=0x{0:X}" -f $vtbl.ToInt64())
    Write-Host ("INIT_SLOT3=0x{0:X}" -f $slot3.ToInt64())
    Write-Host "[TRIGGER_STAGE] before Initialize"

    $initialize = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $slot3,
        [PreviewTrigger.NativeMethods+InitializeWithFileDelegate]
    )

    $initializeHr = $initialize.Invoke($ppv, $resolvedPath, 0)
    Write-Host ("Initialize hr={0}" -f (Format-HResult $initializeHr))
    Throw-IfFailed -HResult $initializeHr -Operation "IInitializeWithFile.Initialize"

    Write-Host "[TRIGGER_STAGE] after Initialize"
    Write-Host "[TRIGGER_STAGE] waiting $WaitSeconds seconds for Frida hooks"
    Start-Sleep -Seconds $WaitSeconds
    Write-Host "[TRIGGER_STAGE] done"
} catch {
    Write-Host ("[TRIGGER_ERROR] {0}" -f $_.Exception.Message)
    Write-Host $_.Exception.ToString()
    throw
} finally {
    if ($ppv -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::Release($ppv) | Out-Null
        Write-Host "[TRIGGER_STAGE] released preview handler"
    }
}
