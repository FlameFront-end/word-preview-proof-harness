Write-Host "[*] Stopping proof/helper PowerShell processes..."
Get-CimInstance Win32_Process -Filter "name='powershell.exe'" |
Where-Object {
    $_.CommandLine -match 'run-proof.ps1|attach-cdb-current|Invoke-PreviewTrigger-current|diag-preview|watch-close-stale-attach-helpers'
} |
ForEach-Object {
    Write-Host "Killing powershell PID=$($_.ProcessId)"
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "[*] Stopping WINWORD/CDB..."
Get-Process WINWORD,cdb -ErrorAction SilentlyContinue |
ForEach-Object {
    Write-Host "Killing $($_.ProcessName) PID=$($_.Id)"
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

cmd.exe /c "taskkill /f /t /im winword.exe >nul 2>nul"
cmd.exe /c "taskkill /f /t /im cdb.exe >nul 2>nul"

Write-Host "[*] Removing stale flags..."
Remove-Item "C:\CVELAB\final\scripts\preview-ready-*.flag" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\CVELAB\final\scripts\preview-go-*.flag" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\CVELAB\final\scripts\breakpoints-ready-*.flag" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\CVELAB\final\scripts\diag-preview-ready-*.flag" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\CVELAB\final\scripts\diag-preview-go-*.flag" -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 5

Write-Host "`n=== Remaining proof processes ==="
Get-CimInstance Win32_Process |
Where-Object {
    $_.Name -match 'WINWORD|cdb|powershell' -and
    $_.CommandLine -match 'run-proof.ps1|attach-cdb-current|Invoke-PreviewTrigger-current|diag-preview|watch-close-stale-attach-helpers'
} |
Select-Object ProcessId,Name,CommandLine |
Format-List

Write-Host "`n=== Remaining WINWORD/CDB ==="
Get-Process WINWORD,cdb -ErrorAction SilentlyContinue |
Select-Object Id,ProcessName,StartTime

Write-Host "`n[+] Cleanup complete."
