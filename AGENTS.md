# Project AGENTS.md

## Role

This project is a Windows lab harness for passive Word preview/CDB/Frida proof work.
Respond in Russian unless the user explicitly asks otherwise.

Do not commit changes unless the user explicitly asks for a commit.
Do not start VM/Word/CDB proof runs unless the user explicitly asks to run them.
If a proof run is already running, do not launch another one; inspect only logs/state.

## Current Objective

Find a passive DOCX-only path that naturally reaches exact reuse/write evidence after the known bad cleanup path.
The useful proof signal is stronger than `HasBadCleanup=True`: it must include one or more of:

- `HasExactReuseRuntime=True`
- `HasWatchHit=True`
- `MarkerFound=True`
- CDB log lines with `CDB_EXACT_REUSE_RUNTIME` or `CDB_WRITE_TO_REUSED_SLOT`

`HasBadCleanup=True` and `HasPayloadRelease=True` only prove that the candidate reaches the vulnerable/root-cause path.
They do not prove natural reuse.

## Repository Layout

- `run-proof.ps1`: main local/VM harness. Generates or copies DOCX candidates, starts Word COM, attaches CDB, triggers preview handler, records attempt summaries.
- `Invoke-RemoteProofSweep.ps1`: local orchestrator for running proof attempts on the VM through WinRM and interactive Scheduled Tasks.
- `tools/preview/Invoke-PreviewTrigger.ps1`: preview handler trigger used by `run-proof.ps1`.
- `tools/preview/trigger-preview.ps1`: simpler trigger used by Frida automation.
- `tools/frida/Start-FridaPreviewRun.ps1`: Frida-based controlled proof runner.
- `tools/frida/frida-placement.js`: Frida allocator/control script.
- `tools/maintenance/clean-proof-state.ps1`: lab cleanup helper for WINWORD/CDB/helper processes and stale flags.
- `tests/RunProof.Static.Tests.ps1`: static/parser checks for the main harness.
- `tests/RemoteProofSweep.Static.Tests.ps1`: static/parser checks for the remote wrapper.
- `docs/superpowers/plans/`: implementation and next-step plans.
- `remote-results/`: local copies/reports from remote sweeps.

Runtime/generated artifacts usually live under:

- `docs/`
- `docs/cache/`
- `scripts/`
- `results/`
- `remote-results/`

## Known Environment

Local workspace:

- `C:\Development\test\cve-ps1`

VM:

- IP: `192.168.200.132`
- User: `labadmin`
- VM working directory: `C:\CVELAB\final`
- WinRM HTTP port: `5985`
- Remote runs must use an interactive Scheduled Task, not direct Word COM inside a non-interactive WinRM session.
- After a VM reboot, verify `quser` before proof runs. If it returns `No User exists`, the VM has no interactive `labadmin` session and Interactive Scheduled Tasks will not execute the Word/preview proof path. In that state, do not switch to non-interactive Word COM; ask for VM console login or wait until the user logs in.

Do not store VM passwords in files. Ask the user for the password if it is not already available in the chat context.

Credential pattern:

```powershell
$password = ConvertTo-SecureString '<password>' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('192.168.200.132\labadmin', $password)
```

## Stable Findings So Far

Attempt 8 is the current known root-cause candidate:

- `tables=2000`
- `customXml=False`
- `rPr=False`
- `order=customXml_first`
- `spray=0`

Attempt 8 repeatedly reached:

- `CDB_HROPEN_PREVIEWER_DOC_ENTER`
- `CDB_DOC_LOOKUP_RET`
- `CDB_PAYLOAD_RELEASE_ENTER`
- `CDB_PAYLOAD_AFTER`
- `CDB_BAD_CLEANUP_RET`

But prior deep runs did not show exact reuse/write/marker.

Allocator diagnostics with `spray=0` showed very weak post-release pressure:

- `PostPayloadAlloc20Count=1`
- first observed `0x20` allocation was far from the freed payload slot.

The 2026-07-06 remote sweep with old VM scripts showed:

- `spray=0`: root-cause path reached, `PostPayloadAlloc20Count=1`, closest delta `0x107205f0`.
- `spray=500`: root-cause path reached, `PostPayloadAlloc20Count=4`, closest positive delta about `0x1ac810`.
- `spray=1000`: preview trigger destabilized; `Initialize hr=0x800706BA`, no bad cleanup/payload release.
- `spray=2000`: scheduled `powershell.exe` crashed at task start with `0xc0000005`; no run output was written.

Conclusion: the current bottleneck is allocator/layout pressure after payload release, not reaching the bad cleanup path.
`spray=500` is the best observed passive candidate so far, but it still did not produce exact reuse/write/marker.
`spray>=1000` is currently too unstable for deep proof runs.

The 2026-07-06 `allocdiag` sweep around `spray=250,400,500,600,750` produced a reported `success` at `spray=400`, repeat 2, but log review showed it was a false positive:

- CDB emitted `Numeric expression missing` for the multi-size `@r8 == 0x10 || @r8 == 0x20...` condition.
- The CDB error line contained proof tags from the breakpoint command text, so the runtime parser counted command text as evidence.
- Local code was fixed after this run: the CDB size filter no longer uses `||`, and runtime parsing excludes `Numeric expression missing` lines and blocks success when CDB command syntax errors appear.
- This fix must be synced to the VM before the next proof run.

After syncing that fix, a 2026-07-06 bounded `allocdiag` sweep around `spray=350,400,450,500` showed:

- No exact reuse/write/marker yet.
- `spray=350`, `spray=400`, and `spray=450` can still reach the bad cleanup path.
- Useful post-release allocation events appeared as request size `0x30`, not `0x20`.
- `spray=400`: one useful run had `0x30:count=5`, closest delta `0x12ae2900`.
- `spray=450`: one useful run had `0x30:count=6`, closest delta `0xffffffffffeabe30` (negative, about `-0x1541d0`).
- `spray=500` crashed the scheduled `powershell.exe` at task startup with `0xc0000005`; treat it as unstable until launcher/VM stability is improved.

The CDB exact-reuse detector was updated after this evidence: it now treats `@rax == freedPayloadPtr` as exact reuse for any monitored size in `0x10,0x20,0x30,0x40,0x50,0x60`, instead of only `0x20`.
Keep the legacy `CDB_POST_PAYLOAD_ALLOC20_RETURN` diagnostic for compatibility, but do not restrict proof detection to `0x20`.

Subsequent focused sweeps narrowed the useful passive range to `spray=474`.
No exact reuse/write/marker has been observed yet, but `spray=474` now has the strongest allocator evidence:

- 2026-07-07 `spray=474` repeated run: best signal was `0x20:count=6`, closest positive delta `0x2c5e0` from the freed payload pointer.
- 2026-07-07 micro-sweep `spray=473,474,475`: `spray=474` again dominated. One run reached `0x20` allocation at `payload-0x3810`, plus `0x40` allocations at `payload-0xc320`/`payload-0xbb50` and `0x30` at `payload+0x2324b0`. This is the closest passive proximity observed so far, but it is still not exact reuse.
- Other useful `spray=474` runs showed `0x40` closest deltas around `0x84090`, `0x119fe0`, and `0x198f60`, plus `0x30` pressure.
- Aggregate local reports confirm the top near-misses are all `spray=474`: `0x3810`, `0x2c5e0`, `0x68f40`, `0x9e610`, and `0xbe760` absolute distance. Nearest non-474 candidates are much worse (`476` about `0x1e3a60`, `475` about `0x41c060`, `473` about `0x4ea9d0`).
- `spray=475` is no longer a good secondary candidate unless new diagnostics change the hypothesis; recent runs either fail at preview-trigger or remain much farther from the freed payload than `474`.
- `spray=474` has intermittent scheduled-task/CDB startup failures; the remote wrapper records these as failed rows and continues.

Frida can force or guide reuse and is useful for learning call stacks, allocator size, heap/thread constraints, and candidate timing.
Frida success does not by itself prove passive DOCX-only natural reuse.

## Important Current Code Behavior

`run-proof.ps1` supports:

- `ObserveMode fast`
- `ObserveMode deep`
- `ObserveMode allocdiag`

`allocdiag` auto-enables `PostPayloadAllocTraceCount=100` when the caller leaves it at `0`.

Current diagnostics include:

- post-payload allocation lines with size, heap, flags, caller, thread id, return pointer, payload pointer, and delta.
- one `CDB_PAYLOAD_RELEASE_STACK` stack capture at payload release.
- bounded allocation stack capture controlled by `PostPayloadAllocStackCount`.
- all-size post-payload allocation ranking: `BestPostPayloadAllocDelta` and closest positive/negative/absolute fields are based on all monitored sizes, not only legacy `0x20` events.
- spray duration and tables/sec in attempt summaries.
- preview trigger `Initialize hr`, exit code, and exit state in attempt summaries.
- remote Scheduled Task result metadata and timeout/crash diagnostics in remote reports.
- remote wrapper report tails: `RemoteOutputTail`, `RemoteErrorTail`, `LastTriggerStage`, and `LastHarnessError`.

Remote attempts now write unique per-run summary/ranking files:

- `results\attempt-summary-remote-<run>-<stamp>.csv`
- `results\attempt-ranking-remote-<run>-<stamp>.csv`

This avoids accidentally reading stale rows from the shared `results\attempt-summary.csv`.

`Invoke-RemoteProofSweep.ps1 -StopOnExactReuse` must stop the whole sweep, not just the inner repeat loop.
`Invoke-RemoteProofSweep.ps1` has a default bounded cooldown between runs via `-DelayBetweenRunsSeconds` to reduce back-to-back Scheduled Task/CDB startup instability.
After `FailureKind=scheduled-task`, `Invoke-RemoteProofSweep.ps1` can use the longer `-ScheduledTaskFailureDelaySeconds` cooldown because recent `powershell.exe` `0xc0000005` startup crashes happened before stdout/stderr were created and repeated quickly with short pauses.
The remote wrapper syncs and runs both static test files on the VM before proof attempts.

## Verification Commands

Run these after code changes:

```powershell
cd C:\Development\test\cve-ps1
& .\tests\RunProof.Static.Tests.ps1
& .\tests\RemoteProofSweep.Static.Tests.ps1

$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\run-proof.ps1), [ref]$tokens, [ref]$errors) | Out-Null
if ($errors) { $errors | Format-List *; throw 'run-proof parser failed' }

$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\Invoke-RemoteProofSweep.ps1), [ref]$tokens, [ref]$errors) | Out-Null
if ($errors) { $errors | Format-List *; throw 'remote parser failed' }
```

Use `rg` first for text/file search.

## Remote Commands

Do not run these unless the user explicitly asks to start tests.

Short allocator diagnostic sweep:

```powershell
cd C:\Development\test\cve-ps1

.\Invoke-RemoteProofSweep.ps1 `
  -ComputerName 192.168.200.132 `
  -Credential $credential `
  -SprayCounts @(0,50,100,250,500) `
  -RepeatsPerSpray 2 `
  -ObserveMode allocdiag `
  -ObserveMinutes 3 `
  -PostPayloadAllocTraceCount 100 `
  -PostPayloadAllocStackCount 5 `
  -StopOnExactReuse
```

Deep confirmation for narrowed candidates:

```powershell
cd C:\Development\test\cve-ps1

.\Invoke-RemoteProofSweep.ps1 `
  -ComputerName 192.168.200.132 `
  -Credential $credential `
  -SprayCounts @(0,50,100,250,500) `
  -RepeatsPerSpray 1 `
  -ObserveMode deep `
  -ObserveMinutes 10 `
  -PostPayloadAllocTraceCount 100 `
  -PostPayloadAllocStackCount 5 `
  -StopOnExactReuse
```

Inspect remote state without launching new proof attempts:

```powershell
$session = New-PSSession -ComputerName 192.168.200.132 -Credential $credential
Invoke-Command -Session $session -ScriptBlock {
    cd C:\CVELAB\final
    Get-ScheduledTask | Where-Object TaskName -like 'ProofRemote-*' | Select-Object TaskName,State
    Get-Process WINWORD,cdb,powershell -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,StartTime,Path
    Import-Csv .\results\attempt-summary.csv -ErrorAction SilentlyContinue |
        Select-Object -Last 10 |
        Format-Table Attempt,SprayCount,Status,FailureKind,HasBadCleanup,HasPayloadRelease,PostPayloadAlloc20Count,BestPostPayloadAllocSize,BestPostPayloadAllocDelta,HasExactReuseRuntime,HasWatchHit,MarkerFound -AutoSize
}
Remove-PSSession $session
```

## Next Steps Plan

Keep this plan updated after each completed step. If a step changes the evidence, update the remaining steps before continuing.

1. Inspect the current running/manual log when the user says it finished.
   Record whether it used the latest per-run summary changes or older scripts.

2. If the run used older scripts, ignore stale shared-summary conclusions and rerun only after syncing the fixed files to the VM.

3. Sync the fixed local files to `C:\CVELAB\final` on the VM when the user asks:
   - `run-proof.ps1`
   - `Invoke-RemoteProofSweep.ps1`
   - `tests\RunProof.Static.Tests.ps1`
   - `tests\RemoteProofSweep.Static.Tests.ps1`
   - `tools\preview\Invoke-PreviewTrigger.ps1`
   - `tools\preview\trigger-preview.ps1`
   - `tools\frida\Start-FridaPreviewRun.ps1`
   - `tools\frida\frida-placement.js`
   - `tools\maintenance\clean-proof-state.ps1`
   - `AGENTS.md`

4. Current best passive candidate is `spray=474`.
   Prefer repeated bounded `allocdiag` runs on `spray=474` before returning to broader ranges. Use `-ScheduledTaskFailureDelaySeconds 300` for unattended sweeps. The strongest observed near-miss is `0x20` at `payload-0x3810`.

5. Rank candidates by:
   - exact reuse/write/marker first
   - then `HasBadCleanup=True` and `HasPayloadRelease=True`
   - then higher `PostPayloadAlloc20Count`
   - then smaller `BestPostPayloadAllocDelta`
   - then lower failure rate

6. Run deep confirmation only after `allocdiag` produces exact reuse/write/marker, or repeatedly shows sub-megabyte allocator proximity on the same size/caller.
   Do not spend long deep runs on candidates that do not improve allocator diagnostics.

7. If no candidate improves allocator diagnostics, use Frida logs to identify the allocator size/caller/thread after payload release and adjust passive diagnostics before running another overnight sweep.

8. For overnight runs, prefer many bounded attempts over one very long attempt.
   Current practical shape: repeated `deep` attempts of 10-15 minutes on narrowed candidates, stopping on exact reuse.

## Plan Maintenance Rule

After every proof run or code change:

1. Update this `AGENTS.md` if the project-level understanding changed.
2. Update or add a plan under `docs/superpowers/plans/` if next steps changed.
3. Mark completed steps and rewrite obsolete steps.
4. Do not leave stale assumptions such as old best candidates, old VM layout, or old log interpretation rules.

## Current Risks

- CDB command syntax for the any-size exact-reuse detector must be verified in a real VM run after syncing the latest local files.
- Frida proves controllability, not passive reuse.
- Shared result files can be stale; prefer unique per-run summaries from the fixed remote wrapper.
- Word COM is unreliable from non-interactive WinRM; use Scheduled Tasks for remote proof runs.
- Interactive Scheduled Tasks require an active logged-in VM user. Rebooting the VM clears that session and blocks proof execution until `labadmin` logs in again.
- `docs/cache` may contain old generated DOCX candidates after generator changes. Delete the cache if DOCX generation logic changes.
