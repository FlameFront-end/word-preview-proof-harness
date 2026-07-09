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
- Aggregate local reports confirm the top near-misses are all `spray=474`: `0x3810`, `0x21100`, `0x2c5e0`, `0x68f40`, and `0x9e610` absolute distance. Nearest non-474 candidates are much worse (`476` about `0x1e3a60`, `475` about `0x41c060`, `473` about `0x4ea9d0`).
- As of the 2026-07-07 `remote-proof-20260707-222252` batch, there are 45 valid focused `spray=474` root-cause runs without exact reuse/write/marker. The old `spray=400` reported success is a known pre-fix false positive and must not be counted.
- Near-miss aggregate artifacts are in `remote-results\near-miss-analysis-20260707-232117`: 624 allocation events and 75 per-run best rows.
- Current near-miss clusters:
  - best single miss: `0x20` at `payload-0x3810`, caller `0x00007ffe4bed4a57`, thread `0x476c`, heap `0x000001865cd70000`.
  - stable frequent cluster: `0x30` from caller `0x00007ffe4bed4a57`, with best `payload-0x21100`.
  - secondary `0x20` cluster: caller `0x00007ffeaa6850d9`, with best `payload-0x21100`.
  - rare `0x40` close misses include dynamic-looking callers such as `0x000001865e521648`; symbolize or compare with stacks before treating them as stable code callers.
- `spray=475` is no longer a good secondary candidate unless new diagnostics change the hypothesis; recent runs either fail at preview-trigger or remain much farther from the freed payload than `474`.
- `spray=474` has intermittent scheduled-task/CDB startup failures; the remote wrapper records these as failed rows and continues.

Frida can force or guide reuse and is useful for learning call stacks, allocator size, heap/thread constraints, and candidate timing.
Frida success does not by itself prove passive DOCX-only natural reuse.

Fresh Frida diagnostic from 2026-07-07 is saved locally in `remote-results\frida-diagnostic-20260707-132749`.
It used `poc-run-attempt-0008-t2000-20260707-020135.docx` and produced a marker write:

- `PAYLOAD_SIZE=0x20` in `tools\frida\frida-placement.js`.
- freed payload: `0x1f506285f20`
- freed heap: `0x1f56e310000`
- freed thread: decimal `7376` / hex `0x1cd0`
- Frida learned `MALLOC_BASE` at `0x7ffeaa6850d9`.
- forced allocation line: `RtlAllocateHeap(size=0x20) original ret=0x1f505d927b0, forcing reuse of 0x1f506285f20`.
- original natural return in that Frida run was `payload-0x4f3770`; Frida forced it to exact reuse and wrote marker `TBL_41414141`.

This directly matches the passive CDB near-miss caller `0x00007ffeaa6850d9` for `size=0x20`.
The best passive CDB rows for that Frida-matched caller are `payload-0x21100` and `payload+0x2c5e0`.
Therefore the next diagnostic target is the `0x20`/`0x00007ffeaa6850d9` path, not broad all-size repetition.

The 2026-07-08 filtering check in `remote-results\remote-proof-20260708-105754` ran 2 attempts on `spray=474`:

- RUN 1 did not reach the root-cause path.
- RUN 2 reached `HasBadCleanup=True` and `HasPayloadRelease=True`, but no exact reuse/write/marker.
- RUN 2 produced one weak post-release `0x20` allocation at `payload+0x121bc860`, caller `0x00007ff8a9cd50d9`; this does not match the Frida-matched caller.
- `remote-proof-events.log` runtime-event filtering is verified on real runtime lines: it includes payload-release/bad-cleanup/post-allocation events and excludes CDB breakpoint command text, `.echo`, `Numeric expression missing`, and `CDB PROOF` banner lines.

The 2026-07-08 module-relative diagnostic check in `remote-results\remote-proof-20260708-114636` confirmed the updated CDB command installs with `mso20win32client+0x2a50d9` and `mso20win32client+0x2a4a57`.
It did not hit either targeted caller:

- RUN 1 failed before CoCreateInstance.
- RUN 2 reached root-cause/no-success and produced 13 far `0x20` allocations at `payload-0x18074a90`; caller was a different path around `AppVIsvSubsystems64` / registry query.
- RUN 3 failed at Scheduled Task startup with `0xc0000005`; WER captured a `powershell.exe` APPCRASH in bucket `abd12585cd6c663009fe454baedf0a0b`.

The 2026-07-08 focused module-relative target batch in `remote-results\remote-proof-20260708-121407` hit the `0x30` module-relative target:

- 6 attempts on `spray=474`: 2 valid root-cause/no-success, 3 Scheduled Task `0xc0000005` failures, and 1 preview-trigger failure before CoCreateInstance.
- No exact reuse/write/marker.
- RUN 1 emitted `CDB_NEAR_MISS_ALLOC30_RETURN` and `CDB_NEAR_MISS_ALLOC30_STACK` for `mso20win32client+0x2a4a57`.
- The hit was still far from proof: `0x30` returned `payload+0x4763b0`.
- The stack was `mso20win32client!Mso::Memory::AllocateEx -> wwlib!operator new -> wwlib!PobjxCreate -> wwlib!PwwserverdocCreate -> wwlib!WWSERVEROBJ::Initialize -> RPCRT4`.
- RUN 1 also had `0x20` allocations at `payload-0xac007e0` from `ucrtbase+0x50d9`, not the Frida-matched `mso20win32client+0x2a50d9`.
- The Frida-matched `mso20win32client+0x2a50d9` path still has not appeared in passive CDB after the module-relative fix.
- Do not run another identical `spray=474` batch as the next default step; either stabilize Scheduled Task/PowerShell startup first, or change the allocator-pressure/timing hypothesis toward the missing `mso20win32client+0x2a50d9` path.

## Important Current Code Behavior

`run-proof.ps1` supports:

- `ObserveMode fast`
- `ObserveMode deep`
- `ObserveMode allocdiag`

`allocdiag` auto-enables `PostPayloadAllocTraceCount=100` when the caller leaves it at `0`.

Current diagnostics include:

- post-payload allocation lines with size, heap, flags, caller, thread id, return pointer, payload pointer, delta, freed-payload heap/thread, and same-heap/same-thread booleans.
- `CDB_PAYLOAD_RTLFREEHEAP_ENTER`, which captures the actual `RtlFreeHeap(payload)` heap/thread before comparing later allocations against the freed slot context.
- same-free allocation ranking fields in local attempt summaries and remote reports:
  - `BestSameFreeHeapAllocSize`, `BestSameFreeHeapAllocDelta`, `BestSameFreeHeapAllocCaller`.
  - `BestSameFreeThreadAllocSize`, `BestSameFreeThreadAllocDelta`, `BestSameFreeThreadAllocCaller`.
- one `CDB_PAYLOAD_RELEASE_STACK` stack capture at payload release.
- bounded allocation stack capture controlled by `PostPayloadAllocStackCount`.
- targeted post-release allocation stack capture for:
  - `CDB_FRIDA_MATCHED_ALLOC20_RETURN` / `CDB_FRIDA_MATCHED_ALLOC20_STACK`: `size=0x20`, caller target `mso20win32client+0x2a50d9`.
  - `CDB_NEAR_MISS_ALLOC30_RETURN` / `CDB_NEAR_MISS_ALLOC30_STACK`: `size=0x30`, caller target `mso20win32client+0x2a4a57`.
  - `CDB_SAME_FREE_THREAD_ALLOC_RETURN` / `CDB_SAME_FREE_THREAD_ALLOC_STACK`: any monitored size where allocation heap/thread match the captured freed payload heap/thread.
  These targeted stacks are bounded by `PostPayloadAllocStackCount` but are not limited to the first global allocation events, so late target hits such as allocation index 14-15 are captured.
  Do not hard-code absolute caller addresses for these diagnostics: VM restart/ASLR changed old `0x00007ffe4bed4a57` to `0x00007ff895534a57` while preserving module offset `mso20win32client+0x2a4a57`.
- all-size post-payload allocation ranking: `BestPostPayloadAllocDelta` and closest positive/negative/absolute fields are based on all monitored sizes, not only legacy `0x20` events.
- spray duration and tables/sec in attempt summaries.
- preview trigger `Initialize hr`, exit code, and exit state in attempt summaries.
- remote Scheduled Task result metadata and timeout/crash diagnostics in remote reports.
- remote wrapper report tails: `RemoteOutputTail`, `RemoteErrorTail`, `LastTriggerStage`, and `LastHarnessError`.
- `Invoke-RemoteProofSweep.ps1` suppresses PowerShell progress in local, remote, and Scheduled Task contexts to avoid WinRM/CLIXML noise breaking local result collection after a proof run has already completed.
- `Invoke-RemoteProofSweep.ps1` filters `remote-proof-events.log` to real runtime CDB event lines. Do not export raw `Select-String` matches from CDB logs because breakpoint command text contains proof tag names.
- `tools\maintenance\clean-proof-state.ps1` must avoid external `cmd.exe / taskkill.exe` cleanup fallbacks. Existing VM evidence showed `cmd.exe` and `taskkill.exe` APPCRASH events during unstable proof windows, so cleanup should stay PowerShell-native unless a new diagnosis proves otherwise.

Remote attempts now write unique per-run summary/ranking files:

- `results\attempt-summary-remote-<run>-<stamp>.csv`
- `results\attempt-ranking-remote-<run>-<stamp>.csv`

This avoids accidentally reading stale rows from the shared `results\attempt-summary.csv`.

`Copy-ProofScripts` must sync `Invoke-RemoteProofSweep.ps1` itself to the VM so remote static validation checks the same wrapper code that is running locally.
`Invoke-RemoteProofSweep.ps1 -StopOnExactReuse` must stop the whole sweep, not just the inner repeat loop.
`Invoke-RemoteProofSweep.ps1` has a default bounded cooldown between runs via `-DelayBetweenRunsSeconds` to reduce back-to-back Scheduled Task/CDB startup instability.
After `FailureKind=scheduled-task`, `Invoke-RemoteProofSweep.ps1` can use the longer `-ScheduledTaskFailureDelaySeconds` cooldown because recent `powershell.exe` `0xc0000005` startup crashes happened before stdout/stderr were created and repeated quickly with short pauses.
`Invoke-RemoteProofSweep.ps1` also has bounded startup retry handling for intermittent Scheduled Task `powershell.exe` crashes:

- `ScheduledTaskStartupRetryCount` defaults to `2`.
- `ScheduledTaskStartupRetryDelaySeconds` defaults to `120`.
- Only `FailureKind=scheduled-task` is retried; `preview-trigger` failures and valid `no-success` rows are not retried.
- Retry events are written as `SCHEDULED_TASK_STARTUP_RETRY`.
- The local CSV report includes `ScheduledTaskStartupRetryCount`.

This is a mitigation for VM/PowerShell startup flakiness before runner stdout/stderr, not proof evidence.
The first retry-enabled verification batch was `remote-results\remote-proof-20260708-164249`:

- 3 attempts on `spray=474` with `ScheduledTaskStartupRetryCount=2`.
- 3/3 Scheduled Tasks completed with `TaskLastTaskResult=0`, so the retry path did not need to fire.
- RUN 2 and RUN 3 reached root-cause/no-success.
- No exact reuse/write/marker.
- No post-release allocation events or targeted tags appeared in that batch.

The 2026-07-08 payload free diagnostic update added an `ntdll!RtlFreeHeap` breakpoint. It must be installed after the allocator and doc-lookup breakpoints:

- `RtlAllocateHeap` remains CDB breakpoint 5 and is disabled by `bd 5` until payload release.
- `wwlib+0xd96cf0` remains the doc lookup return breakpoint 6.
- `RtlFreeHeap` is installed after those, becomes breakpoint 7, and must be disabled with `bd 7` until payload release.
- `CDB_PAYLOAD_RELEASE_ENTER` enables both allocation and free diagnostics with `be 5; be 7`.
- The matched `RtlFreeHeap(payload)` branch disables itself with `bd 7` after the first capture to avoid repeated payload-free lines.

A first attempt installed `RtlFreeHeap` too early and caused `breakpoint 5 redefined`; this was fixed and guarded by static tests.
The control run `remote-results\remote-proof-20260708-174513` verified the command installation order and absence of `breakpoint 5 redefined`, but did not reach root-cause path.
Follow-up batches showed that an always-active `RtlFreeHeap` breakpoint causes pre-release CDB overhead and can stall before root-cause; keep it disabled until payload release.
`remote-results\remote-proof-20260708-222714` verified `CDB_PAYLOAD_RTLFREEHEAP_ENTER` in RUN 1. The observed allocations were on the same heap as the freed payload but on a different thread, and still far from payload.
`remote-results\remote-proof-20260708-224643` verified the self-disable command shape in a root-cause sample, but that sample did not hit `CDB_PAYLOAD_RTLFREEHEAP_ENTER`; runtime self-disable remains to be seen in a later sample that hits the free breakpoint.
The 2026-07-09 overnight micro-sweep `remote-results\remote-proof-20260709-001633` found the current best strict passive signal:

- `spray=474`
- `size=0x30`
- caller `mso20win32client+0x2a4a57`
- `sameFreeHeap=1`
- `sameFreeThread=1`
- `delta=+0x143710`

Follow-up `474 x6` and `472..475 x2` batches did not reproduce a closer same-thread allocation and did not produce exact reuse/write/marker.
The Frida-matched `mso20win32client+0x2a50d9` path is still missing in passive CDB.
After that, `CDB_SAME_FREE_THREAD_ALLOC_RETURN` / `STACK` was added so future runs capture any same-free-thread allocation stack, not only the known `+0x2a4a57` near-miss.
Smoke `remote-results\remote-proof-20260709-094300` reached root-cause/payload release with this command installed; no exact reuse/write/marker and no same-thread allocation occurred in that single sample.

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
   After 51 valid focused root-path runs without exact reuse/write/marker, do not keep running identical blind `spray=474` batches as the next default step. The strongest observed near-miss is still `0x20` at `payload-0x3810`; use that evidence to compare against Frida controlled-reuse diagnostics.

5. Rank candidates by:
   - exact reuse/write/marker first
   - then `HasBadCleanup=True` and `HasPayloadRelease=True`
   - then higher `PostPayloadAlloc20Count`
   - then smaller `BestPostPayloadAllocDelta`
   - then lower failure rate

6. Run deep confirmation only after `allocdiag` produces exact reuse/write/marker, or repeatedly shows sub-megabyte allocator proximity on the same size/caller.
   Do not spend long deep runs on candidates that do not improve allocator diagnostics.

7. Next diagnostic step: obtain or run a Frida controlled-reuse log and compare allocation size, heap, thread, caller/stack, and timing against `remote-results\near-miss-analysis-20260707-232117`.
   This has now identified `0x20` caller `0x00007ffeaa6850d9` as the Frida-matched path, and `run-proof.ps1` now has targeted CDB stack diagnostics for it. Next passive run should use `ObserveMode allocdiag` and a nonzero `PostPayloadAllocStackCount` to collect those target stacks before another overnight sweep.
   The 2026-07-08 focused batch confirmed the `0x30` near-miss targeted stack path, but not the Frida-matched `0x20` path. The `0x30` stack is UI/ribbon/AirSpace related and far from payload in that run, so do not treat it as the main proof path unless it becomes close again.
   A later 2026-07-08 filtering check verified event export filtering, but only produced a weak non-Frida-matched `0x20` allocation at `payload+0x121bc860`.
   The 2026-07-08 cleanup/stability batch completed 2/2 Scheduled Tasks without startup crash and exposed the ASLR issue in targeted caller matching. The next diagnostic run should verify module-relative targets, not absolute-address targets.
   A follow-up module-relative check verified command installation but did not hit the targeted callers.
   The next focused batch hit `mso20win32client+0x2a4a57`, but only at `payload+0x4763b0`, with stack through `wwlib!PobjxCreate` / `PwwserverdocCreate` / `WWSERVEROBJ::Initialize`.
   The Frida-matched `mso20win32client+0x2a50d9` path remains missing in passive CDB.
   A new payload-free heap/thread diagnostic now records `CDB_PAYLOAD_RTLFREEHEAP_ENTER` and annotates later allocations with same-free-heap/thread fields. Runtime was verified in `remote-results\remote-proof-20260708-222714`: allocations were same heap but different thread and still far from payload. Keep `RtlFreeHeap` disabled until payload release; an always-active free breakpoint stalled root-cause progress.
   The current best strict passive signal is `remote-results\remote-proof-20260709-001633`, RUN 4: `spray=474`, `0x30`, `mso20win32client+0x2a4a57`, `sameFreeHeap=1`, `sameFreeThread=1`, `payload+0x143710`.
   Focused repeats did not improve it. Next non-identical step should either add a targeted diagnostic for that same-thread `0x30` path, or use Frida-guided timing comparison to explain why `mso20win32client+0x2a50d9` remains missing passively.

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
- `CDB_PAYLOAD_RTLFREEHEAP_ENTER` runtime capture has been verified, but runtime self-disable needs confirmation in a later sample that hits the free breakpoint after the `bd 7` self-disable change.
- WinRM/PowerShell progress streams can corrupt local wrapper result collection with CLIXML noise. Keep `$ProgressPreference = "SilentlyContinue"` in local, remote, and Scheduled Task runner contexts.
- Scheduled Task / Office startup failures remain common in batches. Recent failures included `0xc0000005` and `0xc0000142`; the latest 6-run batch had 3 Scheduled Task `0xc0000005` failures and 1 preview-trigger failure. Treat those rows as invalid proof attempts and prioritize launcher stabilization before larger unattended sweeps.
- VM Application/WER logs around unstable windows show crashes across `powershell.exe`, `cmd.exe`, `taskkill.exe`, `WINWORD.EXE`, `cdb.exe`, and Office helper processes. Do not assume all `scheduled-task` failures are wrapper bugs; capture diagnostics and reduce avoidable process-launch pressure.
- Frida proves controllability, not passive reuse.
- Shared result files can be stale; prefer unique per-run summaries from the fixed remote wrapper.
- Word COM is unreliable from non-interactive WinRM; use Scheduled Tasks for remote proof runs.
- Interactive Scheduled Tasks require an active logged-in VM user. Rebooting the VM clears that session and blocks proof execution until `labadmin` logs in again.
- `docs/cache` may contain old generated DOCX candidates after generator changes. Delete the cache if DOCX generation logic changes.
