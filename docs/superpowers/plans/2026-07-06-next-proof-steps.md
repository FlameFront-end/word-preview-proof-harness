# Next Proof Steps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Continue the passive Word/CDB proof search without re-learning project context, while avoiding stale logs and false positives.

**Architecture:** Use `run-proof.ps1` for single proof attempts and `Invoke-RemoteProofSweep.ps1` for VM sweeps through interactive Scheduled Tasks. Rank candidates with per-run CSV summaries and allocator diagnostics before spending time on deep confirmation.

**Tech Stack:** PowerShell 5.1, Word COM, CDB, WinRM, Windows Scheduled Tasks, Frida diagnostics.

---

## Plan Maintenance Requirement

After every completed step, update this plan before continuing.
If evidence changes the best candidate, rewrite the remaining steps.
Do not leave completed, obsolete, or contradicted steps in the active path.

## Task 1: Inspect The Current Run

**Files:**
- Read: latest user-provided `log.txt` if copied into the workspace.
- Read: latest `remote-results\remote-proof-*\remote-proof-report.csv` if a remote wrapper run was used.
- Read: latest `remote-results\remote-proof-*\remote-proof-events.log` if a remote wrapper run was used.
- Modify: this plan if the evidence changes next steps.

- [x] Check whether the run used the fixed per-run summary files or older shared `attempt-summary.csv` behavior.
- [x] If the run used old scripts, treat remote-wrapper conclusions as potentially stale.
- [x] Extract these fields for the last meaningful attempt: `SprayCount`, `Status`, `FailureKind`, `HasBadCleanup`, `HasPayloadRelease`, `PostPayloadAlloc20Count`, `BestPostPayloadAllocSize`, `BestPostPayloadAllocDelta`, `HasExactReuseRuntime`, `HasWatchHit`, `MarkerFound`.
- [x] Update this plan with the observed best candidate.

Observed on 2026-07-06:

- The run used old VM scripts: CDB command was still `0x20`-only and no `attempt-summary-remote-*` files existed.
- `spray=0`: `HasBadCleanup=True`, `HasPayloadRelease=True`, `PostPayloadAlloc20Count=1`, closest delta `0x107205f0`.
- `spray=500`: `HasBadCleanup=True`, `HasPayloadRelease=True`, `PostPayloadAlloc20Count=4`, closest positive delta about `0x1ac810`.
- `spray=1000`: no root-cause path; preview `Initialize hr=0x800706BA`.
- `spray=2000`: scheduled `powershell.exe` crashed before writing output, task result `0xc0000005`.
- Best candidate so far: `spray=500`, but no exact reuse/write/marker yet.

## Task 2: Sync Fixed Files To VM

**Files:**
- Copy: `run-proof.ps1`
- Copy: `Invoke-RemoteProofSweep.ps1`
- Copy: `AGENTS.md`
- Copy: `tests\RunProof.Static.Tests.ps1`
- Copy: `tests\RemoteProofSweep.Static.Tests.ps1`
- Copy: `tools\preview\Invoke-PreviewTrigger.ps1`
- Copy: `tools\preview\trigger-preview.ps1`
- Copy: `tools\frida\Start-FridaPreviewRun.ps1`
- Copy: `tools\frida\frida-placement.js`
- Copy: `tools\maintenance\clean-proof-state.ps1`

- [x] Confirm no proof run is already active on the VM.
- [x] Sync files only after the user asks to proceed.
- [x] Run VM static tests after sync:

```powershell
cd C:\CVELAB\final
& .\tests\RunProof.Static.Tests.ps1
& .\tests\RemoteProofSweep.Static.Tests.ps1
```

- [ ] Update this plan with sync/test outcome.

2026-07-06 sync/test outcome:

- Fixed CDB `||` syntax and stale command-error false positives were synced to the VM.
- VM static tests and parser checks passed.
- A smoke run with `spray=0` validated that the `$t13` size filter installs without `Numeric expression missing`.

## Task 3: Run Short Allocdiag Ranking Sweep Around Spray 500

**Files:**
- Output: `remote-results\remote-proof-<stamp>\remote-proof-report.csv`
- Output: `remote-results\remote-proof-<stamp>\remote-proof-events.log`

- [x] Run only when the user explicitly asks to start tests.
- [x] Use this command shape:

```powershell
cd C:\Development\test\cve-ps1

.\Invoke-RemoteProofSweep.ps1 `
  -ComputerName 192.168.200.132 `
  -Credential $credential `
  -SprayCounts @(350,400,450,500) `
  -RepeatsPerSpray 3 `
  -ObserveMode allocdiag `
  -ObserveMinutes 4 `
  -PostPayloadAllocTraceCount 60 `
  -PostPayloadAllocStackCount 2 `
  -StopOnExactReuse
```

- [x] Rank candidates by exact reuse/write/marker first, then root-cause path, then allocation pressure and closest delta.
- [ ] Avoid `spray>=1000` until a later hypothesis explains the preview/RPC destabilization.

2026-07-06 note:

- A reported `success` at `spray=400` repeat 2 was false positive.
- Root cause: CDB rejected the `||` condition with `Numeric expression missing`, and the parser counted proof tags embedded in the command-error text.
- Local fix now removes `||` and excludes CDB syntax-error lines from runtime evidence.
- Before rerunning this task, sync the fixed local files to the VM.
- [x] Update this plan with the best 1-2 candidates.

2026-07-06 post-fix bounded sweep:

- No exact reuse/write/marker was observed.
- `spray=350`: reached bad cleanup in 2/3, payload release in 1/3, no post-release allocation summary.
- `spray=400`: reached bad cleanup and payload release in 2/3; one useful run had `0x30:count=5`, closest delta `0x12ae2900`; one run failed in CDB setup.
- `spray=450`: reached bad cleanup in 2/3, payload release in 1/3; one useful run had `0x30:count=6`, closest delta `0xffffffffffeabe30`.
- `spray=500`: scheduled `powershell.exe` crashed with `0xc0000005` before stdout/stderr; do not prioritize it for unattended runs.
- Important fix after the sweep: exact reuse detection was too narrow and only watched `0x20`; it now detects `@rax == payload` for any monitored allocation size.
- Later focused sweeps superseded this ranking. Best current candidate is `spray=474`.

## Task 4: Deep Confirm Narrowed Candidates

**Files:**
- Output: `remote-results\remote-proof-<stamp>\remote-proof-report.csv`
- Output: `remote-results\remote-proof-<stamp>\remote-proof-events.log`

- [ ] First run a short `allocdiag` syntax/proof smoke after syncing the any-size exact-reuse detector.
- [ ] Before every remote proof run, verify `quser` on the VM. If no user is logged in, ask for VM console login before starting Scheduled Task proof attempts.
- [ ] Run deep only for candidates that improved allocator diagnostics or produced exact-reuse signal.
- [ ] Use bounded attempts, not one unbounded run.
- [ ] Recommended shape after VM sync:

```powershell
cd C:\Development\test\cve-ps1

.\Invoke-RemoteProofSweep.ps1 `
  -ComputerName 192.168.200.132 `
  -Credential $credential `
  -SprayCounts @(450,400) `
  -RepeatsPerSpray 3 `
  -ObserveMode allocdiag `
  -ObserveMinutes 4 `
  -PostPayloadAllocTraceCount 80 `
  -PostPayloadAllocStackCount 2 `
  -StopOnExactReuse
```

- [ ] If exact reuse/write/marker appears, preserve the full CDB log and stop broad sweeps.
- [ ] Update this plan with the confirmed evidence.

2026-07-07 focused `spray=474` status:

- The any-size exact-reuse detector was synced to the VM and real CDB runs no longer show the old `Numeric expression missing` false-positive path.
- Best observed allocator proximity is now `spray=474`, run 1 from `remote-proof-20260707-112543`: `0x20:count=6`, closest positive delta `0x2c5e0`.
- Other useful `spray=474` evidence includes `0x40` closest deltas around `0x84090`, `0x119fe0`, and `0x198f60`.
- Exact reuse/write/marker has not been observed yet.
- `spray=474` has intermittent scheduled-task and CDB startup failures, but the wrapper records failures and continues.
- Code update after this run: `Invoke-RemoteProofSweep.ps1` now syncs/runs both static test files on the VM and defaults to a bounded cooldown between runs. `run-proof.ps1` now ranks closest allocation deltas across all monitored sizes, not only legacy `0x20` events.
- Follow-up fix: the all-size allocation summary initially hit a PowerShell `Argument types do not match` binder error on mixed delta groups. `run-proof.ps1` now stores absolute deltas as signed `Int64` and materializes size groups with `.ToArray()` before sorting. VM static checks passed after sync.
- 2026-07-07 validation run after the parser fix: `spray=474`, 2 repeats. No exact reuse/write/marker. One useful run reached bad cleanup and payload release with `0x30` closest negative delta `0xfffffffffff418a0` (about `-0xbe760`); one run failed in CDB startup. This does not beat the prior best `0x2c5e0`, but confirms all-size summary no longer drops useful runs.
- 2026-07-07 micro-sweep `spray=473,474,475`, intended 2 repeats each, completed 5 valid runs before local command timeout. No exact reuse/write/marker.
- `spray=473` reached root-cause path in both runs, with best `0x20` positive deltas `0x4ea9d0` and `0x2786f20`.
- `spray=474` reached root-cause path in both runs and remains best. One run had `0x30` closest positive delta `0x68f40`; the next run had the best passive near-miss so far: `0x20` at `payload-0x3810`, `0x40` at `payload-0xc320`/`payload-0xbb50`, and `0x50` at `payload-0x1045c0`.
- `spray=475` reached root-cause path but did not beat `474`; best was `0x30` positive delta `0x66b6d0`.
- The strongest observed caller for close post-release allocations remains `00007ffe4bed4a57` on the same heap as the freed payload. The best `0x20` near-miss used thread `476c`.
- Follow-up focused `spray=474` run with 3 repeats completed without exact reuse/write/marker. All 3 runs reached bad cleanup and payload release. Best delta in that batch was `0x30` positive `0x9e610`; useful, but it does not beat the prior `0x20` at `payload-0x3810`.
- A subsequent `spray=474` batch hit two `scheduled-task` startup crashes (`powershell.exe` APPCRASH `0xc0000005`) after one valid run. The wrapper now supports `-ScheduledTaskFailureDelaySeconds`; VM checks passed after sync.
- With `-ScheduledTaskFailureDelaySeconds 300`, a focused `spray=474` batch completed 3/3 valid runs without scheduled-task crashes, but no exact reuse/write/marker. Best delta in that batch was `0x40` positive `0x45f7ef0`.
- Neighbor retest `spray=473,474,475` showed: `473` best `0x40 +0x87a4a20`, `474` best `0x20 +0x248bb0`, and `475` failed at preview-trigger before CoCreateInstance. This keeps `474` as the only candidate worth repeated attempts.
- Aggregate local report ranking confirms the top near-misses are all `spray=474`: `0x3810`, `0x2c5e0`, `0x68f40`, `0x9e610`, and `0xbe760` absolute distance. Nearest non-474 candidates are much worse (`476` about `0x1e3a60`, `475` about `0x41c060`, `473` about `0x4ea9d0`).
- Two follow-up `spray=474` batches added 8 more valid root-cause runs and 2 failed starts (`preview-trigger` once, `scheduled-task` once). Exact reuse/write/marker was not observed.
- The second follow-up batch produced a new second-best near-miss: `0x20` and `0x30` allocations at `payload-0x21100` (`135424` bytes). This does not beat the best `payload-0x3810`, but confirms `spray=474` still repeatedly produces close allocator placement.
- Current local count is 45 valid `spray=474` root-cause runs after fixes/focused sweeps; the old `spray=400` reported success remains a known false positive and must not be counted.
- Near-miss aggregate artifacts are in `remote-results\near-miss-analysis-20260707-232117`. They include 624 allocation events and 75 per-run best rows.
- The best passive miss remains `0x20` at `payload-0x3810` from caller `0x00007ffe4bed4a57`. Other important clusters are `0x30` from caller `0x00007ffe4bed4a57` and `0x20` from caller `0x00007ffeaa6850d9`, both reaching `payload-0x21100`.
- After 45 valid focused runs without exact reuse/write/marker, more identical blind `spray=474` batches have reduced value. Next action is to compare these passive CDB caller/size/thread/heap patterns against a Frida controlled-reuse log before widening or running another overnight passive sweep.
- Fresh Frida diagnostic `remote-results\frida-diagnostic-20260707-132749` used the current `attempt 8 / t2000` DOCX and forced marker write. It learned `MALLOC_BASE=0x7ffeaa6850d9`, freed `0x20` payload `0x1f506285f20`, then observed `RtlAllocateHeap(size=0x20) original ret=0x1f505d927b0` before forcing reuse and writing `TBL_41414141`.
- This matches the passive CDB near-miss caller `0x00007ffeaa6850d9` for `size=0x20`. The best passive rows for that Frida-matched path are `payload-0x21100` and `payload+0x2c5e0`, so the next passive diagnostic should target stacks/timing for `0x20` caller `0x00007ffeaa6850d9`.
- Code update: `run-proof.ps1` now adds targeted CDB diagnostics for `0x20` caller `0x00007ffeaa6850d9` and `0x30` caller `0x00007ffe4bed4a57`. The tags are `CDB_FRIDA_MATCHED_ALLOC20_RETURN`, `CDB_FRIDA_MATCHED_ALLOC20_STACK`, `CDB_NEAR_MISS_ALLOC30_RETURN`, and `CDB_NEAR_MISS_ALLOC30_STACK`. These stacks are bounded by `PostPayloadAllocStackCount` but are not limited to the first global allocation events.
- Control run after that code update reached `HasBadCleanup=True` and `HasPayloadRelease=True` with no exact reuse/write/marker. It confirmed the duplicate `RtlAllocateHeap` breakpoint bug is fixed: there was only one `bu ntdll!RtlAllocateHeap` and no `breakpoint 5 redefined`. The run itself was a weak allocator sample: best `0x20` delta was `payload+0x12ad0260`.
- The same control run exposed an orchestration/reporting defect: the proof finished on the VM, but the local wrapper did not write a normal report because PowerShell progress/CLIXML noise broke result collection. `Invoke-RemoteProofSweep.ps1` now suppresses progress in local, remote, and Scheduled Task contexts; the next short run should verify local report creation.
- Sync fix: `Invoke-RemoteProofSweep.ps1` is now copied to the VM as part of `Copy-ProofScripts`, so VM-side static validation checks the current wrapper instead of a stale copy.
- Follow-up batch `remote-results\remote-proof-20260708-002444` ran 6 attempts on `spray=474`: 4 valid root-cause/no-success runs and 2 invalid Scheduled Task startup failures (`0xc0000005`, `0xc0000142`). Exact reuse/write/marker was not observed.
- The batch confirmed targeted `CDB_NEAR_MISS_ALLOC30_RETURN` / `CDB_NEAR_MISS_ALLOC30_STACK` works. The captured `0x30` stack is `mso20win32client!Mso::Memory::AllocateEx -> mso40uiwin32client!AirSpace::BatchCommand::Create -> AirSpace::FrontEnd::Scene::BeginBatch -> NetUI::DeferCycle::StartDefer -> ... -> wwlib!PitbsCreateAndReadBuiltinOtbs`.
- That `0x30` hit was far from payload (`+0x845b3c0`), and best all-size allocation in the run was `0x40` at `+0x4819db0`. This does not improve the passive proximity hypothesis.
- `CDB_FRIDA_MATCHED_ALLOC20_RETURN` did not appear in the batch. The Frida-matched `0x20` path remains unconfirmed in passive CDB after the targeted diagnostic change.
- Wrapper event export was fixed after the batch: `remote-proof-events.log` now filters to real runtime CDB event lines and excludes breakpoint command text, because proof tag names appear in the `bu ntdll!RtlAllocateHeap` command itself.
- Follow-up short filtering check `remote-results\remote-proof-20260708-105754` ran 2 attempts on `spray=474`. RUN 1 did not reach root-cause. RUN 2 reached `HasBadCleanup=True` and `HasPayloadRelease=True`, but exact reuse/write/marker was not observed.
- RUN 2 produced one post-release `0x20` allocation at `payload+0x121bc860`, caller `0x00007ff8a9cd50d9`. This is weak and does not match the Frida-matched caller `0x00007ffeaa6850d9`.
- `CDB_FRIDA_MATCHED_ALLOC20_RETURN` and `CDB_NEAR_MISS_ALLOC30_RETURN` did not appear in this run.
- The runtime-event export filter is now verified on real runtime lines: `remote-proof-events.log` contains payload-release/bad-cleanup/post-allocation lines and excludes CDB breakpoint command text, `.echo`, `Numeric expression missing`, and `CDB PROOF` banner lines.
- Scheduled Task / Office startup failures were investigated against existing reports and VM Application/WER logs. The failures are not isolated to one wrapper error: the same windows include APPCRASH records for `powershell.exe`, `cmd.exe`, `taskkill.exe`, `WINWORD.EXE`, `cdb.exe`, and Office helper processes.
- A narrow cleanup-risk reduction was implemented: `tools\maintenance\clean-proof-state.ps1` no longer launches `cmd.exe /c taskkill`, because those external helpers have themselves crashed with `0xc0000005`. Cleanup now relies on PowerShell-native `Stop-Process`.
- Follow-up bounded batch `remote-results\remote-proof-20260708-112255` completed 2/2 Scheduled Tasks with `TaskLastTaskResult=0`, so the cleanup change did not break the runner and no startup crash occurred in that small sample.
- Both runs reached `HasBadCleanup=True` and `HasPayloadRelease=True`, but no exact reuse/write/marker. RUN 1 produced one `0x30` allocation at `payload-0x8246f90`, caller `0x00007ff895534a57`.
- That caller revealed an ASLR bug in targeted diagnostics: it is the same `mso20win32client+0x2a4a57` path as old `0x00007ffe4bed4a57`, but the absolute address changed after restart. `run-proof.ps1` now targets `mso20win32client+0x2a4a57` for near-miss `0x30` and `mso20win32client+0x2a50d9` for Frida-matched `0x20`.
- Verification batch `remote-results\remote-proof-20260708-114636` confirmed the module-relative CDB command installs in a real run, but did not hit either targeted caller. RUN 2 was a valid root-cause/no-success sample with 13 far `0x20` post-release allocations at `payload-0x18074a90`; the caller was a different path around `AppVIsvSubsystems64` / registry query.
- The same batch also showed Scheduled Task instability persists: RUN 3 failed before stdout/stderr with `TaskLastTaskResult=3221225477` (`0xc0000005`), and diagnostics captured a `powershell.exe` APPCRASH in WER bucket `abd12585cd6c663009fe454baedf0a0b`.

## Task 5: Use Frida Only For Diagnostics If Passive Runs Stall

**Files:**
- Read: `tools\frida\frida-placement.js`
- Read: Frida output logs copied by the user.
- Modify: CDB diagnostics in `run-proof.ps1` only if Frida evidence shows a missing size/caller/timing class.

- [x] Obtain or run a Frida controlled-reuse log that includes allocation size, heap, thread, caller/stack, and marker/write timing.
- [x] Compare Frida reuse stack/caller with passive CDB allocation events from `remote-results\near-miss-analysis-20260707-232117`.
- [x] Identify whether passive diagnostics are missing allocator size, heap, thread, or timing.
- [x] Add only the smallest diagnostic needed to test that hypothesis.
- [x] Write a failing static test before changing the diagnostic tags or CDB command shape.
- [x] Update this plan after the next passive run.
- [x] Verify `Invoke-RemoteProofSweep.ps1` writes local CSV/report cleanly after progress suppression.
- [x] Verify targeted `0x30` stack capture can fire in a real VM run.
- [x] Verify `remote-proof-events.log` no longer includes breakpoint command text after runtime-event filtering.
- [ ] Stabilize Scheduled Task / Office startup failures before any larger unattended sweep.
  - [x] Remove `cmd.exe / taskkill.exe` from `clean-proof-state.ps1` to reduce avoidable external process crashes during Scheduled Task startup cleanup.
  - [x] Re-test failure rate with a small bounded batch before any larger unattended sweep.
  - [x] Add bounded retry handling for `FailureKind=scheduled-task` startup crashes before counting a planned proof attempt as failed.
    `Invoke-RemoteProofSweep.ps1` now exposes `ScheduledTaskStartupRetryCount` and `ScheduledTaskStartupRetryDelaySeconds`, records `SCHEDULED_TASK_STARTUP_RETRY` events, and adds `ScheduledTaskStartupRetryCount` to the local report.
    This is a mitigation for intermittent `powershell.exe` APPCRASH before runner stdout/stderr, not proof evidence.
  - [x] Verify the retry-enabled wrapper on VM with a short stability batch.
    `remote-results\remote-proof-20260708-164249` completed 3/3 Scheduled Tasks with `TaskLastTaskResult=0`, so the retry path did not need to fire.
    RUN 2 and RUN 3 reached root-cause/no-success; no exact reuse/write/marker and no post-release allocation events appeared.
- [x] Verify module-relative targeted diagnostics in a real run that hits `mso20win32client+0x2a4a57` or `mso20win32client+0x2a50d9`.
  - 2026-07-08 focused batch `remote-results\remote-proof-20260708-121407` hit `mso20win32client+0x2a4a57` in RUN 1 and emitted `CDB_NEAR_MISS_ALLOC30_RETURN` / `CDB_NEAR_MISS_ALLOC30_STACK`.
  - That hit was not close enough for proof: `0x30` returned `payload+0x4763b0`.
  - Stack: `mso20win32client!Mso::Memory::AllocateEx -> wwlib!operator new -> wwlib!PobjxCreate -> wwlib!PwwserverdocCreate -> wwlib!WWSERVEROBJ::Initialize -> RPCRT4`.
  - `mso20win32client+0x2a50d9` still has not appeared in passive CDB after the module-relative fix.
  - Batch quality was poor: 2 valid root-cause/no-success runs out of 6, with 3 Scheduled Task `0xc0000005` failures and 1 preview-trigger failure. Do not run another identical `spray=474` batch as the next default step.
- [ ] Decide the next non-identical step before more passive batches: either stabilize the Scheduled Task/PowerShell startup path, or change allocator-pressure/timing diagnostics to specifically target the still-missing `mso20win32client+0x2a50d9` Frida-matched path.
  - [x] Add a narrow allocator-pressure diagnostic for the Frida heap/thread hypothesis.
    `run-proof.ps1` now captures the actual `RtlFreeHeap(payload)` heap/thread as `CDB_PAYLOAD_RTLFREEHEAP_ENTER` and adds `freeHeap`, `freeTid`, `sameFreeHeap`, and `sameFreeThread` to post-payload allocation diagnostics.
  - [x] Preserve CDB breakpoint IDs after adding the new diagnostic.
    A first version installed `RtlFreeHeap` too early and real CDB logs showed `breakpoint 5 redefined`; the fixed command order installs `RtlAllocateHeap`, disables breakpoint 5, installs doc lookup return as breakpoint 6, then installs `RtlFreeHeap` as breakpoint 7.
  - [x] Verify command installation order in a real VM run.
    `remote-results\remote-proof-20260708-174513` shows no `breakpoint 5 redefined`; allocator remains breakpoint 5 and `RtlFreeHeap` is breakpoint 7.
  - [x] Verify `CDB_PAYLOAD_RTLFREEHEAP_ENTER` in a root-cause run.
    `remote-results\remote-proof-20260708-222714` verified the runtime tag in RUN 1. The observed post-release allocations were on the same heap as the freed payload but on a different thread, and they were still far from payload (`0x30 +0x6e00050`, `0x20 +0xb12bb10`).
  - [x] Avoid pre-release `RtlFreeHeap` CDB overhead.
    Two follow-up batches stalled before root-cause after the always-active `RtlFreeHeap` breakpoint was added. `run-proof.ps1` now installs it as breakpoint 7, immediately disables it with `bd 7`, and enables it only after `CDB_PAYLOAD_RELEASE_ENTER` with `be 5; be 7`.
  - [ ] Verify `RtlFreeHeap` self-disable in a runtime sample where payload free hits the breakpoint.
    `remote-results\remote-proof-20260708-224643` verified the command shape with `bd 7` inside the matched `RtlFreeHeap(payload)` branch, but that particular root-cause sample did not hit `CDB_PAYLOAD_RTLFREEHEAP_ENTER`.
