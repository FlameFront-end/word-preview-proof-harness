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
- Next action: keep bounded `allocdiag` runs focused on `spray=474`; only broaden again if the sub-megabyte proximity stops repeating.

## Task 5: Use Frida Only For Diagnostics If Passive Runs Stall

**Files:**
- Read: `tools\frida\frida-placement.js`
- Read: Frida output logs copied by the user.
- Modify: CDB diagnostics in `run-proof.ps1` only if Frida evidence shows a missing size/caller/timing class.

- [ ] Compare Frida reuse stack/caller with passive CDB allocation events.
- [ ] Identify whether passive diagnostics are missing allocator size, heap, thread, or timing.
- [ ] Add only the smallest diagnostic needed to test that hypothesis.
- [ ] Write a failing static test before changing the diagnostic tags or CDB command shape.
- [ ] Update this plan after the next passive run.
