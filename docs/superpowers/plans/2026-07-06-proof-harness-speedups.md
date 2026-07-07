# Proof Harness Speedups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Speed up candidate ranking by caching generated DOCX files and adding a fast allocator-diagnostics observation mode.

**Architecture:** Keep `run-proof.ps1` as the main harness and add narrowly scoped helpers for cache paths, cached DOCX copies, allocator size summaries, and `allocdiag` terminal behavior. Keep `Invoke-RemoteProofSweep.ps1` as the remote orchestrator and extend only its ranking output.

**Tech Stack:** PowerShell 5.1, Word COM, CDB command scripts, WinRM, Windows Scheduled Tasks.

---

### Task 1: Static Tests

**Files:**
- Modify: `tests/RunProof.Static.Tests.ps1`
- Modify: `tests/RemoteProofSweep.Static.Tests.ps1`

- [ ] Add tests for `allocdiag` in `ObserveMode`.
- [ ] Add tests for DOCX cache helpers and `docs\cache`.
- [ ] Add tests for multi-size allocation tags and CSV fields.
- [ ] Add tests for remote ranking fields.

### Task 2: DOCX Cache

**Files:**
- Modify: `run-proof.ps1`

- [ ] Add cache path helper based on tables/customXml/rPr/order.
- [ ] Generate cached DOCX once.
- [ ] Copy cache file to per-run DOCX path.

### Task 3: Allocdiag Mode

**Files:**
- Modify: `run-proof.ps1`

- [ ] Add `allocdiag` to `ObserveMode`.
- [ ] Emit multi-size post-payload allocation diagnostics.
- [ ] Stop early after allocation diagnostics are collected.

### Task 4: Summary And Ranking

**Files:**
- Modify: `run-proof.ps1`
- Modify: `Invoke-RemoteProofSweep.ps1`

- [ ] Parse allocation counts and closest deltas for multiple sizes.
- [ ] Preserve existing `PostPayloadAlloc20*` fields.
- [ ] Add compact ranking fields to remote report.

### Task 5: Verification

**Files:**
- Test: `tests/RunProof.Static.Tests.ps1`
- Test: `tests/RemoteProofSweep.Static.Tests.ps1`

- [ ] Run static tests.
- [ ] Run PowerShell parser checks.
- [ ] Sync to VM after tests pass.
