# Ночной журнал работ

## 2026-07-08 00:07 MSK

Текущая цель: проверить новую CDB-диагностику для passive `spray=474`, не гоняя большие серии.

Что сделано:

- Синхронизировал свежие файлы на VM.
- На VM прошли `RunProof.Static.Tests.ps1` и parser check для `run-proof.ps1`.
- Первый тестовый proof-run выявил ошибку в диагностике: второй `bu ntdll!RtlAllocateHeap` не создал отдельный breakpoint, а переопределил основной breakpoint `5`. Этот прогон остановлен и очищен.
- Исправил `run-proof.ps1`: targeted tags теперь встроены внутрь единственного `RtlAllocateHeap` breakpoint.
- Добавил static test, который запрещает второй `RtlAllocateHeap` breakpoint.
- Локально прошли `RunProof.Static.Tests.ps1` и parser check.
- Повторно синхронизировал исправление на VM.

Результат тестового `allocdiag`:

- Прогон `spray=474`, `ObserveMinutes=4`, `PostPayloadAllocTraceCount=300`, `PostPayloadAllocStackCount=3` завершился на VM штатно.
- Proof дошел до root-cause пути: `HasBadCleanup=True`, `HasPayloadRelease=True`.
- Exact reuse/write/marker нет: это валидный `no-success`.
- В CDB log только один `bu ntdll!RtlAllocateHeap`; ошибки `breakpoint 5 redefined` больше нет.
- Ближайшая аллокация в этом run была слабая: `0x20` at `payload+0x12ad0260`.
- Targeted tags по Frida-matched caller не появились в этом run. Это не ломает диагностику, просто конкретный caller/near-miss не случился.

Найденный побочный дефект:

- Удаленный proof завершился, но локальный `Invoke-RemoteProofSweep.ps1` не дописал нормальный local report.
- Причина по симптомам: WinRM/PowerShell progress stream дал CLIXML-шум и ошибка возникла уже после фактического завершения proof.
- Исправил wrapper: progress подавляется локально, в remote scriptblocks и внутри Scheduled Task runner.
- Добавил static test, чтобы это не потерять.
- Добавил синхронизацию самого `Invoke-RemoteProofSweep.ps1` на VM. До этого VM static test мог проверять старую копию wrapper.

Следующий шаг:

- Static tests и parser checks прошли локально.
- Контрольный remote-run после исправления wrapper прошел без CLIXML-падения.
- Локальный report создан: `remote-results\remote-proof-20260708-001344\remote-proof-report.csv`.
- Этот контрольный run не дошел до bad cleanup/payload release, поэтому exploit-сигналов не дал.
- Следующий шаг: небольшой bounded batch на `spray=474`, чтобы проверить новую targeted диагностику на нескольких валидных попытках, не возвращаясь к слепым 50 прогонам.

## 2026-07-08 00:23 MSK

Запущен небольшой фоновый batch:

- PID: `12412`
- stdout: `remote-results\night-targeted-20260708-002327.out.log`
- stderr: `remote-results\night-targeted-20260708-002327.err.log`
- параметры: `spray=474`, `RepeatsPerSpray=6`, `ObserveMode=allocdiag`, `ObserveMinutes=4`, `PostPayloadAllocTraceCount=300`, `PostPayloadAllocStackCount=3`, `StopOnExactReuse`.

Цель batch:

- Не искать вслепую 50 раз.
- Проверить новую targeted CDB-диагностику на нескольких валидных попытках.
- Если появится exact reuse/write/marker, остановиться автоматически.

Старт `12412` не дошел до VM: hidden PowerShell не смог автозагрузить `Microsoft.PowerShell.Security`, поэтому `ConvertTo-SecureString` упал до создания WinRM session.
Proof-run не запускался.
Перезапускаю batch через .NET `SecureString`, без зависимости от PowerShell security module.

Перезапуск:

- PID: `24904`
- stdout: `remote-results\night-targeted-20260708-002443.out.log`
- stderr: `remote-results\night-targeted-20260708-002443.err.log`

Промежуточный результат:

- RUN 1: валидный root-cause run, `HasBadCleanup=True`, `HasPayloadRelease=True`, exact reuse/write/marker нет.
- RUN 1 не дал post-release allocation events: `PostPayloadAlloc20Count=0`, targeted tags не появились.
- В CDB есть `breakpoint 7 redefined` после cleanup. Это не старый баг `breakpoint 5 redefined`: основной `RtlAllocateHeap` breakpoint не переопределен. Нужно учитывать как CDB-шум/return-breakpoint поведение, но пока он не дал ложного success.
- RUN 2: невалидный `scheduled-task` crash с `TaskLastTaskResult=3221225477` (`0xc0000005`). Wrapper продолжил batch и применил cooldown.
- RUN 3: валидный root-cause run, `HasBadCleanup=True`, `HasPayloadRelease=True`, exact reuse/write/marker нет.
- RUN 3 также не дал post-release allocation events: `PostPayloadAlloc20Count=0`, targeted tags не появились.
- RUN 4: невалидный `scheduled-task` failure с `TaskLastTaskResult=3221225794` (`0xc0000142`). Это уже второй launcher/Office-level сбой в batch.

Промежуточный вывод:

- Новая CDB-команда не ломает root-cause путь и не дает старого `breakpoint 5 redefined`.
- В двух валидных root-cause runs после payload release не было monitored allocations, поэтому targeted stack-теги пока не проверены на реальном hit.
- Следующая проблема для ночных серий: высокая доля Scheduled Task стартовых сбоев. Wrapper их фиксирует и продолжает, но это сильно снижает полезность длинных серий.

Итог batch:

- Report: `remote-results\remote-proof-20260708-002444\remote-proof-report.csv`.
- Events: `remote-results\remote-proof-20260708-002444\remote-proof-events.log`.
- 6 attempts total: 4 валидных root-cause/no-success, 2 scheduled-task failures.
- Валидные: RUN 1, 3, 5, 6.
- Невалидные: RUN 2 `0xc0000005`, RUN 4 `0xc0000142`.
- Exact reuse/write/marker не найден.
- RUN 6 впервые подтвердил targeted диагностику `CDB_NEAR_MISS_ALLOC30_RETURN` и `CDB_NEAR_MISS_ALLOC30_STACK`.
- RUN 6 deltas слабые: `0x30` at `payload+0x845b3c0`, `0x40` best at `payload+0x4819db0`.
- Stack для `0x30` near-miss: `mso20win32client!Mso::Memory::AllocateEx -> mso40uiwin32client!AirSpace::BatchCommand::Create -> AirSpace::FrontEnd::Scene::BeginBatch -> NetUI::DeferCycle::StartDefer -> ... -> wwlib!PitbsCreateAndReadBuiltinOtbs`.
- `CDB_FRIDA_MATCHED_ALLOC20_RETURN` не появился.

Правка после batch:

- `Invoke-RemoteProofSweep.ps1` теперь фильтрует `remote-proof-events.log`: пишет только реальные runtime event lines, а не строки установки CDB breakpoint.
- Добавлены targeted tags в экспорт событий.
- Это нужно потому, что CDB log содержит названия tags внутри текста команды `bu ntdll!RtlAllocateHeap`, и простой `Select-String` загрязняет events.

## 2026-07-08 checkpoint перед VM sync

- Локально повторно прошли `RunProof.Static.Tests.ps1`, `RemoteProofSweep.Static.Tests.ps1` и parser checks для `run-proof.ps1` / `Invoke-RemoteProofSweep.ps1`.
- Proof-run не запускался.
- VM на момент проверки была недоступна по WinRM, поэтому sync на `C:\CVELAB\final` и VM static/parser checks отложены до запуска VM.
- Текущий коммит должен зафиксировать локально проверенное состояние перед VM sync: targeted CDB diagnostics, suppression `$ProgressPreference`, sync самого wrapper на VM и runtime-only фильтрацию `remote-proof-events.log`.

## 2026-07-08 VM sync/static checks

- VM `CLIENT-PATCHED` доступна по WinRM на `192.168.200.132`; `labadmin` активен в console session.
- Синхронизированы 11 файлов на `C:\CVELAB\final`, включая `Invoke-RemoteProofSweep.ps1`, `run-proof.ps1`, static tests, preview/frida/maintenance helpers, `AGENTS.md` и план.
- На VM прошли `RunProof.Static.Tests.ps1`, `RemoteProofSweep.Static.Tests.ps1` и parser checks для `run-proof.ps1` / `Invoke-RemoteProofSweep.ps1`.
- Proof-run не запускался.

## 2026-07-08 short runtime-event filtering check

- Запущен короткий bounded `allocdiag` batch: `spray=474`, `RepeatsPerSpray=2`, `ObserveMinutes=4`, `PostPayloadAllocTraceCount=300`, `PostPayloadAllocStackCount=3`, `StopOnExactReuse`.
- Local result: `remote-results\remote-proof-20260708-105754`.
- RUN 1: `no-success`, root-cause path не достигнут (`HasBadCleanup=False`, `HasPayloadRelease=False`), proof-сигналов нет.
- RUN 2: `no-success`, root-cause path достигнут (`HasBadCleanup=True`, `HasPayloadRelease=True`), exact reuse/write/marker нет.
- RUN 2 дал один post-release `0x20` allocation: `payload+0x121bc860`, caller `0x00007ff8a9cd50d9`; это далеко и не Frida-matched caller.
- `CDB_FRIDA_MATCHED_ALLOC20_RETURN` и `CDB_NEAR_MISS_ALLOC30_RETURN` не появились.
- `remote-proof-events.log` теперь содержит реальные runtime lines и не содержит CDB breakpoint command text, `.echo`, `Numeric expression missing` или `CDB PROOF` banner lines.
- Полный CDB log RUN 2 сохранён локально: `remote-results\remote-proof-20260708-105754\cdb-proof-attempt-0008-20260708-010709-t2000-cFalse-rFalse-ocustomXml_first-spray474-repeat1.log`.

## 2026-07-08 Scheduled Task startup stability cleanup

- Разобрал существующие `scheduled-task` failures и Application/WER events на VM.
- В окнах сбоев падали не только `powershell.exe`, но и `cmd.exe`, `taskkill.exe`, `WINWORD.EXE`, `cdb.exe` и Office helper processes. Это выглядит как нестабильность VM/Office/CDB под нагрузкой, а не один детерминированный bug wrapper.
- Нашёл конкретный уменьшаемый риск: `tools\maintenance\clean-proof-state.ps1` запускал внешние `cmd.exe /c taskkill ...`, а `cmd.exe`/`taskkill.exe` уже попадали в APPCRASH с `0xc0000005`.
- Добавил static test, запрещающий `cmd/taskkill` в `clean-proof-state.ps1`, сначала подтвердил RED.
- Убрал внешний `cmd/taskkill` fallback из `clean-proof-state.ps1`; cleanup теперь опирается на PowerShell-native `Stop-Process`.
- Локально прошли `RunProof.Static.Tests.ps1`, `RemoteProofSweep.Static.Tests.ps1` и parser checks для `run-proof.ps1`, `Invoke-RemoteProofSweep.ps1`, `tools\maintenance\clean-proof-state.ps1`.
- Синхронизировал изменения на VM: `AGENTS.md`, `WORKLOG.md`, план, `tools\maintenance\clean-proof-state.ps1`, `tests\RunProof.Static.Tests.ps1`.
- На VM прошли `RunProof.Static.Tests.ps1`, `RemoteProofSweep.Static.Tests.ps1` и parser checks для `run-proof.ps1`, `Invoke-RemoteProofSweep.ps1`, `tools\maintenance\clean-proof-state.ps1`.

Follow-up bounded batch:

- Local result: `remote-results\remote-proof-20260708-112255`.
- 2/2 Scheduled Tasks завершились с `TaskLastTaskResult=0`; startup crash не воспроизвёлся.
- RUN 1: `HasBadCleanup=True`, `HasPayloadRelease=True`, exact reuse/write/marker нет. Был один `0x30` post-release allocation at `payload-0x8246f90`, caller `0x00007ff895534a57`.
- RUN 2: `HasBadCleanup=True`, `HasPayloadRelease=True`, exact reuse/write/marker нет, post-release allocation summary пустой.
- RUN 1 подтвердил важную проблему в targeted diagnostics: caller совпадает по module offset с прежним `0x00007ffe4bed4a57`, но absolute address изменился из-за ASLR (`mso20win32client.dll` base изменился).
- Исправил `run-proof.ps1`: targeted caller checks теперь module-relative:
  - Frida-matched `0x20`: `mso20win32client+0x2a50d9`.
  - near-miss `0x30`: `mso20win32client+0x2a4a57`.
- Static tests обновлены: запрещают ASLR-sensitive absolute caller comparisons для targeted diagnostics.
- Локально прошли `RunProof.Static.Tests.ps1`, `RemoteProofSweep.Static.Tests.ps1` и parser checks.
- Синхронизировал module-relative fix на VM (`run-proof.ps1`, static test и контекстные документы).
- На VM прошли `RunProof.Static.Tests.ps1`, `RemoteProofSweep.Static.Tests.ps1` и parser checks для `run-proof.ps1`, `Invoke-RemoteProofSweep.ps1`, `tools\maintenance\clean-proof-state.ps1`.

## 2026-07-08 module-relative targeted diagnostics check

- Запущен короткий verification batch: `remote-results\remote-proof-20260708-114636`, `spray=474`, `RepeatsPerSpray=3`, `ObserveMode=allocdiag`, `ObserveMinutes=4`, `PostPayloadAllocTraceCount=300`, `PostPayloadAllocStackCount=3`.
- RUN 1: failed `preview-trigger`, до CoCreateInstance не дошёл; `TaskLastTaskResult=0`.
- RUN 2: валидный root-cause/no-success, `HasBadCleanup=True`, `HasPayloadRelease=True`, exact reuse/write/marker нет.
- RUN 2 дал `PostPayloadAlloc20Count=13`, все наблюдаемые `0x20` allocations были далеко: `payload-0x18074a90`.
- RUN 2 не попал в module-relative targets: `CDB_FRIDA_MATCHED_ALLOC20_RETURN` / `CDB_NEAR_MISS_ALLOC30_RETURN` не появились. Это не опровергает fix: CDB log показывает, что команда установлена с `mso20win32client+0x2a50d9` и `mso20win32client+0x2a4a57`, но конкретный allocation caller был другим (`0x00007ff895f9e81a`, stack around `AppVIsvSubsystems64` / registry query).
- RUN 3: failed `scheduled-task`, `TaskLastTaskResult=3221225477` (`0xc0000005`). Diagnostics подтвердили `powershell.exe` APPCRASH до stdout/stderr, WER bucket `abd12585cd6c663009fe454baedf0a0b`.
- Вывод: module-relative diagnostics синтаксически валидны и синхронизированы, но целевой `mso20win32client+0x2a4a57` / `+0x2a50d9` hit ещё нужно поймать в реальном run. Scheduled Task / VM instability сохраняется.

## 2026-07-08 focused module-relative target batch

- Запущен bounded batch с редким polling: `remote-results\remote-proof-20260708-121407`, `spray=474`, `RepeatsPerSpray=6`, `ObserveMode=allocdiag`, `ObserveMinutes=4`, `PostPayloadAllocTraceCount=300`, `PostPayloadAllocStackCount=3`, `DelayBetweenRunsSeconds=60`, `ScheduledTaskFailureDelaySeconds=300`, `StopOnExactReuse`.
- Перед запуском VM была чистая: активных `ProofRemote-*`, `WINWORD` и `cdb` не было; `labadmin` был активен в console session.
- Итог: 2 валидных root-cause/no-success runs, 3 `scheduled-task` failures с `TaskLastTaskResult=3221225477` (`0xc0000005`) и 1 `preview-trigger` failure до CoCreateInstance.
- Exact reuse/write/marker снова не найден: `HasExactReuseRuntime=False`, `HasWatchHit=False`, `MarkerFound=False` во всех строках.
- RUN 1 подтвердил module-relative targeted hit `CDB_NEAR_MISS_ALLOC30_RETURN` для `mso20win32client+0x2a4a57`, но delta слабая: `0x30` at `payload+0x4763b0`.
- RUN 1 stack полезнее предыдущего AirSpace-варианта: `mso20win32client!Mso::Memory::AllocateEx -> wwlib!operator new -> wwlib!PobjxCreate -> wwlib!PwwserverdocCreate -> wwlib!WWSERVEROBJ::Initialize -> RPCRT4`.
- RUN 1 также дал `0x20` allocations at `payload-0xac007e0`, caller `ucrtbase+0x50d9`, не Frida-matched `mso20win32client+0x2a50d9`.
- RUN 4 достиг root-cause path, но без monitored post-release allocations.
- Полные CDB/diagnostics logs скопированы локально в `remote-results\remote-proof-20260708-121407`.
- Вывод: module-relative диагностика `+0x2a4a57` теперь проверена реальным hit, но не улучшила proximity; `+0x2a50d9` всё ещё не появился. Не стоит запускать следующий идентичный `spray=474` batch до отдельного шага по launcher stability или новой гипотезы по allocator pressure.

## 2026-07-08 Scheduled Task startup retry mitigation

- Текущая evidence по `scheduled-task` failures указывает на intermittent `powershell.exe` APPCRASH до stdout/stderr и до выполнения runner script.
- Это выглядит как VM/PowerShell startup flakiness, а не как proof-сигнал и не как deterministic harness error.
- Добавил TDD static check для bounded startup retry в `Invoke-RemoteProofSweep.ps1`; сначала подтвердил RED.
- Реализовал retry только для `FailureKind=scheduled-task`:
  - `ScheduledTaskStartupRetryCount` default `2`;
  - `ScheduledTaskStartupRetryDelaySeconds` default `120`;
  - `preview-trigger` failures и валидные `no-success` не ретраятся;
  - retry events пишутся в `remote-proof-events.log` как `SCHEDULED_TASK_STARTUP_RETRY`;
  - итоговый CSV получил поле `ScheduledTaskStartupRetryCount`.
- Локально прошли `RemoteProofSweep.Static.Tests.ps1` и parser check для `Invoke-RemoteProofSweep.ps1`.

Verification batch:

- Синхронизировал retry mitigation на VM и повторил VM static/parser checks; все прошли.
- Запущен короткий stability batch: `remote-results\remote-proof-20260708-164249`, `spray=474`, `RepeatsPerSpray=3`, `ObserveMode=allocdiag`, `ObserveMinutes=4`, `ScheduledTaskStartupRetryCount=2`.
- 3/3 Scheduled Tasks завершились с `TaskLastTaskResult=0`; startup retry не понадобился (`ScheduledTaskStartupRetryCount=0` во всех строках).
- RUN 1 не дошёл до root-cause path.
- RUN 2 и RUN 3 достигли `HasBadCleanup=True` и `HasPayloadRelease=True`, но exact reuse/write/marker не найден.
- Post-release allocation events и targeted tags в этом batch не появились.
- Полные CDB logs сохранены локально в `remote-results\remote-proof-20260708-164249`.

## 2026-07-08 payload free heap/thread diagnostics

- Следующая гипотеза после Frida comparison: passive CDB events должны различать просто близкий allocation и allocation на том же heap/thread, где реально был освобождён payload.
- Добавил TDD static checks для `ntdll!RtlFreeHeap`, `CDB_PAYLOAD_RTLFREEHEAP_ENTER` и полей `freeHeap`, `freeTid`, `sameFreeHeap`, `sameFreeThread`; сначала проверки падали на отсутствующем diagnostic.
- `run-proof.ps1` теперь ловит `RtlFreeHeap(payload)`, сохраняет freed heap/thread в pseudo-registers и добавляет comparison fields в общие post-payload allocation lines, legacy `0x20`, Frida-matched `0x20` и near-miss `0x30` targeted lines.
- `Invoke-RemoteProofSweep.ps1` теперь экспортирует `CDB_PAYLOAD_RTLFREEHEAP_ENTER` в `remote-proof-events.log`.
- Важный порядок breakpoint-ов: `RtlFreeHeap` breakpoint должен ставиться после `RtlAllocateHeap`, `bd 5` и `wwlib+0xd96cf0`, чтобы allocator оставался breakpoint 5 и doc lookup return оставался breakpoint 6.
- Первый вариант нарушил это: CDB log показал `breakpoint 5 redefined` перед `RtlAllocateHeap`. Исправлено перемещением `RtlFreeHeap` ниже doc-lookup breakpoint и добавлен static guard на порядок.
- Локально прошли `RunProof.Static.Tests.ps1`, `RemoteProofSweep.Static.Tests.ps1` и parser checks для `run-proof.ps1` / `Invoke-RemoteProofSweep.ps1`.
- Синхронизировал изменения на VM; VM static/parser checks прошли.
- Контрольный run `remote-results\remote-proof-20260708-174513` подтвердил CDB install order: `RtlAllocateHeap` остался breakpoint 5, `wwlib+0xd96cf0` стал breakpoint 6, `RtlFreeHeap` стал breakpoint 7, `breakpoint 5 redefined` больше нет.
- Этот run не дошёл до root-cause path (`HasBadCleanup=False`, `HasPayloadRelease=False`), поэтому runtime tag `CDB_PAYLOAD_RTLFREEHEAP_ENTER` ещё не подтверждён реальным payload free. Для этого нужен следующий root-cause allocdiag sample, не обязательно новый идентичный batch прямо сейчас.

Follow-up runtime checks:

- Batch `remote-results\remote-proof-20260708-180245`: 3 attempts, exact reuse/write/marker нет. RUN 1 failed `cdb`; RUN 2/3 не дошли до root-cause. RUN 3 подтвердил CDB install order без `breakpoint 5 redefined`, но дошёл только до `CDB_DOC_LOOKUP_RET`.
- Batch `remote-results\remote-proof-20260708-220111`: 2 attempts with `ObserveMinutes=8`. RUN 1 потребовал 2 startup retries (`0xc0000005`) и дошёл только до doc lookup; RUN 2 failed `preview-trigger`.
- Вывод после этих двух batches: активный с самого старта `RtlFreeHeap` breakpoint создавал pre-release CDB overhead. Даже при `$t2 == 0` CDB останавливался на каждом `RtlFreeHeap`, что коррелировало с потерей root-cause path.
- Исправил `run-proof.ps1`: `RtlFreeHeap` breakpoint теперь сразу выключается через `bd 7` после установки и включается только в `CDB_PAYLOAD_RELEASE_ENTER` вместе с allocator breakpoint (`be 5; be 7`).
- Добавил static guards: `RtlFreeHeap` должен быть disabled until payload release, payload release должен включать `be 5; be 7`.
- Verification batch `remote-results\remote-proof-20260708-222714`: 2/2 runs снова достигли root-cause/payload release. RUN 1 подтвердил `CDB_PAYLOAD_RTLFREEHEAP_ENTER` и post-release allocations with `sameFreeHeap=1`, `sameFreeThread=0`; closest observed allocation was still far (`0x30` at `payload+0x6e00050`, `0x20` at `payload+0xb12bb10`). Exact reuse/write/marker нет.
- RUN 2 в том же batch показал, что `RtlFreeHeap` breakpoint оставался включённым и печатал repeated payload-free lines. Исправил self-disable: matched `RtlFreeHeap(payload)` branch теперь выполняет `bd 7` после первого capture.
- Final verification sample `remote-results\remote-proof-20260708-224643`: root-cause/payload release достигнут, exact reuse/write/marker нет, post-release allocations нет. CDB log подтвердил command shape: `be 5; be 7`, `bu ntdll!RtlFreeHeap ... CDB_PAYLOAD_RTLFREEHEAP_ENTER ... bd 7`, затем install-time `bd 7`. В этом sample `CDB_PAYLOAD_RTLFREEHEAP_ENTER` не hit-нулся, поэтому runtime self-disable ждёт подтверждения на следующем sample, где payload free проходит через этот breakpoint.

## 2026-07-09 overnight same-free-thread diagnostics

- Запустил bounded micro-sweep `remote-results\remote-proof-20260709-001633`: `spray=471..477`, по 1 repeat, `ObserveMode=allocdiag`, `ObserveMinutes=4`, `PostPayloadAllocTraceCount=300`, `PostPayloadAllocStackCount=3`.
- Exact reuse/write/marker не найден.
- Лучший новый signal: `spray=474`, RUN 4, `CDB_NEAR_MISS_ALLOC30_RETURN`, `size=0x30`, `caller=mso20win32client+0x2a4a57`, `delta=+0x143710`, `sameFreeHeap=1`, `sameFreeThread=1`.
- Это намного строже прежних near-miss rows: allocation был на том же heap/thread, где freed payload, но всё ещё не exact reuse.
- В этом же batch `spray=472` дал `0x30` same-thread event, но далеко и на другом heap: `delta=0xffffffffe8cdbf30`, caller `AppVIsvSubsystems64`.
- `spray=471` и `476` дошли до root-cause/payload release без useful post-release allocations; `473`, `475`, `477` были слабее или не дошли до payload release.

Focused follow-ups:

- `remote-results\remote-proof-20260709-012612`: `spray=474`, 6 repeats. 4 root-cause/payload-release runs, 1 preview-trigger failure, 1 no-root-cause. Exact reuse/write/marker нет. Хороший `+0x143710` same-thread target не повторился; единственный post-release `0x20` был далёкий negative (`0xffffffffe88d7060`).
- `remote-results\remote-proof-20260709-021833`: `spray=472..475`, по 2 repeats. Exact reuse/write/marker нет. `472` дал только слабый `0x40 +0x86feae0`; `473` после startup retries дал далёкий `0x20` negative (`0xffffffffe90453e0`); `474/475` не улучшили proximity.
- Вывод: лучший строгий passive signal сейчас `spray=474`, `0x30`, `mso20win32client+0x2a4a57`, same heap/thread, `payload+0x143710`. Frida-matched `mso20win32client+0x2a50d9` всё ещё не появился в passive CDB.

Report/schema update:

- Добавил TDD static checks для automatic same-free allocation ranking в local и remote reports.
- `run-proof.ps1` теперь пишет в attempt summary:
  - `BestSameFreeHeapAllocSize`, `BestSameFreeHeapAllocDelta`, `BestSameFreeHeapAllocCaller`;
  - `BestSameFreeThreadAllocSize`, `BestSameFreeThreadAllocDelta`, `BestSameFreeThreadAllocCaller`.
- `Invoke-RemoteProofSweep.ps1` прокидывает эти поля в `remote-proof-report.csv`.
- Smoke `remote-results\remote-proof-20260709-065952` подтвердил новую схему remote report; run достиг root-cause/payload release, exact reuse/write/marker нет, same-free поля присутствуют, но были пустыми из-за отсутствия post-release allocations.
