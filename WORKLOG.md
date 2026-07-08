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
