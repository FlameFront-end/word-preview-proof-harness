# Текущие наблюдения

## Цель

Собрать DOCX, который воспроизводит поведение в лабораторном окружении без принудительного управления аллокациями через Frida.

## Важное различие

Прогоны с Frida доказывают, что DOCX доходит до нужного пути в Word Preview:

- поиск документа
- bad cleanup
- release payload-объекта
- reuse аллокации, когда Frida его принудительно подставляет
- запись маркера, когда Frida принудительно подставляет reuse

Они пока не доказывают, что DOCX воспроизводит финальное поведение без Frida. Для этого CDB-only/passive observation должен показать естественный exact reuse и запись маркера.

## Проверенные варианты DOCX

| Attempt | Tables | CustomXml | Rpr | Order | Frida HasWrite | Frida BadCleanup | Frida PayloadRelease | Заметки |
| --- | ---: | --- | --- | --- | --- | --- | --- | --- |
| 0001 | 500 | True | True | tables_first | True | True | True | Воспроизводится с Frida forcing |
| 0002 | 500 | True | True | customXml_first | True | True | True | Порядок не обязателен для Frida-пути |
| 0003 | 500 | True | False | tables_first | True | True | True | rPr не обязателен для Frida-пути |
| 0005 | 500 | False | True | tables_first | True | True | True | customXml не обязателен для Frida-пути |
| 0007 | 500 | False | False | tables_first | True | True | True | Минимальный текущий Frida-путь: только таблицы |
| 0007 | 250 | False | False | tables_first | True | True | True | Только таблицы, Frida-путь сохраняется |
| 0007 | 1 | False | False | tables_first | True | True | True | Негативный контроль тоже сработал с Frida forcing |

## CDB-only наблюдения

| Tables | CustomXml | Rpr | Order | SprayCount | HasBadCleanup | HasExactReuseRuntime | HasWatchHit | Заметки |
| ---: | --- | --- | --- | ---: | --- | --- | --- | --- |
| 1 | False | False | tables_first | 0 | False | False | False | После правки CDB ready-detection runtime events не появились |
| 500 | False | True | tables_first | 0 | True | False | False | Исторический CDB-only кандидат |
| 2000 | False | True | customXml_first | 0 | True | False | False | Исторический CDB-only кандидат |
| 2000 | False | False | customXml_first | 0 | True | False | False | Исторический CDB-only кандидат без customXml/rPr |
| 1000 | True | True | tables_first | 0 | True | False | False | Исторический CDB-only кандидат |

## Текущие выводы

- `rPr` formatting не требуется для Frida-наблюдаемого пути.
- Порядок `tables_first`/`customXml_first` не требуется для Frida-наблюдаемого пути.
- `customXml` не требуется для Frida-наблюдаемого пути.
- Самый сильный текущий кандидат - DOCX с большим количеством таблиц в `word/document.xml`.
- Даже 1 таблица без `customXml` и без `rPr` срабатывает с Frida forcing.
- Frida-forcing слишком широкий для атрибуции конкретной XML-структуры.
- Frida-результаты показывают путь до `badCleanup`/`payloadRelease`, но не позволяют доказать, какой DOCX даст естественный reuse без Frida.
- CDB-only результаты до правки были недостоверны: в диагностическом выводе появлялся `[CDB_READY_FLAG]`, но `run-proof.ps1` иногда всё равно уходил в timeout или считал attach-helper упавшим до ready.
- `run-proof.ps1` исправлен: ready-detection теперь ищет `[CDB_READY_FLAG]` и в CDB log, и в attach-helper stdout.
- После правки `t1/customXml=False/rPr=False` дошёл до `CDB breakpoints ready` и корректно завершился runtime timeout без terminal event.
- Для последнего `t1` CDB log содержит только команды установки breakpoints, но не runtime-события `CDB_HROPEN`, `CDB_DOC_LOOKUP`, `CDB_FDISPOSE`.
- В старых CDB-only результатах уже есть конфигурации с `HasBadCleanup=True`, но ни одна пока не дала `HasExactReuseRuntime=True` или `HasWatchHit=True`.
- `run-proof.ps1` дополнительно исправлен: PreviewTrigger теперь пишет stdout/stderr в отдельные файлы, а harness показывает exit code и хвосты логов после `GoFile` и при runtime timeout. Это должно показать, доходит ли trigger до `Initialize`.
- `run-proof.ps1` дополнительно исправлен: attach-helper теперь пишет sidecar trace-файл напрямую через `Add-Content`, чтобы диагностировать случаи, когда stdout/stderr пустые и CDB log не создан.
- `run-proof.ps1` дополнительно исправлен: если attach-helper завершается без stdout/stderr/trace/CDB-log, harness повторяет attach прямым запуском `cdb.exe` без wrapper PowerShell.

## Следующие проверки

1. Не тратить CDB-only время на `t1`: он годится как Frida-control, но не как natural reuse кандидат.
2. Повторить CDB-only прогоны на исторических кандидатах с `HasBadCleanup=True`, особенно `2000/customXml=False/rPr=False/customXml_first`.
3. Искать конфигурацию, где CDB покажет natural `CDB_EXACT_REUSE_RUNTIME`, `CDB_WRITE_TO_REUSED_SLOT` и marker.
4. Использовать Frida только как диагностический инструмент для подтверждения `badCleanup`/`payloadRelease`, а не как proof DOCX-only воспроизведения.
