# Передача разработки — 2026-10-22

## Состояние проекта

Контрольная точка 22 октября 2026 — проверенный инкрементальный порт, развиваемый в [PR #1](https://github.com/gon7187/techstream/pull/1). Канонический репозиторий — [`gon7187/techstream`](https://github.com/gon7187/techstream), основная ветка `main`. Точный статус интеграции, SHA и CI следует сверять в PR и истории GitHub. Полная цель «всё без автомобиля» **не достигнута**: незавершённые source/consumer-гейты перечислены ниже. Работа оборудования и автомобиля остаётся **`PHYSICAL_UNCONFIRMED`**.

Полный повторный прогон с доступным локальным корпусом: **6 277 тестов, 0 failures, 0 errors, 0 skips** на коде `05b7249`; source-only регрессии — 17 PASS. Полный публичный CI и точный опубликованный SHA сверяются в PR #1.

Повторное ревью выявило два реальных сбоя с доступным частным корпусом, несмотря на зелёный публичный CI: преждевременный сброс состояния после `PrepareRetry` и отсутствие публикации callback24 в канонический ED0C gateway-кэш. Дополнительно исправлены пересекающиеся владельцы авторской utility-фикстуры и слишком широкий private-only skip guard. Проверки и границы этого исправления приведены в [verification](verification.md#контрольная-точка-22-октября-2026).

Исходный локальный план `.unlazy/no-car-final-20261020/PLAN.md` содержит **153 листа и шесть открытых корневых гейтов G1–G6**. Он и материалы `analysis/`, `runtime/`, `.unlazy/` — частные исследовательские данные, отсутствующие в публичном checkout. Доступный локальный корпус использован для проверки этой контрольной точки, но не публикуется и не требуется для публичной сборки. Зелёный частный прогон не закрывает непроверенные native-семейства или целиком старый план.

## Что подтверждено, а что нет

В репозитории есть нативное Linux-приложение GTK4/libadwaita, синтетические демонстрационные данные, офлайн-парсеры, отдельные диагностические и протокольные компоненты, некоторые связи выбранных профилей и ресурсов, обработчики записей и ограниченные программные сценарии. Наличие кода или успешный отдельный тест подтверждают только указанный контракт и проверенный снимок. Они не доказывают завершение семейства, полной интеграции или поддержку автомобиля.

Различайте виды свидетельств:

- **Реализация** — код существует в указанном модуле.
- **Проверка владельца** — владелец выполнил перечисленные проверки в конкретном снимке.
- **Независимая проверка** — отдельный проверяющий исследовал тот же зафиксированный снимок и контракт.
- **Только анализ исходника** — проверялись статические байты, метаданные или восстановленные ветви, без исполнения OEM-кода.
- **Физическое наблюдение** — проверялись конкретный адаптер, ЭБУ или автомобиль. В этой контрольной точке таких результатов нет.

## Что закрыто публично на этом чекпоинте

Эти пункты закрыты авторским кодом и проверками, не требующими OEM-образов, автомобиля или кабеля:

- **Три lifecycle-дефекта листа 153 и публикация владельца/кэша листа 108** — исправлены и закреплены регрессиями `LifecycleHardeningTests`/`PublicationOwnerTests`; отозванная гипотеза про статус 15 сохранена как опровергнутая.
- **Публичный one-phase execute/context листа 31 и pool consumer 151** — `ControlCommPhase2026.execute` с проверкой owned phase, ровно одной фазой, условной ImportData/ExportData пары, вызовом classic prepare `8990`, retry `3b90` и probe finish; покрыто `ControllerExecuteTests`.
- **Публичная цепочка моста 145→51** — `execute` → `retry_failed_write` → `dispatch_retry_callback` → `_run_outer` → `callback3` под `thread_callback_execution`, с реальным outer dispatch, возвратом ошибки в child и отказом не-child publisher (`EngineThreadRetryBridgeTests`).
- **Явные private-evidence skip** — `tests/private_evidence.py` вместо `FileNotFoundError`; приватный путь даёт `SkipTest` с точной причиной, публичный путь отвергается.
- **DCM free-spin листа 3** — `_paced_native_sleep` добирает реальные 120 мс через stop-event; регрессия ограничивает шаги на virtual-clock host.
- **normal/compact GTK** — `scripts/desktop-smoke.sh normal|compact` и `techstream.py --smoke-compact`; оба варианта в CI.
- **DCM45/BSM27 в настоящем GTK-диалоге** — успех, native-предупреждение 2005, отмена с присоединением рабочего потока, новый запуск с отдельной фикстурой и отказ зонда BSM27; фикстура `scripts/utility_authored.py` с доказательством `tests/test_utility_authored.py`.
- **CI-гейт `public-root`** — свежий checkout под root без приватного корпуса, запрет публикации приватных путей, полный suite и offline workflows.

## Как проверить с чистого checkout

```sh
git clone https://github.com/gon7187/techstream.git
cd techstream
git checkout main
python3 -m unittest discover -s tests
python3 -m scripts.offline_verify workflows     # OFFLINE_WORKFLOWS_PASSED
sh scripts/desktop-smoke.sh normal              # GTK smoke, широкий layout
sh scripts/desktop-smoke.sh compact             # GTK smoke, свёрнутый layout
```

Приватный корпус не нужен: тесты, которым он необходим, дают явный `SkipTest` с точным путём. Helper разрешает только канонические частные корни внутри checkout, а публичные пути и выходы через symlink отвергает. Точные результаты текущего снимка — в [verification](verification.md#контрольная-точка-22-октября-2026).

## Известные красные и открытые места

Исправленные дефекты и открытая полнота разделены:

- **Retry:** успешный `PrepareRetry` очищает primary/passthru ошибки, сохраняя failed/context/error-kind/notifications для confirmation/IsFinish; успешный finish очищает своё состояние отдельно. Исходный результат writer не повышается до успеха.
- **Gateway:** callback24 публикует проверенное значение в принадлежащий engine канонический ED0C-кэш; callback25 читает его. Кэш переживает смену worker, а локальные callback-поля остаются локальными. Это узкое соединение, не полное принятие листов 114/31/151.
- **Authored fixture:** второй активный владелец отвергается до изменения общих реестров; исключение конструктора и повторный close восстанавливают предыдущие значения.
- **Листы 153/108:** lifecycle/publication-регрессии исправлены; полный исходный oracle и независимое принятие всего семейства остаются отдельными гейтами. Отозванная гипотеза про статус 15 не возвращается в дефекты.
- **Лист 134:** producer создаётся через `engine.bind_gateway_startup()`; узкий callback24/25 join исправлен, но это не принятие всей startup/reissue хронологии.
- **Листы 31/151:** публичный one-phase Execute и выбранный pool/getter/fallback реализованы. Полный source-issued execute/context, native multi-row cardinality и поведение ImportData/ExportData при исключении пока не приняты.
- **Лист 51:** финальная обычная retry-ветка имеет узкое независимое принятие. Публичный мост 145→51 существует: `execute` вызывает `retry_failed_write`, `query_control_error` публикует `dispatch_retry_callback`, а `_run_outer` выполняет `callback3` под `thread_callback_execution`. Добавлен публичный компонентный `EngineThreadRetryBridgeTests`: он прогоняет реальный `_run_outer`, проверяет успешный callback на outer-потоке, возврат ошибки в child и отказ не-child publisher. Независимое thread-job-level принятие на приватном контракте остаётся отдельным приоритетом.
- **Лист 49:** проверки владельца для native12 есть. Независимый reviewer оставил одну ошибку harness в ожидании числа обменов с общим кэшем; итоговый путь листа 105 после исправления отдельно не перепроверен. Независимое принятие остаётся открытым.
- **Лист 83:** scoped SIS/JSON/P6 и ограниченные dispatcher-когорты проверены, но сохранённый итоговый verdict предшествует обновлённому SMRT55 receipt и имеет статус HOLD. Нужна сверка с текущим receipt. Это не закрывает всё семейство UtilityEx.
- **Листы 68/58/69/71/152:** старые прямые матрицы не доказывают текущую интеграцию через router. Новый прогон листа 68 прерван пользователем; у листа 71 ограниченный conditional ownership фикс не закрывает все ошибки очистки. Лист 152 — будущая работа по TechVim в статусе ожидания исходной проверки; публичного модуля для неё пока нет.
- **Листы 3 и 11:** у DCM из листа 3 воспроизведён free-spin после буквального `Sleep(120)`. Механизм устранён: фоновые loops используют `_paced_native_sleep`, который добирает реальные 120 мс через stop-event, если host Sleep вернулся раньше; добавлена регрессия. Публичный GTK-сценарий DCM45 и BSM27 подтверждён: настоящий диалог, настоящий контроллер и рабочий поток по авторскому провайдеру дают успех, native-предупреждение 2005, отмену с присоединением потока и отказ зонда BSM27. CGW-prelude DCM45, raw-SDK хронология и полный цикл записи BSM27 остаются приватной границей. У листа 11 есть текущий ограниченный результат 54 теста и 29 GTK-проверок, но он не включает новую очередь листа 143 и не закрывает итоговый DCM/BSM render.
- **Листы 6, 14, 25, 41, 143:** ручная процедура листа 6 ещё не реализована; У листа 14 остаётся программная работа с raw history/formatter. Для листа 25 подготовлен, но не реализован контракт отложенного создания MultiMon lower; normal P4 active/system consumer joins также открыты. У листа 41 непустой P4 secondary пока возвращает `C0050001`. Новая очередь листа 143 не принята независимо и не подтверждена GTK/source проверкой.

Узко принятые случаи вроде STR52, SMRT55, ABS52, MM/HV подтверждают только названные наборы строк и источников. Они не означают полноту соответствующих семейств. Предыдущий отказ A0041001 у листа 105 был исправлен владельцем и является историческим результатом, а не доказанным текущим дефектом; независимая перепроверка исправленного снимка всё ещё требуется.

### Открытые блоки и где они лежат

| Блок | Что осталось | Код | Тесты | Чем закрывается |
| --- | --- | --- | --- | --- |
| 31/151 | source-issued execute/context oracle, native multi-row cardinality, независимый consumer review | `scripts/programming_2026_common.py`, `scripts/cuw_engine_threads.py`, `scripts/cuw_2026.py` | `tests/test_programming_2026_common.py`, `tests/test_cuw_engine_threads.py`, `tests/test_cuw_2026.py` | приватный `analysis/evidence/no-car-*`, `artifacts/extracted/*` |
| 145→51 | thread-job-level принятие моста | `scripts/cuw_engine_threads.py`, `scripts/programming_2026_common.py` | `tests/test_cuw_engine_threads.py` | зафиксированный приватный контракт |
| 114/134 | полное source/consumer-принятие startup/reissue; callback24→ED0C→callback25 исправлен | `scripts/cuw_gateway_startup.py`, `scripts/cuw_2026.py` | `tests/test_cuw_gateway_startup.py` | приватный `runtime/no-car-21/recovered/CUW.dll` |
| Consolidated bridge | подключить `ConsolidatedExecute2026` к worker/runtime, сохранить владельцев, scratch buffers и порядок callback | `scripts/programming_2026_consolidated.py`, `scripts/cuw_engine_threads.py`, `scripts/cuw_engine_worker.py`, `scripts/cuw_2026.py` | `tests/test_programming_2026_consolidated.py` | source-issued ownership/container contract для `TCUWLegacyCIDGettersAndFlashWriters.dll` |
| 153/108 | original-image oracle и независимый review | `scripts/utility_ex_lifecycle.py`, `scripts/cuw_2026.py` | `tests/test_utility_ex_lifecycle.py`, `tests/test_cuw_2026.py` | приватные OEM-образы и отдельный reviewer |
| 49/105/83 | DDR/native12 и SMRT55 receipt | `scripts/database_resources.py`, `scripts/toyota_saved_ffd.py`, `scripts/utility_ex_comm.py`, `scripts/utility_ex_lifecycle.py` | `tests/test_database_resources.py`, `tests/test_toyota_saved_ffd.py`, `tests/test_utility_ex_comm.py`, `tests/test_utility_ex_lifecycle.py` | актуальный приватный снимок/receipt и независимая перепроверка |
| 68/58/69/71/152 | route-gates через router; TechVim без публичного модуля | `scripts/cuw_legacy_engine.py`, `scripts/cuw_legacy_vendor.py`, `scripts/cuw_legacy_recovery.py`, `scripts/cuw_online.py` | `tests/test_cuw_legacy_engine.py`, `tests/test_cuw_legacy_vendor.py`, `tests/test_cuw_legacy_recovery.py`, `tests/test_cuw_online.py` | замороженный приватный snapshot и описания gate |
| 6 | ручной recorder producer и доказательство через UI | `scripts/drive_recorder.py`, `techstream.py`, `scripts/offline_tools.py` | `tests/test_drive_recorder.py`, `tests/test_desktop_smoke.py`, `tests/test_offline_tools.py` | leaf-спецификация листа 6 |
| 14 | raw history/formatter, семейства TSE | `scripts/tse_reports.py`, `scripts/tse_conversion.py`, `scripts/communication_log.py` | `tests/test_tse_reports.py`, `tests/test_tse_conversion.py`, `tests/test_communication_log.py` | leaf-спецификация листа 14 |
| 25 | отложенное создание MultiMon lower; normal P4 active/system joins | `scripts/monitor_poll.py`, `scripts/monitor_variable.py`, `scripts/frame_transport.py`, `scripts/data_monitor.py` | `tests/test_monitor_poll.py`, `tests/test_monitor_variable.py`, `tests/test_frame_transport.py`, `tests/test_data_monitor.py` | leaf-спецификация листа 25 |
| 41 | непустой P4 secondary возвращает `C0050001`; смешанная маршрутизация | `scripts/monitor_poll.py`, `scripts/monitor_legacy.py`, `scripts/data_monitor.py` | `tests/test_monitor_poll.py`, `tests/test_monitor_legacy.py`, `tests/test_data_monitor.py` | leaf-спецификация листа 41 |
| 143 | новая очередь не принята независимо | `scripts/monitor_dlc12.py`, `scripts/monitor_poll.py` | `tests/test_monitor_dlc12.py`, `tests/test_monitor_poll.py` | leaf-спецификация листа 143 |
| CommandDataLib 12 | недоказанные вложенные тела отдельно от внешней ComTol grammar | `scripts/drive_recorder.py`, `scripts/monitor_replay.py`, `scripts/active_replay.py`, `scripts/monitor_support.py` | `tests/test_drive_recorder.py`, `tests/test_monitor_replay.py`, `tests/test_active_replay.py`, `tests/test_monitor_support.py` | исходная сверка тел версии 12 |
| DCM45/BSM27 | CGW-prelude, raw-SDK хронология, полный цикл записи BSM27 | `scripts/utility.py`, `scripts/utility_ex_ty_body.py`, `scripts/utility_authored.py` | `tests/test_utility.py`, `tests/test_utility_authored.py` | приватные точные записи обмена |

## Политика моделей и передачи владения

Для возобновлённой механической реализации использовать доступную модель **`gpt-6-luna`**, для семантического source-gate и независимой проверки — **`gpt-6.1-sol`**. Модели `gpt-6.1-luna` в доступном каталоге нет; не приписывать ей результат. Не передавать активное владение или ревью «на лету»: сначала зафиксировать точные файлы и зависимости, затем передать снимок. Любое изменение зависимого файла требует узкой повторной проверки; старые receipts сохранять как исторические.

## Порядок продолжения

1. Прочитать этот документ и `graphify-out/GRAPH_REPORT.md`, затем локальный `.unlazy/no-car-final-20261020/HANDOFF.md`, `PLAN.md`, `CONTACTS.md`, `GATES.md`, `JVM.md` и нужные листовые handoff. Граф помогает навигации, но не подтверждает эквивалентность native-поведению. Если приватные каталоги отсутствуют, продолжать можно только по публичной части: всё приватно-зависимое честно остаётся открытым.
2. Выполнить свежий Git-аудит: fetch/prune канонического remote, проверить ветку, upstream, статус, worktree и расхождение с `origin/main`. Точные SHA, статус PR #1 и CI брать из свежего GitHub/Git-снимка; статусы draft и старые CI из истории ниже не являются текущими. До правок определить владельцев всех изменённых и новых файлов.
3. Сверить актуальные leases, исходники и тесты с их точными pins; не обновлять хеши пакетом.
4. **Закрыто.** Разобраны три независимых дефекта листа 153 и исправлена публикация владельца/кэша листа 108; отозванная гипотеза про статус 15 сохранена как опровергнутая.
5. Довести полный execute/context листа 31 и параметрический пул 151 до реального source-issued контекста и фактического потребителя. Публичный one-phase execute/context и pool consumer уже реализованы; остаются source-issued oracle, native multi-row cardinality и независимый review.
6. Публичная цепочка моста 145→51 реализована и покрыта `EngineThreadRetryBridgeTests`; остаётся thread-job-level принятие по зафиксированному приватному контракту.
7. Сверить gates листов 69/58/68 с текущим router и зависимостями; запускать матрицы только на согласованном замороженном снимке.
8. Реализовать ручной сценарий листа 6 и доказать его через настоящий UI путь. Отдельно закрыть недоказанные вложенные тела CommandDataLib версии 12.
9. Свести MultiMon листа 25, смешанную маршрутизацию 41 и очередь 143 с настоящими потребителями и идентичностью вложенного модуля. Сохранить различие MultiMon/обычного P4 и не подменять один выбранный producer другим.
10. Закрыть оставшиеся программные контракты и независимые ревью. Публичный CI, root-gate на свежем checkout и normal/compact GTK уже зелёные; остаются приватные source gates. Физическая проверка — отдельный будущий этап.

## Публичные и частные данные

В публичный репозиторий входят только авторский код, документы и синтетические фикстуры. Не копировать из частных артефактов C/ASM, оригинальные бинарники и базы, ключи, учётные данные, клиентские данные и сырые приватные логи. Частные evidence-каталоги — необязательные локальные указатели; setup и CI не должны требовать их наличия.

Для установки и запуска см. [Начало работы](getting-started.md). Границы архитектуры и доказательств описаны в [Архитектуре](architecture.md) и [Матрице реализации](full-port.md).

## История: продолжение 2026-10-21

Работа возобновлена с публичного снимка ветки `offline-completion-20261020` после слияния PR #3. Закрыт первый пункт порядка продолжения — три lifecycle-дефекта и публикация владельца/кэша:

- выбранный P5 worker при ошибке `Thread.start()` больше не сохраняет активного владельца и незапущенный поток; повторный `stop()` не пытается делать join;
- создание lifecycle, CAN/P6 pool, direct driver, selected lower, support cache, driver arbitration, manager mutex и общих field-наборов сериализовано и публикует ровно одного владельца на ключ контекста; конкурентные алиасы получают тот же объект и ту же блокировку;
- отмена выбранного CMN worker не перезаписывает более новый общий статус таймера снимком, прочитанным при входе; терминальная ошибка CMN по-прежнему публикует собственный результат. Гипотеза про статус 15 остаётся опровергнутой и закреплена регрессией.

Добавлены авторские проверки `LifecycleHardeningTests` и `PublicationOwnerTests`, не требующие OEM-образа. Публичный прогон без приватного корпуса: **6 228 тестов, 0 failures, 117 errors, 529 skipped**; все 117 errors — отсутствующие `analysis/evidence/no-car-*` и `artifacts/extracted/*`. Ruff, format и ShellCheck проходят. Один публичный failure (`test_secondary_cpu_host_failure...`) был дефектом структуры теста: проверки выполнялись после `subTest`, даже когда образ отсутствовал; они перенесены внутрь блока.

После этого исправлены ещё четыре публичных harness-дефекта, не требующих OEM-образа: проверки `Body2026Tests` перенесены внутрь `subTest`; Suzuki-тест подменяет source-issued central gateway key; UtilityEx retained-тест отвечает на реальный keepalive `3e00` каждого потока; фикстура листа 134 получает producer через `engine.bind_gateway_startup()`. Затем добавлен общий `tests/private_evidence.py`: тесты, которым нужен отсутствующий приватный корпус, теперь дают явный `SkipTest` с точным путём, а не `FileNotFoundError`; неправильный публичный путь helper отвергает. Итоговый публичный прогон: **6 240 тестов, 0 failures, 0 errors, 626 skipped**. Ruff, format, ShellCheck, offline workflows и GTK smoke проходят.

Границы: оригинальный oracle из 12 проверок и независимый source-review листов 153/108 не запускались — приватные образы в этой среде отсутствуют. Поэтому пункт 4 закрыт только по публичному owner-контракту, а не по полному native-принятию. Публичная часть 31/151 описана ниже; source-issued oracle, мост 145→51, route-gates 58/68/69 и следующие пункты остаются открытыми.

### Execute/context листа 31 и пул 151

Публичная часть шага 5 реализована на авторском/синтетическом контракте:

- `ControlCommPhase2026.execute(engine, session)` проверяет owned phase, controller/worker и неиспользованный replay; загружает выбранную строку в пул, выполняет ровно одну фазу (`get_cid`, `prepare`, `write`, `recovery`, `probe` или `change_gateway`), применяет engine→CONTROL ImportData/ExportData только при фактически связанном `J2534InterfacePair2026`, вызывает classic prepare `8990`, `3b90` retry/clear и probe finish; возвращает additive report (`native_phase`, `exports`, `retry_decision`) без promotion `programming_completed`.
- Пул параметров обновляется фактически исполненной строкой, включая alternate getter; `gateway_startup_fallback` проверяет тип и стадию первой строки; execute сверяет исполненную строку с загруженной.
- Добавлены `ControllerExecuteTests`: classic/modern prepare, write success/retry, recovery/probe, get_cid/change_gateway, foreign context, pool replacement/stage mismatch и фактическая pair chronology.

Проверка: **6 244 теста, 0 failures, 0 errors, 626 skipped**. Все 626 skip — явные причины: отсутствующий приватный корпус, ранее закрытые приватные образы и прежние авторские пропуски; helper `tests/private_evidence.py` вызывается только для путей под `analysis/`, `artifacts/`, `.unlazy/` или `runtime/no-car-*` и отвергает публичный путь. Ruff, format, ShellCheck, offline workflows и GTK smoke проходят. CI `39571959581` на `6662607`: `static`, `desktop`, `core (3.11)` и `core (3.13)` PASS; оба core-прогона — 6 244 теста, 0 failures, 0 errors, 626 skipped.

Границы: это публичный one-phase контракт, а не полный native oracle. Оригинальный execute/context, native multi-row cardinality и независимый consumer review не запускались; отсутствие приватного корпуса теперь видно как skip, а не как error. Для thread-job-level принятия моста 145→51 в этой среде отсутствует зафиксированный контракт из приватного листового handoff; публичная цепочка `execute`→`retry_failed_write`→`dispatch_retry_callback`→`_run_outer`→`callback3` реализована и покрыта компонентными тестами, включая реальный outer dispatch и возврат ошибки в child, но выдавать её за полный native-мост нельзя.

### Публичная часть без приватного корпуса: normal/compact GTK и нативные utility-сценарии

Закрыты оставшиеся публичные пункты порядка продолжения, которые не требуют OEM-образов, автомобиля или кабеля:

- `scripts/desktop-smoke.sh` получил варианты `normal|compact`. `normal` поднимает Xvfb 1600×1200 и рендерит широкий layout; `compact` — 1024×768 и выполняет тот же поток в свёрнутом layout, дополнительно проверяя сработавший breakpoint, свёрнутый split и кнопку меню. Неизвестный вариант отвергается кодом 2 до касания рабочего стола; `tests/test_desktop_smoke.py` фиксирует оба набора аргументов и отказ по usage.
- `techstream.py --smoke-compact` (только вместе с `--smoke-test`) задаёт окно 900×700; обычный запуск сохраняет прежние 1340×820.
- Новый публичный модуль `scripts/utility_authored.py` собирает `NativeUtilityRuntime` по авторским байтам и внедрённому провайдеру. Для зонда BSM27 smoke в `techstream.py` создаёт `NativeBSMRuntime` поверх библиотек этой фикстуры. Фикстура намеренно обходит проверку source-issued пары caller/engine, поэтому `scripts.utility.open_native_utility` сохраняет эту проверку, а `tests/test_utility_authored.py` отдельно доказывает, что авторская пара не проходит production-путь. Прежняя фикстура `tests/test_utility.py` теперь делегирует общему модулю, чтобы логика жила в одном месте.
- `scripts/text_resources.create_utility_group_text_examples` публикует авторские подписи выбранной native-группы и общей группы 20000; `create_utility_text_examples` сохранён без изменения поведения.
- Smoke прогоняет через настоящий GTK-диалог: успешный бизнес-этап DCM45 (исходный результат 0, блок 0x13724, вывод получателя), native-предупреждение 2005 (экран 0x948c/0x9492), отмену с присоединением рабочего потока, отдельный повторный запуск с новой фикстурой и отказ зонда BSM27 (исходный результат 99, общий экран ошибки).
- CI получил job `public-root`: свежий checkout в контейнере `python:3.12-slim` под root без приватного корпуса, запрет публикации `analysis/`, `artifacts/`, `.unlazy/` и `runtime/no-car-*`, полный прогон тестов и offline workflows. Job `desktop` теперь запускает и `normal`, и `compact`.

Проверка: **6 253 теста, 0 failures, 0 errors, 626 skipped**; Ruff, format (294 файла), ShellCheck, offline workflows, `desktop-smoke.sh normal` и `desktop-smoke.sh compact` — PASS локально на Python 3.14.8. CI `39578033940` на `ec9db8d`: `static`, `desktop`, `core (3.11)`, `core (3.13)` и `public checkout and root gate` — PASS; оба core-прогона — 6 252 теста, 0 failures, 0 errors, 626 skipped (последующий коммит добавляет один авторский тест фикстуры). Первый вариант job `public-root` на контейнере `ubuntu:24.04` падал на `actions/checkout@v4` из-за отсутствующего CA-хранилища; контейнер заменён на `python:3.12-slim` с установленным `ca-certificates`, и гейт проходит.

Границы: это публичный контракт — настоящий диалог, настоящий контроллер, настоящий рабочий поток и авторский провайдер. Выделенный `NativeDCM45Runtime`/CGW-prelude, повтор в том же контексте контроллера, raw-SDK хронология, полный цикл записи BSM27, исходный oracle листов 31/151/153/108, route-gates 58/68/69/71 и все листовые сценарии 6/14/25/41/143 остаются открытыми: им требуются точная leaf-спецификация и отдельное source/consumer-принятие. В публичном checkout нет локальных `.unlazy/`, `analysis/` и `runtime/`; для восстановления оставшегося объёма нужны точная листовая спецификация и отдельное source/consumer-принятие.
