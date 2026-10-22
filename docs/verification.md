# Проверки и свидетельства

В проекте несколько уровней проверки. Зелёный синтетический тест подтверждает только авторский путь и данные, которые он запускал. Он не доказывает такое же поведение OEM-программы, адаптера, ЭБУ или автомобиля.

## Контрольная точка 22 октября 2026 — текущая рабочая ветка

Текущая incremental acceptance привязана к frozen source pins: `techstream.py` SHA256 `a16a49b4e36f0eeee53a60a5bef28e07df66b62e635f0f119fad8d735b9210d5`, `.github/workflows/ci.yml` SHA256 `520166b5e4c27401131ea7875c3cbae7f7a7988ee12ba2b91ec758ce02323972`. Это file pins, не commit SHA.

| Проверка | Результат | Граница |
| --- | --- | --- |
| Полный private suite | **6 452 теста, 0 failures, 0 errors, 0 skips**, 207,258 с | Локальный частный корпус; `full-private-checks.log`, root reports G3 PASS |
| Чистый source-only snapshot | **6 443 теста, 0 failures, 0 errors, 744 пропуска**, 68,764 с | Не GitHub clone. Все 74 уникальные skip-причины проверены; это отсутствующие optional private/source/OEM packets (`public-skip-reasons.json`) |
| Automatic CONTROL | **19 checks PASS** для leaf G1/G4/G6/G8 | Отдельно root подтверждает G2 offline workflows PASS; не означает закрытие G1–G6 |
| GTK normal + compact | PASS после GUI-исправлений на frozen snapshot A16 | Проверены cancel/run и pending-close UI состояния; не физическое поведение |
| SourceSpec | **SCOPED_PASS final candidate** на A16 по независимому static review | Остальные source obligations открыты |
| Delivery-standards backend | PASS на `be752462` | Узкий backend verdict, не закрытие всех source/cleanup contracts |
| Source manifest | **299 записей, zero drift — PASS** | `final-private-acceptance.json` |

Два GUI-дефекта были найдены независимым static source/code review после более раннего успешного GTK smoke: idle-owner cancel/run должен восстанавливать каталог, а retry незавершённого cleanup — сохранять тот же owner. Исправления прошли новый normal/compact GTK. Свежий GitHub-clone прогон, публичный CI и доставка пока pending; не подставлять вместо них локальные результаты. Полное принятие 171 software obligations и full port не заявляются.

Точечные результаты этой работы имеют ограниченную область. Источник данных для каждого типа указан отдельно:

- **Публичные synthetic/regression checks:** Body/Sonar сохранил 62 исходных тестовых метода и проверки; добавлен bounded двух-CPU тест. Он подтверждает конкретное выполнение по двум адресам, не общую native multi-row cardinality. Исправление source-only Body skip guard не ослабляет исходные assertions.
- **Private source-dependent review:** scoped review принял Body/Sonar caller migration и лист 74 held-address consumer guard. Это не закрывает G2/G3 или оставшиеся raw retry/outer-job ветви.
- **Private source-dependent capture/admission:** SBR strict replay использует точные request/response пары, но capture adaptation переставляет целые action rows, включая SDK rows; заранее заданная хронология устройства не подтверждена. ADS linked-index имеет только scoped admission verdict. FullID имеет bounded software-source PASS: synthetic capture/strict replay и два original-backend monitor replay, но это не полнота DDR/TSE или всех входных источников.
- **Private source-dependent Utility83 verdict:** scoped SMRT55 receipt reconciliation и bounded public `TYPlusEx2.InitializeDoIP` method с тремя аргументами приняты. Другие PlusDoIP exports, более широкие external consumers, полный UtilityEx, lifecycle parity и живой DoIP остаются открыты.
- Native GTK: normal и compact smoke после GUI-исправлений PASS на frozen snapshot A16. Это подтверждает только проверенные экранные состояния и действия.
- Leaf 11/143 GUI: приняты bounded authored selection → same-owner P4/P5 normal monitor → typed DRS/DM, late load/systems callback cancel, idle close result 9, retry result 0 и catalog restore. Leaf-11 G1 и manual G3/G4/G5 PASS; leaf-11 G2 и full leaf-143 queue/G2 остаются OPEN.
- SBR count-before-store: проверен порядок счётчика до записи и ленивого будущего CPU; уже выполненные два CPU пропускаются. Это программный контракт авторских входов.

Контрольный узкий прогон четырёх модулей Body, ADS, CommandAPI и UtilityEx (244 теста за 107 секунд) относится к более раннему снимку до корректировки durable-anchor пути. Текущие counts приведены в таблице выше. Физическое состояние оборудования по-прежнему `PHYSICAL_UNCONFIRMED`.

## Публичные проверки

Проект использует Python 3.11+ и `unittest`, не pytest:

```sh
python -m unittest discover -s tests -v
python -m scripts.session_cli replay examples/diagnostic-session.json --output /tmp/session.json
python -m scripts.demo --output /tmp/techstream-demo
python -m scripts.offline_verify workflows
ruff check scripts tests techstream.py
ruff format --check scripts tests techstream.py
shellcheck techstream scripts/desktop-smoke.sh
```

CI в `.github/workflows/ci.yml` запускает unittest на Python 3.11 и 3.13, офлайн replay, генерацию синтетических demo-ресурсов, авторские offline workflows, Ruff lint/format, ShellCheck и GTK smoke test на Ubuntu 24.04 с Xvfb и D-Bus. Перед утверждением результата на текущем checkpoint нужно сверить сам workflow и SHA опубликованного дерева.

Для локальной проверки отрисованного интерфейса установите системные зависимости из [раздела установки](getting-started.md#desktop-dependencies), затем выполните:

```sh
xvfb-run -a dbus-run-session -- python3 techstream.py --demo --smoke-test
```

Проверяется синтетический GTK путь, но не полнота семейств исходников, USB, ЭБУ или физическая совместимость. Как и в CI, может потребоваться системный `/usr/bin/python3` с пакетами PyGObject.

## Классы свидетельств

| Свидетельство | Что подтверждает | Чего не подтверждает |
| --- | --- | --- |
| Публичный авторский тест с синтетической фикстурой | Границы парсинга, переходы состояния, сериализацию, negative cases и injected-provider контракт, прямо названный тестом | Эквивалентность OEM, непроверенные ветви, тайминги адаптера или принятие команды ЭБУ |
| Необязательная локальная BYOD-проверка | Формат/парсинг локального файла при указанной версии и хеше | Воспроизводимость из публичного clone, права на распространение или другие версии |
| Текущая частная независимая source/consumer проверка | Ограниченное source-backed утверждение на совпадающих исходниках, зависимостях, тестах и review pins | Завершение целого модуля/семейства или результат после изменения снимка |
| GTK render/smoke | Отображение и действия, реально проверенные в зафиксированной графической среде | Скрытые сценарии, live-данные, полное покрытие исходника или работу устройства |
| Физическая проверка адаптера/ЭБУ/автомобиля | Только конкретный адаптер, ПО, протокол, автомобиль, условия и операция, записанные в свидетельстве | Другие адаптеры, варианты, автомобили и операции программирования |

Статический анализ исходника, дизассемблирование, привязка байтов, инвентаризация метаданных и реконструированные контракты — свидетельства **только анализа исходника**. Они полезны, но не являются исполнением OEM-кода. Host backend или обмен в памяти — **программная симуляция**. Снимок интерфейса — **свидетельство отрисовки**. Не смешивать эти метки в отчётах.

## Как читать результаты контрольной точки

- **Текущий результат** привязан к exact source/test/dependency pins последнего handoff. Если один из файлов изменился — повторить соответствующую узкую проверку.
- **Исторический pass** относится к прежнему снимку; это контекст, а не нынешний зелёный статус.
- **Проверка владельца** подтверждает только перечисленную область. Для независимого принятия нужен отдельный reviewer на том же замороженном candidate.
- **Skipped/unrun** означает неизвестный результат, а не pass. Это включает проверки, код которых написан, но не запускался до паузы.
- **Red/error** остаётся активной проблемой, пока исправление не проверено по исходному контракту. Сохранять красный вывод как свидетельство.
- **Source omission** или неучтённый export/module означает открытый контракт; это не безопасное исключение и не утверждение о физическом оборудовании.
- **Открытый gate** означает, что работа ещё нужна, даже если многие leaf-тесты зелёные. Полная closure G1–G6 остаётся открытой; отдельные subgate уже PASS, включая G2 offline workflow check. Исторические CI и публичные прогоны ниже относятся к указанным снимкам; актуальный SHA и CI вписать после финальной проверки рабочей ветки.

Актуальные красные и ожидающие проверки перечислены в [handoff разработки](development-handoff.md#известные-красные-и-открытые-места). Локальные `analysis/evidence/no-car-*/` содержат команды, снимки и ограничения; это частные необязательные свидетельства, не требование публичной сборки.

## Интерпретация и безопасность

Не ослаблять тесты или issuance guards только ради зелёного результата. При расхождении сначала сопоставить тест с точным исходным контрактом и реальным публичным потребителем. Сохранять положительные и отрицательные проверки отмены, частичного состояния, владения кэшем, очистки и некорректного ввода.

Физический статус остаётся **`PHYSICAL_UNCONFIRMED`**. Будущая проверка должна указать адаптер и firmware, версии host/library, автомобиль и ЭБУ, точную операцию, измеренные обмены/тайминги, очистку после ошибки и границы безопасности. Пока таких данных нет, описывать результат только как Linux-программную реализацию, offline-инструмент, отдельное source-backed поведение или симуляцию — в зависимости от того, что реально проверялось.

## Историческая контрольная точка 22 октября 2026

Исправления кода и callers зафиксированы в `649b53a` и `05b7249`. Независимое source/caller-ревью Sol приняло сохранение retry-state, canonical ED0C join, исключительное владение авторской fixture и каноническую private-only границу. Дополнительно проверены оба cleanup-исключения: живой поток при timeout сохраняет владельца; ошибка уже присоединённого потока освобождает его и продолжает распространяться.

| Проверка | Измеренный результат |
| --- | --- |
| Полный `unittest discover` с доступным локальным частным корпусом, Python 3.14.8 | **6 277 тестов, 0 failures, 0 errors, 0 skipped**, 415,216 с вместе с discovery |
| Новые регрессии и исправленные callers в source-only Bubblewrap без home/originals/сети | **17 тестов PASS, 0 skips**: 15 новых и два существующих caller-теста |
| Ruff / format / ShellCheck | PASS; 294 Python-файла отформатированы |
| Pyright по десяти затронутым Python-файлам | Те же 26 существовавших замечаний в `test_programming_2026_common.py`, новых нет; это не чистый type-check всего проекта |
| Session replay, demo generation, offline workflows | PASS |
| GTK normal и compact из публичного source export | Оба PASS в Ubuntu 24.04/Xvfb; контейнер без сети, host display и приватного корпуса |

Полный публичный suite выполняется на точном опубликованном SHA в CI: core Python 3.11/3.13 и `public-root` Python 3.12 под root без частного корпуса. Итоговый статус и логи — в [проверках PR #1](https://github.com/gon7187/techstream/pull/1/checks) и [Actions](https://github.com/gon7187/techstream/actions/workflows/ci.yml). Локальные 17 source-only проверок дополняют этот полный CI, не заменяют его.

До исправлений полный локальный прогон на `7c05712` давал два failure (retry/gateway), а первый прогон исправленного кода выявил два caller error из-за fixture, удерживаемой до конца всего теста вместо итерации `subTest`. Исправлены lifetime двух callers; проверки владельца, исходные assert и приватные oracle сохранены. Девять дополнительных локальных тестов относятся к непубликуемому acquisition helper; число тестов публичного checkout поэтому отличается от локальных 6 277.

GTK подтверждает бизнес-этап DCM45 через `NativeUtilityRuntime` и BSM27 через `NativeBSMRuntime`, создаваемый в `techstream.py` поверх библиотек авторской fixture. Выделенный DCM45/CGW-prelude, повтор в том же контексте, полная source/consumer-полнота и физическое поведение остаются отдельными открытыми гейтами. OEM-код и автомобиль не исполнялись; `PHYSICAL_UNCONFIRMED` сохраняется.

## Измеренный локальный снимок 21 октября 2026

После остановки feature-агентов root повторил проверки на замороженном дереве под Python 3.14.8. Это результаты контрольной точки, а не основание закрывать открытые source-гейты:

| Проверка | Результат |
| --- | --- |
| Полный `unittest discover` с доступным локальным корпусом | 6 232 теста за 181,117 с; 8 failures и 35 errors |
| Публичный source-only export в Bubblewrap без home/originals/сети, Python 3.14.8 | 6 223 теста за 69,043 с; 1 failure, 117 errors, 515 skipped |
| `ruff check scripts tests techstream.py` | 6 замечаний B023 в `tests/test_monitor_packet_a8.py` |
| `ruff format --check scripts tests techstream.py` | 289 файлов уже отформатированы |
| `shellcheck techstream` | PASS |
| Синтетический session replay | PASS |
| Генерация demo без GTK | PASS |
| `python -m scripts.offline_verify workflows` | `OFFLINE_WORKFLOWS_PASSED` |

Ошибки полного прогона относятся, в частности, к gateway-cache/worker joins, native-pointer replay и отдельным source-backed utility SDK-путям. Они не были скрыты или исправлены в рамках запрошенной паузы. Полные локальные логи остаются частными; публичный CI на конкретном коммите показывает независимый результат чистого checkout. Успешные выборочные проверки не отменяют этот красный общий результат.

Изолированный source-only прогон использовал только явно отобранные публичные файлы; исходный home и частный корпус не монтировались, сеть была отключена. Он обнаружил незаявленные частные зависимости части тестов и дополнительные ошибки. Это экспорт файлов для проверки, а не доказательство успешного fresh Git clone или зелёного GitHub CI. Исправление переносимости остаётся отдельной работой; массовое добавление skip ради зелёного результата не является решением.

### После lifecycle-исправлений 21 октября 2026

Повторный публичный прогон на ветке `offline-completion-20261020` после слияния PR #3, без приватного корпуса:

| Проверка | Результат |
| --- | --- |
| `python -m unittest discover -s tests` | 6 228 тестов за 57,180 с; **0 failures**, 117 errors, 529 skipped |
| `ruff check scripts tests techstream.py` | PASS |
| `ruff format --check scripts tests techstream.py` | 290 файлов уже отформатированы |
| `shellcheck techstream scripts/desktop-smoke.sh` | PASS |
| `python -m scripts.offline_verify workflows` | `OFFLINE_WORKFLOWS_PASSED` |
| GTK smoke через `sh scripts/desktop-smoke.sh` | PASS |

117 errors — это `FileNotFoundError` для отсутствующих приватных `analysis/evidence/no-car-*` и `artifacts/extracted/*`; публичные lifecycle-регрессии и остальные авторские тесты зелёные. Это не полный native pass: оригинальный oracle листов 153/108 и независимый source-review не запускались.

### После execute/context листа 31 и пула 151

Повторный публичный прогон на ветке `offline-completion-20261020`, без приватного корпуса:

| Проверка | Результат |
| --- | --- |
| `python -m unittest discover -s tests` | 6 237 тестов за 60,575 с; **0 failures**, 117 errors, 529 skipped |
| `ruff check scripts tests techstream.py` | PASS |
| `ruff format --check scripts tests techstream.py` | 290 файлов уже отформатированы |
| `shellcheck techstream scripts/desktop-smoke.sh` | PASS |
| `python -m scripts.offline_verify workflows` | `OFFLINE_WORKFLOWS_PASSED` |
| GTK smoke через `sh scripts/desktop-smoke.sh` | PASS |
| GitHub Actions `39564815857` на `9b7deeb` | `static` и `desktop` PASS; `core (3.11)`/`core (3.13)` — 6 237 тестов, 0 failures, 117 errors, 529 skipped |

117 errors — те же отсутствующие приватные `analysis/evidence/no-car-*` и `artifacts/extracted/*`. Авторские `ControllerExecuteTests` покрывают one-phase dispatch, classic/modern prepare, write retry, recovery/probe, pool replacement и фактическую pair chronology. Это не source-issued native oracle: оригинальный execute/context, native multi-row cardinality и независимый consumer review не запускались.

### После исправления публичных harness-дефектов

Повторный публичный прогон на ветке `offline-completion-20261020`, без приватного корпуса:

| Проверка | Результат |
| --- | --- |
| `python -m unittest discover -s tests` | 6 237 тестов за 54,428 с; **0 failures**, 113 errors, 547 skipped |
| `ruff check scripts tests techstream.py` | PASS |
| `ruff format --check scripts tests techstream.py` | 290 файлов уже отформатированы |
| `shellcheck techstream scripts/desktop-smoke.sh` | PASS |
| `python -m scripts.offline_verify workflows` | `OFFLINE_WORKFLOWS_PASSED` |
| GTK smoke через `sh scripts/desktop-smoke.sh` | PASS |

113 errors — только `FileNotFoundError` для отсутствующих приватных `analysis/evidence/no-car-*`, `artifacts/extracted/*` и `runtime/no-car-*`; failures отсутствуют. Четыре ранее публичных harness-дефекта исправлены без маскировки: проверки `Body2026Tests` перенесены внутрь `subTest`, Suzuki-тест явно подменяет новый source-issued central gateway key, а UtilityEx retained-тест отвечает на реальный keepalive `3e00` каждого потока вместо общего итератора ответов. Фикстура `test_cuw_gateway_startup` теперь получает producer через `engine.bind_gateway_startup()`, а не через частный issuer; приватный повтор 55 тестов листа 134 остаётся отдельной проверкой.

### После явных private-evidence skip

Публичный прогон на ветке `offline-completion-20261020`, без приватного корпуса:

| Проверка | Результат |
| --- | --- |
| `python -m unittest discover -s tests` | 6 244 теста за 73,835 с; **0 failures, 0 errors**, 626 skipped |
| `ruff check scripts tests techstream.py` | PASS |
| `ruff format --check scripts tests techstream.py` | 292 файла уже отформатированы |
| `shellcheck techstream scripts/desktop-smoke.sh` | PASS |
| `python -m scripts.offline_verify workflows` | `OFFLINE_WORKFLOWS_PASSED` |
| GTK smoke через `sh scripts/desktop-smoke.sh` | PASS |
| GitHub Actions `39571959581` на `6662607` | все четыре job PASS; `core (3.11)` 6 244 теста за 79,647 с, `core (3.13)` 6 244 за 89,292 с; **0 failures, 0 errors**, 626 skipped |

Добавлен `tests/private_evidence.py`: `require_private` принимает только пути под
`analysis/`, `artifacts/`, `.unlazy/` или `runtime/no-car-*`; отсутствующий путь
даёт `SkipTest` с точной причиной, публичный путь — `AssertionError`. Читатели
`read_private_bytes/text/json` используют тот же барьер. Это не масс-скип по
исключению: каждый затронутый тест явно требует конкретный приватный артефакт, а
новый `tests/test_private_evidence.py` проверяет и skip, и отказ для публичного
пути. `EngineThreadRetryBridgeTests` дополнительно прогоняет реальный `_run_outer`
моста 145→51: успешный `callback3` на outer-потоке, возврат ошибки в child и отказ
не-child publisher. `_paced_native_sleep` закрывает DCM free-spin: фоновый worker
добирает реальные 120 мс, если host Sleep вернулся раньше; регрессия проверяет
ограниченное число шагов на virtual-clock host. GTK-сценарий DCM всё ещё не
подтверждён. 626 skipped включают прежние авторские пропуски; ни один публичный failure
или error не скрыт. Приватный source-issued oracle, native multi-row cardinality,
route-gates 58/68/69 и мост 145→51 по-прежнему не запускались.

### После normal/compact GTK и нативных utility-сценариев

Публичный прогон на ветке `offline-completion-20261020`, без приватного корпуса:

| Проверка | Результат |
| --- | --- |
| `python -m unittest discover -s tests` | 6 253 теста; **0 failures, 0 errors**, 626 skipped |
| `ruff check scripts tests techstream.py` | PASS |
| `ruff format --check scripts tests techstream.py` | PASS, 294 файла отформатированы |
| `shellcheck techstream scripts/desktop-smoke.sh` | PASS |
| `sh scripts/desktop-smoke.sh normal` | PASS |
| `sh scripts/desktop-smoke.sh compact` | PASS |
| `python -m scripts.offline_verify workflows` | `OFFLINE_WORKFLOWS_PASSED` |
| GitHub Actions `39578033940` на `ec9db8d` | `static`, `desktop`, `core (3.11)`, `core (3.13)` и `public checkout and root gate` — PASS; оба core-прогона — 6 252 теста, 0 failures, 0 errors, 626 skipped |

Что изменилось в публичной части:

- `scripts/desktop-smoke.sh` принимает вариант `normal|compact`. `normal`
  поднимает Xvfb 1600×1200 и рендерит широкий layout; `compact` — 1024×768 и
  запускает тот же поток в свёрнутом layout, где smoke дополнительно проверяет
  сработавший breakpoint, свёрнутый split и кнопку меню. Неизвестный вариант
  отвергается с кодом 2 до запуска рабочего стола.
- `techstream.py --smoke-compact` (только вместе с `--smoke-test`) задаёт узкое
  окно 900×700; без него приложение сохраняет прежний размер 1340×820.
- Новый публичный модуль `scripts/utility_authored.py` собирает настоящие
  `NativeUtilityRuntime` по авторским байтам и внедрённому провайдеру. Для BSM27 `techstream.py` создаёт `NativeBSMRuntime` поверх библиотек этой фикстуры. Он
  намеренно обходит проверку source-issued пары caller/engine и никогда не
  обслуживает production-процедуру: `scripts.utility.open_native_utility`
  сохраняет эту проверку, а `tests/test_utility_authored.py` фиксирует, что
  авторская пара не проходит production-путь.
- Smoke прогоняет DCM45 через настоящий GTK-диалог: успешный бизнес-этап с
  исходным результатом 0 и выводом получателя, native-предупреждение 2005 с
  экраном 0x948c/0x9492, отмену с присоединением рабочего потока и закрытием по
  `acknowledge`; затем BSM27 с исходным отказом зонда 99 и общим экраном ошибки.
  `scripts/text_resources.create_utility_group_text_examples` публикует
  авторские подписи выбранной native-группы и общей группы 20000.

Границы: этот GTK-сценарий подтверждает только публичный контракт — реальный
диалог, реальный контроллер, реальный рабочий поток и авторский провайдер.
Выделенный `NativeDCM45Runtime`/CGW-prelude DCM45, повтор в том же контексте, raw-SDK хронология, полный BSM-цикл записи и физическое
поведение ЭБУ по-прежнему не подтверждены. CI получил job `public-root`:
свежий checkout в контейнере под root без приватного корпуса, запрет
публикации `analysis/`, `artifacts/`, `.unlazy/` и `runtime/no-car-*`, полный
прогон тестов и offline workflows.
