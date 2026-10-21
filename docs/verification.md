# Проверки и свидетельства

В проекте несколько уровней проверки. Зелёный синтетический тест подтверждает только авторский путь и данные, которые он запускал. Он не доказывает такое же поведение OEM-программы, адаптера, ЭБУ или автомобиля.

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
- **Открытый gate** означает, что работа ещё нужна, даже если многие leaf-тесты зелёные. В этой точке G1–G6 открыты, а полный набор тестов не подтверждён как зелёный.

Актуальные красные и ожидающие проверки перечислены в [handoff разработки](development-handoff.md#известные-красные-и-открытые-места). Локальные `analysis/evidence/no-car-*/` содержат команды, снимки и ограничения; это частные необязательные свидетельства, не требование публичной сборки.

## Интерпретация и безопасность

Не ослаблять тесты или issuance guards только ради зелёного результата. При расхождении сначала сопоставить тест с точным исходным контрактом и реальным публичным потребителем. Сохранять положительные и отрицательные проверки отмены, частичного состояния, владения кэшем, очистки и некорректного ввода.

Физический статус остаётся **`PHYSICAL_UNCONFIRMED`**. Будущая проверка должна указать адаптер и firmware, версии host/library, автомобиль и ЭБУ, точную операцию, измеренные обмены/тайминги, очистку после ошибки и границы безопасности. Пока таких данных нет, описывать результат только как Linux-программную реализацию, offline-инструмент, отдельное source-backed поведение или симуляцию — в зависимости от того, что реально проверялось.

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
| `python -m unittest discover -s tests` | 6 252 теста; **0 failures, 0 errors**, 626 skipped |
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
  контроллеры DCM45/BSM27 по авторским байтам и внедрённому провайдеру. Он
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
CGW-prelude DCM45, raw-SDK хронология, полный BSM-цикл записи и физическое
поведение ЭБУ по-прежнему не подтверждены. CI получил job `public-root`:
свежий checkout в контейнере под root без приватного корпуса, запрет
публикации `analysis/`, `artifacts/`, `.unlazy/` и `runtime/no-car-*`, полный
прогон тестов и offline workflows.
