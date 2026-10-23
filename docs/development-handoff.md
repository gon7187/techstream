# Передача разработки — 2026-10-23

## Текущее состояние

Текущий опубликованный кодовый checkpoint — `main` **`c2258c929d7755c817a5bb661dd61bf5e6c0961b`**, PR #9 merged. Локальный private `unittest` прогон на tested code tree feature `8aa0c3b8fc83c4f5b68f00277df8d0ea3165d77a` (**тот же код tree, позднее merged в `c2258c9`**) прошёл: **6 617 тестов, 0 ошибок, 0 пропусков, 215,121 с**. Отдельно PR CI: 10/10 checks PASS; main public CI зелёный. Это checkpoint кода, не проверка последующих правок документации. Подробности и точные границы — в [проверках](verification.md#текущая-контрольная-точка-23-октября-2026).

Полный программный порт не завершён. Native inventory содержит **2 454 PE, 3 407 aliases и 146 011 exports**; **148 433 open targets / 165 open contracts** включают платформенные и runtime-зависимости и не являются числом недостающих функций или оценкой объёма. Отдельный coarse workflow registry содержит 49 операций: **39 `open`, 6 `implemented`, 4 `PHYSICAL_UNCONFIRMED`**. Это разные модели учёта. Не выводить закрытие coarse-строки из наличия реализации или теста; меняйте статус только при независимом доказательстве полного контракта этой строки.

Свежие ограниченные приёмки: шесть database contracts/32 точных KgpDataCtrl exports; TechVim status reducer; D2A1 late-cleanup reset; recovery same-job callback re-entry; P6 per-node CID companion records и actual-job импорт. Для P6 это подтверждает хостовую передачу authored traffic через реальный job/import, но **не** vendor getter или полный mixed-CPU prepare/write. Полный TechVim SDK/controller и P6 mixed-CPU prepare/write остаются открыты. Физических проверок нет: `PHYSICAL_UNCONFIRMED`.

Текущие статические уточнения и их границы собраны в [native reverse checkpoint](reverse-checkpoint-2026-10-23.md) и [selected database review](native-selected-review.md). Исторические прогоны и старые red-результаты не подменяют текущий checkpoint.

## Приоритетный порядок продолжения

1. **Расширить уже принятый P6 путь**: выбранный single-file getter → outer import → Phase6 G selection и stale/foreign/malformed receipt rejections уже проверены на issued job с authored producer traffic. Следующий шаг — смешанный multi-CPU getter → CID matching → prepare/write на том же выданном job/context и проверка consumer-side результата. Не пересматривать заново уже принятый single-file import boundary; vendor getter и физическое исполнение при этом всё ещё не подтверждены.
2. **Свести no-car программные цепочки к публичным consumers**: executable legacy/2026 programming controller и recovery composition; gateway/reissue worker context и multi-row pool cardinality; recorder VIN/series/protocol producer с reader/controller join; monitor constructors/support/cache/LSB/direct lower send-receive и Dual/recorder integration. Для каждого пути зафиксировать исходный caller, аргументы, владельца, последовательность, ошибку/cleanup и независимый source/consumer review.
3. **Закрыть оставшиеся широкие feature families по точным контрактам**, не переносить scoped PASS на всю строку: active/system normal producers; MultiMon/mixed-provider/queue; UtilityEx и bindings; ADS/DDR/saved-log capture и timeline; TSE binary field semantics и AllDTC XML parity; enhanced readiness; database/module audit и оставшиеся calibration formats/callers. Для каждого недостающего source target нужен identity-pinned caller/consumer evidence либо явная причина, почему он вне no-car scope.
4. **Сверить финальный публичный интеграционный набор** на свежем clone и актуальном main: unit suite, offline workflows, normal/compact GTK и CI. Сверка публичного дерева не закрывает частные source gates.
5. **После программного гейта — отдельная физическая программа**: установить VID:PID/descriptors и firmware адаптера, затем безопасные read-only обмены на конкретном автомобиле/ЭБУ с замерами timing, ошибок и cleanup. Запись/обновление не запускать без отдельного доказанного контракта и разрешённой процедуры.

Не назначать проценты или календарные оценки: открытые native targets не переводятся напрямую в объём разработки.

## Проверка из чистого checkout

```sh
git clone https://github.com/gon7187/techstream.git
cd techstream
git checkout main
python3 -m unittest discover -s tests
python3 -m scripts.offline_verify workflows
sh scripts/desktop-smoke.sh normal
sh scripts/desktop-smoke.sh compact
```

Эти команды проверяют публичный checkout. OEM binaries и private evidence не требуются для public CI; явные private-evidence skips — не пропуск текущего измеренного checkpoint (там 0 skips) и не доказательство поведения OEM.

## Границы и критерий закрытия

Различайте реализацию, owner check, независимую source/consumer приёмку, статический анализ OEM и физическое наблюдение. Наличие модуля или зелёного scoped теста подтверждает только названный путь на проверенном snapshot. Полный no-car scope остаётся открытым, а физический статус — `PHYSICAL_UNCONFIRMED`.

Строку coarse registry закрывать только когда точный native контракт, caller, consumer, негативные случаи и cleanup независимо приняты на одном source-pinned candidate; обновлять evidence/bindings вместе со статусом. Никаких выводов о полноте по количеству tests, exports, graph nodes или агентских задач.
