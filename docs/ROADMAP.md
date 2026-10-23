# План развития и граница готовности

Контрольная точка кода: **23 октября 2026**, `main` `c2258c929d7755c817a5bb661dd61bf5e6c0961b`, PR #9 merged. Локальный private unittest на tested code tree feature `8aa0c3b8fc83c4f5b68f00277df8d0ea3165d77a` (тот же код tree, позднее merged в main) дал 6 617 тестов, 0 failures/errors/skips за 215,121 с. Отдельно: 10 PR CI checks PASS и main public CI зелёный. Это checkpoint кода, а не статус после последующих изменений документации. Подробный порядок работ — в [handoff](development-handoff.md); исторические и текущие результаты разделены в [verification](verification.md).

Полный no-car port **открыт**; физическое поведение остаётся **`PHYSICAL_UNCONFIRMED`**. Native inventory (2 454 PE, 3 407 aliases, 146 011 exports; 148 433 open targets / 165 open contracts) учитывает также platform/runtime и не является оценкой недостающих функций. Coarse workflow matrix отдельно содержит 49 строк: 39 open, 6 implemented, 4 physical-unconfirmed. Статусы и привязки coarse rows не меняются от одного факта реализации.

## Принятые ограниченные контракты

- P6: уже приняты selected single-file getter → outer import → Phase6 G selection и stale/foreign/malformed receipt rejection через настоящий issued job с authored producer traffic. Это не исполнение vendor getter. Следующий открытый шаг — mixed-CPU getter → matching → prepare/write и consumer-side результат.
- D2A1: полный cleanup сбрасывает latch на достигнутой поздней стадии после resource release; retry result `1` сохраняет его, ранняя ошибка очистки тоже сохраняет.
- Persisted recovery: same-job callback re-entry достигает ordinary query. Это не доказательство исполнения family programming export.
- DRS dispatch: подтверждены шесть context slots и передача monitor pointer из `this + 0x224`; identity internal profile остаётся неизвестной.
- P3: virtual `+0x58` receiver маршрутизирует в J2534 `monitor_system_send`; внешний `DataMonitorPhase3!Run` caller неизвестен.
- VBF: P/Invoke ABI `ProcessBeforeReprogramming` source-bound; точный GUI event/retry timing остаётся неизвестным.
- Database: независимая приёмка шести выбранных contracts/32 exports версии 18. Остальные table/module operations не приняты.
- TechVim: source-bound HRESULT reducer; SDK provisioning, controller scheduling/runtime caller открыты.
- DCM45 обычный source-bound replay path создаёт `NativeDCM45Runtime` через `open_native_utility`; это не подтверждает live CGW parity.

Полные утверждения и provenance см. в [native reverse checkpoint](reverse-checkpoint-2026-10-23.md) и [selected database review](native-selected-review.md).

## Следующая программная работа

1. Расширить принятый P6 single-file actual-job getter → outer import → G path до mixed-CPU getter-to-matching-to-prepare/write на той же выданной job/context и доказать consumer-side результат.
2. Свести оставшиеся programming/recovery пути: executable legacy/2026 controllers, complete imported recovery composition, worker reissue/source-issued context, gateway joins и multi-row pool cardinality.
3. Принять recorder producer и reader/controller join, включая выбранные VIN/series/protocol producers. Для monitor/active/system — доказать конкретные constructors, support/cache, LSB, lower send/receive и Dual/recorder consumers; нормальный P3/P4/P5/PSA/DK/DLC12 маршрут целиком не закрыт.
4. Разобрать оставшиеся offline families по native caller/consumer: MultiMon/mixed-provider/queue; UtilityEx bindings и lifecycle; ADS/DDR/saved-log acquisition/timeline; TSE field semantics и AllDTC XML parity; enhanced readiness; calibration formats/callers и database/module audit. Scoped PASS не закрывает family-level row.
5. Перед программным no-car gate заново выполнить проверки на свежем clone актуального main: unittest, offline workflows, GTK normal/compact и CI. Затем отдельно планировать физическую read-only валидацию конкретного адаптера/ЭБУ/автомобиля.

Критерии приёмки и требуемые evidence описаны в [handoff](development-handoff.md). Не выводить сроки или процент готовности из native inventory.

## После программного гейта

Физическая проверка требует зафиксировать адаптер, VID:PID/descriptors, firmware, версии host/library, автомобиль и ECU, точные read-only операции, сырые обмены и тайминги, ошибки и cleanup. Название на корпусе, статический разбор и synthetic replay совместимость не доказывают. Процедуры записи/обновления не являются частью этой проверки без отдельного подтверждённого контракта.
