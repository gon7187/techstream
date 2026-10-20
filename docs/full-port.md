# Полный порт: реализованное и остаток

Цель — собственное Linux-приложение с функциональностью Techstream без Wine/Windows. **Полное соответствие оригиналу ещё не достигнуто.** Проверки без оборудования подтверждают кодеки, алгоритмы и сценарии на синтетическом обмене; физическая связь остаётся `PHYSICAL_UNCONFIRMED`.

| Функция | Реализовано и проверено без оборудования | Остаётся |
| --- | --- | --- |
| Выбор автомобиля и систем | DDB связи файлов/названий, VehicleName и записи поддержки | Профили модели/года/опций, выбор исключений, обнаружение реальных ЭБУ |
| Ошибки | DDB справочники, standard OBD stored/pending/permanent, native KWP DTC codec | Полные Toyota current/history/info/status, стирание и физическая проверка |
| Стоп-кадры | DDB определения/пересчёт, native P3/P5 codecs, standard OBD frame-zero replay | Выбор Toyota descriptors, runtime overrides и реальные ответы |
| Параметры и снимки | CT identities, числовой evaluator, 15 standard OBD PID, bounded poll/record/replay, переключаемые графики | Toyota enhanced data lists, частота опроса на оборудовании, оригинальные snapshot-форматы, dual ECU |
| Health Check | Последовательный отчёт по заданным ЭБУ, частичные ошибки, JSON | Автообнаружение систем, поддержка всей машины, Toyota-specific сведения |
| Active Tests | Структуры ActTest, ключи и исключения | Выбор доступных тестов, аргументы, start/status/stop и отмена |
| Utility / Customize | Raw CSDF object, 15 операторов, стек/переменные/массивы/переходы; SRP XML и SRPLST decode/inspection | CSDF library calls, исполнение XML actions/COMM, параметры записи/восстановления |
| Monitor / CARB OBDII | Readiness, VIN, CALID/CVN, числовой subset OBD | Mode 06, составные O2/EVAP и оставшиеся сервисы |
| MongoosePro JLR | USB identity/version; raw CAN lifecycle/filters/RX/TX; связанный host ISO-TP exchange, ошибки и отмена | Реальное устройство, K-line и firmware ISO paths, физические тайминги и Toyota-покрытие |
| Программирование ЭБУ | Исходные точки входа исследованы | Calibration containers, engine, совместимость, programming/recovery |
| Бортовой Drive Recorder | Исходные интерфейсы инвентаризированы | Команды VIM, onboard recording и исходные форматы записей |

## Воспроизводимые проверки

- `python -m unittest discover -s tests -v` не требует ресурсов производителя.
- `./techstream --demo --smoke-test` проверяет настоящее GTK-окно: поиск, избранное, CSV, базы, USB-инвентарь без открытия устройств, обзор двух ЭБУ, JSON, график и CALID/CVN.
- `python -m scripts.session_cli replay examples/diagnostic-session.json` разбирает строго упорядоченные байтовые ответы.
- Транспортный integration test соединяет настоящий `Session → ISOTPExchange → CANSession → JLRClient → SLP` с синтетическим USB-транспортом. Это доказательство связности программных слоёв, а не наблюдение физического обмена.

## Статическое исследование

Исходный контракт исследован по 424 PE, RT_MENU/RT_DIALOG и экспортам/вызовам. Основная GUI использует CommandAPI; найдено 332 семейства Snd/Rcv. Число имён не равно числу перенесённых команд.

Корпусные проверки: 3946 CT / 290394 записи и 1422 DDB / 25655 секций. Дополнительные схемы читают 13719 ActTest и 384242 ExceptionProcess записей; это определения, а не запущенные процедуры. Проверены 18 SRP XML и один SRPLST со списком из 19 строк. Оригинальные ресурсы и расшифрованные тексты не публикуются.

Подробности: [DDB](ddb-format.md), [числовой пересчёт](signal-conversion.md), [Toyota codecs](toyota-protocol.md), [CSDF/SRP](script-vm.md), [JLR channels](jlr-channels.md), [offline diagnostics](offline-diagnostics.md), [проверка оборудования](hardware-validation.md).

Полные REA bundles и исторические acceptance ledgers остаются в локальном исследовательском архиве. В технических документах приведены SHA и адреса; владельцы соответствующих ресурсов могут воспроизвести статическую проверку. Отсутствие адаптера не мешает продолжать оставшийся реверс и программную реализацию.
