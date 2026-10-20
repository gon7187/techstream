# MongoosePro JLR: нативный USB

Пользователь сообщил маркировку **Mongoose JLR Pro / SDD V168**, предположительно Atmel. Маркировка не устанавливает фактический чип, VID:PID, прошивку или происхождение устройства. Физическая проверка пока `PHYSICAL_UNCONFIRMED`.

Официальный [архив драйверов Opus IVS](https://opusivs.com/support/product-downloads/) содержит `monpjaguar.inf` с USB **18e1:0104**. Исследованы `monpj432.dll` SHA-256 `2710726fdd174f32b5e703e310cfce047a663451edbb3e35ca0c8eeff6929413` и x86 `dtmonpro.sys` SHA-256 `80c1bba1bc162644c5721df754aa27d049198562e707abb13771f7434590b21d`. Сторонние PE/SYS не исполнялись. Драйвер MFC `18e1:0100` — отдельное исследование.

## Что реализовано

`scripts/jlr.py` использует установленную libusb через ctypes. Интерфейсы 0/1, alt-setting 0; bulk IN/OUT определяются по реальным sysfs-дескрипторам. Неоднозначная конфигурация отклоняется. При открытии libusb повторно проверяет VID:PID; существующий kernel driver не отсоединяется. Нет автоматического reset, загрузки firmware или изменения прав устройств.

Сеанс USB: vendor OUT `bmRequestType=0x40`, `bRequest=0xdb`, `wValue=1`, `wIndex=0`, data length 0; при закрытии `wValue=0`. Интерфейсы освобождаются даже при сбое. Неуспешное закрытие возвращает ошибку. После ошибки открытия выполняется best-effort cleanup, сохраняется первичная ошибка.

Кнопка «Проверить адаптер» выполняет только USB identity/version запросы:

1. Echo `0x100`, без body, timeout 250 ms nonfatal: workaround оригинала для первого обмена USB3.
2. Board info `0x109`: 8 записей по 20 байт с позиции ответа +20.
3. GetValue `0x0c`, параметры `0x2b` и `0x2a`: firmware/bootloader raw u32 с позиции +24.
4. GetString `0x13`, параметр 0: bounded NUL строка серийного номера с +24; сохраняются исходные hex-байты, отображается ASCII с escape для остальных байтов.

Эта последовательность в оригинале выполняется **до** protocol Open. Команды в ЭБУ не отправляются. Закрытие окна отменяет ожидающий запрос и дожидается USB cleanup. Обычный осмотр списка USB остаётся пассивным.

## Протокол и точные опоры

SLP: `<HH>(payload_len, payload_len XOR 0x51e6)` + payload, длина 1..0x1800. Потоковый декодер собирает фрагменты и при плохом заголовке сдвигается на байт. Заголовок payload: шесть LE u16 — destination, source, opcode, sequence, flags, alignment. Sequence 1..255 с переходом к 1; alignment обнуляется, оригинал оставлял его неинициализированным.

Обычный ответ минимум 20 байт, status u32+12; echo допускает header-only 12 байт без status. Порт сверяет destination/source/opcode/sequence; сохраняет несвязанные события в ограниченной очереди, использует monotonic timeout и отклоняет короткую запись USB. Firmware raw значения показываются без догадки о номере версии.

DLL VA: framing `0x1006e180`, receive `0x1006b1c0`, waiter `0x1006d9b0`, enumeration `0x1004a3f0`, echo `0x1003f030`, board `0x1003f160`, GetValue `0x1003ff9e..0x10040050`, protocol Open `0x1003ea00`, Close **opcode 5** `0x1003fb90`. DLL file offset = VA − `0x10000000` − `0xc00`. SYS control builder VA `0x15762`, interface selection `0x15a8e`, raw bulk callbacks `0x11ad6/0x11e18`.

Полные REA записи и исходные хеши: `analysis/evidence/fullport-jlr/`, `jlr-final-evidence.json` (145 записей), `evidence-index.json` (167 запросов). Независимое ревью сопоставило USB probe с исходными инструкциями; minimum reply length, header-only echo и cleanup после неоднозначного timeout проверяются отдельно.

## Что требуется для диагностики

USB-проверка не подтверждает совместимость с автомобилем. Board capabilities определяют адрес канала, например CAN slot1 → `0x0501`, ISO15765 → `0x0601`; это не номера 5/6. CAN/K-line RX разобраны, а ISO15765 требует host segmentation, flow control, filters, allocation и lifecycle. Эти пути ещё не подключены к GUI как готовая диагностика.

В `scripts/isotp.py` реализованы I/O-free state machines для host ISO-TP поверх raw CAN: Classical CAN, PDU 1..4095, один точный peer, 11-/29-bit ID с обязательной проверкой формата входящего кадра, normal/extended addressing, SF/FF/CF/FC, BS, STmin, WAIT limit и monotonic timeouts. Код не отправляет кадры сам. При включении в транспорт caller должен маршрутизировать flow-control отдельно, вызывать `tick()` без входящих данных и отменять передачу при сбое подачи кадра. Проверены 210 roundtrip-вариантов и malformed/таймерные сценарии, включая допустимую длинную STmin при коротком no-progress timeout.

Это собственная host policy, сверенная с [документацией ISO-TP ядра Linux](https://docs.kernel.org/networking/iso15765-2.html), а не перенос таймеров firmware JLR. Штатный ISO-канал JLR уже делегирует segmentation/FC прошивке; host-generated FC нельзя подавать в него повторно. Непрерывный USB RX/event pump и raw CAN/host ISO exchange теперь реализованы в [jlr-channels.md](jlr-channels.md); Write8 ack `0/0x101` не доказывает TxDone или ответ ЭБУ. Точные wire/lifecycle/TX события и ограничения сохранены в `analysis/evidence/fullport-isotp/FINDINGS.md`; непроверенная физическая петля отправки в приложение не включена.

[Официальное руководство JLR](https://www.opusivs.com/wp-content/uploads/2023/12/2019_MGP_User_Guide_JLR.pdf) описывает распиновку оригинального устройства; JLR и Toyota2 различаются. Клон может иметь другие возможности. Полное покрытие Toyota, active tests, программирование и реальные показания остаются открытыми до реализации соответствующих движков и физических проверок.

Проверки: `python -m unittest discover -s tests -p test_jlr.py` — фрагментация/склейка/resync, identity correlation, порядок sequence, header-only echo, несвязанные события и реальные descriptor-derived адреса на синтетическом sysfs. Установленная libusb отдельно проверена read-only перечислением и закрытием пути отсутствующего устройства; USB roundtrip с настоящим JLR не выполнен.
