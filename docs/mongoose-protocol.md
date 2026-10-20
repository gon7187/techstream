# MongoosePro MFC: восстановленный framing

Реализация: `scripts/mongoose_protocol.py`. Это нативный Python-код без USB/ECU I/O. Он кодирует и проверяет пакеты и инспектирует ответы версии, но пока не заменяет J2534-драйвер.

Источник — официальный `MonProMFC_X86-1` → `monpm432.dll`, SHA-256 `56991bad7a4265adfd7f66c884a1684500739551c6421ad96f4b3a730f71a0b5`. REA/Ghidra 12.1.4, локальный bundle `analysis/evidence/mongoose-framing.json`. Принадлежность этой версии адаптеру пользователя не подтверждена.

## Конверт SLP

| Смещение | Поле |
| --- | --- |
| 0 | `uint16_le`: длина payload |
| 2 | `uint16_le`: длина XOR `0x51e6` |
| 4 | payload указанной длины |

`FUN_10065fd0` записывает длину, XOR и payload перед `WriteFile` через `FUN_10062550`; альтернативная ветка вызывает BT transport. `FUN_10062f30` инициализирует константу `0x51e6` и предел приёма `0x1800`. `FUN_10065b60` показывает смещение вложенного объекта, необходимое для сопоставления полей конструктора и отправителя. `FUN_100632f0` проверяет ненулевую длину, предел и XOR; исходный драйвер ищет новую границу побайтово. Наш декодер требует уже выровненный полный поток и отклоняет повреждение/усечение без молчаливого пропуска.

Evidence: constructor assembly `ev_ca8a0e8a46cda7a1f878124127c838986f602102b43a996e008b709040922807`; outer constructor `ev_7143f4b62da10830fdabe0dc3453174c0ebd5bcb25cc2b8d27298babfc9ea4cc`; envelope assembly `ev_8ea2a9d0ca041c64ffc7a580abb06339daeba47d1c575c67928bd6699411b955`; RX validation `ev_2e1b907f510413214523b1cbdcea60a93891e143887c3d1d0ea07720a846a6b6`.

## Запросы версии

`PassThruReadVersion` вызывает get-value с аргументами `(1, 0x2b)`, `(1, 0x2a)` и get-string `(1, 0)`. Не устанавливаем по названиям смысл отдельных version fields.

| Смещение payload | Наблюдение |
| --- | --- |
| 0 | `uint16_le`: первый аргумент, здесь `1` |
| 2 | `uint16_le`: `0` |
| 4 | `uint16_le`: `0x0c` для get-value, `0x13` для get-string |
| 6 | `uint16_le`: последовательность из byte counter; ноль перед запросом заменяется на `1` |
| 8 | `uint16_le`: `0` |
| 10 | Два alignment bytes; наблюдаемая функция их не инициализирует |
| 12 | `uint32_le`: второй аргумент |

Сериализуется 16 байт. Наши alignment bytes равны нулю, а три демонстрационных номера последовательности — `1, 2, 3`. Допустимость такого заполнения на железе пока неизвестна. Раскладку надо проверять по assembly: pseudocode скрывает padding и неполно восстанавливает calling convention.

Evidence get-value assembly `ev_d7575f1fc63bdbd9fda6fbe1cd2b2e8fa12a4372d135f5a72783cfa4d892dd0a`; get-string `ev_299964174e91ce540fe30eb40fbb05447f5917bbcdde40f3710999c6fd7ea145`; нулевая константа `ev_e2e09df5e7f28ad68fb964964737872ec689962687fc03a161a092c9e0db3a93`. Вызывающая функция сохранена в `analysis/evidence/final-investigation.json`, `ev_15ff8f6352069491962085008064c8cc45bd4b18635749e68ec5c129996310d5`.

```sh
python scripts/mongoose_protocol.py version-queries
python scripts/mongoose_protocol.py decode 1000f651010000000c000100000000002b000000
```

## Поля ответов версии: продолжение 2026-10-20

Из assembly того же `monpm432.dll` восстановлен путь RX → router → FIFO → waiter → get-value/get-string. Смещения ниже относятся к payload без четырёхбайтового SLP-конверта. RX удаляет конверт, FIFO возвращает неизменённый payload.

| Смещение | Статически установленное чтение |
| --- | --- |
| 0 | `uint16_le`, waiter сравнивает с request `+2` |
| 4 | opcode ответа; этот waiter его не сравнивает |
| 6 | `uint16_le sequence`, равна request `+6` |
| 12 | `uint32_le status`: 0 — успех; get-value трактует 1 как unsupported parameter |
| 24 | `uint32_le value` для get-value; NUL-terminated bytes для get-string |

`FUN_100658a0` проверяет минимум 20 байт. Для безопасного чтения успешного numeric response наш инспектор требует минимум 28 байт; строка обязана иметь NUL внутри payload. Nonzero status возвращается без чтения значения. `inspect_version_response()` принимает ровно один полный запрос версии и один полный ответ, проверяет framing, известную форму запроса и корреляцию. Opcode возвращается сырым: его соответствие конкретному запросу не подтверждено. Кодировка строки неизвестна, поэтому возвращается `value_hex`.

Новая CLI-команда `python scripts/mongoose_protocol.py version-response REQUEST_HEX RESPONSE_HEX` инспектирует сохранённую пару; ничего не отправляет. Fixture-ответы в тестах синтетические, выведенные из assembly.

Evidence get-string `0x100381c0`: `ev_92fd0584a301b6702b2f986b7c4b4926fec00b497402af1c97fa8b8a49ca622e`; waiter `0x100658a0`: `ev_d337b40e8685cb151f6b079ecb3e5ccff30a4eb066cb075cd2765de9ea4c1466`; RX → router: `ev_da3d10e7d21573814145ef581b50cef7430256e8d9bec48677c67e4ae2a8a011`; FIFO obtain: `ev_28e1e7d9a4706e9121ac6c72d026994b9b04f1283bed4859583f66a881c45fec`. Get-value использует уже сохранённый assembly `ev_d7575f1fc63bdbd9fda6fbe1cd2b2e8fa12a4372d135f5a72783cfa4d892dd0a`.

Полный bundle: `analysis/evidence/mongoose-response-layout-20261020.json` (30 records); инструкция-смещение и расчёт stack offsets — в соседнем `-notes.md`. `.snapshot.json` содержит Evidence без replay bindings; это не сохранённая Ghidra DB. Анализ статический: фактических аппаратных ответов не наблюдалось.

USB endpoints, начальное открытие устройства, реальные opcode/кодировка/тайминги, J2534 connect/read/write/filter и соответствие поколению Mongoose остаются `PHYSICAL_UNCONFIRMED`. Готовые пакеты не отправляются автоматически.
