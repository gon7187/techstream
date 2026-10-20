# Native communication logs

`scripts.communication_log` reads and writes the binary communication log emitted
by RMViewer. It also implements the independent CSDF in-memory message queue.
No proprietary DLL runs and no adapter opens.

`parse(bytes) -> CommunicationLogFile`, `dumps(log) -> bytes`, and `load(path)`
preserve table order, duplicate IDs, unknown IDs and payloads, version revision,
and raw tick/calendar words. `LogRecord` is `snapshot.Table(id, payload)`.
`CommunicationLogFile(version, revision, records)` accepts native version 1;
unknown versions fail explicitly. Revision is retained without assigning meaning.
Input/output is capped at 32 MiB and 100,000 records. Length arithmetic is checked
before consuming bytes or building expanded CAN records.

## Binary layout

All integer fields are little endian. The envelope is `<IHH>`: magic
`0x80000003`, version 1, revision 0 in both observed native writers. Each following
record is `<IH>`: a uint32 size **including the uint16 ID but excluding the uint32
size itself**, then payload. There is no JSON wrapper or invented file signature.
Unknown payloads remain opaque. Known malformed time, status and packet records
fail explicitly. There is no checksum in the recovered writer.

| ID | Native payload |
| --- | --- |
| `0x8000`, `0x8003` | uint32 raw tick, seven uint16 calendar words: year, month, day, hour, minute, second, millisecond |
| `0x0103`, `0x0203` | uint32 tick followed by the concatenated native message byte arrays |
| `0x0105`, `0x0205` | uint32 tick, transport header, padded CAN chunk |
| `0x1103`, `0x1105` | uint32 field2c, uint32 field28, two status bytes |

The native timestamp records are 20 bytes including the ID. RMViewer writes
`start_tick` with the calendar at `_tagLogTime + 8` and `end_tick` with the calendar
at `+24`. CSDF's `SetEndLogTime` changes the former calendar. This apparently
reversed pairing is preserved literally. Tick values are never converted to UTC.
Calendar words are retained even when they do not describe a valid civil date.

`replay(log)` yields each raw record with its index, type, payload and, for proven
timestamped types, raw tick and modulo-uint32 elapsed milliseconds. It performs no
communication, scheduling or inferred ECU response. Unknown records have no
inferred timestamp. The native export loses the boundary between the two message
arrays and omits `field30`; import does not pretend to reconstruct those fields.

## CSDF lifecycle

`CommunicationLog(ticks=callable, local_time=callable)` starts with an empty queue
and zero timing state. The local callback supplies the **eight** Win32 SYSTEMTIME
words, including weekday; these are retained in `get_log_time()`'s exact 40-byte
native layout. `clear()` empties the queue, calls ticks twice, then local time
twice; the first calendar is the end calendar and the second is the start
calendar. `set_end_log_time()` updates only end tick/calendar.

`LogMessage(kind, protocol, first, second, field28, field2c, field30)` retains every
native value field without assigning speculative names to opaque DWORDs.
`put_log()` appends, `get_log()` returns an immutable snapshot, and
`update_log(index, message)` replaces every field in an existing element. An
out-of-range uint32 index is a native no-op. Negative indices fail. Failed budget
checks leave the queue intact. Put/update do not stamp time themselves.

`export()` emits native time records and `encode_message()` results. Kinds 1/2
map to record families `0x0100`/`0x0200`; kind 3 maps to `0x1100`. Protocol 4 uses
subtype 3; protocols 6/11 use subtype 5. Kind 3 writes field2c, field28 and the
first two bytes of `second`. Protocol 4 packet data concatenates both arrays.
CAN packet data uses native seven-byte padding, a six-byte first payload for
multi-frame messages, synthesized first/consecutive PCI bytes and zero tick for
continuation records. Multi-frame export requires the native five-byte transport
header; other header lengths are rejected because the observed native writer's
fixed declared record size would disagree with the bytes it emits. Other packet
protocols and nonpersisted message kinds fail explicitly instead of disappearing.
Imported unknown record types always round-trip untouched.

## DLOG is a separate container

`ReadDlogFile_DT.dll` delegates directly to `CDmFileReader::ReadTable` in
`FileManagerIT3.dll`. `parse_dlog(bytes)` therefore returns the existing native
DM `snapshot.TableFile`, requiring magic `0x80000002`. `snapshot.dumps()` preserves
its original fields. Its monitor/system table interpretation and playback are in
[snapshot-format.md](snapshot-format.md), including `decode_monitor_buffer`,
`decode_system_information` and `playback`. DLOG, RMViewer communication logs,
CSDF in-memory objects and firmware `VIM.vlg` are distinct contracts.
No original DLOG/VLG/communication recording was available in the extracted
corpus; tests use authored native-layout vectors, not captured vehicle data.

## Static provenance and verification

| Binary | SHA-256 | Anchors (RVA) |
| --- | --- | --- |
| Techstream 18 `CSDFCommunicationLog.dll` | `4a7c722445451a0b47707e5766263aee08fdef28f07159c79a0c7951310c7ab1` | clear `1240`, get/put `12c0`/`12d0`, timing `12e0`/`12f0`, update `1310`, node allocation/copy `1370` |
| Techstream 12 `CSDFCommunicationLog.dll` | `0b0e3b94b07de602d08358deb895c74f2c3b3792ea5b28129e070f3035dc55d2` | corresponding exported queue API; no file codec exports |
| Techstream 18 `RMViewer.dll` | `12c2bfec26d235cbaadec59cffde9fbb0927e047df4ae5f15bb5a836f44b4248` | magic/header `1ba85`, timing `1bb4f`, records `1bee6..1c38e`, header defaults `1c4f0` |
| Techstream 12 `RMViewer.dll` | `71d0e5a6b46c943c2a61b54aa96cf08bd0639ece6c46c5c0f75dbcb5e320c553` | matching magic/version/table header `14cf4..14db6`, timing `14dba` |
| GTSPlus `ReadDlogFile_DT.dll` | `dfde248cd9043f15edf580489ad4c79407b983a02ecdbd31e6ffac75bed84ac0` | Execute `13a0`, reader `10b0`, virtual ReadTable call `1262`, direct native thunk `147f` |

Run `python -m unittest discover -s tests -p test_communication_log.py -v`.
Vectors independently specify native integer stores, exact raw timestamps,
unknown records, CAN/status conversion, each truncated prefix, invalid lengths,
unsupported versions, queue mutation and memory budgets. Static provenance is
not a claim of physical vehicle validation.

Export preflights each message against the remaining file byte and record budgets
before allocating its records. CAN sizing includes the native 16-bit sequence wrap;
conversion walks the source buffer by offset without copying its entire remainder.
A rejected export leaves the source queue unchanged.
