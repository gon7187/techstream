# Offline read-only diagnostics

Status: **PHYSICAL_UNCONFIRMED**. The included session is entirely authored synthetic data, with the placeholder VIN `SYNTHET1C00000000`. It contains no vehicle capture, owner data or proprietary database. ECU identifiers `engine` and `transmission` are configured labels, not discovered systems or verified Toyota addresses.

## Run the deterministic scenario

From the repository root, using Python 3.10 or later:

```python
from scripts.diagnostics import Session
from scripts.replay import Replay

replay = Replay.load("examples/diagnostic-session.json")
report = Session(replay.exchange).health_check(replay.ecus)
replay.assert_complete()
assert report["ecus"][0]["stored_dtcs"] == ["P0133", "P0420"]
assert report["ecus"][1]["stored_dtcs"] == []
```

The fixture contains exactly one sequential health check of two configured ECUs. Reports are JSON-compatible and deterministic. Each ECU includes VIN, stored/pending/permanent codes, supported PID lists, readiness, live values and frame-zero freeze data where supported. Failed fields are absent and accompanied by typed errors; they never become invented zero values. `stored_dtcs` means the standard service 03 category, **not** a Toyota current/history distinction. A health check is a snapshot; call it again with a fresh recording to refresh it.

## Application boundary

`Session(exchange, cancelled=None, clock=time.monotonic)` calls `exchange(ecu: str, request: bytes) -> bytes`. The backend must address that ECU, enforce its own bounded timeout, and return one complete ISO-TP-reassembled application PDU, without CAN identifiers, PCI bytes or CAN padding. ECU labels must contain 1–64 ASCII letters, digits, `_`, `-` or `.`. This layer does not select a USB device, CAN address or vehicle profile.

Only the following complete requests pass the allowlist:

- `01 PP`: defined scalar/compound parameters in `PID_SIZES`, including support pages `00`, `20`, `40`, `60`, `80`, `A0`, `C0`, `E0`.
- `02 PP 00`: frame zero for defined parameters, excluding readiness PIDs `01` and `41`.
- `03`, `07`, `0A`: stored, pending and permanent emission-related DTCs.
- `09 PP`: support pages and information types `01`–`0F`: message counts, VIN, CALID/CVN, in-use tracking, ECU name, engine serial/type approval.
- `06 MM`: CAN monitor support pages or one monitor ID, with strictly correlated records.
- `05 TT SS`: explicit legacy non-CAN oxygen tests with Annex C-defined scaling or support page; `SS` is a single-bit sensor-location mask. `oxygen_tests()` requires a legacy protocol argument.

Clear codes, actuator tests, VIN writes, arbitrary UDS requests and programming are rejected before exchange. Positive responses must echo service plus `40`, PID and frame as applicable, with exact data lengths. Service `06` repeats MID in **each** nine-byte record; every echoed MID is checked. Fuel-trim parameters permit exactly one or two bytes where the standard allows a second bank; absence never becomes a zero-valued bank. Negative replies become `NegativeResponse(service, code)`; response-pending does not silently retry. Malformed/unrelated responses raise `DiagnosticError`. The backend reports a bounded no-response as `TimeoutError`. Health checks retain individual failures and continue sequentially; `Cancelled` always propagates. Cancellation is checked before and after exchange and cannot interrupt a blocking backend call.

Mode 01 and Mode 02 support maps are queried separately. Readiness includes support and completion independently, with `complete: null` for unsupported monitors, and separate spark/compression ignition names. The default health check reads coolant temperature, RPM, speed and throttle position. Explicit polling also supports the numeric PIDs below. CAN DTC messages require an explicit count followed by exactly that many two-byte codes; legacy non-CAN DTC layouts are intentionally rejected.

`Session.poll(ecu, pids=(5, 12, 13, 17), samples=1)` performs bounded sequential reads and returns sample indices, acquisition-start `elapsed_seconds`, ECU labels and values. The clock must be finite and monotonic. It does not sleep, schedule a polling rate, imply simultaneous ECU sampling or promise playback timing. Pass an explicit clock to reproduce timestamp tests. Recorded values and ordering replay exactly; host acquisition times do not.

`Session.iter_poll(...)` accepts the same arguments as `poll` and yields one sample at a time, retaining no previous samples. Creating the iterator performs no I/O; validation and cancellation happen when it is consumed. `poll` collects that iterator into a list. Both bound a run to 10,000 samples; callers needing a stream should use the iterator and stop consuming or set the cancellation callback.

### Additional numeric parameters

These scalings follow the instrument manufacturer's [CSS Electronics PID table](https://www.csselectronics.com/pages/obd2-pid-table-on-board-diagnostics-j1979). `A` is the first data byte; `AB` is an unsigned big-endian 16-bit value. `NUMERIC_PIDS` exposes the supported definitions, now including additional pressure, temperature, load, fuel, timing, torque and odometer scalars. The table below retains the original baseline examples; the executable inventory is `NUMERIC_PIDS` / `COMPOUND_SIZES`. The existing four-PID health workflow stays unchanged.

| PID | Signal | Physical value | Unit |
| --- | --- | --- | --- |
| `04` | Calculated load | `A * 100 / 255` | % |
| `05` | Coolant temperature | `A - 40` | degC |
| `06`, `07` | Short/long fuel trim, bank 1 | `A * 100 / 128 - 100` | % |
| `08`, `09` | Short/long fuel trim, bank 2 | `A * 100 / 128 - 100` | % |
| `0A` | Fuel gauge pressure | `A * 3` | kPa |
| `0B` | Manifold absolute pressure | `A` | kPa |
| `0C` | Engine speed | `AB / 4` | rpm |
| `0D` | Vehicle speed | `A` | km/h |
| `0E` | Timing advance | `A / 2 - 64` | deg |
| `0F` | Intake air temperature | `A - 40` | degC |
| `10` | Mass air flow | `AB / 100` | g/s |
| `11` | Throttle position | `A * 100 / 255` | % |
| `1F` | Runtime since engine start | `AB` | s |

### Calibration information

`Session.calibration(ecu)` is a separate read-only operation. It first reads `09 00` and queries `09 04` / `09 06` only when their support bits are set. The JSON-compatible result includes ECU, physical status, scope, status, errors and supported information types; successful fields are `calibration_ids` and `cvns`. Unsupported or failed fields are absent. This operation does not change the bundled health-check fixture or silently append extra requests.

CAN information responses require a nonzero record count followed by exactly that many records: 16 bytes per CALID and four bytes per CVN. CALIDs accept printable ASCII with trailing NUL padding only. CVNs preserve all four bytes as eight uppercase hex digits, including leading zeros. These representations follow SAE J1979 MAY2007 §6.10 and Annex G tables G4/G6; [the 2002 incorporated standard](https://law.resource.org/pub/us/cfr/ibr/005/sae.j1979.2002.pdf) also defines the CALID/CVN fields. Arrays remain independent; the module does not invent a manufacturer-specific mapping between IDs and checksums. Reading a CVN neither calculates one locally nor certifies software authenticity. A response-pending NRC remains an explicit error; no unbounded wait is added.

Calibration and extended-poll fixtures are authored inline in the tests. They demonstrate strict replay/record round trips without presenting original calibration identifiers or vehicle captures.

## Strict replay and recording

The JSON schema is `techstream-native-replay-v1`, with exactly `schema`, `source`, `ecus` and `transactions`. `source` is `authored_synthetic` or `recorded_unverified`; recording does not establish hardware validity. Each transaction has exactly `ecu`, `request` and `response`, with even-length, whitespace-free hexadecimal PDUs. Positive and negative response structure is validated on load. Files are bounded to 16 MiB, 64 ECU labels, 100,000 transactions and 4095 bytes per PDU. Duplicate JSON keys, unknown fields, unknown ECUs, unsupported requests and malformed payloads are rejected.

`Replay.exchange` matches both ECU and request at the current position. Mismatch and exhaustion raise `ReplayMismatch` / `ReplayExhausted`; a mismatch never advances. `remaining` reports unused transactions; `assert_complete()` rejects a partial replay. There is no looping, best-match lookup, fallback ECU or synthetic response generation.

`Recorder(exchange)` exposes the same exchange method and saves accepted transactions with `save(path)`. It bounds storage and validates protocol responses. Saving uses exclusive creation so it cannot overwrite an existing recording. It records successful/negative exchanges, not timeout exceptions, raw USB packets, CAN frames or original Techstream TSE files. A recording containing VINs must be treated as vehicle data; the bundled authored example contains no real VIN.

## Evidence and boundaries

The standard service roles are defined by [SAE J1979](https://saemobilus.sae.org/standards/j1979_200705-e-e-diagnostic-test-modes), with parameter definitions in [SAE J1979-DA](https://saemobilus.sae.org/standards/j1979da_202305-j1979-da-digital-annex-e-e-diagnostic-test-modes). [Elm Electronics' ELM327 datasheet](https://www.elmelectronics.com/wp-content/uploads/2017/01/ELM327DS.pdf), sections “Interpreting Trouble Codes”, “OBD Message Formats”, “Multiline Responses” and “Response Pending Messages”, provides manufacturer-authored examples of service replies, DTC encoding, CAN record counts and VIN reassembly. These sources identify the standard OBD boundary; the implementation does not claim ELM327 serial support.

Private static inspection of original Techstream feature seams identified separate VIN, DTC, freeze-frame, health-check and periodic-data operations. Those seams justify separating orchestration from exchange; they do not establish Toyota message bytes. This implementation uses the standard OBD subset, not proprietary command or database parity. No proprietary artifacts, extracted manuals or binary-derived fixtures are required to run it.

This module does not perform ECU discovery, Toyota enhanced systems/DTC status, real-time scheduling, original session formats, onboard recording, physical transport binding or writes. Those families have separate project modules. Offline tests establish parser/orchestration behavior; real ECU addressing, bus load, timeout tuning and applicability remain physically unconfirmed. Advertised parameters outside this module’s semantic definition inventory are reported explicitly as unresolved, rather than returned as successfully decoded raw bytes.

## Checks

```sh
python -m unittest discover -s tests -p 'test_diagnostics.py' -v
python -m unittest discover -s tests -p 'test_replay.py' -v
ruff check scripts/diagnostics.py scripts/replay.py tests/test_diagnostics.py tests/test_replay.py
pyright scripts/diagnostics.py scripts/replay.py tests/test_diagnostics.py tests/test_replay.py
```

## Monitor results and compound parameters

`Session.monitors(ecu)` walks the service `06` support maps and reads only advertised monitor IDs. It returns `supported_mids`, `results`, `status`, typed `errors`, provenance and physical status. Each nine-byte record is MID, TID, unit/scaling ID, then unsigned big-endian 16-bit value, minimum and maximum. The scaling ID selects signed two's-complement interpretation where defined. The supported scale inventory contains **all 92 defined IDs in SAE J1979-DA OCT2011 Annex E**; reserved/newer IDs remain `unresolved_scaling`, omit physical values and make the report `partial`. Numeric conversion uses the published scaling/bit column, not rounded extrema in examples. Units are preserved explicitly, including milliamperes, microseconds and inches where defined.

Minimum and maximum are inclusive. Status is `pass` or `fail`; value/minimum/maximum all zero means `not_completed`, as specified by service 06, and cannot be called a pass. Reversed limits, repeated TIDs, unrelated MIDs, truncated records and invalid boolean values are rejected. Monitor retrieval does not start a test or infer the cause of a failure. Manufacturer TIDs retain `manufacturer_defined` as their test name; a standard unit does not establish a Toyota-specific test meaning. The overall report is `partial` with `UnresolvedTestDefinition` even when the numeric limit comparison is valid.

```python
from scripts.diagnostics import Session
from scripts.replay import Replay

replay = Replay({
    "schema": "techstream-native-replay-v1",
    "source": "authored_synthetic",
    "ecus": ["engine"],
    "transactions": [
        {"ecu": "engine", "request": "0600", "response": "460080000000"},
        {"ecu": "engine", "request": "0601", "response": "4601010a03e8000007d0"},
    ],
})
report = Session(replay.exchange).monitors("engine")
assert report["results"][0]["value"] == 0.122
assert report["results"][0]["status"] == "pass"
replay.assert_complete()
```

`Session.support(ecu, service=1, frame=0, sensor=1)` traverses at most eight support pages. Only an advertised continuation bit permits the next request. Returned identifiers exclude continuation-page markers and never include identifier 256. Mode 01, freeze frame, legacy oxygen, CAN monitor and vehicle-information maps are independent. A support timeout/negative reply is not silently treated as an empty supported set.

`Session.parameters(ecu, pids=None, freeze=False)` reads the support chain, rejects requested unsupported IDs, and decodes scalar or compound fields. The baseline health fixture and its request order remain unchanged. With `pids=None`, it reads defined advertised parameters; advertised unknown IDs appear in `unresolved_pids` with `status: partial`. Compound oxygen records preserve voltage/trim, or equivalence ratio and voltage/current, as separate physical quantities. A narrowband trim byte `FF` means unavailable and becomes `null`. Signed evaporative vapor pressure, evaporative purge command/level, readiness this cycle, fuel system state, air system state, sensor locations, fuel type, auxiliary support/status, dual MAF/coolant and six intake-temperature fields are decoded structurally. Unsupported sensor measurements become `null` even if their reserved payload bytes contain nonzero data.

Scaling configuration PIDs `4F` and `50`, when advertised and required, are acquired **before** dependent parameters. `decode_parameter(pid, data, configuration_4f=None, configuration_50=None)` also supports explicitly supplied configuration bytes. Nonzero maxima rescale equivalence ratio, oxygen voltage/current, manifold pressure and mass flow using the prescribed denominators; zero maxima select the default definition. The tests include the standard's 32000-count lambda, 40000-count voltage and signed-current examples. A missing/failed advertised configuration raises an error; it does not silently select defaults. Calling a standalone decoder without context explicitly selects the standard default scaling.

## Legacy oxygen tests and information records

Service `05` is **not supported by ISO 15765 CAN**, per SAE J1979 APR2002 §6.5; CAN oxygen monitoring is retrieved through service `06`. `Session.oxygen_tests(ecu, sensor=1, protocol="iso9141")` supports explicit `iso9141`, `iso14230` or `j1850` reassembled application PDUs. The caller owns the legacy transport. Constant tests `01`–`04` have one data byte; calculated tests `05`–`0A` have value/minimum/maximum. Scaling follows Annex C. The support map gates every test; unsupported manufacturer definitions are listed in `unresolved_tids` and produce a partial report. No bus protocol is auto-detected.

`Session.information(ecu)` walks service `09` support and structurally decodes implemented advertised information types. In-use tracking counts 16/20 spark or 16/18 compression counters, using each counter's assigned completion/conditions name. A zero counter is retained as ECU data, without inventing an applicability claim or a ratio with a zero denominator. Optional later counters are absent when not supplied. ECU names require the four-byte acronym, dash delimiter and fifteen-byte name with independent trailing NUL padding; embedded NULs inside either text field are invalid. Serial/type-approval strings require one 17-byte record with leading NUL fill and their defined character alphabets.

Service `04` clear/reset and service `08` EVAP test activation remain rejected: they change ECU state. Read-only EVAP **results** are available through service `06`; pressure/command telemetry uses service `01`/`02`. This boundary preserves the task's no-vehicle-writes requirement.

The monitor record layout/support chain and zero-results rule come from [SAE J1979 APR2002, §6.6](https://s3-us-west-1.amazonaws.com/ptab-filings%2FIPR2023-00504%2F1075). Scale/configuration/information definitions use [SAE J1979-DA OCT2011, Annexes B/E/G](https://www.e90post.com/forums/attachment.php?attachmentid=1509324&d=1476497126). Later scalar quantities were cross-checked against the [instrument manufacturer's machine-readable PID data](https://canlogger.csselectronics.com/files/misc/obd2-pid-table-service-01.csv). These are standard definitions, independent of a claim that a specific Toyota implements them.

Private inspection identified twelve `MarketMonitor_*.bin` files as CSDF programs with ScriptLib dependencies, including Toyota `12`/`13`/`19`/`21`/`22`/`AA`/`AB` command families. They are covered by the separate CSDF/provider runtime; their byte literals are not treated as standard OBD scaling definitions. The inspected corpus contains `GetReadinessCode_DT.dll`, not `Readiness.bin`. Native names establish feature seams; the public implementations and fixtures above derive from cited standard definitions and authored synthetic transactions.

All standard parameter identifiers `00`–`87` now have a semantic decoder. In particular, `69`–`87` use the primary annex's exact support flags, field offsets, lengths and conversions for EGR/air/throttle, fuel/injection pressures, compressor pressure, boost/VGT/wastegate, exhaust pressure, turbo speed and temperatures, charge-air temperatures, exhaust/DPF temperatures and signed DPF pressure, NTE flags, engine/AECD runtimes, NOx, reagent, PM and manifold pressure. `LATE_COMPOUNDS` retains inspectable field definitions. Wide-range EGR temperature and compressor pressure use their actual support/range bits; boost/VGT status stays a separate state, including the specified `fault` state. An AECD timer-2 value `FFFFFFFF` means unavailable, while the same number in the general engine-runtime counters remains a number. Unknown later advertised IDs remain explicitly unresolved; no current-edition SAE coverage is claimed.

Legacy service `05` additionally handles the manufacturer-TID ranges whose **units and scales are defined by Annex C** (`21`–`2F`, `30`–`3F`, `41`–`4F`, `50`–`5F`, `61`–`6F`, `70`–`7F`). Their manufacturer-specific test names remain unknown. Support-page identifiers take precedence over test identifiers at `20`-byte boundaries. Manufacturer ranges without standard scales remain explicit unresolved definitions.


Known monitor MID/TID/scaling contradictions are rejected: standard TIDs01..0A require voltage0A or time10, and misfire TIDs0B/0C require MIDA2..AD plus scale24. Reserved/manufacturer MID or TID descriptions and reserved parameter enums make reports partial even when the numeric scale is known. Enhanced Toyota readiness and original signal rendering are documented in [readiness.md](readiness.md) and [signal-display.md](signal-display.md); they use selected native definitions rather than replacing them with standard PID01 bits.
