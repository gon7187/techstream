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

- `01 PP`: metadata PID `00`, `01`, `02`, or any numeric PID in the table below.
- `02 PP 00`: frame zero, support/DTC PID `00`, `02`, or any numeric PID below.
- `03`, `07`, `0A`: stored, pending and permanent emission-related DTCs.
- `09 00`, `09 02`, `09 04`, `09 06`: vehicle-information support, VIN, calibration IDs and CVNs.

Clear codes, actuator tests, VIN writes, arbitrary UDS requests and programming are rejected before exchange. Positive responses must echo service plus `40`, PID and frame as applicable, with exact data lengths. Negative replies become `NegativeResponse(service, code)`; response-pending does not silently retry. Malformed/unrelated responses raise `DiagnosticError`. The backend reports a bounded no-response as `TimeoutError`. Health checks retain individual failures and continue sequentially; `Cancelled` always propagates. Cancellation is checked before and after exchange and cannot interrupt a blocking backend call.

Mode 01 and Mode 02 support maps are queried separately. Readiness includes support and completion independently, with `complete: null` for unsupported monitors, and separate spark/compression ignition names. The default health check reads coolant temperature, RPM, speed and throttle position. Explicit polling also supports the numeric PIDs below. CAN DTC messages require an explicit count followed by exactly that many two-byte codes; legacy non-CAN DTC layouts are intentionally rejected.

`Session.poll(ecu, pids=(5, 12, 13, 17), samples=1)` performs bounded sequential reads and returns sample indices, acquisition-start `elapsed_seconds`, ECU labels and values. The clock must be finite and monotonic. It does not sleep, schedule a polling rate, imply simultaneous ECU sampling or promise playback timing. Pass an explicit clock to reproduce timestamp tests. Recorded values and ordering replay exactly; host acquisition times do not.

`Session.iter_poll(...)` accepts the same arguments as `poll` and yields one sample at a time, retaining no previous samples. Creating the iterator performs no I/O; validation and cancellation happen when it is consumed. `poll` collects that iterator into a list. Both bound a run to 10,000 samples; callers needing a stream should use the iterator and stop consuming or set the cancellation callback.

### Additional numeric parameters

These scalings follow the instrument manufacturer's [CSS Electronics PID table](https://www.csselectronics.com/pages/obd2-pid-table-on-board-diagnostics-j1979). `A` is the first data byte; `AB` is an unsigned big-endian 16-bit value. `NUMERIC_PIDS` exposes the supported definitions. The existing four-PID health workflow stays unchanged.

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

Unimplemented: ECU discovery, Toyota enhanced systems/DTC status, Mode 06, oxygen-sensor compound records, real-time scheduling, original session formats, onboard recording, physical transport binding and all writes. Offline tests establish parser/orchestration behavior only; real ECU addressing, bus load, timeout tuning and vehicle applicability still require hardware validation.

## Checks

```sh
python -m unittest discover -s tests -p 'test_diagnostics.py' -v
python -m unittest discover -s tests -p 'test_replay.py' -v
ruff check scripts/diagnostics.py scripts/replay.py tests/test_diagnostics.py tests/test_replay.py
pyright scripts/diagnostics.py scripts/replay.py tests/test_diagnostics.py tests/test_replay.py
```
