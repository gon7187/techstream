# Captured native exchange

Native Toyota engines accept a strict recording format separate from the
standard OBD service allowlist. It carries raw application PDUs, receive-only
continuations, native transport errors and explicitly supplied support
observations. It never opens an adapter or infers vehicle identity.

```json
{
  "schema": "techstream-native-exchange-v1",
  "source": "authored_synthetic",
  "ecus": ["engine"],
  "support": {
    "engine": {"pid_lengths": {"0c": 2}, "did_lengths": null}
  },
  "transactions": [
    {"ecu": "engine", "request": "010c", "response": "410c1f40"}
  ]
}
```

Use `source: recorded_unverified` for an imported recording. Each transaction
matches its configured ECU label and request exactly. Empty request strings
mean receive-only continuation, not retransmission. Responses remain raw bytes;
the selected native engine validates their meaning. A native transport failure
has exactly these alternative fields:

```json
{"ecu": "engine", "request": "18", "status": 2432761865, "partial_response": ""}
```

The decimal status is `0x91010009`. Nonzero uint32 statuses become `NativeStatus`
with preserved partial response bytes. This allows timeout/error paths to be
replayed without manufacturing a negative ECU reply.

Support entries are captured `GetEnableIdList` observations: lowercase two-digit
hexadecimal PID/DID keys map to byte lengths. `null` or an absent ECU support
entry means unobserved, while `{}` means an explicitly supplied empty result.
Enhanced readiness requires PID-length observations and does not invent them
from resource definitions. These are supplied observations, not a claim that
the software verified their origin.

```python
from pathlib import Path
from scripts.native_replay import replay_profile
from scripts.profiles import VehicleCatalog

catalog = VehicleCatalog(Path("/path/to/Techstream_DB_NA"))
profile = catalog.build_profile(selected_category, vehicle_name_key=selected_vehicle)
report = replay_profile(profile, Path("recording.json"), operation="readiness")
```

`operation="data_list", signal_keys=(...)` selects original Freeze/PhyData
signals. `operation="command", function_id=...` checks a selected command's
recorded byte sequence and recovered receive masks; its raw responses are not
presented as fully decoded diagnostic results. The entire recording must be
consumed. Unknown ECUs, extra transactions, duplicate JSON keys, malformed
hexadecimal, unsupported fields, and missing observations fail explicitly.

Inputs are limited to 16 MiB and 100000 transactions, with at most 64 configured
ECUs and uint16 PDU lengths. Cancellation precedes each exchange. Reports retain
selected resource hashes and `PHYSICAL_UNCONFIRMED`.
