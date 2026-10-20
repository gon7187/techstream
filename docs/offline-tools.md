# Offline workflows and native files

The desktop's offline tools execute authored examples through the same recovered
engines used by the Python API. They never discover or open an adapter. Example
responses are synthetic; successful execution does not establish compatibility
with an ECU or a vehicle.

```sh
python -m scripts.offline_tools example toyota
python -m scripts.offline_tools example utility
python -m scripts.offline_tools example script
python -m scripts.offline_tools example snapshot
python -m scripts.offline_tools example programming
python -m scripts.offline_tools example recorder
python -m scripts.offline_tools example transport
python -m scripts.offline_tools example monitors
python -m scripts.offline_tools example log
```

Each report includes `source: authored_synthetic`, the workflow identifier and
`physical_status: PHYSICAL_UNCONFIRMED`. Examples check their actual decoded
results and consume every expected exchange. Cancellation is checked before
execution, at engine boundaries, and before publishing a completed report.

The programming example explicitly separates the host state-machine simulation
from the recovered ReproStd transfer fragment. The fragment does not perform or
claim complete programming. The recorder example executes recovered DRS commands
against a stateful host model; it does not assert a recovered onboard control ABI.

Generate authored binary-format examples in a **new** directory, inspect them,
and export a report:

```sh
python -m scripts.offline_tools create-examples /tmp/techstream-examples
python -m scripts.offline_tools inspect /tmp/techstream-examples/capture.dm \
  --output /tmp/capture-report.json
python -m scripts.offline_tools copy-native /tmp/techstream-examples/capture.dm \
  /tmp/capture-copy.dm
```

Inspection accepts recovered DM, DRS, TSE, RMViewer communication logs, CUW,
S-record, native utility XML, CSDF `.bin`, encoded calibration INI/plain CSV,
static DLL export/version metadata, saved AllDTC XML reports and
[native exchange JSON](native-replay.md) formats. DM, DRS and TSE inputs use a
32 MiB limit; other inspected input types retain a 16 MiB limit. Utility XML uses
its original four-byte envelope and UTF-16 BOM. Saved AllDTC XML is a separate
schema and accepts ordinary UTF-8 or declared UTF-16 input. Unsupported or
malformed formats fail explicitly. Native file reports retain their format's
documented coverage boundaries. Original files are never rewritten by inspection.

DM and recovered TSE monitor playback join the saved frame, signal and ring-buffer records. Select a capture with `inspect --buffer-index N`; the report lists `available_buffers` and the selected `playback_index`. Report-only TSE files have no invented monitor data.

Saved TSE report text requires an explicit encoding, for example `inspect report.tse --encoding cp932`. This adds named `report_views` and `report_encoding` to the result; without it, inspection retains raw metadata and monitor summaries. The encoding is never guessed from the current desktop locale. Incompatible text or an unsupported encoding fails without modifying the input.
Playback preserves
raw timestamps and flags, applies the saved conversion parameters, and makes no
assumption about timestamp units. JSON export and native copying reject the
source itself, symlinks to it, and hard links to it. Native copying verifies an
exact byte-preserving round trip, including unknown and duplicate table records,
before atomically replacing the destination. A failed write preserves the
previous destination.

The generated files include a saved diagnostic XML report, imported calibration
and recorder recordings, and seven captured service scenarios. All examples are
authored data; no original calibration, driver code or licensed content is included.

`python -m scripts.offline_verify workflows` executes all examples, inspection,
report export and native copying. It also runs the imported calibration session,
the native recorder recording through DM export/playback, and every generated
service recording to chronology exhaustion. This is an integration check, not the final
no-car completion gate. That separate gate also requires complete reviewed
operation coverage and rejects unresolved software work.
