# Native monitor recordings

`load_monitor_recording(path, source_root, cancelled=...)` reads a bounded JSON
recording and the explicitly selected directory containing `Toyota.ddb`, the
selected ECU database and `M_English.ddb`. It opens no adapter, service, network
connection or imported executable. `session.run()` performs the real selected
support discovery, provider construction, scheduler and native DM/DRS encoding.
The desktop uses this API on its offline page.

```python
from scripts.monitor_replay import load_monitor_recording

session = load_monitor_recording("recording.json", "Techstream_DB_NA")
report = session.run()
session.save_dm("monitor.dm")
# Legacy Run87 retains native settings rather than fabricated samples:
# session.save_output("recording.drs", stream="recording")
# Combined acquisition retains a separate native instrument stream:
if "oscilloscope" in session.outputs:
    session.save_dm("oscilloscope.dm", stream="oscilloscope")
```

A session is single-use. `session.sources` lists all recording/database inputs
for export protection. SHA pins are checked when loading, before execution,
after execution and before export; input aliases and hard links cannot be
export destinations. Native output must reparse byte-for-byte before it is
made available. A failed run has no completed export.

The completed JSON-safe report has `workflow="monitor_replay"`,
`status="completed"`, `physical_status="PHYSICAL_UNCONFIRMED"` and
`result.playback.samples` for DM. `result.outputs` contains named `monitor` and,
when selected, `oscilloscope` streams, each with native DM bytes encoded as
`native_dm_hex` and independently decoded playback. Timestamps retain native
raw units; separate streams are not resampled or assigned an invented common
clock. `session.outputs` retains the bytes, and `save_dm(..., stream=...)`
saves the selected DM stream atomically. Legacy Run87 instead yields a
`recording` output with `format="drs"`, `native_drs_hex` and the actual
`DrsFile.report()` projection in `native_settings`; it has no fabricated
playback. All output descriptors carry `format="dm"` or `format="drs"`.
`save_output(..., stream="recording")` atomically saves DRS; `save_dm` rejects it.

## Recording contract

Top-level fields are exactly `schema`, `source`, `context`, `events`.
`schema` is `techstream-native-monitor-v1`; `source` is `authored_synthetic`
or `recorded_unverified`. The source label records provenance, not hardware
validation. Unknown fields, duplicate JSON keys, nonfinite numbers, malformed
hexadecimal, oversized structures and trailing/unconsumed events are rejected.
The file is at most 16 MiB and contains at most 100,000 primitive events.

Context fields are explicit native observations:

- `source_build`: 12 or 18; `mode`: `normal`, `dual`, `variable` or `legacy`.
- `category`, `selected_ids`, `vehicle_name_key`, `exception_ids`: exact resource
  selection. `vehicle_name_key` is null or a uint16; `exception_ids` is an
  ordered JSON list of at most 256 nonzero uint16 IDs. Order and duplicates
  are preserved; 256 is a host work budget for repeated correspondence scans,
  not a recovered native ceiling. `source_files`: relative filenames mapped to SHA-256. Management,
  language and every consumed ECU/instrument database must be pinned.
- `module_ids`: exact module filename-to-SHA mapping from the canonical static
  native inventory for the build and selected provider. `monitor_module_ids()`
  exposes the required immutable mapping. This includes controller, data-list,
  common monitor/command/lower modules and the selected provider; Dual adds its
  provider, variable adds its actual Phase4 child. Run87 adds
  `FileManagerIT3.dll` and `CommandDataLib.dll`; actual logical VIM calls add
  the explicitly selected application VS variant of `ComTol32.dll` plus
  `CommandDataLib.dll` for typed DMCI bodies, never an
  arbitrary basename match from XP/CUW/SUW copies. Imported modules are never
  loaded. A mismatched build/module mapping is rejected before SDK replay.
- `ecu`, `bus_id`, `diagnostic_mode_hex` (exactly 16 bytes), `controller_flags`,
  `device_kind`, `native_variant`, `initial_request_hex`: selected lower context.
  The actual selected producer validates its exact transport class/request.
- `driver`: `version_status`, `api_version_hex`, `source`.
- `observed_functions`: decimal native function IDs mapped to booleans.
- `selection`: `communication_protocol`, `attribute_3_31`, `excluded`,
  `standard_values`, `parameter_6`, `active_alias_pid`, `dynamic_requested`,
  `routine_ids`, `native_ecu`. Values feed the existing selected factory.
- `metadata`: `phase`, `allocation_size`, `name_hex`, `text_encoding`,
  `system_information_hex` (the actual native system-information record).
- `limits`: `seconds` (positive, at most 3600), `exchanges` (1–65535);
  `packet_count` (1–65535). Decoded playback is capped at 100,000 selected cells.
- `dual`: null or `retry_limit`, `send_timeout`, `receive_timeout`, `map_values`.
- `oscilloscope`: null or `selected_ids`, `measure_time_range`,
  `forward_time_range`; its actual category999 database must also be pinned.
- `variable`: null or `command_kind`, `command_ecu`, `standard_values` for the
  selected variable runtime factory, with optional `init_mode` and
  `parameter_c0` observations. Actual device4 passes raw VIM exchanges to
  `NativeVimClient`; support discovery still uses the actual device4 lower
  context. The selected primary ISO row is read from the database, not JSON.
  This schema currently records one actual target.
- Optional `vim`: exact `capabilities=["denso-vim-control","denso-vim-dmci"]`
  and explicit `module_variant="VS_x86"` or `"VS_x64"`; the selected module SHA
  must match the application artifact for the selected source build.
- Optional `primary`: management-only `category`, `ecu`, `bus_id`,
  `diagnostic_mode_hex`, `initial_request_hex` for an actual command ECU absent
  from the selected target. Its vehicle/exception context is retained; no
  invented ECU database, NULL buffer or sample is created. Variable NULL
  primary uses command kind `0x42`; capture index0 remains the actual child.
- `legacy`: exact `command_id` (9, 56 or 87), `command_ecu`, `enable_mode`,
  `shared_interface`, `init_mode`, `parameter_c0`, `standard_values`,
  `vehicle_selection_hex`, `trigger_info_hex`, `trigger_parameters_hex`. The
  last three fields contain actual native metadata for Run87, otherwise null.
  The source-selected P3/DK factory and exact prepared controller/message pair
  perform Run and Run87; DRS finishing obtains actual VIN/support metadata
  before closing communication.

`kind="vim"`, `operation="exchange"` retains exact raw logical command and
reply bytes: `request={"data":{"bytes":"..."}}`, `result={"bytes":"..."}`.
It is a primitive wire boundary, not an externally supplied operation plan.
Native command/status validation, deadlines and cancellation are enforced by
the existing client. Zero events are valid only when the actual selected
native path completes or rejects before any primitive call; no dummy traffic
is inserted to pad such paths.

`kind="host"`, `operation="enqueue"` records a native host input at its
actual position among SDK/VIM calls. `result` must be null: command completion
is computed by `VariableMonitorRuntime`, not supplied in JSON. The request is
exactly one of:

- `command_id=11`, `signal_id`, `value`, `auxiliary`, `initial_repeat` (null or
  uint16): the existing selected variable active-operation producer.
- `command_id=96`, `signal_id`: the existing selected variable system producer.
- `command_id=12`, `initialize` (literal boolean): native active stop.

The loader uses the real `start`, `enqueue`, `step`, `stop` lifecycle. Both
command count and cooperative steps are bounded by `limits.exchanges`.
`result.commands` contains actual `command_id`, `completed`, `status` and
`error_type`; raw exception messages and recorded bytes are not copied into
that report. A native command failure may be reported alongside a valid
monitor capture when the actual runtime continues acquisition. Cancellation
and cleanup remain owned by the concrete runtime.

Each chronological event has exactly `kind`, `operation`, `request`, `result`,
`elapsed_ms`, `tick`. All support, SDK and instrument calls share one cursor;
observed per-primitive elapsed time and native ticks feed the existing runtime budgets.
`elapsed_ms` excludes waits requested by the ported host logic: those advance
the deterministic host clock by the actual requested duration without sleeping
or fabricating SDK results. Native raw ticks remain exactly the recorded ticks.
There are no operation plans, externally supplied packing layouts, samples,
completed business callbacks or provider fallback guesses.

For `kind="sdk"`, operations are the existing concrete frame SDK primitives:
`connect`, `disconnect`, `ioctl`, `start_message_filter`, `stop_message_filter`,
`write_messages`, `read_messages`, `start_periodic_message`,
`stop_periodic_message`. Requests retain every actual argument. The result is
all `J2534Result` fields: `code`, `handle`, `count`, `messages`, `data`, `configs`,
`host_boundary`. Messages retain all `NativeMessage` fields. `sdk_value()`
produces the literal JSON representation: byte strings become `{"bytes":"..."}`;
sequences become arrays; native dataclasses retain their exact named fields.
A byte string never matches an ordinary string. Native status and explicit
before/after host cancellation/deadline boundaries retain their meaning.

For `kind="support"`, operations are `exchange`, `send`, `receive`. Requests
retain the actual query (`ecu`, byte `request`, `native_parameter`, `extended`,
`capacity`) and, for stream calls, the actual timer/parameter fields. Results
are `{"status": unsigned_status, "data": "strict_hex"}`. A send cannot return
receive bytes. `kind="osc"` carries actual `command`, `set_parameter` or
`read_buffer` calls; read results retain all `OscRead` fields.

Mismatch errors include only the event index, never recorded requests,
responses, arbitrary JSON keys or credentials. Raw recording/report/DM files
remain local data; the API does not upload or publish them.

## Verification and current limits

`python -m unittest discover -s tests -p test_monitor_replay.py -v` exercises
all five selected production paths (normal, A8, combined oscillator, Dual and
single-target variable), device4 VIM/NULL-primary, P3 Run/Run87 and DK Run
on authored source12/source18 databases, native DM/DRS
reparse/export, raw argument order, extra/truncated streams, source mutation,
missing instrument pins, native faults, host exception identity, cancellation,
deadline, parser/storage bounds and input alias protection. The fixture author
is test-only; the second execution reads its literal JSON through the public
loader and actual production factories.

This schema does not yet represent multiple Dual/variable targets, variable
multiple-target host command routing, variable outer Run87 or normal
active/system slots. The current host-input extension covers the actual
single-child variable runtime, including a management-only NULL primary.
Native DK device4 rejects with `C0051302`; DK Run87 device8 preserves
`90050405`. These recovered native unsupported branches do not fall back to
another provider or emit fabricated captures.
Those are software scope limits, not hardware uncertainty. Recordings do not
prove physical timing, driver ABI or vehicle compatibility. Full source and
rendered desktop acceptance are tracked separately; passing the focused tests
does not close the overall native-port gates.

The paused development checkpoint adds the required `CommandDataLib.dll`
pin for every VIM path. Source12/source18 outer logical ComTol framing has
a scoped static comparison; source12 selected nested CommandDataLib body
closure was still being checked when work paused. Authored functional tests
do not replace that pending source proof or a new independent/GTK acceptance
for the host-input candidate. The earlier accepted `35e60b17` consumer
snapshot predates these host-input and module-closure changes.
