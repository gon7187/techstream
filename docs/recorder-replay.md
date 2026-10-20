# Native recorder replay

Open **Без автомобиля → Открыть файл…**, select a native DRS settings file, then choose **Воспроизвести работу регистратора…** and its captured recording. The desktop executes the original settings against the captured exchanges. It does not open an adapter. The result shows the native trigger marker, packet values, a selectable chart and complete error/cleanup details. **Сохранить отчёт JSON** retains the full report.

**Сохранить снимок DM…** is available only after a completed recording with explicitly supplied monitor and system metadata. It writes a native DM using the captured packets, original signal definitions and supplied metadata. The exporter protects both input files and their symbolic/hard-link aliases. Without the required metadata the capture still runs and shows explicitly labelled raw signal values; no blank vehicle identity or metadata is invented. Unknown display types remain unresolved.

The recording uses `techstream-native-recorder-v1`. Its exact top-level fields are `schema`, `source`, `context`, `events`; duplicate JSON keys are rejected. `source` is `authored_synthetic` or `recorded_unverified`. Combined settings and recording inputs are limited to 16 MiB and must be regular local files. Generated native DM files use the snapshot format's separate 32 MiB bound, including its envelope; the desktop can reopen and preserve these larger captures.

The context has these required fields:

- `capabilities`: explicitly captured flags `denso-vim-control` and `denso-vim-dmci`; J2534 events additionally require `native-drs-execution`.
- `interface_id`: the actual unsigned 32-bit interface identifier.
- `phase`: actual native packet phase `0` or `1`.
- `trigger_events`: ordered nullable unsigned 32-bit observations of the manual button's WinCE tick. The engine consumes them only when the native manual trigger requests input and derives the capture marker from the subsequent packet timestamps; these are not direct marker overrides. Parameter triggers use their original comparisons and cannot be bypassed through this list.
- `limits`: `seconds` within `(0,3600]` and `max_polls` within `1..100000`. Caller limits may make these bounds tighter.

Optional `recorder_state_hex` contains the actual eight-byte native `temp.dat` state. If absent, the original constructor defaults apply. Its first DWORD is the persisted raw condition reference; the second is the check-mode state. Optional `system_information_hex` contains the actual native encoded 0x8100 system record. Both system information and monitor metadata are required for full native DM export. Optional `monitor_metadata_hex` contains an explicitly supplied native `encode_monitor_buffer` record. Its phase must match the recording. Native DM export retains its metadata, standard values and ring block size; these are not inferred from adapter branding.

Events share one chronological cursor across both families. A VIM event is `{"kind":"vim","transaction":{...}}`; its transaction has the native exchange fields with explicit `ecu: "vim"`, exact hexadecimal `request` and `response`, or a nonzero native `status` and `partial_response`. Dedicated logical VIM messages may exceed 65535 bytes while remaining within the aggregate file bound. This does not increase Toyota application-PDU bounds.

A J2534 event has exact fields `kind: "j2534"`, `operation`, `fields`, and `result`. A native failure replaces `result` with `error: {"code": nonzero_uint32}`. Supported operations are:

| Operation | Fields | Result |
| --- | --- | --- |
| `connect` | `protocol_id`, `flags` | Actual channel ID |
| `disconnect` | `channel_id` | `null` |
| `read_messages` | Seven native `words`, hexadecimal `mask_data` and `pattern_data`, `channel_id` | Native message |
| `write_messages` | `timeout`, native `message`, `channel_id` | `null` |
| `start_message_filter` | `filter_type`, three native `messages`, `channel_id` | `null` |
| `set_config` | `parameters` as pairs of unsigned words, `channel_id` | `null` |
| `five_baud_init` | Hexadecimal `data`, `value_after_data`, `channel_id` | `null` |
| `fast_init` | Native `message`, `channel_id` | `null` |

A native message has exactly `protocol_id`, `rx_status`, `tx_flags`, `timestamp`, `extra_data_index`, `data_hex`. Every numeric field is an unsigned 32-bit value. Read results preserve status flags; the actual native engine decides which replies to skip or match. Every field and result is validated before executing any command.

The engine consumes the actual DRS start, protocol/check-mode, acquisition and stop operations. Cancellation and failure retain their status, consumed events, remaining counts and cleanup errors. The final stop uses the engine's bounded cleanup path and requires its real recorded reply; success is never synthesized. Completion requires every event and requested manual-trigger observation to be consumed.

The public Python entry points are `replay_recorder(settings_path, recording_path, *, timeout=30, max_polls=100000, cancelled=None)`, `save_recorder_dm(destination, report, *, sources=(settings_path, recording_path))`, and `create_recorder_examples()`. The last returns authored example bytes without reading proprietary resources or importing tests.

All results remain `PHYSICAL_UNCONFIRMED`. Replay does not establish real adapter capabilities, vehicle compatibility or physical recorder behavior.

For a manual trigger, the observed button tick and derived capture marker can differ. The native reader checks the available packet batch and then waits for a following packet batch when required. Serial mode zero preserves the full native ring image in the exported DM; the report's selected trigger-window packets may therefore be a smaller subset of the exported playback.
