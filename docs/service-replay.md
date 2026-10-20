# Captured CUW service execution

`scripts.service_replay` executes the client algorithms in `cuw_services` using
ordered primitive HTTP bytes, browser DOM snapshots and notification events.
It never opens a network connection, browser, device, licensed service or vendor
PE. A capture supplies observations, not a successful business-operation callback.

```python
from scripts.service_replay import ServiceReplay, create_demo_service_capture

replay = ServiceReplay.from_bytes(create_demo_service_capture("rks"))
report = replay.run(timeout=30)
replay.export_report("new-report.json")
```

`ServiceReplay.load(path)` reads a bounded regular file through `local_files`.
`from_bytes(bytes)` accepts the same JSON. Constructor input is copied and results
are copied on return. Executions are single-use, including failures. `report()`
returns a JSON-compatible report after execution or failure. Failed execution
raises the original exception; the stored report contains only its type and any
native status, never exception text, URL, request fields, server messages, DOM,
license, seed, signature or unlocking value.

The authored producer accepts `tis-check`, `tis-save`, `euro-online`, `euro-save`,
`euro-key`, `rks` and `notice`. It requires no installed OEM files and works in a
fresh clone. The PROACE example is a parsed server denial (native status 50).
The RKS example observes pending authorization (12) and independently imports an
explicitly synthetic 512-character ASCII shape fixture. Neither fixture claims
a valid signature, account session, licensed authorization or usable unlock key.
Tests also exercise a captured hidden `result_code=0`; that observation alone
cannot authenticate a key or authorize an ECU operation.

## Capture contract

The exact top-level keys are `schema`, `provenance`, `port_sources`, `workflow`
and `steps`. Schema is `techstream-service-replay-v1`; provenance is `authored`
or `captured`. The latter is a caller declaration, not authenticated provenance.
`port_sources` identifies the exact **ported native contract**, not the capture
file's origin or hash. Its immutable registry covers TIS/Euro 12 and 18, and RKS,
wrapper and notifier 18, verified against leaf 28's native contract index. The
capture's own normalized JSON SHA-256 is reported separately. No 2026 alias or
inferred 12/18 fallback is accepted; service algorithms currently port 12/18 only.

Service workflow fields are `kind`, `request` and `endpoint`; request fields map
to `TISRequest`, `EuroRequest` or `ProaceRequest`. Calibration entries are objects
with `kind` and `value`; frame pairs are arrays. RKS fields are `kind`, `data`
(the eight `RKSData` fields), `url`, `allowed_origins`, `watch_count` and `key_xml`
(canonical lowercase hex bytes). Notice fields are `kind` and `config`, mapping
to `NoticeConfig`.

Each step has `method`, `args`, `result` and `fault`, and optionally
`elapsed_ms` (default zero for instantaneous authored observations). No other
fields are accepted. `fault` is explicitly
null, `io`, `timeout` or `cancel`; it cannot contain arbitrary code or messages.
Argument objects must match the actual primitive call, including exact marshalled
request bytes, DOM paste text, window identity, endpoint/action and connector
properties. There is no wildcard match, default response or automatic retry.
Byte fields use canonical lowercase hexadecimal. Void calls require a null result.
Every supplied step must be consumed before the replay can complete.

| Primitive family | Methods |
| --- | --- |
| HTTP | `http.exchange`, `http.close` |
| Browser | `browser.create`, `browser.navigate`, `browser.snapshot`, `browser.set`, `browser.wait`, `browser.close` |
| Notification | `notice.cursor`, `notice.create`, `notice.render`, `notice.beep`, `notice.event`, `notice.close` |

HTTP exchange arguments contain `endpoint`, `action`, `body`,
`connector_properties` and `content_type`; results contain `status`, `body` and
`source`. Browser snapshot results have `window`, `url`, `busy`, `ready_state`,
`elements` and `closed`; element keys map to `DOMElement`. Notice event results
are null or map to `NoticeEvent`. `create_demo_service_capture` is an executable,
complete schema example for every family.

## Bounds and file outputs

One aggregate capture is limited to 8 MiB and 20,000 primitive steps. The native
XML parser and DOM budgets still apply; RKS additionally admits 1..10,000 explicit
watch observations. Captured elapsed observations must be finite nonnegative numbers, individually
and collectively at most 600,000 milliseconds. The deterministic native clock
advances by these observations, so event polls and browser waits reproduce
notification pulses without sleeping. Each observation must also fit the
primitive's actual requested timeout (including 50 ms event polls and five-second
cleanup); a one-nanosecond comparison tolerance absorbs float roundoff.
Independent outer wall-clock and captured-time deadlines (0..600 seconds,
exclusive zero) bound all workflow stages and watch iterations. Native timing
uses only the deterministic clock; host scheduling delays cannot change pulse
selection. Cancellation is checked
before and after each non-cleanup primitive. Initial clock faults finalize a
redacted failed report. The single-use state claim holds no lock while invoking
caller callbacks, so callback reentry rejects promptly instead of deadlocking. Cleanup is attempted on the owned transport
or window even after cancellation; cleanup faults cannot create success. Replay
waits consume captured scheduling observations without sleeping or real I/O.

`rks_request_bytes()` returns the exact native XML, including explicitly supplied
seed/license data. `export_rks_request(path)` deliberately exports that XML;
this output is sensitive, unlike the redacted report. Both export methods use a
0600 temporary sibling and an exclusive atomic hard-link publication. An existing
destination, including source aliases or symlinks, is preserved. Temporary files
are removed on publication failure. The destination parent must already exist.
The local filesystem must support hard links; failure leaves the destination
unmodified. Rename/power-loss durability of the parent directory is not claimed.

This is executable local software verification. External server authenticity,
licensed login and physical ECU acceptance remain unconfirmed. No service contact
or credential material is needed to exercise the complete replay boundary.

Run `python -m unittest discover -s tests -p test_service_replay.py -v` for positive,
malformed, exact chronology, fault-at-every-primitive, cleanup, deadline,
cancellation, browser identity, source preservation and alias isolation checks.
