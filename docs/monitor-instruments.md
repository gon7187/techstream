# Voltage and oscilloscope instruments

`selected_instrument_monitor` in `scripts.monitor_instruments` binds an explicitly
selected database profile to native instrument descriptors, signal metadata,
frame sizes and a `NativeMonitorBuffer`. It opens no transport. Category `0x68`
means the voltage monitor; category `999` means the four-channel DST-i scope.
These category numbers are literal native identifiers.

The voltage producer requires one distinct Freeze signal whose inclusive bit
range occupies two bytes. Its literal setup descriptor is `04 00 00 00 01`,
mode `0x40`, frame zero, two bytes. Scaling reuses the shared voltage calibration
implementation: observed `0xFFFEFF84`/`0xFFFEFF90` setup and four
`0xFFFEFF80` WORD reads, with native mode `0/1/2` offset/cache behavior. Those
calibration reads do not establish a continuous voltage sampling capability.

Both original 12 and 18 `VoltageMonitorInterface` implementations return
`False` from setup/start/stop and `0xFFFFFFFF` from GetError. The native caller
can retry construction indefinitely. The bounded host exposes these literal
results and does not invent a working voltage sampler or run that retry loop.
A selected voltage descriptor and valid metadata therefore do not imply a
working voltage capture.

The scope producer requires four distinct Freeze signals. Each descriptor is
`channel, measure time, forward time, voltage range`, with `channel = start bit
>> 3` and `voltage range = Freeze[79] - 1` modulo 256. Native invalid/missing INI
time settings fall back to measure `11` and forward `7`; valid settings are
`1..21`. Native signal bit ranges remain unchanged in the saved metadata.

`OscConfiguration.selected(plan)` applies the descriptors using the concrete
J2534 scope setters. `OscilloscopeRuntime` executes these operations over an
injected `OscPrimitives` provider:

- Start: command `0`; set parameter `9` (eight measure bytes), `10` (four forward
  bytes), `6` (four voltage bytes), `8` (one measure-mode byte); command `2`.
- Drain: `DstiOscReadBuffer` with capacity `0x1068`. Actual returned bytes,
  timestamp and remaining-buffer count drive acquisition. Each sample is four
  bytes. The native sampling table, fractional carries and 32-bit rollover are
  preserved with integer arithmetic.
- Stop: commands `3`, `11`; parameter `10` with the four measure-time bytes;
  clear the forward ring and timing state; drain the final data; command `1`.
  The final capture contains the native replacement ring, rather than a merge
  of forward and final samples.

`DstiOscDriver` binds the actual named driver extensions `DstiOscCommand`,
`DstiOscSetParameter`, `DstiOscGetParameter`, `DstiOscReadBuffer`. Its exchange
receives a typed `OscDriverCall` and an absolute deadline. Returned statuses
must be DWORD integers; parameter reads return `OscParameter`, and sample reads
return `OscRead(status, data, timestamp, opaque, remaining)`. An unavailable
module returns native `0x90020101`; an absent extension returns `0x90020102`.
There is no invented scope IOCTL number: the shipped forwarding chain resolves
these names in a separately supplied driver. No concrete external DST-i driver
implementation was present among the inspected extracted DLLs.

Acquisition is bounded by total read count, retained packet count, deadlines
and cancellation. The injected transport must honor the deadline while blocked.
Malformed byte counts are rejected before sample decoding. Release command `1`
gets one separately bounded attempt even after cancellation; an existing
acquisition failure remains the primary error. Native command/parameter/read
failures retain error words `0x907F/0x917F/0x937F` and notifications
`0xE2001000/0xE2001001/0xE2001003`, including the failed selector.
These host resource limits and malformed-input checks replace unsafe native
memory access and indefinite acquisition; they do not model hardware behavior.

`runtime.capture()` returns the shared `NativeRecorderCapture`. Its packet
bytes use the ordinary timestamp-plus-four-byte frame grammar.
`plan.monitor_buffer(...)` preserves selected signal metadata and explicit
language encoding; `capture.monitor_buffer(...)` produces the shared DM ring
for existing snapshot playback. `runtime.report()` is JSON-compatible and keeps
provenance and `PHYSICAL_UNCONFIRMED` explicit.

Static reconciliation covered all 42 relevant exports in original 12/18
DataListIF, including the concrete normal and Dual implementations. Dual object
layout offsets differ between versions; logging source-line constants also
change. Generic DiagInterface setters are false stubs and are not used as
samplers. No OEM code, physical adapter or vehicle was executed for this work.

Clock observations and explicit absolute deadlines must be finite. Invalid clock
values stop acquisition before another driver call; cleanup uses the same check
and preserves an already recorded native fault.

The combined timestamped-receive wrapper uses a zero capacity sentinel for
`DstiOscReadBuffer`, backed by the native 0x41a0-byte allocation. This sentinel
does not relax `DstiOscGetParameter` output limits.

Run the authored positive, malformed, failure, cancellation, rollover, selected
metadata, named-driver and playback checks with:

```sh
python -m unittest discover -s tests -p test_monitor_instruments.py -v
```
