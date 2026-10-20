# Original executable selected-driver channel

`scripts.cuw_legacy_channel` implements original12 and18 selected-driver admission,
symbol resolution, native marker/version classification, mode checking, device and
channel acquisition, SIL filters, disconnect, reconnect and saved-state import.
It reads the explicitly attached executable as data; it never executes a PE.
The original executable SHA is checked by `ExecutableImage` before connect or
reconnect can perform I/O. The wrapper in `cuw_legacy_engine` is the family entry.

Supply `observations['legacy_selected_driver']` as the actually selected driver
path and `observations['legacy_channel_state']` as a `ChannelState`. Fresh state
uses source constructor fields. `restore_state(build, saved, io,
driver_loaded=...)` reads the distinct native12/18 copied records, preserving
actual timeouts, padding, flags, filter count, active filters and symbol addresses.
The copied symbol addresses remain data and are never executed. Restoring a live
handle requires that exact handle already be owned by the same `ExecutableIO`.
A saved state cannot manufacture a current connection.

`connect` performs the original connection path without a preceding disconnect.
`disconnect` stops active SIL filters before disconnecting the channel, closing the
device and unloading the selected driver. It retains the shim library for reuse.
`reconnect` swallows the admitted native exception domain from Disconnect
before connecting, as the original controller does. This includes CJ2534, CPassThru
and foreign native exceptions. Host errors, cancellation and malformed host data
escape with their original identity. Connect exceptions propagate to the distinct
consumer-owned typed CJ2534 retry scope. `close` also releases the shim and any retired owned resources.

The host runtime owns each acquisition before checking cancellation/deadlines.
An ignored native Disconnect/Close driver status clears the corresponding native
active fields while retaining the failed resource in a separate host ownership
list. Failed filter stops remain checked exceptions. Reconnection following one
of these failures retains overwritten resources for eventual host cleanup.
Failed cleanup is never reported as successful cleanup.

The neutral primitive provider supplies individual operations:

- `load_library(path)` returns a DWORD handle; `get_symbol(library, symbol)` returns
  a DWORD address or zero; `free_library(library)` returns `None`.
- `call_symbol(symbol, args)` returns a DWORD. Only a symbol resolved from the
  original image's marker name can reach this operation; arguments are generated
  by the recovered marker sequence.
- `passthru_load_library(path, version)` and
  `passthru_unload_library(version)` return `None`.
- `passthru_open(name, version)` returns the actual device DWORD;
  `passthru_close(device)` returns `None`.
- `passthru_connect(device, protocol, flags, baud, version)` returns the actual
  channel DWORD; `passthru_disconnect(channel)` returns `None`. The alternate18
  branch additionally supplies `physical_channel_count` and `logical_channels`,
  reads its own image data, scans devices and performs its own IOCTL chronology.
  Its Open name concatenates the admitted image string at VA `0x5F2DD9`
  (`J2534-2:` in original18) with the enumerated device name. The same shared
  Open path serves classification, Connect, mode queries and reconnect;
  original12 and common18 keep their native NULL Open name.
- `passthru_scan_for_devices()` returns the device count;
  `passthru_get_next_device()` returns its native name;
  `passthru_read_version(device)` returns `(firmware, dll, api)` strings.
- `start_filter(channel, filter_type, mask, pattern, flow_control)` returns the
  filter DWORD; `stop_filter(filter_id)` returns `None`. Messages are typed
  `NativeMessage` DTOs; the original lifecycle generates their content.
- `ioctl(identifier, ioctl_id, input, output)` supplies the actual native output
  record. The mode query returns its six DWORDs. Other initialization IOCTLs are
  void. The provider does not decide reconnect, mode or programming success.

Driver failures use `NativeTransportError` or `ExecutableJ2534Error`, with raw
DWORD status retained. Host validation, timeouts and cancellation retain their
own types. Required export absence and failed library admission fail explicitly.
Only standard platform export names are embedded. Driver-identification strings,
shim names, baud tables and alternate channel data are read from the admitted
owner-supplied image using source virtual addresses.

Source anchors:18 RVAs `6d388`, `6d698`, `6ddf0`, `6e450`, `6e678`, `6e870`,
`706ac`, `70774`, `7091c`, `70954`, `70ab4`, `713c8`, `71440`, `715f8`, `71638`,
`717c4`;12 RVAs `46248`, `46974`, `46b74`, `47c88`, `48738`, `48798`, `48944`,
`48b10`. Original identities are the exact SHA allowlist in
`cuw_legacy_engine.LEGACY_EXECUTABLE_SHA256`; no cross-build fallback is admitted.

Run `python -m unittest discover -s tests -p test_cuw_legacy_channel.py -v`
for the 26 portable authored checks; they require no original files and skip none.
The three exact-original composition checks live separately in the private
`runtime/no-car-91/legacy_channel_corpus.py` runner. Set both `LEGACY_CUW12` and
`LEGACY_CUW18` to the owner's original executable files, then run
`python -m unittest discover -s runtime/no-car-91 -p legacy_channel_corpus.py -v`.
Missing corpus paths fail explicitly. Original bytes are read as data only and
never copied into the public test tree. Authored checks do not claim OEM
execution equivalence. Physical adapter behavior remains `PHYSICAL_UNCONFIRMED`.

`set_mode` runs the resolved marker's two-call sequence. `get_mode` selects the
native kind-specific query, including the original marker query's close/open/
close/interface chronology and explicit native open flag with DeviceID zero.
`ChannelState.driver_kind` retains only the classification computed from the
marker/version probe. It is **not** the separate selected-driver record's native
field at offset `10`; no delay or adapter capability is inferred from it.

`select_library(context, native_strings)` implements that separate selected
`CJ2534Device` record. It copies the four actual native strings (ABI offsets
`0`, `4`, `8`, `0c`) and runs the original name setter/classifier to compute its
`+10` enum. The source constructor initializes enum `2`; classification chooses
`0` for the first source substring, otherwise `1` for the second, otherwise `2`.
The substrings come from the admitted image, with native case-sensitive order.
The immutable `SelectedLibraryBase` is retained on `ChannelState` across
Disconnect/reconnect and supplies the actual selected library string at `+8`
to Connect and mode operations. Existing path-only providers retain their
compatibility input but cannot manufacture this record's delay predicate.

`selected_driver_delay(context)` reads exactly `+10 == 1`, validates it against
the source name producer and rejects an unbound or corrupt record. The SIL
consumer must additionally check the selected CPUType against source value `9`
before its 20 ms pause. The raw strings must come from the actual selected
record; registry/UI discovery and the user's selection are separate inputs.
No Boolean observation, marker/version `driver_kind`, or CUW2026 flag900 is used.
Static ctor/setter/classifier/copy/getter/consumer instruction proofs for both
builds are recorded in `selected-library-source.json` and `selected-library12.asm`
/ `selected-library18.asm`. This narrow ABI binding does not claim to implement
registry enumeration or UI selection.

NULL `LoadLibrary` is not an acquired resource. Its narrow acquisition helper
reads the shared runtime resource count for preflight and uses its public action,
check, ownership and cleanup interfaces; it never mutates the resource list.
J2534 device/channel/filter DWORD zero remains a valid handle.

The resumed no-car91 check records the alternate18 name counterexample before
repair in `analysis/evidence/no-car-91/prefix-red.log`; the corrected authored
and original-input checks originally passed together in `unittest.log`
(24 tests). They now run separately: `portable-unittest.log` records 26 checks
without corpus inputs, and `private-corpus-unittest.log` records all three
original-dependent checks with both exact images. Neither suite skips checks;
`private-corpus-absent.log` verifies that absent originals fail explicitly.
The actual-image vectors enter
through `cuw_legacy_engine.executable_reconnect`, then exercise ordinary and
alternate Open/Connect/Disconnect/Close, marker modes, DLL-version modes,
reconnect and missing-export rollback. Authored fault vectors cover both
alternate enumerations and both alternate Opens, empty scans and malformed
names before Open. `source-bindings.json` binds 4088 original12 and 7811
original18 disassembled instruction bytes to the admitted input images,
including the 319-byte alternate18 Open body. These are static reads and
neutral-provider calls, not execution of the original binaries.

The native Disconnect catch regression is recorded before repair in
`native-catch-red.log`. Its current portable vectors drive actual StopFilter
failures through `executable_reconnect` for CPassThru and foreign native errors;
separate host OSError/ValueError/InterruptedError/KeyboardInterrupt vectors
verify identity and absence of a following Connect. Connect native errors retain
their original identity. `native-catch-source.json` binds both original12/18
native exception scopes. `driver-record-red.log` records the missing selected
record producer before its implementation; current vectors verify classifier
precedence, case sensitivity, missing-source rejection, selected-path use and
record retention across two reconnects for both builds.
