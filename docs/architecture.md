# Architecture

The project separates a native GTK workbench, resource decoders and offline transport/diagnostic code. Core modules use the Python standard library. GTK, libusb and optional OpenSSL libcrypto are system runtime dependencies for the corresponding desktop and USB paths.

```mermaid
flowchart TD
    Demo[Synthetic demo resources] --> Catalog[CT / DDB resource readers]
    Local[User-supplied local resources] --> Catalog
    Catalog --> UI[GTK4 / libadwaita workbench]
    Catalog --> Conversion[Signal conversion]
    Fixture[Synthetic diagnostic session] --> Replay[Replay transport]
    Replay --> Diagnostics[Diagnostic session / response decoding]
    Diagnostics --> Report[JSON report]
    Diagnostics --> UI
    Diagnostics --> Chart[Selectable sample chart]
    Chart --> UI
    USB[System libusb] --> JLR[JLR identity / channel codecs]
    JLR --> ISO[Raw CAN + host ISO-TP exchange]
    ISO --> Diagnostics
```

The diagram shows implemented modules and data paths, not a claim that every path is wired into a complete live diagnostic engine.

## Entry points

| File/module | Responsibility |
| --- | --- |
| `techstream` | Launch Python in an isolated Linux network namespace |
| `techstream.py` | Desktop presentation, background loading, selection and export |
| `scripts.demo` | Generate authored synthetic resources for a clean checkout |
| `scripts.session_cli` | Run offline diagnostic replay and write a report |
| `scripts.workbench` | Catalog search, local favorites, CSV and passive USB inventory |
| `scripts.pid_catalog` | Parse CT parameter groups |
| `scripts.diagnostic_db` | Decode DDB containers and diagnostic definitions |
| `scripts.signal_conversion` | Bounded bit extraction and numeric conversion |
| `scripts.mongoose_protocol` | Frame encoding/decoding and protocol inspection |
| `scripts.jlr`, `scripts.jlr_channels` | JLR USB lifecycle, identity and channel message structures |
| `scripts.isotp` | Host-side ISO-TP sender/receiver state machines |
| `scripts.diagnostics`, `scripts.replay` | Diagnostic response interpretation and deterministic replay |
| `scripts.script_vm` | CSDF objects/operators, bounded execution and optional SRP/SRPLST inspection |

## Evidence boundaries

Resource formats are recovered from local static research and checked against synthetic regression cases. Supported subsets and unresolved fields are described in [DDB](ddb-format.md), [conversion](signal-conversion.md), [Mongoose framing](mongoose-protocol.md), [JLR](jlr-native.md), [channels](jlr-channels.md) and [script runtime](script-vm.md).

Replay makes request/response behavior deterministic and testable without a device. Mock USB tests exercise failure paths and cleanup. Neither proves that a particular adapter implements those messages correctly or that an ECU accepts them. Physical validation remains `PHYSICAL_UNCONFIRMED`; see the [validation plan](hardware-validation.md).

The desktop browses resources and replays diagnostic records. Reference rows remain separate from decoded recording values; neither is presented as a live vehicle measurement. A complete diagnostic engine still needs validated vehicle selection, ECU sessions, polling, support gating, cancellation and hardware testing. Active tests, customization and programming require additional evidence and safety behavior; see the [feature matrix](full-port.md).

## Data and trust boundaries

Manufacturer resources are external inputs, never bundled dependencies. Parsers validate structure and bounds before exposing decoded values. Favorites and exports are local user data, separate from the source tree. Protocol code must reject truncated/mismatched responses and preserve cleanup on cancellation and errors.

The public tree contains authored code and synthetic fixtures only. Private research artifacts, extracted manuals and original distributions are excluded. CI runs from that public tree without downloading or executing manufacturer binaries.

Some format notes retain identifiers of private `analysis/evidence` archives. Those archives and original binaries are deliberately absent from the public checkout; public evidence includes binary hashes, function addresses, recovered contracts and authored regression cases.
