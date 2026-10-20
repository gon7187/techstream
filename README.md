# Techstream for Linux

[![Checks](https://github.com/gon7187/techstream/actions/workflows/ci.yml/badge.svg)](https://github.com/gon7187/techstream/actions/workflows/ci.yml)

[Русский](README.ru.md) · [Getting started](docs/getting-started.md) · [Contributing](CONTRIBUTING.md)

An independent native Linux diagnostic workbench for Toyota/Lexus research, written in Python with GTK4 and libadwaita. Browse local parameter resources, inspect diagnostic definitions, and replay a synthetic diagnostic session without Windows, Wine, an adapter, or a car.

**This is an early implementation, not a complete replacement for Toyota Techstream. All physical vehicle communication remains `PHYSICAL_UNCONFIRMED`.** The desktop interface is currently in Russian.

![Native GTK workbench using synthetic demo data](docs/images/workbench.png)

## Try it

The core tools use Python 3.11+ and the standard library. No manufacturer data is required:

```sh
git clone https://github.com/gon7187/techstream.git
cd techstream
python -m scripts.session_cli replay examples/diagnostic-session.json --output /tmp/session.json
python -m unittest discover -s tests -v
```

For the desktop, install the system GTK dependencies described in [Getting started](docs/getting-started.md), then run:

```sh
./techstream --demo
```

The demo generates authored synthetic resources. Its codes, names and values are examples, not diagnostic advice or observations from a vehicle. The launcher uses a separate Linux network namespace; it does not change the host firewall. Systems that disable unprivileged user namespaces need the [documented direct launch](docs/getting-started.md#network-isolation).

## What works

| Area | Available now | Boundary |
| --- | --- | --- |
| Desktop workbench | Search groups/parameters, regions, favorites, CSV export, source hashes | Local resource browsing; no live vehicle values |
| Diagnostic resources | CT parameter groups, DDB systems/DTC/freeze-frame definitions, numeric conversion | Supported recovered formats; data supplied separately |
| Offline diagnostics | Strict replay, 15 numeric PIDs, DTC/VIN/readiness/freeze, CALID/CVN, selectable charts and JSON reports | Replay proves software behavior, not ECU compatibility |
| Transport | Mongoose framing, JLR identity/version support, ISO-TP, continuous raw CAN lifecycle and connected exchange pump | Tested with synthetic/mocked traffic; physical behavior unconfirmed |
| Script runtime | CSDF stack/operators/control flow, SRP XML/SRPLST inspection | Partial; no general utility/customization parity |
| Vehicle operations | Planned research | No validated health check, active tests, coding, calibration flashing or recovery |

Toyota-specific byte codecs are separately documented in [native command recovery](docs/toyota-protocol.md); they do not infer vehicle support.

See the [feature matrix](docs/full-port.md), [architecture](docs/architecture.md), [offline session format](docs/offline-diagnostics.md) and [hardware validation plan](docs/hardware-validation.md). Adapter branding or a USB ID does not establish Toyota compatibility.

## Bring your own data

The public repository contains authored source, documentation and synthetic fixtures. It does **not** distribute Toyota/Lexus software, original manuals, installers, drivers, license keys, activation tools, or extracted manufacturer databases. Obtain any required data separately with the necessary rights; see [local resource import](docs/getting-started.md#local-resource-import).

The [MIT license](LICENSE) covers the project's authored material. It grants no rights to third-party products or data. This project is independent and is not affiliated with or endorsed by Toyota, Lexus, or adapter manufacturers. Product names belong to their respective owners.

## Development

```sh
python -m unittest discover -s tests -v
ruff check scripts tests techstream.py
ruff format --check scripts tests techstream.py
shellcheck techstream
```

CI runs the core checks without proprietary resources and exercises the demo GUI under Xvfb. Contributions should preserve strict parsing, bounded I/O, offline reproducibility and honest evidence boundaries. Read [Contributing](CONTRIBUTING.md) and [Security](SECURITY.md) before sharing logs or hardware traces.

![Selectable parameter chart decoded from an authored recording](docs/images/parameter-chart.png)
