# Getting started

The console tools require Python 3.11+ and use the standard library. The desktop additionally requires Linux, PyGObject, GTK4 and **libadwaita 1.5+**. USB probing uses the system libusb-1.0 library through `ctypes`; no Python USB package is needed.

## Desktop dependencies

Arch Linux:

```sh
sudo pacman -S --needed python python-gobject gtk4 libadwaita libusb librsvg util-linux
```

Debian 13 / Ubuntu 24.04 or newer, with sufficiently recent libadwaita:

```sh
sudo apt install python3 python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 libusb-1.0-0 gir1.2-gdkpixbuf-2.0 librsvg2-common util-linux
```

Use the distribution's Python so it can import the distribution's `gi` bindings. A generic virtual environment may hide these bindings. Debian 12's default libadwaita is too old for the current interface.

## Synthetic demo

From the repository root:

```sh
./techstream --demo
```

No downloaded database is necessary. The demo uses synthetic resources and normal application features: group/parameter search, favorites, CSV export and diagnostic definitions. The interface is currently Russian.

Generate a reusable synthetic resource tree without opening GTK:

```sh
python -m scripts.demo --output /tmp/techstream-demo
```

The generator's output is test/demo data, not an OEM database. For a diagnostic replay with no desktop or hardware:

```sh
python -m scripts.session_cli replay examples/diagnostic-session.json --output /tmp/session.json
```

See [offline diagnostics](offline-diagnostics.md) for the session contract and interpretation of the report. Replay does not contact USB or a car.

## Local resource import

Obtain compatible resources separately with the necessary rights. The public checkout supplies no vendor data, installers, activation tools or keys. Do not commit imported material.

Keep an extracted application tree in a private local directory. The workbench recognizes regional parameter groups in this layout:

```text
application/
  Techstream_Data_NA/PIDGroup/.../*.CT
  Techstream_Data_EU/PIDGroup/.../*.CT
  Techstream_Data_JP/PIDGroup/.../*.CT
```

Run with the desired parameter root:

```sh
./techstream --root /path/to/application/Techstream_Data_NA/PIDGroup
```

The application can discover sibling regions. You can also choose a source directory with the folder button. A custom directory of CT groups is supported; diagnostic database discovery additionally needs the compatible application layout. Missing resources and unsupported formats do not imply a vehicle fault. Read [CT/resource behavior](native-linux.md) and [DDB format](ddb-format.md) for supported structures.

The public project does not automate acquiring licensed software. Importing data does not activate a diagnostic engine or enable live values.

## Network isolation

`./techstream` uses `unshare --user --map-current-user --net` before launching Python. This creates an isolated network namespace without changing host firewall rules. Some distributions or container policies disable unprivileged user namespaces; the command then fails before the application opens.

For a deliberate direct launch with no network namespace, use the system Python:

```sh
python3 techstream.py --demo
```

The application itself is an offline workbench, but the direct command does not enforce network isolation. Prefer the launcher where supported. Do not change global system security settings merely to run the demo.

## State and checks

Favorites live in `$XDG_DATA_HOME/techstream/saved.json`, or `~/.local/share/techstream/saved.json`. Source resources are separate from this state. CSV export writes the selected results to the destination you choose.

```sh
python -m unittest discover -s tests -v
./techstream --demo --smoke-test
```

The smoke test opens the GUI, exercises workbench behavior, and exits with a failing status if an assertion fails. For a headless Linux development environment with Xvfb and a D-Bus session launcher installed:

```sh
xvfb-run -a dbus-run-session -- python3 techstream.py --demo --smoke-test
```

This checks the rendered demo interface and synthetic data paths. It does not validate USB, an ECU or road use.

## Diagnostic session views

The desktop session page offers system overview, parameter charts and calibration identifiers. Each mode has an authored example and accepts compatible recordings. Choose the sample count for a polling recording. Charts use sample order, not an assumed original time scale. JSON export preserves decoded values and rejects overwriting the source recording.

```sh
python -m scripts.session_cli poll examples/live-session.json --samples 12 --output /tmp/live-report.json
python -m scripts.session_cli calibration examples/calibration-session.json --output /tmp/calibration-report.json
```

Without `--root`, a checkout without imported data opens synthetic demo resources automatically. Demo resources and favorites are temporary. Pass `--root /path/to/application` to use an existing local source tree.

SRP inspection optionally uses system OpenSSL `libcrypto` through `ctypes`; no vendor key or library is distributed. See [script formats](script-vm.md).
