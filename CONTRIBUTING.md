# Contributing

Small, reproducible changes are welcome. Start with the [architecture](docs/architecture.md) and [feature matrix](docs/full-port.md). For a new protocol claim, include the evidence boundary: synthetic test, static observation, bench test, or vehicle test.

## Local checks

Use Python 3.11 or newer. The core test suite uses `unittest` and the standard library; it needs no GTK, USB adapter, network access or manufacturer databases.

```sh
python -m unittest discover -s tests -v
ruff check scripts tests techstream.py
ruff format --check scripts tests techstream.py
shellcheck techstream
```

Install the desktop dependencies from [Getting started](docs/getting-started.md) for GUI changes, then run `./techstream --demo --smoke-test` and inspect the actual window. For a headless check, use `sh scripts/desktop-smoke.sh`, also used by CI. Keep fixtures synthetic and tests runnable from a clean checkout.

## Pull requests

Explain the concrete problem, resulting behavior and checks performed. Keep unrelated cleanup separate. Preserve parser bounds, response correlation, cancellation, cleanup and validation at file/USB boundaries. Do not claim hardware support from a mock or static code analysis. Unknown behavior stays explicitly unknown.

Do not submit proprietary installers, extracted databases, original manuals, keys, activation code or copied vendor source. A citation or a short description of an observed format is preferable to redistributing the underlying material. Contributions must be material you have the right to publish under the project license.

Before attaching a trace, remove VINs, serial numbers, personal paths, account identifiers, tokens and customer information. Prefer a minimal synthetic reproducer. See [Security](SECURITY.md) for private reporting and [hardware validation](docs/hardware-validation.md) for evidence requirements. Never make CI access a vehicle or perform writes to a real ECU.
