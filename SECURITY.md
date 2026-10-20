# Security and sensitive data

This is experimental diagnostic software. Malformed input handling, path traversal, unintended network access, unsafe device commands and leakage of vehicle/customer information are security concerns.

## Report privately

Use the repository's **Security → Report a vulnerability** feature if available. If private reporting is unavailable, open a minimal public issue requesting a private reporting channel without exploit details, traces or sensitive data. Do not publish working exploits or private vehicle logs in an ordinary issue.

Include the affected commit, platform, minimal reproduction and expected/actual behavior. Prefer synthetic input. Remove VINs, adapter serial numbers, personal paths, accounts, tokens and customer data. Keep an unredacted original privately if necessary to investigate; do not upload it by default.

Only the latest default-branch code is maintained; no release-specific security support is promised. Reports are reviewed on a best-effort basis without a guaranteed response time.

## Boundaries

The launcher isolates external networking using a Linux network namespace. A direct Python launch does not provide that isolation. USB access still reaches local hardware. Offline replay cannot establish safe behavior on a vehicle, and the current implementation does not establish physical compatibility. Follow the [hardware validation plan](docs/hardware-validation.md) before conducting hardware research.

Favorites are stored under `$XDG_DATA_HOME/techstream/saved.json`, defaulting to `~/.local/share/techstream/saved.json`. Exported CSV and session reports are ordinary local files: review their contents before sharing them. Third-party resource files remain outside the public repository.
