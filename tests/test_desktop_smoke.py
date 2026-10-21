import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class DesktopSmokeTests(unittest.TestCase):
    def test_isolates_desktop_and_cleans_up_on_success_and_failure(self):
        root = Path(__file__).resolve().parents[1]
        for status in (0, 7):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                launcher = directory / "xvfb-run"
                launcher.write_text(
                    "#!/bin/sh\n"
                    'test "$GDK_BACKEND" = x11 || exit 91\n'
                    'test -z "${WAYLAND_DISPLAY+x}" || exit 92\n'
                    'test -z "${XDG_CURRENT_DESKTOP+x}" || exit 93\n'
                    'test "$XDG_RUNTIME_DIR" != /run/user/1000 || exit 94\n'
                    'test "$(stat -c %a "$XDG_RUNTIME_DIR")" = 700 || exit 95\n'
                    'grep -qx "default=gtk" "$XDG_CONFIG_HOME/xdg-desktop-portal/portals.conf" || exit 96\n'
                    'printf "%s\\n" "$XDG_RUNTIME_DIR" > "$SMOKE_RECORD"\n'
                    'printf "%s\\n" "$@" >> "$SMOKE_RECORD"\n'
                    'exit "$SMOKE_STATUS"\n'
                )
                launcher.chmod(0o700)
                record = directory / "record"
                result = subprocess.run(
                    ["sh", str(root / "scripts/desktop-smoke.sh")],
                    env={
                        **os.environ,
                        "PATH": f"{directory}:{os.environ['PATH']}",
                        "XDG_RUNTIME_DIR": "/run/user/1000",
                        "WAYLAND_DISPLAY": "wayland-1",
                        "XDG_CURRENT_DESKTOP": "Hyprland",
                        "SMOKE_RECORD": str(record),
                        "SMOKE_STATUS": str(status),
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                runtime, *arguments = record.read_text().splitlines()
                self.assertFalse(Path(runtime).exists())
                self.assertEqual(
                    arguments,
                    [
                        "-a",
                        "dbus-run-session",
                        "--",
                        "python3",
                        str(root / "techstream.py"),
                        "--demo",
                        "--smoke-test",
                    ],
                )
