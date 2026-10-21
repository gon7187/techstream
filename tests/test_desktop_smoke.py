import os
import subprocess
import tempfile
import unittest
from pathlib import Path

VARIANTS = (
    (
        "normal",
        ["-s", "-screen 0 1600x1200x24"],
        ["--demo", "--smoke-test"],
    ),
    (
        "compact",
        ["-s", "-screen 0 1024x768x24"],
        ["--demo", "--smoke-test", "--smoke-compact"],
    ),
)


class DesktopSmokeTests(unittest.TestCase):
    def launcher(self, directory, status):
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
        return launcher

    def test_isolates_desktop_and_cleans_up_on_success_and_failure(self):
        root = Path(__file__).resolve().parents[1]
        for variant, screen, application in VARIANTS:
            for status in (0, 7):
                with (
                    self.subTest(variant=variant, status=status),
                    tempfile.TemporaryDirectory() as temp,
                ):
                    directory = Path(temp)
                    self.launcher(directory, status)
                    record = directory / "record"
                    result = subprocess.run(
                        ["sh", str(root / "scripts/desktop-smoke.sh"), variant],
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
                            *screen,
                            "dbus-run-session",
                            "--",
                            "python3",
                            str(root / "techstream.py"),
                            *application,
                        ],
                    )

    def test_unknown_variant_is_rejected_without_touching_the_desktop(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            ["sh", str(root / "scripts/desktop-smoke.sh"), "wide"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
