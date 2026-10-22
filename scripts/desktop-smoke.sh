#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
variant=${1:-normal}
case "$variant" in
normal)
  screen="-screen 0 1600x1200x24"
  ;;
compact)
  screen="-screen 0 1024x768x24"
  ;;
*)
  echo "usage: desktop-smoke.sh [normal|compact]" >&2
  exit 2
  ;;
esac

smoke_dir=$(mktemp -d "${TMPDIR:-/tmp}/techstream-desktop-XXXXXX")
trap 'rm -rf -- "$smoke_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A private bus must not share the desktop's Wayland socket or portal mounts.
export XDG_RUNTIME_DIR="$smoke_dir/runtime"
export XDG_CONFIG_HOME="$smoke_dir/config"
export XDG_CACHE_HOME="$smoke_dir/cache"
export XDG_DATA_HOME="$smoke_dir/data"
mkdir -m 700 "$XDG_RUNTIME_DIR"
mkdir -p "$XDG_CONFIG_HOME/xdg-desktop-portal"
printf '[preferred]\ndefault=gtk\n' > "$XDG_CONFIG_HOME/xdg-desktop-portal/portals.conf"
unset WAYLAND_DISPLAY XDG_CURRENT_DESKTOP DESKTOP_SESSION
unset DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE
export XDG_SESSION_TYPE=x11 GDK_BACKEND=x11
export GSK_RENDERER=cairo GTK_A11Y=none GIO_USE_VFS=local

set -- --demo --smoke-test
if [ "$variant" = compact ]; then
  set -- "$@" --smoke-compact
fi

xvfb-run -a -s "$screen" dbus-run-session -- python3 "$root/techstream.py" "$@"
