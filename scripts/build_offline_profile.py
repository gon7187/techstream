#!/usr/bin/env python3
"""Build an isolated Techstream configuration profile; this is not a network sandbox."""

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import tempfile
import urllib.parse
from pathlib import Path

CONFIG_SUFFIXES = {".ini", ".xml", ".config"}
MANIFEST = "offline-profile-manifest.json"
AUTHORITY = re.compile(r'https?://([^/\s?#<>"\']+)', re.IGNORECASE)
FLAG = re.compile(
    r"^([ \t]*TISFunction[ \t]*=[ \t]*)([01])([ \t]*(?:;[^\r\n]*)?)(\r?\n)?$"
)


def decode_config(raw: bytes) -> tuple[str, str, bool]:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        codec = "utf-16-le" if raw.startswith(b"\xff\xfe") else "utf-16-be"
        return raw.decode(codec), codec, False
    for encoded in (False, True):
        candidate = bytes(value ^ 255 for value in raw) if encoded else raw
        if candidate.lstrip().startswith((b"[", b";", b"<")) and b"\0" not in candidate:
            # Latin-1 is a reversible byte mapping: untouched legacy text stays exact.
            return candidate.decode("latin-1"), "latin-1", encoded
    raise ValueError("Unsupported configuration encoding")


def is_loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def replace_authority(match: re.Match[str]) -> str:
    authority = match.group(1)
    parsed = urllib.parse.urlsplit("http://" + authority)
    if parsed.username is not None or not parsed.hostname:
        raise ValueError(f"Ambiguous URL authority: {authority!r}")
    port = parsed.port
    if is_loopback(parsed.hostname):
        return match.group()
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", parsed.hostname):
        raise ValueError(f"Unsupported URL host: {authority!r}")
    return (
        match.group()[: match.group().index("://") + 3]
        + "127.0.0.1"
        + (f":{port}" if port is not None else "")
    )


def transform(raw: bytes, system: bool) -> tuple[bytes, list[dict], int]:
    text, codec, encoded = decode_config(raw)
    section = ""
    fields = []
    result = []
    flags = 0
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        stripped = line.strip().lstrip("\ufeff")
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
        replacement = AUTHORITY.sub(replace_authority, line)
        if (
            system
            and section == "AvailableFunction"
            and (match := FLAG.fullmatch(line))
        ):
            flags += 1
            replacement = match.group(1) + "0" + match.group(3) + (match.group(4) or "")
        if replacement != line:
            fields.append(
                {
                    "line": number,
                    "section": section,
                    "key": stripped.split("=", 1)[0] if "=" in stripped else None,
                    "before": line.rstrip("\r\n"),
                    "after": replacement.rstrip("\r\n"),
                }
            )
        result.append(replacement)
    changed = "".join(result)
    # Re-run the same destination classifier: every literal authority must be loopback.
    for match in AUTHORITY.finditer(changed):
        if not is_loopback(urllib.parse.urlsplit("http://" + match.group(1)).hostname):
            raise ValueError("External HTTP(S) destination remains")
    output = changed.encode(codec)
    if encoded:
        output = bytes(value ^ 255 for value in output)
    return output, fields, flags


def publish(stage: Path, output: Path) -> None:
    # Linux RENAME_NOREPLACE keeps a concurrently created destination intact.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(output), 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(output))


def build_profile(source: Path, output: Path) -> dict:
    source, output = source.absolute(), output.absolute()
    for path in (source, output):
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError(f"Symlink path is unsupported: {path}")
    source, output = source.resolve(), output.resolve()
    if (
        not source.is_dir()
        or output.exists()
        or output.is_relative_to(source)
        or not output.parent.is_dir()
    ):
        raise ValueError(
            "Input must be a directory; output must be new, outside input, with an existing parent"
        )
    paths = sorted(source.rglob("*"))
    for path in paths:
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f"Unsupported nonregular input: {path}")
    if (source / MANIFEST).exists():
        raise ValueError(f"Reserved manifest name already exists: {MANIFEST}")
    patches = {}
    files = []
    flags = configs = 0
    for path in paths:
        if path.is_file() and path.suffix.lower() in CONFIG_SUFFIXES:
            configs += 1
            raw = path.read_bytes()
            result, fields, count = transform(raw, path.name.lower() == "it3system.ini")
            flags += count
            if result != raw:
                relative = path.relative_to(source)
                patches[relative] = result
                files.append(
                    {
                        "path": relative.as_posix(),
                        "original_sha256": hashlib.sha256(raw).hexdigest(),
                        "result_sha256": hashlib.sha256(result).hexdigest(),
                        "fields": fields,
                    }
                )
    if flags != 1:
        raise ValueError(
            f"Expected exactly one AvailableFunction/TISFunction flag, found {flags}"
        )
    manifest = {
        "source": str(source),
        "changed_files": files,
        "verification": {
            "config_files": configs,
            "direct_external_http_destinations": 0,
            "tis_function": 0,
        },
        "limitations": [
            "Configuration profile only; does not block network access or establish native/offline application operation.",
            "Percent-encoded nested URL query parameters are preserved without decoding.",
            "Only .ini, .xml and .config files are scanned; executable and other embedded endpoints remain unchanged.",
        ],
    }
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        shutil.copytree(source, stage, dirs_exist_ok=True, symlinks=True)
        if any(path.is_symlink() for path in stage.rglob("*")):
            raise ValueError("Input symlink appeared during copy")
        for relative, data in patches.items():
            (stage / relative).write_bytes(data)
        (stage / MANIFEST).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        verified_configs = verified_flags = 0
        for path in stage.rglob("*"):
            if path.is_file() and path.suffix.lower() in CONFIG_SUFFIXES:
                raw = path.read_bytes()
                result, _, count = transform(raw, path.name.lower() == "it3system.ini")
                if raw != result:
                    raise ValueError(
                        f"Staged configuration verification failed: {path}"
                    )
                verified_configs += 1
                verified_flags += count
        if (verified_configs, verified_flags) != (configs, 1):
            raise ValueError("Staged configuration inventory changed")
        for row in files:
            if (
                hashlib.sha256((stage / row["path"]).read_bytes()).hexdigest()
                != row["result_sha256"]
            ):
                raise ValueError("Staged configuration digest mismatch")
        publish(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        manifest = build_profile(args.source, args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    print(
        f"Built profile: {args.output}; {len(manifest['changed_files'])} changed configuration files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
