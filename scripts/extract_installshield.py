#!/usr/bin/env python3
"""Statically extract supported InstallShield PE overlay records; never execute input.

Format reference: https://github.com/hifi/iss_extract/blob/master/iss_extract.c
Unicode counted records and certificate boundaries verified against local installers.
"""

import argparse
import hashlib
import json
import mmap
import os
import re
import struct
import sys
import tempfile
from pathlib import Path, PureWindowsPath


def pe_bounds(data: mmap.mmap) -> tuple[int, int, dict[str, int] | None]:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("Unsupported format: missing DOS header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("Unsupported format: missing PE header")
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    sections = optional + optional_size
    if not 1 <= count <= 96 or sections + count * 40 > len(data) or optional_size < 2:
        raise ValueError("Invalid or truncated PE section table")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("Unsupported PE optional header")
    directory = optional + (96 if magic == 0x10B else 112)
    if directory + 40 > sections:
        raise ValueError("Truncated PE data directories")
    end = sections + count * 40
    for index in range(count):
        size, offset = struct.unpack_from("<II", data, sections + index * 40 + 16)
        if size:
            if offset < sections + count * 40 or offset + size > len(data):
                raise ValueError("Invalid PE section extent")
            end = max(end, offset + size)
    certificate = None
    limit = len(data)
    directories = struct.unpack_from("<I", data, directory - 4)[0]
    if directories > 4:
        offset, size = struct.unpack_from("<II", data, directory + 32)
        if offset or size:
            if offset < end or offset % 8 or size < 8 or offset + size != len(data):
                raise ValueError("Invalid or unsupported PE certificate extent")
            length, revision, kind = struct.unpack_from("<IHH", data, offset)
            if not 8 <= length <= size or revision != 0x200 or kind != 2:
                raise ValueError("Unsupported PE certificate table")
            certificate = {"offset": offset, "size": size}
            limit = offset
    if end >= limit:
        raise ValueError("Unsupported format: no InstallShield overlay")
    return end, limit, certificate


def safe_path(value: str) -> Path:
    path = PureWindowsPath(value)
    if (
        not value
        or path.is_absolute()
        or path.drive
        or path.root
        or any(
            part in (".", "..") or ":" in part
            for part in value.replace("\\", "/").split("/")
        )
    ):
        raise ValueError(f"Unsafe member path: {value!r}")
    return Path(*path.parts)


def records(data: mmap.mmap, start: int, end: int) -> tuple[str, list[dict]]:
    position = start
    count = struct.unpack_from("<I", data, position)[0] if end - start >= 4 else 0
    wide = 1 <= count <= 10000
    if wide:
        position += 4
    width = 2 if wide else 1
    members: list[dict] = []
    seen: set[Path] = set()
    while position < end:
        if end - position <= 7 and data[position:end] == bytes(end - position):
            position = end
            break
        if wide and len(members) >= count:
            raise ValueError("Unexpected bytes after counted InstallShield records")
        values = []
        for _ in range(4):
            raw = bytearray()
            for _ in range(8192):
                if position + width > end:
                    raise ValueError("Truncated InstallShield metadata")
                unit = data[position : position + width]
                position += width
                if unit == bytes(width):
                    break
                raw.extend(unit)
            else:
                raise ValueError("InstallShield metadata string too long")
            value = raw.decode("utf-16-le" if wide else "ascii")
            if any(ord(character) < 32 for character in value):
                raise ValueError("Unsupported format: invalid metadata characters")
            values.append(value)
        name, path, version, length = values
        relative = safe_path(path)
        if not name or PureWindowsPath(name).name != name or relative.name != name:
            raise ValueError("Unsupported format: inconsistent member name and path")
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version) or not re.fullmatch(
            r"[0-9]{1,20}", length
        ):
            raise ValueError("Unsupported format: invalid version or length")
        size = int(length)
        if position + size > end:
            raise ValueError(f"Truncated member payload: {path}")
        if relative in seen or relative == Path("manifest.json"):
            raise ValueError(f"Duplicate or reserved member path: {path}")
        seen.add(relative)
        members.append(
            {
                "name": name,
                "path": path,
                "relative_path": relative.as_posix(),
                "version": version,
                "offset": position,
                "size": size,
            }
        )
        if len(members) > 10000:
            raise ValueError("Too many InstallShield records")
        position += size
    if not members or (wide and len(members) != count):
        raise ValueError("Unsupported or incomplete InstallShield record stream")
    return ("utf16-counted" if wide else "ascii"), members


def extract(source: Path, output: Path) -> dict:
    with source.open("rb") as handle:
        source_digest = hashlib.file_digest(handle, "sha256").hexdigest()
        if not source.stat().st_size:
            raise ValueError("Unsupported format: empty file")
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            start, end, certificate = pe_bounds(data)
            encoding, members = records(data, start, end)
            targets = [output / member["relative_path"] for member in members] + [
                output / "manifest.json"
            ]
            resolved_targets = {target.resolve() for target in targets}
            if len(resolved_targets) != len(targets) or any(
                parent in resolved_targets
                for target in resolved_targets
                for parent in target.parents
            ):
                raise ValueError("Conflicting file and directory member paths")
            for target in targets:
                if (
                    not target.resolve().is_relative_to(output.resolve())
                    or target.exists()
                    or target.is_symlink()
                    or any(
                        parent.exists() and not parent.is_dir()
                        for parent in target.parents
                    )
                ):
                    raise ValueError(
                        f"Output already exists or escapes destination: {target}"
                    )
            for member, target in zip(members, targets, strict=False):
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary: Path | None = None
                checksum = hashlib.sha256()
                try:
                    with tempfile.NamedTemporaryFile(
                        dir=target.parent, suffix=".partial", delete=False
                    ) as writer:
                        temporary = Path(writer.name)
                        for offset in range(
                            member["offset"],
                            member["offset"] + member["size"],
                            1024 * 1024,
                        ):
                            chunk = data[
                                offset : min(
                                    offset + 1024 * 1024,
                                    member["offset"] + member["size"],
                                )
                            ]
                            checksum.update(chunk)
                            writer.write(chunk)
                    os.link(temporary, target)
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
                member["sha256"] = checksum.hexdigest()
            manifest = {
                "source": str(source.resolve()),
                "source_sha256": source_digest,
                "overlay_offset": start,
                "overlay_end": end,
                "format": encoding,
                "certificate": certificate,
                "certificate_signature_verified": False,
                "members": members,
            }
            with (output / "manifest.json").open("x", encoding="utf-8") as writer:
                json.dump(manifest, writer, indent=2, ensure_ascii=False)
                writer.write("\n")
            return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        manifest = extract(args.source, args.output)
    except (OSError, ValueError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Extracted {len(manifest['members'])} members into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
