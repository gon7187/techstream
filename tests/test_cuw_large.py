"""Authored sparse native-framed files; no OEM payload or vehicle required."""

import dataclasses
import hashlib
import os
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from scripts.cuw_large import (
    CHUNK_SIZE,
    MIN_SIZE,
    LargeSource2026,
    materialize_large_record_2026,
    native_large_cuw_2026,
    validate_large_container_2026,
    validate_large_materialization_2026,
    validate_large_record_2026,
)


def frame(header, data):
    return (
        struct.pack(">H", len(header))
        + header
        + struct.pack(">II", len(data), zlib.crc32(data))
        + data
    )


def srec(kind, address, data=b""):
    width = {0: 2, 1: 2, 2: 3, 3: 4, 9: 2}[kind]
    raw = address.to_bytes(width, "big") + data
    size = len(raw) + 1
    return (
        f"S{kind}{size:02X}".encode()
        + (raw + bytes(((255 - size - sum(raw)) & 255,))).hex().upper().encode()
        + b"\r\n"
    )


def fixture(path, version=500, protocol="02", text=None, metadata_override=None):
    metadata = f"[Format]\nVersion={version}\n[Vehicle]\nProtocol={protocol}\nNumberOfNode=1\n[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n[CPU11]\n".encode()
    if metadata_override is not None:
        metadata = metadata_override
    text = (
        text
        if text is not None
        else (
            srec(0, 0, b"HDR")
            + srec(1, 0x100, b"ab")
            + srec(3, 0x20000, b"cd")
            + srec(9, 0)
        )
    )
    prefix = bytearray(b"\0CALIBRATION\0\x0c" + bytes(4) + struct.pack(">I", MIN_SIZE))
    prefix += frame(b"INI", metadata) + b"\x02" + frame(b"SREC", text)
    payload_start = len(prefix) + 10
    size = MIN_SIZE - payload_start
    zeros = bytes(CHUNK_SIZE)
    crc = 0
    for offset in range(0, size, CHUNK_SIZE):
        crc = zlib.crc32(zeros[: min(CHUNK_SIZE, size - offset)], crc)
    prefix += struct.pack(">HII", 0, size, crc)
    with path.open("wb") as target:
        target.write(prefix)
        target.truncate(MIN_SIZE)
    crc = 0
    with path.open("rb") as source:
        source.seek(18)
        while chunk := source.read(CHUNK_SIZE):
            crc = zlib.crc32(chunk, crc)
    with path.open("r+b") as target:
        target.seek(14)
        target.write(struct.pack(">I", crc))
    return payload_start


class LargeCUWTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.path = Path(cls.directory.name) / "source.CuW"
        cls.payload_start = fixture(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_actual_sparse_positive_provenance_and_geometry(self):
        with native_large_cuw_2026(self.path) as container:
            self.assertEqual(container.format_version, 500)
            self.assertEqual(len(container.records), 2)
            with self.path.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            self.assertEqual(container.digest, digest)
            view = LargeSource2026(container)
            self.assertEqual(len(view), MIN_SIZE)
            self.assertEqual(view[0:13], b"\0CALIBRATION\0")
            with self.assertRaises(ValueError):
                view[0 : CHUNK_SIZE + 1]
            record = container.records[1]
            self.assertEqual(
                record.span, (self.payload_start, MIN_SIZE - self.payload_start)
            )
            self.assertEqual(len(record.descriptor), 0x144)
            self.assertEqual(
                struct.unpack_from("<II", record.descriptor, 0x108),
                (self.payload_start, MIN_SIZE - 1),
            )
            self.assertEqual(record.read(0, 3), b"\0\0\0")
            binary = materialize_large_record_2026(container, record, binary=True)
            validate_large_materialization_2026(container, binary)
            with self.assertRaises(ValueError):
                validate_large_materialization_2026(
                    container, dataclasses.replace(binary)
                )
            self.assertEqual(binary.group_offsets[0], self.payload_start)
            self.assertEqual(next(binary.iter_payload()), bytes(CHUNK_SIZE))
            text = materialize_large_record_2026(
                container,
                container.records[0],
                addresses=(0x100, 0x20000, 0x20000, None),
            )
            self.assertEqual(
                list(text.iter_payload()), [(0x100, b"ab"), (0x20000, b"cd")]
            )
            self.assertEqual(text.prefix_s1, (False, True))
            self.assertEqual(text.group_offsets[1], text.group_offsets[2])
            self.assertGreater(text.group_offsets[1], text.group_offsets[0])
            with self.assertRaises(ValueError):
                validate_large_container_2026(dataclasses.replace(container))
            with self.assertRaises(ValueError):
                validate_large_record_2026(container, dataclasses.replace(record))
            with self.assertRaises(ValueError):
                record.read(record.length, 1)
            with self.assertRaises(ValueError):
                record.read(0, CHUNK_SIZE + 1)
            with self.assertRaises(InterruptedError):
                list(binary.iter_payload(cancelled=lambda: True))
        with self.assertRaises(ValueError):
            record.read(0, 1)

    def test_cancelled_during_stream(self):
        calls = 0

        def cancelled():
            nonlocal calls
            calls += 1
            return calls > 3

        with self.assertRaises(InterruptedError):
            native_large_cuw_2026(self.path, cancelled=cancelled)

    def test_extension_small_device_fifo(self):
        with self.assertRaises(ValueError):
            native_large_cuw_2026(self.path.with_suffix(".bin"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.cuw"
            path.write_bytes(b"short")
            with self.assertRaises(ValueError):
                native_large_cuw_2026(path)
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                native_large_cuw_2026(path)
            path.unlink()
            path.symlink_to("/dev/zero")
            with self.assertRaises(ValueError):
                native_large_cuw_2026(path)
            path.unlink()
            with path.open("wb") as source:
                source.truncate(1 << 32)
            with self.assertRaisesRegex(ValueError, "UINT32_MAX"):
                native_large_cuw_2026(path)

    def test_other_native_versions_and_replaced_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "native.cuw"
            for version in (107, 209):
                fixture(path, version)
                with native_large_cuw_2026(path) as container:
                    self.assertEqual(container.format_version, version)
            container = native_large_cuw_2026(path)
            moved = path.with_suffix(".old")
            path.rename(moved)
            path.write_bytes(b"replacement")
            with self.assertRaises(ValueError):
                container.records[1].read(0, 1)
            container.close()

    def test_inner_faults_with_valid_outer_checksum(self):
        def repair(path):
            crc = 0
            with path.open("rb") as source:
                source.seek(18)
                while chunk := source.read(CHUNK_SIZE):
                    crc = zlib.crc32(chunk, crc)
            with path.open("r+b") as target:
                target.seek(14)
                target.write(struct.pack(">I", crc))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fault.cuw"
            fixture(path)
            with path.open("r+b") as target:
                target.seek(27)
                target.write(b"\xff\xff\xff\xff")
            repair(path)
            with self.assertRaisesRegex(ValueError, "exceeds source"):
                native_large_cuw_2026(path)
            fixture(path)
            with path.open("r+b") as target:
                target.seek(MIN_SIZE - 1)
                target.write(b"x")
            repair(path)
            with self.assertRaisesRegex(ValueError, "record CRC32"):
                native_large_cuw_2026(path)

    def test_authenticated_malformed_srecord_and_materializer_cancel(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.cuw"
            fixture(path, text=b"S9 30000FC\r\n")
            with native_large_cuw_2026(path) as container:
                record = container.records[0]
                with self.assertRaisesRegex(ValueError, "count must be hexadecimal"):
                    materialize_large_record_2026(container, record)
                with self.assertRaises(InterruptedError):
                    materialize_large_record_2026(
                        container, record, cancelled=lambda: True
                    )

    def test_actual_large_metadata_archive_consumer(self):
        from scripts.calibration_2026 import (
            encode_metadata_string_2026,
            native2026_logical_archive,
            native2026_metadata,
        )

        metadata_bytes = (
            b"[Format]\nVersion=209\n[Vehicle]\nNumberOfNode=1\n"
            b"[Node01]\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=1\n"
            b"[LogicalBlock101]\nNewCID=authored\nReproMethod=02\nNumberOfTargets=0\nNonce="
            + encode_metadata_string_2026("00" * 16).encode("ascii")
            + b"\n"
            + b"[ReproData101]\nStartAddress=00001000\nLength=00000004\n"
            b"[EraseAndReproRoutine101]\nStartAddress=00002000\nLength=00000004\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logical.cuw"
            fixture(path, version=209, text=b"DATA", metadata_override=metadata_bytes)
            container = native_large_cuw_2026(path)
            metadata = native2026_metadata(container)
            block = metadata.logical_blocks[0]
            for area in block.areas:
                self.assertIsNone(area.data)
                archive = native2026_logical_archive(metadata, block, area.kind)
                self.assertTrue(archive.streamed)
                assert archive.data is not None
                self.assertEqual(len(archive.data), 0x144)
                self.assertEqual(archive.length, area.record.length)
                validate_large_materialization_2026(container, archive.backing)
                self.assertIs(archive.backing.record, area.record)
                self.assertEqual(
                    archive.backing.record.read(0, 4),
                    b"DATA" if area.kind == "ReproData" else bytes(4),
                )
            container.close()
            with self.assertRaises(ValueError):
                native2026_logical_archive(metadata, block, "ReproData")

    def test_srecord_crosses_five_mib_window(self):
        prefix = srec(0, 0, b"x")
        row = srec(0, 0, b"H" * 250)
        prefix += row * (CHUNK_SIZE // len(row))
        payload = prefix + srec(3, 0x10000, b"DATA") + srec(9, 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boundary.cuw"
            fixture(path, text=payload)
            with native_large_cuw_2026(path) as container:
                record = container.records[0]
                materialized = materialize_large_record_2026(
                    container, record, addresses=(0x10000, None, None, None)
                )
                self.assertEqual(
                    materialized.group_offsets[0], record.source_offset + len(prefix)
                )
                self.assertEqual(
                    list(materialized.iter_payload()), [(0x10000, b"DATA")]
                )

    def test_source_drift(self):
        with native_large_cuw_2026(self.path) as container:
            original = self.path.stat()
            os.utime(self.path, ns=(original.st_atime_ns, original.st_mtime_ns + 1))
            with self.assertRaises(ValueError):
                container.records[0].read(0, 1)
            with self.assertRaises(ValueError):
                validate_large_container_2026(container)

    def test_faults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fault.cuw"
            for version, protocol in ((106, "02"), (500, "01")):
                fixture(path, version, protocol)
                with self.assertRaises(ValueError):
                    native_large_cuw_2026(path)
            fixture(path)
            with path.open("r+b") as target:
                target.seek(MIN_SIZE - 1)
                target.write(b"x")
            with self.assertRaisesRegex(ValueError, "CRC32"):
                native_large_cuw_2026(path)
            with path.open("r+b") as target:
                target.truncate(MIN_SIZE - 1)
            with self.assertRaises(ValueError):
                native_large_cuw_2026(path)


if __name__ == "__main__":
    unittest.main()
