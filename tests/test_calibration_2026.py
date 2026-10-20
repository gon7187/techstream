"""Authored containers only: no OEM firmware, signatures or secret material."""

import dataclasses
import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from scripts.calibration_2026 import (
    METADATA_VERSIONS,
    _large_logical_archive,
    decode_lzf_hex_frames_2026,
    decode_metadata_string_2026,
    encode_metadata_string_2026,
    materialize_intel_hex_2026,
    materialize_srecords_2026,
    metadata_sections_2026,
    native2026_archive,
    native2026_archive_password,
    native2026_cpu_cmac,
    native2026_cpu_count,
    native2026_cpu_file_flash_size,
    native2026_cpu_files,
    native2026_cpu_p4_server_max_time,
    native2026_cpu_security_bytes,
    native2026_cpu_targets,
    native2026_cpu_type,
    native2026_date_presentation,
    native2026_download_geometry,
    native2026_export_state,
    native2026_file_cpu,
    native2026_file_header,
    native2026_file_index,
    native2026_global_cpu_index,
    native2026_header_info,
    native2026_logical_archive,
    native2026_logical_cpu_flash_size,
    native2026_metadata,
    native2026_metadata_for_cpu,
    native2026_new_calibration_id,
    native2026_new_password,
    native2026_node_count,
    native2026_node_cpu_count,
    native2026_node_index,
    native2026_selection_metadata,
    native2026_with_cpu_type,
    native2026_with_parser_parameters,
    native_date_of_issue_components_2026,
    parse_cuw_2026,
)
from scripts.programming_2026_common import make_send_data_records


def record(header, data):
    return (
        struct.pack(">H", len(header))
        + header
        + struct.pack(">II", len(data), zlib.crc32(data))
        + data
    )


def cuw(text, payloads=(b"data",), *, count=None, outer=104, encode_fields=True):
    # Test input uses explicit authored clear values; wire fields follow2dae0.
    text = "\n".join(
        f"{key}={encode_metadata_string_2026(value)}"
        if encode_fields
        and separator
        and (
            key.casefold()
            in {
                "ecuauthkey",
                "serviceauthkey",
                "nonce",
                "seedkey",
                "seedkeyid",
                "newpassword",
                "cmacforflashcodedata",
                "cmacforcpuimagedata",
            }
            or key.casefold().endswith("_targetdata")
        )
        else line
        for line in text.split("\n")
        for key, separator, value in (line.partition("="),)
    )
    version = int(text.split("Version=", 1)[1].splitlines()[0])
    width = 2 if version == 9 else 1
    body = record(b"attach.att", text.encode("ascii"))
    body += (len(payloads) if count is None else count).to_bytes(width, "big")
    body += b"".join(
        record(f"authored{i}".encode(), value) for i, value in enumerate(payloads)
    )
    data = (
        b"\0CALIBRATION\0"
        + bytes((outer,))
        + bytes(4)
        + struct.pack(">I", 22 + len(body))
        + body
    )
    return data[:14] + struct.pack(">I", zlib.crc32(data[18:])) + data[18:]


def cpu_text(version=10):
    return (
        f"[Format]\nVersion={version}\n[Vehicle]\nNumberOfCalibration=1\n"
        "ContactType=P5-Unified\nKindOfECU=149\nByteNumberOfTransmitting=FFF\n"
        "CANIDTx_Func_USDT=000007DF\n[CPU01]\nCPUImageName=authored.vbf\n"
        "CPUType=311\nStartAddress=0100001000\nSizeOfUncompressedDownloadData=00000020\n"
        "SizeOfDownloadData=00000004\n"
    )


def logical_text(version=209, *, method="02", slot=1, routine=False):
    text = (
        f"[Format]\nVersion={version}\n[Vehicle]\nNumberOfNode=1\nContactType=P5-Unified\n"
        "[Node01]\nNumberOfLogicalBlock=1\nRequiredSpecReproVer=03\n"
        "WakeUpTimeAfterReset=0A\nIntervalTimeBetweenFrame=0B\nEmissionsRelatedSystem=0C\n"
        "WaitTimeAfterProgrammingSession=0D\nChargeLocalBusEcuStartTimeAfterPowerOn=0E\n"
        "NumberOfGateway=1\n01_GatewayMode=02\nGatewayMode=wrong\nProtocol=02\n"
        f"ServiceAuthKey={'11' * 16}\nECUAuthKey={'22' * 16}\n"
        f"[LogicalBlock1{slot:02}]\nNewCID=authored-new\nNumberOfTargets=1\n"
        f"01_TargetCalibration=authored-old\nReproMethod={method}\nNonce={'33' * 16}\n"
        "P4ServerMaxTime=0F\n"
        f"[ReproData1{slot:02}]\nStartAddress=00001000\nLength=00000004\n"
        f"CMAC={'44' * 64}\nDigitalSignature={'55' * 384}\n"
    )
    if routine:
        text += f"[EraseAndReproRoutine1{slot:02}]\nStartAddress=00002000\nLength=00000004\n"
    return text


def srecord(kind, address, payload=b""):
    width = {0: 2, 1: 2, 3: 4, 5: 2, 7: 4}[kind]
    data = bytes((width + len(payload) + 1,)) + address.to_bytes(width, "big") + payload
    return (
        f"S{kind}".encode() + (data + bytes((~sum(data) & 255,))).hex().upper().encode()
    )


class Calibration2026Tests(unittest.TestCase):
    def test_logical_resume_uses_present_length_strings_and_first_node_cpu(self):
        from scripts.calibration_2026 import (
            native2026_is_logical_cpu,
            native2026_logical_resume_cpu,
        )

        text = logical_text(209, method="08", routine=True).replace(
            "NumberOfLogicalBlock=1", "NumberOfLogicalBlock=2"
        )
        text += (
            "[DeltaReproData101]\nStartAddress=3000\nLength=05\n"
            "[DeltaEraseAndReproRoutine101]\nStartAddress=4000\nLength=02\n"
            "[LogicalBlock102]\nNewCID=SECOND\nReproMethod=08\n"
            "[ReproData102]\nStartAddress=5000\nLength=04\n"
        )
        original = native2026_metadata(
            parse_cuw_2026(cuw(text, (b"FULL", b"RRRR", b"DELTA", b"RR", b"NEXT")))
        )
        self.assertTrue(native2026_is_logical_cpu(original, 0))
        self.assertEqual(native2026_archive(original).flash_size, 7)
        resumed = native2026_logical_resume_cpu(original, 0)
        self.assertEqual(
            (resumed.remapped_cpu_index, resumed.calculated_flash_size), (0, 8)
        )
        self.assertEqual(resumed.metadata.logical_blocks[0].repro_method, "01")
        self.assertEqual(resumed.metadata.logical_blocks[1].repro_method, "08")
        self.assertEqual(native2026_archive(resumed.metadata).flash_size, 8)
        self.assertEqual(
            native2026_logical_archive(
                resumed.metadata, resumed.metadata.logical_blocks[0], "ReproData"
            ).data,
            b"FULL",
        )
        self.assertEqual(original.logical_blocks[0].repro_method, "08")
        second = native2026_logical_resume_cpu(resumed.metadata, 1)
        self.assertEqual(
            (second.remapped_cpu_index, second.calculated_flash_size), (0, 4)
        )
        self.assertEqual(second.metadata.logical_blocks[1].repro_method, "05")
        self.assertEqual(
            native2026_archive(
                native2026_metadata_for_cpu(second.metadata, 1)
            ).flash_size,
            4,
        )
        self.assertEqual(
            native2026_archive(
                native2026_metadata_for_cpu(second.metadata, 0)
            ).flash_size,
            8,
        )
        self.assertIs(second.metadata.source_container, original.source_container)
        zero = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    logical_text(209, method="08").replace(
                        "Length=00000004", "Length=00"
                    ),
                    (),
                )
            )
        )
        zero_result = native2026_logical_resume_cpu(zero, 0)
        self.assertEqual(
            (
                zero_result.metadata.logical_blocks[0].repro_method,
                zero_result.calculated_flash_size,
            ),
            ("05", 0),
        )
        other = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    logical_text(209).replace(
                        "ContactType=P5-Unified", "ContactType=OTHER"
                    )
                )
            )
        )
        self.assertFalse(native2026_is_logical_cpu(other, 0))
        with self.assertRaises(ValueError):
            native2026_logical_resume_cpu(other, 0)

    def test_runtime_metadata_validator_requires_exact_issued_state_after_transitions(
        self,
    ):
        from scripts.calibration_2026 import (
            native2026_cpu_file_list_flag,
            native2026_select_received_cids,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_2026 import configure_2026
        from scripts.programming_2026_common import NativeGeneralParameters2026

        text = cpu_text(8) + "NewCID=NEW\nNumberOfTargets=1\n01_TargetCalibration=OLD\n"
        text += "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
        original = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertIs(native2026_validate_runtime_metadata(original), original)
        self.assertFalse(native2026_cpu_file_list_flag(original))
        empty_files = native2026_metadata(
            parse_cuw_2026(cuw(cpu_text(9) + "NewCID=FILES\n", ()))
        )
        self.assertTrue(native2026_cpu_file_list_flag(empty_files))
        self.assertEqual(native2026_cpu_files(empty_files), ())
        with self.assertRaisesRegex(ValueError, "Issued"):
            native2026_validate_runtime_metadata(dataclasses.replace(original))
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": b"ParamFileKeySystemProtocolMicon,M16CTypeFlag\r\n149P5-Unified311,0\r\n"
            },
            encoded=False,
        )
        original = native2026_with_parser_parameters(original, general)
        current = native2026_select_received_cids(
            original,
            (b"OLD",),
            (bytes(12),),
            general,
            configuration=configure_2026(struct.pack("<IIddII", 4, 0, 0.0, 0.0, 0, 0)),
            shrink_flag=False,
        ).rebuilt_metadata
        self.assertIs(native2026_validate_runtime_metadata(current), current)
        changed = native2026_with_cpu_type(current, 0, "runtime")
        selected = native2026_metadata_for_cpu(changed, 0)
        self.assertIs(native2026_validate_runtime_metadata(selected), selected)
        self.assertEqual(
            (native2026_cpu_type(selected), selected.cpu.values["cputype"]),
            ("runtime", "runtime"),
        )
        for fields in (
            {},
            {"vehicle": {**current.vehicle, "contacttype": "forged"}},
            {"cpu_rows": ({**current.cpu_rows[0], "newcid": "forged"},)},
            {"cpu_type_overrides": {0: "forged"}},
            {"cpu_target_overrides": {}},
            {"parser_parameters_validated": False},
        ):
            forged = dataclasses.replace(current, **fields)
            for consumer in (
                native2026_validate_runtime_metadata,
                native2026_archive,
                lambda metadata: native2026_metadata_for_cpu(metadata, 0),
            ):
                with self.assertRaisesRegex(ValueError, "Issued"):
                    consumer(forged)

    def test_usb_streamed_300mib_original_file_lease_and_chunk_consumer(self):
        from scripts.calibration_2026 import (
            native2026_usb_file_source,
            native2026_usb_source_span,
        )
        from scripts.cuw_large import CHUNK_SIZE, MIN_SIZE

        text = cpu_text(12).replace(
            "KindOfECU=149", "KindOfECU=149\nCANIDTx_Phys_USDT=0795"
        )
        prefix = cuw(text, (struct.pack(">QI", 1 << 33, 0),))
        tail_size = MIN_SIZE - len(prefix)
        zeros = bytes(CHUNK_SIZE)
        crc = 0
        expected_tail = hashlib.sha256()
        for offset in range(0, tail_size, CHUNK_SIZE):
            chunk = zeros[: min(CHUNK_SIZE, tail_size - offset)]
            crc = zlib.crc32(chunk, crc)
            expected_tail.update(chunk)
        prefix = cuw(text, (struct.pack(">QI", 1 << 33, crc),))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usb.cuw"
            with path.open("wb") as target:
                target.write(prefix)
                target.truncate(MIN_SIZE)
            with native2026_usb_file_source(path) as source:
                self.assertIsNone(source.raw)
                metadata = native2026_metadata(source)
                span = native2026_usb_source_span(metadata)
                self.assertEqual(
                    (span.offset, span.length, span.free_space_requirement),
                    (len(prefix), tail_size, 1 << 33),
                )
                consumed = hashlib.sha256()
                length = 0
                for chunk in span.iter_chunks():
                    self.assertLessEqual(len(chunk), CHUNK_SIZE)
                    length += len(chunk)
                    consumed.update(chunk)
                self.assertEqual(length, tail_size)
                self.assertEqual(consumed.digest(), expected_tail.digest())
                with path.open("rb") as original:
                    self.assertEqual(
                        hashlib.file_digest(original, "sha256").hexdigest(),
                        source.digest,
                    )
                with self.assertRaises(ValueError):
                    span.read(0, CHUNK_SIZE + 1)
                with path.open("r+b") as changed:
                    changed.seek(-1, 2)
                    changed.write(b"x")
                with self.assertRaisesRegex(ValueError, "changed or closed"):
                    span.read(0, 1)
            with self.assertRaisesRegex(ValueError, "changed or closed"):
                native2026_metadata(source)

    def test_large_cpu_import_zero_uses_rewritten_descriptor_crc_and_bounds(self):
        from scripts.cuw_large import CHUNK_SIZE, MIN_SIZE, native_large_cuw_2026

        def fixture(path, *, correct=True, huge_cpu=False):
            text = (
                "[Format]\nVersion=209\n[Vehicle]\nNumberOfNode="
                + ("1" if huge_cpu else "2")
                + "\nContactType=P5-Unified\n[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
                "[CPU11]\nCPUImageName=cpu.vbf\nNewCID=CPU\n"
            )
            if not huge_cpu:
                text += (
                    "[Node02]\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=1\n"
                    "[LogicalBlock201]\nNewCID=LOGICAL\nReproMethod=00\n"
                    "[ReproData201]\nStartAddress=1000\nLength=01\n"
                )
            prefix = b"\0CALIBRATION\0\x0c" + bytes(4) + struct.pack(">I", MIN_SIZE)
            prefix += record(b"INI", text.encode()) + bytes((1 if huge_cpu else 2,))
            descriptor = b""
            if not huge_cpu:
                start = len(prefix) + 13
                data = bytearray(0x144)
                data[:3] = b"209"
                filename = str(path).encode()
                data[4 : 4 + len(filename)] = filename
                struct.pack_into("<II", data, 0x108, start, start + 0x143)
                descriptor = bytes(data)
                if not correct:
                    data[-1] = 1
                prefix += record(b"CPU", bytes(data))
            payload_size = MIN_SIZE - len(prefix) - 10
            zeros = bytes(CHUNK_SIZE)
            crc = 0
            for offset in range(0, payload_size, CHUNK_SIZE):
                crc = zlib.crc32(zeros[: min(CHUNK_SIZE, payload_size - offset)], crc)
            prefix += struct.pack(">HII", 0, payload_size, crc)
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
            return descriptor

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authored.cuw"
            expected = fixture(path)
            with native_large_cuw_2026(path) as container:
                metadata = native2026_metadata(container)
                self.assertEqual(native2026_cpu_count(metadata), 2)
                archive = native2026_archive(metadata)
                self.assertEqual(
                    (archive.data, archive.length, archive.flash_size),
                    (expected, 0x144, 0),
                )
                self.assertEqual(
                    native2026_archive(native2026_metadata_for_cpu(metadata, 0)).data,
                    expected,
                )
            fixture(path, correct=False)
            with (
                native_large_cuw_2026(path) as container,
                self.assertRaisesRegex(ValueError, "ImportData0 CRC"),
            ):
                native2026_metadata(container)
            fixture(path, huge_cpu=True)
            with (
                native_large_cuw_2026(path) as container,
                self.assertRaisesRegex(ValueError, "ImportData0: Data too big"),
            ):
                native2026_metadata(container)

    def test_usb_original_trailer_producer_crc_span_and_cpu_archive_are_distinct(self):
        from scripts.calibration_2026 import (
            NativeUSBSource2026,
            native2026_usb_source,
            native2026_usb_source_span,
        )
        from scripts.programming_2026_common import NativePassThruException2026

        trailer = b"ACTUAL USB FILE BYTES\0\xff"
        header = struct.pack(">QI", 0x100000001, zlib.crc32(trailer))
        text = cpu_text(12).replace(
            "KindOfECU=149", "KindOfECU=149\nCANIDTx_Phys_USDT=0795"
        )
        prefix = cuw(text, (header,))
        raw = prefix + trailer
        source = parse_cuw_2026(raw)
        self.assertIsInstance(source, NativeUSBSource2026)
        metadata = native2026_metadata(source)
        span = native2026_usb_source_span(metadata)
        self.assertIs(span.source_container, source)
        self.assertEqual(span.source_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(
            (span.offset, span.length, span.free_space_requirement),
            (len(prefix), len(trailer), 0x100000001),
        )
        self.assertEqual(span.read(), trailer)
        self.assertEqual(span.read(7, 3), trailer[7:10])
        self.assertEqual(span.image_name, "authored.vbf")
        self.assertEqual(native2026_archive(metadata).data, header)
        self.assertEqual(native2026_archive(metadata).flash_size, 12)
        self.assertIs(native2026_metadata_for_cpu(metadata, 0).source_container, source)
        for bad in (prefix + trailer[:-1], prefix + trailer[:-1] + b"x"):
            with self.assertRaises(NativePassThruException2026) as failure:
                parse_cuw_2026(bad)
            self.assertEqual(
                (failure.exception.error, failure.exception.line), (6, 0x647)
            )
            self.assertTrue(failure.exception.source.endswith("CPassThruCtrlr.cpp"))
        with self.assertRaises(ValueError):
            span.read(len(trailer), 1)
        with self.assertRaisesRegex(ValueError, "Issued"):
            dataclasses.replace(span).read()
        with self.assertRaisesRegex(ValueError, "Issued"):
            native2026_metadata(dataclasses.replace(source))
        empty = native2026_usb_source(cuw(text, (struct.pack(">QI", 1, 0),)))
        self.assertEqual(
            native2026_usb_source_span(native2026_metadata(empty)).read(), b""
        )

    def test_node_projection_classifies_using_new_global_cpu_zero(self):
        from scripts.calibration_2026 import native2026_project_node

        text = (
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=2\n"
            "[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
            "[CPU11]\nCPUImageName=first.vbf\n"
            "[Node02]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\nContactType=CAN\n"
            "[CPU21]\nCPUImageName=second.raw\n"
        )
        wire = b"\n".join((srecord(1, 0x1000, b"DATA"), srecord(7, 0)))
        original = native2026_metadata(parse_cuw_2026(cuw(text, (b"FIRST", wire))))
        self.assertEqual(
            native2026_archive(native2026_metadata_for_cpu(original, 1)).data, wire
        )
        selected = native2026_project_node(original, 1)
        self.assertEqual(native2026_archive(selected).data, b"DATA")
        self.assertEqual(native2026_archive(selected).flash_size, 4)
        self.assertEqual(selected.vehicle["contacttype"], "CAN")

    def test_composite_node16_projection_uses_first_target_and_original_owner(self):
        from scripts.calibration_2026 import (
            NativeNodeSource2026,
            native2026_project_node,
        )

        text = logical_text(209, method="00").replace(
            "NumberOfNode=1", "NumberOfNode=16"
        )
        text += (
            "[Node16]\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=2\nContactType=Phase6\n"
            "[LogicalBlock1601]\nNewCID=SIXTEEN\nNumberOfTargets=1\n01_TargetCalibration=A\nReproMethod=00\n"
            "[ReproData1601]\nStartAddress=2000\nLength=04\n"
            "[LogicalBlock1602]\nNewCID=SIXTEEN\nNumberOfTargets=1\n01_TargetCalibration=B\nReproMethod=00\n"
            "[ReproData1602]\nStartAddress=3000\nLength=08\n"
        )
        original = native2026_metadata(
            parse_cuw_2026(cuw(text, (b"FIRST", b"NODE16-A", b"NODE16-B")))
        )
        self.assertEqual(native2026_node_count(original), 16)
        selected = native2026_project_node(original, 15)
        self.assertIsInstance(selected.source_container, NativeNodeSource2026)
        self.assertIs(selected.source_container.parent, original)
        self.assertEqual(
            (
                native2026_node_count(selected),
                native2026_cpu_count(selected),
                native2026_node_index(selected),
            ),
            (1, 1, 0),
        )
        self.assertEqual(selected.vehicle["contacttype"], "Phase6")
        self.assertEqual(selected.sections["vehicle"]["numberofnode"], "16")
        self.assertEqual(
            tuple(
                (block.node, block.slot, block.cpu_index)
                for block in selected.logical_blocks
            ),
            ((1, 1, 0),),
        )
        self.assertEqual(
            native2026_logical_archive(
                selected, selected.logical_blocks[0], "ReproData"
            ).data,
            b"NODE16-A",
        )
        self.assertEqual(native2026_archive(selected).flash_size, 4)
        self.assertEqual(
            native2026_new_calibration_id(
                native2026_metadata(selected.source_container)
            ),
            "SIXTEEN",
        )
        with self.assertRaises(ValueError):
            native2026_project_node(original, 16)
        with self.assertRaisesRegex(ValueError, "Issued"):
            native2026_metadata(dataclasses.replace(selected.source_container))

    def test_phase6_merge_preserves_both_real_sources_and_left_header(self):
        from scripts.calibration_2026 import (
            NativeCompositeSource2026,
            native2026_logical_resume_cpu,
            native2026_merge_phase6,
            native2026_validate_phase6_pair,
        )

        left_text = logical_text(209, method="00").replace(
            "ContactType=P5-Unified", "ContactType=Phase6\nVehicleName=LEFT"
        )
        right_text = logical_text(209, method="00", slot=2).replace(
            "ContactType=P5-Unified", "ContactType=Phase6\nVehicleName=RIGHT"
        )
        right_text = right_text.replace("authored-new", "right-new").replace(
            "authored-old", "right-old"
        )
        right_text = right_text.replace(
            "WakeUpTimeAfterReset=0A", "WakeUpTimeAfterReset=20"
        ).replace("Length=00000004", "Length=00000008")
        left = native2026_metadata(parse_cuw_2026(cuw(left_text, (b"LEFTDATA",))))
        right = native2026_metadata(parse_cuw_2026(cuw(right_text, (b"RIGHTDATA",))))
        merged = native2026_merge_phase6(left, right)
        self.assertIsNone(native2026_validate_phase6_pair(left, right))
        other_diag = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    right_text.replace("[Node01]", "[Node01]\nDiagID=DIFFERENT"),
                    (b"RIGHTDATA",),
                )
            )
        )
        self.assertIsNone(native2026_validate_phase6_pair(left, other_diag))
        with self.assertRaisesRegex(ValueError, "Not combinable"):
            native2026_merge_phase6(left, other_diag)
        self.assertIsInstance(merged.source_container, NativeCompositeSource2026)
        self.assertIs(merged.source_container.left, left)
        self.assertIs(merged.source_container.right, right)
        self.assertNotEqual(merged.source_sha256, left.source_sha256)
        self.assertEqual(merged.vehicle["vehiclename"], "LEFT")
        self.assertEqual(native2026_cpu_count(merged), 2)
        self.assertEqual(tuple(block.slot for block in merged.logical_blocks), (1, 2))
        self.assertEqual(merged.wakeup_ms, 1600)
        resumed_right = native2026_logical_resume_cpu(right, 0).metadata
        reversed_merge = native2026_merge_phase6(resumed_right, left)
        self.assertEqual(
            tuple(
                native2026_archive(
                    native2026_metadata_for_cpu(reversed_merge, index)
                ).flash_size
                for index in range(2)
            ),
            (4, 8),
        )
        self.assertEqual(merged.sections["node01"]["wakeuptimeafterreset"], "0A")
        for index, payload in enumerate((b"LEFTDATA", b"RIGHTDATA")):
            selected = native2026_metadata_for_cpu(merged, index)
            block = selected.logical_blocks[index]
            self.assertEqual(
                native2026_logical_archive(selected, block, "ReproData").data, payload
            )
            self.assertIs(selected.source_container, merged.source_container)
            reparsed = native2026_metadata(merged.source_container, cpu_index=index)
            self.assertEqual(
                native2026_new_calibration_id(reparsed, index),
                ("authored-new", "right-new")[index],
            )
            self.assertIs(reparsed.source_container, merged.source_container)
        forged = dataclasses.replace(merged.source_container)
        with self.assertRaisesRegex(ValueError, "Issued"):
            native2026_metadata(forged)
        for replacement in (
            right_text.replace("LogicalBlock102", "LogicalBlock101").replace(
                "ReproData102", "ReproData101"
            ),
            right_text.replace("right-new", "authored-new"),
            right_text.replace("right-new", "authored-old"),
            right_text.replace(
                "01_TargetCalibration=right-old", "01_TargetCalibration=authored-new"
            ),
            right_text.replace("Protocol=02", "Protocol=01"),
            right_text.replace("01_GatewayMode=02", "01_GatewayMode=01"),
            right_text.replace(
                "ServiceAuthKey=" + "11" * 16, "ServiceAuthKey=" + "22" * 16
            ),
        ):
            candidate = native2026_metadata(
                parse_cuw_2026(cuw(replacement, (b"RIGHTDATA",)))
            )
            with self.assertRaisesRegex(ValueError, "Not combinable"):
                native2026_merge_phase6(left, candidate)

    def test_vbf_selection_requires_actual_target_hardware_and_allows_empty_cid(self):
        from scripts.calibration_2026 import native2026_select_received_cids
        from scripts.cuw_2026 import configure_2026
        from scripts.programming_2026_common import NativeGeneralParameters2026

        text = cpu_text(8) + (
            "NewCID=NEW\nNumberOfTargets=1\n01_TargetCalibration=OLD\n"
            "NumberOfTargetHardwares=2\n01_TargetHardware=OTHER\n02_TargetHardware=HW123\n"
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": b"ParamFileKeySystemProtocolMicon,M16CTypeFlag\r\n149P5-Unified311,0\r\n"
            },
            encoded=False,
        )
        config = configure_2026(struct.pack("<IIddII", 4, 0, 0.0, 0.0, 0, 0))

        def select(cids, hardware):
            return native2026_select_received_cids(
                metadata,
                cids,
                tuple(bytes(12) for _ in cids),
                general,
                configuration=config,
                shrink_flag=False,
                received_hardware=hardware,
            )

        for hardware in (b"", b"OTHER-WRONG"):
            with self.assertRaisesRegex(ValueError, "target hardware"):
                select((b"OLD",), hardware)
        result = select((), b"HW123")
        self.assertEqual(
            (result.target_indices, result.authored_target_indices), ((0,), (0,))
        )
        self.assertEqual(result.unmatched_identifiers, ())
        self.assertEqual(native2026_archive(result.rebuilt_metadata).data, b"data")
        self.assertEqual(select((b"OLD",), b"HW123").target_indices, (0,))
        d4f8 = configure_2026(struct.pack("<IIddII", 4, 0, 0.0, 0.0, 1, 0))
        self.assertEqual(
            native2026_select_received_cids(
                metadata,
                (),
                (),
                general,
                configuration=d4f8,
                shrink_flag=False,
                received_hardware=b"HW123",
            ).target_indices,
            (0,),
        )
        with self.assertRaisesRegex(ValueError, "target hardware"):
            native2026_select_received_cids(
                native2026_metadata(
                    parse_cuw_2026(
                        cuw(
                            text.replace(
                                "NumberOfTargetHardwares=2", "NumberOfTargetHardwares=0"
                            )
                        )
                    )
                ),
                (b"OLD",),
                (bytes(12),),
                general,
                configuration=config,
                shrink_flag=False,
                received_hardware=b"HW123",
            )

    def test_native_node_export_logical_count_is_not_deduplicated_cpu_count(self):
        from scripts.calibration_2026 import (
            native2026_node_logical_block_count,
            native2026_select_received_cids,
        )
        from scripts.cuw_2026 import configure_2026
        from scripts.programming_2026_common import NativeGeneralParameters2026

        ordinary = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=2\n[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\nNumberOfLogicalBlock=7\n[CPU11]\nCPUImageName=ordinary.vbf\nNewCID=ORDINARY\n[Node02]\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=0\n",
                )
            )
        )
        self.assertEqual(native2026_node_logical_block_count(ordinary), 0)
        self.assertEqual(native2026_node_cpu_count(ordinary, 0), 1)
        self.assertEqual(native2026_node_logical_block_count(ordinary, 1), 0)
        text = logical_text(209, method="00").replace(
            "NumberOfLogicalBlock=1", "NumberOfLogicalBlock=2"
        )
        text += "[LogicalBlock102]\nNewCID=authored-new\nNumberOfTargets=1\n01_TargetCalibration=SECOND\nReproMethod=00\n[ReproData102]\nStartAddress=2000\nLength=08\n"
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (b"FIRST", b"SECOND"))))
        self.assertEqual(native2026_node_logical_block_count(metadata), 2)
        self.assertEqual(native2026_node_cpu_count(metadata, 0), 1)
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": b"ParamFileKeySystemProtocolMicon,M16CTypeFlag\r\nP5-Unified,0\r\n"
            },
            encoded=False,
        )
        projected = native2026_select_received_cids(
            metadata,
            (b"SECOND",),
            (bytes(12),),
            general,
            configuration=configure_2026(struct.pack("<IIddII", 4, 0, 0.0, 0.0, 0, 0)),
            shrink_flag=True,
        ).rebuilt_metadata
        self.assertEqual(native2026_node_logical_block_count(projected), 1)
        self.assertEqual(projected.sections["node01"]["numberoflogicalblock"], "2")
        for bad in (dataclasses.replace(metadata), dataclasses.replace(projected)):
            with self.assertRaisesRegex(ValueError, "Issued"):
                native2026_node_logical_block_count(bad)
        with self.assertRaisesRegex(ValueError, "index"):
            native2026_node_logical_block_count(metadata, 1)

    def test_cid_match_snapshot_is_issued_and_vbf_does_not_rebuild(self):
        from scripts.calibration_2026 import (
            native2026_cid_rebuild_allowed,
            native2026_match_received_cids,
            native2026_rebind_cid_match,
            native2026_rebuild_received_cids,
            native2026_select_received_cids,
            native2026_unrebuilt_selection,
        )
        from scripts.cuw_2026 import configure_2026
        from scripts.programming_2026_common import NativeGeneralParameters2026

        text = cpu_text(8).replace("NumberOfCalibration=1", "NumberOfCalibration=2")
        text += "NewCID=M16C\nNumberOfTargets=1\n01_TargetCalibration=OLD1\nNumberOfTargetHardwares=1\n01_TargetHardware=\n[CPU02]\nCPUImageName=two.vbf\nCPUType=312\nNewCID=FOREST\nNumberOfTargets=1\n01_TargetCalibration=OLD2\n"
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (b"FIRST", b"SECOND"))))
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": b"ParamFileKeySystemProtocolMicon,Unrelated\r\n149P5-Unified311,1\r\n"
            },
            encoded=False,
        )
        config = configure_2026(struct.pack("<IIddII", 4, 0, 0.0, 0.0, 0, 0))
        match = native2026_match_received_cids(
            metadata,
            (b"OLD1", b"FOREST"),
            (bytes(12), bytes(12)),
            general,
            configuration=config,
            shrink_flag=True,
        )
        self.assertEqual(match.authored_target_indices, (0, -1))
        self.assertTrue(match.check_target)
        rejected = native2026_match_received_cids(
            metadata,
            (b"OLD1", b"M16C", b"FOREST"),
            (bytes(12),) * 3,
            general,
            configuration=config,
            shrink_flag=False,
        )
        self.assertEqual(rejected.authored_target_indices, (0, -1))
        self.assertFalse(rejected.check_target)
        changed = native2026_with_cpu_type(metadata, 0, "312")
        changed = native2026_with_cpu_type(changed, 1, "313")
        rebound = native2026_rebind_cid_match(match, changed)
        self.assertIs(rebound.metadata, changed)
        self.assertEqual(rebound.authored_target_indices, match.authored_target_indices)
        self.assertEqual(rebound.unmatched_identifiers, match.unmatched_identifiers)
        self.assertEqual(rebound.check_target, match.check_target)
        self.assertEqual(
            native2026_cpu_type(
                native2026_unrebuilt_selection(rebound).rebuilt_metadata
            ),
            "312",
        )
        selected_view = native2026_metadata_for_cpu(changed, 1)
        rebound_view = native2026_rebind_cid_match(match, selected_view)
        self.assertIs(rebound_view.metadata, selected_view)
        self.assertEqual(
            rebound_view.authored_target_indices, match.authored_target_indices
        )
        for unrelated in (
            native2026_metadata(metadata.source_container),
            dataclasses.replace(changed),
        ):
            with self.assertRaisesRegex(ValueError, "issued|Issued"):
                native2026_rebind_cid_match(match, unrelated)
        self.assertEqual(match.unmatched_identifiers, (b"FOREST",))
        self.assertFalse(native2026_cid_rebuild_allowed(metadata))
        raw = native2026_unrebuilt_selection(match)
        self.assertIs(raw.rebuilt_metadata, metadata)
        self.assertEqual((raw.cpu_offset, raw.ordered_to_authored), (0, (0, 1)))
        self.assertEqual(len(native2026_cpu_targets(metadata, 1)), 1)
        with self.assertRaisesRegex(ValueError, "skips"):
            native2026_rebuild_received_cids(metadata, match, general)
        with self.assertRaisesRegex(ValueError, "Issued"):
            native2026_unrebuilt_selection(dataclasses.replace(match))
        convenience = native2026_select_received_cids(
            metadata,
            (b"OLD1", b"FOREST"),
            (bytes(12), bytes(12)),
            general,
            configuration=config,
            shrink_flag=True,
        )
        self.assertIs(convenience.rebuilt_metadata, metadata)
        self.assertEqual(convenience.cpu_offset, 0)
        indexed = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    cpu_text(9).replace("authored.vbf", "authored.hex")
                    + "NewCID=INDEXED\nNumberOfTargets=1\n01_TargetCalibration=OLD\nNumberOfFiles=1\n[File1001]\nFileName=one\nALFID=44\nDownloadAddress=0\nDownloadMemsize=4\n",
                    (srecord(1, 0, b"DATA") + b"\n" + srecord(7, 0),),
                )
            )
        )
        self.assertFalse(native2026_cid_rebuild_allowed(indexed))
        indexed_match = native2026_match_received_cids(
            indexed,
            (b"OLD",),
            (bytes(12),),
            general,
            configuration=config,
            shrink_flag=False,
        )
        self.assertIs(
            native2026_unrebuilt_selection(indexed_match).rebuilt_metadata, indexed
        )
        with self.assertRaisesRegex(ValueError, "skips"):
            native2026_rebuild_received_cids(indexed, indexed_match, general)

    def test_received_cids_promote_forest_and_append_actual_image_password(self):
        from scripts.calibration_2026 import native2026_select_received_cids
        from scripts.cuw_2026 import configure_2026
        from scripts.programming_2026_common import NativeGeneralParameters2026

        text = (
            cpu_text(8)
            .replace("authored.vbf", "authored.hex")
            .replace("NumberOfCalibration=1", "NumberOfCalibration=2")
        )
        text += (
            "NewCID=M16C\nNumberOfTargets=1\n01_TargetCalibration=OLD1\n"
            "[CPU02]\nCPUImageName=two.hex\nCPUType=312\nNewCID=FOREST\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD2\n"
        )
        text = text.replace(
            "[CPU01]", "[CPU01]\nNumberOfTargetHardwares=1\n01_TargetHardware="
        )
        metadata = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    text,
                    tuple(
                        srecord(1, 0, value) + b"\n" + srecord(7, 0)
                        for value in (b"FIRST", b"\x01\x02\x03\x04REST")
                    ),
                )
            )
        )
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": (
                    b"ParamFileKeySystemProtocolMicon,M16CTypeFlag,FORESTTypeFlag,PasswordAddress,ByteOrder,FlagToHoldSFormatRecords\r\n"
                    b"149P5-Unified311,1,0,00,1,0\r\n149P5-Unified312,0,1,00,1,0\r\n"
                )
            },
            encoded=False,
        )
        config = configure_2026(struct.pack("<IIddII", 4, 0, 0.0, 0.0, 0, 0))
        result = native2026_select_received_cids(
            metadata,
            (b"OLD1", b"FOREST"),
            (bytes(12), bytes(12)),
            general,
            configuration=config,
            shrink_flag=True,
        )
        self.assertEqual(
            (result.ordered_to_authored, result.target_indices, result.cpu_offset),
            ((1, 0), (1, 0), 1),
        )
        self.assertEqual(result.unmatched_identifiers, (b"FOREST",))
        self.assertEqual(result.unmatched_companions, (b"",))
        self.assertEqual(
            (result.authored_cpu_count, result.authored_target_indices), (2, (0, -1))
        )
        rebuilt = result.rebuilt_metadata
        self.assertEqual(native2026_cpu_type(rebuilt, 0), "312")
        self.assertEqual(native2026_cpu_targets(rebuilt, 0)[1].calibration, "FOREST")
        self.assertEqual(native2026_cpu_targets(rebuilt, 0)[1].password, 0x01020304)
        self.assertEqual(native2026_archive(rebuilt).data, b"\x01\x02\x03\x04REST")
        self.assertEqual(
            native2026_archive(native2026_metadata_for_cpu(rebuilt, 1)).data, b"FIRST"
        )
        self.assertEqual(len(native2026_cpu_targets(metadata, 1)), 1)

    def test_received_cids_prune_real_logical_backing_and_match_node_companion(self):
        from scripts.calibration_2026 import native2026_select_received_cids
        from scripts.cuw_2026 import configure_2026
        from scripts.programming_2026_common import NativeGeneralParameters2026

        text = logical_text(209, method="00").replace(
            "NumberOfLogicalBlock=1", "NumberOfLogicalBlock=2"
        )
        text = text.replace("NumberOfGateway=1", "DiagID=NODE\nNumberOfGateway=1")
        text += (
            "[LogicalBlock102]\nNewCID=authored-new\nNumberOfTargets=1\n"
            "01_TargetCalibration=second\nReproMethod=00\nNonce="
            + "00" * 16
            + "\n[ReproData102]\nStartAddress=2000\nLength=08\n"
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (b"FIRST", b"SECOND"))))
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": b"ParamFileKeySystemProtocolMicon,M16CTypeFlag\r\nP5-Unified,0\r\n"
            },
            encoded=False,
        )
        config = configure_2026(struct.pack("<IIddII", 4, 0, 0.0, 0.0, 0, 0))
        record = bytes(4) + b"NODE\0\0\0\0"
        result = native2026_select_received_cids(
            metadata,
            (b"second",),
            (record,),
            general,
            configuration=config,
            shrink_flag=True,
        )
        rebuilt = result.rebuilt_metadata
        self.assertEqual(result.target_indices, (1,))
        self.assertEqual(tuple(block.slot for block in rebuilt.logical_blocks), (2,))
        self.assertEqual(rebuilt.logical_blocks[0].cpu_index, 0)
        self.assertEqual(
            native2026_logical_archive(
                rebuilt, rebuilt.logical_blocks[0], "ReproData"
            ).data,
            b"SECOND",
        )
        self.assertIs(
            rebuilt.logical_blocks[0].areas[0].record,
            metadata.logical_blocks[1].areas[0].record,
        )
        self.assertEqual(native2026_archive(rebuilt).flash_size, 12)
        selected = native2026_metadata_for_cpu(rebuilt, 0)
        self.assertEqual(tuple(block.slot for block in selected.logical_blocks), (2,))
        absent = native2026_select_received_cids(
            metadata,
            (b"second",),
            (bytes(12),),
            general,
            configuration=config,
            shrink_flag=True,
        )
        self.assertEqual(native2026_cpu_count(absent.rebuilt_metadata), 0)

    def test_received_cids_rebuild_actual_cpu_archives_and_empty_vector(self):
        from scripts.calibration_2026 import native2026_select_received_cids
        from scripts.cuw_2026 import configure_2026
        from scripts.programming_2026_common import NativeGeneralParameters2026

        text = (
            cpu_text(8)
            .replace("authored.vbf", "authored.hex")
            .replace("NumberOfCalibration=1", "NumberOfCalibration=2")
        )
        text += (
            "NewCID=NEW1\nNumberOfTargets=1\n01_TargetCalibration=OLD1\n"
            "[CPU02]\nCPUImageName=two.hex\nCPUType=311\nNewCID=NEW2\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD2\n"
        )
        text = text.replace(
            "[CPU01]", "[CPU01]\nNumberOfTargetHardwares=1\n01_TargetHardware="
        )
        metadata = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    text,
                    tuple(
                        srecord(1, 0, value) + b"\n" + srecord(7, 0)
                        for value in (b"FIRST", b"SECOND")
                    ),
                )
            )
        )
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": b"ParamFileKeySystemProtocolMicon,M16CTypeFlag\r\n149P5-Unified311,0\r\n"
            },
            encoded=False,
        )
        configuration = configure_2026(struct.pack("<IIddII", 4, 0, 0.0, 0.0, 0, 0))
        result = native2026_select_received_cids(
            metadata,
            (b"MISSING", b"OLD2"),
            (bytes(12), bytes(12)),
            general,
            configuration=configuration,
            shrink_flag=False,
        )
        self.assertEqual(
            (result.ordered_to_authored, result.target_indices, result.cpu_offset),
            ((1,), (0,), 0),
        )
        rebuilt = result.rebuilt_metadata
        self.assertEqual(native2026_cpu_count(rebuilt), 1)
        self.assertEqual(native2026_new_calibration_id(rebuilt), "NEW2")
        self.assertIs(rebuilt.source_container, metadata.source_container)
        self.assertEqual(native2026_archive(rebuilt).data, b"SECOND")
        selected = native2026_metadata_for_cpu(rebuilt, 0)
        self.assertEqual(native2026_archive(selected).data, b"SECOND")
        output = native2026_file_cpu(selected, 0, bytes(0xBBAC))
        self.assertEqual(output[:5], b"NEW2\0")
        empty = native2026_select_received_cids(
            metadata,
            (b"NONE1", b"NONE2"),
            (bytes(12), bytes(12)),
            general,
            configuration=configuration,
            shrink_flag=False,
        ).rebuilt_metadata
        self.assertEqual(native2026_cpu_count(empty), 0)
        with self.assertRaises(ValueError):
            native2026_metadata_for_cpu(empty, 0)
        with self.assertRaises(ValueError):
            native2026_select_received_cids(
                metadata,
                (b"OLD2",),
                (b"x" * 12,),
                general,
                configuration=configuration,
                shrink_flag=False,
            )
        assert rebuilt.runtime_projection is not None
        forged = dataclasses.replace(
            rebuilt, runtime_projection=dataclasses.replace(rebuilt.runtime_projection)
        )
        with self.assertRaisesRegex(ValueError, "Issued"):
            native2026_archive(forged)

    def test_native_append_target_uses_image_password_and_preserves_runtime_state(self):
        from scripts.calibration_2026 import (
            native2026_append_current_target,
            native2026_cpu_values,
        )
        from scripts.programming_2026_common import (
            NativeCallbackLookupError,
            NativeGeneralParameters2026,
        )

        text = (
            cpu_text(8)
            + "NewCID=NEW\nNumberOfTargets=1\n01_TargetCalibration=OLD\nNewPassword=DEADBEEF\n"
        )
        metadata = native2026_metadata(
            parse_cuw_2026(cuw(text, (b"x\x01\x02\x03\x04z",)))
        )

        def parameters(order="65536", address="01"):
            return NativeGeneralParameters2026.from_sources(
                {
                    "Parameter.ini": (
                        "ParamFileKeySystemProtocolMicon,PasswordAddress,ByteOrder\r\n"
                        + f"149P5-Unified311,{address},{order}\r\n"
                    ).encode()
                },
                encoded=False,
            )

        updated, index = native2026_append_current_target(metadata, 0, parameters())
        self.assertEqual(index, 1)
        self.assertEqual(
            tuple(
                (target.calibration, target.password)
                for target in native2026_cpu_targets(updated)
            ),
            (("OLD", 0), ("NEW", 0x01020304)),
        )
        self.assertEqual(len(native2026_cpu_targets(metadata)), 1)
        self.assertIs(updated.source_container, metadata.source_container)
        self.assertEqual(updated.sections["cpu01"]["numberoftargets"], "1")
        self.assertEqual(native2026_cpu_values(updated)["numberoftargets"], "2")
        selected = native2026_metadata_for_cpu(updated, 0)
        self.assertEqual(
            native2026_cpu_targets(selected), native2026_cpu_targets(updated)
        )
        self.assertIs(selected.source_container, metadata.source_container)
        output = native2026_file_cpu(selected, 0, bytes(0xBBAC))
        self.assertEqual(struct.unpack_from("<I", output, 0x24)[0], 2)
        self.assertEqual(output[0x58:0x5C], b"NEW\0")
        little, _ = native2026_append_current_target(metadata, 0, parameters("0"))
        self.assertEqual(native2026_cpu_targets(little)[-1].password, 0x04030201)
        with self.assertRaises(NativeCallbackLookupError):
            native2026_append_current_target(
                metadata,
                0,
                NativeGeneralParameters2026.from_sources(
                    {
                        "Parameter.ini": b"ParamFileKeySystemProtocolMicon,PasswordAddress\r\n149P5-Unified311,01\r\n"
                    },
                    encoded=False,
                ),
            )
        with self.assertRaisesRegex(ValueError, "address"):
            native2026_append_current_target(
                metadata, 0, parameters(address="FFFFFFFF")
            )
        full = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    text.replace("NumberOfTargets=1", "NumberOfTargets=1000"),
                    (b"x\x01\x02\x03\x04z",),
                )
            )
        )
        unchanged, last = native2026_append_current_target(full, 0, parameters())
        self.assertIs(unchanged, full)
        self.assertEqual(last, 999)
        with self.assertRaisesRegex(ValueError, "address"):
            native2026_append_current_target(full, 0, parameters(address="FFFFFFFF"))

    def test_standalone_scuw_recovery_header_is_issued_without_binary_archives(self):
        from scripts.calibration_2026 import native2026_recovery_header

        raw = (
            b"[Format]\nVersion=2\n[Vehicle]\nDateOfIssue=invalid\nVehicleType=TYPE\n"
            b"VehicleName=CAR\nEngineType=ENG\nSystem=ignored\nModelYear=2006\n"
            b"ContactType=Ethernet\nKindOfECU=ignored\nNumberOfCalibration=2\n"
            b"[KindOfCal]\nIsControlledBySCC=1\n[CPU1]\nNewCID=CID1\n"
            b"CPUType=ignored\nCPUImageName=ignored\nNumberOfTargets=3\n"
            b"01_TargetCalibration=OLD1\n02_TargetCalibration=\n03_TargetCalibration=OLD3\n"
            b"01_TargetData=FFFFFFFF\n[CPU2]\nNewCID=CID2\nNumberOfTargets=1\n"
            b"01_TargetCalibration=OLD2\n[CPU01]\nNewCID=wrong-section\n"
        )
        metadata = native2026_recovery_header(raw, cpu_capacity=2, region=3)
        self.assertEqual(
            (metadata.format_version, native2026_cpu_count(metadata)), (500, 2)
        )
        self.assertEqual((metadata.region, native2026_node_count(metadata)), (3, 0))
        self.assertEqual(metadata.source_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(metadata.vehicle["modelyear"], "2006")
        self.assertEqual(metadata.vehicle["enginetype"], "ENG")
        self.assertNotIn("kindofecu", metadata.vehicle)
        self.assertFalse(metadata.is_controlled_by_scc)
        self.assertEqual(native2026_cpu_type(metadata), "")
        self.assertEqual(
            tuple(
                (target.calibration, target.password)
                for target in native2026_cpu_targets(metadata)
            ),
            (("OLD1", 0), ("", 0), ("OLD3", 0)),
        )
        output = native2026_file_cpu(metadata, 0, bytes(0xBBAC))
        self.assertEqual(output[:5], b"CID1\0")
        self.assertEqual(struct.unpack_from("<I", output, 0x24)[0], 3)
        header = native2026_file_header(metadata, bytes(0x98))
        self.assertEqual(struct.unpack_from("<I", header, 0x64)[0], 2)
        self.assertEqual(header[0x26:0x2B], b"2006\0")
        reselected = native2026_metadata_for_cpu(metadata, 1)
        self.assertIs(reselected.source_container, metadata.source_container)
        self.assertEqual(native2026_new_calibration_id(reselected, 1), "CID2")
        with self.assertRaisesRegex(ValueError, "archive"):
            native2026_archive(metadata)
        with self.assertRaisesRegex(ValueError, "issued"):
            native2026_metadata(dataclasses.replace(metadata.source_container))
        empty = native2026_recovery_header(
            b"[Vehicle]\nNumberOfCalibration=0\n", cpu_capacity=0
        )
        self.assertEqual(native2026_cpu_count(empty), 0)
        for invalid in (
            raw + b"\0",
            raw + b"[vehicle]\n",
            raw.replace(b"NumberOfCalibration=2", b"NumberOfCalibration=100"),
        ):
            with self.assertRaises(ValueError):
                native2026_recovery_header(invalid, cpu_capacity=2)
        wide = native2026_recovery_header(
            b"[Vehicle]\nNumberOfCalibration=1\n[CPU1]\nNewCID=CID\nNumberOfTargets=100\n"
            b"100_TargetCalibration=ignored\n100_TargetCalibratio=RIGHT\n",
            cpu_capacity=1,
        )
        self.assertEqual(native2026_cpu_targets(wide)[99].calibration, "RIGHT")
        many = (
            "[Vehicle]\nNumberOfCalibration=100\n"
            + "".join(f"[CPU{index}]\nNewCID=CID{index}\n" for index in range(1, 100))
        ).encode()
        hundred = native2026_recovery_header(many, cpu_capacity=100)
        self.assertEqual(native2026_cpu_count(hundred), 100)
        self.assertEqual(native2026_new_calibration_id(hundred, 99), "CID10")
        self.assertEqual(hundred.report()["selected_node_cpu_count"], 100)

    def test_native_file_header_preserves_padding_and_requires_issued_date(self):
        text = cpu_text(8).replace(
            "[CPU01]",
            "DateOfIssue=2026-02-31\nVehicleName=CAR\nModelYear=2026\n"
            "VehicleType=TYPE\nEngineType=ENG\n[KindOfCal]\n"
            "IsControlledBySCC=1\nIsBlankECU=1\nIsNonFieldFix=1\n[CPU01]",
        )
        container = parse_cuw_2026(cuw(text))
        metadata = native2026_metadata(container)
        before = b"\xa5" * 0x98
        with self.assertRaisesRegex(ValueError, "presentation"):
            native2026_file_header(metadata, before)
        observed = []

        def formatter(components):
            observed.append(components)
            return b"31/02/2026"

        date = native2026_date_presentation(metadata, formatter)
        self.assertEqual(observed, [(2026, 2, 31)])
        output = native2026_file_header(metadata, before, date_presentation=date)
        expected = bytearray(before)
        for offset, value in (
            (0, b"31/02/2026"),
            (0x13, b"CAR"),
            (0x26, b"2026"),
            (0x39, b"TYPE"),
            (0x4C, b"ENG"),
            (0x68, b"P5-Unified"),
        ):
            expected[offset : offset + len(value) + 1] = value + b"\0"
        struct.pack_into("<I", expected, 0x64, 1)
        expected[0x89] = expected[0x8A] = 1
        struct.pack_into("<I", expected, 0x94, 8)
        self.assertEqual(output, bytes(expected))
        self.assertEqual(before, b"\xa5" * 0x98)
        for forged in (
            dataclasses.replace(date, value=b"changed"),
            native2026_date_presentation(
                native2026_metadata(parse_cuw_2026(cuw(text))), formatter
            ),
        ):
            with self.assertRaisesRegex(ValueError, "presentation"):
                native2026_file_header(metadata, before, date_presentation=forged)
        for value in (b"x\0y", b"x" * 19, "wrong type"):
            with self.assertRaises(ValueError):
                native2026_date_presentation(metadata, lambda _, result=value: result)  # pyright: ignore[reportArgumentType]
        invalid = native2026_metadata(
            parse_cuw_2026(cuw(text.replace("2026-02-31", "invalid")))
        )
        self.assertEqual(native2026_file_header(invalid, before)[0:2], b"\0\xa5")
        with self.assertRaises(ValueError):
            native2026_file_header(metadata, before[:-1], date_presentation=date)

    def test_native_file_cpu_global_nodes_targets_and_truncated_diagnostic_id(self):
        text = (
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=2\nContactType=P5-Unified\n"
            "[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
            "DiagID=\nLogicalAddress=abcdefghi\n"
            "[Node02]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\nDiagID=123456789\n"
            "[CPU11]\nCPUImageName=first.vbf\nNewCID=first-CID\nNumberOfTargets=1\n01_TargetCalibration=OLD1\n"
            "[CPU21]\nCPUImageName=second.vbf\nNewCID=second-CID\nNumberOfTargets=2\n"
            "01_TargetCalibration=OLD2\n02_TargetCalibration=OLD3\n"
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (b"a", b"b"))))
        before = b"\xa5" * 0xBBAC
        for index, name, targets, diag in (
            (0, b"first-CID", (b"OLD1",), b"abcdef"),
            (1, b"second-CID", (b"OLD2", b"OLD3"), b"123456"),
        ):
            output = native2026_file_cpu(metadata, index, before)
            expected = bytearray(before)
            expected[: len(name) + 1] = name + b"\0"
            struct.pack_into("<I", expected, 0x24, len(targets))
            for slot, target in enumerate(targets):
                offset = 0x28 + slot * 0x30
                expected[offset : offset + len(target) + 1] = target + b"\0"
                expected[offset + 0x28 : offset + 0x2F] = diag + b"\0"
            self.assertEqual(output, bytes(expected))
            self.assertEqual(output[0xBBA8:], b"\xa5" * 4)
        for index in (-1, 2, True):
            with self.assertRaises(ValueError):
                native2026_file_cpu(metadata, index, before)
        long_name = native2026_metadata(
            parse_cuw_2026(cuw(text.replace("first-CID", "x" * 36), (b"a", b"b")))
        )
        with self.assertRaises(ValueError):
            native2026_file_cpu(long_name, 0, before)
        self.assertEqual(before, b"\xa5" * 0xBBAC)

    def test_retained_archive_map_includes_s0_but_not_count_or_termination(self):
        # 6a9d0 appends headers and data to the same exported record list.
        data = b"\n".join(
            (
                srecord(0, 0x1234, b"HDR"),
                srecord(1, 0x1000, b"ab"),
                srecord(3, 0x1002, b"cd"),
                srecord(5, 2),
                srecord(7, 0x1000),
            )
        )
        text = cpu_text(8).replace("authored.vbf", "authored.srec")
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (data,))))
        archive = native2026_archive(metadata, preserve_srecords=True)
        self.assertEqual(
            archive.mapped_records,
            ((0x1234, b"HDR"), (0x1000, b"ab"), (0x1002, b"cd")),
        )
        self.assertEqual(archive.record_count, 3)
        self.assertEqual(
            (archive.data, archive.header, archive.flash_size), (None, b"", 2)
        )
        self.assertEqual(archive.length, len(data))
        self.assertEqual(make_send_data_records(archive.kind_records, 0x1000, 2), b"cd")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            make_send_data_records(archive.kind_records, 0x1000, 3)
        binary = native2026_archive(metadata)
        self.assertEqual((binary.data, binary.header), (b"abcd", b"HDR"))
        self.assertEqual((binary.mapped_records, binary.record_count), ((), 0))
        malformed = data.replace(b"484452", b"484453")
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (malformed,))))
        with self.assertRaisesRegex(ValueError, "checksum"):
            native2026_archive(metadata, preserve_srecords=True)

    def test_structural_header_strings_are_preserved_before_geometry_conversion(self):
        text = (
            cpu_text(7)
            + "[CPUImage01]\nNumberOfAreaSettings=2\nDataFormatID=custom\n01_StartAddress=10\n01_Length=00\n02_StartAddress=literal\n02_Length=\n"
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        header = native2026_header_info(metadata)
        self.assertEqual((header.count, header.data_format_id), (2, "custom"))
        self.assertEqual(
            (header.areas[0].start_address, header.areas[0].length), ("10", "00")
        )
        self.assertEqual(
            (header.areas[1].start_address, header.areas[1].length), ("literal", "")
        )
        self.assertEqual(metadata.cpu.image_areas, ())
        with self.assertRaises(ValueError):
            header.numeric_areas()
        alias = text.replace("CPUImage01", "WriteRoutine01")
        historical = native2026_metadata(parse_cuw_2026(cuw(alias)))
        self.assertEqual(native2026_header_info(historical, "write_routine").count, 0)

    def test_header_geometry_preserves_variable_source_byte_widths(self):
        text = (
            cpu_text(7)
            + "[CPUImage01]\nNumberOfAreaSettings=2\n01_StartAddress=10\n01_Length=04\n02_StartAddress=0100001000\n02_Length=08\n"
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(metadata.cpu.image_areas, ((0x10, 4), (0x100001000, 8)))
        self.assertEqual(metadata.cpu.headers["image"]["01_startaddress"], "10")
        self.assertEqual(metadata.cpu.headers["image"]["02_startaddress"], "0100001000")

    def test_native_metadata_file_limit_is_258(self):
        text = cpu_text(9) + "NumberOfFiles=258\n"
        text += "".join(
            f"[File1{index:03}]\nALFID=44\nDownloadAddress=0\nDownloadMemsize=1\n"
            for index in range(1, 259)
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (b"D",) * 258)))
        self.assertEqual(len(native2026_cpu_files(metadata)), 258)
        with self.assertRaises(ValueError):
            native2026_metadata(
                parse_cuw_2026(
                    cuw(
                        text.replace("NumberOfFiles=258", "NumberOfFiles=259"),
                        (b"D",) * 259,
                    )
                )
            )

    def test_metadata_preserves_non_ascii_native_bytes(self):
        sections, version = metadata_sections_2026(
            b"[Format]\nVersion=7\n[Vehicle]\nNote=\x81\x8f\n"
        )
        self.assertEqual(version, 7)
        self.assertEqual(sections["vehicle"]["note"].encode("latin1"), b"\x81\x8f")

    def test_exact_22_metadata_versions_and_outer_104(self):
        self.assertEqual(len(METADATA_VERSIONS), 22)
        for version in METADATA_VERSIONS:
            _, result = metadata_sections_2026(
                f"[Format]\nVersion={version}\n".encode()
            )
            self.assertEqual(result, version)
        with self.assertRaises(ValueError):
            metadata_sections_2026(b"[Format]\nVersion=1\n")
        self.assertEqual(parse_cuw_2026(cuw(cpu_text())).version, 104)

    def test_encoded_native_auth_strings_and_distinct_global_node_getters(self):
        self.assertEqual(decode_metadata_string_2026("303243"), "01A")
        self.assertEqual(encode_metadata_string_2026("01A"), "303243")
        self.assertEqual(
            decode_metadata_string_2026(encode_metadata_string_2026("A" * 300)),
            "A" * 300,
        )
        self.assertEqual(decode_metadata_string_2026("300a"), "0)")
        text = logical_text().replace(
            "[Node01]",
            "ECUAuthKey=" + "AA" * 16 + "\nServiceAuthKey=" + "BB" * 16 + "\n[Node01]",
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(metadata.global_ecu_auth_key_bytes, b"\xaa" * 16)
        self.assertEqual(metadata.global_service_auth_key_bytes, b"\xbb" * 16)
        self.assertEqual(metadata.ecu_auth_key_bytes, b"\x22" * 16)
        self.assertEqual(metadata.service_auth_key_bytes, b"\x11" * 16)
        self.assertEqual(metadata.logical_blocks[0].nonce, b"\x33" * 16)
        self.assertNotEqual(
            metadata.sections["vehicle"]["ecuauthkey"], metadata.vehicle["ecuauthkey"]
        )
        with self.assertRaises(ValueError):
            native2026_metadata(parse_cuw_2026(cuw(text, encode_fields=False)))

    def test_10_12_target_count_and_ignored_ordinary_cpu_aliases(self):
        for version in (10, 12):
            text = (
                cpu_text(version)
                + "NumberOfTargets=100\n01_TargetCalibration=first\n0100_TargetCalibration=hundred\n01=wrong\n01_TargetData=FFFFFFFF\nNewPassword=FE\nP4ServerMaxTime=FF\nSeedKeyID=client-key\n"
            )
            text += "".join(
                f"{index:02}_unused=x\n{index:02}_TargetCalibration=target{index}\n"
                for index in range(2, 100)
            )
            metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
            targets = native2026_cpu_targets(metadata)
            self.assertEqual(
                (targets[0].calibration, targets[99].calibration), ("first", "hundred")
            )
            self.assertTrue(all(item.password == 0 for item in targets))
            self.assertEqual(metadata.cpu.values["seedkeyid"], "client-key")
            self.assertEqual(metadata.cpu.values["newpassword"], "")
            self.assertEqual(native2026_cpu_p4_server_max_time(metadata), 0)

    def test_mixed_logical_cpu_empty_tail_has_no_exported_cpu(self):
        text = logical_text().replace("NumberOfNode=1", "NumberOfNode=2")
        text += "[Node02]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n[CPU21]\n"
        container = parse_cuw_2026(cuw(text, (b"logical", b"unused-empty-cpu")))
        metadata = native2026_metadata(container)
        self.assertEqual(native2026_cpu_count(metadata), 1)
        self.assertEqual(native2026_node_cpu_count(metadata, 1), 0)
        with self.assertRaises(ValueError):
            native2026_metadata(container, node=2)

    def test_native_cpu_count_stops_at_first_empty_row(self):
        text = cpu_text(7).replace("NumberOfCalibration=1", "NumberOfCalibration=3")
        text += "[CPU02]\n[CPU03]\nCPUType=late\nCPUImageName=late.vbf\n"
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(native2026_cpu_count(metadata), 1)
        self.assertEqual(len(metadata.cpu_rows), 1)
        self.assertEqual(
            native2026_cpu_count(
                native2026_metadata(
                    parse_cuw_2026(cuw(text.replace("Version=7", "Version=4")))
                )
            ),
            1,
        )
        with self.assertRaises(ValueError):
            native2026_metadata(parse_cuw_2026(cuw(text, (b"a", b"b", b"c"))))
        text = "[Format]\nVersion=7\n[Vehicle]\nNumberOfCalibration=1\n[CPU01]\nNumberOfTargets=1\n01_TargetData=1\n"
        with self.assertRaises(ValueError):
            native2026_metadata(parse_cuw_2026(cuw(text)))
        text += "01_TargetCalibration=target\n"
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(native2026_cpu_count(metadata), 1)

    def test_target_array_native_gap_validation_and_empty_tail(self):
        for version in (7, 8, 10, 12, 105):
            text = cpu_text(version) + "NumberOfTargets=3\n01_TargetCalibration=first\n"
            if version >= 101:
                text = text.replace("NumberOfCalibration=1", "NumberOfNode=1").replace(
                    "[CPU01]",
                    "[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n[CPU11]",
                )
            metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
            self.assertEqual(
                tuple(item.calibration for item in native2026_cpu_targets(metadata)),
                ("first", "", ""),
            )
            with self.assertRaises(ValueError):
                native2026_metadata(
                    parse_cuw_2026(cuw(text + "03_TargetCalibration=gap\n"))
                )
        # 05e80 checks declared rows even after06230 would stop at an empty CPU.
        text = cpu_text(7).replace("NumberOfCalibration=1", "NumberOfCalibration=3")
        text += "[CPU02]\n[CPU03]\nNumberOfTargets=1\n01_TargetData=1\n"
        with self.assertRaises(ValueError):
            native2026_metadata(parse_cuw_2026(cuw(text)))

    def test_large_logical_descriptor_addresses_follow_native_source_fields(self):
        for version, method in ((107, "00"), (209, "00"), (500, "00"), (500, "02")):
            text = logical_text(version).replace(
                "ReproMethod=02", f"ReproMethod={method}"
            )
            text += "[EraseAndReproRoutine101]\nStartAddress=2000\nLength=1\n"
            records = (
                (b"routine", b"image")
                if version == 500 and method != "00"
                else (b"image",)
            )
            metadata = native2026_metadata(parse_cuw_2026(cuw(text, records)))
            block = metadata.logical_blocks[0]
            for area in block.areas:
                if (
                    area.kind not in ("ReproData", "EraseAndReproRoutine")
                    or area.record is None
                ):
                    continue
                with (
                    patch(
                        "scripts.cuw_large.materialize_large_record_2026",
                        side_effect=RuntimeError("captured"),
                    ) as materialize,
                    self.assertRaisesRegex(RuntimeError, "captured"),
                ):
                    _large_logical_archive(metadata, block, area)
                expected = (0x1000, 0x2000, None, None)
                if version == 500 and method != "00":
                    expected = (
                        0x2000 if area.kind == "EraseAndReproRoutine" else 0x1000,
                        None,
                        None,
                        None,
                    )
                self.assertEqual(materialize.call_args.kwargs["addresses"], expected)

    def test_logical_cpu_targets_merge_by_newcid_before_native_gap_validation(self):
        text = logical_text().replace("NumberOfTargets=1", "NumberOfTargets=2")
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(native2026_cpu_p4_server_max_time(metadata), 0)
        self.assertEqual(metadata.logical_blocks[0].routine_response_pending_limit, 900)
        self.assertEqual(
            tuple(item.calibration for item in native2026_cpu_targets(metadata)),
            ("authored-old", ""),
        )
        with self.assertRaises(ValueError):
            native2026_metadata(
                parse_cuw_2026(
                    cuw(
                        text.replace("NumberOfTargets=2", "NumberOfTargets=3").replace(
                            "01_TargetCalibration=authored-old",
                            "01_TargetCalibration=authored-old\n03_TargetCalibration=later",
                        )
                    )
                )
            )
        text = logical_text().replace(
            "NumberOfLogicalBlock=1", "NumberOfLogicalBlock=2"
        )
        text += (
            "[LogicalBlock102]\nNewCID=authored-new\nNumberOfTargets=2\n"
            "01_TargetCalibration=second\n02_TargetCalibration=authored-old\n"
            "ReproMethod=02\nNonce="
            + "00" * 16
            + "\n[ReproData102]\nStartAddress=2000\nLength=1\n"
        )
        metadata = native2026_metadata(
            parse_cuw_2026(cuw(text, (b"a", b"b"))), cpu_index=1
        )
        self.assertEqual(native2026_cpu_count(metadata), 1)
        self.assertEqual(
            tuple(item.calibration for item in native2026_cpu_targets(metadata, 0)),
            ("authored-old", "second"),
        )

    def test_native_cpu_type_state_transition_retains_original_source(self):
        metadata = native2026_metadata(parse_cuw_2026(cuw(cpu_text(7))))
        changed = native2026_with_cpu_type(metadata, 0, "identified-type")
        self.assertEqual(native2026_cpu_type(changed), "identified-type")
        self.assertEqual(changed.cpu.values["cputype"], "identified-type")
        self.assertEqual(native2026_cpu_type(metadata), "311")
        exported = native2026_export_state(changed, shrink_flag=False)
        self.assertEqual(exported.cpu_types, ("identified-type",))
        self.assertFalse(exported.shrink_flag)
        self.assertIs(changed.sections, metadata.sections)
        self.assertEqual(changed.source_sha256, metadata.source_sha256)
        self.assertEqual(native2026_node_index(changed), 0)
        with self.assertRaises(ValueError):
            native2026_with_cpu_type(metadata, 1, "invalid-index")

    def test_usb_archive_header_is_not_a_materialized_cpu_image(self):
        wrong_field = native2026_metadata(
            parse_cuw_2026(cuw(cpu_text(12).replace("KindOfECU=149", "KindOfECU=0795")))
        )
        self.assertEqual(native2026_archive(wrong_field).data, b"data")
        metadata = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    cpu_text(12).replace(
                        "KindOfECU=149", "KindOfECU=149\nCANIDTx_Phys_USDT=0795"
                    ),
                    (b"\x00" * 12,),
                )
            )
        )
        with self.assertRaises(ValueError):
            native2026_archive(metadata)

    def test_archive_vbf_classification_uses_global_cpu_zero(self):
        text = "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=2\n[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n[CPU11]\nCPUImageName=first.vbf\n[Node02]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n[CPU21]\nCPUImageName=second.raw\n"
        metadata = native2026_metadata(
            parse_cuw_2026(cuw(text, (b"ONE", b"TWO"))), node=2
        )
        self.assertEqual(native2026_archive(metadata).data, b"TWO")
        text = text.replace("first.vbf", "first.raw").replace(
            "second.raw", "second.vbf"
        )
        payload = srecord(3, 0, b"TWO") + b"\n"
        metadata = native2026_metadata(
            parse_cuw_2026(cuw(text, (b"ONE", payload))), node=2
        )
        self.assertEqual(native2026_archive(metadata).data, b"TWO")

    def test_srecord_canonical_span_uses_first_and_last_source_rows(self):
        data = srecord(3, 0x2000, b"a") + b"\n" + srecord(3, 0x1000, b"b") + b"\n"
        with self.assertRaises(ValueError):
            materialize_srecords_2026(data)
        retained = materialize_srecords_2026(data, preserve=True)
        self.assertEqual(retained.records, ((0x2000, b"a"), (0x1000, b"b")))
        self.assertIsNone(retained.data)

    def test_metadata9_file_materialization_alfid_and_native_half_count(self):
        text = (
            cpu_text(9)
            + "NumberOfFiles=2\n[File1001]\nALFID=24\nDownloadAddress=10\nDownloadMemsize=3\n[File1002]\nALFID=22\nDownloadAddress=20\nDownloadMemsize=5\n"
        )
        payload = srecord(0, 0, b"HDR") + b"\n" + srecord(3, 0x1000, b"abc") + b"\n"
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (payload, b"ABCDE"))))
        first, second = native2026_cpu_files(metadata)
        self.assertEqual(
            (first.values["downloadaddress"], first.values["downloadmemsize"]),
            ("00001010", "0003"),
        )
        self.assertEqual(
            (second.values["downloadaddress"], second.values["downloadmemsize"]),
            ("0020", "0005"),
        )
        archive = native2026_archive(metadata)
        self.assertEqual(
            (archive.data, archive.header, archive.flash_size), (b"abc", b"HDR", 0)
        )
        self.assertEqual(native2026_archive(metadata, file_index=1).data, b"ABCDE")
        self.assertEqual(native2026_cpu_file_flash_size(metadata), 3)
        self.assertEqual(native2026_file_index(metadata), 0)
        self.assertEqual(metadata.sections["file1001"]["downloadaddress"], "10")
        with self.assertRaises(ValueError):
            native2026_metadata(
                parse_cuw_2026(
                    cuw(text.replace("ALFID=24", "ALFID=54"), (payload, b"ABCDE"))
                )
            )

    def test_metadata4_multiple_srecord_archive_outputs(self):
        def payload(address, value):
            return (
                b"\r\n".join(
                    (srecord(0, 0, b"HDR"), srecord(3, address, value), srecord(7, 0))
                )
                + b"\r\n"
            )

        text = cpu_text(4) + "01_CPUImageName=ONE\n03_CPUImageName=THREE\n"
        metadata = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    text,
                    (payload(0x1000, b"ab"), payload(0x2000, b"xyz"), payload(0, b"F")),
                    count=2,
                )
            )
        )
        first = native2026_archive(metadata)
        second = native2026_archive(metadata, file_index=1)
        self.assertEqual((first.data, first.header, first.flash_size), (b"ab", b"", 5))
        self.assertEqual(
            (second.data, second.header, second.flash_size), (b"xyz", b"", 3)
        )
        self.assertEqual((first.length, second.length), (0, 0))
        self.assertEqual((first.record_count, second.record_count), (0, 0))
        flash = native2026_archive(metadata, flash_code=True)
        self.assertEqual((flash.data, flash.flash_size, flash.header), (b"F", 0, b""))
        text = text.replace("NumberOfCalibration=1", "NumberOfCalibration=2")
        text += "[CPU02]\nCPUType=312\nCPUImageName=second\n"
        metadata = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    text,
                    (payload(0x1000, b"ab"), payload(0x2000, b"xyz"), payload(0, b"F")),
                    count=2,
                )
            ),
            cpu_index=1,
        )
        self.assertEqual(native2026_cpu_count(metadata), 2)
        self.assertEqual(native2026_archive(metadata).data, b"xyz")
        self.assertEqual(native2026_archive(metadata).length, 0)
        self.assertEqual(metadata.cpu.files, ())
        self.assertIsNone(native2026_archive(metadata, flash_code=True).data)

    def test_global_cpu_count_includes_unselected_nodes_and_deduplicates(self):
        text = logical_text().replace("NumberOfNode=1", "NumberOfNode=2")
        text += "[Node02]\nRequiredSpecReproVer=02\nNumberOfCalibration=2\n[CPU21]\nCPUType=A\nCPUImageName=one.vbf\n[CPU22]\nCPUType=B\nCPUImageName=two.vbf\n"
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (b"a", b"b", b"c"))))
        self.assertEqual(native2026_cpu_count(metadata), 3)
        self.assertEqual(native2026_node_count(metadata), 2)
        self.assertEqual(metadata.report()["cpu_count"], 3)
        self.assertEqual(metadata.report()["selected_node_cpu_count"], 1)
        self.assertEqual(native2026_node_index(metadata, 2), 1)
        self.assertEqual(native2026_node_cpu_count(metadata, 0), 1)
        self.assertEqual(native2026_node_cpu_count(metadata, 1), 2)
        text = text.replace("NumberOfLogicalBlock=1", "NumberOfLogicalBlock=2")
        text += (
            "[LogicalBlock102]\nNewCID=authored-new\nReproMethod=02\nNonce="
            + "00" * 16
            + "\n[ReproData102]\nStartAddress=2000\nLength=1\n"
        )
        metadata = native2026_metadata(
            parse_cuw_2026(cuw(text, (b"a", b"b", b"c", b"d"))), cpu_index=1
        )
        self.assertEqual(native2026_cpu_count(metadata), 3)
        self.assertEqual(native2026_node_cpu_count(metadata, 0), 1)
        self.assertEqual(native2026_global_cpu_index(metadata), 0)
        historical = native2026_metadata(parse_cuw_2026(cuw(cpu_text())))
        self.assertEqual(native2026_cpu_count(historical), 1)
        self.assertEqual(native2026_node_count(historical), 0)
        with self.assertRaises(ValueError):
            native2026_node_cpu_count(historical, 0)

    def test_archive_password_ignores_cpu_new_password(self):
        metadata = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    cpu_text(7).replace("[CPU01]", "[CPU01]\nNewPassword=FE"),
                    (b"\x01\x02\x03\x04",),
                )
            )
        )
        parameters = {"PasswordAddress": "0", "ByteOrder": "0"}
        self.assertEqual(native2026_new_password(metadata, parameters), 0xFE)
        self.assertEqual(
            native2026_archive_password(native2026_archive(metadata), parameters),
            0x04030201,
        )
        self.assertEqual(
            native2026_archive_password(
                native2026_archive(metadata), {**parameters, "ByteOrder": "1"}
            ),
            0x01020304,
        )

    def test_actual_10_12_variable_address_geometry_and_raw_archive(self):
        for version in (10, 12):
            raw = cuw(cpu_text(version))
            metadata = native2026_metadata(parse_cuw_2026(raw))
            geometry = native2026_download_geometry(metadata)
            self.assertEqual(geometry.start_address, bytes.fromhex("0100001000"))
            self.assertEqual(
                (geometry.uncompressed_size, geometry.download_size), (32, 4)
            )
            self.assertEqual(native2026_archive(metadata).data, b"data")
            self.assertEqual(metadata.source_sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(
                native2026_selection_metadata(parse_cuw_2026(raw))["cpu_type"], ""
            )
        with self.assertRaises(ValueError):
            native2026_download_geometry(
                native2026_metadata(parse_cuw_2026(cuw(cpu_text(7))))
            )

    def test_node_units_gateway_alias_keys_and_logical_32_slot(self):
        metadata = native2026_metadata(parse_cuw_2026(cuw(logical_text(slot=32))))
        self.assertEqual(
            (
                metadata.wakeup_ms,
                metadata.interval_between_frame_ms,
                metadata.emissions_delay_ms,
                metadata.wait_after_programming_ms,
                metadata.charge_local_bus_start_ms,
            ),
            (500, 11, 120, 650, 700),
        )
        self.assertEqual(metadata.gateway_values[0]["gatewaymode"], "02")
        self.assertEqual(metadata.service_auth_key_bytes, b"\x11" * 16)
        self.assertEqual(metadata.ecu_auth_key_bytes, b"\x22" * 16)
        block = metadata.logical_blocks[0]
        self.assertEqual(
            (block.slot, block.did_subtype, block.routine_response_pending_limit),
            (32, 32, 900),
        )
        self.assertEqual(block.device_info, b"\x33" * 16)
        self.assertEqual(block.repro_method_type, 3)
        self.assertEqual(len(block.areas[0].cmac), 64)
        self.assertEqual(len(block.areas[0].digital_signature), 384)
        self.assertNotIn("11111111", repr(metadata))
        with self.assertRaises(TypeError):
            metadata.node_values["protocol"] = "03"  # pyright: ignore[reportIndexIssue]

    def test_500_routine_precedes_whole_and_00_has_no_separate_archive(self):
        metadata = native2026_metadata(
            parse_cuw_2026(cuw(logical_text(500, routine=True), (b"ROUT", b"DATA")))
        )
        self.assertEqual(
            [(area.kind, area.data) for area in metadata.logical_blocks[0].areas],
            [("EraseAndReproRoutine", b"ROUT"), ("ReproData", b"DATA")],
        )
        metadata = native2026_metadata(
            parse_cuw_2026(cuw(logical_text(209, method="00", routine=True)))
        )
        areas = metadata.logical_blocks[0].areas
        self.assertIsNotNone(areas[0].record)
        self.assertIsNone(areas[1].record)

    def test_srecord_native_header_binary_span_flash_size_and_preservation(self):
        data = b"\n".join(
            (
                srecord(0, 0, b"AUTHORED"),
                srecord(3, 0x1000, b"ab"),
                srecord(3, 0x1004, b"cd"),
                srecord(5, 2),
                srecord(7, 0x1000),
            )
        )
        archive = materialize_srecords_2026(data)
        self.assertEqual(archive.data, b"ab\xff\xffcd")
        self.assertEqual(
            (archive.length, archive.flash_size, archive.header, archive.header_length),
            (6, 4, b"AUTHORED", 8),
        )
        self.assertIsNone(materialize_srecords_2026(data, preserve=True).data)
        self.assertEqual(materialize_srecords_2026(data, preserve=True).flash_size, 4)
        self.assertEqual(
            materialize_srecords_2026(data, preserve=True).length, len(data)
        )
        with self.assertRaises(ValueError):
            materialize_srecords_2026(data[:-1] + b"0")
        with self.assertRaises(ValueError):
            materialize_srecords_2026(
                srecord(3, 0, b"ab") + b"\n" + srecord(3, MAX_ADDRESS, b"c")
            )

    def test_lzf_preserves_frames_without_decompressing(self):
        binary = b"ZV\0\0\x04dataZV\x01\0\x02\0\x08xx"
        self.assertEqual(
            decode_lzf_hex_frames_2026(binary.hex().upper().encode()), binary
        )
        for data in (b"5A5602", b"5A56000004AA", b"5A56000000", b"5A56 00000100"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode_lzf_hex_frames_2026(data)

    def test_mixed_node_archive_order_and_cpu_associations(self):
        text = logical_text(209).replace("NumberOfNode=1", "NumberOfNode=2")
        text += (
            "[Node02]\nNumberOfCalibration=1\nRequiredSpecReproVer=02\n"
            "[CPU21]\nCPUType=311\nCPUImageName=authored.vbf\n"
        )
        container = parse_cuw_2026(cuw(text, (b"LOGI", b"CPU2")))
        logical = native2026_metadata(container)
        cpu = native2026_metadata(container, node=2)
        self.assertEqual(logical.logical_blocks[0].cpu_index, 0)
        self.assertEqual((cpu.cpu.index, cpu.image_bytes), (1, b"CPU2"))
        with self.assertRaises(ValueError):
            native2026_metadata(dataclasses.replace(container, declared_count=1))

    def test_intel_hex_retains_native_address_map(self):
        data = b":020000040001F9\n:041000006162636462\n:00000001FF"
        result = materialize_intel_hex_2026(data)
        self.assertIsNone(result.data)
        self.assertEqual(result.records, ((0x11000, b"abcd"),))
        self.assertEqual((result.length, result.flash_size), (len(data), 4))
        for invalid in (
            data[:-1] + b"0",
            data.splitlines()[1],
            data + b"\n:00000001FF",
        ):
            with self.assertRaises(ValueError):
                materialize_intel_hex_2026(invalid)

    def test_actual_historical_getters_targets_and_password_order(self):
        for version in (2, 3):
            text = cpu_text(version).replace("KindOfECU=149", "KindOfECU=ENG & ECT")
            text = text.replace("CPUType=311", "ECUType=MPC565CAN")
            text = text.replace("ContactType=P5-Unified", "ContactType=SIL")
            metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
            self.assertEqual(
                (metadata.vehicle["kindofecu"], native2026_cpu_type(metadata)),
                ("0", "9"),
            )
            self.assertEqual(metadata.sections["vehicle"]["kindofecu"], "ENG & ECT")
            self.assertEqual(native2026_archive(metadata).data, b"data")
            year_text = text.replace("[CPU01]", "ModelYear= +2006tail\n[CPU01]")
            year_metadata = native2026_metadata(parse_cuw_2026(cuw(year_text)))
            self.assertEqual(
                year_metadata.vehicle["modelyear"],
                "06" if version == 2 else "+2006tail",
            )
            self.assertEqual(
                year_metadata.sections["vehicle"]["modelyear"], "+2006tail"
            )
        text = cpu_text(2).replace("KindOfECU=149", "KindOfECU=ENG & ECT")
        text = text.replace("CPUType=311", "ECUType=MPC565CAN")
        for value, expected in (
            ("2006", "06"),
            ("-1", "-1"),
            ("-101", "-1"),
            ("2147483647", "47"),
            ("-2147483600", "00"),
            ("+00000000000000002006tail", "06"),
        ):
            metadata = native2026_metadata(
                parse_cuw_2026(
                    cuw(text.replace("[CPU01]", f"ModelYear={value}\n[CPU01]"))
                )
            )
            self.assertEqual(metadata.vehicle["modelyear"], expected)
        for value in ("x", "2147483648", "-2147483649", "-99"):
            with self.assertRaisesRegex(ValueError, "ModelYear"):
                native2026_metadata(
                    parse_cuw_2026(
                        cuw(text.replace("[CPU01]", f"ModelYear={value}\n[CPU01]"))
                    )
                )
        for version in (5, 6, 7, 8, 40):
            text = (
                cpu_text(version)
                + "NumberOfTargets=1\n01_TargetCalibration=OLD\n01_TargetData=12345678\n"
            )
            metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
            self.assertEqual(
                native2026_cpu_targets(metadata)[0].password,
                0 if version == 8 else 0x12345678,
            )
            self.assertEqual(
                native2026_new_password(
                    metadata, {"PasswordAddress": "0", "ByteOrder": "0"}
                ),
                int.from_bytes(b"data", "little"),
            )
            self.assertEqual(
                native2026_new_password(
                    metadata, {"PasswordAddress": "0", "ByteOrder": "1"}
                ),
                int.from_bytes(b"data", "big"),
            )
            self.assertEqual(
                native2026_new_password(
                    metadata, {"PasswordAddress": "0", "ByteOrder": "65536"}
                ),
                int.from_bytes(b"data", "little"),
            )
            with self.assertRaises(ValueError):
                native2026_new_password(metadata, {"PasswordAddress": "FFFFFFFF"})

    def test_metadata4_multi_image_and_metadata9_file_count_width(self):
        text = cpu_text(4) + "01_CPUImageName=ONE\n03_CPUImageName=THREE\n"
        metadata = native2026_metadata(
            parse_cuw_2026(cuw(text, (b"one", b"three", b"flash"), count=2))
        )
        self.assertEqual(
            [
                (item.index, item.record.data)
                for item in metadata.cpu.files
                if item.record is not None
            ],
            [(1, b"one"), (3, b"three")],
        )
        flash = metadata.cpu.flash_code
        assert flash is not None
        self.assertEqual(flash.data, b"flash")
        text = (
            cpu_text(9)
            + "NumberOfFiles=1\n[File1001]\nFileName=authored\nALFID=44\nDownloadAddress=0\nDownloadMemsize=4\n"
        )
        container = parse_cuw_2026(cuw(text))
        self.assertEqual(container.count_width, 2)
        metadata = native2026_metadata(container)
        record = metadata.cpu.files[0].record
        assert record is not None
        self.assertEqual(record.data, b"data")
        self.assertIsNone(metadata.cpu.image)

    def test_all_modern_versions_actual_node_container_contexts(self):
        data = b"\n".join(
            (srecord(0, 0, b"HDR"), srecord(3, 0x1000, b"abcd"), srecord(7, 0x1000))
        )
        for version in (101, 103, 104, 105, 106, 107, 206, 209, 300, 400, 500):
            with self.subTest(version=version):
                text = logical_text(version, method="00")
                container = parse_cuw_2026(cuw(text, (data,)))
                metadata = native2026_metadata(container)
                self.assertEqual(
                    native2026_new_calibration_id(metadata), "authored-new"
                )
                self.assertEqual(native2026_cpu_type(metadata), "")
                self.assertEqual(native2026_logical_cpu_flash_size(metadata, 0), 4)
                self.assertEqual(
                    tuple(
                        target.calibration
                        for target in native2026_cpu_targets(metadata)
                    ),
                    ("authored-old",),
                )
                block = metadata.logical_blocks[0]
                archive = native2026_logical_archive(metadata, block, "ReproData")
                if version in (206, 209, 400):
                    self.assertEqual((archive.data, archive.flash_size), (data, 0))
                    self.assertEqual(archive.record_count, 0)
                else:
                    self.assertEqual((archive.data, archive.flash_size), (None, 4))
                    self.assertEqual(archive.record_count, 2)
                    self.assertEqual(
                        make_send_data_records(archive.kind_records, 0x1000, 4), b"abcd"
                    )
                updated = native2026_with_cpu_type(metadata, 0, "311")
                reselected = native2026_metadata_for_cpu(updated, 0)
                self.assertIs(reselected.source_container, container)
                self.assertEqual(native2026_cpu_type(reselected), "311")
                self.assertEqual(
                    native2026_logical_archive(
                        reselected, reselected.logical_blocks[0], "ReproData"
                    ),
                    archive,
                )
                with self.assertRaisesRegex(ValueError, "digest"):
                    native2026_metadata(dataclasses.replace(container, digest="0" * 64))
        for version in (5, 6, 7, 8, 40):
            metadata = native2026_metadata(parse_cuw_2026(cuw(cpu_text(version))))
            self.assertEqual(metadata.format_version, version)

    def test_modern_cpu_values_exclude_unread_aliases(self):
        text = (
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\n"
            "[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
            "[CPU11]\nCPUImageName=authored.vbf\nCPUType=311\nLocationID=1234\n"
            "NumberOfTargetHardwares=1\n01_TargetHardware=unread\nOtherAlias=unread\n"
            "[CPUImage11]\nDataFormatID=unread\nNumberOfAreaSettings=1\n01_StartAddress=10\n01_Length=00\n"
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(metadata.cpu.values["cputype"], "")
        self.assertEqual(metadata.cpu.values["locationid"], "")
        for key in ("numberoftargethardwares", "01_targethardware", "otheralias"):
            self.assertNotIn(key, metadata.cpu.values)
            self.assertIn(key, metadata.sections["cpu11"])
        self.assertEqual(native2026_header_info(metadata).data_format_id, "")
        self.assertEqual(native2026_header_info(metadata).count, 1)
        self.assertEqual(metadata.sections["cpuimage11"]["dataformatid"], "unread")

    def test_nonsecret_fixed_nonce_and_offset_copy_defaults(self):
        for nonce in ("", "12", "AB" * 17):
            text = logical_text().replace("Nonce=" + "33" * 16, "Nonce=" + nonce)
            metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
            expected = bytes.fromhex(nonce)[:16].ljust(16, b"\0")
            self.assertEqual(metadata.logical_blocks[0].nonce, expected)
        text = "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\n[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n[CPU11]\nCPUImageName=authored.vbf\nNonce=12\nOffsetAddress=1234\n"
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(
            native2026_cpu_security_bytes(metadata, "nonce"), b"\x12" + bytes(15)
        )
        self.assertEqual(
            native2026_cpu_security_bytes(metadata, "offsetaddress"),
            b"\x12\x34" + bytes(3),
        )
        historical = native2026_metadata(
            parse_cuw_2026(cuw(cpu_text(7) + "OffsetAddress=FFFFFFFFFF\n"))
        )
        self.assertEqual(
            native2026_cpu_security_bytes(historical, "offsetaddress"), bytes(5)
        )
        with self.assertRaises(ValueError):
            native2026_cpu_security_bytes(metadata, "seedkey")

    def test_historical_schema_ignores_aliases_and_flash_code_length(self):
        text = cpu_text(7) + "OtherAlias=unread\n01_CPUImageName=unread\n"
        text += "[FlashCode01]\nDataFormatID=native\nNumberOfAreaSettings=1\n01_StartAddress=10\n01_Length=AA\n"
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertNotIn("otheralias", metadata.cpu.values)
        self.assertNotIn("01_cpuimagename", metadata.cpu.values)
        header = native2026_header_info(metadata, "flash_code")
        self.assertEqual(
            (header.data_format_id, header.areas[0].length), ("native", "")
        )
        self.assertEqual(metadata.sections["flashcode01"]["01_length"], "AA")
        text = cpu_text(9).replace("NumberOfCalibration=1", "NumberOfCalibration=2")
        text += "NumberOfFiles=130\n[CPU02]\nCPUImageName=second\nNumberOfFiles=130\n"
        with self.assertRaisesRegex(ValueError, "global file count"):
            native2026_metadata(parse_cuw_2026(cuw(text)))

    def test_metadata4_encoded_cpu_cmac_fields(self):
        text = (
            cpu_text(4)
            + "CMACForCPUImageData=01234567\nCMACForFlashCodeData=89ABCDEF\n"
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(native2026_cpu_cmac(metadata), bytes.fromhex("01234567"))
        self.assertEqual(
            native2026_cpu_cmac(metadata, flash_code=True), bytes.fromhex("89ABCDEF")
        )
        ignored = native2026_metadata(
            parse_cuw_2026(cuw(text.replace("Version=4", "Version=7")))
        )
        self.assertEqual(native2026_cpu_cmac(ignored), b"")
        self.assertEqual(native2026_archive(metadata).data, b"data")
        self.assertEqual(native2026_archive(metadata).flash_size, 4)

    def test_native_vehicle_region_projection_and_system_fallback(self):
        keys = ("VehicleType", "EngineType", "VehicleName", "ModelYear")
        text = cpu_text(7).replace("[CPU01]", "System=system-first\n[CPU01]")
        text += "[KindOfCal]\nIsControlledBySCC=1\nIsBlankECU=0\nIsNonFieldFix=1\n"
        for section, prefix in (("VehicleForNA", "NA"), ("VehicleForEUOT", "EU")):
            text += f"[{section}]\n" + "".join(f"{key}={prefix}{key}\n" for key in keys)
        container = parse_cuw_2026(cuw(text))
        for region, expected in (
            (0, "NAEngineType"),
            (1, "EUEngineType"),
            (2, "system-first"),
            (3, "EUEngineType"),
        ):
            metadata = native2026_metadata(container, region=region)
            self.assertEqual(metadata.vehicle["enginetype"], expected)
            self.assertEqual(native2026_metadata_for_cpu(metadata, 0).region, region)
            self.assertTrue(metadata.is_controlled_by_scc)
            self.assertFalse(metadata.is_blank_ecu)
            self.assertTrue(metadata.is_non_field_fix)
        # An empty selected region falls back to a complete available region.
        text = (
            text.split("[VehicleForNA]", 1)[0]
            + "[VehicleForEUOT]"
            + text.split("[VehicleForEUOT]", 1)[1]
        )
        self.assertEqual(
            native2026_metadata(parse_cuw_2026(cuw(text)), region=0).vehicle[
                "enginetype"
            ],
            "EUEngineType",
        )
        blank = native2026_metadata(container, region=0)
        plain = native2026_metadata(
            parse_cuw_2026(cuw(text.replace("IsBlankECU=0", "IsBlankECU=1"))), region=0
        )
        self.assertNotEqual(blank.vehicle["enginetype"], plain.vehicle["enginetype"])
        self.assertEqual(plain.vehicle["enginetype"], "system-first")

    def test_native_date_components_keep_crt_width_and_calendar_semantics(self):
        for value, expected in (
            ("2026-10-20", (2026, 10, 20)),
            (" \t+2026-2-31trailing", (2026, 2, 31)),
            ("-0-1-1", (0, 1, 1)),
            ("2026- 2-012", (2026, 2, 1)),
        ):
            self.assertEqual(native_date_of_issue_components_2026(value), expected)
        for value in (
            "",
            "20260-1-1",
            "2026- 02-1",
            "2026 -1-1",
            "-1-1-1",
            "2026-0-1",
            "2026-1-32",
        ):
            self.assertIsNone(native_date_of_issue_components_2026(value))
        text = cpu_text(7).replace("[CPU01]", "DateOfIssue=2026-02-31tail\n[CPU01]")
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(metadata.date_of_issue_components, (2026, 2, 31))
        self.assertEqual(metadata.sections["vehicle"]["dateofissue"], "2026-02-31tail")

    def test_initial_shrink_flag_uses_all_declared_cpu_targets(self):
        text = (
            cpu_text(7) + "NewCID=same\nNumberOfTargets=1\n01_TargetCalibration=same\n"
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertTrue(metadata.initial_shrink_flag)
        self.assertFalse(
            native2026_metadata(
                parse_cuw_2026(cuw(text.replace("NewCID=same", "NewCID=other")))
            ).initial_shrink_flag
        )
        text = (
            text.replace("NumberOfCalibration=1", "NumberOfCalibration=2") + "[CPU02]\n"
        )
        self.assertFalse(
            native2026_metadata(parse_cuw_2026(cuw(text))).initial_shrink_flag
        )
        logical = logical_text(method="00").replace(
            "01_TargetCalibration=authored-old", "01_TargetCalibration=authored-new"
        )
        self.assertTrue(
            native2026_metadata(parse_cuw_2026(cuw(logical))).initial_shrink_flag
        )

    def test_parser_general_parameters_require_forest_when_any_m16c(self):
        from scripts.programming_2026_common import (
            NativeCallbackLookupError,
            NativeGeneralParameters2026,
        )

        def parameters(forest, second=True):
            rows = f"149P5-Unified311,1,{int(forest)}\r\n"
            if second:
                rows += f"149P5-Unified312,0,{int(forest)}\r\n"
            return NativeGeneralParameters2026.from_sources(
                {
                    "Parameter.ini": (
                        "ParamFileKeySystemProtocolMicon,M16CTypeFlag,FORESTTypeFlag\r\n"
                        + rows
                    ).encode()
                },
                encoded=False,
            )

        text = cpu_text(7).replace("NumberOfCalibration=1", "NumberOfCalibration=2")
        text += "[CPU02]\nCPUType=312\nCPUImageName=second.vbf\n"
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (b"a", b"b"))))
        failing = parameters(False)
        with self.assertRaisesRegex(ValueError, "FOREST"):
            native2026_with_parser_parameters(metadata, failing)
        with self.assertRaises(NativeCallbackLookupError):
            native2026_with_parser_parameters(metadata, parameters(True, second=False))
        with self.assertRaises(TypeError):
            native2026_with_parser_parameters(metadata, object())
        passing = parameters(True)
        checked = native2026_with_parser_parameters(metadata, passing)
        self.assertTrue(checked.parser_parameters_validated)
        self.assertFalse(metadata.parser_parameters_validated)
        selected = native2026_metadata_for_cpu(
            native2026_with_cpu_type(checked, 1, "runtime"), 1
        )
        self.assertTrue(selected.parser_parameters_validated)
        self.assertEqual(native2026_cpu_type(selected, 1), "runtime")
        modern = native2026_metadata(parse_cuw_2026(cuw(logical_text())))
        ignored = parameters(False)
        self.assertTrue(
            native2026_with_parser_parameters(
                modern, ignored
            ).parser_parameters_validated
        )

    def test_logical_zero_length_and_cross_node_global_flash_size(self):
        text = logical_text(209, method="08").replace("Length=00000004", "Length=00")
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, ())))
        area = metadata.logical_blocks[0].areas[0]
        self.assertEqual(area.length, 0)
        self.assertIsNone(area.record)
        empty_address = text.replace("StartAddress=00001000", "StartAddress=")
        self.assertEqual(
            native2026_metadata(parse_cuw_2026(cuw(empty_address, ())))
            .logical_blocks[0]
            .areas[0]
            .address,
            0,
        )
        self.assertEqual(
            native2026_logical_archive(
                metadata, metadata.logical_blocks[0], "ReproData"
            ).length,
            0,
        )
        text = logical_text(209, method="00").replace(
            "NumberOfNode=1", "NumberOfNode=2"
        )
        text += (
            "[Node02]\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=1\n[LogicalBlock201]\nNewCID=second\nReproMethod=00\nNonce="
            + "00" * 16
            + "\n[ReproData201]\nStartAddress=2000\nLength=08\n"
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (b"a", b"b"))))
        self.assertEqual(native2026_logical_cpu_flash_size(metadata, 1), 8)
        selected = native2026_metadata_for_cpu(metadata, 1)
        archive = native2026_archive(selected)
        self.assertEqual(
            (archive.data, archive.length, archive.flash_size), (None, 0, 8)
        )
        self.assertEqual(native2026_archive(selected, flash_code=True).flash_size, 0)
        with self.assertRaises(ValueError):
            native2026_logical_cpu_flash_size(metadata, 2)

    def test_exact_logical_area_fields_and_archive_semantics(self):
        text = logical_text(209).replace(
            "Length=00000004",
            "Length=00000004\nTransferLength=00000003\nCheckData=ABCDEF\nCRC=01",
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        block = metadata.logical_blocks[0]
        area = block.areas[0]
        self.assertEqual(area.crc, b"\x01")
        self.assertEqual(
            (area.length, area.transfer_length, area.check_data),
            (4, 3, bytes.fromhex("ABCDEF")),
        )
        archive = native2026_logical_archive(metadata, block, "ReproData")
        self.assertEqual(
            (archive.data, archive.length, archive.flash_size), (b"data", 4, 0)
        )
        text = logical_text(300, method="00").replace("P4ServerMaxTime=0F\n", "")
        raw = srecord(3, 0x1000, b"ab") + b"\n" + srecord(3, 0x1002, b"cd")
        metadata = native2026_metadata(parse_cuw_2026(cuw(text, (raw,))))
        block = metadata.logical_blocks[0]
        self.assertEqual(block.routine_response_pending_limit, 180)
        archive = native2026_logical_archive(metadata, block, "ReproData")
        self.assertIsNone(archive.data)
        self.assertEqual(archive.kind_records, ((3, 0x1000, b"ab"), (3, 0x1002, b"cd")))
        self.assertEqual(archive.flash_size, 4)

    def test_srecord_first_s1_count_variable_s5_and_flash_checksum_mode2(self):
        data = srecord(1, 0x1000, b"ab") + b"\n" + srecord(1, 0x1002, b"cd")
        count_raw = b"\x04\x00\x00\x02"
        data += (
            b"\nS5"
            + (count_raw + bytes((~sum(count_raw) & 255,))).hex().upper().encode()
        )
        result = materialize_srecords_2026(data, preserve=True)
        self.assertEqual(result.flash_size, 2)
        self.assertEqual(result.kind_records[-1], (5, 2, b""))
        raw = bytes((7,)) + (0x1000).to_bytes(4, "big") + b"ab"
        mode2 = b"S3" + (raw + bytes((-sum(raw) & 255,))).hex().upper().encode()
        self.assertEqual(materialize_srecords_2026(mode2, checksum_mode=2).data, b"ab")
        with self.assertRaises(ValueError):
            materialize_srecords_2026(mode2)
        with self.assertRaises(ValueError):
            decode_lzf_hex_frames_2026(b"5a5600000161")
        bomb = b"ZV\x01\x00\x01\xff\xffx"
        self.assertEqual(
            len(decode_lzf_hex_frames_2026(bomb.hex().upper().encode())), 8
        )

    def test_selector_global_cpu0_is_distinct_from_selected_cpu(self):
        text = (
            "[Format]\nVersion=105\n[Vehicle]\nContactType=P5-Unified\nNumberOfNode=2\n"
            "[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
            "[CPU11]\nCPUType=20\nNewCID=FIRST\nCPUImageName=one.vbf\n"
            "[Node02]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
            "[CPU21]\nCPUType=21\nNewCID=SECOND\nCPUImageName=two.vbf\n"
        )
        container = parse_cuw_2026(cuw(text, (b"ONE", b"TWO")))
        metadata = native2026_metadata(container, node=2)
        self.assertEqual((metadata.cpu.index, metadata.cpu.values["cputype"]), (1, ""))
        self.assertEqual(native2026_cpu_type(metadata, 0), "")
        self.assertEqual(
            native2026_selection_metadata(container, node=2)["cpu_type"], ""
        )
        self.assertEqual(native2026_new_calibration_id(metadata, 1), "SECOND")
        changed = native2026_with_cpu_type(metadata, 0, "runtime-first")
        self.assertEqual(native2026_cpu_type(changed, 0), "runtime-first")
        self.assertEqual(native2026_cpu_type(changed, 1), "")
        first = native2026_metadata_for_cpu(changed, 0)
        self.assertEqual((first.node, first.cpu.index), (1, 0))
        self.assertEqual(native2026_cpu_type(first), "runtime-first")
        second = native2026_metadata_for_cpu(first, 1)
        self.assertEqual((second.node, second.cpu.index), (2, 1))
        self.assertEqual(native2026_cpu_type(second), "runtime-first")

    def test_faults_and_bounds_fail_before_exposing_context(self):
        raw = cuw(cpu_text())
        for data in (raw[:-1], raw + b"x", raw[:40] + bytes((raw[40] ^ 1,)) + raw[41:]):
            with self.assertRaises(ValueError):
                parse_cuw_2026(data)
        for text in (
            cpu_text().replace("NumberOfCalibration=1", "NumberOfCalibration=2"),
            cpu_text().replace("Version=10", "Version=999"),
            cpu_text() + "[vehicle]\nNumberOfCalibration=1\n",
        ):
            with self.assertRaises(ValueError):
                native2026_metadata(parse_cuw_2026(cuw(text)))
        with self.assertRaises(ValueError):
            native2026_metadata(
                dataclasses.replace(parse_cuw_2026(raw), digest="0" * 64)
            )
        original = native2026_metadata(parse_cuw_2026(raw))
        bad = dataclasses.replace(
            original, node_values={"wakeuptimeafterreset": "FFFFFFFF"}
        )
        self.assertEqual(bad.wakeup_ms, (0x7FFFFFFF * 50) & 0xFFFFFFFF)


MAX_ADDRESS = 0x7FFFFFFF

if __name__ == "__main__":
    unittest.main()
