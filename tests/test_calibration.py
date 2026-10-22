import hashlib
import struct
import unittest
import zlib

from scripts.calibration import (
    SIGNATURE,
    VERSIONS,
    bind_native_cpu_records,
    bind_native_logical_records,
    crc16,
    decode_cuw_text,
    inspect_attached_metadata,
    inspect_calibration,
    materialize_native_srecord_area,
    native_selection_metadata,
    parse_cuw,
    parse_srecords,
)


def record(header=b"synthetic", payload=b"authored calibration bytes"):
    return (
        struct.pack(">H", len(header))
        + header
        + struct.pack(">II", len(payload), zlib.crc32(payload))
        + payload
    )


def container(version=1, width=1, count=1, images=None):
    tail = (
        record(b"metadata", b"authored metadata")
        + count.to_bytes(width, "big")
        + (record() if images is None else images)
    )
    raw = (
        SIGNATURE
        + bytes([version])
        + bytes(4)
        + struct.pack(">I", 22 + len(tail))
        + tail
    )
    return raw[:14] + struct.pack(">I", zlib.crc32(raw[18:])) + raw[18:]


def srecord(kind, address, payload=b"", width=None):
    width = width or {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 7: 4, 8: 3, 9: 2}[kind]
    raw = bytes([width + len(payload) + 1]) + address.to_bytes(width, "big") + payload
    return f"S{kind}".encode() + (raw + bytes([~sum(raw) & 255])).hex().upper().encode()


def logical_container(
    method="05", spec="03", kinds=("ReproData",), version=206, payloads=None
):
    metadata = (
        f"[Format]\nVersion={version}\n[Vehicle]\nNumberOfNode=1\nContactType=P5-Unified\n"
        f"[Node01]\nRequiredSpecReproVer={spec}\nNumberOfLogicalBlock=1\n"
        f"[LogicalBlock101]\nNewCID=authored-new\nNumberOfTargets=1\n"
        f"01_TargetCalibration=authored-old\nReproMethod={method}\nNonce={bytes(range(16)).hex()}\n"
    )
    for kind in kinds:
        metadata += (
            f"[{kind}101]\nStartAddress=00001000\nLength=00000004\n"
            f"CRC=01020304\nCMAC={'AA' * 16}\nDigitalSignature={'BB' * 256}\n"
        )
    archived = tuple(
        kind for kind in kinds if version == 206 or kind != "EraseAndReproRoutine"
    )
    tail = record(b"attach.att", metadata.encode()) + bytes([len(archived)])
    tail += b"".join(
        record(kind.encode(), (payloads or {}).get(kind, b"data")) for kind in archived
    )
    raw = SIGNATURE + b"\x65" + bytes(4) + struct.pack(">I", 22 + len(tail)) + tail
    return raw[:14] + struct.pack(">I", zlib.crc32(raw[18:])) + raw[18:]


class LogicalBindingTests(unittest.TestCase):
    def test_native_record_order_all_six_variants(self):
        kinds = (
            "ReproData",
            "EraseAndReproRoutine",
            "DeltaReproData",
            "DeltaEraseAndReproRoutine",
            "CompressionReproData",
            "CompressionEraseAndReproRoutine",
        )
        bound = bind_native_logical_records(parse_cuw(logical_container(kinds=kinds)))
        self.assertEqual(len(bound), 1)
        self.assertEqual(tuple(area.kind for area in bound[0].areas), kinds)
        self.assertEqual(bound[0].nonce, bytes(range(16)))
        self.assertEqual(bound[0].targets, ("authored-old",))
        self.assertEqual(bound[0].slot, 1)
        self.assertNotIn("nonce", repr(bound[0]))

    def test_metadata_record_mismatch_and_invalid_hex_are_rejected(self):
        raw = logical_container()
        for old, new in (
            (b"Length=00000004", b"Length=00000005"),
            (b"NumberOfLogicalBlock=1", b"NumberOfLogicalBlock=2"),
            (b"Nonce=0001", b"Nonce=ZZ01"),
            (b"RequiredSpecReproVer=03", b"RequiredSpecReproVer=02"),
        ):
            parsed = parse_cuw(raw)
            from dataclasses import replace

            with self.assertRaises(ValueError):
                bind_native_logical_records(
                    replace(
                        parsed,
                        attached=replace(
                            parsed.attached, data=parsed.attached.data.replace(old, new)
                        ),
                    )
                )


class NativeMaterializationTests(unittest.TestCase):
    @staticmethod
    def payload(kind=1):
        records = (
            [srecord(1, 0, b"authored native header")]
            if kind == 1
            else [srecord(0, 0, b"authored")]
        )
        records += [
            srecord(kind, 0x1000, b"da"),
            srecord(kind, 0x1002, b"ta"),
            srecord(10 - kind, 0x1000),
        ]
        return b"\n".join(records)

    def test_native_record_selection_and_host_overrun_guards(self):
        for kind in (1, 2, 3):
            data = self.payload(kind)
            self.assertEqual(materialize_native_srecord_area(data, 0x1000, 4), b"data")
            with self.assertRaises(ValueError):
                materialize_native_srecord_area(data, 0x1000, 3)
            with self.assertRaises(ValueError):
                materialize_native_srecord_area(data, 0x1000, 5)
            with self.assertRaises(ValueError):
                materialize_native_srecord_area(data[:-1] + b"0", 0x1000, 4)

    def test_native_first_s1_identification_allows_mixed_s2_s3_data(self):
        data = b"\n".join(
            (
                srecord(1, 0, b"identification"),
                srecord(2, 0x1000, b"da"),
                srecord(3, 0x1002, b"ta"),
                srecord(7, 0x1000),
            )
        )
        self.assertEqual(materialize_native_srecord_area(data, 0x1000, 4), b"data")
        with self.assertRaises(ValueError):
            parse_srecords(data)

    def test_pre206_whole_package_shares_archive_with_image(self):
        parsed = parse_cuw(
            logical_container(
                "01",
                kinds=("ReproData", "EraseAndReproRoutine"),
                version=107,
                payloads={"ReproData": self.payload()},
            )
        )
        bound = bind_native_logical_records(parsed)
        self.assertEqual(len(parsed.records), 1)
        self.assertEqual([area.data for area in bound[0].areas], [b"data", b"data"])
        self.assertIs(bound[0].areas[0].record, bound[0].areas[1].record)

    def test_pre206_delta_image_remains_binary_routine_is_srecord(self):
        bound = bind_native_logical_records(
            parse_cuw(
                logical_container(
                    "07",
                    kinds=("DeltaReproData", "DeltaEraseAndReproRoutine"),
                    version=107,
                    payloads={"DeltaEraseAndReproRoutine": self.payload()},
                )
            )
        )
        self.assertEqual([area.data for area in bound[0].areas], [b"data", b"data"])


def metadata_container(metadata, records, declared_count, width=1):
    tail = record(b"attach.att", metadata.encode()) + declared_count.to_bytes(
        width, "big"
    )
    tail += b"".join(record(name, data) for name, data in records)
    raw = SIGNATURE + b"\x09" + bytes(4) + struct.pack(">I", 22 + len(tail)) + tail
    return raw[:14] + struct.pack(">I", zlib.crc32(raw[18:])) + raw[18:]


class NativeCPUBindingTests(unittest.TestCase):
    def test_original12_metadata102_is_node_cpu_schema(self):
        metadata = (
            "[Format]\nVersion=102\n[Vehicle]\nNumberOfNode=2\n"
            "KindOfECU=1\nContactType=CAN\n"
            "[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=2\n"
            "[Node02]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
        )
        for suffix, cid in (("11", "NEW-A"), ("12", "NEW-B"), ("21", "NEW-C")):
            metadata += (
                f"[CPU{suffix}]\nCPUImageName=authored-{suffix}.vbf\nNewCID={cid}\n"
                f"[CPUImage{suffix}]\nNumberOfAreaSettings=1\n"
                "01_StartAddress=00001000\n01_Length=00000004\n"
            )
        parsed = parse_cuw(
            metadata_container(
                metadata, [(b"a", b"AAAA"), (b"b", b"BBBB"), (b"c", b"CCCC")], 3
            )
        )
        self.assertEqual(
            inspect_attached_metadata(parsed.attached.data)["format_version"], 102
        )
        rows = bind_native_cpu_records(parsed)
        self.assertEqual(
            [(row.node, row.section) for row in rows],
            [(1, "CPU11"), (1, "CPU12"), (2, "CPU21")],
        )
        self.assertEqual(
            [row.image.data for row in rows if row.image], [b"AAAA", b"BBBB", b"CCCC"]
        )
        self.assertEqual(
            native_selection_metadata(parsed, node=2),
            {
                "kind_of_ecu": "1",
                "cpu_type": "",
                "contact_type": "CAN",
                "required_spec": "02",
            },
        )
        alternate_spec = parse_cuw(
            metadata_container(
                metadata.replace("RequiredSpecReproVer=02", "RequiredSpecReproVer=03"),
                [(b"a", b"AAAA"), (b"b", b"BBBB"), (b"c", b"CCCC")],
                3,
            )
        )
        self.assertEqual(len(bind_native_cpu_records(alternate_spec)), 3)
        for old, new in (
            ("NumberOfNode=2", "NumberOfNode=10"),
            ("NumberOfCalibration=2", "NumberOfCalibration=3"),
            ("01_Length=00000004", "01_Length=FFFFFFFF"),
        ):
            with self.subTest(new=new), self.assertRaises(ValueError):
                bind_native_cpu_records(
                    parse_cuw(
                        metadata_container(
                            metadata.replace(old, new),
                            [(b"a", b"AAAA"), (b"b", b"BBBB"), (b"c", b"CCCC")],
                            3,
                        )
                    )
                )

    def test_original12_metadata102_catalog_native_cpu_consumer(self):
        from scripts.calibration_catalog import (
            CalibrationCatalog,
            parse_parameter_table,
        )
        from scripts.demo_calibration import table
        from scripts.programming_legacy import bind_native_cpu_context

        metadata = (
            "[Format]\nVersion=102\n[Vehicle]\nNumberOfNode=1\n"
            "KindOfECU=1\nContactType=CAN\n"
            "[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
            "[CPU11]\nCPUImageName=authored.vbf\nNewCID=AUTHORED-NEW\n"
        )
        parsed = parse_cuw(
            metadata_container(metadata, [(b"authored", bytes(1024))], 1)
        )
        catalog = CalibrationCatalog(
            [
                parse_parameter_table(
                    "1CAN.ini",
                    table(
                        ("ParamFileKeySystemProtocolMicon", "DLLFileNameForFlashWrite"),
                        [("1CAN", "TCUWCanCommonFlashWriter.dll")],
                    ),
                    encoded=False,
                )
            ]
        )
        selection = catalog.select_metadata(
            **native_selection_metadata(parsed), stage="write"
        )
        native = bind_native_cpu_context(
            parsed,
            1,
            ("AUTHORED-OLD",),
            selection,
            stage="write",
            original_executable_build=12,
        )
        self.assertEqual(native.metadata_version, 102)
        self.assertEqual(native.selected.values["newcid"], "AUTHORED-NEW")
        assert native.image is not None
        self.assertEqual(native.image.data, bytes(1024))

    def test_original12_metadata102_cannot_alias18_logical103(self):
        with self.assertRaises(ValueError):
            bind_native_logical_records(parse_cuw(logical_container(version=102)))

    def test_older_cpu_and_optional_flash_record_order(self):
        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\n[CPU01]\nCPUImageName=main\nFlashCodeName=stub\nNewCID=authored-new\n[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000004\nDataFormatID=01\n"
        bound = bind_native_cpu_records(
            parse_cuw(
                metadata_container(
                    metadata, [(b"main", b"data"), (b"stub", b"code")], 1
                )
            )
        )
        self.assertEqual(bound[0].node, 0)
        assert bound[0].image is not None
        self.assertEqual(bound[0].image.data, b"data")
        assert bound[0].flash_code is not None
        self.assertEqual(bound[0].flash_code.data, b"code")
        self.assertEqual(bound[0].image_areas, ((0x1000, 4),))
        self.assertEqual(bound[0].headers["image"]["dataformatid"], "01")
        self.assertNotIn("data", repr(bound[0]))
        with self.assertRaises(TypeError):
            bound[0].values["newcid"] = "other"  # pyright: ignore[reportIndexIssue]

    def test_native_selection_uses_empty_modern_cpu_type_without_alias(self):
        metadata = native_selection_metadata(parse_cuw(logical_container()), node=1)
        self.assertEqual(
            metadata,
            {
                "kind_of_ecu": "",
                "cpu_type": "",
                "contact_type": "P5-Unified",
                "required_spec": "03",
            },
        )
        with self.assertRaises(ValueError):
            native_selection_metadata(parse_cuw(logical_container()), node=2)

    def test_node_cpu_and_format9_file_records(self):
        metadata = "[Format]\nVersion=107\n[Vehicle]\nNumberOfNode=1\n[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n[CPU11]\nCPUImageName=main\nNewCID=authored-new\n[CPUImage11]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000004\n"
        bound = bind_native_cpu_records(
            parse_cuw(metadata_container(metadata, [(b"main", b"data")], 1))
        )
        self.assertEqual((bound[0].node, bound[0].section), (1, "CPU11"))
        self.assertIsNone(bound[0].flash_code)
        metadata = "[Format]\nVersion=9\n[Vehicle]\nNumberOfCalibration=1\n[CPU01]\nNumberOfFiles=1\n[File1001]\nFileName=authored.bin\nDataFormat=00\nDownloadAddress=00001000\nDownloadMemsize=00000004\nALFID=44\n"
        bound = bind_native_cpu_records(
            parse_cuw(metadata_container(metadata, [(b"file", b"data")], 1, 2))
        )
        self.assertIsNone(bound[0].image)
        file_record = bound[0].files[0].record
        assert file_record is not None
        self.assertEqual(file_record.data, b"data")
        self.assertEqual(bound[0].files[0].values["alfid"], "44")


class CalibrationTests(unittest.TestCase):
    def test_cuw_versions_counts_and_checksums(self):
        for version in VERSIONS:
            for width in (1, 2):
                with self.subTest(version=version, width=width):
                    data = container(version, width)
                    parsed = parse_cuw(data)
                    self.assertEqual(parsed.count_width, width)
                    self.assertEqual(parsed.version, version)
                    self.assertEqual(parsed.digest, hashlib.sha256(data).hexdigest())
                    self.assertEqual(
                        parsed.records[0].data, b"authored calibration bytes"
                    )
                    self.assertFalse(
                        inspect_calibration(data)["programming_authorized"]
                    )
        self.assertEqual(
            len(parse_cuw(container(images=record() + record())).records), 2
        )

    def test_cuw_rejects_all_truncations(self):
        data = container()
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                parse_cuw(data[:length])

    def test_cuw_rejects_damage_and_boundaries(self):
        data = container()
        for offset in range(len(data)):
            damaged = bytearray(data)
            damaged[offset] ^= 0x80
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                parse_cuw(bytes(damaged))
        for raw in (
            container(2),
            container(count=0),
            container(count=3),
            container(images=b"\x00"),
            container(images=record(payload=b"x")[:-1]),
            data + b"x",
        ):
            with self.assertRaises(ValueError):
                parse_cuw(raw)
        # Inner checksum remains checked after outer checksum is repaired.
        damaged = bytearray(data)
        damaged[-1] ^= 1
        damaged[14:18] = struct.pack(">I", zlib.crc32(damaged[18:]))
        with self.assertRaisesRegex(ValueError, "framing"):
            parse_cuw(bytes(damaged))

    def test_attached_metadata_bounds_and_secret_omission(self):
        data = b"[Format]\nVersion=9\n[Vehicle]\nNumberOfCalibration=1\n[CPUImage00]\nCPUType=synthetic\nNewCID=new\nSeedKey=must-not-appear\n"
        result = inspect_attached_metadata(data)
        self.assertEqual(result["count_width"], 2)
        self.assertNotIn("must-not-appear", str(result))
        self.assertEqual(result["fields"]["CPUImage00"]["newcid"], "new")
        for bad in (
            b"[Format]\nVersion=999",
            b"[Format]\nVersion=9\nVersion=1",
            b"[Format]\nVersion=9\n[format]\nVersion=1",
            b"[Format]\nVersion=9\n[Vehicle]\nNumberOfCalibration=-1",
            b"\x00",
            b"[DEFAULT]\nx=1\n[Format]\nVersion=9",
        ):
            with self.assertRaises(ValueError):
                inspect_attached_metadata(bad)

    def test_native_nibble_text_all_bytes_and_random_bits(self):
        plain = bytes(range(256))
        for noise in range(4):
            encoded = bytes(
                ((nibble + 8) << 2) | noise
                for byte in plain
                for nibble in (byte >> 4, byte & 15)
            )
            self.assertEqual(decode_cuw_text(encoded), plain)
        for bad in (b"", b" ", b"\x1f ", b" `"):
            with self.assertRaises(ValueError):
                decode_cuw_text(bad)

    def test_crc16_native_vector(self):
        self.assertEqual(crc16(b""), 0)
        self.assertEqual(crc16(b"123456789"), 0x906E)

    def test_srecord_native_supported_families(self):
        for kind in (1, 2, 3):
            for count_width in (2, 3, 4):
                raw = b"\r\n".join(
                    (
                        srecord(0, 0, b"authored"),
                        srecord(kind, 16, b"test"),
                        srecord(5, 1, width=count_width),
                        srecord(10 - kind, 16),
                    )
                )
                parsed = parse_srecords(raw)
                self.assertEqual(parsed["segments"][0]["address"], 16)
                self.assertFalse(parsed["programming_authorized"])

    def test_srecord_malformed(self):
        good = srecord(1, 16, b"test")
        end = srecord(9, 16)
        for lines in (
            (good,),
            (end,),
            (good, end, good),
            (good, srecord(5, 2), end),
            (good, srecord(5, 1), good, end),
            (good, srecord(2, 32, b"x"), end),
            (good, srecord(1, 17, b"x"), end),
            (good, srecord(8, 16)),
            (good[:-1], end),
            (good[:-1] + b"0", end),
            (b"S4FF", end),
            (good, b"", end),
            (good, srecord(0, 0), end),
        ):
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                parse_srecords(b"\n".join(lines))

    def test_no_implicit_formats(self):
        for raw in (b"MZprogram", b"PK\x03\x04archive", b"<xml/>", b"", b"S1030000FC"):
            with self.assertRaises(ValueError):
                inspect_calibration(raw)


class HistoricalSelectionTests(unittest.TestCase):
    def test_metadata_one_uses_native_constructor_contact_and_first_location_kind(self):
        from scripts.calibration import native_selection_metadata

        metadata = "[Format]\nVersion=1\n[Vehicle]\nNumberOfCalibration=1\nECUType=32B 192K\n[CPU01]\nLocationID=0000001300000000\n"
        container = parse_cuw(
            metadata_container(metadata, ((b"authored.vbf", b"data"),), 1)
        )
        self.assertEqual(
            native_selection_metadata(container),
            {
                "kind_of_ecu": "0",
                "cpu_type": "0",
                "contact_type": "SIL",
                "required_spec": "02",
            },
        )

    def test_metadata_two_three_native_name_tables_and_sil_override(self):
        from scripts.calibration import native_selection_metadata

        for version in (2, 3):
            for contact, expected in (("CAN", "10"), ("SIL", "9")):
                metadata = f"[Format]\nVersion={version}\n[Vehicle]\nNumberOfCalibration=1\nContactType={contact}\nKindOfECU=Eng & Ect\n[CPU01]\nECUType=MPC565\n"
                container = parse_cuw(
                    metadata_container(metadata, ((b"authored.vbf", b"data"),), 1)
                )
                self.assertEqual(
                    native_selection_metadata(container),
                    {
                        "kind_of_ecu": "0",
                        "cpu_type": expected,
                        "contact_type": contact,
                        "required_spec": "02",
                    },
                )


if __name__ == "__main__":
    unittest.main()
