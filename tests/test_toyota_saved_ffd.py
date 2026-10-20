"""Authored DDB, chronological TSS3 primitives and malformed source guards."""

import json
import struct
import tempfile
import unittest
from pathlib import Path
from typing import cast

from scripts.monitor_support import MonitorSupportCache
from scripts.profiles import VehicleCatalog
from scripts.toyota import ToyotaCodecError
from scripts.toyota_saved_ffd import (
    ADS_IMAGE_SOURCE_SHA256,
    ADS_OPERATION_SOURCE_SHA256,
    IMAGE_P4_SOURCE_SHA256,
    IMAGE_P5_SOURCE_SHA256,
    LCS_SOURCE_SHA256,
    PCS_OPERATION_SOURCE_SHA256,
    RC_IMAGE_SOURCE_SHA256,
    TSS3_SOURCE_SHA256,
    AdsDdrBitCondition,
    AdsDdrValueDefinition,
    AdsImageRequest18,
    AdsImageSource,
    ImageEcuReference,
    ImageP4Signal,
    ImageP4Source,
    ImageP5Request18,
    ImageP5Source,
    OperationDataId,
    PcsOperationSource,
    RcImageRequest18,
    RcImageSource,
    SavedFfdProvider,
    SavedFfdSource,
    Tss3OperationRequest,
    ads_extract_bits64,
    ads_operation_groups,
    capture_ads_image_groups,
    capture_ads_image_indices,
    capture_ads_image_p5_information,
    capture_ads_image_record,
    capture_ads_image_record_phase,
    capture_ads_image_saved,
    capture_ads_operation_phase,
    capture_ads_saved_operations,
    capture_image_p4_information,
    capture_image_p4_saved,
    capture_image_p4_security,
    capture_image_p5_information,
    capture_image_p5_memorized,
    capture_image_p5_record,
    capture_image_p5_saved,
    capture_image_p5_security,
    capture_lcs_saved_operations,
    capture_pcs_item,
    capture_pcs_operation_phase,
    capture_pcs_saved_operations,
    capture_pvm21_image_p5_information,
    capture_pvm_image_p5_information,
    capture_rc_image_indices,
    capture_rc_image_p5_information,
    capture_rc_image_record_phase,
    capture_rc_image_saved,
    capture_tss3_image_p5_information,
    capture_tss3_saved_operations,
    decode_ads_ddr_group,
    image_p4_ram_layout,
    image_p4_saved_records,
    image_p4_security_key,
    image_p4_signal_definitions,
    image_p5_information,
    rc_image_adjacent_index,
    rc_image_regular_index,
    selected_image_p4_schedule,
    selected_image_p5_schedule,
    tss3_operation_groups,
    tss3_operation_numbers,
    tss3_supported_ids,
)
from scripts.toyota_session import Cancelled, Limits, SessionError


def database(kind, sections):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes((kind, max(sections) + 1))
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, 0x0100032F)
    body = bytearray()
    for slot, (count, payload) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
    return bytes(header + body)


def profile(root, diagnostic=None, condition_variable=b"", *, build=18):
    category = bytearray(76)
    category[:18] = "demo.ddb\0".encode("utf-16le")
    struct.pack_into("<H", category, 68, 42)
    settings = bytearray(16)
    struct.pack_into("<H", settings, 10, 1)
    variable_index = struct.pack("<IH", 0, 2)
    if condition_variable:
        variable_index += struct.pack("<IH", 2, len(condition_variable))
    management = database(
        1,
        {
            0: (
                1 + bool(condition_variable),
                variable_index + b"\xab\x11" + condition_variable,
            ),
            16: (1, category),
            17: (1, struct.pack("<4H", 1, 1, 0, 0)),
            18: (1, struct.pack("<8H", 42, 0x66, 1, 1, 0, 0, 0, 0)),
            29: (1, settings),
        },
    )
    (root / "Toyota.ddb").write_bytes(management)
    (root / "M_English.ddb").write_bytes(database(4, {0: (0, b"")}))
    (root / "demo.ddb").write_bytes(database(2, diagnostic or {10: (0, b"")}))
    if build == 12:
        for name in ("Toyota.ddb", "M_English.ddb", "demo.ddb"):
            raw = bytearray((root / name).read_bytes())
            struct.pack_into("<I", raw, 28, 0x0100030C)
            (root / name).write_bytes(raw)
    return VehicleCatalog(root).build_profile(42)


def image_information_profile(root, build, modes=()):
    selected = profile(root)
    from scripts.diagnostic_db import parse_database

    management = parse_database((root / "Toyota.ddb").read_bytes())
    sections = {
        slot: (item.count, item.payload) for slot, item in management.sections.items()
    }
    sections[0] = (2, struct.pack("<IHIH", 0, 2, 2, 2) + b"\x01\0\x21\0")
    sections[17] = (2, struct.pack("<8H", 1, 1, 0, 0, 2, 2, 0, 0))
    sections[18] = (
        3,
        b"".join(
            struct.pack("<8H", 42, function, 1, communication, 0, 0, 0, 0)
            for function, communication in ((0x0F, 1), (0x13, 1), (0x6B, 2))
        ),
    )
    groups, checks, freezes = [], [], []
    for index in range(10):
        group = bytearray(12)
        struct.pack_into("<H", group, 4, index + 1)
        group[8] = 0x2A + index
        groups.append(bytes(group))
        checks.append(struct.pack("<4H", index + 1, 100 + index, 0, 0))
        freeze = bytearray(84)
        struct.pack_into("<H", freeze, 56, 100 + index)
        struct.pack_into("<HH", freeze, 62, 0, 7)
        freeze[77], freeze[79] = modes[index] if modes else 0, 1
        freezes.append(bytes(freeze))
    support = bytes((0, 0, 0, 0, 0, 1, 0, 0))
    diagnostic = {
        0: (10, b"".join(groups)),
        1: (10, b"".join(checks)),
        3: (1, support),
        6: (1, bytes((0, 0, 1, 1, 0, 0, 0, 0))),
        10: (10, b"".join(freezes)),
    }
    for name, kind, content in (
        ("Toyota.ddb", 1, sections),
        ("demo.ddb", 2, diagnostic),
    ):
        encoded = bytearray(database(kind, content))
        struct.pack_into("<I", encoded, 28, 0x0100030C if build == 12 else 0x0100032F)
        (root / name).write_bytes(encoded)
    return VehicleCatalog(root).build_profile(selected.category)


def internal_image_profile(
    root, variant, *, support_values=False, family="generic", build=18
):
    """Merge authored49 DDR metadata with real77 controller fixture geometry."""
    from test_native_communication import serialized_profile

    from scripts.diagnostic_db import parse_database

    base = (
        Path(__file__).resolve().parents[1]
        / "analysis/evidence/no-car-49/internal-consumer-fixture"
        / variant
    )
    original = parse_database((base / "Toyota.ddb").read_bytes())
    can = serialized_profile(
        version=build, request=b"\x21\x00", mask=b"", check=b""
    ).catalog.management
    sections = {
        key: (section.count, section.payload)
        for key, section in original.sections.items()
    }
    values = tuple(
        bytes.fromhex(value)
        for value in (
            "91000000000000",
            "2100",
            "27010000",
            "27021000",
            "27030000",
            "27042000",
            "220000",
            "1001",
            "81",
            "3e",
            "81",
            "2100",
        )
    )
    if family == "ads":
        values += (bytes.fromhex("2701"),)
    storage, directory = bytearray(), bytearray()
    for value in values:
        directory += struct.pack("<IH", len(storage), len(value))
        storage += value
    sections[0] = (len(values), bytes(directory + storage))
    target_id = 0x1BC if variant == "p5" else 0xBC
    target = bytearray(sections[16][1])
    struct.pack_into("<H", target, 68, target_id)
    image = bytearray(can.sections[16].payload)
    name = "image.ddb\0".encode("utf-16le")
    image[: len(name)] = name
    sections[16] = (2, bytes(image) + bytes(target))
    sections[17] = (
        14 if family == "ads" else 13,
        struct.pack("<4H", 0, 2, 0, 0)
        + sections[17][1]
        + b"".join(
            struct.pack("<4H", index, index, 0, 0)
            for index in range(8, 14 if family == "ads" else 13)
        ),
    )
    functions = []
    for offset in range(0, len(sections[18][1]), 16):
        row = bytearray(sections[18][1][offset : offset + 16])
        struct.pack_into("<H", row, 0, target_id)
        functions.append(bytes(row))
    for category in (42, target_id):
        for function, communication in ((0x67, 8), (0x68, 9), (0x7F, 10), (0x98, 11)):
            functions.append(
                struct.pack("<8H", category, function, 0, communication, 0, 0, 0, 0)
            )
    functions.append(struct.pack("<8H", 42, 0x66, 1, 12, 0, 0, 0, 0))
    if family == "ads":
        functions.append(struct.pack("<8H", 42, 0x109, 1, 13, 0, 0, 0, 0))
    sections[18] = (
        len(functions),
        b"".join(sorted(functions, key=lambda row: struct.unpack_from("<HH", row))),
    )
    communication = bytearray(can.sections[13].payload)
    other = bytearray(communication)
    struct.pack_into("<H", other, 0, target_id)
    sections[13] = (2, bytes(communication) + bytes(other))
    for key in (14, 15, 29, 51):
        sections[key] = (can.sections[key].count, can.sections[key].payload)
    attributes = []
    for offset in range(0, len(sections[54][1]), 44):
        row = bytearray(sections[54][1][offset : offset + 44])
        struct.pack_into("<H", row, 18, target_id)
        row[38] = 0x12
        attributes.append(bytes(row))
    if support_values:
        by_id = {struct.unpack_from("<H", row, 16)[0]: row for row in attributes}
        support_rows = ((170, 103),) if variant == "p5" else ((170, 103), (171, 136))
        for logical, source_logical in support_rows:
            row = bytearray(by_id[source_logical])
            struct.pack_into("<H", row, 16, logical)
            if variant == "p5":
                struct.pack_into(
                    "<HH", row, 20, *((8, 15) if logical == 170 else (32, 63))
                )
            attributes.append(bytes(row))
        attributes.sort(key=lambda row: struct.unpack_from("<H", row, 16)[0])
    sections[54] = (len(attributes), b"".join(attributes))
    module = bytearray(88)
    name = (
        "GetADSImageFFDP5_DT.dll\0" if family == "ads" else "GetImageFFDP5_DT.dll\0"
    ).encode("utf-16le")
    module[: len(name)] = name
    struct.pack_into("<H", module, 80, 42)
    module[86] = 0xE1 if family == "ads" else 0xBB
    sections[19] = (1, bytes(module))
    (root / "Toyota.ddb").write_bytes(database(1, sections))
    for filename in ("demo.ddb", "M_English.ddb"):
        (root / filename).write_bytes((base / filename).read_bytes())
    (root / "image.ddb").write_bytes(database(2, {10: (0, b"")}))
    if build == 12:
        for filename in ("Toyota.ddb", "demo.ddb", "image.ddb", "M_English.ddb"):
            raw = bytearray((root / filename).read_bytes())
            struct.pack_into("<I", raw, 28, 0x0100030C)
            (root / filename).write_bytes(raw)
    return VehicleCatalog(root).build_profile(42), json.loads(
        (base / "primitive-replies.json").read_text()
    )


class SavedFfdTests(unittest.TestCase):
    def test_generic12_retained_internal_normal_then_original_image_outer(self):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            ImageFacadeResult,
            SavedOperationFacadeFreeze,
            SavedOperationFacadeValue,
        )
        from scripts.database_resources import DdrPacketLog
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        for specification in (2, 6, 7, 8):
            with tempfile.TemporaryDirectory() as directory:
                selected, fixture = internal_image_profile(
                    Path(directory),
                    "normal",
                    support_values=specification != 2,
                    build=12,
                )
                if specification != 2:
                    from scripts.diagnostic_db import parse_database

                    management = parse_database(
                        (Path(directory) / "Toyota.ddb").read_bytes()
                    )
                    sections = {
                        key: (item.count, item.payload)
                        for key, item in management.sections.items()
                    }
                    attributes = bytearray(sections[54][1])
                    for offset in range(0, len(attributes), 44):
                        logical = struct.unpack_from("<H", attributes, offset + 16)[0]
                        if logical in (170, 171):
                            attributes[offset + 39] = 0xB2
                            struct.pack_into("<H", attributes, offset + 34, 0x14B2)
                            struct.pack_into(
                                "<HH",
                                attributes,
                                offset + 20,
                                *((16, 31) if logical == 170 else (0, 31)),
                            )
                    sections[54] = (sections[54][0], bytes(attributes))
                    raw = bytearray(database(1, sections))
                    struct.pack_into("<I", raw, 28, 0x0100030C)
                    (Path(directory) / "Toyota.ddb").write_bytes(raw)
                    selected = VehicleCatalog(Path(directory)).build_profile(42)
                information = bytearray(70)
                information[:3], information[6] = bytes.fromhex("621202"), 12
                for offset in range(7, 35, 4):
                    information[offset : offset + 4] = (13).to_bytes(4, "big")
                information[35:39] = (0x1000).to_bytes(4, "big")
                information[65] = 1
                header = bytearray.fromhex("630f0012340102030400000000")
                scalar = 0x1234 if specification == 2 else 0x5678
                header[3:5] = scalar.to_bytes(2, "big")
                header[9] = sum(header[1:9]) & 255
                replies = {
                    bytes.fromhex(key): bytes.fromhex(value)
                    for key, value in fixture["responses_hex"].items()
                }
                replies.update(
                    {
                        bytes.fromhex("2100"): bytes.fromhex("6100"),
                        bytes.fromhex("221201"): bytes.fromhex("621201020201010101"),
                        bytes.fromhex("2703"): b"\x67\x03" + bytes(6),
                        bytes.fromhex("221203"): bytes.fromhex(
                            "6212030100000001000000"
                        ),
                        bytes.fromhex("221204"): b"\x62",
                        bytes.fromhex("222090"): b"\x62",
                        bytes.fromhex("221202"): bytes(information),
                        bytes.fromhex("231501000010000c"): bytes(header),
                        bytes.fromhex("2315010000100c01"): b"\x63",
                    }
                )

                replies[bytes.fromhex("2214f0")] = bytes.fromhex(
                    "6214f0"
                ) + specification.to_bytes(2, "big")
                replies[bytes.fromhex("2214b2")] = bytes.fromhex("6214b2f1234567")

                class Fixture(J2534Fixture):
                    request = b""

                    def invoke(self, operation, fields, *, replies=replies, **kwargs):
                        if operation == "write_messages":
                            self.request = fields["messages"][0].data[4:]
                        if operation == "read_messages":
                            self.calls.append((operation, dict(fields)))
                            reply = (
                                bytes.fromhex("67010000")
                                if self.request
                                in (
                                    bytes.fromhex("27010000"),
                                    bytes.fromhex("27030000"),
                                )
                                else replies[self.request]
                            )
                            return J2534Result(
                                count=1,
                                messages=(
                                    NativeMessage(
                                        6, 0, 0, 0, 0, bytes.fromhex("000007e8") + reply
                                    ),
                                ),
                            )
                        return super().invoke(operation, fields, **kwargs)

                backend = Fixture([])
                channel = NativeCommunication.from_backend(
                    selected,
                    backend,
                    "original12-image",
                    first_request=b"\x21\x00",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=12,
                    clock=lambda: 0.0,
                )
                assert isinstance(channel.operations, NativeFrameController)
                logger = DdrPacketLog(Path(directory) / "logs", channel.operations)
                result = capture_image_p5_saved(
                    channel,
                    logger,
                    ImageP5Source(12, IMAGE_P5_SOURCE_SHA256[12]),
                    bytes(6),
                )
                self.assertEqual(result.native_status, 0)
                self.assertEqual(
                    result.ddr_status,
                    0,
                    [
                        (operation, fields["messages"][0].data[4:].hex())
                        for operation, fields in backend.calls
                        if operation == "write_messages"
                    ],
                )
                self.assertIsNotNone(result.ddr_report)
                from scripts.database_resources import ddr_report_support_values

                assert result.ddr_report is not None
                supports = ddr_report_support_values(result.ddr_report)
                self.assertEqual(
                    tuple((item.present, item.value) for item in supports),
                    ((False, 0), (False, 0))
                    if specification == 2
                    else ((True, 0x4567), (True, 0x11234567)),
                )
                self.assertEqual(tuple(row.scalar for row in result.records), (scalar,))
                self.assertIsNone(logger._file)
                self.assertTrue(channel.closed)
                writes = [
                    fields["messages"][0].data[4:].hex()
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(
                    writes[:5], ["2100", "27030000", "27010000", "221421", "2214f0"]
                )
                self.assertEqual("2214b2" in writes, specification != 2)
                self.assertNotIn("2214b1", writes)
                self.assertFalse(any(request.startswith("91") for request in writes))
                self.assertEqual(writes[-2:], ["231501000010000c", "2315010000100c01"])

                public_backend = Fixture([])
                public_channel = NativeCommunication.from_backend(
                    selected,
                    public_backend,
                    "original12-public",
                    first_request=b"\x21\x00",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=12,
                    clock=lambda: 0.0,
                )
                assert isinstance(public_channel.operations, NativeFrameController)
                public_log = DdrPacketLog(
                    Path(directory) / "public-logs", public_channel.operations
                )
                api = CommandAPI(CommandSource(12, SOURCE_SHA256[12]))
                prior = ImageFacadeResult(
                    0,
                    (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),),
                    (7, 8, 9),
                )
                output = api.get_image_ffd_p5(
                    public_channel, public_log, bytes(6), previous=prior
                )
                self.assertEqual(output.return_code, 0)
                self.assertEqual(output.native_fields18, (7, 8, 9))
                self.assertEqual(
                    tuple(row.values[0].scalar for row in output.freezes), (99, scalar)
                )
                self.assertIsNone(public_log._file)
                self.assertTrue(public_channel.closed)
                saved = json.loads(json.dumps(api.image_ffd_report(output)))
                self.assertNotIn("raw_reply", json.dumps(saved))
                public_writes = [
                    fields["messages"][0].data[4:].hex()
                    for operation, fields in public_backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(public_writes, writes)

    def test_rc_complete_outer_provided_support_and_seven_blocks(self):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture

        from scripts.database_resources import DdrP5SupportValue, DdrPacketLog
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        for mode in ("success", "bodyfault", "metadatafault", "cancel"):
            with tempfile.TemporaryDirectory() as directory:
                selected, _fixture = internal_image_profile(Path(directory), "normal")
                mapping = {
                    "2100": "6100",
                    "221103": "6211030200",
                    "221126": "621126010201",
                    "2703": "6703000000000000",
                    "222031": "62203100",
                    "221129": "62112933003500",
                    "22112c": "62112c0100",
                    "22112f": "62112f000100",
                    "221132": "62",
                    "221130": "62",
                    "221133": "62",
                    "ab31": "eb313300",
                }
                if mode == "metadatafault":
                    mapping["221103"] = "6211030100"
                for block in range(1, 8):
                    index = rc_image_regular_index(block, 1, 1)
                    key = "ab333300" + index.to_bytes(4, "big").hex()
                    mapping[key] = (
                        "7fab23"
                        if mode == "bodyfault" and block == 4
                        else "eb333300"
                        + index.to_bytes(4, "big").hex()
                        + ("010501021234" if block == 1 else "")
                    )
                replies = {
                    bytes.fromhex(key): bytes.fromhex(value)
                    for key, value in mapping.items()
                }
                cancelled = [False]

                class Fixture(J2534Fixture):
                    request = b""

                    def invoke(
                        self,
                        operation,
                        fields,
                        *,
                        replies=replies,
                        mode=mode,
                        cancel_state=cancelled,
                        **kwargs,
                    ):
                        if operation == "write_messages":
                            self.request = fields["messages"][0].data[4:]
                        if operation == "read_messages":
                            self.calls.append((operation, dict(fields)))
                            if mode == "cancel" and self.request == bytes.fromhex(
                                "22112c"
                            ):
                                cancel_state[0] = True
                            return J2534Result(
                                count=1,
                                messages=(
                                    NativeMessage(
                                        6,
                                        0,
                                        0,
                                        0,
                                        0,
                                        bytes.fromhex("000007e8")
                                        + replies[self.request],
                                    ),
                                ),
                            )
                        return super().invoke(operation, fields, **kwargs)

                backend = Fixture([])
                channel = NativeCommunication.from_backend(
                    selected,
                    backend,
                    "rc-full",
                    first_request=b"\x21\x00",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=18,
                    clock=lambda: 0.0,
                    cancelled=lambda cancelled=cancelled: cancelled[0],
                )
                assert isinstance(channel.operations, NativeFrameController)
                logger = DdrPacketLog(Path(directory) / "logs", channel.operations)
                args = (
                    channel,
                    logger,
                    RcImageSource(18, RC_IMAGE_SOURCE_SHA256),
                    bytes(6),
                    RcImageRequest18(
                        (1,), ddr_support=DdrP5SupportValue(170, False, 0)
                    ),
                )
                if mode == "cancel":
                    with self.assertRaises(Cancelled):
                        capture_rc_image_saved(*args)
                else:
                    result = capture_rc_image_saved(*args)
                    self.assertEqual(
                        result.native_status,
                        0x90040501 if mode == "metadatafault" else 0,
                    )
                    self.assertTrue(result.ddr_provided)
                    self.assertIsNone(result.ddr_report)
                    if mode != "metadatafault":
                        assert result.phase is not None
                        self.assertEqual(
                            len(result.phase.freezes), 1 if mode == "success" else 0
                        )
                        self.assertEqual(
                            len(result.phase.acquisitions[0].blocks),
                            4 if mode == "bodyfault" else 7,
                        )
                self.assertIsNone(logger._file)
                self.assertTrue(channel.closed)
                writes = [
                    fields["messages"][0].data[4:].hex()
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(
                    writes[:5],
                    ["2100", "221103", "221126", "2703", "222031"]
                    if mode != "metadatafault"
                    else ["2100", "221103"],
                )
                self.assertNotIn("27030000", writes)
                if mode == "bodyfault":
                    self.assertNotIn(b"7FAB23", logger.path.read_bytes())

    def test_rc_actual_seven_block_regular_adjacent_duplicate_and_rollback(self):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture, serialized_profile

        from scripts.database_resources import DdrP5SupportValue, DdrPacketLog
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        for mode in ("success", "fault", "filter"):
            selected = serialized_profile(request=b"\x21\x00", mask=b"", check=b"")
            sections = {
                key: (item.count, item.payload)
                for key, item in selected.catalog.management.sections.items()
            }
            count, rows = sections[18]
            rows += struct.pack("<8H", 42, 0x66, 1, 0, 0, 0, 0, 0)
            sections[18] = (
                count + 1,
                b"".join(
                    sorted(
                        (
                            rows[offset : offset + 16]
                            for offset in range(0, len(rows), 16)
                        ),
                        key=lambda row: struct.unpack_from("<HH", row),
                    )
                ),
            )
            selected.catalog.management = parse_database(database(1, sections))
            metadata = {
                "2100": "6100",
                "221129": "62112933003500",
                "22112c": "62112c0100",
                "22112f": "62112f010101",
                "221132": "62",
                "221130": "62",
                "221133": "62",
                "ab31": "eb313300",
            }
            groups = (
                (0x201, 0x401, 0x601, 0x801, 0xA01, 0xC01, 0xE01),
                (
                    0x02010000,
                    0x04010000,
                    0x06010000,
                    0x08010000,
                    0x0A010000,
                    0x0C010000,
                    0x0E010000,
                ),
                (
                    0x02010001,
                    0x04010001,
                    0x06010001,
                    0x08010001,
                    0x0A010001,
                    0x0C010001,
                    0x0E010001,
                ),
            )
            replies = {
                bytes.fromhex(key): bytes.fromhex(value)
                for key, value in metadata.items()
            }
            for indices in groups:
                for block, index in enumerate(indices, 1):
                    request = bytes.fromhex("ab333300") + index.to_bytes(4, "big")
                    replies[request] = (
                        bytes.fromhex("7fab23")
                        if mode == "fault" and index == 0x801
                        else bytes.fromhex("eb333300")
                        + index.to_bytes(4, "big")
                        + (bytes.fromhex("010501021234") if block == 1 else b"")
                    )

            class Fixture(J2534Fixture):
                request = b""

                def invoke(self, operation, fields, *, replies=replies, **kwargs):
                    if operation == "write_messages":
                        self.request = fields["messages"][0].data[4:]
                    if operation == "read_messages":
                        self.calls.append((operation, dict(fields)))
                        return J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6,
                                    0,
                                    0,
                                    0,
                                    0,
                                    bytes.fromhex("000007e8") + replies[self.request],
                                ),
                            ),
                        )
                    return super().invoke(operation, fields, **kwargs)

            backend = Fixture([])
            channel = NativeCommunication.from_backend(
                selected,
                backend,
                "rc-blocks",
                first_request=b"\x21\x00",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=18,
                clock=lambda: 0.0,
            )
            assert isinstance(channel.operations, NativeFrameController)
            with tempfile.TemporaryDirectory() as directory:
                logger = DdrPacketLog(Path(directory), channel.operations)
                self.assertEqual(logger.start(26), 0)
                self.assertEqual(channel.connection_no_buffer().status, 0)
                with channel.cache.temporary_scope(no_init=True):
                    acquired = capture_rc_image_record_phase(
                        channel.cache,
                        selected.frame_records(0x66)[0],
                        logger,
                        (1, 1),
                        DdrP5SupportValue(170, mode == "filter", 0x1234),
                    )
                self.assertEqual(acquired.log_status, 0)
                self.assertEqual(len(acquired.acquisitions), 6)
                self.assertEqual(
                    len(acquired.freezes),
                    0 if mode == "filter" else 4 if mode == "fault" else 6,
                )
                self.assertTrue(all(len(item.blocks) == 7 for item in acquired.freezes))
                self.assertEqual(logger.stop(), 0)
                saved = logger.path.read_bytes()
                if mode == "fault":
                    self.assertNotIn(b"7FAB23", saved)
                writes = [
                    fields["messages"][0].data[4:]
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                actual = [
                    int.from_bytes(request[4:], "big")
                    for request in writes
                    if request.startswith(bytes.fromhex("ab333300"))
                ]
                expected = [
                    index
                    for indices in groups
                    for index in (
                        indices[:1]
                        if mode == "filter"
                        else indices[:4]
                        if mode == "fault" and indices[0] == 0x201
                        else indices
                    )
                ] * 2
                self.assertEqual(actual, expected)
                channel.disconnect(1)

    def test_rc_index_metadata_order_caps_failures_and_native_word_indices(self):
        frame = self.profile.frame_records(0x66)[0]
        for fail_first, duplicate in ((False, False), (True, False), (False, True)):
            queries = []
            mapping = {
                "221129": "6211293300" + ("3300" if duplicate else "3500"),
                "22112c": "62112cfffe",
                "22112f": "62112f010b02030304",
                "221132": "621132010201030405060708",
                "221130": "62",
                "221133": "62",
                "ab31": "eb3133003500",
            }

            def exchange(
                query, fail_first=fail_first, mapping=mapping, queries=queries
            ):
                queries.append(query.request.hex())
                if fail_first and query.request.hex() == "22112f":
                    raise ToyotaCodecError(
                        "authored subgroup receive failure", 0x90020323
                    )
                return bytes.fromhex(mapping[query.request.hex()])

            cache = MonitorSupportCache(self.profile, exchange, "rc-indices")
            acquired = capture_rc_image_indices(cache, frame, (1, 2))
            self.assertEqual(
                queries,
                ["221129", "22112c", "22112f", "221132", "221130", "221133", "ab31"],
            )
            self.assertEqual(
                tuple(group.native_count for group in acquired.groups),
                (0 if fail_first else 2, 3),
            )
            self.assertEqual(
                acquired.groups[0].subgroups[0].regular if not fail_first else 0,
                0 if fail_first else 10,
            )
            self.assertEqual(acquired.groups[1].subgroups[-1].after, 8)
            self.assertEqual(
                tuple(group.enabled for group in acquired.groups), (True, not duplicate)
            )
            self.assertEqual(
                acquired.suppressed_errors,
                ((0x112F, 0x90020323),) if fail_first else (),
            )
        self.assertEqual(rc_image_regular_index(1, 1, 1), 0x201)
        self.assertEqual(rc_image_regular_index(7, 3, 10), 0xE1E)
        self.assertEqual(rc_image_adjacent_index(1, 1, 1, 0), 0x02010000)
        self.assertEqual(rc_image_adjacent_index(7, 3, 2, 3), 0x0E150004)
        with self.assertRaises(ValueError):
            rc_image_adjacent_index(256, 1, 0, 0)

    def test_ads_image_complete_internal_ddr_and_provided_counter_filter(self):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            ImageFacadeResult,
            SavedOperationFacadeFreeze,
            SavedOperationFacadeValue,
        )
        from scripts.database_resources import DdrP5SupportValue, DdrPacketLog
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        for provided, facade, mode in (
            (False, False, "success"),
            (True, False, "success"),
            (False, True, "success"),
            (True, True, "success"),
            (False, True, "fault"),
            (False, True, "cancel"),
            (False, True, "ascii"),
            (False, True, "generic"),
            (False, True, "source12"),
        ):
            with tempfile.TemporaryDirectory() as directory:
                selected, fixture = internal_image_profile(
                    Path(directory), "normal", family="ads"
                )
                info = b"\x62" + bytes(38)
                first = bytes.fromhex("eb232820000000010250040233000501021234")
                second = bytes.fromhex("eb232820000000020250040233000501021235")
                responses = {
                    bytes.fromhex(key): bytes.fromhex(value)
                    for key, value in fixture["responses_hex"].items()
                }
                responses.update(
                    {
                        bytes.fromhex("2100"): bytes.fromhex("6100"),
                        bytes.fromhex("221c05"): bytes.fromhex("621c05020201010101"),
                        bytes.fromhex("2701"): b"\x67\x01" + bytes(16),
                        bytes.fromhex("221c07"): bytes.fromhex("621c0701000000000000"),
                        bytes.fromhex("221c06"): info,
                        bytes.fromhex("ab21"): bytes.fromhex("eb212820"),
                        bytes.fromhex("ab222820"): bytes.fromhex(
                            "eb2228200000000100000002"
                        ),
                        bytes.fromhex("ab23282000000001"): first,
                        bytes.fromhex("ab23282000000002"): second,
                    }
                )

                if mode == "fault":
                    responses[bytes.fromhex("ab21")] = bytes.fromhex("eb21")
                if mode in ("ascii", "generic"):
                    management = selected.catalog.management
                    sections = {
                        key: (row.count, row.payload)
                        for key, row in management.sections.items()
                    }
                    module = bytearray(sections[19][1])
                    module[:80] = bytes(80)
                    name = (
                        "GetADSImageFFDP5_DT.dll"
                        if mode == "ascii"
                        else "GetImageFFDP5_DT.dll"
                    )
                    encoded = (name + "\0").encode(
                        "ascii" if mode == "ascii" else "utf-16le"
                    )
                    module[: len(encoded)] = encoded
                    sections[19] = (1, bytes(module))
                    (Path(directory) / "Toyota.ddb").write_bytes(database(1, sections))
                    selected = VehicleCatalog(Path(directory)).build_profile(42)
                cancelled = [False]

                class Fixture(J2534Fixture):
                    request = b""

                    def invoke(
                        self,
                        operation,
                        fields,
                        *,
                        responses=responses,
                        mode=mode,
                        cancel_state=cancelled,
                        **kwargs,
                    ):
                        if operation == "write_messages":
                            self.request = fields["messages"][0].data[4:]
                        if operation == "read_messages":
                            self.calls.append((operation, dict(fields)))
                            reply = (
                                bytes.fromhex("67010000")
                                if self.request
                                in (
                                    bytes.fromhex("27010000"),
                                    bytes.fromhex("27030000"),
                                )
                                else responses[self.request]
                            )
                            if mode == "cancel" and self.request == bytes.fromhex(
                                "221c06"
                            ):
                                cancel_state[0] = True
                            return J2534Result(
                                count=1,
                                messages=(
                                    NativeMessage(
                                        6, 0, 0, 0, 0, bytes.fromhex("000007e8") + reply
                                    ),
                                ),
                            )
                        return super().invoke(operation, fields, **kwargs)

                backend = Fixture([])
                channel = NativeCommunication.from_backend(
                    selected,
                    backend,
                    "ads-image-full",
                    first_request=b"\x21\x00",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=18,
                    clock=lambda: 0.0,
                    cancelled=lambda cancelled=cancelled: cancelled[0],
                )
                assert isinstance(channel.operations, NativeFrameController)
                logger = DdrPacketLog(Path(directory) / "logs", channel.operations)
                request = AdsImageRequest18(
                    (1,),
                    ddr_support=DdrP5SupportValue(170, True, 0x1234)
                    if provided
                    else None,
                )
                if facade:
                    api_build = 12 if mode == "source12" else 18
                    api = CommandAPI(CommandSource(api_build, SOURCE_SHA256[api_build]))
                    prior = ImageFacadeResult(
                        0,
                        (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),),
                        (7, 8, 9),
                    )
                    if mode in ("ascii", "generic", "source12"):
                        with self.assertRaises(NotImplementedError):
                            api.get_ads_image_ffd(
                                channel, logger, bytes(16), request, previous=prior
                            )
                        self.assertEqual(backend.calls, [])
                        self.assertFalse(logger.directory.exists())
                        continue
                    if mode == "cancel":
                        with self.assertRaises(Cancelled):
                            api.get_ads_image_ffd(
                                channel, logger, bytes(16), request, previous=prior
                            )
                        self.assertIsNone(logger._file)
                        self.assertTrue(channel.closed)
                        continue
                    output = api.get_ads_image_ffd(
                        channel, logger, bytes(16), request, previous=prior
                    )
                    if mode == "fault":
                        self.assertEqual(output.return_code, 0x90040501)
                        self.assertEqual(output.freezes, ())
                        self.assertEqual(output.native_fields18, (0, 0, 0))
                        self.assertIsNone(logger._file)
                        self.assertTrue(channel.closed)
                        continue
                    self.assertEqual(output.return_code, 0)
                    self.assertEqual(output.native_fields18, (0, 0, 0))
                    self.assertEqual(
                        tuple(row.values[0].scalar for row in output.freezes),
                        (0x1235,) if provided else (0x1234, 0x1235),
                    )
                    public_json = json.dumps(api.ads_image_ffd_report(output))
                    self.assertEqual(
                        json.loads(public_json)["operation"], "GetADSImageFFDApi"
                    )
                    for private in ("raw_reply", "log_path", "security", "ddr_report"):
                        self.assertNotIn(private, public_json)
                    self.assertIsNone(logger._file)
                    self.assertTrue(channel.closed)
                    continue
                result = capture_ads_image_saved(
                    channel,
                    logger,
                    AdsImageSource(18, ADS_IMAGE_SOURCE_SHA256),
                    bytes(16),
                    request,
                )
                self.assertEqual(result.native_status, 0)
                self.assertEqual(result.ddr_provided, provided)
                self.assertEqual(result.ddr_status, 0)
                self.assertEqual(result.ddr_report is None, provided)
                self.assertIsNotNone(result.phase)
                assert result.phase is not None
                self.assertEqual(
                    tuple(row.values[0] for row in result.phase.freezes),
                    (0x1235,) if provided else (0x1234, 0x1235),
                )
                self.assertIsNone(logger._file)
                self.assertTrue(channel.closed)
                saved = logger.path.read_bytes()
                self.assertIn(second.hex().upper().encode(), saved)
                if provided:
                    self.assertNotIn(first.hex().upper().encode(), saved)
                else:
                    self.assertIn(first.hex().upper().encode(), saved)
                writes = [
                    fields["messages"][0].data[4:].hex()
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual("27030000" in writes, not provided)
                self.assertEqual(
                    writes[-8:],
                    [
                        "2100",
                        "221c05",
                        "2701",
                        "221c07",
                        "221c06",
                        "ab21",
                        "ab222820",
                        "ab23282000000001",
                        "ab23282000000002",
                    ][-8:],
                )

    def test_internal_ddr_image_public_route(self):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            ImageFacadeResult,
        )
        from scripts.database_resources import DdrPacketLog
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        for variant, support_values in (
            (variant, support)
            for variant in ("normal", "p5")
            for support in (False, True)
        ):
            with tempfile.TemporaryDirectory() as directory:
                selected, fixture = internal_image_profile(
                    Path(directory), variant, support_values=support_values
                )
                information = bytearray(70)
                information[:3], information[6] = bytes.fromhex("621202"), 12
                information[7:11] = (13).to_bytes(4, "big")
                information[35:39] = (0x1000).to_bytes(4, "big")
                information[65] = 1
                header = bytearray.fromhex("630f0012340102030400000000")
                header[9] = sum(header[1:9]) & 255
                responses = {
                    bytes.fromhex(key): bytes.fromhex(value)
                    for key, value in fixture["responses_hex"].items()
                }
                responses.update(
                    {
                        bytes.fromhex("2100"): bytes.fromhex("6100"),
                        bytes.fromhex("221201"): bytes.fromhex("621201020201010101"),
                        bytes.fromhex("2703"): b"\x67\x03" + bytes(6),
                        bytes.fromhex("221203"): bytes.fromhex(
                            "6212030100000001000000"
                        ),
                        bytes.fromhex("221204"): b"\x62",
                        bytes.fromhex("222090"): b"\x62",
                        bytes.fromhex("221202"): bytes(information),
                        bytes.fromhex("231501000010000c"): bytes(header),
                        bytes.fromhex("2315010000100c01"): b"\x63",
                    }
                )
                payload = bytes.fromhex(fixture["ram_payload_hex"]) + bytes(56)
                security_reply = bytes.fromhex(fixture["security_reply_hex"])

                class Fixture(J2534Fixture):
                    request = b""

                    def invoke(
                        self,
                        operation,
                        fields,
                        *,
                        responses=responses,
                        payload=payload,
                        security_reply=security_reply,
                        **kwargs,
                    ):
                        if operation == "write_messages":
                            self.request = fields["messages"][0].data[4:]
                        if operation == "read_messages":
                            self.calls.append((operation, dict(fields)))
                            request = self.request
                            if request in (
                                bytes.fromhex("27010000"),
                                bytes.fromhex("27030000"),
                            ):
                                reply = security_reply
                            elif request[:1] == b"\x91":
                                address = int.from_bytes(request[3:7], "big")
                                reply = (
                                    b"\xd1"
                                    + request[1:]
                                    + payload[address : address + request[2]]
                                )
                            else:
                                reply = responses[request]
                            return J2534Result(
                                count=1,
                                messages=(
                                    NativeMessage(
                                        6, 0, 0, 0, 0, bytes.fromhex("000007e8") + reply
                                    ),
                                ),
                            )
                        return super().invoke(operation, fields, **kwargs)

                backend = Fixture([])
                channel = NativeCommunication.from_backend(
                    selected,
                    backend,
                    "image-internal",
                    first_request=b"\x21\x00",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=18,
                    clock=lambda: 0.0,
                )
                assert isinstance(channel.operations, NativeFrameController)
                logger = DdrPacketLog(Path(directory) / "logs", channel.operations)
                request = ImageP5Request18(
                    (1,), 1, (ImageEcuReference(0x1BC, 1),) if variant == "p5" else ()
                )
                api = CommandAPI(CommandSource(18, SOURCE_SHA256[18]))
                result = api.get_image_ffd_p5(
                    channel,
                    logger,
                    bytes(6),
                    request,
                    previous=ImageFacadeResult(0, (), (7, 8, 9)),
                )
                self.assertEqual(result.return_code, 0)
                self.assertEqual(
                    result.native_fields18,
                    (1, 1, 3) if support_values and variant == "p5" else (1, 0, 0),
                )
                self.assertEqual(
                    tuple(row.values[0].scalar for row in result.freezes), (0x1234,)
                )
                self.assertIsNone(logger._file)
                self.assertTrue(channel.closed)
                writes = [
                    fields["messages"][0].data[4:].hex()
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                for native_request in (
                    fixture["requests_hex"][:4]
                    if variant == "normal"
                    else fixture["requests_hex"]
                ):
                    self.assertIn(native_request, writes)
                self.assertEqual(writes[-2:], ["231501000010000c", "2315010000100c01"])

    def test_ads_image_native_record_phase_actual_wire_type_counter_and_file_filter(
        self,
    ):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture, serialized_profile

        from scripts.database_resources import DdrP5SupportValue, DdrPacketLog
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        for faults in (False, True):
            selected = serialized_profile(request=b"\x21\x00", mask=b"", check=b"")
            sections = {
                slot: (item.count, item.payload)
                for slot, item in selected.catalog.management.sections.items()
            }
            count, rows = sections[18]
            rows += struct.pack("<8H", 42, 0x66, 1, 0, 0, 0, 0, 0)
            sections[18] = (
                count + 1,
                b"".join(
                    sorted(
                        (
                            rows[offset : offset + 16]
                            for offset in range(0, len(rows), 16)
                        ),
                        key=lambda row: struct.unpack_from("<HH", row),
                    )
                ),
            )
            selected.catalog.management = parse_database(database(1, sections))

            def record(index, scalar):
                return (
                    bytes.fromhex("eb232820")
                    + index.to_bytes(4, "big")
                    + bytes.fromhex("025004023300050102")
                    + scalar.to_bytes(2, "big")
                )

            first, second, bulk = (
                record(1, 0x1234),
                record(2, 0x1235),
                record(0x10001, 0x9999),
            )
            answers = [
                bytes.fromhex("6100"),
                bytes.fromhex("eb2128209999"),
                bytes.fromhex("eb222820000000020000000100010001"),
            ]
            answers += (
                [bytes.fromhex("7fab23"), bytes.fromhex("7fab23")]
                if faults
                else [first, second, bulk]
            )
            backend = J2534Fixture(
                [
                    J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 0, 0, bytes.fromhex("000007e8") + answer
                            ),
                        ),
                    )
                    for answer in answers
                ]
            )
            channel = NativeCommunication.from_backend(
                selected,
                backend,
                "ads-image-phase",
                first_request=b"\x21\x00",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=18,
                clock=lambda: 0.0,
            )
            assert isinstance(channel.operations, NativeFrameController)
            with tempfile.TemporaryDirectory() as directory:
                logger = DdrPacketLog(Path(directory), channel.operations)
                self.assertEqual(logger.start(24), 0)
                self.assertEqual(channel.connection_no_buffer().status, 0)
                with channel.cache.temporary_scope(no_init=True):
                    result = capture_ads_image_record_phase(
                        channel.cache,
                        selected.frame_records(0x66)[0],
                        logger,
                        (1,),
                        DdrP5SupportValue(170, False, 0),
                    )
                self.assertEqual(result.native_status, 0)
                self.assertEqual(result.log_status, 0)
                self.assertEqual(
                    tuple(row.values[0] for row in result.freezes),
                    () if faults else (0x1234, 0x1235),
                )
                self.assertEqual(len(result.suppressed_errors), 2 if faults else 0)
                self.assertEqual(logger.stop(), 0)
                data = logger.path.read_bytes()
                if faults:
                    self.assertNotIn(b"7FAB23", data)
                else:
                    self.assertIn(first.hex().upper().encode(), data)
                    self.assertIn(second.hex().upper().encode(), data)
                    self.assertNotIn(bulk.hex().upper().encode(), data)
                self.assertEqual(backend.replies, [])
                channel.disconnect(1)

    def test_generic_p5_complete_selected18_wire_log_retry_and_partial_output(self):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture, serialized_profile

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            ImageFacadeResult,
            SavedOperationFacadeFreeze,
            SavedOperationFacadeValue,
        )
        from scripts.database_resources import DdrPacketLog
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        modes = (
            "success",
            "retry",
            "checksum",
            "header-fault",
            "body-fault",
            "empty",
            "cancel",
        )
        for facade, mode in [
            (facade, mode) for facade in (False, True) for mode in modes
        ] + [(True, mode) for mode in ("ascii", "p4", "source12")]:
            cancelled = [False]

            class ImageFixture(J2534Fixture):
                def invoke(
                    self, operation, fields, *, case=mode, flag=cancelled, **kwargs
                ):
                    result = super().invoke(operation, fields, **kwargs)
                    if (
                        case == "cancel"
                        and operation == "read_messages"
                        and len(self.replies) == 1
                    ):
                        flag[0] = True
                    return result

            retry = mode in ("retry", "checksum")
            selected = serialized_profile(request=b"\x21\x00", mask=b"", check=b"")
            sections = {
                slot: (item.count, item.payload)
                for slot, item in selected.catalog.management.sections.items()
            }
            count, rows = sections[18]
            rows += struct.pack("<8H", 42, 0x66, 1, 0, 0, 0, 0, 0)
            sections[18] = (
                count + 1,
                b"".join(
                    sorted(
                        (
                            rows[offset : offset + 16]
                            for offset in range(0, len(rows), 16)
                        ),
                        key=lambda row: struct.unpack_from("<HH", row),
                    )
                ),
            )
            module = bytearray(88)
            name = "GetImageFFD_DT.dll" if mode == "p4" else "GetImageFFDP5_DT.dll"
            encoded_name = (name + "\0").encode(
                "ascii" if mode == "ascii" else "utf-16le"
            )
            module[: len(encoded_name)] = encoded_name
            struct.pack_into("<H", module, 80, 42)
            module[86] = 0xBB
            sections[19] = (1, bytes(module))
            selected.catalog.management = parse_database(database(1, sections))
            info = bytearray(70)
            info[:3], info[6] = bytes.fromhex("621202"), 12
            info[7:11] = (13).to_bytes(4, "big")
            info[35:39] = (0x1000).to_bytes(4, "big")
            info[65] = 1
            header = bytearray.fromhex("630f0012340102030400000000")
            header[9] = sum(header[1:9]) & 255
            answers = [
                bytes.fromhex("6100"),
                bytes.fromhex("621201020201010101"),
                b"\x67\x03" + bytes(6),
                bytes.fromhex("6212030100000001000000"),
                b"\x62",
                b"\x62",
                bytes(info),
                bytes(header),
                bytes.fromhex("7f2323") if mode == "retry" else b"\x63",
            ]
            bad_header = bytearray(header)
            bad_header[9] ^= 1
            if retry:
                if mode == "checksum":
                    answers[-2] = bytes(bad_header)
                answers += [bytes(header), b"\x63"]
            elif mode == "header-fault":
                answers[-2:] = [bytes.fromhex("7f2323")]
            elif mode == "body-fault":
                answers[-1] = b"\x64"
            backend = ImageFixture(
                [
                    J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 0, 0, bytes.fromhex("000007e8") + answer
                            ),
                        ),
                    )
                    for answer in answers
                ]
            )
            channel = NativeCommunication.from_backend(
                selected,
                backend,
                "p5-full",
                first_request=b"\x21\x00",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=18,
                clock=lambda: 0.0,
                cancelled=lambda cancelled=cancelled: cancelled[0],
            )
            assert isinstance(channel.operations, NativeFrameController)
            with tempfile.TemporaryDirectory() as temp:
                logger = DdrPacketLog(Path(temp), channel.operations)
                if facade:
                    api_build = 12 if mode == "source12" else 18
                    api = CommandAPI(CommandSource(api_build, SOURCE_SHA256[api_build]))
                    prior = ImageFacadeResult(
                        0,
                        (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),),
                        (7, 8, 9),
                    )
                    request = ImageP5Request18(() if mode == "empty" else (1,), 1)
                    if mode in ("ascii", "p4", "source12"):
                        with self.assertRaises(
                            ValueError if mode == "source12" else NotImplementedError
                        ):
                            api.get_image_ffd_p5(
                                channel, logger, bytes(6), request, previous=prior
                            )
                        self.assertEqual(backend.calls, [])
                        self.assertFalse(logger.directory.exists())
                        continue
                    if mode == "cancel":
                        with self.assertRaises(Cancelled):
                            api.get_image_ffd_p5(
                                channel, logger, bytes(6), request, previous=prior
                            )
                        self.assertIsNone(logger._file)
                        self.assertTrue(channel.closed)
                        continue
                    output = api.get_image_ffd_p5(
                        channel, logger, bytes(6), request, previous=prior
                    )
                    expected_status = (
                        0x90020321
                        if mode == "header-fault"
                        else 0xA0040201
                        if mode == "body-fault"
                        else 0xC0040001
                        if mode == "empty"
                        else 0
                    )
                    self.assertEqual(output.return_code, expected_status)
                    self.assertEqual(
                        output.native_fields18,
                        (7, 8, 9) if expected_status else (0, 0, 0),
                    )
                    expected_scalars = (
                        (99,)
                        if expected_status
                        else (99, 0x1234, 0x1234)
                        if mode == "retry"
                        else (99, 0x1234)
                    )
                    self.assertEqual(
                        tuple(freeze.values[0].scalar for freeze in output.freezes),
                        expected_scalars,
                    )
                    report = json.loads(json.dumps(api.image_ffd_report(output)))
                    for private in (
                        "raw_reply",
                        "ddr_report",
                        "seed_reply",
                        "log_path",
                    ):
                        self.assertNotIn(private, json.dumps(report))
                    self.assertIsNone(logger._file)
                    if mode == "empty":
                        self.assertEqual(backend.calls, [])
                        self.assertFalse(logger.directory.exists())
                        self.assertFalse(channel.closed)
                    else:
                        self.assertEqual(len(backend.replies), 0)
                        self.assertTrue(channel.closed)
                        self.assertNotIn(b"7F2323", logger.path.read_bytes())
                    continue
                if mode == "empty":
                    rejected = capture_image_p5_saved(
                        channel,
                        logger,
                        ImageP5Source(18, IMAGE_P5_SOURCE_SHA256[18]),
                        bytes(6),
                        ImageP5Request18((), 1),
                    )
                    self.assertEqual(rejected.native_status, 0xC0040001)
                    self.assertEqual(backend.calls, [])
                    self.assertFalse(logger.directory.exists())
                    self.assertFalse(channel.closed)
                    continue
                if mode == "cancel":
                    with self.assertRaises(Cancelled):
                        capture_image_p5_saved(
                            channel,
                            logger,
                            ImageP5Source(18, IMAGE_P5_SOURCE_SHA256[18]),
                            bytes(6),
                            ImageP5Request18((1,), 1),
                        )
                    self.assertIsNone(logger._file)
                    self.assertFalse(logger.active)
                    self.assertTrue(channel.closed)
                    continue
                result = capture_image_p5_saved(
                    channel,
                    logger,
                    ImageP5Source(18, IMAGE_P5_SOURCE_SHA256[18]),
                    bytes(6),
                    ImageP5Request18((1,), 1),
                )
                self.assertEqual(
                    result.native_status,
                    0x90020321
                    if mode == "header-fault"
                    else 0xA0040201
                    if mode == "body-fault"
                    else 0,
                )
                self.assertNotEqual(
                    result.ddr_status, 0
                )  # Actual absent BC; native caller ignores failure.
                self.assertIsNone(result.ddr_report)
                self.assertEqual(
                    tuple(row.scalar for row in result.records),
                    (None, 0x1234)
                    if mode == "checksum"
                    else (0x1234, 0x1234)
                    if retry
                    else ()
                    if mode == "header-fault"
                    else (0x1234,),
                )
                if result.records:
                    self.assertEqual(result.records[0].retry, retry)
                self.assertEqual(len(backend.replies), 0)
                self.assertTrue(channel.closed)
                self.assertFalse(logger.active)
                self.assertIsNone(logger._file)
                saved = logger.path.read_bytes()
                self.assertNotIn(b"7F2323", saved)
                if mode == "checksum":
                    self.assertNotIn(bytes(bad_header).hex().upper().encode(), saved)
                    self.assertIn(bytes(header).hex().upper().encode(), saved)
                writes = [
                    fields["messages"][0].data[4:]
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(
                    writes[1:7],
                    [
                        bytes.fromhex("221201"),
                        bytes.fromhex("2703"),
                        bytes.fromhex("221203"),
                        bytes.fromhex("221204"),
                        bytes.fromhex("222090"),
                        bytes.fromhex("221202"),
                    ],
                )
                if mode != "header-fault":
                    self.assertEqual(
                        writes[-2:],
                        [
                            bytes.fromhex("231501000010000c"),
                            bytes.fromhex("2315010000100c01"),
                        ],
                    )
                else:
                    self.assertEqual(writes[-1], bytes.fromhex("231501000010000c"))

    def test_ads_image_actual_group_index_record_and_extended_field_association(self):
        frame = self.profile.frame_records(0x66)[0]
        raw = bytes.fromhex("eb23282000000001") + bytes.fromhex(
            "0450040233000501021234600100000003aabbcc050102ffff"
        )
        replies = iter(
            (
                bytes.fromhex("eb2128202820282bff"),
                bytes.fromhex("eb222820ffffffff000000010000000100000000"),
                raw,
            )
        )
        queries = []

        def exchange(query):
            queries.append(query)
            return next(replies)

        cache = MonitorSupportCache(self.profile, exchange, "ads-image-records")
        self.assertEqual(
            capture_ads_image_groups(cache, frame), (0x2820, 0x2820, 0x282B)
        )
        self.assertEqual(
            capture_ads_image_indices(cache, frame, 0x2820), (0, 1, 0xFFFFFFFF)
        )
        result = capture_ads_image_record(cache, frame, 0x2820, 1)
        self.assertEqual(result.values, (0x1234,))
        self.assertEqual(result.record_types, (0x3300,))
        self.assertEqual(result.groups[0].records[2], (0x6001, bytes.fromhex("aabbcc")))
        self.assertEqual(
            [query.request.hex() for query in queries],
            ["ab21", "ab222820", "ab23282000000001"],
        )
        cache = MonitorSupportCache(
            self.profile, lambda query: raw[:-1], "ads-image-short-record"
        )
        partial = capture_ads_image_record(cache, frame, 0x2820, 1)
        self.assertEqual(partial.values, (0x1234,))
        self.assertEqual(partial.record_types, (0x3300,))

    def test_pvm21_distinct_two_snapshot_and_second_spec_chronology(self):
        frame = self.profile.frame_records(0x66)[0]
        for second, status in (
            (bytes.fromhex("62ffff0000"), 0),
            (bytes.fromhex("62ffff0001"), 0x90040501),
            (bytes.fromhex("62ffff00"), 0xA0040202),
        ):
            queries = []
            replies = iter(
                (
                    b"\x67\x03" + bytes(6),
                    bytes.fromhex("62ffff020102"),
                    bytes.fromhex("62fffffe"),
                    second,
                    b"\x62",
                )
            )

            def exchange(query, queries=queries, replies=replies):
                queries.append(query)
                return next(replies)

            cache = MonitorSupportCache(self.profile, exchange, "pvm21")
            if status:
                with self.assertRaises(ToyotaCodecError) as caught:
                    capture_pvm21_image_p5_information(cache, frame, bytes(6))
                self.assertEqual(caught.exception.code, status)
                self.assertEqual(cache.calls, 4)
            else:
                result = capture_pvm21_image_p5_information(cache, frame, bytes(6))
                self.assertEqual(result.numbers, (2,))
                self.assertEqual(result.raw_specification[3], 0xFE)
                self.assertEqual(result.raw_encryption_method, b"\x62")
                self.assertEqual(
                    [query.request.hex() for query in queries],
                    ["2703", "221126", "221103", "221128", "222031"],
                )

    def test_ads_image_information_actual_selected_aes_and_field_association(self):
        from scripts.diagnostic_db import parse_database

        selected = self.profile
        sections = {
            slot: (item.count, item.payload)
            for slot, item in selected.catalog.management.sections.items()
        }
        sections[0] = (2, struct.pack("<IHIH", 0, 2, 2, 2) + bytes.fromhex("ab112701"))
        sections[17] = (2, struct.pack("<8H", 1, 1, 0, 0, 2, 2, 0, 0))
        sections[18] = (
            2,
            sections[18][1] + struct.pack("<8H", 42, 0x109, 1, 2, 0, 0, 0, 0),
        )
        selected.catalog.management = parse_database(database(1, sections))
        frame = selected.frame_records(0x66)[0]
        information = bytearray(range(39))
        information[0] = 0x62
        queries = []
        replies = iter(
            (
                bytes.fromhex("621c05020201020102"),
                b"\x67\x01" + bytes(16),
                bytes.fromhex("621c0701000000000000"),
                bytes(information),
            )
        )

        def exchange(query):
            queries.append(query)
            return next(replies)

        cache = MonitorSupportCache(selected, exchange, "ads-image")
        result = capture_ads_image_p5_information(cache, frame, bytes(16))
        self.assertEqual(result.numbers, (1, 3, 5))
        self.assertEqual(
            result.native_dwords,
            tuple(
                int.from_bytes(information[offset : offset + 4], "big")
                for offset in range(4, 24, 4)
            ),
        )
        self.assertEqual(result.counts, (34, 35, 36, 37, 38))
        self.assertEqual(
            [query.request.hex() for query in queries],
            ["221c05", "2701", "221c07", "221c06"],
        )
        self.assertIsNone(result.security.key_request)
        # Missing snapshots prevents even the selected security query.
        cache = MonitorSupportCache(
            selected,
            lambda query: bytes.fromhex("621c05020101010101"),
            "ads-image-no-flags",
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            capture_ads_image_p5_information(cache, frame, bytes(16))
        self.assertEqual(caught.exception.code, 0x90040501)
        self.assertEqual(cache.calls, 1)

    def test_legacy_pvm_image_information_security_first_and_literal_fields(self):
        frame = self.profile.frame_records(0x66)[0]
        information = bytearray(range(144))
        information[0], information[6] = 0x62, 8
        specification = bytes.fromhex("62110301000000000000000000")
        replies = iter(
            (
                b"\x67\x03" + bytes(6),
                bytes.fromhex("6211010202010201020102"),
                specification,
                b"\x62",
                b"\x62",
                bytes(information),
            )
        )
        queries = []

        def exchange(query):
            queries.append(query)
            return next(replies)

        cache = MonitorSupportCache(self.profile, exchange, "pvm-info")
        result = capture_pvm_image_p5_information(cache, frame, bytes(6))
        self.assertEqual(result.numbers, (1, 3, 5, 7))
        self.assertEqual(
            result.native_dwords,
            tuple(
                int.from_bytes(information[offset : offset + 4], "big")
                for offset in range(7, 35, 4)
            ),
        )
        self.assertEqual(result.counts, tuple(range(137, 144)))
        self.assertEqual(
            [query.request.hex() for query in queries],
            ["2703", "221101", "221103", "222032", "222033", "221102"],
        )
        for raw, code in (
            (bytes(information[:143]), 0xA0040202),
            (bytes(information[:6]) + b"\x07" + bytes(information[7:]), 0x90040501),
        ):
            received = iter(
                (
                    b"\x67\x03" + bytes(6),
                    bytes.fromhex("6211010202010201020102"),
                    specification,
                    b"\x62",
                    b"\x62",
                    raw,
                )
            )
            cache = MonitorSupportCache(
                self.profile,
                lambda query, received=received: next(received),
                "pvm-info-invalid",
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                capture_pvm_image_p5_information(cache, frame, bytes(6))
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(cache.calls, 6)

    def test_tss3_image_information_actual_format5_and7_field_order(self):
        frame = self.profile.frame_records(0x66)[0]
        for format in (5, 7):
            count = 10 if format == 5 else 11
            specification = bytearray(count + 5)
            specification[:4] = bytes((0x62, 0xFF, 0xFF, format))
            specification[6], specification[11] = 2, 1
            availability = bytes.fromhex("62ffff02") + bytes((2,)) * count
            queries = []
            replies = iter(
                (
                    bytes(specification),
                    availability,
                    b"\x67\x03" + bytes(6),
                    bytes.fromhex("62ffff00"),
                )
            )

            def exchange(query, replies=replies, queries=queries):
                queries.append(query)
                return next(replies)

            cache = MonitorSupportCache(self.profile, exchange, "tss-image")
            result = capture_tss3_image_p5_information(cache, frame, bytes(6))
            self.assertEqual(result.format, format)
            self.assertEqual(result.numbers, tuple(range(1, count + 1)))
            self.assertEqual(
                [query.request.hex() for query in queries],
                ["221103", "221101", "2703", "222081"],
            )
            # Every native spec field is required; do not accept a format-only tag.
            for offset in range(5, count + 5):
                invalid = bytearray(specification)
                invalid[offset] ^= 1
                cache = MonitorSupportCache(
                    self.profile,
                    lambda query, invalid=invalid: bytes(invalid),
                    "tss-image-invalid",
                )
                with self.assertRaises(ToyotaCodecError) as caught:
                    capture_tss3_image_p5_information(cache, frame, bytes(6))
                self.assertEqual(caught.exception.code, 0x90040501)
                self.assertEqual(cache.calls, 1)
            if format == 7:
                for spec, flags, calls in (
                    (bytes(specification[:-1]), availability, 1),
                    (bytes(specification), availability[:-1], 2),
                ):
                    received = iter((spec, flags))
                    cache = MonitorSupportCache(
                        self.profile,
                        lambda query, received=received: next(received),
                        "tss-image-short",
                    )
                    with self.assertRaises(ToyotaCodecError) as caught:
                        capture_tss3_image_p5_information(cache, frame, bytes(6))
                    self.assertEqual(caught.exception.code, 0xA0040202)
                    self.assertEqual(cache.calls, calls)

    def test_rc_image_selected_information_wire_order_and_fault_precedence(self):
        frame = self.profile.frame_records(0x66)[0]
        for flags, expected in (
            (b"\x02\x02", (1, 2)),
            (b"\x01\x02", (2,)),
            (b"\x02\x01", (1,)),
        ):
            replies = iter(
                (
                    bytes.fromhex("62ffff0200"),
                    bytes.fromhex("62ffff01") + flags,
                    b"\x67\x03" + bytes(6),
                    bytes.fromhex("62ffff09"),
                )
            )
            queries = []

            def exchange(query, replies=replies, queries=queries):
                queries.append(query)
                return next(replies)

            cache = MonitorSupportCache(self.profile, exchange, "rc-info")
            result = capture_rc_image_p5_information(cache, frame, bytes(6))
            self.assertEqual(result.numbers, expected)
            self.assertEqual(result.format, 2)
            self.assertEqual(result.raw_encryption_method, bytes.fromhex("62ffff09"))
            self.assertEqual(
                [query.request.hex() for query in queries],
                ["221103", "221126", "2703", "222031"],
            )
            self.assertTrue(all(query.extended for query in queries))
        for replies, code, count in (
            ((bytes.fromhex("6211030200")[:4],), 0xA0040202, 1),
            ((bytes.fromhex("6211030100"),), 0x90040501, 1),
            (
                (bytes.fromhex("6211030200"), bytes.fromhex("621126020202")),
                0x90040501,
                2,
            ),
            (
                (bytes.fromhex("6211030200"), bytes.fromhex("621126010101")),
                0x90040501,
                2,
            ),
        ):
            received = iter(replies)
            cache = MonitorSupportCache(
                self.profile,
                lambda query, received=received: next(received),
                "rc-invalid",
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                capture_rc_image_p5_information(cache, frame, bytes(6))
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(cache.calls, count)

    def test_generic_p5_original12_wire_geometry_and_timestamp_filter(self):
        from scripts.database_resources import DdrP5SupportValue

        with tempfile.TemporaryDirectory() as directory:
            selected = profile(Path(directory), build=12)
            frame = selected.frame_records(0x66)[0]
            specification = bytearray.fromhex("6212030100000001000000")
            information = bytearray(70)
            information[:3] = bytes.fromhex("621202")
            information[6] = 12
            for offset in range(7, 35, 4):
                information[offset : offset + 4] = (13).to_bytes(4, "big")
            information[35:39] = (0x1000).to_bytes(4, "big")
            information[65] = 1
            queries = []
            replies = iter(
                (
                    b"\x67\x03" + bytes(6),
                    bytes.fromhex("621201020201020102"),
                    bytes(specification),
                    b"\x62",
                    b"\x62",
                    bytes(information),
                )
            )

            def exchange(query):
                queries.append(query)
                return next(replies)

            cache = MonitorSupportCache(selected, exchange, "image12", source_build=12)
            capture_image_p5_security(cache, frame, bytes(6))
            self.assertEqual(capture_image_p5_memorized(cache, frame), (1, 3, 5))
            acquired = capture_image_p5_information(cache, frame)
            self.assertEqual(acquired.build, 12)
            self.assertEqual(
                [query.request.hex() for query in queries],
                ["2703", "221201", "221203", "221204", "222090", "221202"],
            )
            self.assertEqual(
                set(dict(acquired.record_lengths)),
                {
                    0x0F00,
                    0x1000,
                    0x1203,
                    0x1204,
                    0x1205,
                    0x120E,
                    0x1300,
                    0x1402,
                    0x1403,
                    0x1900,
                },
            )
            for offset in range(7, 35, 4):
                malformed = bytearray(information)
                malformed[offset : offset + 4] = (12).to_bytes(4, "big")
                with self.assertRaises(ToyotaCodecError) as caught:
                    image_p5_information(
                        bytes(specification), bytes(malformed), build=12
                    )
                self.assertEqual(caught.exception.code, 0x90040501)
            specification[3] = 2
            with self.assertRaises(ToyotaCodecError):
                image_p5_information(bytes(specification), bytes(information), build=12)
            for present, first, timestamp, second, expected in (
                (True, 0x1234, 0x20000009, 0x40000008, 0x1234),
                (True, 0x1234, 9, 9, None),
                (True, 0x1234, 9, 10, None),
                (False, 0x1234, 9, 10, 0x1234),
                (True, 0x1233, 9, 10, 0x1234),
                (True, 0x1235, 9, 8, None),
            ):
                header = bytearray.fromhex("630f0012340000000000000000")
                header[5:9] = timestamp.to_bytes(4, "big")
                header[9] = sum(header[1:9]) & 255
                replies = iter((bytes(header), b"\x63"))
                cache = MonitorSupportCache(
                    selected,
                    lambda query, replies=replies: next(replies),
                    "image12-record",
                    source_build=12,
                )
                result = capture_image_p5_record(
                    cache,
                    frame,
                    acquired,
                    1,
                    0,
                    DdrP5SupportValue(170, True, first),
                    DdrP5SupportValue(171, present, second),
                )
                self.assertEqual(result.scalar, expected)
                self.assertEqual(result.excluded, expected is None)

            def body_fault(query):
                if query.request[-1] == acquired.header_size:
                    return bytes(header)
                raise ToyotaCodecError("authored original12 body NRC", 0x90020323)

            cache = MonitorSupportCache(
                selected, body_fault, "image12-fault", source_build=12
            )
            partial = capture_image_p5_record(
                cache,
                frame,
                acquired,
                1,
                0,
                DdrP5SupportValue(170, False, 0),
                DdrP5SupportValue(171, False, 0),
            )
            self.assertEqual(partial.scalar, 0x1234)
            self.assertEqual(partial.native_status, 0x90020323)
            self.assertFalse(partial.retry)
            self.assertEqual(len(partial.body), 1)
            self.assertEqual(partial.next_offset, 13)
            with self.assertRaises(ValueError):
                selected_image_p5_schedule(b"MZ", build=12)

    def test_generic_p5_exact_caller_bytes_and_ddr_selector(self):
        for build, sha in IMAGE_P5_SOURCE_SHA256.items():
            self.assertEqual(ImageP5Source(build, sha).build, build)
            with self.assertRaises(ValueError):
                ImageP5Source(build, "0" * 64)
        empty = ImageP5Request18((), 0)
        self.assertEqual(empty.numbers, ())
        self.assertEqual(empty.ddr_category, 0xBC)
        selected = ImageP5Request18(
            (7, 1, 1, 0), 4, (ImageEcuReference(0x1BC, 2), ImageEcuReference(0xBC, 1))
        )
        self.assertEqual(selected.numbers, (7, 1, 1, 0))
        self.assertEqual(selected.ddr_category, 0xBC)
        selected = ImageP5Request18(
            (1,), 1, selected.ecu_info + (ImageEcuReference(0x1BC, 1),)
        )
        self.assertEqual(selected.ddr_category, 0x1BC)
        with self.assertRaises(ValueError):
            ImageP5Request18((256,), 1)

    def test_p5_image_actual_header_checksum_ddr_filter_and_body_chunks(self):
        from scripts.database_resources import DdrP5SupportValue

        frame = self.profile.frame_records(0x66)[0]
        spec = bytearray(11)
        spec[3], spec[7] = 1, 1
        raw = bytearray(70)
        raw[6] = 12
        raw[7:11] = (300).to_bytes(4, "big")
        raw[35:39] = (0x1000).to_bytes(4, "big")
        raw[65] = 1
        information = image_p5_information(bytes(spec), bytes(raw))
        for checksum_valid, value, present, fault, scalar in (
            (True, 0, False, False, 0x1234),
            (False, 0, False, False, None),
            (True, 0x1234, True, False, None),
            (True, 0x1233, True, False, 0x1234),
            (True, 0, False, True, 0x1234),
        ):
            header = bytearray.fromhex("630f0012340102030400000000")
            header[9] = sum(header[1:9]) & 255
            if not checksum_valid:
                header[9] ^= 1
            queries = []
            replies = [bytes(header), b"\x63", b"\x63"]

            def exchange(query, queries=queries, replies=replies, fault=fault):
                queries.append(query)
                if len(queries) == 2 and fault:
                    replies.pop(0)
                    raise ToyotaCodecError("authored image body NRC", 0x90020323)
                return replies.pop(0)

            cache = MonitorSupportCache(self.profile, exchange, "image-record")
            acquired = capture_image_p5_record(
                cache, frame, information, 1, 0, DdrP5SupportValue(170, present, value)
            )
            self.assertEqual(
                [query.request.hex() for query in queries],
                ["231501000010000c", "2315010000100cff", "2315010000110b21"],
            )
            self.assertEqual(acquired.native_status, 0)
            self.assertEqual(acquired.scalar, scalar)
            self.assertEqual(acquired.checksum_valid, checksum_valid)
            self.assertEqual(acquired.retry, not checksum_valid or fault)
            self.assertEqual(
                acquired.excluded, checksum_valid and present and value == 0x1234
            )
            self.assertEqual(acquired.next_offset, 300)
            self.assertEqual(tuple(item.length for item in acquired.body), (255, 33))
            self.assertEqual(acquired.body[0].native_status, 0x90020323 if fault else 0)

    def test_p5_image_actual_spec_customization_and_versioned_field_association(self):
        frame = self.profile.frame_records(0x66)[0]
        for format in (1, 2, 3, 4):
            spec = bytearray(13)
            spec[:4] = bytes((0x62, 0x12, 3, format))
            spec[7] = 2 if format == 4 else 1
            info = bytearray(range(96))
            info[:3], info[6] = bytes.fromhex("621202"), 8
            replies = iter((bytes(spec), b"\x62", b"\x62", bytes(info)))
            queries = []

            def exchange(query, queries=queries, replies=replies):
                queries.append(query)
                return next(replies)

            cache = MonitorSupportCache(self.profile, exchange, "p5-info")
            acquired = capture_image_p5_information(cache, frame)
            self.assertEqual(
                [query.request.hex() for query in queries],
                ["221203", "221204" if format == 1 else "22201a", "222090", "221202"],
            )
            self.assertTrue(all(query.extended for query in queries))
            self.assertEqual(acquired.header_size, 8)
            self.assertEqual(acquired.format, format)
            self.assertEqual(
                dict(acquired.record_lengths)[0x1402],
                int.from_bytes(info[23:27], "big"),
            )
            self.assertEqual(
                dict(acquired.record_lengths)[0x120E],
                int.from_bytes(info[27:31] if format == 1 else info[15:19], "big"),
            )
            self.assertEqual(acquired.addresses[0], int.from_bytes(info[35:39], "big"))
            self.assertEqual(
                len(acquired.counts), 5 if format == 1 else 6 if format == 2 else 7
            )
            if format in (3, 4):
                self.assertEqual(
                    acquired.addresses[-1], int.from_bytes(info[86:90], "big")
                )
            with self.assertRaises(ToyotaCodecError) as caught:
                image_p5_information(bytes(spec), bytes(info[:69]))
            self.assertEqual(caught.exception.code, 0xA0040202)
        invalid = bytearray(spec)
        invalid[8] = 1
        cache = MonitorSupportCache(
            self.profile, lambda query: bytes(invalid), "bad-p5-info"
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            capture_image_p5_information(cache, frame)
        self.assertEqual(caught.exception.code, 0x90040501)
        self.assertEqual(cache.calls, 1)

    def test_p5_image_memorized_native_selected_counts_and_bounds(self):
        frame = self.profile.frame_records(0x66)[0]
        for selector, expected in (
            (1, (1, 3, 5)),
            (2, (1, 3, 5, 6)),
            (3, (1, 3, 5, 6, 7)),
            (4, (1, 3, 5, 6, 7)),
        ):
            queries = []

            def exchange(query, queries=queries):
                queries.append(query)
                return bytes.fromhex("6212010202010201020202")

            cache = MonitorSupportCache(self.profile, exchange, "image-flags")
            self.assertEqual(
                capture_image_p5_memorized(cache, frame, selector), expected
            )
            self.assertEqual(queries[0].request, bytes.fromhex("221201"))
            self.assertTrue(queries[0].extended)
        cache = MonitorSupportCache(
            self.profile,
            lambda query: bytes.fromhex("62ffff020201020102"),
            "image-flags-no-did-check",
        )
        self.assertEqual(capture_image_p5_memorized(cache, frame, 1), (1, 3, 5))
        for selector, reply, code in (
            (0, bytes.fromhex("621201020202020202"), 0x90040501),
            (1, bytes.fromhex("621201020101010101"), 0x90040501),
            (2, bytes.fromhex("621201020202020202"), 0xA0040202),
        ):
            cache = MonitorSupportCache(
                self.profile, lambda query, reply=reply: reply, "image-bad-flags"
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                capture_image_p5_memorized(cache, frame, selector)
            self.assertEqual(caught.exception.code, code)

    def test_p5_image_native_replacement_frame_security_stage(self):
        for seed in (bytes(6), bytes.fromhex("010203040506")):
            queries = []

            def exchange(query, seed=seed, queries=queries):
                queries.append(query)
                return (
                    b"\x67\x03" + seed if query.request == b"\x27\x03" else b"\x67\x04"
                )

            cache = MonitorSupportCache(self.profile, exchange, "p5-image-security")
            frame = self.profile.frame_records(0x66)[0]
            result = capture_image_p5_security(cache, frame, bytes(6))
            self.assertEqual(
                [query.request for query in queries],
                [b"\x27\x03", bytes.fromhex("27040613340d1a36")]
                if any(seed)
                else [b"\x27\x03"],
            )
            self.assertTrue(
                all(query.selected == frame and query.extended for query in queries)
            )
            self.assertEqual(result.key_reply, b"\x67\x04" if any(seed) else None)
        for reply, status in (
            (b"\x67\x02" + bytes(6), 0xA0040201),
            (b"\x67\x03" + bytes(5), 0xA0040202),
        ):
            cache = MonitorSupportCache(
                self.profile, lambda query, reply=reply: reply, "p5-image-fault"
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                capture_image_p5_security(cache, frame, bytes(6))
            self.assertEqual(caught.exception.code, status)
        with self.assertRaises(ValueError):
            selected_image_p5_schedule(b"MZ")

    def test_pcs_complete_selected_outer_real_wire_and_partial_fault(self):
        from dataclasses import replace

        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture, serialized_profile

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            SavedOperationFacadeFreeze,
            SavedOperationFacadeResult,
            SavedOperationFacadeValue,
        )
        from scripts.database_resources import DdrPacketLog
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        class PcsFixture(J2534Fixture):
            cancel_last = False

            def invoke(self, operation, fields, *, deadline, cancelled):
                if (
                    operation == "read_messages"
                    and len(self.replies) == 1
                    and self.cancel_last
                ):
                    raise Cancelled("authored PCS counter cancellation")
                return super().invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )

        cases = (
            (12, False),
            (18, False),
            (12, True),
            (18, True),
            (12, "cancel"),
            (18, "cancel"),
            (12, "ascii"),
            (18, "ascii"),
            (12, "p5"),
            (18, "p5"),
        )
        for build, fault, facade in (
            (build, fault, facade) for build, fault in cases for facade in (False, True)
        ):
            if fault in ("ascii", "p5") and not facade:
                continue
            with (
                self.subTest(build=build, fault=fault, facade=facade),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                authored = profile(root)
                selected = serialized_profile(
                    version=build,
                    flags=4,
                    request=bytes.fromhex("21000000"),
                    check=b"\x61",
                )
                selected.catalog.language = authored.catalog.language
                group, freeze, operation = bytearray(12), bytearray(84), bytearray(8)
                struct.pack_into("<H", group, 4, 1)
                group[8] = 0x25
                struct.pack_into("<H", freeze, 56, 100)
                struct.pack_into("<HH", freeze, 62, 0, 31)
                struct.pack_into("<H", freeze, 70, 7)
                freeze[79] = 0xE1
                operation[5] = 13
                pattern = bytearray(20 if build == 12 else 24)
                if build == 12:
                    struct.pack_into("<HH", pattern, 4, 7, 0)
                    struct.pack_into("<H", pattern, 10, 0x1234)
                else:
                    struct.pack_into("<I", pattern, 4, 0x00E11234)
                    struct.pack_into("<H", pattern, 12, 7)
                items = []
                for key in (10, 11, 12):
                    row = bytearray(12)
                    struct.pack_into("<3H", row, 0, key, 16, 23)
                    row[8] = 10
                    items.append(bytes(row))
                diagnostic = {
                    0: (1, bytes(group)),
                    1: (1, struct.pack("<4H", 1, 100, 0, 0)),
                    3: (2, bytes((0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xE0, 1, 0, 0))),
                    10: (1, bytes(freeze)),
                    14: (1, bytes(pattern)),
                    38: (3, b"".join(items)),
                    54: (1, bytes(operation)),
                    86: (2, bytes((0, 0, 0xE1, 1, 0, 0, 10, 2))),
                }
                encoded = bytearray(database(2, diagnostic))
                struct.pack_into("<I", encoded, 28, selected.database.version)
                selected = replace(selected, database=parse_database(bytes(encoded)))
                sections = {
                    slot: (section.count, section.payload)
                    for slot, section in selected.catalog.management.sections.items()
                }
                values = (
                    b"\x10\x01",
                    b"\x81",
                    b"\x3e",
                    b"\x81",
                    bytes.fromhex("21000000"),
                    b"\xff",
                    b"\x61",
                    bytes.fromhex("0100"),
                    bytes.fromhex("12000000"),
                )
                index, storage = bytearray(), bytearray()
                for value in values:
                    index += struct.pack("<IH", len(storage), len(value))
                    storage += value
                sections[0] = (len(values), bytes(index + storage))
                count, comm = sections[17]
                sections[17] = (
                    count + 2,
                    comm + struct.pack("<8H", 50, 8, 0, 0, 51, 9, 0, 0),
                )
                count, functions = sections[18]
                rows = [
                    functions[offset : offset + 16]
                    for offset in range(0, len(functions), 16)
                ]
                rows += [
                    struct.pack("<8H", 42, function, 1, comm, 0, 0, 0, 0)
                    for function, comm in (
                        (0x0E, 51),
                        (0x0F, 50),
                        (0x11, 0),
                        (0x13, 50),
                    )
                ]
                rows.sort(
                    key=lambda row: (
                        int.from_bytes(row[:2], "little"),
                        int.from_bytes(row[2:4], "little"),
                    )
                )
                sections[18] = (count + 4, b"".join(rows))
                support = bytearray(24)
                struct.pack_into("<4H", support, 4, 1, 0x13, 0xE1, 42)
                support[18], support[19], support[23] = 1, 1, 1
                sections[48] = (1, bytes(support))
                module = bytearray(88)
                name = (
                    "GetOperationFrzFrmDatP5_DT.dll\0"
                    if fault == "p5"
                    else "GetPCSOperationFFDP4_DT.dll\0"
                ).encode("ascii" if fault == "ascii" else "utf-16le")
                module[: len(name)] = name
                struct.pack_into("<H", module, 80, 42)
                module[86] = 0xBA
                sections[19] = (1, bytes(module))
                encoded = bytearray(database(1, sections))
                struct.pack_into("<I", encoded, 28, selected.catalog.management.version)
                selected.catalog.management = parse_database(bytes(encoded))
                payloads = [
                    bytes.fromhex("000007e86100"),
                    bytes.fromhex("000007e84100e104010101010a0401010101"),
                    None,
                    bytes.fromhex("000007e8610d00e112340000"),
                    bytes.fromhex("000007e841000040"),
                    bytes.fromhex("000007e841e080"),
                    bytes.fromhex("000007e8520d00400000"),
                    bytes.fromhex("000007e8520d80000000"),
                    None if fault else bytes.fromhex("000007e8610d000a01010000"),
                ]
                if not fault:
                    payloads += [
                        bytes.fromhex("000007e861fd000a01010000"),
                        bytes.fromhex("000007e8611d000a01010000"),
                    ]
                backend = PcsFixture(
                    [
                        J2534Result(code=9)
                        if payload is None
                        else J2534Result(
                            count=1, messages=(NativeMessage(6, 0, 0, 0, 0, payload),)
                        )
                        for payload in payloads
                    ]
                )
                backend.cancel_last = fault == "cancel"
                if build == 12:
                    backend.replies.insert(1, J2534Result(code=9))
                channel = NativeCommunication.from_backend(
                    selected,
                    backend,
                    "pcs-saved",
                    first_request=bytes.fromhex("210d00e1"),
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=build,
                    clock=lambda: 0.0,
                )
                assert isinstance(channel.operations, NativeFrameController)
                logger = DdrPacketLog(root / "logs", channel.operations)
                api = CommandAPI(CommandSource(build, SOURCE_SHA256[build]))
                prior = SavedOperationFacadeResult(
                    0, (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),)
                )
                if fault in ("ascii", "p5"):
                    with self.assertRaises(NotImplementedError):
                        api.get_pcs_operation_ffd(channel, logger, previous=prior)
                    self.assertEqual(backend.calls, [])
                    self.assertFalse((root / "logs").exists())
                    continue
                if fault == "cancel":
                    with self.assertRaises(Cancelled):
                        if facade:
                            api.get_pcs_operation_ffd(channel, logger, previous=prior)
                        else:
                            capture_pcs_saved_operations(
                                channel,
                                logger,
                                PcsOperationSource(
                                    build, PCS_OPERATION_SOURCE_SHA256[build]
                                ),
                            )
                    self.assertFalse(logger.active)
                    self.assertIsNone(logger._file)
                    self.assertFalse(channel.closed)
                    backend.cancel_last = False
                    channel.disconnect(1)
                    continue
                if facade:
                    result = api.get_pcs_operation_ffd(channel, logger, previous=prior)
                    self.assertEqual(result.return_code, 0x91010009 if fault else 0)
                    self.assertEqual(
                        tuple(freeze.values[0].scalar for freeze in result.freezes),
                        (99,) if fault else (99, 0x1234),
                    )
                    report = json.loads(json.dumps(api.pcs_operation_report(result)))
                    self.assertEqual(
                        report["result"]["freezes"][0]["values"][0]["scalar"], 99
                    )
                    serialized = json.dumps(report)
                    for private in (
                        "matched_value",
                        "raw_reply",
                        "expanded",
                        "log_path",
                    ):
                        self.assertNotIn(private, serialized)
                    self.assertFalse(logger.active)
                    self.assertIsNone(logger._file)
                    self.assertFalse(channel.closed)
                    channel.disconnect(1)
                    continue
                result = capture_pcs_saved_operations(
                    channel,
                    logger,
                    PcsOperationSource(build, PCS_OPERATION_SOURCE_SHA256[build]),
                )
                self.assertEqual(result.native_status, 0x91010009 if fault else 0)
                self.assertEqual(len(result.freezes), 1)
                self.assertEqual(result.freezes[0].first.scalar, 0x1234)
                if fault:
                    self.assertIsNone(result.freezes[0].second)
                else:
                    assert result.freezes[0].second is not None
                    assert result.freezes[0].third is not None
                    self.assertEqual(result.freezes[0].second.records[0].number, 0xFD)
                    self.assertEqual(result.freezes[0].third.records[0].number, 0x1D)
                self.assertTrue(Path(result.log_path).is_file())
                self.assertFalse(logger.active)
                self.assertFalse(channel.closed)
                channel.disconnect(1)

    def test_pcs_actual_distinct_enable_and_native_record_phases(self):
        from test_monitor_support import SupportStreamDriver

        for build in (12, 18):
            with self.subTest(build=build), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                selected = image_information_profile(root, build)
                sections = {
                    slot: (item.count, item.payload)
                    for slot, item in selected.catalog.management.sections.items()
                }
                values = (b"\x01\0", b"\x21\0\0\0", b"\x12\0\0\0")
                sections[0] = (
                    3,
                    struct.pack("<IHIHIH", 0, 2, 2, 4, 6, 4) + b"".join(values),
                )
                sections[17] = (
                    3,
                    struct.pack("<12H", 1, 1, 0, 0, 2, 2, 0, 0, 3, 3, 0, 0),
                )
                sections[18] = (
                    4,
                    b"".join(
                        struct.pack("<8H", 42, function, 1, comm, 0, 0, 0, 0)
                        for function, comm in (
                            (0x0E, 3),
                            (0x0F, 1),
                            (0x11, 2),
                            (0x13, 1),
                        )
                    ),
                )
                data = bytearray(database(1, sections))
                struct.pack_into("<I", data, 28, selected.catalog.management.version)
                (root / "Toyota.ddb").write_bytes(data)
                diagnostic = {
                    3: (1, bytes((0, 0, 0, 0, 0xE0, 1, 0, 0))),
                    86: (
                        4,
                        b"".join(
                            bytes((0, 0, pid, selector))
                            for pid, selector in ((0xE1, 1), (10, 2), (11, 2), (12, 2))
                        ),
                    ),
                }
                data = bytearray(database(2, diagnostic))
                struct.pack_into("<I", data, 28, selected.database.version)
                (root / "demo.ddb").write_bytes(data)
                selected = VehicleCatalog(root).build_profile(42)
                stream = SupportStreamDriver(
                    [
                        (
                            0,
                            b"\x41\0"
                            + b"".join(
                                bytes((pid, 4, 1, 1, 1, 1))
                                for pid in (0xE1, 10, 11, 12)
                            ),
                        ),
                        (0x91010009, b""),
                    ]
                )
                queries = []

                def exchange(query, queries=queries):
                    queries.append(query)
                    if query.request == b"\x01\xe0":
                        return b"\x41\xe0\x80"
                    if query.request[0] == 0x12:
                        return bytes((0x52, query.request[1], 0x80, 0, 0, 0))
                    return bytes(
                        (0x61, query.request[1], 0, query.request[3], 0x12, 0x34, 0, 0)
                    )

                cache = MonitorSupportCache(
                    selected,
                    exchange,
                    "pcs-actual",
                    source_build=build,
                    stream=stream,
                    bus_id=7,
                )
                source = PcsOperationSource(build, PCS_OPERATION_SOURCE_SHA256[build])
                enabled = cache.pcs_operation_pids(kind=1)
                self.assertEqual(enabled, {0xE1: 4})
                with cache.temporary_scope():
                    first = capture_pcs_operation_phase(
                        cache, source, 13, 1, enabled=enabled
                    )
                    second = capture_pcs_operation_phase(
                        cache, source, 13, 2, repeats=2, pid_count=2
                    )
                    third = capture_pcs_operation_phase(
                        cache, source, 13, 3, repeats=2, pid_count=1
                    )
                self.assertEqual(first.scalar, 0x1234)
                self.assertEqual(
                    [(record.number, record.pid) for record in second.records],
                    [(0xFD, 10), (0xFD, 11), (0xED, 10), (0xED, 11)],
                )
                self.assertEqual(
                    [(record.number, record.pid) for record in third.records],
                    [(0x1D, 10), (0x2D, 10)],
                )
                self.assertEqual(queries[1].request, bytes.fromhex("210d00e1"))
                item = bytearray(12)
                struct.pack_into("<HH", item, 2, 16, 31)
                item[8] = 0xE1
                with cache.temporary_scope():
                    self.assertEqual(
                        capture_pcs_item(cache, source, bytes(item), 13), 0x1234
                    )
                self.assertEqual(queries[-2].request, bytes.fromhex("120d00e0"))

                def fault(query):
                    raise ToyotaCodecError("authored PCS receive fault", 0xA0040201)

                cache.exchange = fault
                with cache.temporary_scope():
                    suppressed = capture_pcs_operation_phase(
                        cache, source, 13, 2, repeats=2, pid_count=3
                    )
                self.assertEqual(suppressed.records, ())
                self.assertEqual(len(suppressed.suppressed_errors), 4)
                self.assertEqual(
                    [item[0] for item in suppressed.suppressed_errors],
                    [0xFD, 0xFD, 0xED, 0xED],
                )

    def test_image_p4_complete_real_communication_ram_and_saved_log(self):
        from dataclasses import replace

        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture, serialized_profile

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            ImageFacadeResult,
            SavedOperationFacadeFreeze,
            SavedOperationFacadeValue,
        )
        from scripts.database_resources import DdrPacketLog
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        class ImageFixture(J2534Fixture):
            cancel_last = False

            def invoke(self, operation, fields, *, deadline, cancelled):
                if (
                    operation == "read_messages"
                    and len(self.replies) == 1
                    and self.cancel_last
                ):
                    raise Cancelled("authored image RAM cancellation")
                return super().invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )

        cases = (
            (12, None),
            (18, None),
            (12, "status"),
            (18, "status"),
            (12, "malformed"),
            (18, "malformed"),
            (12, "cancel"),
            (18, "cancel"),
            (12, "log"),
            (18, "log"),
            (12, "ascii"),
            (18, "ascii"),
            (12, "p5"),
            (18, "p5"),
        )
        for build, ram_fault, facade in (
            (build, fault, facade) for build, fault in cases for facade in (False, True)
        ):
            if ram_fault in ("ascii", "p5") and not facade:
                continue
            with (
                self.subTest(build=build, ram_fault=ram_fault, facade=facade),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                selected = serialized_profile(
                    version=build, flags=4, request=b"\x21\0", check=b"\x61"
                )
                authored = image_information_profile(root, build)
                selected.catalog.language = authored.catalog.language
                diagnostic = {
                    slot: (section.count, section.payload)
                    for slot, section in authored.database.sections.items()
                }
                rows = []
                for index, row in enumerate(authored.records(10)):
                    row = bytearray(row)
                    row[79] = index + 1
                    struct.pack_into("<HH", row, 62, 0, 31)
                    rows.append(bytes(row))
                diagnostic[10] = (10, b"".join(rows))
                diagnostic[6] = (
                    10,
                    b"".join(bytes((0, 0, pid, 4, 0, 0, 0, 0)) for pid in range(1, 11)),
                )
                encoded = bytearray(database(2, diagnostic))
                struct.pack_into("<I", encoded, 28, selected.database.version)
                selected = replace(selected, database=parse_database(bytes(encoded)))
                sections = {
                    slot: (section.count, section.payload)
                    for slot, section in selected.catalog.management.sections.items()
                }
                values = (
                    b"\x10\x01",
                    b"\x81",
                    b"\x3e",
                    b"\x81",
                    b"\x21\0",
                    b"\xff",
                    b"\x61",
                    b"\x01\0",
                    b"\x27\x01",
                    b"\x23\0\0\0\0\0\0",
                )
                index, storage = bytearray(), bytearray()
                for value in values:
                    index += struct.pack("<IH", len(storage), len(value))
                    storage += value
                sections[0] = (len(values), bytes(index + storage))
                count, communications = sections[17]
                sections[17] = (
                    count + 3,
                    communications
                    + b"".join(
                        struct.pack("<4H", identifier, variable, 0, 0)
                        for identifier, variable in ((50, 8), (51, 9), (52, 10))
                    ),
                )
                count, functions = sections[18]
                function_rows = [
                    functions[offset : offset + 16]
                    for offset in range(0, len(functions), 16)
                ]
                function_rows += [
                    struct.pack("<8H", 42, function, 1, communication, 0, 0, 0, 0)
                    for function, communication in (
                        (0x0F, 50),
                        (0x13, 50),
                        (0x6B, 0),
                        (0xA1, 52),
                        (0xE5, 51),
                    )
                ]
                function_rows.sort(
                    key=lambda row: (
                        int.from_bytes(row[:2], "little"),
                        int.from_bytes(row[2:4], "little"),
                    )
                )
                sections[18] = (count + 5, b"".join(function_rows))
                module = bytearray(88)
                name = (
                    "GetImageFFDP5_DT.dll\0"
                    if ram_fault == "p5"
                    else "GetImageFFD_DT.dll\0"
                ).encode("ascii" if ram_fault == "ascii" else "utf-16le")
                module[: len(name)] = name
                struct.pack_into("<H", module, 80, 42)
                module[86] = 0xBB
                sections[19] = (1, bytes(module))
                encoded = bytearray(database(1, sections))
                struct.pack_into("<I", encoded, 28, selected.catalog.management.version)
                selected.catalog.management = parse_database(bytes(encoded))
                # Connection, raw support stream, enable bitmap, ten raw fields,
                # zero seed, and the exact trimmed six-byte RAM result.
                signal_values = (2, 2, 0, 0, 1, 0, 0, 0, 0x1000, 2)
                payloads = [
                    bytes.fromhex("000007e86100"),
                    b"\0\0\x07\xe8\x41\0"
                    + b"".join(bytes((pid, 4, 1, 1, 1, 1)) for pid in range(1, 11)),
                    None,
                    bytes.fromhex("000007e84100ffc0"),
                ]
                payloads += [
                    bytes.fromhex("000007e861")
                    + bytes((pid,))
                    + value.to_bytes(4, "big")
                    for pid, value in enumerate(signal_values, 1)
                ]
                payloads += [
                    bytes.fromhex("000007e86701") + bytes(6),
                    bytes.fromhex("000007e863010600001000123400000000"),
                ]
                backend = ImageFixture(
                    [
                        J2534Result(code=9)
                        if payload is None
                        else J2534Result(
                            count=1, messages=(NativeMessage(6, 0, 0, 0, 0, payload),)
                        )
                        for payload in payloads
                    ]
                )
                backend.cancel_last = ram_fault == "cancel"
                if ram_fault == "status":
                    backend.replies[-1] = J2534Result(code=9)
                elif ram_fault == "malformed":
                    backend.replies[-1] = J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 0, 0, bytes.fromhex("000007e8630106")
                            ),
                        ),
                    )
                if build == 12:
                    backend.replies.insert(1, J2534Result(code=9))
                channel = NativeCommunication.from_backend(
                    selected,
                    backend,
                    "saved-image",
                    first_request=b"\x01\0",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=build,
                    clock=lambda: 0.0,
                )
                assert isinstance(channel.operations, NativeFrameController)
                if ram_fault == "log":
                    (root / "logs").write_bytes(b"authored blocked log directory")
                logger = DdrPacketLog(root / "logs", channel.operations)
                api = CommandAPI(CommandSource(build, SOURCE_SHA256[build]))
                prior = ImageFacadeResult(
                    0,
                    (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),),
                    (7, 8, 9),
                )
                if ram_fault in ("ascii", "p5"):
                    with self.assertRaises(NotImplementedError):
                        api.get_image_ffd(channel, logger, bytes(6), previous=prior)
                    self.assertEqual(backend.calls, [])
                    self.assertFalse((root / "logs").exists())
                    continue
                if ram_fault == "cancel":
                    with self.assertRaises(Cancelled):
                        if facade:
                            api.get_image_ffd(channel, logger, bytes(6), previous=prior)
                        else:
                            capture_image_p4_saved(
                                channel,
                                logger,
                                ImageP4Source(build, IMAGE_P4_SOURCE_SHA256[build]),
                                bytes(6),
                            )
                    self.assertFalse(logger.active)
                    self.assertIsNone(logger._file)
                    self.assertFalse(channel.closed)
                    backend.cancel_last = False
                    channel.disconnect(1)
                    continue
                if facade:
                    saved = api.get_image_ffd(channel, logger, bytes(6), previous=prior)
                    self.assertEqual(
                        saved.return_code, 0x90020706 if ram_fault == "log" else 0
                    )
                    self.assertEqual(
                        tuple(freeze.values[0].scalar for freeze in saved.freezes),
                        (99,)
                        if ram_fault == "log"
                        else (
                            99,
                            0xFFFF if ram_fault in ("status", "malformed") else 0x1234,
                        ),
                    )
                    self.assertEqual(
                        saved.native_fields18,
                        (0, 0, 0) if build == 18 and ram_fault != "log" else (7, 8, 9),
                    )
                    report = api.image_ffd_report(saved)
                    decoded = json.loads(json.dumps(report))
                    self.assertEqual(
                        decoded["result"]["native_fields18"],
                        list(saved.native_fields18),
                    )
                    self.assertEqual(
                        decoded["result"]["freezes"][0]["values"][0]["scalar"], 99
                    )
                    serialized = json.dumps(report)
                    for private_field in (
                        "seed_reply",
                        "key_reply",
                        "raw_reply",
                        "log_path",
                        "schedule",
                    ):
                        self.assertNotIn(private_field, serialized)
                    self.assertFalse(logger.active)
                    self.assertIsNone(logger._file)
                    self.assertFalse(channel.closed)
                    channel.disconnect(1)
                    continue
                output = capture_image_p4_saved(
                    channel,
                    logger,
                    ImageP4Source(build, IMAGE_P4_SOURCE_SHA256[build]),
                    bytes(6),
                )
                self.assertEqual(
                    output.native_status, 0x90020706 if ram_fault == "log" else 0
                )
                self.assertEqual(
                    tuple(record.scalar for record in output.records),
                    (0xFFFF if ram_fault in ("status", "malformed") else 0x1234,),
                )
                self.assertEqual(
                    output.records[0].raw,
                    b"\xff" * 6
                    if ram_fault in ("status", "malformed")
                    else bytes.fromhex("123400000000"),
                )
                self.assertFalse(logger.active)
                self.assertIsNone(logger._file)
                self.assertEqual(Path(output.log_path).is_file(), ram_fault != "log")
                self.assertFalse(channel.closed)
                self.assertNotEqual(backend.calls[-1][0], "disconnect")
                channel.disconnect(1)

    def test_image_p4_actual_support_stream_enable_and_selected_value_order(self):
        from test_monitor_support import SupportStreamDriver

        for build in (12, 18):
            with self.subTest(build=build), tempfile.TemporaryDirectory() as directory:
                selected = image_information_profile(Path(directory), build)
                stream = SupportStreamDriver(
                    [(0, b"\x41\0\x01\x01\xff"), (0x91010009, b"")]
                )
                queries = []

                def exchange(query, queries=queries):
                    queries.append(query)
                    return (
                        b"\x41\0\x80" if query.request == b"\x01\0" else b"\x61\x01\x02"
                    )

                cache = MonitorSupportCache(
                    selected,
                    exchange,
                    "image-information",
                    source_build=build,
                    stream=stream,
                    bus_id=7,
                )
                with cache.temporary_scope():
                    acquired = capture_image_p4_information(cache)
                self.assertEqual(tuple(item.value for item in acquired), (2,) * 10)
                self.assertEqual(
                    tuple(item.logical_pid for item in acquired), tuple(range(100, 110))
                )
                self.assertEqual(
                    [query.request for query in queries], [b"\x01\0", b"\x21\x01"]
                )
                self.assertEqual(
                    [event[0] for event in stream.events],
                    ["send", "receive", "receive"],
                )
            with tempfile.TemporaryDirectory() as directory:
                selected = image_information_profile(
                    Path(directory), build, (2,) + (1,) * 8 + (99,)
                )
                stream = SupportStreamDriver(
                    [(0, b"\x41\0\x01\x01\xff"), (0x91010009, b"")]
                )
                cache = MonitorSupportCache(
                    selected,
                    lambda query: b"\x41\0\x80",
                    "image-fault-order",
                    source_build=build,
                    stream=stream,
                    bus_id=7,
                )
                with self.assertRaises(ToyotaCodecError) as caught:
                    capture_image_p4_information(cache)
                self.assertEqual(caught.exception.code, 0xA0040004)

    def test_image_p4_selected_seed_key_chronology_and_faults(self):
        for build, version in ((12, 0x0100030C), (18, 0x0100032F)):
            for seed in (bytes(6), bytes.fromhex("010203040506")):
                with (
                    self.subTest(build=build, seed=seed.hex()),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    profile(root)
                    category = bytearray(76)
                    category[:18] = "demo.ddb\0".encode("utf-16le")
                    struct.pack_into("<H", category, 68, 42)
                    settings = bytearray(16)
                    struct.pack_into("<H", settings, 10, 1)
                    payload = b"\x27\x01\x27\x02" + bytes(6)
                    variables = struct.pack("<IHIH", 0, 2, 2, 8) + payload
                    management = bytearray(
                        database(
                            1,
                            {
                                0: (2, variables),
                                16: (1, category),
                                17: (2, struct.pack("<8H", 1, 1, 0, 0, 2, 2, 0, 0)),
                                18: (
                                    2,
                                    struct.pack(
                                        "<16H",
                                        42,
                                        0xE5,
                                        1,
                                        1,
                                        0,
                                        0,
                                        0,
                                        0,
                                        42,
                                        0xE6,
                                        1,
                                        2,
                                        0,
                                        0,
                                        0,
                                        0,
                                    ),
                                ),
                                29: (1, settings),
                            },
                        )
                    )
                    struct.pack_into("<I", management, 28, version)
                    (root / "Toyota.ddb").write_bytes(management)
                    for name in ("demo.ddb", "M_English.ddb"):
                        content = bytearray((root / name).read_bytes())
                        struct.pack_into("<I", content, 28, version)
                        (root / name).write_bytes(content)
                    selected = VehicleCatalog(root).build_profile(42)
                    queries = []

                    def exchange(query, queries=queries, seed=seed):
                        queries.append(query)
                        return (
                            b"\x67\x01" + seed
                            if query.request == b"\x27\x01"
                            else b"\x67\x02"
                        )

                    cache = MonitorSupportCache(
                        selected, exchange, "authored-image-p4", source_build=build
                    )
                    source = ImageP4Source(build, IMAGE_P4_SOURCE_SHA256[build])
                    with cache.temporary_scope():
                        result = capture_image_p4_security(cache, source, bytes(6))
                    expected = [b"\x27\x01"]
                    if any(seed):
                        expected.append(bytes.fromhex("27020613340d1a36"))
                    self.assertEqual([query.request for query in queries], expected)
                    self.assertEqual(
                        result.key_reply, b"\x67\x02" if any(seed) else None
                    )
                    self.assertTrue(
                        all(
                            query.native_parameter == 0 and not query.extended
                            for query in queries
                        )
                    )
                    self.assertEqual(
                        [
                            int.from_bytes(
                                query.selected.function_record[2:4], "little"
                            )
                            for query in queries
                        ],
                        [0xE5, 0xE6] if any(seed) else [0xE5],
                    )
                    short = MonitorSupportCache(
                        selected,
                        lambda query: b"\x67\x01" + bytes(5),
                        "short-image",
                        source_build=build,
                    )
                    with self.assertRaises(ToyotaCodecError) as caught:
                        capture_image_p4_security(short, source, bytes(6))
                    self.assertEqual(caught.exception.code, 0xA0040202)

    def test_image_p4_native_keys_layout_and_selected_metadata(self):
        self.assertEqual(
            image_p4_security_key(bytes.fromhex("010203040506"), bytes(6)).hex(),
            "0613340d1a36",
        )
        # Later iterations consume already written output, rather than the
        # original seed. Shift counts retain the native x86 low-five bits.
        self.assertEqual(
            image_p4_security_key(bytes.fromhex("010203040506"), bytes((32,) * 6)),
            image_p4_security_key(bytes.fromhex("010203040506"), bytes(6)),
        )
        for seed, schedule in ((b"", bytes(6)), (bytes(6), bytes(5))):
            with self.assertRaises(ValueError):
                image_p4_security_key(seed, schedule)
        for build, sha in IMAGE_P4_SOURCE_SHA256.items():
            source = ImageP4Source(build, sha)
            with self.assertRaises(ValueError):
                selected_image_p4_schedule(source, b"MZ")
        groups, checks = [], []
        for index in range(10):
            row = bytearray(12)
            struct.pack_into("<H", row, 4, index + 1)
            # Duplicates are legal; association uses this row's WORD4.
            row[8] = 0x2A if index < 2 else 0x2A + index
            groups.append(bytes(row))
            checks.append(struct.pack("<4H", index + 1, 100 + index, 0, 0))
        with tempfile.TemporaryDirectory() as directory:
            selected = profile(
                Path(directory), {0: (10, b"".join(groups)), 1: (10, b"".join(checks))}
            )
            definitions = image_p4_signal_definitions(selected)
            self.assertEqual(
                tuple(item.logical_pid for item in definitions), tuple(range(100, 110))
            )
            self.assertEqual(
                tuple(item.selector for item in definitions[:2]), (0x2A, 0x2A)
            )
        values = (
            (0x2C, 0x100),
            (0x2E, 0x102),
            (0x31, 99),
            (0x32, 0x12340000),
            (0x33, 6),
        )
        layout = image_p4_ram_layout(
            tuple(ImageP4Signal(0, selector, b"", value) for selector, value in values)
        )
        self.assertEqual(
            (layout.address, layout.count, layout.stride, layout.length),
            (0x12340000, 2, 10, 20),
        )
        raw = bytes.fromhex("12340000abcd00000000aabb0000ef1200000000")
        self.assertEqual(
            tuple(item.scalar for item in image_p4_saved_records(layout, raw, 0x178)),
            (0xABCD, 0xEF12),
        )
        self.assertEqual(
            tuple(item.scalar for item in image_p4_saved_records(layout, raw, 42)),
            (0x1234, 0xAABB),
        )
        self.assertEqual(
            b"".join(item.raw for item in image_p4_saved_records(layout, raw, 42)), raw
        )
        with self.assertRaises(ToyotaCodecError):
            image_p4_saved_records(layout, raw[:-1], 42)
        with self.assertRaises(ToyotaCodecError) as caught:
            image_p4_ram_layout((ImageP4Signal(0, 0x2E, b"", 0),))
        self.assertEqual(caught.exception.code, 0xA0040201)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.profile = profile(Path(directory.name))
        self.source = SavedFfdSource(18, TSS3_SOURCE_SHA256)

    def test_actual_selected_ddb_chronology_and_owned_values(self):
        queries = []
        reply = bytes.fromhex(
            "eb1300010002030501021234050102ffff050202000101050102abcd"
        )
        replies = iter((bytes.fromhex("eb1100010002ff"), reply))

        def exchange(query):
            queries.append(query)
            return next(replies)

        cache = MonitorSupportCache(self.profile, exchange, "authored-tss3")
        provider = SavedFfdProvider(cache, self.source)
        self.assertEqual(provider.tss3_supported_ids(), (1, 2))
        result = provider.tss3_operation(Tss3OperationRequest(1, 2))
        self.assertEqual(
            [q.request for q in queries], [b"\xab\x11", bytes.fromhex("ab1300010002")]
        )
        self.assertTrue(all(q.extended and q.native_parameter == 0 for q in queries))
        self.assertTrue(
            all(q.selected in self.profile.frame_records(0x66) for q in queries)
        )
        self.assertEqual(result.raw_reply, reply)
        self.assertEqual(
            [group.values for group in result.groups], [(0x1234,), (0xABCD,)]
        )
        self.assertEqual([r.did for r in result.groups[0].records], [0x501, 0x502])

    def test_count_zero_native_scan_and_truncated_tail(self):
        self.assertEqual(
            tss3_operation_groups(bytes.fromhex("eb1300000000000501021234"))[0].values,
            (0x1234,),
        )
        truncated = bytes.fromhex("eb1300000000020501021234050203ff")
        result = tss3_operation_groups(truncated)
        self.assertEqual(result[0].values, (0x1234,))
        self.assertEqual(tss3_operation_groups(b"\xeb\x13"), ())

    def test_zero_did_zero_length_and_short_projection(self):
        reply = bytes.fromhex("eb130000000004000001ff05010005010112050201aa")
        result = tss3_operation_groups(reply)
        self.assertEqual([r.did for r in result[0].records], [0x501, 0x502])
        self.assertEqual(result[0].values, ())
        with self.assertRaises(ToyotaCodecError) as raised:
            tss3_supported_ids(b"\xeb\x11")
        self.assertEqual(raised.exception.code, 0x90040501)

    def test_fault_cancel_budget_and_source_guard(self):
        calls = []
        cancelled = [False]

        def exchange(query):
            calls.append(query)
            raise ToyotaCodecError("authored transport failure", 0x90020323)

        cache = MonitorSupportCache(
            self.profile,
            exchange,
            "fault",
            limits=Limits(exchanges=1),
            cancelled=lambda: cancelled[0],
        )
        provider = SavedFfdProvider(cache, self.source)
        with self.assertRaises(ToyotaCodecError):
            provider.tss3_supported_ids()
        self.assertEqual(len(calls), 1)
        with self.assertRaises(SessionError):
            provider.tss3_supported_ids()
        cancelled[0] = True
        with self.assertRaises(Cancelled):
            provider.tss3_supported_ids()
        cancelled[0] = False
        cache.ecu = "different-selection"
        with self.assertRaises(SessionError):
            provider.tss3_supported_ids()
        self.assertEqual(len(calls), 1)

    def test_deadline_and_service_fault_never_produce_acquisition(self):
        now = [0.0]

        def delayed(query):
            now[0] = 2.0
            return b"\xeb\x11\x00\x01"

        cache = MonitorSupportCache(
            self.profile,
            delayed,
            "deadline",
            limits=Limits(seconds=1),
            clock=lambda: now[0],
        )
        with self.assertRaises(SessionError):
            SavedFfdProvider(cache, self.source).tss3_supported_ids()
        cache = MonitorSupportCache(
            self.profile, lambda query: b"\xaa\x11\x00\x01", "service"
        )
        with self.assertRaises(ToyotaCodecError) as raised:
            SavedFfdProvider(cache, self.source).tss3_supported_ids()
        self.assertEqual(raised.exception.code, 0xA0040201)

    def test_ads_native64_extraction_and_support_conditions(self):
        self.assertEqual(
            ads_extract_bits64(bytes.fromhex("8123456789abcdef"), 0, 63),
            0x8123456789ABCDEF,
        )
        self.assertEqual(ads_extract_bits64(bytes.fromhex("f12340"), 4, 19), 0x1234)
        row = bytearray(60)
        struct.pack_into("<H", row, 36, 99)
        struct.pack_into("<HH", row, 42, 8, 15)
        struct.pack_into("<H", row, 52, 0x1234)
        row[59] = 1
        definition = AdsDdrValueDefinition(bytes(row), 1)
        self.assertEqual(
            definition.decode((OperationDataId(0x1234, b"\x01\x45"),)), 0x45
        )
        self.assertIsNone(definition.decode((OperationDataId(0x1234, b"\x00\x45"),)))
        self.assertIsNone(definition.decode((OperationDataId(0x1234, b"\x01"),)))
        struct.pack_into("<H", row, 38, 9)
        condition = AdsDdrBitCondition(4, 7, 7, b"\x88\x99")
        definition = AdsDdrValueDefinition(bytes(row), 0, condition)
        self.assertIsNone(definition.decode((OperationDataId(0x1234, b"\x00\x45"),)))
        self.assertEqual(
            definition.decode(
                (OperationDataId(0x1234, b"\x00\x45"), OperationDataId(0x8899, b"\x01"))
            ),
            0x45,
        )
        self.assertIsNone(
            AdsDdrValueDefinition(bytes(row), 3, condition).decode(
                (OperationDataId(0x1234, b"\x00\x45"),)
            )
        )
        with self.assertRaises(ToyotaCodecError):
            AdsDdrValueDefinition(bytes(row), 0)
        with self.assertRaises(ToyotaCodecError):
            AdsDdrBitCondition(0, 0, 6, b"\x88\x99").enabled(
                (OperationDataId(0x8899, b"\x01"),)
            )

    def test_ads_selected_real_ddb_hydrated_rob_condition_to64_value(self):
        with tempfile.TemporaryDirectory() as directory:
            row = bytearray(60)
            struct.pack_into("<HH", row, 36, 99, 3)
            struct.pack_into("<HH", row, 42, 0, 15)
            struct.pack_into("<H", row, 52, 0x1234)
            did = bytearray(8)
            struct.pack_into("<H", did, 2, 0x1234)
            condition = bytearray(12)
            struct.pack_into("<HHHHH", condition, 0, 3, 2, 0, 0, 0)
            condition[11] = 7
            selected = profile(
                Path(directory),
                {
                    0: (1, struct.pack("<IH", 0, 2) + b"\x88\x99"),
                    89: (1, bytes(condition)),
                    90: (1, bytes(did)),
                    134: (1, bytes(row)),
                },
                condition_variable=b"\x88\x99",
            )
            observations = (
                OperationDataId(0x1234, bytes.fromhex("1234")),
                OperationDataId(0x8899, b"\x80"),
            )
            actual = decode_ads_ddr_group(selected, observations)
            self.assertEqual(
                [(r.identifier, r.did, value) for r, value in actual],
                [(99, 0x1234, 0x1234)],
            )
            self.assertEqual(decode_ads_ddr_group(selected, observations[:1]), ())

    def test_complete_tss3_group_index_record_business_chronology(self):
        requests = []
        replies = iter(
            (
                bytes.fromhex("eb1122703001"),
                bytes.fromhex("eb1230010100000200010002"),
                bytes.fromhex("eb1330010001010501021234"),
                bytes.fromhex("eb1330010002010501025678"),
                bytes.fromhex("eb133001010001050102ffff"),
            )
        )

        def exchange(query):
            requests.append(query.request)
            return next(replies)

        cache = MonitorSupportCache(self.profile, exchange, "complete-tss3")
        result = SavedFfdProvider(cache, self.source).capture_tss3_operation_records()
        self.assertEqual(
            requests,
            [
                bytes.fromhex(v)
                for v in (
                    "ab11",
                    "ab123001",
                    "ab1330010001",
                    "ab1330010002",
                    "ab1330010100",
                )
            ],
        )
        self.assertEqual(
            [(row.operation, row.group, row.native_values) for row in result.freezes],
            [(1, 0x3001, (0x1234,)), (2, 0x3001, (0x5678,))],
        )
        self.assertEqual(result.suppressed_errors, ())
        self.assertEqual(
            tss3_operation_numbers(bytes.fromhex("eb120001000200010002ff")), (1, 2)
        )

    def test_tss3_suppressed_index_and_two_consecutive_record_faults(self):
        requests = []

        def exchange(query):
            requests.append(query.request)
            if query.request == b"\xab\x11":
                return bytes.fromhex("eb1130013002")
            if query.request == bytes.fromhex("ab123002"):
                return bytes.fromhex("eb123002000100020003")
            raise ToyotaCodecError("authored suppressed receive", 0x90020323)

        cache = MonitorSupportCache(self.profile, exchange, "fault-tss3")
        result = SavedFfdProvider(cache, self.source).capture_tss3_operation_records()
        self.assertEqual(len(requests), 5)
        self.assertEqual(requests[-1], bytes.fromhex("ab1330020002"))
        self.assertEqual(result.freezes, ())
        self.assertEqual(len(result.suppressed_errors), 3)
        cache = MonitorSupportCache(
            self.profile, lambda query: bytes.fromhex("eb1122702271"), "known-only"
        )
        with self.assertRaises(ToyotaCodecError) as raised:
            SavedFfdProvider(cache, self.source).capture_tss3_operation_records()
        self.assertEqual(raised.exception.code, 0x90040501)

    def test_real43_77_105_49_chain_and_saved_log_failure_precedence(self):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture, serialized_profile
        from test_profiles import encode_database

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            SavedOperationFacadeFreeze,
            SavedOperationFacadeResult,
            SavedOperationFacadeValue,
        )
        from scripts.database_resources import DdrPacketLog
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        class FaultFixture(J2534Fixture):
            primary: BaseException | None = None
            cleanup: BaseException | None = None

            def invoke(self, operation, fields, *, deadline, cancelled):
                if (
                    operation == "read_messages"
                    and len(self.replies) == 1
                    and self.primary
                ):
                    raise self.primary
                if operation == "disconnect" and self.cleanup:
                    self.calls.append((operation, dict(fields)))
                    raise self.cleanup
                return super().invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )

        for build, sha, lcs, blocked, fault, facade in (
            (18, TSS3_SOURCE_SHA256, False, False, False, False),
            (18, TSS3_SOURCE_SHA256, False, True, False, False),
            (12, LCS_SOURCE_SHA256[12], True, False, False, False),
            (18, LCS_SOURCE_SHA256[18], True, False, False, False),
            (18, TSS3_SOURCE_SHA256, False, False, True, False),
            (18, LCS_SOURCE_SHA256[18], True, False, True, False),
            (18, TSS3_SOURCE_SHA256, False, False, False, True),
            (18, TSS3_SOURCE_SHA256, False, True, False, True),
            (12, LCS_SOURCE_SHA256[12], True, False, False, True),
            (18, LCS_SOURCE_SHA256[18], True, False, False, True),
        ):
            selected = serialized_profile(
                version=build, flags=4, request=b"\x21\x00", check=b"\x61"
            )
            sections = {
                slot: (s.count, s.payload)
                for slot, s in selected.catalog.management.sections.items()
            }
            count, functions = sections[18]
            sections[18] = (
                count + 1,
                struct.pack("<8H", 42, 0x66, 1, 0, 0, 0, 0, 0) + functions,
            )
            module = (
                b"GetLCSOperationFFDP5_DT.dll"
                if lcs
                else b"GetTSS3OperationFFDP5_DT.dll"
            )
            module = module.decode("ascii").encode("utf-16le")
            library = bytearray(88)
            library[: len(module)] = module
            struct.pack_into("<H", library, 80, 42)
            library[86] = 0xD0 if lcs else 0xEA
            sections[19] = (1, bytes(library))
            management = bytearray(encode_database(1, sections))
            struct.pack_into("<I", management, 28, selected.catalog.management.version)
            selected.catalog.management = parse_database(bytes(management))
            backend = FaultFixture(
                [
                    J2534Result(
                        count=1,
                        messages=(NativeMessage(6, 0, 0, 0, 0, bytes.fromhex(v)),),
                    )
                    for v in (
                        "000007e86100",
                        *(
                            ("000007e8621f01", "000007e8621f02", "000007e8621f03")
                            if lcs
                            else ()
                        ),
                        "000007e8eb113001",
                        "000007e8eb1230010001",
                        "000007e8eb1330010001010501021234"
                        + ("01050102abcd" if facade else ""),
                    )
                ]
            )
            if fault:
                backend.primary = Cancelled(
                    "authored cancellation during operation receive"
                )
                backend.cleanup = RuntimeError("authored disconnect host failure")
            if build == 12:
                backend.replies.insert(1, J2534Result(code=9))
            channel = NativeCommunication.from_backend(
                selected,
                backend,
                "authored-saved",
                first_request=b"\x22\x1f\x01" if lcs else b"\xab\x11",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=build,
                clock=lambda: 0.0,
            )
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if blocked:
                    root = root / "blocked"
                    root.write_bytes(b"authored-file")
                assert isinstance(channel.operations, NativeFrameController)
                logger = DdrPacketLog(root, channel.operations)
                capture = (
                    capture_lcs_saved_operations
                    if lcs
                    else capture_tss3_saved_operations
                )
                if fault:
                    with self.assertRaises(Cancelled) as raised:
                        capture(channel, logger, SavedFfdSource(build, sha))
                    self.assertIs(raised.exception, backend.primary)
                    self.assertIn(
                        "Saved-operation cleanup raised RuntimeError",
                        raised.exception.__notes__,
                    )
                    self.assertFalse(logger.active)
                    self.assertIsNone(logger._file)
                    self.assertTrue(channel.closed)
                    self.assertEqual(backend.calls[-1][0], "disconnect")
                    continue
                if facade:
                    api = CommandAPI(CommandSource(build, SOURCE_SHA256[build]))
                    prior = SavedOperationFacadeResult(
                        0,
                        (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),),
                    )
                    route = (
                        api.get_lcs_operation_ffd if lcs else api.get_tss3_operation_ffd
                    )
                    output = route(channel, logger, previous=prior)
                    self.assertEqual(output.return_code, 0x90020706 if blocked else 0)
                    saved = json.loads(
                        json.dumps(
                            api.saved_operation_report(
                                SavedFfdSource(build, sha), output
                            )
                        )
                    )
                    self.assertEqual(
                        saved["operation"],
                        "GetLCSOperationFFDApi" if lcs else "GetTSS3OperationFFDApi",
                    )
                    self.assertEqual(saved["producer_sha256"], sha)
                    self.assertEqual(
                        saved["result"]["freezes"][0]["values"][0]["scalar"], 99
                    )
                    self.assertEqual(output.freezes[:1], prior.freezes)
                    for freeze in output.freezes[1:]:
                        self.assertEqual(freeze.metadata.words, (0, 1, 0, 0, 0))
                        self.assertEqual(freeze.metadata.dwords, (0,) * 8)
                        self.assertEqual(freeze.metadata.bytes, (0, 0, 0))
                        self.assertEqual(freeze.metadata.strings, ("", "", ""))
                        self.assertEqual(freeze.metadata.display_entries, ())
                    self.assertEqual(len(output.freezes), 1 if blocked else 2)
                    if not blocked:
                        self.assertEqual(
                            output.freezes[1].values,
                            (SavedOperationFacadeValue(0x1234),),
                        )
                else:
                    result = capture(channel, logger, SavedFfdSource(build, sha))
                    self.assertEqual(result.native_status, 0x90020706 if blocked else 0)
                    self.assertIsNotNone(result.report)
                    assert result.report is not None
                    self.assertEqual(result.report.freezes[0].native_values, (0x1234,))
                    self.assertEqual(result.disconnect_status, 0)
                self.assertTrue(channel.closed)
                self.assertFalse(channel.no_init)
                self.assertFalse(logger.active)
                if not blocked:
                    content = logger.path.read_bytes()
                    self.assertIn(b"AB1330010001", content)
                    self.assertFalse(content.endswith(b"\\n"))
                writes = [
                    fields["messages"][0].data[4:]
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(
                    writes,
                    [
                        bytes.fromhex(v)
                        for v in (
                            "2100",
                            *(("221f01", "221f02", "221f03") if lcs else ()),
                            "ab11",
                            "ab123001",
                            "ab1330010001",
                        )
                    ],
                )
                self.assertEqual(backend.calls[-1][0], "disconnect")

    def test_lcs_both_sources_real_selected_inputs_preflight_and_no_exclusion(self):
        for build, sha in LCS_SOURCE_SHA256.items():
            with self.subTest(build=build):
                requests = []
                answers = iter(
                    bytes.fromhex(v)
                    for v in (
                        "621fff",
                        "621fff",
                        "621fff",
                        "eb112270",
                        "eb122270000200010002",
                        "eb1322700001010501021234",
                        "eb132270000201050102abcd",
                    )
                )

                def exchange(query, requests=requests, answers=answers):
                    requests.append(query)
                    return next(answers)

                cache = MonitorSupportCache(
                    self.profile,
                    exchange,
                    "authored-lcs",
                    source_build=build,
                )
                # CommCacheSndRcvExt uses fresh TEMP, never connection Ever.
                cache._responses[(*cache.identity, b"\x22\x1f\x01")] = b"\x62\x1f\x00"
                producer = SavedFfdProvider(cache, SavedFfdSource(build, sha))
                result = producer.capture_lcs_operation_records()
                self.assertEqual(
                    [q.request for q in requests],
                    [
                        bytes.fromhex(v)
                        for v in (
                            "221f01",
                            "221f02",
                            "221f03",
                            "ab11",
                            "ab122270",
                            "ab1322700001",
                            "ab1322700002",
                        )
                    ],
                )
                self.assertEqual(
                    [r.native_values for r in result.freezes],
                    [
                        (0x1234,),
                        (0xABCD,),
                    ],
                )
                self.assertTrue(all(q.extended for q in requests))
                self.assertEqual(result.groups, (0x2270,))
                self.assertEqual(result.freezes[0].acquisition.source_sha256, sha)
                self.assertEqual(cache._temporary_responses, {})
                with self.assertRaises(ValueError):
                    producer.capture_tss3_operation_records()
        with self.assertRaises(ValueError):
            SavedFfdProvider(
                MonitorSupportCache(self.profile, lambda q: b"", "tss"), self.source
            ).capture_lcs_operation_records()

    def test_lcs_preflight_fault_and_cancel_are_fatal_and_restore_scope(self):
        for cancel in (False, True):
            calls, cancelled = [], [False]

            def exchange(query, calls=calls, cancel=cancel, cancelled=cancelled):
                calls.append(query.request)
                if len(calls) == 2:
                    if cancel:
                        cancelled[0] = True
                    else:
                        raise ToyotaCodecError("authored preflight failure", 0x90020323)
                return b"\x62\x1f\xff"

            cache = MonitorSupportCache(
                self.profile,
                exchange,
                "lcs-fault",
                cancelled=lambda cancelled=cancelled: cancelled[0],
            )
            previous = cache._temporary_responses
            producer = SavedFfdProvider(
                cache, SavedFfdSource(18, LCS_SOURCE_SHA256[18])
            )
            with self.assertRaises(Cancelled if cancel else ToyotaCodecError):
                producer.capture_lcs_operation_records()
            self.assertEqual(calls, [b"\x22\x1f\x01", b"\x22\x1f\x02"])
            self.assertIs(cache._temporary_responses, previous)

    def test_ads_operation_ext_lengths_duplicate_zero_scan_and_truncated_tail(self):
        payload = bytes(300)
        raw = (
            bytes.fromhex("eb2328150000000100")
            + bytes.fromhex("60000000012c")
            + payload
            + bytes.fromhex("0501021234050102ffff")
        )
        groups = ads_operation_groups(raw)
        self.assertEqual(groups[0].values, (0x1234,))
        self.assertEqual(groups[0].records, ((0x6000, payload), (0x501, b"\x12\x34")))
        truncated = bytes.fromhex("eb2328150000000102050102123460000000012cff")
        self.assertEqual(ads_operation_groups(truncated)[0].values, (0x1234,))
        self.assertEqual(ads_operation_groups(bytes.fromhex("eb23281500000001")), ())
        # A fully empty parsed group stops the native outer loop.
        self.assertEqual(
            ads_operation_groups(
                bytes.fromhex("eb232815000000010100000100010501021234")
            ),
            (),
        )
        with self.assertRaises(ValueError):
            ads_operation_groups(bytes(65536))

    def test_ads_operation_phase_selected_input_dword_order_filter_and_errors(self):
        for phase, base in ((3, 0x21), (4, 0x31)):
            with self.subTest(phase=phase):
                requests = []

                def exchange(query, requests=requests, base=base):
                    requests.append(query)
                    if query.request == bytes((0xAB, base)):
                        # The adjacent vtable word1000 is literally in native42-word scan.
                        return bytes((0xEB, base)) + bytes.fromhex("227028151000")
                    if query.request == bytes((0xAB, base + 1)) + bytes.fromhex("2815"):
                        return bytes((0xEB, base + 1)) + bytes.fromhex(
                            "2815 0000f000 00000100 00000001 00000100"
                        )
                    if query.request == bytes((0xAB, base + 1)) + bytes.fromhex("1000"):
                        raise ToyotaCodecError("authored suppressed index", 0x90020323)
                    return bytes((0xEB, base + 2)) + bytes.fromhex(
                        "281500000001010501021234"
                    )

                cache = MonitorSupportCache(
                    self.profile, exchange, "ads-operation-phase"
                )
                result = capture_ads_operation_phase(
                    cache, SavedFfdSource(18, ADS_OPERATION_SOURCE_SHA256), phase
                )
                self.assertEqual([r.operation for r in result.freezes], [1, 0x100])
                self.assertEqual(
                    [r.native_values for r in result.freezes], [(0x1234,), (0x1234,)]
                )
                self.assertEqual(
                    [q.request for q in requests],
                    [
                        bytes((0xAB, base)),
                        bytes((0xAB, base + 1)) + bytes.fromhex("2815"),
                        *(
                            bytes((0xAB, base + 2))
                            + bytes.fromhex("2815")
                            + n.to_bytes(4, "big")
                            for n in (1, 0x100, 0xF000)
                        ),
                        bytes((0xAB, base + 1)) + bytes.fromhex("1000"),
                    ],
                )
                self.assertTrue(all(q.capacity == 65535 for q in requests))
                self.assertEqual(result.suppressed_errors[-1][1], 0x90020323)
        calls = []

        def absent_groups(query):
            calls.append(query.request)
            return bytes.fromhex("eb212270")

        cache = MonitorSupportCache(self.profile, absent_groups, "ads-no-groups")
        with self.assertRaises(ToyotaCodecError) as raised:
            capture_ads_operation_phase(
                cache, SavedFfdSource(18, ADS_OPERATION_SOURCE_SHA256), 3
            )
        self.assertEqual(raised.exception.code, 0x90040501)
        self.assertEqual(calls, [bytes.fromhex("ab21")])

    def test_ads_actual_security_ready_two_phases_and_saved_logs(self):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture, serialized_profile
        from test_profiles import encode_database

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            SavedOperationFacadeFreeze,
            SavedOperationFacadeResult,
            SavedOperationFacadeValue,
        )
        from scripts.database_resources import DdrPacketLog
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )
        from scripts.toyota import VariableTable

        cases = (
            (True, True, True, False, False),
            (False, True, True, False, False),
            (True, False, True, False, False),
            (False, False, True, False, False),
            (True, True, False, False, False),
            (True, True, True, True, False),
            (True, True, True, False, True),
        )
        authored_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        for first, second, ready, change_failure, nonzero_seed, facade in (
            (*case, facade) for facade in (False, True) for case in cases
        ):
            selected = serialized_profile(flags=4, request=b"\x21\x00", check=b"\x61")
            sections = {
                slot: (section.count, section.payload)
                for slot, section in selected.catalog.management.sections.items()
            }
            count, raw = sections[0]
            variables = VariableTable(raw, count)
            values = [variables.get(n) for n in range(1, count + 1)] + [
                b"\x27\x01",
                b"\xff",
                b"\x67",
                b"\x22\x00\x00",
                b"\xff",
                b"\x62",
                b"\x27\x02",
                b"\xff",
                b"\x67",
            ]
            directory, storage = bytearray(), bytearray()
            for value in values:
                directory += struct.pack("<IH", len(storage), len(value))
                storage += value
            sections[0] = (len(values), bytes(directory + storage))
            row_count, rows = sections[17]
            sections[17] = (
                row_count + 3,
                rows
                + struct.pack("<4H", 0x400, count + 1, count + 2, count + 3)
                + struct.pack("<4H", 0x401, count + 4, count + 5, count + 6)
                + struct.pack("<4H", 0x402, count + 7, count + 8, count + 9),
            )
            row_count, rows = sections[18]
            sections[18] = (
                row_count + 4,
                rows
                + b"".join(
                    struct.pack("<8H", 42, function, 1, comm, 0, 0, 0, 0)
                    for function, comm in (
                        (0x66, 0),
                        (0xCA, 0x401),
                        (0x109, 0x400),
                        (0x10A, 0x402),
                    )
                ),
            )
            row_count, rows = sections[18]
            sections[18] = (
                row_count,
                b"".join(
                    sorted(
                        (rows[i : i + 16] for i in range(0, len(rows), 16)),
                        key=lambda row: struct.unpack_from("<HH", row, 0),
                    )
                ),
            )
            row_count, rows = sections[29]
            settings = bytearray(rows[:16])
            struct.pack_into("<H", settings, 10, 11)
            sections[29] = (row_count + 1, rows + settings)
            library = bytearray(88)
            module = "GetADSOperationFFDP5_DT.dll".encode("utf-16le")
            library[: len(module)] = module
            struct.pack_into("<H", library, 80, 42)
            library[86] = 0xE0
            sections[19] = (1, bytes(library))
            selected.catalog.management = parse_database(encode_database(1, sections))
            answers = [
                "6100",
                "6701"
                + ("00112233445566778899aabbccddeeff" if nonzero_seed else "00" * 16),
                *(("6702",) if nonzero_seed else ()),
                "62010100000008",
                "621c0001",
                "621c08" + ("00" if ready else "01"),
            ]
            if ready:
                for available, base in ((first, 0x21), (second, 0x31)):
                    answers.append(f"eb{base:02x}" + ("2815" if available else ""))
                    if available:
                        answers.extend(
                            (
                                f"eb{base + 1:02x}281500000001",
                                f"eb{base + 2:02x}281500000001010501021234"
                                + ("01050102abcd" if facade else ""),
                            )
                        )
            backend = J2534Fixture(
                [
                    J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 0, 0, bytes.fromhex("000007e8" + answer)
                            ),
                        ),
                    )
                    for answer in answers
                ]
            )
            channel = NativeCommunication.from_backend(
                selected,
                backend,
                "ads-full",
                first_request=b"\x27\x01",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=18,
                clock=lambda: 0.0,
            )
            with tempfile.TemporaryDirectory() as temp:
                assert isinstance(channel.operations, NativeFrameController)
                logger = DdrPacketLog(Path(temp), channel.operations)
                if change_failure:
                    (logger.directory / "ADSOperationFFD_Eng.log").mkdir(parents=True)
                expected_status = (
                    0x90040501
                    if not ready or not first and not second
                    else 0x90020706
                    if change_failure
                    else 0
                )
                if facade:
                    api = CommandAPI(CommandSource(18, SOURCE_SHA256[18]))
                    prior = SavedOperationFacadeResult(
                        0,
                        (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),),
                    )
                    output = api.get_ads_operation_ffd(
                        channel, logger, authored_key, previous=prior
                    )
                    self.assertEqual(output.return_code, expected_status)
                    saved = json.loads(
                        json.dumps(
                            api.saved_operation_report(
                                SavedFfdSource(18, ADS_OPERATION_SOURCE_SHA256), output
                            )
                        )
                    )
                    self.assertEqual(saved["operation"], "GetADSOperationFFDApi")
                    self.assertEqual(saved["result"]["return_code"], expected_status)
                    self.assertEqual(
                        saved["result"]["freezes"][0]["values"][0]["scalar"], 99
                    )
                    serialized = json.dumps(saved)
                    for omitted in (
                        "seed_reply",
                        "key_request",
                        "raw_reply",
                        "log_path",
                        "frame_provenance",
                        authored_key.hex(),
                    ):
                        self.assertNotIn(omitted, serialized)
                    self.assertEqual(output.freezes[:1], prior.freezes)
                    for freeze in output.freezes[1:]:
                        self.assertEqual(freeze.metadata.words, (0, 1, 0, 0, 0))
                        self.assertEqual(freeze.metadata.dwords, (0,) * 8)
                        self.assertEqual(freeze.metadata.bytes, (0, 0, 0))
                        self.assertEqual(freeze.metadata.strings, ("", "", ""))
                        self.assertEqual(freeze.metadata.display_entries, ())
                    expected = (
                        int(first) + int(second) if ready and not expected_status else 0
                    )
                    self.assertEqual(len(output.freezes), 1 + expected)
                    self.assertTrue(
                        all(
                            freeze.values == (SavedOperationFacadeValue(0x1234),)
                            for freeze in output.freezes[1:]
                        )
                    )
                else:
                    result = capture_ads_saved_operations(
                        channel,
                        logger,
                        SavedFfdSource(18, ADS_OPERATION_SOURCE_SHA256),
                        authored_key,
                    )
                    self.assertEqual(result.native_status, expected_status)
                    self.assertEqual(
                        len(result.freezes), (int(first) + int(second)) if ready else 0
                    )
                    self.assertIsNotNone(result.security)
                    self.assertEqual(
                        [transaction.did for transaction in result.readiness],
                        [0x101, 0x1C00, 0x1C08],
                    )
                    self.assertEqual(result.disconnect_status, 0)
                self.assertTrue(channel.closed)
                self.assertFalse(logger.active)
                self.assertFalse(channel.no_init)
                self.assertIsNone(logger._file)
                self.assertTrue((logger.directory / "ADSOperationFFD.log").is_file())
                if ready and not change_failure:
                    self.assertTrue(
                        (logger.directory / "ADSOperationFFD_Eng.log").is_file()
                    )
                self.assertEqual(backend.replies, [])
                writes = [
                    fields["messages"][0].data[4:]
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(
                    writes[:2], [bytes.fromhex("2100"), bytes.fromhex("2701")]
                )
                if nonzero_seed:
                    # Public AES128 known-answer vector; no OEM key material.
                    self.assertEqual(
                        writes[2], bytes.fromhex("270269c4e0d86a7b0430d8cdb78070b4c55a")
                    )
                else:
                    self.assertFalse(
                        any(
                            request.startswith(bytes.fromhex("2702"))
                            for request in writes
                        )
                    )

    def test_ascii_module_identity_is_rejected_before_any_io(self):
        from test_frame_transport import DRIVER
        from test_native_communication import J2534Fixture, serialized_profile
        from test_profiles import encode_database

        from scripts.command_api import SOURCE_SHA256, CommandAPI, CommandSource
        from scripts.database_resources import DdrPacketLog
        from scripts.diagnostic_db import parse_database
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        for build, command, module, route_name in (
            (12, 0xD0, b"GetLCSOperationFFDP5_DT.dll", "get_lcs_operation_ffd"),
            (18, 0xD0, b"GetLCSOperationFFDP5_DT.dll", "get_lcs_operation_ffd"),
            (18, 0xEA, b"GetTSS3OperationFFDP5_DT.dll", "get_tss3_operation_ffd"),
            (18, 0xE0, b"GetADSOperationFFDP5_DT.dll", "get_ads_operation_ffd"),
        ):
            selected = serialized_profile(version=build)
            sections = {
                slot: (section.count, section.payload)
                for slot, section in selected.catalog.management.sections.items()
            }
            library = bytearray(88)
            library[: len(module)] = (
                module  # Deliberately wrong ANSI instead of WCHAR40.
            )
            struct.pack_into("<H", library, 80, 42)
            library[86] = command
            sections[19] = (1, bytes(library))
            management = bytearray(encode_database(1, sections))
            struct.pack_into("<I", management, 28, selected.catalog.management.version)
            selected.catalog.management = parse_database(bytes(management))
            backend = J2534Fixture([])
            channel = NativeCommunication.from_backend(
                selected,
                backend,
                "wrong-module",
                first_request=b"\xab\x11",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=build,
                clock=lambda: 0.0,
            )
            assert isinstance(channel.operations, NativeFrameController)
            api = CommandAPI(CommandSource(build, SOURCE_SHA256[build]))
            with tempfile.TemporaryDirectory() as temp:
                logger = DdrPacketLog(Path(temp), channel.operations)
                route = getattr(api, route_name)
                with self.assertRaises(NotImplementedError):
                    if command == 0xE0:
                        route(channel, logger, bytes(16))
                    else:
                        route(channel, logger)
                self.assertEqual(backend.calls, [])
                self.assertFalse(logger.active)
                self.assertFalse(logger.directory.exists())

    def test_wrong_source_and_untyped_or_out_of_bounds_input(self):
        for build, sha in (
            (12, TSS3_SOURCE_SHA256),
            (18, "0" * 64),
            (True, TSS3_SOURCE_SHA256),
        ):
            with self.assertRaises(ValueError):
                SavedFfdSource(build, sha)
        for first, second in ((-1, 0), (0, 65536), (True, 0)):
            with self.assertRaises(ValueError):
                Tss3OperationRequest(first, second)
        with self.assertRaises(ValueError):
            tss3_operation_groups(bytes(4097))
        with self.assertRaises(ValueError):
            tss3_operation_groups(cast(bytes, bytearray()))


if __name__ == "__main__":
    unittest.main()
