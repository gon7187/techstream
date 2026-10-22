import json
import struct
import tempfile
import unittest
from pathlib import Path

from scripts.profiles import VehicleCatalog


def encode_database(kind, sections):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes((kind, max(sections) + 1))
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, 0x0100032F)
    body = bytearray()
    for slot, (count, payload) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
    return bytes(header + body)


class ProfileTests(unittest.TestCase):
    def test_protocol_profile_has_real_management_frames_without_ecu_database(self):
        from dataclasses import replace
        from unittest.mock import patch

        from scripts.profiles import ProtocolProfile, VehicleProfile
        from scripts.toyota import ToyotaCodecError

        catalog = VehicleCatalog(self.root)
        vehicle = catalog.build_profile(42)
        with patch.object(
            catalog, "read_system", side_effect=AssertionError("ECU file access")
        ):
            protocol = catalog.build_protocol_profile(42)
        self.assertIsInstance(vehicle, ProtocolProfile)
        self.assertNotIsInstance(protocol, VehicleProfile)
        self.assertFalse(hasattr(protocol, "database"))
        self.assertFalse(hasattr(protocol, "records"))
        self.assertIsNone(protocol.ecu_database_sha256)
        self.assertEqual(vehicle.ecu_database_sha256, vehicle.database.sha256)
        selected = protocol.frame_records(16)[0]
        self.assertEqual(selected.frame.request, b"\x21\0")
        protocol.validate_frame(selected)
        with self.assertRaisesRegex(ValueError, "does not belong"):
            protocol.validate_frame(vehicle.frame_records(16)[0])

        sections = {
            key: (section.count, section.payload)
            for key, section in catalog.management.sections.items()
        }
        first = bytearray(sections[16][1])
        first[:40] = bytes(40)
        later = bytearray(first)
        later[72] = 99
        sections[16] = (2, bytes(first + later))
        (self.root / "Toyota.ddb").write_bytes(encode_database(1, sections))
        empty_name_catalog = VehicleCatalog(self.root)
        with patch.object(
            empty_name_catalog,
            "read_system",
            side_effect=AssertionError("ECU file access"),
        ):
            actual = empty_name_catalog.build_protocol_profile(42)
        self.assertEqual(actual.filename, "")
        self.assertEqual(actual.category_record, bytes(first))
        bad_first = bytearray(first)
        struct.pack_into("<I", bad_first, 60, 0xFFFFFFFF)
        sections[16] = (2, bytes(bad_first + later))
        (self.root / "Toyota.ddb").write_bytes(encode_database(1, sections))
        from scripts.diagnostic_db import read_database

        category_label_catalog = empty_name_catalog
        category_label_catalog.management = read_database(self.root / "Toyota.ddb")
        self.assertEqual(
            category_label_catalog.build_protocol_profile(42).category_record,
            bytes(bad_first),
        )
        sections[16] = (2, bytes(later + bad_first))
        (self.root / "Toyota.ddb").write_bytes(encode_database(1, sections))
        category_label_catalog.management = read_database(self.root / "Toyota.ddb")
        with self.assertRaises(ToyotaCodecError) as label_error:
            category_label_catalog.build_protocol_profile(42)
        self.assertEqual(label_error.exception.code, 0xA0030102)
        self.assertEqual(actual.frame_records(16)[0].frame.request, b"\x21\0")
        with self.assertRaises(ValueError):
            empty_name_catalog.build_profile(42)
        with self.assertRaises(ValueError):
            catalog.build_protocol_profile(65535)
        for invalid in (True, -1, 65536):
            with self.assertRaises(ValueError):
                catalog.build_protocol_profile(invalid)
        missing = replace(catalog.management, sections={})
        with patch.object(catalog, "management", missing):
            with self.assertRaises(ToyotaCodecError) as caught:
                catalog.build_protocol_profile(42)
            self.assertEqual(caught.exception.code, 0xA0030107)

    def test_protocol_profile_native_exception_selection_and_short_count(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        catalog = VehicleCatalog(self.root)
        original = catalog.management.sections[16].payload
        overlay = bytearray(original)
        struct.pack_into("<H", overlay, 70, 9)
        overlay[72:74] = bytes((7, 2))
        for version in (0x0100030C, 0x0100032F):
            catalog.management = replace(
                catalog.management,
                version=version,
                sections={16: Section(16, 0, 2, False, original + bytes(overlay))},
            )
            self.assertEqual(
                catalog.build_protocol_profile(42).category_record, original
            )
            selected = catalog.build_protocol_profile(42, exception_ids=(9,))
            self.assertEqual(selected.category_record, bytes(overlay))
            self.assertEqual(selected.exception_ids, (9,))
            catalog.management = replace(
                catalog.management,
                sections={16: Section(16, 0, 32768, False, original * 32768)},
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                catalog.build_protocol_profile(42)
            self.assertEqual(caught.exception.code, 0xA0030110)

    def test_pid_query_filters_before_native_short_count_both_builds(self):
        from dataclasses import replace
        from unittest.mock import patch

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        groups = [struct.pack("<HBBHBB", 0, pid, 3, 0, 0, 0) for pid in range(256)]
        payload = b"".join(row * 128 for row in groups)
        for version in (0x0100030C, 0x0100032F):
            actual = replace(
                profile,
                database=replace(
                    profile.database,
                    version=version,
                    sections={6: Section(6, 0, 32768, False, payload)},
                ),
            )
            self.assertEqual(actual.pid_records(7), (groups[7],) * 128)
            self.assertEqual(actual.pid_records(255), (groups[255],) * 128)
            self.assertEqual(actual.pid_records(0x107), ())
            self.assertEqual(actual.pid_records(0x1000007), ())
            with patch.object(
                type(actual),
                "_signal_rows",
                return_value=(groups[7], groups[8], groups[7]),
            ):
                self.assertEqual(actual.pid_records(7), (groups[7],))
            too_many = replace(
                actual,
                database=replace(
                    actual.database,
                    sections={6: Section(6, 0, 32768, False, groups[7] * 32768)},
                ),
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                too_many.pid_records(7)
            self.assertEqual(caught.exception.code, 0xA0030110)
            for invalid in (True, -1, 0x100000000):
                with self.assertRaises(ValueError):
                    actual.pid_records(invalid)

    def test_raw_vehicle_matches_do_not_run_registration_or_option_policy(self):
        from unittest.mock import patch

        from scripts.profiles import VehicleContext
        from scripts.support import ExceptionContext

        catalog = VehicleCatalog(self.root)
        context = VehicleContext(ExceptionContext(0, 0), mode=1)
        with patch.object(
            catalog,
            "selectable_vehicles",
            side_effect=AssertionError("unrelated option fallback"),
        ):
            rows = catalog.raw_matching_vehicles(context)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["row"], 0)
            with self.assertRaisesRegex(AssertionError, "unrelated option fallback"):
                catalog.matching_vehicles(context)
        from scripts.toyota import ToyotaCodecError

        original = catalog.management.sections[41].payload
        with (
            patch("scripts.profiles._rows", return_value=(original,) * 32768),
            patch.object(
                catalog, "vehicle_definitions", [catalog.vehicle_definitions[0]] * 32768
            ),
        ):
            with self.assertRaises(ToyotaCodecError) as caught:
                catalog.raw_matching_vehicles(context)
            self.assertEqual(caught.exception.code, 0xA0030110)

    def test_category_master_query_eager_all_names_and_native_fault(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        catalog = VehicleCatalog(self.root)
        rows = catalog.management.sections[47].payload
        for version in (0x0100030C, 0x0100032F):
            catalog.management = replace(
                catalog.management,
                version=version,
                sections={47: Section(47, 0, 4, False, rows)},
            )
            self.assertEqual(
                catalog.category_master_records(),
                tuple(rows[n : n + 8] for n in range(0, len(rows), 8)),
            )
            invalid = bytearray(rows)
            struct.pack_into("<I", invalid, len(rows) - 8, 0xFFFFFFFF)
            catalog.management = replace(
                catalog.management,
                sections={47: Section(47, 0, 4, False, bytes(invalid))},
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                catalog.category_master_records()
            self.assertEqual(caught.exception.code, 0xA0030102)
            catalog.management = replace(catalog.management, sections={})
            with self.assertRaises(ToyotaCodecError) as missing:
                catalog.category_master_records()
            self.assertEqual(missing.exception.code, 0xA0030107)

    def test_dkiso_freeze_pid_selected_original_layout(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        original = bytes((0, 0, 0x12, 0x34, 0x80, 0x56, 0, 0x78))
        selected = bytes((9, 0, 0x21, 0x43, 0x80, 0x65, 2, 0x87))
        for version in (0x0100030C, 0x0100032F):
            actual = replace(
                profile,
                database=replace(
                    profile.database,
                    version=version,
                    sections={20: Section(20, 0, 2, False, original + selected)},
                ),
                exception_ids=(9,),
            )
            self.assertEqual(actual.records(20), (selected,))

    def test_selected_ddr_query_stages_and_v12_trigger_offsets(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        for version, width, offset in ((0x0100030C, 32, 26), (0x0100032F, 36, 30)):
            rows = []
            for first, second in ((1, 2), (1, 3), (2, 2)):
                row = bytearray(width)
                row[offset : offset + 2] = bytes((first, second))
                rows.append(bytes(row))
            object.__setattr__(
                profile,
                "database",
                replace(
                    profile.database,
                    version=version,
                    sections={51: Section(51, 0, 3, False, b"".join(rows))},
                ),
            )
            self.assertEqual(profile.ddr_records(51, 1, 2), (rows[0],))
            self.assertEqual(profile.ddr_records(51, 1, 258), ())
            with self.assertRaises(ValueError):
                profile.ddr_records(51, 1)
            with self.assertRaises(ValueError):
                profile.ddr_records(0, 1)

    def test_plain_can_info_first_contiguous_group_both_versions(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        management = profile.catalog.management
        rows = []
        for key, value in ((9, 1), (7, 2), (7, 3), (8, 4), (7, 5)):
            row = bytearray(28)
            struct.pack_into("<I", row, 0, value)
            struct.pack_into("<H", row, 8, key)
            rows.append(bytes(row))
        for version in (0x0100030C, 0x0100032F):
            profile.catalog.management = replace(
                management,
                version=version,
                sections={
                    **management.sections,
                    14: Section(14, 0, 5, False, b"".join(rows)),
                },
            )
            self.assertEqual(profile.comm_info_can_records(7), tuple(rows[1:3]))
            self.assertEqual(profile.comm_info_can_records(6), ())
            with self.assertRaises(ValueError):
                profile.comm_info_can_records(True)
        profile.catalog.management = replace(management, sections={})
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.comm_info_can_records(7)
        self.assertEqual(caught.exception.code, 0xA0030107)

    def test_plain_iso_info_uses_word4_and_native_56byte_stride(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        management = profile.catalog.management
        rows = []
        for key in (7, 7, 8, 7):
            row = bytearray(56)
            struct.pack_into("<H", row, 4, key)
            rows.append(bytes(row))
        for version in (0x0100030C, 0x0100032F):
            profile.catalog.management = replace(
                management,
                version=version,
                sections={15: Section(15, 0, 4, False, b"".join(rows))},
            )
            self.assertEqual(profile.comm_info_iso_records(7), tuple(rows[:2]))
            self.assertEqual(profile.comm_info_iso_records(6), ())

    def test_communication_frame_first_row_but_exact_one_settings(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        management = profile.catalog.management
        sections = dict(management.sections)
        original = profile.command_frames(16)
        frame = sections[17]
        sections[17] = replace(
            frame,
            count=frame.count + 1,
            payload=frame.payload + struct.pack("<4H", 2, 0, 0, 0),
        )
        profile.catalog.management = replace(management, sections=sections)
        self.assertEqual(profile.command_frames(16), original)
        settings = sections[29]
        sections[29] = Section(
            29, 0, settings.count + 1, False, settings.payload + settings.payload[:16]
        )
        profile.catalog.management = replace(management, sections=sections)
        with self.assertRaisesRegex(ValueError, "Expected one communication settings"):
            profile.frame_records(16)

    def test_custom_management_query_uses_native_kind_and_item_keys(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        sign = bytearray(12)
        sign[8] = 7
        struct.pack_into("<H", sign, 4, 99)
        item = bytearray(52)
        struct.pack_into("<H", item, 8, 99)
        profile.catalog.management = replace(
            profile.catalog.management,
            sections={
                20: Section(20, 0, 1, False, bytes(sign)),
                21: Section(21, 0, 1, False, bytes(item)),
            },
        )
        self.assertEqual(profile.custom_sign_records(7), (bytes(sign),))
        self.assertEqual(profile.custom_sign_records(263), ())
        self.assertEqual(profile.custom_item_records(99), (bytes(item),))
        self.assertEqual(profile.custom_item_records(7), ())

    def test_operation_freeze_query_is_byte7_first_group_not_overlay_word2(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        rows = []
        for key, selector in ((1, 7), (2, 7), (3, 8), (4, 7)):
            row = bytearray(8)
            struct.pack_into("<H", row, 2, key)
            row[7] = selector
            rows.append(bytes(row))
        object.__setattr__(
            profile,
            "database",
            replace(
                profile.database,
                sections={54: Section(54, 0, 4, False, b"".join(rows))},
            ),
        )
        self.assertEqual(profile.operation_freeze_records(7), tuple(rows[:2]))
        self.assertEqual(profile.operation_freeze_records(1), ())
        self.assertEqual(profile.operation_freeze_records(263), ())

    def test_monitor_did_bit_query_and_resolved_management_variable(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        for version, width in ((0x0100030C, 12), (0x0100032F, 16)):
            row = bytearray(width)
            struct.pack_into("<HH", row, 0, 7, 1)
            object.__setattr__(
                profile,
                "database",
                replace(
                    profile.database,
                    version=version,
                    sections={63: Section(63, 0, 1, False, bytes(row))},
                ),
            )
            self.assertEqual(profile.data_id_bit_records(7), (bytes(row),))
            self.assertEqual(profile.data_id_bit_records(1), ())
            self.assertEqual(profile.data_id_bit_variable(bytes(row)), b"\x21\0")
            with self.assertRaises(ValueError):
                profile.data_id_bit_variable(bytes(width))

    def test_direct_frame_and_support_reference_without_function_association(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        sections = {
            k: v for k, v in profile.catalog.management.sections.items() if k != 18
        }
        support = bytearray(24)
        struct.pack_into("<H", support, 0, 99)
        struct.pack_into("<H", support, 10, 42)
        sections[48] = Section(48, 0, 1, False, bytes(support))
        management = profile.catalog.management
        for version in (0x0100030C, 0x0100032F):
            profile.catalog.management = replace(
                management, version=version, sections=sections
            )
            direct = profile.direct_frame(2, 1)
            self.assertEqual(direct.frame.request, b"\x21\0")
            self.assertEqual(direct.function_record, b"")
            self.assertIn("native-direct", direct.provenance)
            self.assertEqual(direct.communication_record, sections[17].payload)
            self.assertEqual(direct.settings_record, sections[29].payload)
            self.assertEqual(
                profile.communication_support_records(99), (bytes(support),)
            )
            self.assertEqual(profile.communication_support_records(42), ())
            with self.assertRaises(ValueError):
                profile.direct_frame(True, 1)
            with self.assertRaisesRegex(ValueError, "No selected communication frame"):
                profile.direct_frame(999, 1)

    def test_direct_frame_native_lookup_order_and_all_row_variable_validation(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        management = profile.catalog.management
        for sections, code in (
            ({}, 0xA0030107),
            ({17: Section(17, 0, 0, False, b"")}, 0xC0040101),
        ):
            profile.catalog.management = replace(management, sections=sections)
            with self.assertRaises(ToyotaCodecError) as caught:
                profile.direct_frame(2, 1)
            self.assertEqual(caught.exception.code, code)
        sections = dict(management.sections)
        sections.pop(29)
        profile.catalog.management = replace(management, sections=sections)
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.direct_frame(2, 1)
        self.assertEqual(caught.exception.code, 0xA0030107)
        # GetDbRecord eagerly resolves the later row's mask before missing settings.
        sections[17] = Section(
            17, 0, 2, False, sections[17].payload + struct.pack("<4H", 2, 1, 999, 0)
        )
        profile.catalog.management = replace(management, sections=sections)
        with self.assertRaisesRegex(ToyotaCodecError, "Variable reference"):
            profile.direct_frame(2, 1)
        # Function GetCommFrmInfo deliberately has the opposite settings-first order.
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.frame_records(16)
        self.assertEqual(caught.exception.code, 0xA0030107)

    def test_direct_no_buffer_allows_empty_send_but_function_setter_rejects_it(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        sections = dict(profile.catalog.management.sections)
        sections[17] = Section(17, 0, 1, False, struct.pack("<4H", 2, 0, 0, 0))
        profile.catalog.management = replace(
            profile.catalog.management, sections=sections
        )
        self.assertEqual(profile.direct_frame(2, 1).frame.request, b"")
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.frame_records(16)
        self.assertEqual(caught.exception.code, 0xC0040102)

    def test_direct_frame_group_native_signed_count_bound(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        row = struct.pack("<4H", 2, 1, 0, 0)
        profile.catalog.management = replace(
            profile.catalog.management,
            sections={17: Section(17, 0, 32768, False, row * 32768)},
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.direct_frame(2, 1)
        self.assertEqual(caught.exception.code, 0xA0030110)

    def test_dll_query_command_byte_precedes_selected_category_word(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        rows = []
        for command, category in ((0x13, 42), (0x13, 99), (0x14, 42)):
            row = bytearray(88)
            row[86] = command
            struct.pack_into("<H", row, 80, category)
            rows.append(bytes(row))
        profile.catalog.management = replace(
            profile.catalog.management,
            sections={19: Section(19, 0, 3, False, b"".join(rows))},
        )
        self.assertEqual(profile.dll_records(0x13), (rows[0],))
        self.assertEqual(profile.dll_records(0x113), ())
        self.assertEqual(profile.dll_records(42), ())
        other = replace(
            profile,
            category_record=bytes(bytearray(68) + struct.pack("<H", 77) + bytes(6)),
        )
        self.assertEqual(other.dll_records(0x13), (rows[0],))

    def test_behavior_first_settings_and_setcommset_only_have_distinct_counts(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        sections = dict(profile.catalog.management.sections)
        first = sections[29].payload
        second = bytearray(first)
        struct.pack_into("<I", second, 0, 123)
        sections[29] = Section(29, 0, 2, False, first + second)
        profile.catalog.management = replace(
            profile.catalog.management, sections=sections
        )
        self.assertEqual(profile.behavior_frame(2, 1).settings_record, first)
        self.assertEqual(profile.communication_settings_first(1), first)
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.communication_settings(1)
        self.assertEqual(caught.exception.code, 0xC0040102)
        sections[29] = Section(29, 0, 0, False, b"")
        sections.pop(17)
        profile.catalog.management = replace(
            profile.catalog.management, sections=sections
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.behavior_frame(2, 1)
        self.assertEqual(caught.exception.code, 0xC0040101)
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.communication_settings_first(1)
        self.assertEqual(caught.exception.code, 0xC0040101)

    def test_detail_selected_group_and_plain_highlighting_group(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        detail = bytearray(20)
        struct.pack_into("<H", detail, 8, 7)
        highlight = [
            struct.pack("<4H", key, index, 0, 0)
            for index, key in enumerate((7, 7, 8, 7))
        ]
        for version in (0x0100030C, 0x0100032F):
            object.__setattr__(
                profile,
                "database",
                replace(
                    profile.database,
                    version=version,
                    sections={
                        47: Section(47, 0, 1, False, bytes(detail)),
                        48: Section(48, 0, 4, False, b"".join(highlight)),
                    },
                ),
            )
            self.assertEqual(profile.detail_code_records(7), (bytes(detail),))
            self.assertEqual(profile.detail_code_records(0), ())
            self.assertEqual(profile.highlighting_records(7), tuple(highlight[:2]))
            self.assertEqual(profile.highlighting_records(0), ())

    def test_target_category_query_and_eager_bit_group_variables(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        target = bytearray(76)
        struct.pack_into("<H", target, 68, 43)
        target[72] = 20
        sections = dict(profile.catalog.management.sections)
        sections[16] = Section(16, 0, 2, False, profile.category_record + target)
        profile.catalog.management = replace(
            profile.catalog.management, sections=sections
        )
        self.assertEqual(profile.category_records(43), (bytes(target),))
        self.assertEqual(profile.category_records(44), ())
        first, second = bytearray(16), bytearray(16)
        struct.pack_into("<HH", first, 0, 7, 1)
        struct.pack_into("<HH", second, 0, 7, 999)
        object.__setattr__(
            profile,
            "database",
            replace(
                profile.database,
                sections={63: Section(63, 0, 2, False, bytes(first + second))},
            ),
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.data_id_bit_records(7)
        self.assertEqual(caught.exception.code, 0xA0030102)

    def test_frame_origin_validation_and_function_only_without_settings(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        for selected in (
            *profile.frame_records(16),
            profile.direct_frame(2, 1),
            profile.behavior_frame(2, 1),
            profile.function_frame(16),
        ):
            self.assertIsNone(profile.validate_frame(selected))
        own = profile.frame_records(16)[0]
        foreign_catalog = VehicleCatalog(self.root)
        foreign = foreign_catalog.build_profile(42)
        sections = dict(foreign_catalog.management.sections)
        timer = bytearray(sections[29].payload)
        struct.pack_into("<I", timer, 0, 31337)
        sections[29] = Section(29, 0, 1, False, bytes(timer))
        foreign_catalog.management = replace(
            foreign_catalog.management, sha256="b" * 64, sections=sections
        )
        changed = foreign.frame_records(16)[0]
        with self.assertRaisesRegex(ValueError, "does not belong"):
            profile.validate_frame(changed)
        with self.assertRaisesRegex(ValueError, "does not belong"):
            profile.validate_frame(replace(changed, provenance=own.provenance))
        with self.assertRaisesRegex(ValueError, "does not belong"):
            profile.validate_frame(
                replace(own, frame=replace(own.frame, request=b"wrong"))
            )
        for selected in (profile.direct_frame(2, 1), profile.behavior_frame(2, 1)):
            other = replace(
                profile, database=replace(profile.database, sha256="c" * 64)
            )
            with self.assertRaisesRegex(ValueError, "does not belong"):
                other.validate_frame(selected)
        sections = dict(profile.catalog.management.sections)
        sections.pop(29)
        profile.catalog.management = replace(
            profile.catalog.management, sections=sections
        )
        single = profile.function_frame(16)
        self.assertEqual(single.settings_record, b"")
        self.assertEqual(single.frame.request, b"\x21\0")
        self.assertIsNone(profile.validate_frame(single))
        with self.assertRaises(ToyotaCodecError) as caught:
            profile.function_frame(999)
        self.assertEqual(caught.exception.code, 0x90020104)

    def test_ecu_function_info_query_field_differs_from_overlay_order(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        self.assertFalse(profile.mode_wwh())
        row = bytearray(24)
        struct.pack_into("<HH", row, 8, 42, 0x27)
        struct.pack_into("<H", row, 20, 999)
        profile.catalog.management = replace(
            profile.catalog.management,
            sections={26: Section(26, 0, 1, False, bytes(row))},
        )
        self.assertEqual(profile.ecu_function_info(0x27), (bytes(row),))
        self.assertEqual(profile.ecu_function_info(999), ())
        self.assertTrue(profile.mode_wwh())

    def test_ffd_bit_uses_own_selected_table_and_management_variables(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        row = bytearray(12)
        struct.pack_into("<HH", row, 0, 7, 1)
        for version in (0x0100030C, 0x0100032F):
            object.__setattr__(
                profile,
                "database",
                replace(
                    profile.database,
                    version=version,
                    sections={80: Section(80, 0, 1, False, bytes(row))},
                ),
            )
            self.assertEqual(profile.ffd_bit_records(7), (bytes(row),))
            self.assertEqual(profile.ffd_bit_records(1), ())
            self.assertEqual(profile.ffd_bit_variable(bytes(row)), b"\x21\0")

    def test_bit_queries_stop_after_first_contiguous_key_group(self):
        from dataclasses import replace
        from unittest.mock import patch

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        for version in (0x0100030C, 0x0100032F):
            for slot in (8, 63, 80, 89):
                width = 16 if slot == 63 and version == 0x0100032F else 12
                rows = [bytearray(width) for _ in range(3)]
                for row, key, variable in zip(
                    rows, (7, 8, 7), (1, 1, 999), strict=True
                ):
                    struct.pack_into("<HH", row, 0, key, variable)
                staged = tuple(bytes(row) for row in rows)
                object.__setattr__(
                    profile,
                    "database",
                    replace(
                        profile.database,
                        version=version,
                        sections={slot: Section(slot, 0, 3, False, b"".join(staged))},
                    ),
                )
                with self.assertRaisesRegex(ValueError, "index is not sorted"):
                    profile._bit_records(slot, 7)
                # Exercise the native query itself independently of index validation.
                with patch.object(type(profile), "_signal_rows", return_value=staged):
                    self.assertEqual(profile._bit_records(slot, 7), (staged[0],))
                    self.assertEqual(profile._bit_variable(slot, staged[0]), b"\x21\0")
                    with self.assertRaisesRegex(ValueError, "not in the selected"):
                        profile._bit_variable(slot, staged[2])

    def test_work_factor_selected_queries_and_old_factory_boundary(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        for slot, width, fields in (
            (37, 20, (8, 10)),
            (114, 24, (16,)),
            (115, 20, (4, 18)),
            (116, 16, (8, 10)),
            (117, 16, (14,)),
        ):
            rows = []
            for first, second in ((7, 1), (7, 2), (8, 1)):
                row = bytearray(width)
                if slot == 117:
                    row[14] = first
                else:
                    struct.pack_into("<H", row, fields[0], first)
                    if len(fields) == 2:
                        struct.pack_into("<H", row, fields[1], second)
                rows.append(bytes(row))
            for version in (0x0100030C, 0x0100032F):
                object.__setattr__(
                    profile,
                    "database",
                    replace(
                        profile.database,
                        version=version,
                        sections={slot: Section(slot, 0, 3, False, b"".join(rows))},
                    ),
                )
                if version == 0x0100030C and slot != 37:
                    with self.assertRaisesRegex(ValueError, "version 12 factory"):
                        profile.records(slot)
                    continue
                self.assertEqual(profile.work_factor_records(slot, 7), tuple(rows[:2]))
                if slot == 37:
                    self.assertEqual(profile.work_factor_records(37, 7, 0x10001), ())
                    self.assertEqual(profile.work_factor_records(37, 7, 0xFFFFFFFF), ())
                    for invalid in (-1, 0x100000000, True):
                        with self.assertRaises(ValueError):
                            profile.work_factor_records(37, 7, invalid)
                if len(fields) == 2:
                    self.assertEqual(
                        profile.work_factor_records(slot, 7, 2), (rows[1],)
                    )
                    if slot == 115:
                        self.assertEqual(
                            profile.work_factor_records(slot, 7, 0x102), ()
                        )
                else:
                    with self.assertRaises(ValueError):
                        profile.work_factor_records(slot, 7, 2)
                self.assertEqual(profile.work_factor_records(slot, 0x107), ())

    def test_vehicle_context_label_queries_keep_native_counts_and_string_validation(
        self,
    ):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        catalog = VehicleCatalog(self.root)
        collect = [
            struct.pack("<I4H", 0, level, value, 0, 0)
            for level, value in ((1, 7), (1, 7), (1, 8), (2, 7))
        ]
        brand = [struct.pack("<I2H", 0, key, 0) for key in (7, 7, 8, 7)]
        for version in (0x0100030C, 0x0100032F):
            catalog.management = replace(
                catalog.management,
                version=version,
                sections={
                    46: Section(46, 0, 4, False, b"".join(collect)),
                    67: Section(67, 0, 4, False, b"".join(brand)),
                },
            )
            self.assertEqual(catalog.collect_item_records(1, 7), tuple(collect[:2]))
            self.assertEqual(catalog.collect_item_records(2, 7), (collect[3],))
            self.assertEqual(catalog.vehicle_brand_records(7), tuple(brand[:2]))
            self.assertEqual(catalog.vehicle_brand_records(9), ())
        invalid = struct.pack("<I2H", 0xFFFFFFFF, 7, 0)
        catalog.management = replace(
            catalog.management,
            sections={67: Section(67, 0, 2, False, brand[0] + invalid)},
        )
        with self.assertRaisesRegex(ValueError, "outside language table"):
            catalog.vehicle_brand_records(7)

    def test_work_factor_eager_all_selected_native_string_references(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        for slot, width, key_offset, text_offsets in (
            (37, 20, 8, (0, 4)),
            (114, 24, 16, (12,)),
            (115, 20, 4, (0,)),
            (116, 16, 8, (0, 4)),
            (117, 16, 14, (0,)),
        ):
            for text_offset in text_offsets:
                first, invalid = bytearray(width), bytearray(width)
                for row in (first, invalid):
                    if slot == 117:
                        row[key_offset] = 7
                    else:
                        struct.pack_into("<H", row, key_offset, 7)
                struct.pack_into("<I", invalid, text_offset, 0xFFFFFFFF)
                for version in (
                    (0x0100030C, 0x0100032F) if slot == 37 else (0x0100032F,)
                ):
                    object.__setattr__(
                        profile,
                        "database",
                        replace(
                            profile.database,
                            version=version,
                            sections={
                                slot: Section(slot, 0, 2, False, bytes(first + invalid))
                            },
                        ),
                    )
                    if slot in (37, 116) and text_offset == 0:
                        self.assertEqual(
                            profile.work_factor_records(slot, 7),
                            (bytes(first), bytes(invalid)),
                        )
                    else:
                        with self.assertRaises(ToyotaCodecError) as caught:
                            profile.work_factor_records(slot, 7)
                        self.assertEqual(caught.exception.code, 0xA0030102)
                    invalid[key_offset] = 8
                    object.__setattr__(
                        profile,
                        "database",
                        replace(
                            profile.database,
                            sections={
                                slot: Section(slot, 0, 2, False, bytes(first + invalid))
                            },
                        ),
                    )
                    self.assertEqual(
                        profile.work_factor_records(slot, 7), (bytes(first),)
                    )
                    invalid[key_offset] = 7

    def test_work_factor_p4_selected_queries_and_native_label_priority(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        for version in (0x0100030C, 0x0100032F):
            for slot, width, offset, text, method in (
                (35, 28, 4, 0, "work_factor_signal_records"),
                (36, 40, 20, 16, "work_factor_item_records"),
            ):
                rows = [bytearray(width) for _ in range(3)]
                for row, key in zip(rows, (7, 7, 8), strict=True):
                    struct.pack_into("<H", row, offset, key)
                    if slot == 36:
                        struct.pack_into("<I", row, 12, 0xFFFFFFFF)
                actual = replace(
                    profile,
                    database=replace(
                        profile.database,
                        version=version,
                        sections={slot: Section(slot, 0, 3, False, b"".join(rows))},
                    ),
                )
                self.assertEqual(getattr(actual, method)(), tuple(map(bytes, rows)))
                self.assertEqual(
                    getattr(actual, method)(7), tuple(map(bytes, rows[:2]))
                )
                struct.pack_into("<I", rows[1], text, 0xFFFFFFFF)
                actual = replace(
                    actual,
                    database=replace(
                        actual.database,
                        sections={slot: Section(slot, 0, 3, False, b"".join(rows))},
                    ),
                )
                with self.assertRaises(ToyotaCodecError) as caught:
                    getattr(actual, method)(7)
                self.assertEqual(caught.exception.code, 0xA0030102)

    def test_rob_data_id_selected_group_keeps_versioned_raw_fields(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        for version, flag in ((0x0100030C, 5), (0x0100032F, 7)):
            original, other = bytearray(8), bytearray(8)
            struct.pack_into("<H", original, 2, 7)
            struct.pack_into("<H", other, 2, 8)
            override = bytearray(original)
            struct.pack_into("<H", override, 0, 9)
            override[4] = 0x33
            override[flag] = 2
            actual = replace(
                profile,
                database=replace(
                    profile.database,
                    version=version,
                    sections={
                        90: Section(90, 0, 3, False, bytes(original + other + override))
                    },
                ),
                exception_ids=(9,),
            )
            self.assertEqual(actual.rob_data_id_records(7), (bytes(override),))
            self.assertEqual(actual.rob_data_id_records(8), (bytes(other),))

    def test_shared_ecu_group_key_and_kind_are_distinct_and_contiguous(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        catalog = VehicleCatalog(self.root)
        rows = []
        for group, kind in ((3325, 1), (3326, 1), (3327, 2), (9999, 1)):
            row = bytearray(12)
            struct.pack_into("<HH", row, 4, 7, group)
            row[11] = kind
            rows.append(bytes(row))
        for version in (0x0100030C, 0x0100032F):
            catalog.management = replace(
                catalog.management,
                version=version,
                sections={5: Section(5, 0, 4, False, b"".join(rows))},
            )
            self.assertEqual(catalog.ecu_group_records(7, 1), tuple(rows[:2]))
            self.assertEqual(catalog.ecu_group_records(7, 2), (rows[2],))
            self.assertEqual(catalog.ecu_group_records(42, 1), ())
            self.assertEqual(catalog.ecu_group_records(7, 0x101), ())

    def test_native_option_name_and_vehicle_set_queries_before_policy(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        catalog = VehicleCatalog(self.root)
        options = [
            struct.pack("<I6H", 0, 7, group, choice, model, 0, 0)
            for group, choice, model in ((1, 1, 55), (1, 2, 56), (2, 1, 57))
        ]
        names = [struct.pack("<I4H", 0, key, 0, 0, 0) for key in (55, 55, 56)]
        sets = [
            name.encode("utf-16le").ljust(18, b"\0") + struct.pack("<H", key)
            for key, name in (
                (55, "HIDDEN"),
                (55, "SECOND"),
                (56, "NEXT"),
                (55, "LATER"),
            )
        ]
        for version in (0x0100030C, 0x0100032F):
            catalog.management = replace(
                catalog.management,
                version=version,
                sections={
                    42: Section(42, 0, 3, False, b"".join(options)),
                    43: Section(43, 0, 3, False, b"".join(names)),
                    82: Section(82, 0, 4, False, b"".join(sets)),
                },
            )
            self.assertEqual(catalog.option_records(7), tuple(options))
            self.assertEqual(catalog.option_records(7, 1), tuple(options[:2]))
            self.assertEqual(catalog.option_records(7, 1, 2), (options[1],))
            self.assertEqual(catalog.vehicle_name_records(55), tuple(names[:2]))
            self.assertEqual(catalog.vehicle_set_records(55), tuple(sets[:2]))
            with self.assertRaises(ValueError):
                catalog.option_records(7, choice=1)

    def test_selected_monitor_signal_physical_and_unit_native_hydration(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        for version in (0x0100030C, 0x0100032F):
            for slot, width, key_offset, text_offset, method in (
                (62, 64, 36, 24, "datamonitor_p5_records"),
                (0, 12, 8, 0, "signal_group_records"),
                (1, 8, 0, None, "signal_check_records"),
                (13, 24, 12, None, "physical_records"),
                (15, 12, 4, 0, "unit_records"),
            ):
                rows = [bytearray(width) for _ in range(3)]
                for row, key in zip(rows, (7, 7, 8), strict=True):
                    if slot == 0:
                        row[key_offset] = key
                    else:
                        struct.pack_into("<H", row, key_offset, key)
                    if slot in (62, 13):
                        struct.pack_into("<I", row, 0, 0xFFFFFFFF)
                actual = replace(
                    profile,
                    database=replace(
                        profile.database,
                        version=version,
                        sections={slot: Section(slot, 0, 3, False, b"".join(rows))},
                    ),
                )
                self.assertEqual(
                    getattr(actual, method)(7), tuple(bytes(row) for row in rows[:2])
                )
                if slot == 0:
                    self.assertEqual(
                        actual.signal_group_records(), tuple(map(bytes, rows))
                    )
                    self.assertEqual(actual.signal_group_records(0x107), ())
                if text_offset is not None:
                    struct.pack_into("<I", rows[1], text_offset, 0xFFFFFFFF)
                    actual = replace(
                        actual,
                        database=replace(
                            actual.database,
                            sections={slot: Section(slot, 0, 3, False, b"".join(rows))},
                        ),
                    )
                    with self.assertRaises(ToyotaCodecError) as caught:
                        getattr(actual, method)(7)
                    self.assertEqual(caught.exception.code, 0xA0030102)

    def test_rob_bit_and_ddr_behavior_selected_hydration(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        bit = bytearray(12)
        struct.pack_into("<HH", bit, 0, 7, 1)
        behavior = bytearray(60)
        struct.pack_into("<H", behavior, 36, 7)
        struct.pack_into("<I", behavior, 0, 0xFFFFFFFF)
        for version in (0x0100030C, 0x0100032F):
            actual = replace(
                profile,
                database=replace(
                    profile.database,
                    version=version,
                    sections={
                        89: Section(89, 0, 1, False, bytes(bit)),
                        134: Section(134, 0, 2, False, bytes(behavior * 2)),
                    },
                ),
            )
            self.assertEqual(actual.rob_bit_records(7), (bytes(bit),))
            self.assertEqual(actual.rob_bit_variable(bytes(bit)), b"\x21\0")
            invalid = bytearray(bit)
            struct.pack_into("<H", invalid, 2, 0xFFFF)
            invalid_profile = replace(
                actual,
                database=replace(
                    actual.database,
                    sections={89: Section(89, 0, 2, False, bytes(bit + invalid))},
                ),
            )
            with self.assertRaises(ToyotaCodecError) as variable_error:
                invalid_profile.rob_bit_records(7)
            self.assertEqual(variable_error.exception.code, 0xA0030102)
            if version == 0x0100030C:
                with self.assertRaisesRegex(ValueError, "version 12 factory"):
                    actual.ddr_behavior_records(7)
                continue
            self.assertEqual(actual.ddr_behavior_records(7), (bytes(behavior),) * 2)
            self.assertEqual(actual.ddr_behavior_records(), (bytes(behavior),) * 2)
            bad = bytearray(behavior)
            struct.pack_into("<I", bad, 24, 0xFFFFFFFF)
            actual = replace(
                actual,
                database=replace(
                    actual.database,
                    sections={
                        134: Section(134, 0, 2, False, bytes(behavior + bad)),
                    },
                ),
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                actual.ddr_behavior_records(7)
            self.assertEqual(caught.exception.code, 0xA0030102)

    def test_ddr_behavior_code_native_third_label_error_priority(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        rows = [bytearray(44) for _ in range(3)]
        for row, second in zip(rows, (1, 2, 3), strict=True):
            struct.pack_into("<H", row, 32, 7)
            row[40:42] = bytes((8, second))
            struct.pack_into("<II", row, 12, 0xFFFFFFFF, 0)
            struct.pack_into("<I", row, 28, 0xFFFFFFFF)
        actual = replace(
            profile,
            database=replace(
                profile.database,
                sections={
                    133: Section(133, 0, 3, False, b"".join(rows)),
                },
            ),
        )
        self.assertEqual(actual.ddr_behavior_code_records(7, 8, 2), (bytes(rows[1]),))
        self.assertEqual(actual.ddr_behavior_code_records(7, 0x108, 2), ())
        from unittest.mock import patch

        # Structured GetQuery scans all rows, not only the first matching block.
        staged = (bytes(rows[1]), bytes(rows[0]), bytes(rows[1]))
        with patch.object(type(actual), "_signal_rows", return_value=staged):
            self.assertEqual(
                actual.ddr_behavior_code_records(7, 8, 2), (staged[0], staged[2])
            )
        struct.pack_into("<I", rows[1], 16, 0xFFFFFFFF)
        actual = replace(
            actual,
            database=replace(
                actual.database,
                sections={
                    133: Section(133, 0, 3, False, b"".join(rows)),
                },
            ),
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            actual.ddr_behavior_code_records(7)
        self.assertEqual(caught.exception.code, 0xA0030102)

    def test_freeze_query_wildcard_scans_all_and_hydrates_all_labels(self):
        from dataclasses import replace
        from unittest.mock import patch

        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        rows = [bytearray(84) for _ in range(3)]
        for row, selector, logical in zip(rows, (1, 2, 3), (7, 8, 7), strict=True):
            row[79] = selector
            struct.pack_into("<H", row, 56, logical)
        staged = tuple(map(bytes, rows))
        for version in (0x0100030C, 0x0100032F):
            actual = replace(
                profile, database=replace(profile.database, version=version)
            )
            with patch.object(type(actual), "_signal_rows", return_value=staged):
                self.assertEqual(
                    actual.freeze_records(0x100, 7), (staged[0], staged[2])
                )
                self.assertEqual(actual.freeze_records(1, 7), (staged[0],))
                self.assertEqual(actual.freeze_records(0x100, 0x10007), ())
            struct.pack_into("<I", rows[2], 48, 0xFFFFFFFF)
            with patch.object(
                type(actual), "_signal_rows", return_value=tuple(map(bytes, rows))
            ):
                with self.assertRaises(ToyotaCodecError) as caught:
                    actual.freeze_records(0x100, 7)
                self.assertEqual(caught.exception.code, 0xA0030102)
            struct.pack_into("<I", rows[2], 48, 0)

    def test_plain_pcs_operation_pid_and_all_operation_freeze_queries(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        rows = tuple(
            bytes((0, 0, pid, selector))
            for pid, selector in ((7, 1), (8, 1), (9, 2), (10, 1))
        )
        op = bytes(8)
        for version in (0x0100030C, 0x0100032F):
            actual = replace(
                profile,
                database=replace(
                    profile.database,
                    version=version,
                    sections={
                        86: Section(86, 0, 4, False, b"".join(rows)),
                        54: Section(54, 0, 1, False, op),
                    },
                ),
            )
            self.assertEqual(actual.pcs_operation_pid_records(), rows)
            self.assertEqual(actual.pcs_operation_pid_records(1), rows[:2])
            self.assertEqual(actual.pcs_operation_pid_records(0x101), ())
            self.assertEqual(actual.operation_freeze_records(), (op,))

    def test_selected_comm_ecu_and_versioned_pattern_hydration(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        for version, width, offset in ((0x0100030C, 20, 4), (0x0100032F, 24, 12)):
            comm = bytearray(12)
            struct.pack_into("<H", comm, 0, 10)
            patterns = [bytearray(width) for _ in range(2)]
            for row in patterns:
                struct.pack_into("<H", row, offset, 7)
            actual = replace(
                profile,
                database=replace(
                    profile.database,
                    version=version,
                    sections={
                        38: Section(38, 0, 1, False, bytes(comm)),
                        14: Section(14, 0, 2, False, b"".join(patterns)),
                    },
                ),
            )
            self.assertEqual(actual.comm_ecu_records(10), (bytes(comm),))
            self.assertEqual(actual.comm_ecu_records(11), ())
            self.assertEqual(actual.pattern_records(7), tuple(map(bytes, patterns)))
            struct.pack_into("<I", patterns[1], 0, 0xFFFFFFFF)
            actual = replace(
                actual,
                database=replace(
                    actual.database,
                    sections={14: Section(14, 0, 2, False, b"".join(patterns))},
                ),
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                actual.pattern_records(7)
            self.assertEqual(caught.exception.code, 0xA0030102)

    def test_dtc_status_query_keeps_full_unsigned_type_and_raw_mask_expected(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        profile = VehicleCatalog(self.root).build_profile(42)
        low, high = bytearray(12), bytearray(12)
        struct.pack_into("<I", low, 0, 1)
        struct.pack_into("<I", high, 0, 0x80000000)
        high[8:10] = b"\xf0\x40"
        for version in (0x0100030C, 0x0100032F):
            object.__setattr__(
                profile,
                "database",
                replace(
                    profile.database,
                    version=version,
                    sections={66: Section(66, 0, 2, False, bytes(low + high))},
                ),
            )
            self.assertEqual(profile.dtc_status_records(0x80000000), (bytes(high),))
            self.assertEqual(profile.dtc_status_records(0), ())
            with self.assertRaises(ValueError):
                profile.dtc_status_records(True)

    def test_selected_protocol_multi_pid_and_communication_queries(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        selected_protocol = profile.protocol_info(7)
        assert selected_protocol is not None
        self.assertEqual(selected_protocol[24], 7)
        self.assertIsNone(profile.protocol_info(0x107))
        self.assertIsNone(profile.protocol_info(8))
        with self.assertRaises(ValueError):
            profile.protocol_info(True)
        management = profile.catalog.management
        for version, width, offset in ((0x0100030C, 24, 22), (0x0100032F, 28, 24)):
            protocol = bytearray(width)
            struct.pack_into("<H", protocol, 0, 42)
            protocol[offset] = 7
            profile.catalog.management = replace(
                management,
                version=version,
                sections={
                    **management.sections,
                    13: Section(13, 0, 1, False, bytes(protocol)),
                },
            )
            self.assertEqual(profile.protocol_info(7), bytes(protocol))
            self.assertIsNone(profile.protocol_info(0x107))
            self.assertEqual(profile.catalog.default_diagnostic_mode(42, 7).key2, 8)
        sections = dict(management.sections)
        for slot, width, key_offset, order_offset in (
            (54, 44, 16, 30),
            (88, 36, 16, 26),
            (62, 24, 0, 16),
        ):
            rows = []
            for logical, order, category in ((1, 1, 999), (1, 2, 42), (2, 1, 42)):
                row = bytearray(width)
                struct.pack_into("<HH", row, key_offset, logical, category)
                struct.pack_into("<H", row, order_offset, order)
                rows.append(bytes(row))
            sections[slot] = Section(slot, 0, 3, False, b"".join(rows))
        timer = struct.pack("<I4H", 1000, 42, 1, 0, 0)
        details = bytearray(24)
        struct.pack_into("<3H", details, 4, 42, 7, 9)
        sections[25] = Section(25, 0, 1, False, timer)
        sections[27] = Section(27, 0, 1, False, bytes(details))
        profile.catalog.management = replace(management, sections=sections)
        self.assertEqual(profile.timer_records(1), (timer,))
        self.assertEqual(profile.ecu_function_details(7), (bytes(details),))
        self.assertEqual(profile.ecu_function_details(9), ())
        self.assertEqual(profile.timer_records(42), ())
        self.assertEqual(
            [struct.unpack_from("<H", r, 18)[0] for r in profile.comm_pid_records(1)],
            [999, 42],
        )
        self.assertEqual(
            [struct.unpack_from("<H", r, 18)[0] for r in profile.comm_rid_records(1)],
            [999, 42],
        )
        self.assertEqual(profile.comm_pid_records(99), ())
        self.assertEqual(
            [struct.unpack_from("<H", r, 2)[0] for r in profile.comm_did_records(1)],
            [999, 42],
        )
        links = struct.pack("<6H", 7, 1, 3, 0, 0, 0) + struct.pack(
            "<6H", 7, 2, 4, 0, 0, 0
        )
        mode = struct.pack("<HBBHBB", 9, 0x6D, 0, 0, 0, 0)
        lsb = struct.pack("<II6H", 2, 3, 9, 0, 7, 0, 0, 0)
        did_lsb = struct.pack("<II6H", 2, 3, 0x1234, 9, 0, 7, 0, 0)
        profile = replace(
            profile,
            database=replace(
                profile.database,
                sections={
                    26: Section(26, 0, 2, False, links),
                    60: Section(60, 0, 1, False, mode),
                    39: Section(39, 0, 1, False, lsb),
                    64: Section(64, 0, 1, False, did_lsb),
                },
            ),
        )
        self.assertEqual(
            [struct.unpack_from("<H", r, 2)[0] for r in profile.multi_pid_records(7)],
            [1, 2],
        )
        active = bytearray(92)
        self.assertEqual(profile.signal_lsb_records(9), (lsb,))
        self.assertEqual(profile.signal_did_lsb_records(9), (did_lsb,))
        self.assertEqual(profile.signal_lsb_records(10), ())
        struct.pack_into("<H", active, 56, 9)
        self.assertEqual(profile.active_comm_mode(bytes(active)), mode)
        struct.pack_into("<H", active, 56, 10)
        self.assertIsNone(profile.active_comm_mode(bytes(active)))
        profile = replace(profile, database=replace(profile.database, sections={}))
        self.assertEqual(profile.signal_lsb_records(9), ())
        self.assertEqual(profile.signal_did_lsb_records(9), ())
        self.assertIsNone(profile.active_comm_mode(bytes(active)))
        with self.assertRaises(ToyotaCodecError) as error:
            profile.multi_pid_records(7)
        self.assertEqual(error.exception.code, 0xA0030107)

    def test_base_carb_mode_keeps_word8_and_selected_carb_overlay(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.toyota import ToyotaCodecError

        profile = VehicleCatalog(self.root).build_profile(42)
        management = profile.catalog.management
        sections = dict(management.sections)
        protocol = bytearray(sections[13].payload)
        struct.pack_into("<H", protocol, 8, 2)
        sections[13] = replace(sections[13], payload=bytes(protocol))
        sections[72] = Section(
            72, 0, 2, False, struct.pack("<HBBHBB", 8, 3, 0, 10, 3, 0)
        )
        carb = sections[73].payload
        overlay = bytearray(carb)
        struct.pack_into("<H", overlay, 4, 9)
        overlay[9], overlay[10] = 11, 2
        sections[73] = Section(73, 0, 2, False, carb + bytes(overlay))
        profile.catalog.management = replace(management, sections=sections)
        self.assertEqual(profile.carb_mode_info(7).key2, 10)
        self.assertEqual(profile.carb_mode_info(7, p5=True).key2, 8)
        self.assertEqual(profile.catalog.default_diagnostic_mode(42, 7).key2, 8)
        selected = replace(profile, exception_ids=(9,))
        self.assertEqual(selected.carb_mode_info(7).protocol, 11)
        self.assertEqual(
            profile.catalog.default_diagnostic_mode(42, 7, (9,)).protocol, 11
        )
        with self.assertRaises(ToyotaCodecError) as error:
            profile.carb_mode_info(0x107)
        self.assertEqual(error.exception.code, 0xC0040101)
        profile.catalog.management = replace(
            profile.catalog.management,
            sections={k: v for k, v in sections.items() if k != 73},
        )
        with self.assertRaises(ToyotaCodecError) as error:
            profile.carb_mode_info(7)
        self.assertEqual(error.exception.code, 0xA0030107)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        category = bytearray(76)
        category[:18] = "demo.ddb\0".encode("utf-16le")
        struct.pack_into("<HH", category, 68, 42, 0)
        variables = struct.pack("<IH", 0, 2) + b"\x21\0"
        function1 = struct.pack("<8H", 42, 16, 1, 2, 0, 1, 0, 0)
        function2 = struct.pack("<8H", 42, 16, 99, 2, 0, 2, 0, 0)
        settings = bytearray(16)
        struct.pack_into("<H", settings, 10, 1)
        decision = bytearray(52)
        struct.pack_into("<I", decision, 36, 0x3FF)
        struct.pack_into("<6H", decision, 40, 1, 1, 1, 1, 4, 0)
        group = struct.pack("<IHHHBB", 0, 55, 77, 0, 0, 1)
        installing = bytearray(24)
        struct.pack_into("<HH", installing, 4, 77, 42)
        vin = bytearray(32)
        struct.pack_into("<I", vin, 0, 0x7FF)
        struct.pack_into("<HHH", vin, 12, 4, 0, 42)
        protocol = bytearray(28)
        struct.pack_into("<H", protocol, 0, 42)
        protocol[24] = 7
        carb = bytearray(12)
        struct.pack_into("<I", carb, 0, 42)
        carb[6:10] = bytes((7, 0, 3, 9))
        management = {
            13: (1, protocol),
            72: (1, struct.pack("<HBB", 8, 3, 0)),
            73: (1, carb),
            59: (1, vin),
            2: (1, struct.pack("<HBB", 42, 7, 0)),
            0: (1, variables),
            16: (1, category),
            17: (1, struct.pack("<4H", 2, 1, 0, 0)),
            18: (2, function1 + function2),
            29: (1, settings),
            5: (1, group),
            44: (1, installing),
            41: (1, decision),
            46: (4, b"".join(struct.pack("<I4H", 0, i, 1, 1, 0) for i in range(1, 5))),
            47: (4, b"".join(struct.pack("<IHH", 0, i, i) for i in range(1, 5))),
            42: (
                2,
                struct.pack("<I6H", 0, 4, 1, 1, 0, 2, 0)
                + struct.pack("<I6H", 0, 4, 2, 1, 55, 0, 0),
            ),
            43: (1, struct.pack("<IHHI", 0, 55, 0, 0)),
        }
        (self.root / "Toyota.ddb").write_bytes(encode_database(1, management))
        (self.root / "M_English.ddb").write_bytes(encode_database(4, {0: (0, b"")}))
        active_rows = []
        for signal, did, mode in ((9, 0, 1), (10, 12, 0), (11, 13, 2)):
            row = bytearray(92)
            struct.pack_into("<I", row, 40, 42)
            struct.pack_into("<H", row, 56, signal)
            struct.pack_into("<H", row, 68, 7)
            row[82], row[83] = did, mode
            active_rows.append(bytes(row))
        (self.root / "demo.ddb").write_bytes(
            encode_database(2, {8: (0, b""), 11: (3, b"".join(active_rows))})
        )

    def test_selected_signal_and_dtc_freeze_joins_preserve_source_and_exception(self):
        from scripts.toyota import ToyotaCodecError

        group = bytearray(12)
        struct.pack_into("<H", group, 4, 7)
        group[8] = 0x1C
        overlay = bytearray(group)
        struct.pack_into("<HH", overlay, 4, 8, 9)
        overlay[9] = 2
        checks = b"".join(
            struct.pack("<4H", key, pid, 0, 0)
            for key, pid in ((7, 10), (7, 20), (7, 10), (8, 99))
        )
        freezes = []
        for selector, pid in ((1, 10), (1, 20), (2, 10), (2, 99)):
            row = bytearray(84)
            struct.pack_into("<H", row, 56, pid)
            row[79] = selector
            freezes.append(bytes(row))
        dtc = bytearray(10)
        struct.pack_into("<H", dtc, 0, 0x1234)
        dtc[2] = 0x1C
        sections = {
            0: (2, group + overlay),
            1: (4, checks),
            10: (4, b"".join(freezes)),
            32: (1, dtc),
        }
        (self.root / "demo.ddb").write_bytes(encode_database(2, sections))
        catalog = VehicleCatalog(self.root)
        profile = catalog.build_profile(42)
        self.assertEqual(profile.signal_pids(0x1C), (10, 20, 10))
        selected = profile.dtc_freeze_records(0x1234)
        self.assertEqual([item.pid_id for item in selected], [10, 20, 10])
        self.assertEqual(selected[0].freeze_record[79], 1)
        self.assertIn(profile.database.sha256, selected[0].provenance)
        self.assertIsNone(selected[0].physical_record)
        overlay_profile = catalog.build_profile(42, exception_ids=(9,))
        self.assertEqual(overlay_profile.signal_pids(0x1C), (99,))
        self.assertEqual(overlay_profile.dtc_freeze_records(0x1234)[0].pid_id, 99)
        with self.assertRaises(ToyotaCodecError) as error:
            profile.signal_checks(0x1D)
        self.assertEqual(error.exception.code, 0xC0040101)
        with self.assertRaises(ValueError):
            profile.signal_pids(0)

    def test_native_vin_decision_and_option_resolution(self):
        from scripts.profiles import VinVehicleContext, vin_vehicle_matches

        catalog = VehicleCatalog(self.root)
        context = VinVehicleContext(42, 0, bytes(11))
        self.assertEqual(
            VinVehicleContext.from_vin(42, 0, b"123456789ABCDEFGH").attributes,
            b"123456789AB",
        )
        with self.assertRaises(ValueError):
            VinVehicleContext.from_vin(42, 0, b"?23456789ABCDEFGH")
        self.assertEqual(catalog.matching_vin_vehicles(context, collect_key=1), ())
        self.assertEqual(len(catalog.matching_vin_vehicles(context)), 1)
        self.assertEqual(catalog.vehicle_identity(55).category, 0)
        with self.assertRaises(ValueError):
            catalog.vehicle_identity(True)
        self.assertEqual(catalog.resolve_vin_vehicle(0, (1, 1))["vehicle_name_key"], 55)
        from scripts.support import ProtocolSelection

        observed = ProtocolSelection(42, 0, 7, 0)
        selected = catalog.resolve_protocol_vehicle(
            observed, b"123456789ABCDEFGH", answers=(1, 1)
        )
        self.assertEqual(selected["vehicle_name_key"], 55)
        with self.assertRaisesRegex(ValueError, "no selectable"):
            catalog.resolve_protocol_vehicle(
                ProtocolSelection(41, 0, 7, 0), b"123456789ABCDEFGH"
            )
        row = bytearray(32)
        struct.pack_into("<H", row, 16, 42)
        for index in range(11):
            row[19 + index] = 1
            self.assertFalse(vin_vehicle_matches(bytes(row), context))
            struct.pack_into("<I", row, 0, 1 << index)
            self.assertTrue(vin_vehicle_matches(bytes(row), context))
            row[19 + index] = 0
            struct.pack_into("<I", row, 0, 0)
        self.assertFalse(
            vin_vehicle_matches(bytes(row), VinVehicleContext(41, 0, bytes(11)))
        )
        with self.assertRaises(ValueError):
            VinVehicleContext(42, 0, bytes(10))
        with self.assertRaises(ValueError):
            catalog.resolve_vin_vehicle(True)

    def test_original_identification_buffers_construct_eu_context(self):
        from scripts.profiles import VehicleContext

        data = bytearray(range(22))
        data[0], data[4] = 3, 3
        context = VehicleContext.from_identification_fields(42, 7, bytes(data))
        self.assertEqual(context.identity.identifier, bytes((1, 2, 3)))
        self.assertEqual(context.identity.subidentifier, bytes((0x35, 6, 7)))
        self.assertEqual(
            (context.identity.key_0c, context.identity.key_19, context.identity.key_1a),
            (9, 21, 0),
        )
        self.assertEqual(context.mode, 2)
        data = bytearray(range(25))
        data[0], data[8] = 7, 6
        context = VehicleContext.from_identification_fields(
            42, 7, bytes(data), extended=True
        )
        self.assertEqual(context.identity.identifier, bytes(range(1, 8)))
        self.assertEqual(context.identity.subidentifier, bytes(range(9, 15)))
        self.assertEqual(
            (
                context.identity.key_0c,
                context.identity.key_14,
                context.identity.key_15,
                context.identity.key_16,
                context.identity.key_17,
                context.identity.key_1a,
            ),
            (16, 18, 20, 22, 0, 24),
        )
        data[0] = 8
        with self.assertRaises(ValueError):
            VehicleContext.from_identification_fields(42, 7, bytes(data), extended=True)

    def test_pointer_free_native_vehicle_input_key(self):
        from scripts.profiles import VehicleContext

        key = bytearray(40)
        struct.pack_into("<3H", key, 0, 3, 42, 2)
        key[12] = 9
        key[20:28] = bytes(range(10, 18))
        struct.pack_into("<H", key, 28, 0xFFF)
        key[30] = 3
        struct.pack_into("<4H", key, 32, 1, 2, 3, 4)
        context = VehicleContext.from_native_key(
            bytes(key), identifier=b"abcX", subidentifier=b"deX"
        )
        self.assertEqual(context.identity.category, 42)
        self.assertEqual(context.identity.variant, 17)
        self.assertEqual(context.identity.identifier, b"abc")
        self.assertEqual(context.identity.subidentifier, b"de")
        self.assertEqual((context.identity.key_0c, context.identity.key_1a), (9, 16))
        self.assertEqual(
            (context.mode, context.selected_fields, context.option_keys),
            (3, 0xFFF, (1, 2, 3, 4)),
        )
        with self.assertRaises(ValueError):
            VehicleContext.from_native_key(bytes(key))

    def test_default_alternate_diagnostic_context_join(self):
        catalog = VehicleCatalog(self.root)
        mode = catalog.default_diagnostic_mode(42, 7)
        self.assertEqual(catalog.protocol_candidates()[0].category, 42)
        self.assertEqual(catalog.protocol_resume_index(42, 7), 1)
        self.assertEqual(catalog.protocol_resume_index(43, 7), 1)
        value = mode.replace_in(bytes.fromhex("aaaa3412") + bytes(12))
        self.assertEqual(struct.unpack("<HHIIHH", value), (1, 0x1234, 42, 8, 9, 0))
        with self.assertRaisesRegex(ValueError, "protocol info"):
            catalog.default_diagnostic_mode(42, 8)
        with self.assertRaises(ValueError):
            mode.replace_in(bytes(15))

    def test_selected_active_list_and_count_follow_observed_enable_lengths(self):
        profile = VehicleCatalog(self.root).build_profile(42)

        def unexpected(*args):
            raise AssertionError("No probe required")

        self.assertEqual(
            [
                item["signal_id"]
                for item in profile.active_tests(
                    pid_lengths={}, did_lengths={}, exchange=unexpected
                )
            ],
            [9],
        )
        available = profile.active_tests(
            pid_lengths={}, did_lengths={12: 1}, exchange=unexpected
        )
        self.assertEqual([item["signal_id"] for item in available], [9, 10])
        self.assertEqual(available[1]["control_value"], 42)
        self.assertEqual(len(available), 2)

    def test_explicit_selection_and_first_row_settings(self):
        catalog = VehicleCatalog(self.root)
        profile = catalog.build_profile(42, vehicle_name_key=55)
        self.assertEqual(profile.filename, "demo.ddb")
        self.assertEqual(profile.category, 42)
        self.assertEqual(len(catalog.options), 2)
        selected = profile.frame_records(16)
        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[0].settings_record, selected[1].settings_record)
        self.assertEqual(
            [frame.request for frame in profile.command_frames(16)], [b"\x21\0"] * 2
        )
        self.assertEqual(profile.pid_bits(), {})
        self.assertEqual(
            json.loads(json.dumps(profile.report()))["selection"],
            "explicit-resource-selection",
        )

    def test_vehicle_option_tree_and_resource_join(self):
        from scripts.profiles import VehicleContext
        from scripts.support import ExceptionContext

        catalog = VehicleCatalog(self.root)
        self.assertEqual(catalog.resolve_vehicle(0)["group"], 1)
        self.assertEqual(catalog.resolve_vehicle(0, (1,))["group"], 2)
        selected = catalog.resolve_vehicle(0, (1, 1))
        self.assertEqual(selected["vehicle_name_key"], 55)
        systems = catalog.vehicle_systems(55)
        self.assertEqual([row["category"] for row in systems], [42])
        self.assertEqual(systems[0]["file"], "demo.ddb")
        self.assertEqual(
            catalog.matching_vehicles(VehicleContext(ExceptionContext(0, 0)))[0][
                "option_key"
            ],
            4,
        )
        for answers in ((9,), (1, 1, 1), (True,)):
            with self.assertRaises(ValueError):
                catalog.resolve_vehicle(0, answers)
        catalog.options[1]["vehicle_name_key"] = 0
        catalog.options[1]["next_group"] = 1
        with self.assertRaisesRegex(ValueError, "Cycle"):
            catalog.resolve_vehicle(0, (1, 1))

    def test_native_registered_set_filter_prunes_descendants(self):
        from scripts.profiles import VinVehicleContext

        catalog = VehicleCatalog(self.root)
        self.assertEqual(len(catalog.selectable_vehicles()), 1)
        catalog.vehicle_sets[55] = "DEMO"
        vin = VinVehicleContext(42, 0, bytes(11))
        self.assertEqual(len(catalog.raw_matching_vin_vehicles(vin)), 1)
        self.assertEqual(catalog.matching_vin_vehicles(vin), ())
        with self.assertRaisesRegex(ValueError, "unregistered"):
            catalog.vehicle_systems(55)
        with self.assertRaisesRegex(ValueError, "unregistered"):
            catalog.build_profile(42, vehicle_name_key=55)
        self.assertEqual(catalog.build_profile(42).category, 42)
        self.assertEqual(catalog.selectable_vehicles(), ())
        with self.assertRaises(ValueError):
            catalog.resolve_vehicle(0)
        catalog.registered_sets = frozenset({"DEMO"})
        self.assertEqual(len(catalog.selectable_vehicles()), 1)
        self.assertEqual(catalog.resolve_vehicle(0, (1, 1))["vehicle_name_key"], 55)

    def test_missing_selection_and_invalid_resource_fail(self):
        catalog = VehicleCatalog(self.root)
        for category in (True, -1, 1, 65536):
            with self.assertRaises(ValueError):
                catalog.build_profile(category)
        with self.assertRaises(ValueError):
            catalog.build_profile(42, vehicle_name_key=99)
        profile = catalog.build_profile(42)
        with self.assertRaises(ValueError):
            profile.command_frames(99)
        with self.assertRaises(ValueError):
            profile.command_frames(True)
        (self.root / "demo.ddb").unlink()
        (self.root / "demo.ddb").symlink_to(self.root / "Toyota.ddb")
        with self.assertRaises(ValueError):
            catalog.build_profile(42)


class VehicleMatcherTests(unittest.TestCase):
    def row(self, prefix=b"ABC"):
        row = bytearray(52)
        struct.pack_into("<H", row, 0, 42)
        row[2] = 3
        row[3 : 3 + len(prefix)] = prefix
        row[10], row[11] = len(prefix), 1
        row[12:15] = b"XYZ"
        row[18], row[19] = 3, 1
        for offset in (20, 22, 24, 26, 28, 30, 32, 34):
            row[offset], row[offset + 1] = 10, 1
        struct.pack_into("<4H", row, 40, 1, 2, 3, 4)
        return row

    def context(self, mode=0, **kwargs):
        from scripts.profiles import VehicleContext
        from scripts.support import ExceptionContext

        identity = ExceptionContext(42, 3, b"ABC-tail", b"XYZ-tail", *([10] * 8))
        return VehicleContext(identity, mode, **kwargs)

    def test_four_modes_exact_and_selected_fields(self):
        from dataclasses import replace

        from scripts.profiles import vehicle_matches

        for mode in (0, 1, 2, 3):
            context = self.context(mode, selected_fields=0xFFF)
            row = bytes(self.row())
            self.assertEqual(
                vehicle_matches(row, context), (True, 3 if mode >= 2 else 0)
            )
            bad = replace(context, identity=replace(context.identity, category=0))
            self.assertFalse(vehicle_matches(row, bad)[0])
            if mode in (1, 3):
                self.assertTrue(
                    vehicle_matches(row, replace(bad, selected_fields=0xFFE))[0]
                )
                self.assertFalse(
                    vehicle_matches(row, replace(context, option_keys=(1, 2, 9, 4)))[0]
                )

    def test_scalar_comparison_modes_and_native_reused_mode(self):
        from dataclasses import replace

        from scripts.profiles import vehicle_matches

        for comparison, actual, expected in (
            (1, 10, True),
            (1, 9, False),
            (2, 9, True),
            (2, 10, False),
            (3, 11, True),
            (3, 9, False),
            (4, 9, True),
            (4, 11, False),
        ):
            row = self.row()
            row[21] = comparison
            context = self.context()
            context = replace(
                context, identity=replace(context.identity, key_0c=actual)
            )
            self.assertEqual(vehicle_matches(bytes(row), context)[0], expected)
        row = self.row()
        row[29], row[31] = 1, 0
        self.assertTrue(vehicle_matches(bytes(row), self.context())[0])
        row[29] = 2
        self.assertFalse(vehicle_matches(bytes(row), self.context())[0])

    def test_eu_trim_and_score_survives_later_failure(self):
        from dataclasses import replace

        from scripts.profiles import vehicle_matches

        row = self.row(b"ABC# ")
        context = self.context(2)
        self.assertEqual(vehicle_matches(bytes(row), context), (True, 3))
        row[20] = 99
        self.assertEqual(vehicle_matches(bytes(row), context), (False, 3))
        self.assertEqual(
            vehicle_matches(bytes(self.row(b"AB")), context, 3), (False, 3)
        )
        with self.assertRaises(ValueError):
            vehicle_matches(
                bytes(self.row()),
                replace(
                    context, identity=replace(context.identity, identifier=b"\xff")
                ),
            )
        row = self.row()
        row[10] = 8
        with self.assertRaises(ValueError):
            vehicle_matches(bytes(row), self.context())
