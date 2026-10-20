"""Authored native-layout vectors; no vendor fixtures, library execution or device."""

import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from scripts.active_tests import (
    ActiveSupport,
    ActiveTestCatalog,
    SAFinalizer,
    SAKeyMaterial,
)
from scripts.diagnostic_db import Database, Section
from scripts.profiles import VehicleCatalog, VehicleProfile
from scripts.toyota import CommandFrame, ToyotaCodecError
from scripts.toyota_session import (
    Cancelled,
    Limits,
    NativeStatus,
    SessionError,
    ToyotaSession,
)


def put(row, offset, value, fmt="H"):
    struct.pack_into("<" + fmt, row, offset, value)


def legacy(key=1):
    row = bytearray(92)
    row[:5] = b"Test\0"
    for offset, value in (
        (20, 11),
        (24, 22),
        (28, 33),
        (32, 1),
        (36, 2),
        (40, 3),
        (44, 4),
        (48, 5),
        (52, 6),
    ):
        put(row, offset, value, "I")
    for offset, value in ((56, key), (58, 9), (62, 2), (64, 3), (76, 10), (78, 11)):
        put(row, offset, value)
    row[83] = 1
    return row


def modern(key=1, routine=False):
    row = bytearray(64)
    for offset, value in (
        (0, 11),
        (4, 22),
        (8, 33),
        (12, 1),
        (16, 2),
        (20, 3),
        (24, 4),
        (28, 5),
    ):
        put(row, offset, value, "I")
    if routine:
        for offset, value in (
            (28, 123),
            (30, key),
            (34, 2),
            (36, 3),
            (46, 30),
            (48, 31),
            (50, 10),
            (52, 11),
            (54, 12),
            (56, 1),
        ):
            put(row, offset, value)
    else:
        for offset, value in (
            (32, key),
            (52, 123),
            (36, 2),
            (38, 3),
            (48, 10),
            (50, 11),
            (54, 12),
            (44, 2),
        ):
            put(row, offset, value)
        row[57], row[61] = 1, 1
    return row


def dependencies():
    pattern, physical, unit, display = (
        bytearray(24),
        bytearray(24),
        bytearray(12),
        bytearray(24),
    )
    put(pattern, 0, 3)
    for offset, value in ((2, 12), (4, 20), (6, 30), (10, 4), (12, 40)):
        put(pattern, offset, value)
    pattern[18:22] = bytes((1, 2, 1, 5))
    struct.pack_into("<iiiHH", physical, 0, -2, 4, -8, 2, 7)
    physical[20:22] = bytes((1, 2))
    put(unit, 0, 8, "I")
    put(unit, 4, 7)
    put(unit, 6, 9)
    for offset, value in ((0, 9), (4, 0xFFFFFFFF), (8, 5)):
        put(display, offset, value, "I")
    put(display, 12, 4)
    put(display, 18, 17)
    display[22] = 1
    return {
        12: [bytes(pattern)],
        13: [bytes(physical)],
        14: [bytes(display)],
        15: [bytes(unit)],
    }


def profile(rows=None, variables=(b"\x11\x22", b"\x33"), subaru=False):
    mapping = dependencies() | (rows or {})
    sections = {
        slot: Section(slot, 0, len(items), False, b"".join(items))
        for slot, items in mapping.items()
    }
    body, directory = b"", b""
    for value in variables:
        directory += struct.pack("<IH", len(body), len(value))
        body += value
    management = Database(
        1,
        0x0100032F,
        "authored-management",
        {0: Section(0, 0, len(variables), False, directory + body)},
    )
    catalog = cast(
        VehicleCatalog,
        SimpleNamespace(
            management=management,
            language=SimpleNamespace(resolve=lambda value: f"label-{value}"),
        ),
    )
    category = bytearray(76)
    put(category, 68, 1)
    category[72] = 0x20 if subaru else 0
    return VehicleProfile(
        catalog, bytes(category), Database(2, 0x0100032F, "authored-ecu", sections)
    )


def variable_display(group, *, ref=1, mode=1):
    row = bytearray(20)
    put(row, 0, 9, "I")
    put(row, 4, group)
    put(row, 10, ref)
    put(row, 12, 2)
    put(row, 14, 17)
    row[18] = mode
    return bytes(row)


def multi(parent, child, order=1, optional=False):
    row = bytearray(12)
    put(row, 0, parent)
    put(row, 2, child)
    put(row, 6, order)
    row[11] = int(optional)
    return bytes(row)


class InitializationTests(unittest.TestCase):
    def test_native_data_bounds_are_max_then_min_and_bit_length_is_separate(self):
        # Original printf/field stores: +AC DataMax, +B0 DataMin, +94 BitLength.
        for family, routine in (
            ("p3", False),
            ("dk", False),
            ("p4", False),
            ("p5", False),
            ("routine", True),
        ):
            row = modern(routine=routine) if family in ("p5", "routine") else legacy()
            maximum_offset, minimum_offset = (
                (0, 4) if routine else (4, 8) if family == "p5" else (24, 28)
            )
            put(row, maximum_offset, 255, "I")
            put(row, minimum_offset, 3, "I")
            selected = profile(
                {
                    71 if routine else 68 if family == "p5" else 11: [bytes(row)],
                    62: [],
                    72: [],
                    73: [],
                }
            )
            result = ActiveTestCatalog(selected).initialize(
                family,
                1,
                support=ActiveSupport(
                    panel=lambda *_: False,
                    pid=lambda _: False,
                    routine_probe=lambda *_: False,
                ),
            )
            self.assertEqual((result.minimum, result.maximum), (3, 255))
            self.assertEqual(
                (result.bit_length, result.graph_minimum, result.graph_maximum),
                (0, 0, 0),
            )
            self.assertEqual(result.report()["bit_length"], 0)

    def test_limit_read_mode_one_updates_maximum_two_updates_minimum(self):
        for mode, expected in ((1, (33, 210)), (2, (211, 22)), (3, (211, 210))):
            row = legacy()
            row[89] = mode
            freezes = []
            for key in (10, 11):
                freeze = bytearray(84)
                put(freeze, 56, key)
                freezes.append(bytes(freeze))
            selected = profile({11: [bytes(row)], 10: freezes})
            result = ActiveTestCatalog(selected).initialize(
                "p3",
                1,
                support=ActiveSupport(panel=lambda *_: False),
                read_value=lambda _, freeze: (
                    200 + struct.unpack_from("<H", freeze, 56)[0]
                ),
            )
            self.assertEqual((result.minimum, result.maximum), expected)

    def test_scalar_api_materializes_signed_long_independently_of_physical_sign_mode(
        self,
    ):
        for family in ("p3", "dk", "p4", "p5", "routine"):
            with self.subTest(family=family):
                routine = family == "routine"
                modern_family = family in ("p5", "routine")
                row = modern(routine=routine) if modern_family else legacy()
                maximum, minimum = (
                    (0, 4) if routine else (4, 8) if modern_family else (24, 28)
                )
                put(row, maximum, 0xFFFFFFFF, "I")
                put(row, minimum, 0xFFFFFFF6, "I")
                rows = {
                    71 if routine else 68 if modern_family else 11: [bytes(row)],
                    72: [],
                    73: [],
                }
                if not modern_family:
                    row[84] = 1
                    rows[11] = [bytes(row)]
                    freeze = bytearray(84)
                    put(freeze, 56, 9)
                    rows[10] = [bytes(freeze)]
                elif not routine:
                    put(row, 0, 0xFFFFFFFF, "I")
                    rows[68] = [bytes(row)]
                selected = profile(rows)
                value = ActiveTestCatalog(selected).initialize(
                    family,
                    1,
                    support=ActiveSupport(
                        panel=lambda *_: False,
                        pid=lambda _: False,
                        routine_probe=lambda *_: False,
                    ),
                    read_value=lambda *_: 0xFFFFFFFF,
                )
                self.assertEqual((value.minimum, value.maximum), (-10, -1))
                self.assertEqual(value.initial_value, 0 if routine else -1)
                if not routine:
                    self.assertEqual(value.displays[0].press, -1)
                self.assertEqual(value.test.record, bytes(row))

    def test_routine_scalar_button_assembly_retains_signed32_value(self):
        selected = profile(
            {71: [bytes(modern(routine=True))], 72: [], 73: [variable_display(12)]},
            variables=(b"\xff" * 4, b"\x80\0\0\0"),
        )
        result = ActiveTestCatalog(selected).initialize(
            "routine",
            1,
            support=ActiveSupport(
                panel=lambda *_: False, routine_probe=lambda *_: False
            ),
        )
        self.assertEqual(
            (result.displays[0].press, result.displays[0].release), (-1, -0x80000000)
        )

    def test_legacy_modes_joins_and_full_controls(self):
        for family in ("p3", "dk", "p4"):
            row = legacy()
            row[84], row[89], row[85] = 1, 3, 7
            freeze = []
            for key in (9, 10, 11):
                item = bytearray(84)
                put(item, 56, key)
                freeze.append(bytes(item))
            calls = []
            selected = profile({11: [bytes(row)], 10: freeze})
            init = ActiveTestCatalog(selected).initialize(
                family,
                1,
                support=ActiveSupport(panel=lambda ref, mode: ref == 17 and mode == 1),
                read_value=lambda kind, item, calls=calls: (
                    calls.append((kind, struct.unpack_from("<H", item, 56)[0]))
                    or 100 + struct.unpack_from("<H", item, 56)[0]
                ),
            )
            self.assertEqual(
                (init.initial_value, init.minimum, init.maximum), (109, 111, 110)
            )
            self.assertEqual(
                [kind for kind, _ in calls], ["p4" if family == "p4" else "p3"] * 3
            )
            self.assertEqual(init.test.short_name, "Test")
            self.assertEqual(init.unit, "label-8")
            self.assertEqual(init.unit_function, 9)
            self.assertEqual(
                init.controls,
                {
                    "pattern": 7,
                    "key_operation_pattern": 2,
                    "key_invalid_flag": 1,
                    "maintenance_time": 20,
                    "auto_continue_time": 30,
                    "button_size": 5,
                    "lock_time": 40,
                },
            )
            self.assertEqual(
                (
                    init.displays[0].press,
                    init.displays[0].release,
                    init.displays[0].enabled,
                ),
                (-1, 5, True),
            )
            self.assertEqual(init.report()["physical"]["multiplier"], -2)
            self.assertEqual(
                init.text_ids,
                {"caution": 5, "help": 3, "prohibition": 6, "info": 4, "comment": 2},
            )

    def test_legacy_shortname_is_bounded_byte_cstring_not_utf16(self):
        for prefix, expected in (
            (b"T\0e\0s\0t\0", "T"),
            (b"\x80\0", None),
            (b"\0", ""),
        ):
            row = legacy()
            row[:20] = prefix.ljust(20, b"\0")
            test = ActiveTestCatalog(profile({11: [bytes(row)]})).list(
                "p3", support=ActiveSupport(legacy=lambda *_: True)
            )[0]
            self.assertEqual(test.short_name, expected)
            self.assertEqual(test.short_name_bytes, prefix.split(b"\0", 1)[0])
        row = legacy()
        row[:20] = b"A" * 20
        with self.assertRaises(ToyotaCodecError):
            ActiveTestCatalog(profile({11: [bytes(row)]})).list(
                "p3", support=ActiveSupport(legacy=lambda *_: True)
            )

    def test_v12_display_has_word_values_and_distinct_group_support_offsets(self):
        display = bytearray(20)
        put(display, 0, 9, "I")
        for offset, value in ((4, 4), (10, 65535), (12, 7), (14, 17)):
            put(display, offset, value)
        display[18] = 1
        for family in ("p3", "dk", "p4", "p5"):
            modern_family = family == "p5"
            selected = profile(
                {
                    68 if modern_family else 11: [
                        bytes(modern() if modern_family else legacy())
                    ],
                    14: [bytes(display)],
                }
            )
            selected = replace(
                selected, database=replace(selected.database, version=0x0100030C)
            )
            seen = []
            result = ActiveTestCatalog(selected).initialize(
                family,
                1,
                support=ActiveSupport(
                    panel=lambda ref, mode, seen=seen: seen.append((ref, mode)) or True,
                    pid=lambda _: False,
                ),
            )
            self.assertEqual(
                (
                    result.displays[0].identifier,
                    result.displays[0].press,
                    result.displays[0].release,
                ),
                (4, 65535, 7),
            )
            self.assertEqual(seen, [(17, 1)])
        selected = replace(
            selected, database=replace(selected.database, version=0x01000225)
        )
        with self.assertRaisesRegex(ValueError, "layouts"):
            ActiveTestCatalog(selected)

    def test_native_unavailable_read_keeps_constants_but_disabled_initial_zero(self):
        row = legacy()
        row[89] = 3
        freezes = []
        for key in (10, 11):
            item = bytearray(84)
            put(item, 56, key)
            freezes.append(bytes(item))
        host = ActiveTestCatalog(profile({11: [bytes(row)], 10: freezes}))
        init = host.initialize(
            "p3",
            1,
            support=ActiveSupport(panel=lambda *_: False),
            read_value=lambda *_: None,
        )
        self.assertEqual((init.initial_value, init.minimum, init.maximum), (0, 33, 22))
        self.assertFalse(init.displays[0].enabled)

    def test_missing_read_provider_or_selected_read_record_fails(self):
        row = legacy()
        row[84] = 1
        host = ActiveTestCatalog(profile({11: [bytes(row)]}))
        with self.assertRaises(ToyotaCodecError):
            host.initialize("p3", 1, support=ActiveSupport())
        item = bytearray(84)
        put(item, 56, 9)
        host = ActiveTestCatalog(profile({11: [bytes(row)], 10: [bytes(item)]}))
        with self.assertRaisesRegex(ValueError, "read provider"):
            host.initialize("p3", 1, support=ActiveSupport())

    def test_cancel_deadline_and_provider_type_errors_are_never_fallback(self):
        row = modern()
        row[57] = 0
        host = ActiveTestCatalog(profile({68: [bytes(row)]}))
        for failure in (Cancelled("cancel"), SessionError("deadline")):

            def fail(*args, failure=failure):
                raise failure

            with self.assertRaises(type(failure)):
                host.initialize("p5", 1, support=ActiveSupport(), read_value=fail)
        with self.assertRaises(ValueError):
            host.initialize(
                "p5", 1, support=ActiveSupport(), read_value=lambda *_: True
            )

    def test_p5_initial_and_auto_current_pid_exact_join(self):
        row = modern()
        row[57], row[61] = 0, 0
        put(row, 40, 5)
        put(row, 42, 7)
        monitors = []
        for key in (7000, 6000):
            monitor = bytearray(64)
            put(monitor, 32, 0x40, "I")
            for offset, value in ((36, key), (44, 5), (46, 7), (54, 123)):
                put(monitor, offset, value)
            monitors.append(bytes(monitor))
        # Native chooses first matching non-reserved PID, in selected order.
        monitors.reverse()
        seen = []
        init = ActiveTestCatalog(profile({68: [bytes(row)], 62: monitors})).initialize(
            "p5",
            1,
            support=ActiveSupport(
                panel=lambda *_: True, pid=lambda pid: seen.append(pid) or False
            ),
            read_value=lambda kind, item: 99,
        )
        self.assertEqual((init.initial_value, init.minimum, init.maximum), (99, 33, 22))
        self.assertEqual(seen, [6000])
        self.assertEqual(init.current_value_pid, 6000)
        self.assertFalse(init.current_value_supported)
        self.assertEqual(init.test.short_name, "")

    def test_p5_missing_pid_support_never_defaults_true(self):
        host = ActiveTestCatalog(profile({68: [bytes(modern())]}))
        with self.assertRaisesRegex(ValueError, "support provider"):
            host.initialize("p5", 1, support=ActiveSupport(panel=lambda *_: True))

    def test_invalid_modes_fail_and_first_selected_row_is_consumed(self):
        row = legacy()
        row[84] = 2
        with self.assertRaises(ToyotaCodecError):
            ActiveTestCatalog(profile({11: [bytes(row)]})).initialize(
                "p3", 1, support=ActiveSupport()
            )
        first, second = legacy(), legacy()
        put(second, 24, 999, "I")
        init = ActiveTestCatalog(
            profile({11: [bytes(first), bytes(second)]})
        ).initialize("p3", 1, support=ActiveSupport(panel=lambda *_: True))
        self.assertEqual(init.minimum, 33)

    def test_routine_all_groups_variables_support_and_final_group_length(self):
        row = modern(routine=True)
        status = struct.pack("<HHHHBBH", 30, 1, 1, 0, 0, 0, 0)
        gates = []
        init = ActiveTestCatalog(
            profile(
                {
                    71: [bytes(row)],
                    73: [
                        variable_display(10),
                        variable_display(11),
                        variable_display(12, ref=2),
                    ],
                    72: [status],
                }
            )
        ).initialize(
            "routine",
            1,
            support=ActiveSupport(
                panel=lambda ref, mode: gates.append((ref, mode)) or True,
                routine_probe=lambda rid, size: gates.append((rid, size)) or True,
            ),
        )
        self.assertEqual(gates, [(17, 1), (123, 1)])
        self.assertFalse(init.routine_labels[0].enabled)
        self.assertTrue(init.routine_inputs[0].enabled)
        self.assertFalse(init.routine_buttons[0].enabled)
        self.assertEqual(init.routine_buttons[0].press, b"\x33")
        self.assertEqual(init.display_data_length, 1)
        self.assertTrue(init.routine_status_supported)
        self.assertEqual(init.completion_patterns, (b"\x11\x22",))
        self.assertEqual(init.failure_patterns, ())
        self.assertEqual((init.initial_value, init.minimum, init.maximum), (0, 22, 11))

    def test_v12_routine60_has_shifted_dependencies_and_normal_rid_path(self):
        row = bytearray(60)
        for offset, value in (
            (0, 11),
            (4, 22),
            (8, 1),
            (12, 2),
            (16, 3),
            (20, 4),
            (24, 5),
        ):
            put(row, offset, value, "I")
        for offset, value in (
            (28, 123),
            (30, 1),
            (32, 2),
            (34, 3),
            (36, 42),
            (38, 1),
            (40, 2),
            (42, 1),
            (44, 30),
            (46, 31),
            (48, 10),
            (50, 11),
            (52, 12),
            (54, 4),
        ):
            put(row, offset, value)
        row[58] = 1
        selected = profile(
            {
                71: [bytes(row)],
                73: [variable_display(10), variable_display(11), variable_display(12)],
            },
            subaru=True,
        )
        selected = replace(
            selected, database=replace(selected.database, version=0x0100030C)
        )
        host = ActiveTestCatalog(selected)
        support = host.observed_support(
            "routine",
            protocol=3,
            pid_lengths={},
            did_lengths={},
            enabled_dids=(),
            enabled_rids=(),
            check_bits=lambda *_: False,
            exchange=lambda _: b"",
            routine_probe=lambda *_: False,
        )
        listed = host.list("routine", support=support)
        self.assertEqual([(item.signal_id, item.order) for item in listed], [(1, 4)])
        result = host.initialize("routine", 1, support=support)
        self.assertEqual(
            (result.minimum, result.maximum, result.routine_spec_id), (22, 11, 42)
        )
        self.assertEqual(
            (result.command, result.output_mask, result.button_mask),
            (b"\x11\x22", b"\x33", b"\x11\x22"),
        )
        self.assertEqual(len(result.routine_labels), 1)
        self.assertEqual(len(result.routine_inputs), 1)
        self.assertEqual(len(result.routine_buttons), 1)

    def test_routine_missing_variable_group_and_malformed_reference_fail(self):
        row = modern(routine=True)
        with self.assertRaises(ToyotaCodecError):
            ActiveTestCatalog(profile({71: [bytes(row)]})).initialize(
                "routine", 1, support=ActiveSupport()
            )
        with self.assertRaises(ValueError):
            ActiveTestCatalog(
                profile({71: [bytes(row)], 73: [variable_display(10, ref=42)]})
            ).initialize("routine", 1, support=ActiveSupport())


class ListTests(unittest.TestCase):
    def test_legacy_list_keeps_selected_order_and_explicit_support(self):
        host = ActiveTestCatalog(profile({11: [bytes(legacy(1)), bytes(legacy(2))]}))
        for family in ("p3", "dk", "old_body"):
            self.assertEqual(
                [
                    test.signal_id
                    for test in host.list(
                        family,
                        support=ActiveSupport(
                            legacy=lambda selected, row, family=family: (
                                selected == family and row[56] == 2
                            )
                        ),
                    )
                ],
                [2],
            )
        with self.assertRaises(ValueError):
            host.list("p3", support=ActiveSupport())

    def test_p4_multidid_optional_missing_required_and_all_optional_failures(self):
        rows = [bytes(legacy(key)) for key in (1, 2, 3)]
        links = [multi(1, 2, optional=True), multi(1, 3, order=2)]
        host = ActiveTestCatalog(profile({11: rows, 33: links}))
        result = host.list(
            "p4", support=ActiveSupport(legacy=lambda _, row: row[56] == 3)
        )
        self.assertEqual([test.signal_id for test in result], [1])
        self.assertEqual(
            host.list("p4", support=ActiveSupport(legacy=lambda *_: False)), ()
        )
        links[1] = multi(1, 3, order=2, optional=True)
        self.assertEqual(
            ActiveTestCatalog(profile({11: rows, 33: links})).list(
                "p4", support=ActiveSupport(legacy=lambda *_: False)
            ),
            (),
        )

    def test_p4_special_pattern_requires_two_independent_bit_checks(self):
        for pattern in (20, 21, 22, 23):
            for first, second in (
                (False, False),
                (True, False),
                (False, True),
                (True, True),
            ):
                row = legacy()
                row[85], row[82] = pattern, 8
                put(row, 66, 19)
                calls = []

                def bit(ident, start, end, calls=calls, first=first, second=second):
                    calls.append((ident, start, end))
                    return first if start == 16 else second

                found = ActiveTestCatalog(profile({11: [bytes(row)]})).list(
                    "p4", support=ActiveSupport(legacy=lambda *_: True, bit=bit)
                )
                self.assertEqual(
                    bool(found),
                    (not (first and second))
                    if pattern in (20, 21)
                    else first and second,
                )
                self.assertEqual(calls, [(8, 16, 23), (8, 24, 31)])

    def test_p4_support_range_wraps_native_ushort(self):
        row = legacy()
        row[85] = 22
        put(row, 66, 65535)
        seen = []
        found = ActiveTestCatalog(profile({11: [bytes(row)]})).list(
            "p4",
            support=ActiveSupport(
                legacy=lambda *_: True,
                bit=lambda pid, begin, end: seen.append((begin, end)) or True,
            ),
        )
        self.assertTrue(found)
        self.assertEqual(seen, [(65528, 65535), (0, 7)])

    def test_p5_combines_normal_routine_orders_and_multidid(self):
        normal, child, routine = modern(1), modern(2), modern(3, routine=True)
        host = ActiveTestCatalog(
            profile(
                {
                    68: [bytes(normal), bytes(child)],
                    71: [bytes(routine)],
                    33: [multi(1, 2)],
                }
            )
        )
        got = host.list(
            "p5",
            support=ActiveSupport(
                did=lambda key: key in (1, 2), rid=lambda key: key == 3
            ),
        )
        self.assertEqual(
            [(test.signal_id, test.routine) for test in got], [(3, True), (1, False)]
        )
        self.assertEqual(
            host.list(
                "p5",
                support=ActiveSupport(did=lambda key: key == 1, rid=lambda _: False),
            ),
            (),
        )

    def test_p5_native_pairwise_sort_is_not_stable_for_equal_orders(self):
        rows = []
        for key, order in ((1, 2), (2, 2), (3, 1)):
            row = modern(key)
            put(row, 44, order)
            rows.append(bytes(row))
        found = ActiveTestCatalog(profile({68: rows})).list(
            "p5", support=ActiveSupport(did=lambda _: True)
        )
        self.assertEqual([item.signal_id for item in found], [3, 2, 1])

    def test_subaru_uses_distinct_gates_and_never_normal_gate(self):
        host = ActiveTestCatalog(
            profile({68: [bytes(modern())], 71: [bytes(modern(2, True))]}, subaru=True)
        )
        got = host.list(
            "p5",
            support=ActiveSupport(
                did_subaru=lambda _: True, rid_subaru=lambda _: False
            ),
        )
        self.assertEqual([test.signal_id for test in got], [1])
        with self.assertRaises(ValueError):
            host.list(
                "p5", support=ActiveSupport(did=lambda _: True, rid=lambda _: True)
            )

    def test_sa_finalization_only_after_nonempty_list_and_fault_propagates(self):
        host = ActiveTestCatalog(profile({11: [bytes(legacy())]}))
        self.assertEqual(
            host.list("sa", support=ActiveSupport(legacy=lambda *_: False)), ()
        )
        with self.assertRaisesRegex(ValueError, "finalization"):
            host.list("sa", support=ActiveSupport(legacy=lambda *_: True))

        def fail():
            raise Cancelled("cancel")

        with self.assertRaises(Cancelled):
            host.list(
                "sa", support=ActiveSupport(legacy=lambda *_: True, sa_finalize=fail)
            )


class BoundSupportTests(unittest.TestCase):
    def bind(
        self,
        host,
        family,
        *,
        exchange=lambda request: b"",
        enabled_dids=(),
        enabled_rids=(),
    ):
        return host.observed_support(
            family,
            protocol=3,
            pid_lengths={},
            did_lengths={},
            enabled_dids=enabled_dids,
            enabled_rids=enabled_rids,
            check_bits=lambda *_: False,
            exchange=exchange,
            pid_support=lambda _: False,
            routine_probe=lambda *_: False,
        )

    def test_native_legacy_modes_no_invented_support_or_io(self):
        first, second = legacy(1), legacy(2)
        second[83] = 0
        host = ActiveTestCatalog(profile({11: [bytes(first), bytes(second)]}))
        support = self.bind(host, "p3")
        self.assertEqual(
            [item.signal_id for item in host.list("p3", support=support)], [1]
        )
        self.assertTrue(host.initialize("p3", 1, support=support).displays[0].enabled)
        self.assertEqual(
            [item.signal_id for item in host.list("p4", support=self.bind(host, "p4"))],
            [1],
        )

    def test_p4_panel_retains_membership_but_p3_uses_old_body_path(self):
        row = legacy()
        display = bytearray(dependencies()[14][0])
        put(display, 18, 17)
        display[22] = 0
        bit = bytearray(12)
        for offset, value in ((0, 17), (2, 1), (6, 0), (8, 0)):
            put(bit, offset, value)
        bit[10] = 2
        host = ActiveTestCatalog(
            profile(
                {11: [bytes(row)], 14: [bytes(display)], 9: [bytes(bit)]},
                variables=(b"\x08",),
            )
        )
        with patch.object(
            VehicleProfile, "command_frames", lambda *_: (CommandFrame(b"\x21\x00"),)
        ):
            legacy_init = host.initialize(
                "p3",
                1,
                support=self.bind(host, "p3", exchange=lambda _: b"\x61\x08\x80"),
            )
            p4_init = host.initialize(
                "p4",
                1,
                support=self.bind(host, "p4", exchange=lambda _: b"\x61\x08\x80"),
            )
        self.assertTrue(legacy_init.displays[0].enabled)
        self.assertFalse(p4_init.displays[0].enabled)

    def test_p5_protocol21_uses_observed_length_not_missing_cache_quirk(self):
        action = modern()
        put(action, 42, 15)
        host = ActiveTestCatalog(profile({68: [bytes(action)]}))
        support = host.observed_support(
            "p5",
            protocol=21,
            pid_lengths={},
            did_lengths={123: 1},
            enabled_dids=(123,),
            enabled_rids=(),
            check_bits=lambda *_: False,
            exchange=lambda _: b"",
        )
        self.assertEqual(host.list("p5", support=support), ())

    def test_bound_initial_reader_executes_selected_legacy_p5_and_fault_policy(self):
        action = legacy()
        action[84] = 1
        freeze = bytearray(84)
        for offset, value in ((56, 9), (60, 2), (62, 0), (64, 7)):
            put(freeze, offset, value)
        freeze[79] = 8
        host = ActiveTestCatalog(
            profile({11: [bytes(action)], 10: [bytes(freeze)], 68: [bytes(modern())]})
        )
        requests = []
        replies = [
            b"\x61\x08\x10",
            b"\x61\x08\x10",
            b"\x62\x00\x7b\x80",
            NativeStatus(77),
        ]

        def exchange(ecu, request):
            requests.append(request)
            response = replies.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

        session = ToyotaSession(exchange, "authored", {})
        with patch.object(
            VehicleProfile,
            "frame_records",
            lambda _, ident: (
                SimpleNamespace(
                    frame=CommandFrame(
                        b"\x22\x00\x00" if ident == 0xCA else b"\x21\x00"
                    ),
                    provenance="authored-selected",
                ),
            ),
        ):
            reader = host.initial_value_reader(session, positions={8: b"\x01"})
            self.assertEqual(reader("p3", bytes(freeze)), 0xFFFFFFF0)
            self.assertEqual(reader("p4", bytes(freeze)), 0xFFFFFFF0)
            self.assertEqual(reader("p5-active", bytes(modern())), 1)
            self.assertIsNone(reader("p3", bytes(freeze)))
            self.assertEqual(len(session.trace), 4)
            self.assertEqual(session.trace[-1]["native_status"], 77)
            with self.assertRaises(ValueError):
                host.initial_value_reader(session, positions={})("p4", bytes(freeze))
        self.assertEqual(
            requests, [b"\x21\x08", b"\x21\x08", b"\x22\x00\x7b", b"\x21\x08"]
        )

    def test_missing_initial_function_is_native_unavailable_not_synthetic_read(self):
        host = ActiveTestCatalog(profile({68: [bytes(modern())]}))
        session = ToyotaSession(
            lambda *_: self.fail("Absent function must not exchange"), "authored", {}
        )
        self.assertIsNone(
            host.initial_value_reader(session, positions={})(
                "p5-active", bytes(modern())
            )
        )
        self.assertEqual(session.trace, [])

    def test_initial_duplicate_templates_preserve_constant_without_io(self):
        row = modern()
        row[57] = 0
        host = ActiveTestCatalog(profile({68: [bytes(row)]}))

        def unexpected(ecu, request):
            self.fail("Duplicate native read templates must not perform I/O")

        session = ToyotaSession(unexpected, "authored", {})
        selected = SimpleNamespace(
            frame=CommandFrame(b"\x22\x00\x00"), provenance="authored"
        )
        for records in (
            (selected, selected),
            (SimpleNamespace(frame=CommandFrame(b""), provenance="authored"),),
            (SimpleNamespace(frame=CommandFrame(b"\x22"), provenance="authored"),),
        ):
            with patch.object(
                VehicleProfile, "frame_records", lambda *_, records=records: records
            ):
                result = host.initialize(
                    "p5",
                    1,
                    support=ActiveSupport(panel=lambda *_: True, pid=lambda _: False),
                    read_value=host.initial_value_reader(session, positions={}),
                )
            self.assertEqual(result.initial_value, 11)
            self.assertEqual(session.trace, [])

    def test_native_p5_selected_ca_read_and_cache(self):
        action = modern()
        data = bytearray(12)
        put(data, 2, 123)
        host = ActiveTestCatalog(profile({68: [bytes(action)], 67: [bytes(data)]}))
        calls = []
        with patch.object(
            VehicleProfile,
            "command_frames",
            lambda *_: (CommandFrame(b"\x22\x00\x00"),),
        ):
            support = self.bind(
                host,
                "p5",
                exchange=lambda request: calls.append(request) or b"\x62\x00\x7b\x01",
                enabled_dids=(123,),
            )
            for _ in range(2):
                self.assertEqual(
                    [item.signal_id for item in host.list("p5", support=support)], [1]
                )
        self.assertEqual(calls, [b"\x22\x00\x7b"])
        denied = self.bind(host, "p5")
        self.assertEqual(host.list("p5", support=denied), ())

    def test_native_subaru_uses_reference_gate_and_normal_rid_membership(self):
        action, routine = modern(), modern(2, True)
        host = ActiveTestCatalog(
            profile({68: [bytes(action)], 71: [bytes(routine)]}, subaru=True)
        )
        # Native Subaru ref0 is explicitly available even without an observed DID.
        found = host.list("p5", support=self.bind(host, "p5"))
        self.assertEqual([item.signal_id for item in found], [2, 1])
        ordinary = ActiveTestCatalog(profile({71: [bytes(routine)]}))
        self.assertEqual(
            ordinary.list("routine", support=self.bind(ordinary, "routine")), ()
        )
        self.assertEqual(
            [
                item.signal_id
                for item in ordinary.list(
                    "routine",
                    support=self.bind(ordinary, "routine", enabled_rids=(123,)),
                )
            ],
            [2],
        )

    def test_routine_command_refs_and_scalar_button_shift_wrapping(self):
        row = modern(routine=True)
        for offset, ref in ((40, 1), (42, 2), (44, 1)):
            put(row, offset, ref)
        host = ActiveTestCatalog(
            profile(
                {
                    71: [bytes(row)],
                    73: [
                        variable_display(10),
                        variable_display(11),
                        variable_display(12),
                    ],
                },
                variables=(b"\x01\x02\x03\x04\x05", b"\x06"),
            )
        )
        result = host.initialize(
            "routine",
            1,
            support=ActiveSupport(
                panel=lambda *_: False, routine_probe=lambda *_: False
            ),
        )
        self.assertEqual(result.command, b"\x01\x02\x03\x04\x05")
        self.assertEqual(result.output_mask, b"\x06")
        self.assertEqual(result.button_mask, result.command)
        self.assertEqual(result.displays[0].press, 0x02030405 | 1)

    def test_empty_group_success_is_distinct_from_absent_table(self):
        selected = profile({71: [bytes(modern(routine=True))], 73: []})
        result = ActiveTestCatalog(selected).initialize(
            "routine", 1, support=ActiveSupport(routine_probe=lambda *_: False)
        )
        self.assertEqual(result.routine_labels, ())
        self.assertEqual(result.display_data_length, 0)
        broken = replace(
            selected,
            database=replace(
                selected.database,
                sections={
                    key: value
                    for key, value in selected.database.sections.items()
                    if key != 12
                },
            ),
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            ActiveTestCatalog(broken).initialize("routine", 1, support=ActiveSupport())
        self.assertEqual(caught.exception.code, 0xA0030107)


class SAFinalizerTests(unittest.TestCase):
    def test_authored_key_math_all_uint16_boundaries(self):
        material = SAKeyMaterial(0x1234, 0x4321)
        for seed in (0, 1, 2, 3, 4, 255, 256, 32767, 32768, 65535):
            shifted = ((seed ^ 0x1234) // 4) & 65535
            rotated = shifted + (3 - seed % 4) * 16384
            expected = (((rotated - 0x4321) % (2**32)) // 8) % 8192 + (
                (rotated - 1) % 8
            ) * 8192
            self.assertEqual(material.derive(seed), expected)
        with self.assertRaises(ValueError):
            material.derive(65536)
        self.assertNotIn("4660", repr(material))

    def test_unrecognized_library_fails_before_any_exchange(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "authored.dll"
            source.write_bytes(bytes(57344))
            with self.assertRaises(ValueError):
                SAKeyMaterial.from_library(str(source))

    def run_finalizer(self, replies, frames=None, session_kwargs=None):
        requests = []

        def exchange(ecu, request):
            requests.append(request)
            reply = replies.pop(0)
            if isinstance(reply, BaseException):
                raise reply
            return reply

        session = ToyotaSession(exchange, "authored", {}, **(session_kwargs or {}))
        frames = frames or {
            0xEB: (CommandFrame(b"\x27\x01"),),
            0xEC: (CommandFrame(b"\x27\x02\x00\x00"),),
        }
        with patch.object(
            VehicleProfile, "command_frames", lambda _, ident: frames[ident]
        ):
            SAFinalizer(profile(), session, SAKeyMaterial(0x1234, 0x4321))()
        return requests, session

    def test_actual_two_step_exchange_and_no_key_trace(self):
        requests, session = self.run_finalizer([b"\x67\x01\x00\x01", b"\x67\x02"])
        self.assertEqual(
            requests,
            [
                b"\x27\x01",
                b"\x27\x02"
                + SAKeyMaterial(0x1234, 0x4321).derive(1).to_bytes(2, "big"),
            ],
        )
        self.assertEqual(session.trace, [])

    def test_zero_seed_short_reply_and_native_fault_are_nonfatal(self):
        for reply in (b"\x67\x01\x00\x00", b"\x67\x01\x01", NativeStatus(77)):
            requests, _ = self.run_finalizer([reply])
            self.assertEqual(requests, [b"\x27\x01"])
        requests, _ = self.run_finalizer([b"\x67\x01\x00\x01", NativeStatus(77)])
        self.assertEqual(len(requests), 2)

    def test_sa_ec_dependency_only_after_nonzero_seed(self):
        frames = {0xEB: (CommandFrame(b"\x27\x01"),)}
        for reply in (b"\x67\x01\x00\x00", b"\x67\x01", NativeStatus(77)):
            requests, _ = self.run_finalizer([reply], frames=frames)
            self.assertEqual(requests, [b"\x27\x01"])
        with self.assertRaises(KeyError):
            self.run_finalizer([b"\x67\x01\x00\x01"], frames=frames)

    def test_preflight_deadline_cancel_and_budget(self):
        with self.assertRaises(ToyotaCodecError):
            self.run_finalizer([], frames={0xEB: (), 0xEC: ()})
        with self.assertRaises(Cancelled):
            self.run_finalizer([], session_kwargs={"cancelled": lambda: True})
        with self.assertRaises(SessionError):
            self.run_finalizer(
                [b"\x67\x01\x00\x01"], session_kwargs={"limits": Limits(exchanges=1)}
            )
        times = iter((0, 0, 2))
        with self.assertRaises(SessionError):
            self.run_finalizer(
                [NativeStatus(77)],
                session_kwargs={
                    "limits": Limits(seconds=1),
                    "clock": lambda: next(times),
                },
            )
