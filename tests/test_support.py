import struct
import unittest
from dataclasses import replace

from scripts.diagnostic_db import Database, Section
from scripts.support import (
    ExceptionContext,
    ExceptionResolver,
    PidBit,
    check_pid_support,
    correspondence_rows,
    exception_matches,
)
from scripts.toyota import CommandFrame, ToyotaCodecError, VariableTable


def database(kind, slot, width, rows):
    return Database(
        kind,
        0x0100032F,
        "synthetic",
        {slot: Section(slot, 0, len(rows), False, b"".join(rows))},
    )


def bit_row(key, exception=0, flag=0):
    row = bytearray(12)
    struct.pack_into("<HHHHH", row, 0, key, 1, exception, 0, 7)
    row[10], row[11] = flag, 2
    return bytes(row)


class CorrespondenceTests(unittest.TestCase):
    def test_freeze_pid_unsigned_key_and_native_exception_fields_both_versions(self):
        first, last = bytearray(8), bytearray(8)
        first[4:6], last[4:6] = b"\x80\x11", b"\xff\x22"
        replacement = bytearray(first)
        struct.pack_into("<H", replacement, 0, 9)
        replacement[5:7] = b"\x33\x02"
        deletion = bytearray(last)
        struct.pack_into("<H", deletion, 0, 10)
        deletion[6] = 1
        for version in (0x0100030C, 0x0100032F):
            db = replace(
                database(
                    2,
                    20,
                    8,
                    (bytes(first), bytes(last), bytes(replacement), bytes(deletion)),
                ),
                version=version,
            )
            self.assertEqual(correspondence_rows(db, 20), (bytes(first), bytes(last)))
            self.assertEqual(
                correspondence_rows(db, 20, (9, 10)), (bytes(replacement),)
            )
        with self.assertRaisesRegex(ValueError, "No recovered selection schema"):
            correspondence_rows(replace(db, version=0), 20)

    def test_work_factor_native_keys_exceptions_and_version_factory(self):
        for slot, width, key_fields, exception, flag in (
            (37, 20, ((8, "H", 7), (10, "H", 9)), 14, 16),
            (114, 24, ((16, "H", 7),), 20, 22),
            (115, 20, ((4, "H", 7), (18, "B", 9)), 14, 19),
            (116, 16, ((8, "H", 7), (10, "H", 9)), 12, 14),
            (117, 16, ((14, "B", 7),), 10, 15),
        ):
            original = bytearray(width)
            for offset, fmt, value in key_fields:
                struct.pack_into("<" + fmt, original, offset, value)
            changed = bytearray(original)
            struct.pack_into("<I", changed, 0, 1234)
            struct.pack_into("<H", changed, exception, 9)
            changed[flag] = 2
            replacement = bytes(changed)
            db = database(2, slot, width, (bytes(original), bytes(changed)))
            self.assertEqual(correspondence_rows(db, slot), (bytes(original),))
            self.assertEqual(correspondence_rows(db, slot, (9,)), (bytes(changed),))
            changed[flag] = 1
            deleted = database(2, slot, width, (bytes(original), bytes(changed)))
            self.assertEqual(correspondence_rows(deleted, slot, (9,)), ())
            old = replace(db, version=0x0100030C)
            if slot == 37:
                self.assertEqual(correspondence_rows(old, slot, (9,)), (replacement,))
            else:
                with self.assertRaisesRegex(ValueError, "version 12 factory"):
                    correspondence_rows(old, slot)

    def test_rob_data_id_has_distinct_original_flag_offsets(self):
        for version, flag_offset, other_offset in (
            (0x0100030C, 5, 7),
            (0x0100032F, 7, 5),
        ):
            original = bytearray(8)
            struct.pack_into("<H", original, 2, 0x8001)
            original[other_offset] = 0xA5
            changed = bytearray(original)
            struct.pack_into("<H", changed, 0, 9)
            changed[4] = 0x33
            changed[flag_offset] = 2
            db = replace(
                database(2, 90, 8, (bytes(original), bytes(changed))), version=version
            )
            self.assertEqual(correspondence_rows(db, 90, (9,)), (bytes(changed),))
            changed[flag_offset] = 1
            db = replace(
                db, sections={90: Section(90, 0, 2, False, bytes(original + changed))}
            )
            self.assertEqual(correspondence_rows(db, 90, (9,)), ())

    def test_ddr_native_layouts_and_versioned_trigger_banks(self):
        for version in (0x0100030C, 0x0100032F):
            for slot, width, keys, exc, flag in (
                (50, 48, ((24, "H", 7),), 40, 45),
                (
                    51,
                    32 if version == 0x0100030C else 36,
                    (
                        (26 if version == 0x0100030C else 30, "B", 7),
                        (27 if version == 0x0100030C else 31, "B", 8),
                    ),
                    24 if version == 0x0100030C else 28,
                    28 if version == 0x0100030C else 32,
                ),
                (52, 16, ((10, "B", 7), (11, "B", 8), (4, "H", 9)), 8, 12),
                (53, 16, ((4, "H", 7), (8, "H", 8)), 10, 14),
            ):
                row = bytearray(width)
                for offset, fmt, key in keys:
                    struct.pack_into("<" + fmt, row, offset, key)
                overlay = bytearray(row)
                struct.pack_into("<I", overlay, 0, 99)
                struct.pack_into("<H", overlay, exc, 9)
                overlay[flag] = 2
                db = replace(database(2, slot, width, [row, overlay]), version=version)
                self.assertEqual(correspondence_rows(db, slot, (9,)), (bytes(overlay),))
        with self.assertRaisesRegex(ValueError, "version 12 factory"):
            correspondence_rows(
                replace(database(2, 105, 36, []), version=0x0100030C), 105
            )

    def test_monitor_did_bit_has_different_old_width_and_flag(self):
        for version, width, flag in ((0x0100030C, 12, 10), (0x0100032F, 16, 12)):
            row = bytearray(width)
            struct.pack_into("<H", row, 0, 7)
            overlay = bytearray(row)
            struct.pack_into("<H", overlay, 4, 9)
            overlay[flag] = 1
            db = replace(database(2, 63, width, [row, overlay]), version=version)
            self.assertEqual(correspondence_rows(db, 63), (bytes(row),))
            self.assertEqual(correspondence_rows(db, 63, (9,)), ())

    def test_custom_and_monitor_did_versioned_overlays(self):
        for version in (0x0100030C, 0x0100032F):
            for kind, slot, width, keys, exc, flag in (
                (
                    1,
                    20,
                    12,
                    ((8, "B", 7), (4, "H", 8)),
                    6,
                    9 if version == 0x0100030C else 10,
                ),
                (1, 19, 88, ((86, "B", 7), (80, "H", 8)), 82, 87),
                (1, 26, 24, ((8, "H", 7), (20, "H", 8)), 18, 23),
                (1, 21, 52, ((8, "H", 7), (10, "H", 8)), 36, 51),
                (1, 48, 24, ((0, "H", 7), (12, "H", 8)), 14, 22),
                (2, 61, 8, ((2, "H", 7),), 0, 7),
            ):
                row = bytearray(width)
                for offset, fmt, key in keys:
                    struct.pack_into("<" + fmt, row, offset, key)
                overlay = bytearray(row)
                struct.pack_into("<H", overlay, exc, 9)
                overlay[flag] = 1
                db = replace(
                    database(kind, slot, width, [row, overlay]), version=version
                )
                self.assertEqual(correspondence_rows(db, slot), (bytes(row),))
                self.assertEqual(correspondence_rows(db, slot, (9,)), ())

    def test_detail_and_p5_dtc_overlay_keys_keep_all_unsigned_dword_bits(self):
        for slot, width, offset, exception, flag in (
            (47, 20, 0, 14, 18),
            (65, 68, 44, 60, 66),
        ):
            low, high = bytearray(width), bytearray(width)
            struct.pack_into("<I", low, offset, 1)
            struct.pack_into("<I", high, offset, 0x80000001)
            overlay = bytearray(high)
            struct.pack_into("<H", overlay, exception, 9)
            overlay[flag] = 1
            for version in (0x0100030C, 0x0100032F):
                db = replace(
                    database(2, slot, width, [low, high, overlay]), version=version
                )
                self.assertEqual(correspondence_rows(db, slot, (9,)), (bytes(low),))

    def test_late_native_ecu_dynamic_and_p5_ddr_schemas(self):
        for slot, width, keys, exc, flag in (
            (38, 12, ((0, "H", 7),), 6, 9),
            (41, 92, ((80, "B", 7), (56, "H", 8)), 72, 85),
            (5, 28, ((20, "H", 7),), 22, 27),
            (81, 8, ((0, "H", 7),), 4, 6),
            (80, 12, ((0, "H", 7),), 4, 10),
            (89, 12, ((0, "H", 7),), 4, 10),
            (54, 8, ((2, "H", 7),), 0, 6),
            (47, 20, ((8, "H", 7), (0, "I", 0x80000001)), 14, 18),
            (65, 68, ((44, "I", 0x80000001),), 60, 66),
            (133, 44, ((32, "H", 7), (40, "B", 8), (41, "B", 9)), 34, 43),
            (134, 60, ((36, "H", 7),), 50, 58),
            (135, 24, ((8, "H", 7), (12, "H", 8)), 14, 18),
            (108, 8, ((0, "H", 7),), 4, 6),
            (109, 12, ((0, "H", 7), (8, "B", 8), (9, "B", 9)), 6, 10),
        ):
            row = bytearray(width)
            for offset, fmt, key in keys:
                struct.pack_into("<" + fmt, row, offset, key)
            overlay = bytearray(row)
            struct.pack_into("<H", overlay, exc, 9)
            overlay[flag] = 1
            db = database(2, slot, width, [row, overlay])
            self.assertEqual(correspondence_rows(db, slot), (bytes(row),))
            self.assertEqual(correspondence_rows(db, slot, (9,)), ())
            if slot not in (38, 41, 47, 65, 80, 89, 81, 54, 5):
                with self.assertRaisesRegex(ValueError, "version 12 factory"):
                    correspondence_rows(replace(db, version=0x0100030C), slot)
            else:
                self.assertEqual(
                    correspondence_rows(replace(db, version=0x0100030C), slot),
                    (bytes(row),),
                )

    def test_work_factor_p4_both_version_overlay_geometry(self):
        for version in (0x0100030C, 0x0100032F):
            for slot, width, key, exc, flag in (
                (35, 28, 4, 16, 26),
                (36, 40, 20, 32, 35),
            ):
                row = bytearray(width)
                struct.pack_into("<H", row, key, 7)
                if slot == 36:
                    row[34] = 0xFF
                overlay = bytearray(row)
                struct.pack_into("<H", overlay, exc, 9)
                overlay[flag] = 1
                db = replace(database(2, slot, width, [row, overlay]), version=version)
                self.assertEqual(correspondence_rows(db, slot), (bytes(row),))
                self.assertEqual(correspondence_rows(db, slot, (9,)), ())

    def test_diagcode_native_default_rows_keep_source_order(self):
        rows = []
        for key in (3, 1, 2):
            row = bytearray(28)
            struct.pack_into("<H", row, 20, key)
            rows.append(bytes(row))
        self.assertEqual(correspondence_rows(database(2, 5, 28, rows), 5), tuple(rows))

    def test_supfreeze_preserves_native_unsorted_default_frame_order(self):
        rows = [struct.pack("<HBB", 0, frame, 0) for frame in (3, 1, 2)]
        selected = correspondence_rows(database(2, 2, 4, rows), 2)
        self.assertEqual([row[2] for row in selected], [3, 1, 2])

    def test_selected_byte_key_supfreeze_pid_addition_and_carb_overlays(self):
        for kind, slot, width, key, exception, flag in (
            (2, 2, 4, 2, 0, 3),
            (2, 3, 8, 4, 0, 6),
            (2, 4, 8, 4, 0, 6),
            (2, 7, 8, 4, 0, 6),
            (2, 6, 8, 2, 0, 6),
            (2, 55, 8, 4, 2, 5),
            (1, 73, 12, 6, 4, 10),
        ):
            row = bytearray(width)
            row[key] = 0xF1
            overlay = bytearray(row)
            struct.pack_into("<H", overlay, exception, 9)
            overlay[flag] = 1
            db = database(kind, slot, width, [row, overlay])
            self.assertEqual(correspondence_rows(db, slot), (bytes(row),))
            self.assertEqual(correspondence_rows(db, slot, (9,)), ())

    def test_new_selected_table_keys_and_versioned_protocol(self):
        for kind, slot, width, first, second, exc, flag in (
            (1, 54, 44, 16, 30, 32, 42),
            (1, 25, 12, 4, 6, 8, 10),
            (1, 27, 24, 4, 6, 16, 22),
            (1, 62, 24, 0, 16, 18, 22),
            (1, 88, 36, 16, 26, 28, 35),
            (2, 26, 12, 0, 2, 6, 8),
            (2, 39, 20, 8, None, 14, 16),
            (2, 19, 8, 0, None, 4, 7),
            (2, 64, 20, 10, None, 16, 18),
            (2, 60, 8, 0, None, 4, 6),
        ):
            original = bytearray(width)
            struct.pack_into("<H", original, first, 7)
            if second is not None:
                struct.pack_into("<H", original, second, 8)
            overlay = bytearray(original)
            overlay[3] = 99
            # Keep both key fields identical for the replacement.
            struct.pack_into("<H", overlay, first, 7)
            if second is not None:
                struct.pack_into("<H", overlay, second, 8)
            struct.pack_into("<H", overlay, exc, 9)
            overlay[flag] = 2
            db = database(kind, slot, width, [original, overlay])
            self.assertEqual(correspondence_rows(db, slot, (9,)), (bytes(overlay),))
        for version, width, bus, flag in (
            (0x0100030C, 24, 22, 23),
            (0x0100032F, 28, 24, 25),
        ):
            row = bytearray(width)
            struct.pack_into("<H", row, 0, 42)
            row[bus] = 7
            overlay = bytearray(row)
            struct.pack_into("<H", overlay, 12, 9)
            overlay[flag] = 1
            db = replace(database(1, 13, width, [row, overlay]), version=version)
            self.assertEqual(correspondence_rows(db, 13), (bytes(row),))
            self.assertEqual(correspondence_rows(db, 13, (9,)), ())
        with self.assertRaisesRegex(ValueError, "version 12"):
            correspondence_rows(
                replace(database(1, 88, 36, []), version=0x0100030C), 88
            )
        with self.assertRaisesRegex(ValueError, "database version"):
            correspondence_rows(
                replace(database(1, 54, 44, []), version=0x01000225), 54
            )

    def test_defaults_delete_replace_insert_and_order(self):
        one, two = bit_row(1), bit_row(2)
        replacement = bit_row(2, 5, 2)
        addition = bit_row(3, 5, 2)
        removal = bit_row(1, 5, 1)
        db = database(2, 8, 12, [one, two, removal, replacement, addition])
        self.assertEqual(correspondence_rows(db, 8), (one, two))
        self.assertEqual(correspondence_rows(db, 8, (5,)), (replacement, addition))
        self.assertEqual(correspondence_rows(db, 8, (99,)), (one, two))

    def test_p5_action_overlay_uses_signal_key_not_target_did_or_rid(self):
        for slot, key_offset, target_offset, exception_offset, flag_offset in (
            (68, 32, 34, 46, 59),
            (71, 30, 28, 58, 61),
        ):
            original = bytearray(64)
            struct.pack_into("<H", original, key_offset, 7)
            struct.pack_into("<H", original, target_offset, 42)
            replacement = bytearray(original)
            struct.pack_into("<H", replacement, target_offset, 43)
            struct.pack_into("<H", replacement, exception_offset, 3)
            replacement[flag_offset] = 2
            selected = correspondence_rows(
                database(2, slot, 64, [bytes(original), bytes(replacement)]), slot, (3,)
            )
            self.assertEqual(selected, (bytes(replacement),))

    def test_active_did_mode_precedes_mask_ordinal_in_overlay_key(self):
        def row(mode, ordinal, exception=0, flag=0):
            return struct.pack("<5HBB", exception, 42, ordinal, 1, 8, mode, flag)

        unsorted_masks = [row(4, 16), row(4, 2)]
        self.assertEqual(
            correspondence_rows(database(2, 67, 12, unsorted_masks), 67),
            tuple(unsorted_masks),
        )
        originals = [row(1, 1), row(1, 2), row(3, 1)]
        removal = row(1, 2, 3, 1)
        selected = correspondence_rows(
            database(2, 67, 12, originals + [removal]), 67, (3,)
        )
        self.assertEqual(selected, (originals[0], originals[2]))

    def test_pattern_display_uses_unsigned_dword_within_pattern_group(self):
        def row(value, exception=0, flag=0):
            data = bytearray(24)
            struct.pack_into("<I", data, 4, value)
            struct.pack_into("<H", data, 12, 7)
            struct.pack_into("<H", data, 16, exception)
            data[23] = flag
            return bytes(data)

        low, high = row(1), row(0xFFFFFFFF)
        self.assertEqual(
            correspondence_rows(database(2, 14, 24, [high, low]), 14), (high, low)
        )
        self.assertEqual(
            correspondence_rows(
                database(2, 14, 24, [low, high, row(0xFFFFFFFF, 3, 1)]), 14, (3,)
            ),
            (low,),
        )

    def test_native_deletion_stops_after_first_duplicate(self):
        original = bit_row(1)
        removal = bit_row(1, 3, 1)
        self.assertEqual(
            correspondence_rows(
                database(2, 8, 12, [original] * 3 + [removal]), 8, (3,)
            ),
            (original, original),
        )

    def test_v12_pattern_schema_has_native_twenty_byte_layout(self):
        original = bytearray(20)
        struct.pack_into("<H", original, 4, 7)
        struct.pack_into("<H", original, 10, 0xFFFF)
        removal = bytearray(original)
        struct.pack_into("<H", removal, 8, 3)
        removal[19] = 1
        source = replace(
            database(2, 14, 20, [bytes(original), bytes(removal)]), version=0x0100030C
        )
        self.assertEqual(correspondence_rows(source, 14), (bytes(original),))
        self.assertEqual(correspondence_rows(source, 14, (3,)), ())

    def test_bad_order_width_and_id_fail(self):
        for rows in ([bit_row(2), bit_row(1)], [bit_row(1, 5), bit_row(1)]):
            with self.assertRaises(ValueError):
                correspondence_rows(database(2, 8, 12, rows), 8)
        with self.assertRaises(ValueError):
            correspondence_rows(database(2, 8, 12, [b"bad"]), 8)
        for value in (0, -1, True, 65536):
            with self.assertRaises(ValueError):
                correspondence_rows(database(2, 8, 12, []), 8, (value,))


class ExceptionTests(unittest.TestCase):
    def row(self):
        row = bytearray(36)
        row[:4], row[8:11] = b"ABCD", b"XYZ"
        struct.pack_into("<H", row, 14, 42)
        row[7], row[24], row[34] = 7, 8, 3
        row[25:31] = bytes((20, 10, 40, 30, 60, 50))
        row[31:34] = bytes((9, 10, 11))
        return row

    def context(self):
        return ExceptionContext(
            42, 3, b"ABCD-tail", b"XYZ-tail", 7, 8, 15, 35, 55, 9, 10, 11
        )

    def test_exact_prefix_equality_and_inclusive_reversed_ranges(self):
        row, context = self.row(), self.context()
        self.assertTrue(exception_matches(bytes(row), context))
        for value in (10, 20):
            self.assertTrue(
                exception_matches(bytes(row), replace(context, key_15=value))
            )
        for value in (9, 21):
            self.assertFalse(
                exception_matches(bytes(row), replace(context, key_15=value))
            )
        self.assertFalse(
            exception_matches(bytes(row), replace(context, identifier=b"ABC"))
        )
        self.assertFalse(
            exception_matches(bytes(row), replace(context, subidentifier=b"other"))
        )
        self.assertFalse(exception_matches(bytes(row), replace(context, category=43)))
        self.assertFalse(exception_matches(bytes(row), replace(context, variant=2)))

    def test_all_ten_mask_bits_ignore_only_their_own_comparison(self):
        context = self.context()
        for bit, changes in (
            (1, {"identifier": b""}),
            (2, {"subidentifier": b""}),
            (4, {"key_0c": 0}),
            (8, {"key_14": 0}),
            (16, {"key_15": 0}),
            (32, {"key_16": 0}),
            (64, {"key_17": 0}),
            (128, {"key_18": 0}),
            (256, {"key_19": 0}),
            (512, {"key_1a": 0}),
        ):
            with self.subTest(bit=bit):
                row = self.row()
                self.assertFalse(
                    exception_matches(bytes(row), replace(context, **changes))
                )
                struct.pack_into("<I", row, 16, bit)
                self.assertTrue(
                    exception_matches(bytes(row), replace(context, **changes))
                )
        with self.assertRaises(ValueError):
            exception_matches(b"", context)
        with self.assertRaises(ValueError):
            ExceptionContext(True, 0)

    def test_resolver_preserves_rule_and_process_order(self):
        row = bytes(self.row())
        db = database(1, 3, 36, [row, row])
        self.assertEqual(
            ExceptionResolver(db).matching_rules(self.context()), (row, row)
        )
        process = struct.pack("<IHH12x", 0, 4, 6)
        self.assertEqual(
            ExceptionResolver(database(1, 4, 20, [process])).processes(4, second_key=6),
            (process,),
        )


class PidSupportTests(unittest.TestCase):
    def freeze(self):
        row = bytearray(84)
        row[79] = 5
        struct.pack_into("<H", row, 58, 9)
        return row

    def test_decode_and_execute_all_three_native_bit_selectors(self):
        for selector in (2, 3, 4):
            identifier = b"\x12\x34" if selector == 4 else b"\x12"
            bit = PidBit(0, 7, selector, identifier)
            requests = []

            def exchange(request, requests=requests, selector=selector):
                requests.append(request)
                return b"\x61\0\0\0\x80" if selector == 4 else b"\x61\0\x80"

            self.assertTrue(
                check_pid_support(
                    bytes(self.freeze()),
                    {5: 1, 18: 1},
                    {9: bit},
                    lambda function: [CommandFrame(b"\x21\0\0\0")],
                    exchange,
                    did_lengths={18: 1},
                )
            )
            self.assertEqual(
                requests[0], b"\x21\0\x12\x34" if selector == 4 else b"\x21\x12\0\0"
            )
        variables = VariableTable(struct.pack("<IH", 0, 1) + b"\x12", 1)
        self.assertEqual(
            PidBit.from_record(bit_row(9), variables), PidBit(0, 7, 2, b"\x12")
        )

    def test_modes_missing_pid_and_zero_reply_are_false_without_io(self):
        row = self.freeze()

        def unexpected(*args):
            raise AssertionError("I/O should not occur")

        row[77] = 1
        self.assertTrue(check_pid_support(bytes(row), {}, {}, unexpected, unexpected))
        row[77] = 2
        self.assertFalse(check_pid_support(bytes(row), {}, {}, unexpected, unexpected))
        row[77] = 0
        self.assertFalse(check_pid_support(bytes(row), {}, {}, unexpected, unexpected))
        self.assertFalse(
            check_pid_support(bytes(row), {5: 1}, {}, unexpected, unexpected)
        )
        bit = PidBit(0, 0, 2, b"\x12")
        self.assertFalse(
            check_pid_support(
                bytes(row),
                {5: 1},
                {9: bit},
                lambda _: [CommandFrame(b"\x21\0")],
                unexpected,
            )
        )
        self.assertFalse(bit.evaluate(b"\x61\0\0"))

    def test_native_support_timeout_codes_are_false_other_errors_propagate(self):
        for code in (0x91010009, 0x90020323, 0x90020321):

            def exchange(request, code=code):
                raise ToyotaCodecError("injected failure", code)

            def check():
                return check_pid_support(
                    bytes(self.freeze()),
                    {5: 1, 18: 1},
                    {9: PidBit(0, 7, 2, b"\x12")},
                    lambda _: [CommandFrame(b"\x21\0")],
                    exchange,
                )

            if code == 0x90020321:
                with self.assertRaises(ToyotaCodecError):
                    check()
            else:
                self.assertFalse(check())

    def test_invalid_and_short_definitions_fail(self):
        for args in ((0, 7, 1, b"x"), (8, 7, 2, b"x"), (0, 7, 4, b"x")):
            with self.assertRaises(ToyotaCodecError):
                PidBit(*args)
        bit = PidBit(0, 7, 2, b"\x12")
        with self.assertRaises(ToyotaCodecError):
            bit.request(CommandFrame(b"\x21"))
        with self.assertRaises(ToyotaCodecError):
            bit.evaluate(b"\x61\0")
        with self.assertRaises(ToyotaCodecError):
            check_pid_support(
                bytes(self.freeze()),
                {5: 1, 18: 1},
                {9: bit},
                lambda _: [],
                lambda _: b"",
            )


class DefaultProbeRuntimeTests(unittest.TestCase):
    def test_partial_mode_write_failure_still_restores_and_preserves_both_errors(self):
        from scripts.support import DefaultExceptionProbe, evaluate_default_probe

        for restoration_fails in (False, True):
            events = []

            def write(value, events=events, restoration_fails=restoration_fails):
                events.append(value)
                if len(events) == 1 or restoration_fails:
                    raise RuntimeError("injected state write failure")

            def run(write=write):
                return evaluate_default_probe(
                    DefaultExceptionProbe(3, 42, 7, 9, 0, 0, 0),
                    support_bit=lambda *args: True,
                    frame_check=lambda *args: False,
                    read_mode=lambda: bytes(16),
                    write_mode=write,
                    build_mode=lambda *args: bytes([1]) * 16,
                )

            with self.assertRaises(
                BaseExceptionGroup if restoration_fails else RuntimeError
            ):
                run()
            self.assertEqual(events, [bytes([1]) * 16, bytes(16)])

    def test_protocol_mode_restored_after_success_and_failure(self):
        from scripts.support import DefaultExceptionProbe, evaluate_default_probe

        for fail in (False, True):
            events = []
            original, alternate = bytes(16), bytes([1]) * 16

            def support(key, flag1, flag2, events=events, fail=fail):
                events.append((key, flag1, flag2))
                if fail:
                    raise ToyotaCodecError("injected timeout", 0x91010009)
                return True

            def evaluate(
                probe,
                support=support,
                original=original,
                alternate=alternate,
                events=events,
            ):
                return evaluate_default_probe(
                    probe,
                    support_bit=support,
                    frame_check=lambda *args: False,
                    read_mode=lambda: original,
                    write_mode=events.append,
                    build_mode=lambda category, protocol, old: alternate,
                )

            probe = DefaultExceptionProbe(3, 42, 7, 9, 0, 0, 0)
            if fail:
                with self.assertRaises(ToyotaCodecError):
                    evaluate(probe)
            else:
                self.assertTrue(evaluate(probe))
            self.assertEqual(events, [alternate, (9, 0, 0), original])
            events.clear()
            if not fail:
                self.assertTrue(evaluate(DefaultExceptionProbe(1, 42, 7, 9, 0, 0, 0)))
                self.assertEqual(events, [(9, 1, 0)])
            events.clear()
            self.assertFalse(evaluate(DefaultExceptionProbe(3, 42, 7, 0, 0, 0, 0)))
            self.assertEqual(events, [])


class ExceptionProcessTests(unittest.TestCase):
    def process(self, mode, bit=0, exception=99):
        row = bytearray(20)
        struct.pack_into("<6H", row, 4, 42, 7, 3, bit, 4, exception)
        row[18], row[19] = mode, 5
        return bytes(row)

    def test_unconditional_conditional_and_missing_callbacks(self):
        unconditional = self.process(0)
        bit = self.process(1, 12, 100)
        frame = self.process(1, exception=101)
        resolver = ExceptionResolver(database(1, 4, 20, [unconditional, bit, frame]))
        seen = []

        def support(reference):
            seen.append(reference)
            return True

        def check(frame, settings, length):
            seen.append((frame, settings, length))
            return True

        self.assertEqual(
            resolver.resolve_processes(
                42, (7,), support_bit=support, frame_check=check
            ),
            (99, 100, 101),
        )
        self.assertEqual(seen, [12, (3, 4, 5)])
        with self.assertRaises(ValueError):
            resolver.resolve_processes(42, (7,))
        self.assertEqual(
            resolver.resolve_processes(
                42, (7,), support_bit=lambda _: False, frame_check=lambda *_: False
            ),
            (99,),
        )
        with self.assertRaises(ToyotaCodecError):
            ExceptionResolver(database(1, 4, 20, [self.process(2)])).resolve_processes(
                42, (7,)
            )

    def test_native_conditional_errors_skip_process(self):
        def failed(*args):
            raise ToyotaCodecError("Injected communication error", 0x91010009)

        resolver = ExceptionResolver(database(1, 4, 20, [self.process(1, 12)]))
        self.assertEqual(resolver.resolve_processes(42, (7,), support_bit=failed), ())


class DefaultExceptionTests(unittest.TestCase):
    def resolver(self, modes):
        installing = struct.pack("<HHBBH", 55, 32, 17, 0, 0)
        rows = []
        for mode in modes:
            row = bytearray(20)
            struct.pack_into("<6H", row, 4, 32, 42, 3, 12, 4, 99 + mode)
            row[16], row[17], row[18] = 17, mode, 5
            rows.append(bytes(row))
        return ExceptionResolver(
            Database(
                1,
                0x0100032F,
                "synthetic",
                {
                    57: Section(57, 0, 1, False, installing),
                    58: Section(58, 0, len(rows), False, b"".join(rows)),
                },
            )
        )

    def test_default_unconditional_support_and_context_probe(self):
        resolver = self.resolver((0, 1, 3))
        seen = []

        def evaluate(probe):
            seen.append(probe)
            return True

        self.assertEqual(
            resolver.default_processes(55, 42, evaluate),
            ((32, 99), (32, 100), (32, 102)),
        )
        self.assertEqual([probe.mode for probe in seen], [1, 3])
        self.assertEqual(
            (seen[1].category, seen[1].protocol, seen[1].support_bit), (32, 17, 12)
        )
        self.assertEqual(resolver.default_processes(56, 42), ())
        self.assertEqual(resolver.default_processes(55, 43), ())
        with self.assertRaises(ValueError):
            resolver.default_processes(55, 42)
        with self.assertRaises(ToyotaCodecError):
            self.resolver((2,)).default_processes(55, 42, evaluate)


class ConnectionCacheTests(unittest.TestCase):
    def test_native_request_receive_and_empty_template_paths(self):
        from scripts.support import ConnectionCacheEntry, lookup_connection_cache

        entries = [ConnectionCacheEntry(42, 7, 1, b"\x21", b"\x61\x85")]
        self.assertEqual(
            lookup_connection_cache(entries, 42, 7, CommandFrame(b"")), (1, 1)
        )
        frame = CommandFrame(b"\x21", b"\xff\xf0", b"\x61\x80")
        self.assertEqual(lookup_connection_cache(entries, 42, 7, frame), (1, 1))
        self.assertEqual(
            lookup_connection_cache(entries, 42, 7, CommandFrame(b"\x22")), (0, 0)
        )
        self.assertEqual(
            lookup_connection_cache(entries, 42, 7, CommandFrame(b"\x21")), (0, 0)
        )
        self.assertEqual(lookup_connection_cache(entries, 42, 8, frame), (0, 0))
        self.assertEqual(
            lookup_connection_cache(
                [ConnectionCacheEntry(42, 7, 0, b"\x21")], 42, 7, frame
            ),
            (0, 1),
        )
        mismatch = CommandFrame(b"\x21", b"\xff\xff", b"\x61\x80")
        self.assertEqual(lookup_connection_cache(entries, 42, 7, mismatch), (0, 1))
        with self.assertRaises(ToyotaCodecError):
            lookup_connection_cache(
                entries, 42, 7, CommandFrame(b"\x21", bytes(3), bytes(3))
            )


class ProtocolCacheTests(unittest.TestCase):
    def test_order_misses_failure_recording_and_native_flags(self):
        from scripts.support import ProtocolCandidate, check_protocol_cache

        events = []
        candidates = [
            ProtocolCandidate(1, 7, 3),
            ProtocolCandidate(2, 8, 4),
            ProtocolCandidate(3, 9, 5),
        ]

        def probe(*args):
            events.append(args)
            if args[0] == 1:
                raise ToyotaCodecError("injected failure", 0x91010009)

        selected = check_protocol_cache(
            candidates,
            lookup=lambda *args: (0, 0),
            probe=probe,
            remember_failure=lambda *args: events.append(args),
        )
        assert selected is not None
        self.assertEqual(
            (selected.category, selected.variant, selected.protocol, selected.index),
            (2, 8, 4, 1),
        )
        self.assertEqual(events, [(1, 7, 1000, 1, 1), (1, 0, 7, 3), (2, 8, 1000, 1, 1)])

    def test_cached_positive_keeps_native_zero_protocol_and_negative_is_skipped(self):
        from scripts.support import ProtocolCandidate, check_protocol_cache

        def unexpected(*args):
            raise AssertionError("No probe expected for cached observations")

        with self.assertRaises(ToyotaCodecError):
            check_protocol_cache(
                [], lookup=unexpected, probe=unexpected, remember_failure=unexpected
            )
        candidates = [ProtocolCandidate(1, 7, 3), ProtocolCandidate(2, 8, 4)]
        selected = check_protocol_cache(
            candidates,
            lookup=lambda category, variant: (category == 2, 1),
            probe=unexpected,
            remember_failure=unexpected,
        )
        assert selected is not None
        self.assertEqual(
            (selected.category, selected.protocol, selected.index), (2, 0, 1)
        )
        self.assertIsNone(
            check_protocol_cache(
                candidates,
                lookup=lambda *args: (0, 1),
                probe=unexpected,
                remember_failure=unexpected,
            )
        )
        self.assertIsNone(
            check_protocol_cache(
                candidates,
                lookup=unexpected,
                probe=unexpected,
                remember_failure=unexpected,
                start=2,
            )
        )


class ActiveSupportTests(unittest.TestCase):
    def test_native_modes_observed_length_and_didbit_gate(self):
        from scripts.support import check_active_support

        row = bytearray(92)
        row[82] = 12
        struct.pack_into("<H", row, 68, 7)

        def unexpected(*args):
            raise AssertionError("No support exchange expected")

        row[83] = 1
        self.assertTrue(
            check_active_support(bytes(row), {}, {}, {}, unexpected, unexpected)
        )
        row[83] = 2
        self.assertFalse(
            check_active_support(bytes(row), {}, {}, {}, unexpected, unexpected)
        )
        row[83] = 0
        self.assertFalse(
            check_active_support(bytes(row), {}, {}, {}, unexpected, unexpected)
        )
        self.assertTrue(
            check_active_support(bytes(row), {}, {12: 1}, {}, unexpected, unexpected)
        )
        struct.pack_into("<H", row, 60, 9)
        self.assertFalse(
            check_active_support(bytes(row), {}, {12: 1}, {}, unexpected, unexpected)
        )
        bit = PidBit(0, 0, 2, b"\x0c")
        self.assertTrue(
            check_active_support(
                bytes(row),
                {12: 1},
                {12: 1},
                {9: bit},
                lambda _: [CommandFrame(b"\x21\0")],
                lambda _: b"\x61\x0c\x80",
            )
        )
        row[83] = 9
        with self.assertRaises(ToyotaCodecError):
            check_active_support(bytes(row), {}, {}, {}, unexpected, unexpected)


class PanelSupportTests(unittest.TestCase):
    def test_native_panel_request_mask_and_all_six_comparisons(self):
        from scripts.support import check_panel_support

        variables = VariableTable(
            struct.pack("<IHIH", 0, 2, 2, 2) + b"\xff\xf0\x10\x80", 2
        )
        row = bytearray(16)
        struct.pack_into("<HHHHH", row, 0, 7, 0x1234, 1, 1, 2)
        requests = []

        def exchange(request):
            requests.append(request)
            return b"\x62\x12\x34\x00\x10\x8f"

        for mode, expected in (
            (1, True),
            (2, False),
            (3, True),
            (4, True),
            (5, False),
            (6, False),
        ):
            row[13] = mode
            self.assertEqual(
                check_panel_support(
                    7,
                    0,
                    {7: bytes(row)},
                    variables,
                    lambda _: [CommandFrame(b"\x22\0\0")],
                    exchange,
                ),
                expected,
            )
        self.assertEqual(requests, [b"\x22\x12\x34"] * 6)
        row[13] = 0
        self.assertTrue(
            check_panel_support(
                7, 0, {7: bytes(row)}, variables, lambda _: [], lambda _: b""
            )
        )
        self.assertTrue(
            check_panel_support(0, 1, {}, variables, lambda _: [], lambda _: b"")
        )
        self.assertFalse(
            check_panel_support(0, 2, {}, variables, lambda _: [], lambda _: b"")
        )
        with self.assertRaises(ToyotaCodecError):
            check_panel_support(0, 0, {}, variables, lambda _: [], lambda _: b"")


class ActiveP5SupportTests(unittest.TestCase):
    def test_p5_raw_cache_precedes_forced_mode_and_length_underflow(self):
        from scripts.support import check_p5_active_support

        row = bytearray(64)
        struct.pack_into("<H", row, 32, 7)
        struct.pack_into("<H", row, 42, 15)
        struct.pack_into("<H", row, 52, 0x1234)
        variables = VariableTable(b"", 0)
        cache, lengths = {}, {}

        def run(protocol=21, enabled=(0x1234,), records=(), reply=b""):
            return check_p5_active_support(
                bytes(row),
                protocol,
                enabled,
                records,
                cache,
                lengths,
                {},
                variables,
                lambda _: [CommandFrame(b"\x22\0\0")],
                lambda _: reply,
            )

        self.assertTrue(run())
        self.assertEqual(lengths, {0x1234: 0xFFFD})
        row[56] = 2
        self.assertFalse(run())
        self.assertTrue(cache[7])
        cache.clear()
        row[56] = 1
        self.assertTrue(run(enabled=()))
        self.assertFalse(cache[7])
        row[56] = 0
        self.assertFalse(run())
        cache.clear()
        records = [bytes(12)]
        self.assertTrue(run(0, records=records, reply=b"\x62\x12\x34\x80\0"))
        self.assertTrue(cache[7])

    def test_p5_request_and_native_fixed_reply_byte_scan(self):
        from scripts.support import check_p5_active_support

        row = bytearray(64)
        struct.pack_into("<H", row, 32, 7)
        struct.pack_into("<HH", row, 40, 0, 8)
        struct.pack_into("<H", row, 52, 0x1234)
        definition = bytearray(12)
        definition[10] = 1
        requests = []

        def exchange(request):
            requests.append(request)
            return b"\x62\x12\x34\0\0"

        # Native uses the same reply byte and x86 masks; the zero mask reached
        # at the second iteration makes this true even for a zero byte.
        self.assertTrue(
            check_p5_active_support(
                bytes(row),
                0,
                {0x1234},
                [bytes(definition)],
                {},
                {},
                {},
                VariableTable(b"", 0),
                lambda _: [CommandFrame(b"\x22\0\0")],
                exchange,
            )
        )
        self.assertEqual(requests, [b"\x22\x12\x34"])

    def test_routine_raw_membership_cache_and_post_override(self):
        from scripts.support import check_routine_support, check_subaru_routine_support

        row = bytearray(64)
        struct.pack_into("<HH", row, 28, 0x1234, 7)
        cache = {}
        self.assertTrue(check_routine_support(bytes(row), {0x1234}, cache))
        row[60] = 2
        self.assertFalse(check_routine_support(bytes(row), set(), cache))
        self.assertTrue(cache[7])
        row[60] = 0
        self.assertTrue(
            check_subaru_routine_support(
                bytes(row),
                set(),
                {},
                {},
                VariableTable(b"", 0),
                lambda _: [],
                lambda _: b"",
            )
        )
        struct.pack_into("<H", row, 32, 99)
        self.assertFalse(
            check_subaru_routine_support(
                bytes(row),
                set(),
                {},
                {},
                VariableTable(b"", 0),
                lambda _: [],
                lambda _: b"",
            )
        )

    def test_p4_mode_membership_and_exact_cache_bits(self):
        from scripts.support import check_active_support_p4

        row = bytearray(92)
        row[82] = 12
        struct.pack_into("<HH", row, 66, 3, 9)
        calls = []

        def check_bits(*args):
            calls.append(args)
            return True

        self.assertFalse(check_active_support_p4(bytes(row), {}, check_bits))
        self.assertTrue(check_active_support_p4(bytes(row), {12: 1}, check_bits))
        self.assertEqual(calls, [(12, 3, 9)])
        row[83] = 1
        self.assertTrue(check_active_support_p4(bytes(row), {}, check_bits))


class SubaruActiveSupportTests(unittest.TestCase):
    def test_subaru_has_no_enabled_did_gate_and_override_does_not_change_cache(self):
        from scripts.support import check_subaru_active_support

        row = bytearray(64)
        struct.pack_into("<H", row, 32, 7)
        cache = {}
        variables = VariableTable(b"", 0)
        self.assertTrue(
            check_subaru_active_support(
                bytes(row), cache, {}, variables, lambda _: [], lambda _: b""
            )
        )
        row[56] = 2
        self.assertFalse(
            check_subaru_active_support(
                bytes(row), cache, {}, variables, lambda _: [], lambda _: b""
            )
        )
        self.assertEqual(cache, {7: True})
        cache.clear()
        struct.pack_into("<H", row, 34, 99)
        row[56] = 1
        self.assertTrue(
            check_subaru_active_support(
                bytes(row), cache, {}, variables, lambda _: [], lambda _: b""
            )
        )
        self.assertEqual(cache, {7: False})

    def test_selected_did_bit_drives_subaru_action_and_routine_wire(self):
        from scripts.support import (
            check_subaru_active_support,
            check_subaru_routine_support,
        )

        variables = VariableTable(struct.pack("<IH", 0, 2) + b"\x12\x34", 1)
        definition = bytearray(12)
        struct.pack_into("<H", definition, 2, 1)
        definition[11] = 7
        row = bytearray(64)
        struct.pack_into("<HH", row, 30, 7, 9)
        requests = []

        def exchange(request):
            requests.append(request)
            return b"\x62\x12\x34\x80"

        frames = lambda _: [CommandFrame(b"\x22\0\0")]
        self.assertTrue(
            check_subaru_routine_support(
                bytes(row),
                {0x1234},
                {},
                {9: bytes(definition)},
                variables,
                frames,
                exchange,
            )
        )
        self.assertFalse(
            check_subaru_routine_support(
                bytes(row),
                set(),
                {},
                {9: bytes(definition)},
                variables,
                frames,
                exchange,
            )
        )
        struct.pack_into("<HH", row, 32, 7, 9)
        self.assertTrue(
            check_subaru_active_support(
                bytes(row), {}, {9: bytes(definition)}, variables, frames, exchange
            )
        )
        self.assertEqual(requests, [b"\x22\x12\x34"] * 2)


class Routine12Tests(unittest.TestCase):
    def test_versioned_routine_overlay_and_mode_offset(self):
        from scripts.support import check_routine_support

        row = bytearray(60)
        struct.pack_into("<HH", row, 28, 0x1234, 7)
        overlay = bytearray(row)
        struct.pack_into("<H", overlay, 56, 9)
        overlay[58], overlay[59] = 1, 2
        db = replace(database(2, 71, 60, [row, overlay]), version=0x0100030C)
        selected = correspondence_rows(db, 71, (9,))
        self.assertEqual(selected, (bytes(overlay),))
        cache = {}
        self.assertTrue(
            check_routine_support(
                selected[0], set(), cache, database_version=0x0100030C
            )
        )
        self.assertFalse(cache[7])
        with self.assertRaises(ToyotaCodecError):
            check_routine_support(selected[0], set(), {})
