import struct
import unittest

from scripts.script_vm import (
    ScriptObject,
    decode_utility_list,
    decode_utility_resource,
    evaluate,
    parse_object,
    parse_steps,
    parse_utility_xml,
    utility_resource_key,
)


class ScriptVMTests(unittest.TestCase):
    def test_library_dispatch_uses_high_library_byte_and_low_function_id(self):
        data = b"\x11\x01a\x40\x03\x07\x01\x01\x44\0"
        script = ScriptObject(0, (), (b"unused", b"Demo"), parse_steps(data))
        called = []

        def function(context, argc):
            called.append((argc, context.next_step))
            tag, value = context.pop()
            context.push(tag, value + b"b")

        self.assertEqual(
            evaluate(script, libraries={b"Demo": {7: function}}), ((1, b"ab"),)
        )
        self.assertEqual(called, [(1, 2)])
        with self.assertRaisesRegex(ValueError, "Unavailable"):
            evaluate(script)

    def test_library_references_initial_variables_and_mutable_program_counter(self):
        script = ScriptObject(
            1,
            (),
            (b"Demo",),
            parse_steps(b"\x15\x02\0\x80\x40\x03\x01\0\x01\xff\0\x44\0"),
        )

        def function(context, argc):
            ref = context.pop(resolve=False)
            context.store(ref, (3, b"changed"))
            context.push(*context.variables[0])
            context.next_step = 3

        self.assertEqual(
            evaluate(
                script,
                libraries={b"Demo": {1: function}},
                initial_variables={0x8000: (3, b"before")},
            ),
            ((3, b"changed"),),
        )
        for variable_id in (0, 0x7FFF, 0x8001, True):
            with self.subTest(variable_id=variable_id), self.assertRaises(ValueError):
                evaluate(script, initial_variables={variable_id: (3, b"x")})
        invalid_low_ref = ScriptObject(
            1, (), (), parse_steps(b"\x15\x02\0\0\x11\x01x\x30\x01\x01\x44\0")
        )
        with self.assertRaisesRegex(ValueError, "outside declared"):
            evaluate(invalid_low_ref)

    def test_library_failures_cancellation_and_budgets(self):
        script = ScriptObject(0, (), (b"Demo",), parse_steps(b"\x40\x03\x01\0\0\x44\0"))

        def too_large(context, argc):
            context.push(3, b"x" * 9)

        with self.assertRaisesRegex(ValueError, "byte budget"):
            evaluate(script, libraries={b"Demo": {1: too_large}}, max_bytes=8)

        def invalid(context, argc):
            context.stack.append((99, b"x"))

        with self.assertRaisesRegex(ValueError, "library value"):
            evaluate(script, libraries={b"Demo": {1: invalid}})

        def bad_pc(context, argc):
            context.next_step = -1

        with self.assertRaisesRegex(ValueError, "program counter"):
            evaluate(script, libraries={b"Demo": {1: bad_pc}})

        def recurse(context, argc):
            context.next_step = 0

        with self.assertRaisesRegex(ValueError, "instruction budget"):
            evaluate(script, libraries={b"Demo": {1: recurse}}, max_steps=5)
        state = [False]

        def cancel(context, argc):
            state[0] = True

        with self.assertRaises(InterruptedError):
            evaluate(
                script, libraries={b"Demo": {1: cancel}}, cancelled=lambda: state[0]
            )

        def fail(context, argc):
            raise OSError("fake library failed")

        with self.assertRaisesRegex(OSError, "fake library"):
            evaluate(script, libraries={b"Demo": {1: fail}})

    def test_aggregate_budget_counts_retained_concatenations_and_variables(self):
        # v0='abcd'; loop leaves a fresh copy of v0+'x' on the stack.
        data = b"\x15\x02\0\x80\x12\x04abcd\x30\x01\x01"
        data += b"\x15\x02\0\x80\x11\x01x\x30\x01\x31\x41\x02\x03\0"
        script = ScriptObject(1, (), (), parse_steps(data))
        with self.assertRaisesRegex(ValueError, "byte budget"):
            evaluate(script, max_steps=100, max_bytes=20)
        # Even shared raw push payloads count conservatively.
        script = ScriptObject(0, (), (), parse_steps(b"\x12\x04abcd\x41\x02\0\0"))
        with self.assertRaisesRegex(ValueError, "byte budget"):
            evaluate(script, max_bytes=7)
        for budget in (0, -1, True, 16 * 1024 * 1024 + 1):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                evaluate(script, max_bytes=budget)
        for data in (b"\x11\0\x41\x02\0\0", b"\x42\x02\0\0"):
            with (
                self.subTest(data=data),
                self.assertRaisesRegex(ValueError, "stack entry budget"),
            ):
                evaluate(ScriptObject(0, (), (), parse_steps(data)), max_steps=9000)

    def test_synthetic_encrypted_xml_and_csv_need_no_vendor_key_or_payload(self):
        # Authored fixtures encrypted with public test key bytes(range(32)).
        ciphertext = bytes.fromhex(
            "c7ffa9a610d3824a70df8dd0c98ace7ce2b28cf5c019f51035ddfc48f9fa2657"
            "beb6e6429702f7bea2720c92457044feca5fb7c8625d2ccce158000f69b38b203"
            "a2b9cb58cc10efb8b1529471522d495d4d2f5140b07c88156544ab86cb91ef4"
            "b7dbe7d1af01e1537151addc2a5d480a6eb17719e981ce3140d70d7d856afda"
            "9c3c4646f071c73c1814044a246dd9a44ffd2c0a3c22c8c6f0153a274241597"
            "d223b97ca069718f56a608c60792c47bb8520905e1703d7612dff03eedf1309ae7"
        )
        resource = decode_utility_resource(ciphertext, bytes(range(32)))
        self.assertEqual(resource.header, b"\x01\0\x01\0")
        self.assertEqual(
            resource.inspect()["functions"],
            [{"name": "Demo", "id": "7", "blocks": [{"ID": "B1"}]}],
        )
        rows = decode_utility_list(
            bytes.fromhex("4b618e207dd697c4057db16d374d055f"), bytes(range(32))
        )
        self.assertEqual(rows, [["7", "DEMO", "1", "0"]])
        for data, key in (
            (ciphertext[:-1], bytes(32)),
            (ciphertext, b"bad"),
            (b"", bytes(32)),
            (ciphertext, bytes(32)),
        ):
            with (
                self.subTest(length=len(data), key_length=len(key)),
                self.assertRaises(ValueError),
            ):
                decode_utility_resource(data, key)

    def test_utility_xml_rejects_entities_bounds_and_unrecognized_key_library(self):
        for data in (
            b"",
            bytes(8),
            b"head\xff\xfe"
            + '<!DOCTYPE x [<!ENTITY e "x">]><x>&e;</x>'.encode("utf-16le"),
            b"head\xff\xfe" + "<bad>".encode("utf-16le"),
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_utility_xml(data)
        with self.assertRaises(ValueError):
            utility_resource_key(b"unrecognized library")

    def test_byte_arithmetic_unsigned_comparisons_and_x86_shifts(self):
        for operator, left, right, expected in (
            (0x11, 255, 2, 1),
            (0x12, 0, 1, 255),
            (0x21, 1, 32, 1),
            (0x21, 1, 8, 0),
            (0x22, 128, 1, 64),
            (0x22, 255, 40, 0),
            (0x23, 0xA5, 0x0F, 5),
            (0x24, 0xA0, 5, 0xA5),
            (0x43, 128, 1, 0),
            (0x44, 128, 1, 1),
            (0x45, 9, 9, 1),
            (0x46, 8, 9, 0),
        ):
            data = bytes([0x11, 1, left, 0x11, 1, right, 0x30, 1, operator, 0x44, 0])
            with self.subTest(operator=operator):
                self.assertEqual(
                    evaluate(ScriptObject(0, (), (), parse_steps(data))),
                    ((1, bytes([expected])),),
                )

    def test_equality_compares_whole_payload_and_preserves_mismatch_rule(self):
        for operator, tag, payload, expected in (
            (0x41, 0x12, b"ab", 1),
            (0x42, 0x12, b"ac", 1),
            (0x42, 0x13, b"ab", 0),
            (0x41, 0x12, b"a", 0),
        ):
            data = (
                b"\x12\x02ab"
                + bytes([tag, len(payload)])
                + payload
                + bytes([0x30, 1, operator, 0x44, 0])
            )
            with self.subTest(operator=operator, tag=tag, payload=payload):
                self.assertEqual(
                    evaluate(ScriptObject(0, (), (), parse_steps(data))),
                    ((1, bytes([expected])),),
                )

    def test_conditional_jump_uses_first_byte_zero_without_numeric_conversion(self):
        for value, expected in ((b"\0\xff", b"f"), (b"\x80\0", b"t")):
            data = b"\x12\x02" + value + b"\x45\x02\x04\0\x11\x01t\x44\0\x11\x01f\x44\0"
            self.assertEqual(
                evaluate(ScriptObject(0, (), (), parse_steps(data))), ((1, expected),)
            )

    def test_variable_store_array_reference_and_zero_for_missing_element(self):
        # v0=type2('ab'); v0[1]=type1('x'); compare v0 to 'ax'.
        data = b"\x15\x02\0\x80\x12\x02ab\x30\x01\x01"
        data += b"\x15\x02\0\x80\x11\x01\x01\x30\x01\x32\x11\x01x\x30\x01\x01"
        data += b"\x15\x02\0\x80\x12\x02ax\x30\x01\x41\x44\0"
        self.assertEqual(
            evaluate(ScriptObject(1, (), (), parse_steps(data))), ((1, b"\x01"),)
        )
        # Appending preserves left/right order and produces type 3.
        data = b"\x12\x02ab\x11\x01c\x30\x01\x31\x44\0"
        self.assertEqual(
            evaluate(ScriptObject(0, (), (), parse_steps(data))), ((3, b"abc"),)
        )
        data = b"\x15\x02\0\x80\x12\x01a\x30\x01\x01"
        data += b"\x15\x02\0\x80\x11\x01\x03\x30\x01\x32\x11\x01z\x30\x01\x01"
        data += b"\x15\x02\0\x80\x12\x04a\0\0z\x30\x01\x41\x44\0"
        self.assertEqual(
            evaluate(ScriptObject(1, (), (), parse_steps(data))), ((1, b"\x01"),)
        )
        data = b"\x15\x02\0\x80\x12\x02ab\x30\x01\x01"
        data += b"\x15\x02\0\x80\x11\x01\xff\x30\x01\x32\x11\x01\0\x30\x01\x41\x44\0"
        self.assertEqual(
            evaluate(ScriptObject(1, (), (), parse_steps(data))), ((1, b"\x01"),)
        )
        for data in (
            b"\x15\x02\x01\x80\x11\x01\0\x30\x01\x41",
            b"\x15\x02\0\x80\x11\x01\0\x30\x01\x41",
            b"\x12\x01x\x11\x01\0\x30\x01\x11",
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                evaluate(ScriptObject(1, (), (), parse_steps(data)))

    def test_object_tables_and_instruction_operands(self):
        header = struct.pack("<HH", 2, 1) + b"\x03rpm" + struct.pack("<H", 17)
        header += b"\x01\x03lib" + struct.pack("<H", 2)
        script = parse_object(header + b"\x40\x03\x34\x12\x02\x44\x00")
        self.assertEqual(script.variable_count, 2)
        self.assertEqual(script.identifiers, ((b"rpm", 17),))
        self.assertEqual(script.libraries, (b"lib",))
        self.assertEqual(script.steps[0].inspect()["operand_u16"], 0x1234)
        self.assertEqual(script.steps[0].inspect()["argument_count"], 2)
        self.assertEqual(script.steps[0].offset, len(header))
        for cut in range(len(header + b"\x40\x03\x34\x12\x02\x44\x00")):
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                parse_object((header + b"\x40\x03\x34\x12\x02\x44\x00")[:cut])
        with self.assertRaises(ValueError):
            parse_object(header + b"\x44\x00\x44\x00\x00")

    def test_only_recovered_stack_and_call_flow_are_evaluated(self):
        # call 3; pop; exit; push type2 raw; return
        steps = parse_steps(b"\x42\x02\x03\x00\x20\x00\x44\x00\x12\x02ab\x43\x00")
        self.assertEqual(evaluate(ScriptObject(0, (), (), steps)), ())
        steps = parse_steps(b"\x11\x01x\x15\x01y\x44\x00")
        self.assertEqual(
            evaluate(ScriptObject(0, (), (), steps)), ((1, b"x"), (4, b"y"))
        )

    def test_malformed_unsupported_and_unbounded_programs_fail(self):
        for data in (b"\x41", b"\x41\x01x", b"\x40\x02ab", b"\x30\x00"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_steps(data)
        for data in (
            b"\x20\x00",
            b"\x43\x00",
            b"\x41\x02\xff\xff",
            b"\x30\x01\x00",
            b"\xff\x00",
            b"\x45\x02\x00\x00",
            b"\x41\x02\x00\x00",
        ):
            script = ScriptObject(0, (), (), parse_steps(data))
            with self.subTest(data=data), self.assertRaises(ValueError):
                evaluate(script, max_steps=10)
        self.assertEqual(
            parse_steps(b"\xff\x00")[0].inspect()["operation"], "unsupported"
        )


if __name__ == "__main__":
    unittest.main()
