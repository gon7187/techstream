import unittest
from typing import Any, cast

from scripts.cuw_legacy_body import (
    BodyOperationError,
    BodyTables,
    CPUDescriptor,
    airbag_prepare,
    airbag_security,
    airbag_seed_key,
    body_change_mode,
    body_mode_switch,
    body_security,
    body_security_session,
    body_seed_key,
    chassis_prepare_cpu,
    convert_seed,
    cpu_matches,
    diagnostic,
    dss_primary_security_session,
    epb_erase,
    epb_memory,
    epb_prepare,
    epb_verify,
    epb_write,
    epc_erase,
    epc_inverify,
    epc_prepare,
    epc_reset_progress,
    epc_write,
    epc_write_cpu,
    fc_prepare,
    four_byte_security,
    memory_mode,
    old_ecb_prepare_cpu,
    s0_block_ranges,
    sequential_ranges,
    sonar_prepare,
    sonar_security,
    validate_external_ranges,
)


class Channel:
    def __init__(self, statuses=(), acks=()):
        self.statuses = iter(statuses)
        self.acks = iter(acks)
        self.events = []

    def write(self, payload):
        self.events.append(("write", payload))

    def ack(self):
        self.events.append(("ack",))
        return next(self.acks, True)

    def status(self, *, retry=True):
        self.events.append(("status", retry))
        return next(self.statuses)

    def wait(self, milliseconds):
        self.events.append(("wait", milliseconds))


class GeometryTests(unittest.TestCase):
    def test_cpu_mode_and_identifier_are_both_compared(self):
        narrow = CPUDescriptor(3, False, True, 2, False)
        wide = CPUDescriptor(0x63, True, False, 0, True)
        self.assertTrue(cpu_matches(narrow, 0xB7, False))
        self.assertFalse(cpu_matches(narrow, 0xB7, True))
        self.assertTrue(cpu_matches(wide, 0xE3, True))
        self.assertFalse(cpu_matches(wide, 0xE3, False))
        self.assertEqual(memory_mode(narrow, b"xx\x01"), 1)
        self.assertEqual(memory_mode(narrow, b"xx\x00"), 0)
        self.assertEqual(memory_mode(narrow, b"xx\x03"), 2)
        with self.assertRaises(ValueError):
            memory_mode(narrow, b"x")
        with self.assertRaises(ValueError):
            cpu_matches(narrow, True, False)

    def test_native_s0_expands_zero_based_big_endian_ranges(self):
        header = (
            b"noise\xaa\x55\xaa\x55\x00\x00\x00\x02\x00\x01\x00\x03\x00\x06\x00\x06tail"
        )
        self.assertEqual(s0_block_ranges(header), ((2, 2), (3, 3), (4, 4), (7, 7)))
        self.assertEqual(
            s0_block_ranges(b"\xaa\x55\xaa\x55\x00\x00\x00\x01\x00\x02\x00\x01"), ()
        )
        self.assertEqual(sequential_ranges(3), ((1, 1), (2, 2), (3, 3)))

    def test_s0_skips_embedded_markers_in_record(self):
        header = b"\xaa\x55\xaa\x55\x00\x00\x00\x01\xaa\x55\xaa\x55"
        self.assertEqual(s0_block_ranges(header), ((0xAA56, 0xAA56),))

    def test_malformed_range_and_word_wrap_fail(self):
        for header in (
            b"\xaa\x55\xaa\x55",
            b"\xaa\x55\xaa\x55\0\0\0\1",
            b"\xaa\x55\xaa\x55\0\0\0\1\xff\xfe\xff\xff",
        ):
            with self.subTest(header=header), self.assertRaises(ValueError):
                s0_block_ranges(header)

    def test_external_flash_size_and_order(self):
        validate_external_ranges((1024, 2048, 4096), ((1, 1), (3, 3)), 5120)
        for ranges, size in (
            (((3, 3), (1, 1)), 5120),
            (((1, 1), (1, 1)), 2048),
            (((4, 4),), 0),
            (((1, 1),), 1025),
        ):
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                validate_external_ranges((1024, 2048, 4096), ranges, size)


class GroupedRangeTests(unittest.TestCase):
    def test_source_row_fallback_tail_and_zero_terminator(self):
        class SyntheticTables(BodyTables):
            def __init__(self):
                self.build = 18

            def _name(self, row):
                return "fixtureCPU" if row == 0x6170C4 else ""

            def number(self, address):
                return {0x6170C4 + 4: 2, 0x6170C4 + 8: 4, 0x6170C4 + 44 + 4: 1}.get(
                    address, 0
                )

        tables = SyntheticTables()
        self.assertEqual(tables.ranges("chassis", "fixtureCPU", 8), ((2, 4),))
        self.assertEqual(tables.ranges("old_ecb", "other", 8), ((1, 8),))
        with self.assertRaises(ValueError):
            tables.ranges("chassis", "fixtureCPU", 3)


class PrivateOperandTests(unittest.TestCase):
    def test_relative_initializer_preserves_register_and_displacement_selection(self):
        code = (
            b"\x8b\x15"
            + (0x11111111).to_bytes(4, "little")
            + b"\x89\x13"
            + b"\x8b\x0d"
            + (0x22222222).to_bytes(4, "little")
            + b"\x89\x4b\x08"
            + b"\xa1"
            + (0x33333333).to_bytes(4, "little")
            + b"\x89\x83\x80\0\0\0"
            + b"\xa1"
            + (0x44444444).to_bytes(4, "little")
            + b"\x89\x53\x10"
            + b"\xa1"
            + (0x55555555).to_bytes(4, "little")
            + b"\x89\x43\xff"
        )

        class Image:
            def read(self, address, size):
                return code

        class Tables(BodyTables):
            def __init__(self):
                self.image = Image()
                self.names = {}

            def number(self, address):
                return address + 0x100

        tables = Tables()
        tables._relative_names(0, len(code), 0x600000, 3)
        self.assertEqual(
            tables.names,
            {0x600000: 0x11111211, 0x600008: 0x22222322, 0x600080: 0x33333433},
        )

    def test_four_round_material_reads_word_constructor_and_rejects_ambiguous_source(
        self,
    ):
        class Image:
            image_base = 0x400000

            def __init__(self, data):
                self.data = data
                self.sections = ((0x1000, len(data), 0),)

        class Tables(BodyTables):
            def __init__(self, build):
                self.build = build
                self.image = Image(b"")

        for build, constructor in ((12, 0x40E310), (18, 0x419BDC)):
            tables = Tables(build)

            def code(word, target):
                return (
                    b"\x68"
                    + word.to_bytes(4, "little")
                    + b"\x68"
                    + (0x500000).to_bytes(4, "little")
                    + b"\xe8"
                    + (target - 0x40100F).to_bytes(4, "little", signed=True)
                )

            tables.image = Image(code(0x1234, constructor))
            self.assertEqual(tables._constructed_word(0x500000), b"\x12\x34")
            for data in (
                code(0x1234, constructor + 1),
                code(0x10000, constructor),
                code(0x1234, constructor) + code(0x1234, constructor - 15),
            ):
                tables.image = Image(data)
                with self.assertRaises(ValueError):
                    tables._constructed_word(0x500000)

    def test_epc_identification_uses_its_source_table_and_empty_sentinel(self):
        class Image:
            def read(self, address, size):
                return b"\7\0"

        class Tables(BodyTables):
            def __init__(self, build):
                self.build = build
                self.image = Image()
                self.addresses = []

            def _name(self, row):
                self.addresses.append(row)
                return "syntheticCPU" if len(self.addresses) == 1 else ""

        for build, table in ((12, 0x5CCA40), (18, 0x628EC0)):
            for firmware, expected in ((0x70, True), (0xF0, True), (0x60, False)):
                tables = Tables(build)
                self.assertEqual(
                    tables.epc_cpu_matches("syntheticCPU", firmware), expected
                )
                self.assertEqual(tables.addresses, [table])
            tables = Tables(build)
            self.assertFalse(tables.epc_cpu_matches("unlisted", 0x70))
            self.assertEqual(tables.addresses, [table, table + 8])

    def test_sonar_uses_source_constructor_operands_not_uninitialized_objects(self):
        class Tables(BodyTables):
            def __init__(self, build):
                self.build = build
                self.addresses = []

            def number(self, address):
                self.addresses.append(address)
                return 0x1234 if len(self.addresses) == 1 else 0x5678

        for build, addresses in (
            (12, [0x526714, 0x526739]),
            (18, [0x56E964, 0x56E989]),
        ):
            tables = Tables(build)
            self.assertEqual(tables.sonar_passwords(), (b"\x12\x34", b"\x56\x78"))
            self.assertEqual(tables.addresses, addresses)

    def test_two_word_columns_are_selected_and_converted_to_wire_order(self):
        class Image:
            def read(self, address, size):
                self.last = (address, size)
                return bytes((address & 255, (address >> 8) & 255))

        class Tables(BodyTables):
            def __init__(self, build):
                self.build = build
                self.image = Image()

            def _row(self, table, count, stride, cpu_type):
                self.selected = (table, count, stride, cpu_type)
                return table + (count - 1) * stride

        for build, airbag, dss1 in ((12, 0x5B75F0, 0x5BD62C), (18, 0x61361C, 0x619690)):
            tables = Tables(build)
            for kind, table, count in (("airbag", airbag, 1), ("dss1", dss1, 3)):
                for index in range(4):
                    passwords = tables.two_byte_passwords(kind, "syntheticCPU", index)
                    row = table + (count - 1) * 20
                    expected = tuple(
                        (row + offset + 2 * index).to_bytes(4, "little")[:2][::-1]
                        for offset in (4, 12)
                    )
                    self.assertEqual(passwords, expected)
                    self.assertEqual(
                        tables.selected, (table, count, 20, "syntheticCPU")
                    )
            for index in (-1, 4, True):
                with self.assertRaises(ValueError):
                    tables.two_byte_passwords("airbag", "syntheticCPU", index)
            with self.assertRaises(ValueError):
                tables.two_byte_passwords("sonar", "syntheticCPU")


class EPBTests(unittest.TestCase):
    def test_erase_memory_internal_verify_preserve_passthru_domain(self):
        from scripts.cuw_legacy_can import ExecutableCANError
        from scripts.cuw_legacy_engine import ExecutableJ2534Error

        class FaultChannel(Channel):
            def __init__(self, fault):
                super().__init__()
                self.fault = fault

            def write(self, payload):
                raise self.fault

        for operation, code in (
            (lambda c: epb_erase(c, 1), 12),
            (epb_memory, 10),
            (lambda c: epc_erase(c, 1), 12),
            (lambda c: epc_inverify(c, 1), 14),
        ):
            passthru = ExecutableCANError(4)
            with self.assertRaises(ExecutableCANError) as caught:
                operation(FaultChannel(passthru))
            self.assertIs(caught.exception, passthru)
            driver = ExecutableJ2534Error(1, 9)
            with self.assertRaises(ExecutableJ2534Error) as caught:
                operation(FaultChannel(driver))
            self.assertIs(caught.exception, driver)
            self.assertEqual((driver.native_code, driver.driver_status), (code, 9))
            with self.assertRaises(InterruptedError):
                operation(FaultChannel(InterruptedError("cancel")))

    def test_erase_pending_80_and_error(self):
        channel = Channel((0x80, 0x80, 0))
        epb_erase(channel, 256)
        self.assertEqual(
            channel.events,
            [
                ("write", b"\x25\xff"),
                ("ack",),
                ("wait", 10),
                ("status", True),
                ("wait", 10),
                ("status", True),
                ("wait", 10),
                ("status", True),
            ],
        )
        with self.assertRaises(BodyOperationError) as caught:
            epb_erase(Channel((1,)), 1)
        self.assertEqual(caught.exception.native_code, 12)

    def test_verify_256_chunks_offset_progress_and_pending20(self):
        image = b"A" * 256 + b"B" * 256 + b"C" * 256
        channel = Channel((0x20, 0, 0))
        progress = []
        epb_verify(
            channel, image, (256, 512), 2, 3, lambda *event: progress.append(event)
        )
        self.assertEqual(
            [event[1] for event in channel.events if event[0] == "write"],
            [b"\x15\x01", b"B" * 256, b"C" * 256],
        )
        self.assertEqual(progress, [(3, 256), (3, 256)])
        self.assertEqual(
            [event for event in channel.events if event[0] == "status"],
            [("status", False), ("status", False), ("status", True)],
        )

    def test_verify_native_final_copy_is_not_silently_truncated(self):
        channel = Channel((0,))
        with self.assertRaises(ValueError):
            epb_verify(channel, b"A", (1,), 1, 0, lambda *_: None)
        self.assertEqual(channel.events, [])
        epb_verify(channel, b"A" * 256, (1,), 1, 0, lambda *_: None)
        self.assertEqual(channel.events[2], ("write", b"A" * 256))

    def test_ack_status_and_callback_failures_stop(self):
        for acks in ((False,), (True, False)):
            channel = Channel((0,), acks)
            with self.assertRaises(BodyOperationError) as caught:
                epb_verify(channel, b"A" * 256, (256,), 1, 0, lambda *_: None)
            self.assertEqual(caught.exception.native_code, 15)
        with self.assertRaises(BodyOperationError):
            epb_verify(Channel((2,)), b"A" * 256, (256,), 1, 0, lambda *_: None)
        with self.assertRaises(ValueError):
            epb_erase(Channel((True,)), 1)
        channel = Channel((0,))

        def cancelled(*_):
            raise InterruptedError("cancelled")

        with self.assertRaises(InterruptedError):
            epb_verify(channel, b"A" * 256, (256,), 1, 0, cancelled)
        self.assertEqual(channel.events[-1][0], "write")


class VerifyExceptionTests(unittest.TestCase):
    def test_only_nonfinal_passthru_fault_before_pending_is_ignored(self):
        from scripts.cuw_legacy_can import ExecutableCANError
        from scripts.cuw_legacy_engine import ExecutableJ2534Error
        from scripts.programming import NativeTransportError

        class FaultChannel(Channel):
            def status(self, *, retry=True):
                value = super().status(retry=retry)
                if isinstance(value, Exception):
                    raise value
                return value

        channel = FaultChannel((ExecutableCANError(4), 0))
        epb_verify(channel, b"A" * 512, (512,), 1, 0, lambda *_: None)
        self.assertEqual(
            len([event for event in channel.events if event[0] == "write"]), 3
        )
        for statuses in ((0, ExecutableCANError(4)), (0x20, ExecutableCANError(4))):
            with (
                self.subTest(statuses=statuses),
                self.assertRaises(BodyOperationError) as caught,
            ):
                epb_verify(
                    FaultChannel(statuses), b"A" * 512, (512,), 1, 0, lambda *_: None
                )
            self.assertEqual(caught.exception.code, 15)
        driver = ExecutableJ2534Error(1, 9)
        with self.assertRaises(NativeTransportError) as caught:
            epb_verify(
                FaultChannel((driver,)), b"A" * 512, (512,), 1, 0, lambda *_: None
            )
        self.assertEqual(caught.exception.code, 9)
        self.assertEqual(driver.native_code, 15)
        self.assertEqual(driver.driver_status, 9)
        host_transport = NativeTransportError(9)
        with self.assertRaises(NativeTransportError) as caught:
            epb_verify(
                FaultChannel((host_transport,)),
                b"A" * 512,
                (512,),
                1,
                0,
                lambda *_: None,
            )
        self.assertIs(caught.exception, host_transport)
        self.assertNotIn("native_cuw_code", host_transport.__dict__)
        with self.assertRaises(InterruptedError):
            epb_verify(
                FaultChannel((InterruptedError("cancelled"),)),
                b"A" * 512,
                (512,),
                1,
                0,
                lambda *_: None,
            )


class WriterTests(unittest.TestCase):
    def test_write_native_domains_change_category_without_losing_driver_status(self):
        from scripts.cuw_legacy_can import ExecutableCANError
        from scripts.cuw_legacy_engine import ExecutableJ2534Error

        class FaultChannel(Channel):
            fault: Exception

            def write(self, payload):
                raise self.fault

        for writer in (epb_write, epc_write):
            driver = ExecutableJ2534Error(1, 9)
            channel = FaultChannel()
            channel.fault = driver
            with self.assertRaises(ExecutableJ2534Error) as caught:
                writer(channel, b"x" * 1024, (1024,), 1, 0, 0, lambda *_: None)
            self.assertIs(caught.exception, driver)
            self.assertEqual((driver.native_code, driver.driver_status), (13, 9))
            channel.fault = ExecutableCANError(4)
            with self.assertRaises(BodyOperationError) as caught:
                writer(channel, b"x" * 1024, (1024,), 1, 0, 0, lambda *_: None)
            self.assertEqual(caught.exception.code, 13)
            self.assertIs(caught.exception.__cause__, channel.fault)
            channel.fault = InterruptedError("cancel")
            with self.assertRaises(InterruptedError):
                writer(channel, b"x" * 1024, (1024,), 1, 0, 0, lambda *_: None)

    def test_epb_write_address_offset_and_continuation(self):
        channel = Channel((0x40, 0, 0))
        progress = []
        epb_write(
            channel,
            b"A" * 1024 + b"B" * 2048,
            (1024, 2048),
            2,
            0x123456,
            1,
            lambda *event: progress.append(event),
        )
        writes = [event[1] for event in channel.events if event[0] == "write"]
        self.assertEqual(
            writes,
            [b"\x41", bytes.fromhex("123856ff"), b"B" * 1024, b"\x45", b"B" * 1024],
        )
        self.assertEqual(progress, [(1, 1024), (1, 1024)])
        self.assertEqual(
            [event for event in channel.events if event[0] == "status"],
            [("status", False)] * 3,
        )

    def test_epc_first_wait_and_retry_are_real_deltas(self):
        channel = Channel((0,))
        epc_write(channel, b"A" * 1024, (1024,), 1, 0x1200, 0, lambda *_: None)
        self.assertEqual(channel.events[3], ("wait", 3))
        self.assertIn(("status", True), channel.events)
        for operation, pending, code in (
            (epc_erase, 0x80, 12),
            (epc_inverify, 0x40, 14),
        ):
            channel = Channel((pending, 0))
            operation(channel, 2)
            self.assertEqual(channel.events[0][1][1], 1)
            with self.assertRaises(BodyOperationError) as caught:
                operation(Channel((1,)), 1)
            self.assertEqual(caught.exception.native_code, code)

    def test_write_rejects_native_overread_before_io(self):
        channel = Channel((0,))
        with self.assertRaises(ValueError):
            epb_write(channel, b"A" * 1023, (1024,), 1, 0, 0, lambda *_: None)
        self.assertEqual(channel.events, [])
        with self.assertRaises(BodyOperationError) as caught:
            epb_write(
                Channel((0,), (False,)), b"A" * 1024, (1024,), 1, 0, 0, lambda *_: None
            )
        self.assertEqual(caught.exception.native_code, 13)

    def test_real_raw_commoncan_memory_and_pending_erase(self):
        from scripts.cuw_legacy_can import CommonCAN
        from scripts.cuw_legacy_engine import ExecutableIO
        from scripts.j2534_2026 import NativeMessage

        request, response = bytes.fromhex("00000700"), bytes.fromhex("00000708")
        frames = iter(
            (
                b"\x3c",
                NativeMessage(6, response, rx_status=2),
                bytes.fromhex("0123450008002063"),
                b"\x3c",
                b"\x3c",
                b"\x3c",
                b"\x80",
                b"\x3c",
                b"\x3c",
                b"\x00",
                b"\x3c",
            )
        )
        events = []
        indications = []

        def action(event, remaining):
            self.assertGreater(remaining, 0)
            events.append(event)
            if event["operation"] == "ioctl":
                return None
            if event["operation"] == "write_messages":
                indications.append(NativeMessage(6, event["data"], rx_status=9))
                return 1
            if event["operation"] == "read_messages":
                if indications:
                    return (indications.pop(0),)
                value = next(frames)
                return (
                    (value,)
                    if isinstance(value, NativeMessage)
                    else (NativeMessage(6, response + value),)
                )
            if event["operation"] == "wait":
                return None
            raise AssertionError(event)

        io = ExecutableIO(action)
        channel = CommonCAN(io, request, response, padding=False)
        memory = epb_memory(channel)
        self.assertEqual(
            (
                memory.address,
                memory.end_address,
                memory.block_size_kib,
                memory.firmware_descriptor,
            ),
            (0x12345, 0x800, 0x20, 0x63),
        )
        epb_erase(channel, 1)
        self.assertEqual(
            [
                event["data"]
                for event in events
                if event["operation"] == "write_messages"
            ],
            [
                request + b"\x75",
                request + b"\x25\x00",
                request + b"\x50",
                request + b"\x50",
            ],
        )
        self.assertEqual(io.close(), [])

    def test_raw_runtime_cancellation_bounds_native_pending_loop(self):
        from scripts.cuw_legacy_can import CommonCAN
        from scripts.cuw_legacy_engine import ExecutableIO
        from scripts.j2534_2026 import NativeMessage

        cancelled = [False]
        reads = [0]
        indications = []

        def action(event, remaining):
            if event["operation"] == "ioctl":
                return None
            if event["operation"] == "write_messages":
                indications.append(NativeMessage(6, event["data"], rx_status=9))
                return 1
            if event["operation"] == "wait":
                cancelled[0] = True
                return None
            reads[0] += 1
            if indications:
                return (indications.pop(0),)
            return (NativeMessage(6, b"\0\0\7\x08\x3c"),)

        channel = CommonCAN(
            ExecutableIO(action, cancelled=lambda: cancelled[0]),
            b"\0\0\7\0",
            b"\0\0\7\x08",
            padding=False,
        )
        with self.assertRaises(InterruptedError):
            epb_erase(channel, 1)
        self.assertEqual(reads[0], 2)


class DiagnosticChannel:
    request = b"\0\0\7\0"

    def __init__(self, responses):
        self.responses = iter(responses)
        self.events = []
        self.timeout_ms = 1000
        from scripts.cuw_legacy_engine import ExecutableIO

        self.io = ExecutableIO(lambda event, remaining: None)

    def diagnostic_mask(self):
        self.events.append(("mask",))

    def set_timeout(self, milliseconds, *, cleanup=False):
        self.timeout_ms = milliseconds
        self.events.append(("set_timeout", milliseconds))

    def _write(self, payload, header):
        self.events.append(("write", header + payload))

    def read(self, *, mode, padding):
        self.events.append(("read", mode, padding, self.timeout_ms))
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return b"\0\0\7\x08" + value

    def wait(self, milliseconds):
        self.events.append(("wait", milliseconds))


class DiagnosticTests(unittest.TestCase):
    def test_diagnostic_typed_driver_handler_uses_error_argument_and_preserves_domains(
        self,
    ):
        from scripts.cuw_legacy_can import ExecutableCANError
        from scripts.cuw_legacy_engine import ExecutableJ2534Error
        from scripts.programming import NativeTransportError

        for code, expected in ((3, 3), (16, 16), (255, -1)):
            driver = ExecutableJ2534Error(1, 9)
            with self.assertRaises(ExecutableJ2534Error) as caught:
                diagnostic(
                    DiagnosticChannel((driver,)),
                    b"\x27\1",
                    b"\x67\1",
                    2,
                    code,
                    padding=False,
                )
            self.assertIs(caught.exception, driver)
            self.assertEqual((driver.native_code, driver.driver_status), (expected, 9))
        for error in (ExecutableCANError(4), NativeTransportError(9)):
            with self.assertRaises(type(error)) as caught:
                diagnostic(
                    DiagnosticChannel((error,)),
                    b"\x27\1",
                    b"\x67\1",
                    2,
                    16,
                    padding=False,
                )
            self.assertIs(caught.exception, error)
        with self.assertRaises(BodyOperationError) as caught:
            diagnostic(
                DiagnosticChannel((b"wrong",)),
                b"\x27\1",
                b"\x67\1",
                2,
                255,
                padding=False,
            )
        self.assertEqual(caught.exception.code, 255)
        self.assertEqual(caught.exception.native_code, -1)

    def test_native_cancel_predicate_retains_existing_response_and_neutral_code3(self):
        early = DiagnosticChannel(())
        self.assertEqual(
            diagnostic(
                early, b"\x09\0", b"", 0, 3, padding=False, native_cancel=lambda: True
            ),
            b"",
        )
        self.assertFalse(any(event[0] == "read" for event in early.events))
        decisions = iter((False, True))
        pending = DiagnosticChannel((b"\x7f\x09\x78",))
        self.assertEqual(
            diagnostic(
                pending,
                b"\x09\0",
                b"",
                0,
                3,
                padding=False,
                native_cancel=lambda: next(decisions),
            ),
            b"\x7f\x09\x78",
        )
        self.assertEqual(pending.timeout_ms, 1000)
        probe = DiagnosticChannel((b"\x49\0abcd",))
        self.assertEqual(
            diagnostic(probe, b"\x09\0", b"", 0, 3, padding=False), b"\x49\0abcd"
        )
        self.assertEqual(
            [event[1] for event in probe.events if event[0] == "read"], [2]
        )
        with self.assertRaises(ValueError):
            diagnostic(
                DiagnosticChannel(()),
                b"\x09\0",
                b"",
                0,
                3,
                padding=False,
                native_cancel=cast(Any, lambda: 1),
            )

    def test_busy_resends_pending_does_not_and_timeout_restores(self):
        channel = DiagnosticChannel((b"\x7f\x27\x21", b"\x7f\x27\x78", b"\x67\x01x"))
        self.assertEqual(
            diagnostic(channel, b"\x27\x01", b"\x67\x01", 3, 16, padding=False),
            b"\x67\x01x",
        )
        self.assertEqual(
            [event for event in channel.events if event[0] == "write"],
            [("write", channel.request + b"\x27\x01")] * 2,
        )
        self.assertEqual(
            [event[3] for event in channel.events if event[0] == "read"],
            [1000, 1000, 5000],
        )
        self.assertEqual(channel.timeout_ms, 1000)

    def test_cancellation_during_cleanup_wins_and_chains_original_native_failure(self):
        from scripts.cuw_legacy_can import ExecutableCANError
        from scripts.cuw_legacy_engine import ExecutableIO

        cancelled = [False]

        class CleanupChannel(DiagnosticChannel):
            def set_timeout(self, milliseconds, *, cleanup=False):
                super().set_timeout(milliseconds, cleanup=cleanup)
                if cleanup:
                    cancelled[0] = True

        native = ExecutableCANError(4)
        channel = CleanupChannel((b"\x7f\x27\x78", native))
        channel.io = ExecutableIO(
            lambda event, remaining: None, cancelled=lambda: cancelled[0]
        )
        with self.assertRaises(InterruptedError) as caught:
            diagnostic(channel, b"\x27\1", b"\x67\1", 2, 16, padding=False)
        self.assertIs(caught.exception.__cause__, native)
        self.assertEqual(channel.timeout_ms, 1000)

    def test_native_diagnostic_fault_retains_payload_and_full_frame_size(self):
        channel = DiagnosticChannel((b"\x7f\x27\x22",))
        with self.assertRaises(BodyOperationError) as caught:
            diagnostic(channel, b"\x27\1", b"\x67\1", 2, 16, padding=False)
        error = caught.exception
        self.assertEqual((error.response, error.response_size), (b"\x7f\x27\x22", 7))
        self.assertNotIn(repr(error.response), str(error))
        self.assertNotIn(repr(error.response), repr(error))
        for responses, kwargs in (
            ((b"\x67",), {}),
            ((b"\x7f\x27\x21",), {"busy_retries": 0}),
            ((b"\x7f\x27\x78",), {"pending_responses": 0}),
        ):
            with self.assertRaises(BodyOperationError) as caught:
                diagnostic(
                    DiagnosticChannel(responses),
                    b"\x27\1",
                    b"\x67\1",
                    2,
                    16,
                    padding=False,
                    **cast(Any, kwargs),
                )
            self.assertEqual(caught.exception.response, responses[0])
            self.assertEqual(caught.exception.response_size, 4 + len(responses[0]))

    def test_cancel_restores_timeout_through_cleanup_and_preserves_primary_fault(self):
        class CleanupChannel(DiagnosticChannel):
            def set_timeout(self, milliseconds, *, cleanup=False):
                if cleanup:
                    self.events.append(("cleanup", milliseconds))
                    raise ValueError("synthetic restoration failure")
                super().set_timeout(milliseconds, cleanup=cleanup)

        channel = CleanupChannel((b"\x7f\x27\x78", InterruptedError("cancelled")))
        with self.assertRaises(InterruptedError) as caught:
            diagnostic(channel, b"\x27\1", b"\x67\1", 2, 16, padding=False)
        self.assertEqual(channel.events[-1], ("cleanup", 1000))
        self.assertIn("ValueError", caught.exception.__notes__[0])
        self.assertNotIn("synthetic", caught.exception.__notes__[0])

    def test_pending_limit_writes_only_tester_present_then_fails(self):
        channel = DiagnosticChannel((b"\x7f\x27\x78", b"\x7f\x27\x78"))
        with self.assertRaises(BodyOperationError) as caught:
            diagnostic(
                channel,
                b"\x27\x01",
                b"\x67\x01",
                2,
                17,
                padding=True,
                pending_responses=1,
            )
        self.assertEqual(caught.exception.native_code, 17)
        self.assertIn(("write", channel.request + b"\x3e"), channel.events)
        self.assertEqual(channel.timeout_ms, 1000)

    def test_fault_prefix_short_and_busy_limit(self):
        for responses, kwargs in (
            ((b"\x7f\x27\x21",), {"busy_retries": 0}),
            ((b"\x67",), {}),
            ((b"\x68\x01",), {}),
            ((b"\x7f\x27\x78", InterruptedError("cancelled")), {}),
        ):
            channel = DiagnosticChannel(responses)
            with (
                self.subTest(responses=responses),
                self.assertRaises((BodyOperationError, InterruptedError)),
            ):
                diagnostic(
                    channel,
                    b"\x27\x01",
                    b"\x67\x01",
                    2,
                    16,
                    padding=False,
                    **cast(Any, kwargs),
                )
            self.assertEqual(channel.timeout_ms, 1000)


class SecurityTests(unittest.TestCase):
    def test_airbag_sonar_and_body_dss_security_session_chronology(self):
        for prepare, tail in (
            (airbag_prepare, [1500]),
            (sonar_prepare, [500]),
            (dss_primary_security_session, []),
        ):
            channel = DiagnosticChannel((b"\x67\3\0\0\x34", b"\x67\4\x34", b"\x50"))
            prepare(channel, b"ab", b"cd", padding=False)
            self.assertEqual(
                [event[1][4:] for event in channel.events if event[0] == "write"],
                [b"\x27\3ab", b"\x27\4cc", b"\x10\2"],
            )
            self.assertEqual(
                [
                    event[1]
                    for event in channel.events
                    if event[0] == "wait" and event[1]
                ],
                [100, 100] + tail,
            )
            self.assertEqual(channel.events.count(("mask",)), 1)
        for secondary in (False, True):
            channel = DiagnosticChannel(
                (b"\x67\x61" + b"\0" * 6, b"\x67\x62\x34", b"\x50")
            )
            body_security_session(channel, b"\0" * 6, secondary, padding=False)
            self.assertEqual(channel.events.count(("mask",)), 0 if secondary else 1)
            self.assertEqual(
                [event[1][4:] for event in channel.events if event[0] == "write"],
                [
                    b"\x27\x61",
                    b"\x27\x62" + b"\0" * 6,
                    b"\x10\x60" if secondary else b"\x10\2",
                ],
            )

    def test_body_mode_and_external_switch_preserve_actual_primitive_fields(self):
        from scripts.cuw_legacy_engine import ExecutableIO, ExecutableJ2534Error
        from scripts.programming import NativeTransportError

        for secondary, request, code in (
            (False, b"\x10\2", 18),
            (True, b"\x10\x60", 49),
        ):
            channel = DiagnosticChannel((b"\x50",))
            body_change_mode(channel, secondary, padding=False)
            self.assertEqual(channel.events[0], ("write", channel.request + request))
            with self.assertRaises(BodyOperationError) as caught:
                body_change_mode(
                    DiagnosticChannel((b"invalid",)), secondary, padding=False
                )
            self.assertEqual(caught.exception.code, code)
        events = []
        io = ExecutableIO(lambda event, remaining: events.append(event.copy()))
        for value in (True, False):
            body_mode_switch(io, value)
        self.assertEqual(
            events,
            [
                {
                    "operation": "ioctl",
                    "ioctl_id": 2,
                    "input": {"num_params": 1, "config": ((30, value),)},
                    "output": None,
                }
                for value in (1, 0)
            ],
        )

        def fail(event, remaining):
            raise NativeTransportError(9)

        with self.assertRaises(ExecutableJ2534Error) as caught:
            body_mode_switch(ExecutableIO(fail), True)
        self.assertEqual(
            (caught.exception.native_code, caught.exception.driver_status), (1, 9)
        )

    def test_four_byte_family_preparation_cpu_mask_and_repeated_session(self):
        rounds = (b"\0\0",) * 4
        for kind, prepare, suffix, mask_count, waits, repeats in (
            (
                "epb",
                lambda c: epb_prepare(c, rounds, padding=False),
                b"\0",
                1,
                [100, 100],
                1,
            ),
            (
                "chassis",
                lambda c: chassis_prepare_cpu(c, rounds, 2, padding=False),
                b"\2",
                1,
                [100, 100],
                1,
            ),
            (
                "old_first",
                lambda c: old_ecb_prepare_cpu(c, rounds, 1, first=True, padding=False),
                b"\1",
                1,
                [100],
                1,
            ),
            (
                "old_second",
                lambda c: old_ecb_prepare_cpu(c, rounds, 0, first=False, padding=False),
                b"\0",
                0,
                [100],
                1,
            ),
            (
                "fc",
                lambda c: fc_prepare(c, rounds, repeat_session=False, padding=False),
                b"",
                1,
                [100, 100],
                1,
            ),
            (
                "fc_repeat",
                lambda c: fc_prepare(c, rounds, repeat_session=True, padding=False),
                b"",
                1,
                [100, 100, 110],
                2,
            ),
        ):
            with self.subTest(kind=kind):
                channel = DiagnosticChannel(
                    (b"\x67\1abcd", b"\x67\2") + (b"\x50",) * repeats
                )
                prepare(channel)
                writes = [
                    event[1][4:] for event in channel.events if event[0] == "write"
                ]
                self.assertEqual(
                    writes, [b"\x27\1" + suffix, b"\x27\2abcd"] + [b"\x10\2"] * repeats
                )
                self.assertEqual(channel.events.count(("mask",)), mask_count)
                self.assertEqual(
                    [
                        event[1]
                        for event in channel.events
                        if event[0] == "wait" and event[1]
                    ],
                    waits,
                )

    def test_sonar_retries_only_native_seed_error_with_reversed_access_word(self):
        channel = DiagnosticChannel((b"invalid", b"\x67\x03\0\0\x34", b"\x67\x04\x34"))
        sonar_security(channel, b"ab", b"cd", padding=False)
        self.assertEqual(
            [event[1][4:] for event in channel.events if event[0] == "write"],
            [b"\x27\x03ab", b"\x27\x03ba", b"\x27\x04cc"],
        )
        self.assertEqual(
            [event for event in channel.events if event == ("wait", 100)],
            [("wait", 100)] * 2,
        )
        for error in (InterruptedError("cancel"), ValueError("provider")):
            channel = DiagnosticChannel((error,))
            with self.assertRaises(type(error)):
                sonar_security(channel, b"ab", b"cd", padding=False)
            self.assertEqual(sum(event[0] == "write" for event in channel.events), 1)
        channel = DiagnosticChannel((b"\x67\x03\0\0\x34", b"invalid"))
        with self.assertRaises(BodyOperationError) as caught:
            sonar_security(channel, b"ab", b"cd", padding=False)
        self.assertEqual(caught.exception.code, 17)
        self.assertEqual(sum(event[0] == "write" for event in channel.events), 2)

    def test_four_round_conversion_keeps_native_half_rotation(self):
        self.assertEqual(
            convert_seed(bytes.fromhex("01020304"), (b"\0\0",) * 4),
            bytes.fromhex("01020304"),
        )
        self.assertEqual(
            convert_seed(
                bytes.fromhex("01020304"),
                (
                    bytes.fromhex("1020"),
                    bytes.fromhex("3040"),
                    bytes.fromhex("5060"),
                    bytes.fromhex("7080"),
                ),
            ),
            bytes.fromhex("414243c4"),
        )
        with self.assertRaises(ValueError):
            convert_seed(b"abc", (b"xx",) * 4)

    def test_two_byte_subtract_and_six_byte_sequential_transform(self):
        self.assertEqual(airbag_seed_key(b"\0\0", b"\0\0"), b"\xff\xff")
        self.assertEqual(
            airbag_seed_key(bytes.fromhex("1234"), bytes.fromhex("5678")),
            bytes.fromhex("4443"),
        )
        seed = bytes((1, 6, 7, 128, 255, 2))
        self.assertEqual(body_seed_key(seed, b"\0" * 6), bytes.fromhex("0a3aaa0b39ba"))
        self.assertEqual(
            body_seed_key(seed, b"\x20" * 6), bytes.fromhex("0a3aaa0b39ba")
        )

    def test_family_security_requests_and_minimum_responses(self):
        cases = (
            (
                lambda channel: airbag_security(channel, b"ab", b"cd", padding=False),
                (b"\x67\x03\0\0\x34", b"\x67\x04\x34"),
                [b"\x27\x03ab", b"\x27\x04cc"],
            ),
            (
                lambda channel: body_security(channel, b"\0" * 6, padding=False),
                (b"\x67\x61" + b"\0" * 6, b"\x67\x62\x34"),
                [b"\x27\x61", b"\x27\x62" + b"\0" * 6],
            ),
            (
                lambda channel: four_byte_security(
                    channel, (b"\0\0",) * 4, padding=False
                ),
                (b"\x67\x01abcd", b"\x67\x02"),
                [b"\x27\x01", b"\x27\x02abcd"],
            ),
        )
        for operation, responses, expected in cases:
            channel = DiagnosticChannel(responses)
            operation(channel)
            self.assertEqual(
                [event[1][4:] for event in channel.events if event[0] == "write"],
                expected,
            )
        channel = DiagnosticChannel((b"\x67\x03\0\0x",))
        with self.assertRaises(BodyOperationError) as caught:
            airbag_security(channel, b"ab", b"cd", padding=False)
        self.assertEqual(caught.exception.native_code, 16)
        channel = DiagnosticChannel(())
        with self.assertRaises(ValueError):
            body_security(channel, b"xx", padding=False)
        self.assertEqual(channel.events, [])

    def test_epc_security_and_session_delay_chronology(self):
        class EPCChannel(DiagnosticChannel):
            def diagnostic_mask(self):
                self.events.append(("mask",))

        for seed, key in ((0, 255), (5, 4)):
            channel = EPCChannel((b"\x67\x01" + bytes((seed,)), b"\x67\x02", b"\x50"))
            epc_prepare(channel, padding=False)
            self.assertEqual(
                [event[1][4:] for event in channel.events if event[0] == "write"],
                [b"\x27\x01", b"\x27\x02" + bytes((key,)), b"\x10\x02"],
            )
            self.assertEqual(
                [event for event in channel.events if event[0] in ("wait", "mask")],
                [
                    ("wait", 0),
                    ("wait", 100),
                    ("wait", 0),
                    ("wait", 100),
                    ("mask",),
                    ("wait", 0),
                    ("wait", 300),
                ],
            )


class EPCTransferTests(unittest.TestCase):
    def test_native_failure_progress_reset_preserves_other_cpu_and_copy_order(self):
        from scripts.cuw_legacy_can import CANProgress
        from scripts.cuw_legacy_engine import ExecutableIO

        events = []
        progress = CANProgress(
            ExecutableIO(lambda event, remaining: events.append(event.copy())),
            (200, 200),
        )
        progress.counts[:] = [100, 200]
        progress.percentages[:] = [25, 50]
        epc_reset_progress(progress, 1)
        self.assertEqual(progress.counts, [100, 0])
        self.assertEqual(progress.percentages, [25, 0])
        self.assertEqual(
            events,
            [
                {
                    "operation": "notification",
                    "field": "writing_bytes",
                    "values": (100, 0),
                },
                {
                    "operation": "notification",
                    "field": "writing_percent",
                    "values": (25, 0),
                },
            ],
        )

    def test_imported_authored_cpu_composes_raw_transfer_and_retains_uncertain_state(
        self,
    ):
        self._run_transfer(False)
        self._run_transfer(True)

    def test_native_partial_block_copy_is_rejected_before_first_io(self):
        self._run_transfer(False, bad_geometry=True)

    def test_full_epc_execute_uses_raw_diagnostic_and_transfer_primitives(self):
        self._run_transfer(False, full_controller=True)
        self._run_transfer(True, full_controller=True)

    def test_full_epb_execute_retains_native_distinctions(self):
        self._run_transfer(False, full_controller=True, epb=True)
        self._run_transfer(True, full_controller=True, epb=True)

    def test_full_chassis_execute_raw_grouped_transfer_and_cancellation(self):
        self._run_transfer(False, full_controller=True, chassis=True)
        self._run_transfer(True, full_controller=True, chassis=True)

    def test_full_old_ecb_execute_raw_groups_and_cancellation(self):
        self._run_transfer(False, full_controller=True, old_ecb=True)
        self._run_transfer(True, full_controller=True, old_ecb=True)

    def test_full_body_execute_raw_security_blocks_and_cancellation(self):
        self._run_transfer(False, full_controller=True, body=True)
        self._run_transfer(True, full_controller=True, body=True)

    def test_full_dss_execute_raw_security_blocks_and_cancellation(self):
        self._run_transfer(False, full_controller=True, dss1=True)
        self._run_transfer(True, full_controller=True, dss1=True)

    def test_full_airbag_execute_raw_security_blocks_and_cancellation(self):
        self._run_transfer(False, full_controller=True, airbag=True)
        self._run_transfer(True, full_controller=True, airbag=True)

    def test_full_fc_execute_raw_security_groups_and_cancellation(self):
        self._run_transfer(False, full_controller=True, fc=True)
        self._run_transfer(True, full_controller=True, fc=True)

    def test_full_sonar_execute_raw_security_groups_and_cancellation(self):
        self._run_transfer(False, full_controller=True, sonar=True)
        self._run_transfer(True, full_controller=True, sonar=True)

    def _run_transfer(
        self,
        cancel,
        *,
        bad_geometry=False,
        full_controller=False,
        epb=False,
        chassis=False,
        old_ecb=False,
        sonar=False,
        fc=False,
        body=False,
        dss1=False,
        airbag=False,
    ):
        # Authored CUW fixture and synthetic geometry: this is not source-PE admission.
        from dataclasses import replace
        from unittest.mock import patch

        from scripts.cuw_legacy_can import CANProgress, CommonCAN, location_headers
        from scripts.cuw_legacy_engine import ExecutableIO
        from scripts.j2534_2026 import NativeMessage
        from tests.test_cuw_legacy_engine import imported_context

        class Tables:
            def __init__(self, context):
                pass

            def sizes(self, kind, cpu_type):
                return (1, 1023) if bad_geometry else (1024,)

            def epc_cpu_matches(self, cpu_type, firmware_id):
                return firmware_id == 0x70

            def identified(self, kind, cpu_type, firmware_id, wide):
                return firmware_id == 0x70

            def descriptor(self, kind, cpu_type):
                return CPUDescriptor(0x70, True, False, 0, False)

            def body_shift_operands(self):
                return bytes(6)

            def two_byte_passwords(self, kind, ecu_kind):
                return bytes(2), bytes(2)

            def sonar_passwords(self):
                return b"\0\0", b"\0\0"

            def sonar_cpu(self, cpu_type):
                return 0x70, False

            def _name(self, address):
                return "syntheticCPU"

            def ranges(self, kind, cpu_type, count):
                return ((1, 1),)

            def preparation_cpu_selectors(self, kind, ecu_kind, address_count):
                return (0,)

            def four_round_operands(self, kind, cpu_type=""):
                return (b"\0\0",) * 4

        context = replace(
            imported_context(),
            controller="CCanBodyFlashWriter"
            if body
            else "CCanDSS1FlashWriter"
            if dss1
            else "CCanAirbagFlashWriter"
            if airbag
            else "CCanFCFlashWriter"
            if fc
            else "CCanClearanceSonarFlashWriter"
            if sonar
            else "CCanOldSpecECBFlashWriter"
            if old_ecb
            else "CCanChassisShrinkFlashWriter"
            if chassis
            else "CCanEPBFlashWriter"
            if epb
            else "CCanElectricPowerControlFlashWriter",
            cpu_types=("syntheticCPU",),
            observations={"observed_cids": ("DEMO-OLD",)},
        )
        context.state.native_cpu_type_ee0 = "syntheticCPU"
        # Authored target0 RAM shared by all fixture controllers.
        context.state.target_indices = (0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        assert context.native.location_id is not None
        tx, rx = location_headers(context.native.location_id)
        frames = []
        events = []
        identification = [0]
        filter_ids = [0]
        address_next = [False]

        def receive(payload, rx_status=0):
            frames.append(NativeMessage(6, rx + payload, rx_status=rx_status))

        def action(event, remaining):
            events.append(event.copy())
            operation = event["operation"]
            if operation == "write_messages":
                if "messages" in event:
                    frames.append(NativeMessage(6, tx, rx_status=9))
                    identification[0] = 5
                    receive(b"\x3c")
                    receive(b"", 2)
                    receive(b"\0")
                    return event["count"]
                payload = event["data"][4:]
                frames.append(NativeMessage(6, event["data"][:4], rx_status=9))
                if full_controller and payload in (
                    b"\x27\x03\0\0",
                    b"\x27\x04\xff\xff",
                    b"\x27\x01",
                    b"\x27\x02\x02",
                    b"\x27\x01\0",
                    b"\x27\x02" + bytes(4),
                    b"\x10\x02",
                    b"\x27\x61",
                    b"\x27\x62" + bytes(6),
                ):
                    receive(
                        {
                            b"\x27\x03\0\0": b"\x67\x03\0\0\x34",
                            b"\x27\x04\xff\xff": b"\x67\x04\x34",
                            b"\x27\x01": b"\x67\x01" + (bytes(4) if fc else b"\x03"),
                            b"\x27\x01\0": b"\x67\x01" + bytes(4),
                            b"\x27\x02" + bytes(4): b"\x67\x02",
                            b"\x27\x02\x02": b"\x67\x02",
                            b"\x10\x02": b"\x50",
                            b"\x27\x61": b"\x67\x61" + bytes(6),
                            b"\x27\x62" + bytes(6): b"\x67\x62\x34",
                        }[payload]
                    )
                elif full_controller and payload == b"\xa0\x27":
                    pass
                elif identification[0] < 5:
                    identification[0] += 1
                    if identification[0] == 5:
                        receive(b"\x3c")
                        receive(b"", 2)
                        receive(b"\0")
                elif payload == b"\x3c":
                    pass
                elif payload == b"\x76":
                    receive(b"\x3c")
                    receive(b"", 2)
                    receive(b"\0\0\0\0\x03\xff\1\x70\0")
                    receive(b"\x3c")
                elif payload == b"\x75":
                    receive(b"\x3c")
                    receive(b"", 2)
                    receive(b"\0\0\0\0\x03\xff\1\x70")
                    receive(b"\x3c")
                elif fc and payload[:1] == b"\x36":
                    receive(b"\x3c")
                    receive(b"\0")
                elif payload == b"\x80" and (epb or chassis or old_ecb or fc):
                    pass
                elif payload == b"\x50":
                    for response in (b"\x3c", b"\0", b"\x3c"):
                        receive(response)
                elif address_next[0]:
                    address_next[0] = False
                else:
                    receive(b"\x3c")
                    if payload == b"\x41":
                        address_next[0] = True
                return 1
            if operation == "read_messages":
                return (frames.pop(0),)
            if operation == "get_timeout":
                return 5000
            if operation == "start_filter":
                filter_ids[0] += 1
                return filter_ids[0]
            if operation == "notification" and cancel:
                raise InterruptedError("synthetic cancellation")
            if operation not in {
                "notification",
                "controller_callback",
                "ioctl",
                "wait",
                "set_timeout",
                "set_send_timeout",
                "stop_filter",
            }:
                raise AssertionError(operation)
            return None

        io = ExecutableIO(action)
        from scripts.cuw_legacy_channel import ChannelState

        state = ChannelState(protocol=6, read_timeout=5000, padding=False)
        context = replace(
            context,
            observations={**context.observations, "legacy_channel_state": state},
        )
        channel = CommonCAN(
            io, tx, rx, padding=False, read_timeout_ms=5000, state=state
        )
        progress = CANProgress(io, (1024,))
        transfer = lambda: epc_write_cpu(context, channel, progress)
        if full_controller:
            from scripts.cuw_legacy_body import (
                AirbagController,
                BodyController,
                ChassisController,
                DSS1Controller,
                EPBController,
                EPCController,
                FCController,
                OldECBController,
                SonarController,
            )

            controller = object.__new__(
                BodyController
                if body
                else DSS1Controller
                if dss1
                else AirbagController
                if airbag
                else FCController
                if fc
                else SonarController
                if sonar
                else OldECBController
                if old_ecb
                else ChassisController
                if chassis
                else EPBController
                if epb
                else EPCController
            )
            controller.context, controller.io = context, io
            if fc or body or dss1 or airbag:
                controller.source = cast(
                    Any,
                    type(
                        "Source",
                        (),
                        {
                            "read": lambda self, address, size: (
                                (b"00000720\0" + bytes(23))
                                if size == 32
                                else bytes(size)
                            )
                        },
                    )(),
                )
            from scripts.cuw_legacy_body import functional_header

            controller.mask_header = functional_header(context)
            controller.channel = controller.prepare_channel = channel
            controller.progress = progress
            from scripts.cuw_legacy_addresses import CAddress

            controller.prepare_addresses = (CAddress(bytes(8)),)
            controller.entry_timeout = controller.saved_timeout = 5000
            if sonar:
                controller = cast(Any, controller)
                controller.saved_send_timeout = controller.entry_send_timeout = 1000
            controller.value_78 = controller.value_80 = 0
            controller.flag_68 = False
            controller.status_70 = 100
            controller.status = lambda index: 100 + index
            transfer = controller.run
        from scripts.cuw_legacy_addresses import CAddress

        with (
            patch("scripts.cuw_legacy_body.BodyTables", Tables),
            patch(
                "scripts.cuw_legacy_addresses.legacy_address_inputs",
                return_value=("24", None, False, None),
            ),
            patch(
                "scripts.cuw_legacy_addresses.select_legacy_addresses",
                return_value=(CAddress(b"\0" + tx[2:] + b"\0" + rx[2:] + bytes(2)),),
            ),
        ):
            if bad_geometry:
                with self.assertRaises(ValueError):
                    transfer()
                self.assertEqual(events, [])
                self.assertFalse(context.state.native_flag_ed8)
                return
            if cancel:
                with self.assertRaises(InterruptedError):
                    transfer()
                self.assertEqual(
                    context.state.native_flag_ed8,
                    not (epb or chassis or old_ecb or sonar or fc or airbag),
                )
                self.assertEqual(
                    context.state.native_flag_ed6,
                    not (epb or chassis or old_ecb or sonar or fc or airbag),
                )
            else:
                transfer()
                self.assertFalse(context.state.native_flag_ed8)
                self.assertFalse(context.state.native_flag_ed6)
                self.assertEqual(progress.counts, [2048])
                self.assertEqual(progress.percentages, [100])
                self.assertEqual(
                    next(
                        event
                        for event in events
                        if event.get("callback") == ("completion" if fc else "flag_88")
                    ),
                    {
                        "operation": "controller_callback",
                        **(
                            {"callback": "completion", "outcome": "success"}
                            if fc
                            else {"callback": "flag_88", "value": False}
                        ),
                    },
                )
        writes = [
            event["data"][4:]
            for event in events
            if event["operation"] == "write_messages" and "data" in event
        ]
        self.assertIn(
            b"\x36\0\0\0\0"
            if fc
            else b"\x26\0\0\0\0"
            if chassis or old_ecb or sonar or body or dss1 or airbag
            else b"\x25\0",
            writes,
        )
        self.assertIn(b"\x41", writes)
        if cancel:
            self.assertNotIn(b"\x80", writes)
        else:
            self.assertEqual(
                (
                    b"\x48\0\0\0\0"
                    if chassis or old_ecb or sonar or fc or body or dss1 or airbag
                    else b"\x47\0"
                )
                in writes,
                not epb,
            )
            self.assertEqual(writes[-1], b"\x80")
            self.assertEqual(frames, [])


class EPCExecuteTests(unittest.TestCase):
    def controller(self, *, writing=False, prepare_error=None, retry=()):
        from dataclasses import replace

        from scripts.cuw_legacy_body import EPCController
        from scripts.cuw_legacy_can import CANProgress, CommonCAN, location_headers
        from scripts.cuw_legacy_engine import ExecutableIO
        from tests.test_cuw_legacy_engine import imported_context

        events = []
        answers = iter(retry)
        handles = [0]

        def action(event, remaining):
            events.append(event.copy())
            if event["operation"] == "start_filter":
                handles[0] += 1
                return handles[0]
            if (
                event["operation"] == "controller_callback"
                and event["callback"] == "read_flag_88"
            ):
                return next(answers, False)
            return None

        context = replace(
            imported_context(), controller="CCanElectricPowerControlFlashWriter"
        )
        context.state.native_flag_ed8 = writing
        controller = object.__new__(EPCController)
        controller.context = context
        from scripts.cuw_legacy_body import functional_header

        controller.mask_header = functional_header(context)
        controller.io = ExecutableIO(action)
        assert context.native.location_id is not None
        tx, rx = location_headers(context.native.location_id)
        controller.channel = CommonCAN(
            controller.io, tx, rx, padding=False, read_timeout_ms=73
        )
        controller.prepare_channel = controller.channel
        controller.progress = CANProgress(controller.io, (1024,))
        controller.saved_timeout, controller.entry_timeout = 41, 73
        controller.value_78 = controller.value_80 = 0
        controller.flag_68 = False
        controller.status_70 = 100
        controller.status = lambda index: 100 + index
        return controller, events

    def test_prepare_typed_failure_skips_transfer_unless_writing_latch_is_set(self):
        from unittest.mock import patch

        from scripts.cuw_legacy_engine import ExecutableJ2534Error

        for writing in (False, True):
            with self.subTest(writing=writing):
                controller, events = self.controller(writing=writing)
                with (
                    patch(
                        "scripts.cuw_legacy_body.epc_prepare",
                        side_effect=ExecutableJ2534Error(16, 9),
                    ),
                    patch("scripts.cuw_legacy_body.epc_write_cpu") as transfer,
                ):
                    result = controller.run()
                self.assertEqual(transfer.call_count, int(writing))
                self.assertEqual(result["native_success"], writing)
                self.assertEqual(result["native_value_78"], 16)
                self.assertEqual(result["native_value_80"], 9)
                self.assertEqual(
                    [
                        event["filter_id"]
                        for event in events
                        if event["operation"] == "stop_filter"
                    ],
                    [1, 2] if writing else [1],
                )
                self.assertEqual(
                    events[-1]["outcome"], "success" if writing else "failure"
                )
                self.assertEqual(
                    [
                        event["milliseconds"]
                        for event in events
                        if event["operation"] == "set_timeout"
                    ],
                    [5000, 41] if writing else [41],
                )

    def test_stop_scope_swallows_native_foreign_but_propagates_host_faults(self):
        from unittest.mock import patch

        from scripts.cuw_legacy_engine import ExecutableForeignNativeError

        controller, _events = self.controller()
        with patch(
            "scripts.cuw_legacy_engine.executable_stop_filter",
            side_effect=ExecutableForeignNativeError("native"),
        ):
            controller.stop_filter(1)
        with (
            patch(
                "scripts.cuw_legacy_engine.executable_stop_filter",
                side_effect=OSError("host"),
            ),
            self.assertRaises(OSError),
        ):
            controller.stop_filter(1)

    def test_saved_recovery_writing_does_not_substitute_for_manager_ed8(self):
        from unittest.mock import patch

        controller, _events = self.controller()
        controller.context.state.writing = True
        controller.context.state.writing_end_block = True
        with (
            patch(
                "scripts.cuw_legacy_body.epc_prepare",
                side_effect=BodyOperationError(16, "seed"),
            ),
            patch("scripts.cuw_legacy_body.epc_write_cpu") as transfer,
        ):
            result = controller.run()
        self.assertFalse(result["native_success"])
        transfer.assert_not_called()
        self.assertTrue(controller.context.state.writing)
        self.assertTrue(controller.context.state.writing_end_block)
        self.assertFalse(controller.context.state.native_flag_ed8)
        self.assertFalse(controller.context.state.native_flag_ed6)

    def test_transfer_native_fault_resets_progress_and_updates_password_latch(self):
        from unittest.mock import patch

        controller, events = self.controller()
        controller.progress.counts[0] = 1024
        controller.progress.percentages[0] = 50

        def failure(*args):
            controller.context.state.native_flag_ed8 = True
            controller.context.state.native_flag_ed6 = True
            raise BodyOperationError(13, "synthetic transfer")

        with (
            patch("scripts.cuw_legacy_body.epc_prepare"),
            patch("scripts.cuw_legacy_body.epc_write_cpu", side_effect=failure),
        ):
            result = controller.run()
        self.assertFalse(result["native_success"])
        self.assertTrue(controller.context.state.use_new_software_password)
        self.assertTrue(controller.context.state.native_flag_ed8)
        self.assertEqual(controller.progress.counts, [0])
        self.assertEqual(controller.progress.percentages, [0])
        self.assertEqual(
            [event["value"] for event in events if event.get("callback") == "value_70"],
            [102],
        )

    def test_host_abort_releases_filter_and_restores_entry_timeout_without_completion(
        self,
    ):
        from unittest.mock import patch

        controller, events = self.controller()

        def interrupted(*args):
            controller.context.state.native_flag_ed8 = True
            raise InterruptedError("host stop")

        with (
            patch("scripts.cuw_legacy_body.epc_prepare"),
            patch("scripts.cuw_legacy_body.epc_write_cpu", side_effect=interrupted),
            self.assertRaises(InterruptedError),
        ):
            controller.run()
        self.assertTrue(controller.context.state.native_flag_ed8)
        self.assertEqual(
            [
                event["milliseconds"]
                for event in events
                if event["operation"] == "set_timeout"
            ],
            [5000, 73],
        )
        self.assertEqual(
            [
                event["filter_id"]
                for event in events
                if event["operation"] == "stop_filter"
            ],
            [1, 2],
        )
        self.assertFalse(any(event.get("callback") == "completion" for event in events))

    def test_epb_native_failure_keeps_password_and_writing_flags_and_resets_only_cache(
        self,
    ):
        from dataclasses import replace
        from unittest.mock import patch

        from scripts.cuw_legacy_body import EPBController

        controller, events = self.controller()
        controller.__class__ = EPBController
        controller.context = replace(
            controller.context, controller="CCanEPBFlashWriter"
        )
        controller.context.state.use_new_software_password = True
        controller.progress.counts[0] = 200
        controller.progress.percentages[0] = 10
        with (
            patch.object(controller, "prepare", return_value=False),
            patch(
                "scripts.cuw_legacy_body.epb_write_cpu",
                side_effect=BodyOperationError(7, "ID"),
            ),
        ):
            result = controller.run()
        self.assertFalse(result["native_success"])
        self.assertTrue(controller.context.state.use_new_software_password)
        self.assertFalse(controller.context.state.native_flag_ed8)
        self.assertFalse(controller.context.state.native_flag_ed6)
        self.assertEqual(controller.progress.counts, [0])
        self.assertEqual(controller.progress.percentages, [0])
        self.assertFalse(any(event["operation"] == "notification" for event in events))
        self.assertEqual(
            [
                event["milliseconds"]
                for event in events
                if event["operation"] == "set_timeout"
            ],
            [120000, 73],
        )

    def test_unknown_family_rejected_before_io(self):
        from scripts.cuw_legacy_body import execute
        from scripts.cuw_legacy_engine import ExecutableIO
        from tests.test_cuw_legacy_engine import imported_context

        events = []
        with self.assertRaises(ValueError):
            execute(
                imported_context(),
                ExecutableIO(lambda event, remaining: events.append(event)),
            )
        self.assertEqual(events, [])


class ChassisExecuteTests(unittest.TestCase):
    def controller(self) -> tuple[Any, list[dict]]:
        from dataclasses import replace

        from scripts.cuw_legacy_body import ChassisController
        from scripts.cuw_legacy_can import CANProgress

        controller, events = EPCExecuteTests().controller()
        controller.__class__ = ChassisController
        raw0 = controller.context.native.selected
        raw1 = replace(raw0, index=1)
        raws = (raw0, raw1)
        native0 = replace(controller.context.native, cpus=raws)
        native1 = replace(native0, selected=raw1)
        controller.context = replace(
            controller.context,
            controller="CCanChassisShrinkFlashWriter",
            native=native0,
            cpus=(native0, native1),
        )
        controller.progress = CANProgress(controller.io, (1024, 1024))
        return controller, events

    def test_second_cpu_native_failure_retains_first_cpu_progress_and_callback(self):
        from unittest.mock import patch

        controller, events = self.controller()
        channel = controller.channel

        def transfer(native):
            index = native.selected.index
            controller.progress.counts[index] = 1024
            controller.progress.percentages[index] = 50
            controller.end_block = index == 0
            if index:
                raise BodyOperationError(13, "second CPU")

        with (
            patch.object(controller, "prepare", return_value=False),
            patch.object(controller, "channel_for_cpu", return_value=channel),
            patch.object(controller, "transfer_cpu", side_effect=transfer),
            patch.object(channel, "change_cpu"),
        ):
            result = controller.run()
        self.assertFalse(result["native_success"])
        self.assertEqual(result["completed_cpu_indices"], [0])
        self.assertEqual(controller.progress.counts, [1024, 0])
        self.assertEqual(controller.progress.percentages, [50, 0])
        self.assertEqual(
            [
                event["outcome"]
                for event in events
                if event.get("callback") == "completion"
            ],
            ["success", "failure"],
        )
        self.assertFalse(controller.context.state.writing)
        self.assertFalse(controller.context.state.writing_end_block)

    def test_host_abort_after_completed_cpu_does_not_emit_final_success(self):
        from unittest.mock import patch

        controller, events = self.controller()
        channel = controller.channel

        def transfer(native):
            if native.selected.index:
                raise InterruptedError("second CPU host stop")

        with (
            patch.object(controller, "prepare", return_value=False),
            patch.object(controller, "channel_for_cpu", return_value=channel),
            patch.object(controller, "transfer_cpu", side_effect=transfer),
            patch.object(channel, "change_cpu"),
            self.assertRaises(InterruptedError),
        ):
            controller.run()
        self.assertEqual(
            [
                event["outcome"]
                for event in events
                if event.get("callback") == "completion"
            ],
            ["success"],
        )
        self.assertEqual(
            [
                event["filter_id"]
                for event in events
                if event["operation"] == "stop_filter"
            ],
            [1, 2],
        )
        self.assertEqual(
            [
                event["milliseconds"]
                for event in events
                if event["operation"] == "set_timeout"
            ][-1],
            73,
        )


class OldECBProgressTests(unittest.TestCase):
    def test_native_retry_progress_uses_previous_range_and_multiplies_by_two(self):
        from dataclasses import replace

        from scripts.cuw_legacy_body import OldECBController
        from scripts.cuw_legacy_can import CANProgress

        controller, events = EPCExecuteTests().controller()
        controller = cast(Any, controller)
        controller.__class__ = OldECBController
        native = replace(
            controller.context.native,
            image=replace(controller.context.native.image, data=bytes(16384)),
        )
        controller.progress = CANProgress(controller.io, (16384,))
        controller.block_sizes = (1024,) * 16
        controller.block_ranges = ((1, 10), (11, 16))
        controller.range_index = 1
        controller.restore_progress(native)
        self.assertEqual(controller.progress.counts, [20480])
        self.assertEqual(controller.progress.percentages, [250])
        self.assertEqual(
            [event["field"] for event in events], ["writing_bytes", "writing_percent"]
        )


class CGWTests(unittest.TestCase):
    def test_private_encoded_source_key_uses_literal_aes128_ecb(self):
        from dataclasses import replace
        from unittest.mock import patch

        from scripts.cuw_legacy_body import central_gw_seed_key
        from scripts.cuw_legacy_recovery import encode_recovery_text
        from tests.test_cuw_legacy_engine import imported_context

        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        seed = bytes.fromhex("00112233445566778899aabbccddeeff")
        encoded = encode_recovery_text(key.hex().encode("ascii")) + bytes(4)
        addresses = []

        class Image:
            def __init__(self, context):
                pass

            def read(self, address, length):
                addresses.append(address)
                return encoded[:length]

        with patch("scripts.cuw_legacy_engine.ExecutableImage", Image):
            for build in (12, 18):
                for mode in (False, True):
                    result = central_gw_seed_key(
                        replace(imported_context(), build=build),
                        seed,
                        reprogramming=mode,
                    )
                    self.assertEqual(result.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(addresses, [0x5CD75C, 0x5CD718, 0x629C84, 0x629C40])

    def test_cgw_process_feature_rejects_missing_and_caller_boolean(self):
        from dataclasses import replace

        from scripts.cuw_legacy_body import central_gw_exists
        from tests.test_cuw_legacy_engine import imported_context

        for observations in ({}, {"legacy_cgw_state": True}):
            with self.assertRaises(TypeError):
                central_gw_exists(
                    replace(imported_context(), observations=observations)
                )

    def test_source_decoder_and_legacy_diagnostic_precede_cgw_feature_publication(self):
        from scripts.cuw_legacy_body import _cgw_detect_variant
        from scripts.cuw_legacy_can import CommonCAN
        from scripts.cuw_legacy_channel import ChannelState
        from scripts.cuw_legacy_engine import ExecutableIO
        from scripts.j2534_2026 import NativeMessage
        from scripts.programming import NativeTransportError

        for first in (b"\x7e", b"\x7f\x3e\x11", 9):
            frames = []
            writes = []
            request = bytes.fromhex("00000750e9")
            response = bytes.fromhex("00000758e9")

            def action(
                event,
                remaining,
                *,
                writes=writes,
                first=first,
                frames=frames,
                request=request,
                response=response,
            ):
                operation = event["operation"]
                if operation == "write_messages":
                    payload = event["data"][5:]
                    writes.append(payload)
                    if payload == b"\x3e" and first == 9:
                        raise NativeTransportError(9)
                    frames.append(NativeMessage(6, request, rx_status=9))
                    answer = first if payload == b"\x3e" else b"\x7e\0"
                    assert isinstance(answer, bytes)
                    frames.append(NativeMessage(6, response + answer))
                    return 1
                if operation == "read_messages":
                    return (frames.pop(0),)
                if operation not in ("wait", "set_timeout", "ioctl"):
                    raise AssertionError(operation)
                return None

            io = ExecutableIO(action)
            channel = CommonCAN(
                io, request, response, padding=False, state=ChannelState(protocol=6)
            )
            state = cast(Any, type("State", (), {"double_driver_fault": False})())
            result = _cgw_detect_variant(channel, state)
            self.assertEqual(result, 2 if first == b"\x7e" else 1)
            self.assertEqual(writes, [b"\x3e"] if result == 2 else [b"\x3e", b"\x3e\0"])
            self.assertEqual(frames, [])


class BodyCheckIDRetryTests(unittest.TestCase):
    def context(self):
        from dataclasses import replace

        from tests.test_cuw_legacy_engine import imported_context

        context = replace(imported_context(), cpu_types=("syntheticCPU",))
        context.state.target_indices = (0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        context.state.native_cpu_type_ee0 = "syntheticCPU"
        return context

    def test_airbag_retries_only_cpass7_and_reloads_password_after2000ms(self):
        from unittest.mock import patch

        from scripts.cuw_legacy_body import AirbagController
        from scripts.cuw_legacy_engine import ExecutableIO, executable_selected_password

        context = self.context()
        context.state.use_new_software_password = True
        controller = object.__new__(AirbagController)
        controller.context = context
        controller.io = ExecutableIO(lambda event, remaining: None)
        controller.started = True
        controller.value_78 = 0
        passwords, waits = [], []

        class Channel:
            def check_id(self, location, password, **kwargs):
                passwords.append(password)
                if len(passwords) == 1:
                    raise BodyOperationError(7, "authored ID negative")

            def wait(self, milliseconds):
                waits.append(milliseconds)

            def memory(self, **kwargs):
                raise InterruptedError("stop after source ID scope")

        class Tables:
            def __init__(self, context):
                pass

            def sizes(self, kind, cpu_type):
                return (1024,)

        controller.channel = cast(Any, Channel())
        with (
            patch("scripts.cuw_legacy_body.BodyTables", Tables),
            self.assertRaises(InterruptedError),
        ):
            controller.transfer_cpu(context.native)
        self.assertEqual(waits, [2000])
        self.assertEqual(len(passwords), 2)
        self.assertEqual(passwords[-1], executable_selected_password(context))
        self.assertFalse(context.state.use_new_software_password)
        self.assertEqual(controller.value_78, 7)

    def test_airbag_check_id_does_not_retry_other_cpass_or_cj_categories(self):
        from unittest.mock import patch

        from scripts.cuw_legacy_body import AirbagController
        from scripts.cuw_legacy_engine import ExecutableJ2534Error

        class Tables:
            def __init__(self, context):
                pass

            def descriptor(self, kind, cpu_type):
                return CPUDescriptor(0, True, False, 0, False)

            def sizes(self, kind, cpu_type):
                return (1024,)

        for error in (
            BodyOperationError(8, "authored CP8"),
            ExecutableJ2534Error(7, 9),
        ):
            with self.subTest(error=type(error).__name__):
                controller = object.__new__(AirbagController)
                controller.context, controller.started = self.context(), True
                controller.value_78 = 0
                controller.channel = cast(Any, type("Channel", (), {})())
                with (
                    patch("scripts.cuw_legacy_body.BodyTables", Tables),
                    patch.object(
                        controller.channel, "check_id", side_effect=error, create=True
                    ) as check,
                    self.assertRaises(type(error)) as caught,
                ):
                    controller.transfer_cpu(controller.context.native)
                self.assertIs(caught.exception, error)
                self.assertEqual(check.call_count, 1)

    def test_original_location_text_ignores_strict_dll_row_and_preserves_foreign(self):
        from dataclasses import replace

        from scripts.cuw_legacy_body import _original_cpu_location, functional_header
        from scripts.cuw_legacy_can import location_headers
        from scripts.cuw_legacy_engine import ExecutableForeignNativeError

        context = self.context()
        for text, expected in (
            ("", bytes(8)),
            ("98", b"\x98" + bytes(7)),
            ("0108010000000720", bytes.fromhex("0108010000000720")),
        ):
            with self.subTest(text=text):
                selected = replace(
                    context.native.selected,
                    values={**context.native.selected.values, "locationid": text},
                )
                native = replace(context.native, selected=selected, location_id=None)
                changed = replace(context, native=native, cpus=(native,))
                self.assertEqual(_original_cpu_location(native), expected)
                self.assertEqual(functional_header(changed), b"\0\0" + expected[6:8])
                self.assertEqual(
                    location_headers(_original_cpu_location(native)),
                    (b"\0\0" + expected[2:4], b"\0\0" + expected[:2]),
                )
        for text in ("216", "GG"):
            selected = replace(
                context.native.selected,
                values={**context.native.selected.values, "locationid": text},
            )
            with self.assertRaises(ExecutableForeignNativeError):
                _original_cpu_location(
                    replace(context.native, selected=selected, location_id=None)
                )

    def test_native_category_signed_byte_publishes_sign_extended_dword(self):
        from scripts.cuw_legacy_body import EPCController
        from scripts.cuw_legacy_engine import ExecutableJ2534Error

        controller = object.__new__(EPCController)
        for code, expected in (
            (127, 127),
            (128, 0xFFFFFF80),
            (255, 0xFFFFFFFF),
            (-1, 0xFFFFFFFF),
        ):
            for error in (
                BodyOperationError(code, "authored signed category"),
                ExecutableJ2534Error(code if code < 128 else code - 256, 9),
            ):
                with self.subTest(code=code, error=type(error).__name__):
                    controller.value_78, controller.value_80 = 0, 123
                    controller.capture(error)
                    self.assertEqual(controller.value_78, expected)
                    self.assertEqual(
                        controller.value_80,
                        9 if isinstance(error, ExecutableJ2534Error) else 123,
                    )

    def test_body_check_id_uses_retained_first_factory_cpu_endian(self):
        from unittest.mock import patch

        from scripts.cuw_legacy_body import BodyController

        context = self.context()
        context.state.native_cpu_type_ee0 = "firstFactoryCPU"
        controller = object.__new__(BodyController)
        controller.context, controller.family = context, "body"
        swaps = []

        class Channel:
            def check_id(self, location, password, **kwargs):
                swaps.append(kwargs["swap_endian"])
                raise InterruptedError("stop before memory operation")

        class Tables:
            def __init__(self, context):
                pass

            def descriptor(self, kind, cpu_type):
                return CPUDescriptor(0, True, cpu_type == "firstFactoryCPU", 0, False)

            def sizes(self, kind, cpu_type):
                return (1024,)

        controller.channel = cast(Any, Channel())
        with (
            patch("scripts.cuw_legacy_body.BodyTables", Tables),
            self.assertRaises(InterruptedError),
        ):
            controller.transfer_cpu(context.native)
        self.assertEqual(swaps, [True])

    def test_body_native_catch_all_retries11_but_host_error_is_not_swallowed(self):
        from unittest.mock import patch

        from scripts.cuw_legacy_body import BodyController
        from scripts.cuw_legacy_engine import ExecutableForeignNativeError

        context = self.context()
        context.state.native_flag_ed8 = True
        controller = object.__new__(BodyController)
        controller.context = context
        controller.family = "body"
        calls = []

        class Channel:
            def check_id(self, location, password, **kwargs):
                calls.append(password)
                raise ExecutableForeignNativeError("authored native catch-all")

        class Tables:
            def __init__(self, context):
                pass

            def descriptor(self, kind, cpu_type):
                return CPUDescriptor(0, True, False, 0, False)

            def sizes(self, kind, cpu_type):
                return (1024,)

        controller.channel = cast(Any, Channel())
        with patch("scripts.cuw_legacy_body.BodyTables", Tables):
            with self.assertRaises(ExecutableForeignNativeError):
                controller.transfer_cpu(context.native)
            self.assertEqual(len(calls), 11)
            host_error = OSError("authored host provider fault")
            with (
                patch.object(
                    controller.channel, "check_id", side_effect=host_error
                ) as host_call,
                self.assertRaises(OSError) as caught,
            ):
                controller.transfer_cpu(context.native)
            self.assertIs(caught.exception, host_error)
            self.assertEqual(host_call.call_count, 1)


if __name__ == "__main__":
    unittest.main()
