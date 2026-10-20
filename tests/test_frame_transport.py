"""Literal authored J2534 layouts; no adapter discovery or vendor execution."""

import struct
import unittest
from dataclasses import replace
from typing import Literal

from scripts import drive_recorder as drs
from scripts.diagnostic_db import Database, Section
from scripts.frame_transport import (
    MAX_DATA,
    DriverProperties,
    FrameTransportError,
    NativeConfig,
    NativeConnect,
    NativeFrameReceive,
    NativeMessage,
    _translated_configs,
    get_comm_frame,
)
from scripts.profiles import VehicleCatalog, VehicleProfile


def selected_profile(bus=0x12, *, version=18, flags=1, init_flags=3):
    category = bytearray(76)
    struct.pack_into("<H", category, 68, 42)
    category[72] = flags
    prot = bytearray(24 if version == 12 else 28)
    struct.pack_into("<6H", prot, 0, 42, 1, 0x33, 0x7DF, 0x7E0, 0xAB)
    prot[22 if version == 12 else 24] = bus
    can = bytearray(28)
    struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
    struct.pack_into("<H", can, 16 if version == 12 else 18, 9)
    iso = bytearray(56)
    struct.pack_into("<IHH", iso, 0, 10400, 1, init_flags)
    for offset in range(8, 50, 2):
        struct.pack_into("<H", iso, offset, offset + 100)
    j1850 = bytearray(16)
    struct.pack_into("<HII", j1850, 0, 1, 0, 0)  # Baud DWORD is at +4.
    struct.pack_into("<I", j1850, 4, 10400)
    requests = (b"\x10\x01", b"\x81", b"\x3e", b"\x81")
    directory, storage, functions, frames = (
        bytearray(),
        bytearray(),
        bytearray(),
        bytearray(),
    )
    for index, (function, request) in enumerate(
        zip((0x67, 0x68, 0x7F, 0x98), requests, strict=True), 1
    ):
        directory += struct.pack("<IH", len(storage), len(request))
        storage += request
        functions += struct.pack("<8H", 42, function, 0, index, 0, 0, 0, 0)
        frames += struct.pack("<4H", index, index, 0, 0)
    sections = {
        slot: Section(slot, 0, count, False, payload)
        for slot, count, payload in (
            (0, 4, bytes(directory + storage)),
            (13, 1, bytes(prot)),
            (14, 1, bytes(can)),
            (15, 1, bytes(iso)),
            (16, 1, bytes(category)),
            (17, 4, bytes(frames)),
            (18, 4, bytes(functions)),
            (51, 1, bytes(j1850)),
        )
    }
    management = Database(
        1, 0x0100030C if version == 12 else 0x0100032F, "synthetic-management", sections
    )
    catalog = object.__new__(VehicleCatalog)
    catalog.management = management
    return VehicleProfile(
        catalog, bytes(category), Database(2, management.version, "synthetic-ecu", {})
    )


DRIVER = DriverProperties(0, b"04.04", "authored-version-reply")


class FrameCodecTests(unittest.TestCase):
    def test_literal_six_dword_header_and_independent_address_bytes(self):
        message = NativeMessage(
            6, 0, 0x100, 0x11223344, 0, b"\x00\x00\x07\xe0\x22\xf1\x90"
        )
        literal = bytes.fromhex(
            "06000000 00000000 00010000 44332211 07000000 00000000 000007e022f190"
        )
        self.assertEqual(message.encode(), literal)
        self.assertEqual(NativeMessage.decode(literal), message)
        self.assertEqual(message.header_words, (6, 0, 0x100, 0x11223344, 7, 0))

    def test_assembled_receive_uses_word_capacity_not_single_message_capacity(self):
        payload = bytes(0xFFFF)
        self.assertEqual(NativeFrameReceive(payload).data, payload)
        with self.assertRaises(ValueError):
            NativeFrameReceive(bytes(0x10000))
        with self.assertRaises(ValueError):
            NativeMessage(0x8208, 0, 0, 0, 0, payload)

    def test_connect_has_exactly_two_words_and_config_pairs_remain_literal(self):
        self.assertEqual(
            NativeConnect(6, 0x80).encode(), bytes.fromhex("0600000080000000")
        )
        self.assertEqual(
            NativeConfig(0x8000, 0x12345678).encode(), bytes.fromhex("0080000078563412")
        )

    def test_native_storage_and_malformed_header_bounds(self):
        full = NativeMessage(4, 0, 0, 0, 0, bytes(MAX_DATA))
        self.assertEqual(NativeMessage.decode(full.encode()), full)
        for blob in (b"", bytes(23), struct.pack("<6I", 6, 0, 0, 0, 1, 0)):
            with self.assertRaises(ValueError):
                NativeMessage.decode(blob)
        with self.assertRaises(ValueError):
            NativeMessage(4, 0, 0, 0, 0, bytes(MAX_DATA + 1))
        with self.assertRaises(ValueError):
            NativeConnect(True, 0)

    def test_explicit_driver_reply_controls_api_translation_boundary(self):
        self.assertEqual(
            DriverProperties(0, b"03.04.0000", "synthetic").api_word, 0x304
        )
        self.assertEqual(DriverProperties(0, b"03.05", "synthetic").api_word, 0x305)
        self.assertEqual(DriverProperties(7, b"", "observed-error").api_word, 0)
        for version in (b"", b"03", b"03.0", b"unwritten", bytes(81)):
            with self.assertRaises(ValueError):
                DriverProperties(0, version, "synthetic")

    def test_config_capacity_is_checked_before_an_omitted_parameter(self):
        for omitted in (14, 0x10009):
            with self.assertRaises(FrameTransportError) as error:
                _translated_configs(((1, 1),) * 32 + ((omitted, 0),), DRIVER)
            self.assertEqual(error.exception.status, 0xC0020203)


class NativeProducerTests(unittest.TestCase):
    def plan(self, bus=0x12, **options):
        return get_comm_frame(
            selected_profile(bus, **options), b"\x22\xf1\x90", bus_id=bus, driver=DRIVER
        )

    def test_can_literal_header_two_filters_and_selected_config(self):
        for version in (12, 18):
            plan = self.plan(version=version)
            self.assertEqual(
                plan.send.encode(),
                bytes.fromhex(
                    "06000000 00000000 40000000 00000000 07000000 07000000 000007e022f190"
                ),
            )
            self.assertEqual(
                [(v.parameter, v.value) for v in plan.configs],
                [(1, 500000), (0x10103, 0x1234), (0x10106, 20)],
            )
            self.assertEqual(plan.startup_request, b"\x10\x01")
            self.assertEqual(plan.tester_request, b"\x3e")
            self.assertEqual([f.filter_type for f in plan.filters], [1, 3])
            self.assertEqual(plan.filters[0].mask.data, bytes.fromhex("000007ff"))
            self.assertEqual(plan.filters[0].pattern.data, bytes.fromhex("000007e8"))
            self.assertEqual(
                plan.filters[0].flow_control, NativeMessage(0, 0, 0, 0, 0, b"")
            )
            self.assertEqual(
                plan.filters[1].flow_control.data, bytes.fromhex("000007e0")
            )
            self.assertEqual(plan.filters[1].flow_control.extra_data_index, 4)
            self.assertEqual(plan.initialization_message.data, b"")

    def test_can_extended_and_functional_target_modes(self):
        extended = self.plan(0x22)
        self.assertEqual(extended.connect, NativeConnect(6, 0x80))
        self.assertEqual(extended.send.data, bytes.fromhex("000007e0ab22f190"))
        functional = self.plan(0x32)
        self.assertEqual(functional.send.data, bytes.fromhex("000007df22f190"))
        self.assertFalse(functional.filters)
        psa = self.plan(flags=0x14)
        self.assertEqual(psa.filters[1].mask.data, bytes.fromhex("ffffffff"))
        self.assertEqual(psa.tester_request, b"")

    def test_iso_headers_initialization_and_source_selector(self):
        for version in (12, 18):
            plan = self.plan(0x11, version=version)
            self.assertEqual(plan.connect, NativeConnect(4, 0))
            self.assertEqual(plan.send.data, bytes.fromhex("83e0f022f190"))
            self.assertEqual(
                plan.initialization_message.data, bytes.fromhex("81e0f081")
            )
            self.assertEqual(plan.initialization_message.extra_data_index, 4)
            self.assertEqual(plan.init_bytes, b"\x33")
            configs = {v.parameter: v.value for v in plan.configs}
            self.assertEqual(configs[6], 260)
            self.assertEqual(configs[7], 256)
            self.assertEqual(configs[14], 108)
            self.assertEqual(configs[15], 112)
            self.assertNotIn(0x10009, configs)
        self.assertEqual(self.plan(0x21).send.data, bytes.fromhex("686af022f190"))
        self.assertEqual(self.plan(0x31).send.data, bytes.fromhex("c3dff022f190"))
        self.assertEqual(self.plan(0x11, flags=0x81).send.data[2], 0xF1)
        self.assertEqual(self.plan(0x1C).send.data[2], 0)
        profile = selected_profile(0x11)
        old = get_comm_frame(
            profile,
            b"\x01",
            bus_id=0x11,
            driver=DriverProperties(0, b"03.04", "old-observed"),
        )
        self.assertEqual({v.parameter: v.value for v in old.configs}[6], 130)

    def test_j1850_physical_functional_and_observed_diagnostic_address(self):
        self.assertEqual(self.plan(0x17).send.data, bytes.fromhex("68dff022f190"))
        self.assertEqual(self.plan(0x27).send.data, bytes.fromhex("68e0f022f190"))
        mode = struct.pack("<HHIIHH", 1, 0, 42, 0x600, 0x12, 1)
        profile = selected_profile()
        plan = get_comm_frame(
            profile, b"\x01", bus_id=0x12, driver=DRIVER, diagnostic_mode=mode
        )
        self.assertEqual(plan.address, 0x600)
        self.assertEqual(plan.send.data, bytes.fromhex("000007e001"))
        self.assertEqual(plan.filters[0].pattern.data, bytes.fromhex("00000608"))
        self.assertEqual(plan.filters[1].pattern.data, bytes.fromhex("000007e8"))

    def test_missing_metadata_bounds_and_no_inferred_protocol(self):
        for bus in (0, 3, 8, 10, 11):
            with self.assertRaises(FrameTransportError):
                self.plan(bus)
        with self.assertRaises(FrameTransportError):
            self.plan(flags=0)
        profile = selected_profile()
        management = profile.catalog.management
        profile.catalog.management = replace(
            management,
            sections={k: v for k, v in management.sections.items() if k != 18},
        )
        with self.assertRaises(FrameTransportError):
            get_comm_frame(profile, b"\x01", bus_id=0x12, driver=DRIVER)
        profile = selected_profile()
        with self.assertRaises(FrameTransportError):
            get_comm_frame(profile, b"", bus_id=0x12, driver=DRIVER)
        with self.assertRaises(ValueError):
            get_comm_frame(profile, bytes(MAX_DATA), bus_id=0x12, driver=DRIVER)

    def test_missing_tester_is_required_except_psa_and_empty_codes_are_retained(self):
        for flags in (1, 0x14):
            profile = selected_profile(flags=flags)
            database = profile.catalog.management
            functions = database.sections[18]
            rows = functions.rows(16)
            payload = b"".join(
                row for row in rows if struct.unpack_from("<H", row, 2)[0] != 0x7F
            )
            profile.catalog.management = replace(
                database,
                sections={
                    **database.sections,
                    18: replace(functions, count=3, payload=payload),
                },
            )
            if flags == 0x14:
                self.assertEqual(
                    get_comm_frame(
                        profile, b"\x01", bus_id=0x12, driver=DRIVER
                    ).tester_request,
                    b"",
                )
            else:
                with self.assertRaises(FrameTransportError) as error:
                    get_comm_frame(profile, b"\x01", bus_id=0x12, driver=DRIVER)
                self.assertEqual(error.exception.status, 0x90020104)
        for index, expected in ((0, 0x90020501), (2, 0x90020502)):
            profile = selected_profile()
            database = profile.catalog.management
            section = database.sections[0]
            payload = bytearray(section.payload)
            struct.pack_into("<H", payload, index * 6 + 4, 0)
            profile.catalog.management = replace(
                database,
                sections={
                    **database.sections,
                    0: replace(section, payload=bytes(payload)),
                },
            )
            with self.assertRaises(FrameTransportError) as error:
                get_comm_frame(profile, b"\x01", bus_id=0x12, driver=DRIVER)
            self.assertEqual(error.exception.status, expected)

    def test_j1850_normalizes_ignored_tester_lookup_failure(self):
        profile = selected_profile(0x17)
        database = profile.catalog.management
        functions = database.sections[18]
        payload = b"".join(
            row
            for row in functions.rows(16)
            if struct.unpack_from("<H", row, 2)[0] != 0x7F
        )
        profile.catalog.management = replace(
            database,
            sections={
                **database.sections,
                18: replace(functions, count=3, payload=payload),
            },
        )
        with self.assertRaises(FrameTransportError) as error:
            get_comm_frame(profile, b"\x01", bus_id=0x17, driver=DRIVER)
        self.assertEqual(error.exception.status, 0x90020502)

    def test_exact_storage_limit_diagnostic_mode_and_first_simple_record(self):
        for bus, header in ((0x12, 4), (0x22, 5), (0x11, 3), (0x17, 3)):
            profile = selected_profile(bus)
            self.assertEqual(
                len(
                    get_comm_frame(
                        profile, bytes(MAX_DATA - header), bus_id=bus, driver=DRIVER
                    ).send.data
                ),
                MAX_DATA,
            )
            with self.assertRaises(FrameTransportError) as error:
                get_comm_frame(
                    profile, bytes(MAX_DATA - header + 1), bus_id=bus, driver=DRIVER
                )
            self.assertEqual(error.exception.status, 0x90020702)
        profile = selected_profile()
        database = profile.catalog.management
        section = database.sections[14]
        other = bytearray(section.payload)
        struct.pack_into("<I", other, 4, 125000)
        profile.catalog.management = replace(
            database,
            sections={
                **database.sections,
                14: replace(section, count=2, payload=section.payload + bytes(other)),
            },
        )
        self.assertEqual(
            get_comm_frame(profile, b"\x01", bus_id=0x12, driver=DRIVER)
            .configs[0]
            .value,
            500000,
        )
        for mode in (b"", bytes(15), bytes(17)):
            with self.assertRaises(ValueError):
                get_comm_frame(
                    profile, b"\x01", bus_id=0x12, driver=DRIVER, diagnostic_mode=mode
                )
        mode = struct.pack("<HHIIHH", 2, 0, 42, 0x650, 0x12, 1)
        plan = get_comm_frame(
            profile, b"\x01", bus_id=0x12, driver=DRIVER, diagnostic_mode=mode
        )
        self.assertEqual(plan.address, 0x7E0)
        self.assertEqual(plan.filters[0].pattern.data, bytes.fromhex("00000658"))


def executable_plan():
    plan = get_comm_frame(
        selected_profile(), b"\x22\xf1\x90", bus_id=0x12, driver=DRIVER
    )

    def message(value):
        return drs.NativeMessage(
            value.protocol_id,
            value.rx_status,
            value.tx_flags,
            value.timestamp,
            value.extra_data_index,
            value.data,
        )

    response = drs.NativeMessage(6, 0, 0, 0, 7, bytes.fromhex("000007e862f190"))
    expected = drs.NativeReadExpectation(
        100, (6, 0, 0x40, 0, 0, 0), bytes([255]) * 7, response.data
    )
    commands = [
        drs.encode_command(
            0x200,
            {"protocol_id": plan.connect.protocol_id, "flags": plan.connect.flags},
        ),
        drs.encode_command(
            0x211, {"parameters": tuple((v.parameter, v.value) for v in plan.configs)}
        ),
    ]
    commands.extend(
        drs.encode_command(
            0x206,
            {
                "filter_type": f.filter_type,
                "messages": tuple(
                    message(m) for m in (f.mask, f.pattern, f.flow_control)
                ),
            },
        )
        for f in plan.filters
    )
    commands.extend(
        (
            drs.encode_command(0x203, {"timeout": 100, "message": message(plan.send)}),
            drs.DrsTable(0x202, expected.encode()),
            drs.encode_command(0x201, {}),
        )
    )
    settings = drs.DrsFile(
        2, 0, (drs.encode_command(0x27, {"children": tuple(commands)}),)
    )
    return plan, settings, response


class PrimitiveIO:
    def __init__(self, response, *, fault=0, cancel_at=0, slow_at=0):
        self.response = response
        self.fault, self.cancel_at, self.slow_at = fault, cancel_at, slow_at
        self.calls = []
        self.stopped = False
        self.now = 0.0

    def clock(self):
        return self.now

    def cancelled(self):
        return self.stopped

    def invoke(self, operation, fields, *, deadline, cancelled):
        self.calls.append((operation, fields))
        if len(self.calls) == self.fault:
            raise OSError("authored primitive fault")
        if len(self.calls) == self.cancel_at:
            self.stopped = True
        if len(self.calls) == self.slow_at:
            self.now += 2.0
        if operation == "connect":
            return 0
        if operation == "read_messages":
            return self.response
        return None


class PrimitiveConsumerTests(unittest.TestCase):
    def test_actual_plan_drives_existing_native_primitive_executor(self):
        plan, settings, response = executable_plan()
        io = PrimitiveIO(response)
        executor = drs.NativeDrsExecutor(settings, io, clock=io.clock)
        results = executor.execute_group(0x27)
        self.assertEqual(results[-2], response)
        self.assertEqual(
            [name for name, _ in io.calls],
            [
                "connect",
                "set_config",
                "start_message_filter",
                "start_message_filter",
                "write_messages",
                "read_messages",
                "disconnect",
            ],
        )
        self.assertEqual(io.calls[0][1], {"protocol_id": 6, "flags": 0})
        self.assertEqual(
            io.calls[1][1]["parameters"],
            tuple((v.parameter, v.value) for v in plan.configs),
        )
        outgoing = io.calls[4][1]["message"]
        assert isinstance(outgoing, drs.NativeMessage)
        self.assertEqual(outgoing.encode(), plan.send.encode())
        self.assertIsNone(executor.channel)

    def test_fault_cancel_and_deadline_at_primitive_boundaries(self):
        _, settings, response = executable_plan()
        for boundary in range(1, 8):
            for mode, error_type in (
                ("fault", OSError),
                ("cancel_at", drs.RecorderCancelled),
                ("slow_at", TimeoutError),
            ):
                io = PrimitiveIO(response, **{mode: boundary})
                executor = drs.NativeDrsExecutor(settings, io, clock=io.clock)
                with self.assertRaises(error_type):
                    executor.execute_group(0x27, timeout=1, cancelled=io.cancelled)
                if mode != "fault" or boundary > 1:
                    self.assertIn("disconnect", [name for name, _ in io.calls])
                self.assertIsNone(executor.channel)


if __name__ == "__main__":
    unittest.main()


class DriverPrimitive:
    def __init__(self, replies=(), *, fault_at=0, cancel_at=0):
        self.replies = list(replies)
        self.calls = []
        self.now = 10.0
        self.stopped = False
        self.fault_at, self.cancel_at = fault_at, cancel_at
        self.filter_id = 30
        self.config_failures = []

    def invoke(self, operation, fields, *, deadline, cancelled):
        from scripts.frame_transport import J2534Result

        self.calls.append((operation, fields, deadline))
        if len(self.calls) == self.fault_at:
            raise OSError("authored primitive failure")
        if len(self.calls) == self.cancel_at:
            self.stopped = True
        if operation == "connect":
            return J2534Result(handle=7)
        if operation == "start_message_filter":
            self.filter_id += 1
            return J2534Result(handle=self.filter_id)
        if operation == "ioctl" and fields["ioctl_id"] == 2 and self.config_failures:
            return J2534Result(code=self.config_failures.pop(0))
        if operation == "write_messages":
            return J2534Result(count=1)
        if operation == "read_messages":
            value = self.replies.pop(0) if self.replies else J2534Result(code=9)
            return (
                value
                if isinstance(value, J2534Result)
                else J2534Result(count=1, messages=(value,))
            )
        return J2534Result()

    def clock(self):
        return self.now

    def wait(self, seconds):
        self.now += seconds

    def cancelled(self):
        return self.stopped


def native_operations(
    backend, *, version=18, bus=0x12, profile=None, plan=None, device_kind=8, **options
):
    from scripts.frame_transport import NativeFrameOperations

    profile = profile or selected_profile(bus, version=version)
    plan = plan or get_comm_frame(profile, b"\x22\xf1\x90", bus_id=bus, driver=DRIVER)
    return NativeFrameOperations(
        profile,
        plan,
        backend,
        native_build=12 if version == 12 else 18,
        bus_id=bus,
        driver=DRIVER,
        device_kind=device_kind,
        clock=backend.clock,
        wait=backend.wait,
        cancelled=backend.cancelled,
        **options,
    )


def native_can(payload, *, address=0x7E8, flags=0, stamp=0, protocol=6):
    data = address.to_bytes(4, "big") + payload
    return NativeMessage(protocol, flags, 0, stamp, len(data), data)


class NativeFrameRuntimeTests(unittest.TestCase):
    def test_retained_header_dynamic_payload_and_inverse_protocol_context(self):
        from scripts.frame_transport import decode_frame_message, frame_message

        plan = get_comm_frame(selected_profile(), b"\x01", bus_id=0x12, driver=DRIVER)
        self.assertEqual(
            frame_message(plan, b"\x3e", bus_id=0x12).data, bytes.fromhex("000007e03e")
        )
        self.assertEqual(
            frame_message(plan, b"", bus_id=0x12).data, bytes.fromhex("000007e0")
        )
        # The native decoder uses retained class type; it ignores driver ProtocolID.
        result = decode_frame_message(
            native_can(bytes.fromhex("62f190"), protocol=4), bus_id=0x12, protocol_id=6
        )
        self.assertEqual(
            (result.data, result.source_id), (bytes.fromhex("62f190"), 0x7E8)
        )
        short = NativeMessage(6, 0, 0, 0, 2, b"\x00\x00")
        self.assertEqual(
            decode_frame_message(short, bus_id=0x12, protocol_id=6).code, 0x90020601
        )

    def test_iso_literal_inverse_keeps_checksum_and_source_validator(self):
        from scripts.frame_transport import decode_frame_message, validate_frame_message

        ops = native_operations(DriverPrimitive(), bus=0x11)
        data = bytes.fromhex("83f0e062f190")
        message = NativeMessage(4, 0, 0, 0, len(data), data)
        self.assertEqual(
            validate_frame_message(ops.plan, message, bus_id=0x11, ecu_flags=1), 0
        )
        self.assertEqual(
            decode_frame_message(message, bus_id=0x11, protocol_id=4).data,
            bytes.fromhex("62f190"),
        )
        data = bytes.fromhex("84f0e062f190aa")
        message = NativeMessage(4, 0, 0, 0, len(data), data)
        self.assertEqual(
            decode_frame_message(message, bus_id=0x11, protocol_id=4).data,
            bytes.fromhex("62f190aa"),
        )
        wrong = replace(message, data=bytes.fromhex("84f0e162f190aa"))
        self.assertEqual(
            validate_frame_message(ops.plan, wrong, bus_id=0x11, ecu_flags=1),
            0x91020325,
        )

    def test_actual_normal_setup_differs_from_get_frame_and_config_retry(self):
        for version in (12, 18):
            backend = DriverPrimitive()
            backend.config_failures = [1, 0]
            ops = native_operations(backend, version=version)
            self.assertEqual(ops.open(), 0)
            configs = [
                fields["input"]
                for name, fields, _ in backend.calls
                if name == "ioctl" and fields["ioctl_id"] == 2
            ]
            self.assertEqual(configs[0][-1], NativeConfig(0x2A, 0))
            self.assertEqual(configs[1], configs[0][:-1])
            filters = [
                fields
                for name, fields, _ in backend.calls
                if name == "start_message_filter"
            ]
            self.assertEqual(
                len(filters), 1
            )  # Device8 omits native device4 pass filter.
            self.assertEqual(filters[0]["mask"].data, bytes.fromhex("ffffffff"))
            self.assertEqual(ops.close(), 0)
            self.assertIsNone(ops.channel)

    def test_no_init_send_receive_and_borrowed_channel_ownership(self):
        backend = DriverPrimitive([native_can(bytes.fromhex("62f190"))])
        ops = native_operations(backend)
        ops.adopt_channel(9)
        self.assertEqual(
            ops.send(b"\x22\xf1\x90", timeout=80, initialization_mode=2), 0
        )
        result = ops.receive(maximum=4096, timeout=120)
        self.assertEqual(
            (result.data, result.source_id, result.code),
            (bytes.fromhex("62f190"), 0x7E8, 0),
        )
        self.assertEqual(
            [name for name, _, _ in backend.calls],
            ["ioctl", "write_messages", "read_messages"],
        )
        self.assertEqual(backend.calls[0][1]["ioctl_id"], 8)
        self.assertEqual(
            backend.calls[1][1]["messages"][0].data, bytes.fromhex("000007e022f190")
        )
        self.assertEqual(ops.close(), 0)
        self.assertNotIn("disconnect", [name for name, _, _ in backend.calls])

    def test_pending_busy_partial_negative_and_rx_flags(self):
        backend = DriverPrimitive(
            [
                native_can(b"\x50", flags=0x20),
                native_can(bytes.fromhex("7f2278")),
                native_can(bytes.fromhex("7f2221")),
                native_can(bytes.fromhex("7f2213")),
            ]
        )
        ops = native_operations(backend)
        ops.adopt_channel(9)
        self.assertEqual(ops.send(b"\x22", timeout=25, initialization_mode=2), 0)
        result = ops.receive(maximum=64, timeout=50)
        self.assertEqual(
            (result.data, result.code), (bytes.fromhex("7f2213"), 0x90020321)
        )
        writes = [
            fields for name, fields, _ in backend.calls if name == "write_messages"
        ]
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[0]["messages"], writes[1]["messages"])
        reads = [fields for name, fields, _ in backend.calls if name == "read_messages"]
        self.assertEqual([fields["timeout"] for fields in reads], [50, 50, 20, 20])

    def test_native_buffer_empty_mapping_and_null_output_make_no_io(self):
        from scripts.frame_transport import J2534Result

        backend = DriverPrimitive([J2534Result(code=0x10)])
        ops = native_operations(backend)
        ops.adopt_channel(9)
        self.assertEqual(
            ops.receive(maximum=64, timeout=10, buffer=False).code, 0x90020701
        )
        self.assertFalse(backend.calls)
        self.assertEqual(ops.receive(maximum=64, timeout=10).code, 0x91010009)
        self.assertEqual(ops.send(None, timeout=10, initialization_mode=1), 0x90020701)

    def test_native_count_pending_time_mode_timestamp_wrap_and_zero_write_timeout(self):
        backend = DriverPrimitive(
            [native_can(bytes.fromhex("7f2278")), native_can(bytes.fromhex("7f2278"))]
        )
        ops = native_operations(backend)
        ops.adopt_channel(9)
        ops.pending_limit = 2
        self.assertEqual(ops.receive(maximum=64, timeout=10).code, 0x90020323)
        backend = DriverPrimitive(
            [native_can(b"\x62", stamp=0xFFFFFF00), native_can(b"\x62", stamp=0x1000)]
        )
        ops = native_operations(backend)
        ops.adopt_channel(9)
        ops.set_runtime_flags(
            write_without_wait=True, timestamp_unwrap=True, pending_by_time=True
        )
        self.assertEqual(ops.send(b"\x22", timeout=900, initialization_mode=2), 0)
        self.assertEqual(
            [f["timeout"] for n, f, _ in backend.calls if n == "write_messages"], [0]
        )
        self.assertEqual(ops.receive(maximum=64, timeout=10).timestamp, 4294967)
        self.assertEqual(ops.receive(maximum=64, timeout=10).timestamp, 4294971)

    def test_can_mask_shared_state_initialization_and_connection_block(self):
        from scripts.frame_transport import NativeSharedState

        profile = selected_profile()
        database = profile.catalog.management
        profile.catalog.management = replace(
            database,
            sections={
                **database.sections,
                70: Section(70, 0, 1, False, bytes.fromhex("2a001200")),
            },
        )
        shared = NativeSharedState(255, 0, "authored-shared-bytes")
        backend = DriverPrimitive([native_can(bytes.fromhex("5001"))])
        ops = native_operations(backend, profile=profile, shared_state=shared)
        self.assertEqual(ops.open(), 0)
        self.assertEqual(ops.send(None, timeout=20, initialization_mode=0), 0)
        self.assertEqual((shared.mask_result, shared.connection_blocked), (1, 1))
        self.assertEqual(ops.initialization_mode, 0)
        writes = [
            fields for name, fields, _ in backend.calls if name == "write_messages"
        ]
        self.assertEqual(len(writes), 1)  # NULL did not add an application request.
        self.assertEqual(writes[0]["messages"][0].data, bytes.fromhex("000007e01001"))
        self.assertEqual(ops.close(), 0)
        blocked_backend = DriverPrimitive()
        blocked = native_operations(
            blocked_backend, profile=profile, shared_state=shared
        )
        self.assertEqual(blocked.open(), 0x91010009)
        self.assertFalse(blocked_backend.calls)

    def test_native_packet_log_literal_and_failed_writer_disable_only_logging(self):
        from scripts.frame_transport import packet_log_record

        self.assertEqual(packet_log_record(bytes.fromhex("62f190")), b"62F190\\n")
        backend = DriverPrimitive([native_can(b"\x62")])
        ops = native_operations(backend)
        ops.adopt_channel(9)
        written, failures = [], []

        def write(data):
            written.append(data)
            return len(data)

        ops.set_packet_log(write)
        self.assertEqual(ops.send(b"\x22", timeout=20, initialization_mode=2), 0)
        self.assertEqual(ops.receive(maximum=64, timeout=20).data, b"\x62")
        self.assertEqual(written, [b"22\\n", b"62\\n"])
        ops.set_packet_log(lambda data: 0, lambda: failures.append(1))
        self.assertEqual(ops.send(b"\x3e", timeout=20, initialization_mode=2), 0)
        self.assertTrue(ops.log_error)
        self.assertEqual(failures, [1])

    def test_fault_cancel_and_uncertain_count_close_owned_resources(self):
        from scripts.frame_transport import J2534Result

        for kind in ("fault", "cancel"):
            for boundary in range(1, 5):
                with self.subTest(kind=kind, boundary=boundary):
                    backend = DriverPrimitive(
                        fault_at=boundary if kind == "fault" else 0,
                        cancel_at=boundary if kind == "cancel" else 0,
                    )
                    ops = native_operations(backend)
                    with self.assertRaises(
                        OSError if kind == "fault" else InterruptedError
                    ):
                        ops.open()
                    self.assertIsNone(ops.channel)

        class MissingCount(DriverPrimitive):
            def invoke(self, operation, fields, **options):
                if operation == "write_messages":
                    self.calls.append((operation, fields, options["deadline"]))
                    return J2534Result(count=0)
                return super().invoke(operation, fields, **options)

        backend = MissingCount()
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        with self.assertRaises(OSError):
            ops.send(b"\x22", timeout=20, initialization_mode=2)
        self.assertIsNone(ops.channel)
        self.assertTrue(ops.poisoned)

    def test_cleanup_deadline_validation_and_retry_preserve_remaining_ownership(self):
        class SlowCleanup(DriverPrimitive):
            def invoke(self, operation, fields, **options):
                result = super().invoke(operation, fields, **options)
                if operation == "stop_message_filter" and fields["filter_id"] == 12:
                    self.now += 3
                return result

        backend = SlowCleanup()
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        ops.filter_handles[:] = [11, 12]
        with self.assertRaises(ValueError):
            ops.close(deadline=float("nan"))
        self.assertFalse(backend.calls)
        with self.assertRaises(TimeoutError):
            ops.close(deadline=12)
        self.assertEqual(ops.channel, 9)
        self.assertEqual(ops.filter_handles, [11])
        self.assertEqual(
            [f["filter_id"] for n, f, _ in backend.calls if n == "stop_message_filter"],
            [12],
        )
        self.assertEqual(ops.close(), 0)
        self.assertIsNone(ops.channel)
        self.assertEqual(
            [f["filter_id"] for n, f, _ in backend.calls if n == "stop_message_filter"],
            [12, 11],
        )

    def test_delay_checks_deadline_and_cancel_after_final_wait(self):
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                backend = DriverPrimitive()
                ops = native_operations(backend)
                if cancelled:

                    def final_wait(seconds, backend=backend):
                        backend.now += seconds
                        backend.stopped = True

                    ops.wait = final_wait
                with self.assertRaises(InterruptedError if cancelled else TimeoutError):
                    ops._wait_ms(100, 10.1)

    def test_concrete_virtual_header_and_validator_used_by_runtime(self):
        from scripts.frame_transport import NativeFrameOperations

        class ConcreteWire(NativeFrameOperations):
            def _frame_message(self, request):
                return NativeMessage(
                    6, 0, 0, 0, 4 + len(request), b"\x00\x00\x07\xdf" + request
                )

            def _validate_message(self, message):
                return 0x90020321

        backend = DriverPrimitive([native_can(b"\x62")])
        base = native_operations(backend)
        ops = ConcreteWire(
            base.profile,
            base.plan,
            backend,
            native_build=18,
            bus_id=0x12,
            driver=DRIVER,
            device_kind=8,
            clock=backend.clock,
            wait=backend.wait,
        )
        ops.adopt_channel(9)
        self.assertEqual(ops.send(b"\x22", timeout=20, initialization_mode=2), 0)
        write = next(f for n, f, _ in backend.calls if n == "write_messages")
        self.assertEqual(write["messages"][0].data, bytes.fromhex("000007df22"))
        self.assertEqual(ops.receive(maximum=64, timeout=20).code, 0x90020321)

    def test_slow_init_retries_and_checks_native_category_keywords(self):
        from scripts.frame_transport import J2534Result

        class SlowInit(DriverPrimitive):
            def __init__(self, results):
                super().__init__()
                self.results = list(results)

            def invoke(self, operation, fields, **options):
                if operation == "ioctl" and fields["ioctl_id"] == 4:
                    self.calls.append((operation, fields, options["deadline"]))
                    return self.results.pop(0)
                return super().invoke(operation, fields, **options)

        backend = SlowInit([J2534Result(code=7), J2534Result(data=b"\x08\x08")])
        ops = native_operations(
            backend, bus=0x11, profile=selected_profile(0x11, flags=3)
        )
        ops.adopt_channel(9)
        self.assertEqual(ops._iso_slow_initialize(20), (0, b"\x08\x08"))
        self.assertAlmostEqual(backend.now, 15)
        self.assertEqual([f["ioctl_id"] for n, f, _ in backend.calls], [8, 4, 8, 4])
        backend.results = [J2534Result(data=b"\x94\x94")]
        self.assertEqual(ops._iso_slow_initialize(20)[0], 0x91020302)

    def test_native_can_temporary_config_reads_retains_and_restores_word(self):
        from scripts.frame_transport import J2534Result

        class ConfigRead(DriverPrimitive):
            def invoke(self, operation, fields, **options):
                if operation == "ioctl" and fields["ioctl_id"] == 1:
                    self.calls.append((operation, fields, options["deadline"]))
                    return J2534Result(configs=(NativeConfig(0x23, 0x12345),))
                return super().invoke(operation, fields, **options)

        for version in (12, 18):
            profile = selected_profile(version=version)
            table = profile.catalog.management.sections[14]
            row = bytearray(table.payload)
            struct.pack_into("<H", row, 18 if version == 12 else 20, 255)
            row[24 if version == 12 else 26] = 1
            profile.catalog.management.sections[14] = replace(table, payload=bytes(row))
            backend = ConfigRead()
            ops = native_operations(backend, version=version, profile=profile)
            ops.adopt_channel(9)
            ops.apply_temporary_config()
            ops.apply_temporary_config()
            ops.restore_temporary_config()
            ops.restore_temporary_config()
            self.assertEqual([f["ioctl_id"] for n, f, _ in backend.calls], [1, 2, 2])
            self.assertEqual(
                [f["input"][0].value for n, f, _ in backend.calls], [0, 255, 0x2345]
            )

    def test_j1850_protocol_two_config_and_psa62_native_setup(self):
        profile = selected_profile(0x17)
        plan = get_comm_frame(profile, b"\x22", bus_id=0x17, driver=DRIVER)
        plan = replace(
            plan, send=replace(plan.send, protocol_id=2), connect=NativeConnect(2, 0)
        )
        backend = DriverPrimitive()
        ops = native_operations(backend, bus=0x17, profile=profile, plan=plan)
        ops.adopt_channel(9)
        self.assertEqual(ops.setup(), 0)
        self.assertEqual([f["ioctl_id"] for n, f, _ in backend.calls], [12, 2])
        self.assertEqual(backend.calls[0][1]["input"], b"\x6b")
        pairs = [(c.parameter, c.value) for c in backend.calls[1][1]["input"]]
        self.assertIn((4, 0xF0), pairs)
        self.assertIn((5, 0), pairs)
        self.assertNotIn(0x10300, dict(pairs))
        backend = DriverPrimitive()
        ops = native_operations(
            backend, bus=0x62, profile=selected_profile(0x62, flags=0x14)
        )
        ops.adopt_channel(9)
        self.assertEqual(ops.setup(), 0)
        self.assertEqual(backend.calls[0][1]["input"][0], NativeConfig(0x8001, 0x30B))
        self.assertIn(10, [f["ioctl_id"] for n, f, _ in backend.calls if n == "ioctl"])

    def test_wwh_state_selects_native_address_filters_and_health(self):
        profile = selected_profile(0x12, flags=0x15)
        table = profile.catalog.management.sections[13]
        row = bytearray(table.payload)
        struct.pack_into("<H", row, 20, 0x760)
        profile.catalog.management.sections[13] = replace(table, payload=bytes(row))
        backend = DriverPrimitive()
        ops = native_operations(backend, profile=profile, native_variant="psa_wwh")
        ops.adopt_channel(9)
        ops.force_initialization = True
        for state, target, peer, initializes in (
            (1, 0x7E0, 0x7E8, True),
            (2, 0x7E0, 0x7E8, True),
            (3, 0x760, 0x768, False),
            (4, 0x7DF, 0x768, False),
        ):
            ops.set_request_state(state)
            self.assertEqual(
                ops._frame_message(b"\x22").data, target.to_bytes(4, "big") + b"\x22"
            )
            self.assertEqual(
                ops._can_filters()[-1].pattern.data, peer.to_bytes(4, "big")
            )
            self.assertEqual(ops._needs_initialize(10000), initializes)
        with self.assertRaises(ValueError):
            native_operations(DriverPrimitive(), version=12, native_variant="psa_wwh")

    def test_raw_drain_and_successful_clear_release_filter_ownership(self):
        backend = DriverPrimitive([native_can(b"\x62"), native_can(b"\x63", flags=1)])
        ops = native_operations(backend)
        ops.adopt_channel(9)
        ops.filter_handles[:] = [1, 2]
        self.assertEqual(ops.drain(), 0x91010009)
        self.assertEqual([n for n, _, _ in backend.calls], ["read_messages"] * 3)
        ops._ioctl(10, None, 20)
        self.assertEqual(ops.filter_handles, [])

    def test_native_close_selected_iso81_and_psa_d1_are_real_exchanges(self):
        for function, bus, flags, variant in (
            (0x81, 0x1C, 1, "normal"),
            (0xD1, 0x12, 0x14, "psa"),
        ):
            profile = selected_profile(bus, flags=flags)
            table = profile.catalog.management.sections[18]
            row = bytearray(table.payload)
            struct.pack_into(
                "<H", row, 3 * 16 + 2, function
            )  # Existing final synthetic frame.
            profile.catalog.management.sections[18] = replace(table, payload=bytes(row))
            # Construct the plan before changing the startup function reference.
            original = selected_profile(bus, flags=flags)
            plan = get_comm_frame(original, b"\x22", bus_id=bus, driver=DRIVER)
            backend = DriverPrimitive()
            ops = native_operations(
                backend, profile=profile, plan=plan, bus=bus, native_variant=variant
            )
            ops.adopt_channel(9, owned=True)
            ops.set_preinit_d1_suppressed(0)
            self.assertEqual(ops.close(), 0)
            self.assertEqual(
                [n for n, _, _ in backend.calls],
                ["ioctl", "write_messages", "read_messages", "disconnect"],
            )
            self.assertEqual(backend.calls[1][1]["messages"][0].data[-1:], b"\x81")
            self.assertEqual(ops.close(), 0)
            self.assertEqual(len(backend.calls), 4)

    def test_every_transport_boundary_fault_cancel_and_cleanup_retry(self):
        for kind in ("fault", "cancel"):
            for boundary in range(1, 8):
                with self.subTest(kind=kind, boundary=boundary):
                    backend = DriverPrimitive(
                        [native_can(b"\x62")],
                        fault_at=boundary if kind == "fault" else 0,
                        cancel_at=boundary if kind == "cancel" else 0,
                    )
                    ops = native_operations(backend)
                    with self.assertRaises(
                        OSError if kind == "fault" else InterruptedError
                    ):
                        ops.open()
                        ops.send(b"\x22", timeout=20, initialization_mode=2)
                        ops.receive(maximum=64, timeout=20)
                    self.assertTrue(ops.poisoned)
                    self.assertIsNone(ops.channel)
        for boundary in (8, 9):
            backend = DriverPrimitive([native_can(b"\x62")], fault_at=boundary)
            ops = native_operations(backend)
            ops.open()
            ops.send(b"\x22", timeout=20, initialization_mode=2)
            ops.receive(maximum=64, timeout=20)
            with self.assertRaises(OSError):
                ops.close()
            self.assertIsNotNone(ops.channel)
            self.assertEqual(ops.close(), 0)
            self.assertIsNone(ops.channel)

    def test_reopen_rebuilds_configuration_for_new_owned_channel(self):
        backend = DriverPrimitive()
        ops = native_operations(backend)
        for _ in range(2):
            self.assertEqual(ops.open(), 0)
            self.assertEqual(ops.close(), 0)
        self.assertEqual(sum(n == "connect" for n, _, _ in backend.calls), 2)
        self.assertEqual(
            sum(n == "start_message_filter" for n, _, _ in backend.calls), 2
        )
        self.assertEqual(
            sum(n == "ioctl" and f["ioctl_id"] == 2 for n, f, _ in backend.calls), 2
        )

    def test_signed_native_clear_flag_only_one_clears_rx(self):
        backend = DriverPrimitive()
        ops = native_operations(backend)
        ops.adopt_channel(9)
        for flag in (-1, 0, 2, 0xFFFFFFFF):
            self.assertEqual(
                ops.send(b"\x22", timeout=20, initialization_mode=2, clear_rx=flag), 0
            )
        self.assertEqual([n for n, _, _ in backend.calls], ["write_messages"] * 4)

    def test_runtime_psa_metadata_does_not_require_unused_tester_frame(self):
        from scripts.frame_transport import runtime_frame_plan

        for version in (12, 18):
            profile = selected_profile(version=version, flags=0x15)
            table = profile.catalog.management.sections[18]
            rows = [table.payload[i : i + 16] for i in range(0, len(table.payload), 16)]
            profile.catalog.management.sections[18] = replace(
                table,
                count=3,
                payload=b"".join(
                    row for row in rows if struct.unpack_from("<H", row, 2)[0] != 0x7F
                ),
            )
            with self.assertRaises(FrameTransportError):
                get_comm_frame(profile, b"\x22", bus_id=0x12, driver=DRIVER)
            plan = runtime_frame_plan(
                profile,
                b"\x22",
                native_build=version,
                native_variant="psa",
                bus_id=0x12,
                driver=DRIVER,
            )
            self.assertEqual(plan.tester_request, b"")
            backend = DriverPrimitive()
            ops = native_operations(
                backend,
                version=version,
                profile=profile,
                plan=plan,
                native_variant="psa",
            )
            ops.adopt_channel(9)
            self.assertEqual(ops.setup(), 0)

    def test_runtime_j1850_protocol_two_has_source_selected_header(self):
        from scripts.frame_transport import runtime_frame_plan

        profile = selected_profile(0x16)
        with self.assertRaises(FrameTransportError):
            get_comm_frame(profile, b"\x22", bus_id=0x16, driver=DRIVER)
        plan = runtime_frame_plan(
            profile,
            b"\x22",
            native_build=18,
            native_variant="normal",
            bus_id=0x16,
            driver=DRIVER,
        )
        self.assertEqual(plan.connect, NativeConnect(2, 0))
        self.assertEqual(plan.send.data, bytes.fromhex("61dff022"))
        self.assertEqual(plan.send.protocol_id, 2)
        with self.assertRaises(FrameTransportError):
            runtime_frame_plan(
                selected_profile(0x1C),
                b"\x22",
                native_build=18,
                native_variant="normal",
                bus_id=0x1C,
                driver=DRIVER,
            )

    def test_iso_initialization_fault_cancel_at_actual_primitive_boundaries(self):
        from scripts.frame_transport import J2534Result

        class FastInit(DriverPrimitive):
            def invoke(self, operation, fields, **options):
                result = super().invoke(operation, fields, **options)
                if operation == "ioctl" and fields["ioctl_id"] == 5:
                    data = bytes.fromhex("83f0e0c10808")
                    return J2534Result(
                        messages=(NativeMessage(4, 0, 0, 0, len(data), data),)
                    )
                return result

        profile = selected_profile(0x11, init_flags=1)
        data = bytes.fromhex("81f0e062")
        response = NativeMessage(4, 0, 0, 0, len(data), data)
        for kind in ("fault", "cancel"):
            for boundary in range(3, 9):
                with self.subTest(kind=kind, boundary=boundary):
                    backend = FastInit(
                        [J2534Result(code=9), response],
                        fault_at=boundary if kind == "fault" else 0,
                        cancel_at=boundary if kind == "cancel" else 0,
                    )
                    ops = native_operations(backend, bus=0x11, profile=profile)
                    self.assertEqual(ops.open(), 0)
                    with self.assertRaises(
                        OSError if kind == "fault" else InterruptedError
                    ):
                        ops.send(b"\x22", timeout=20)
                        ops.receive(maximum=64, timeout=20)
                    self.assertTrue(ops.poisoned)
                    self.assertIsNone(ops.channel)

    def test_owned_worker_can_defer_only_confirmed_host_cancellation(self):
        from scripts.frame_transport import J2534Result

        backend = DriverPrimitive(cancel_at=2)
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        ops.defer_cancel_cleanup = True
        with self.assertRaises(InterruptedError):
            ops.send(b"\x22", timeout=20, initialization_mode=2)
        self.assertEqual(ops.channel, 9)
        self.assertFalse(ops.poisoned)
        backend.stopped = False  # Owning worker's separate bounded stop lease.
        self.assertEqual(ops.send(b"\xa3", timeout=20, initialization_mode=2), 0)
        self.assertEqual(ops.close(), 0)

        class Uncertain(DriverPrimitive):
            def invoke(self, operation, fields, **options):
                result = super().invoke(operation, fields, **options)
                if operation == "write_messages":
                    self.stopped = True
                    return J2534Result(count=0)
                return result

        backend = Uncertain()
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        ops.defer_cancel_cleanup = True
        with self.assertRaises(OSError):
            ops.send(b"\x22", timeout=20, initialization_mode=2)
        self.assertTrue(ops.poisoned)
        self.assertIsNone(ops.channel)

        class InterruptedBackend(DriverPrimitive):
            def invoke(self, operation, fields, **options):
                if operation == "write_messages":
                    raise InterruptedError("Unconfirmed backend write interrupted")
                return super().invoke(operation, fields, **options)

        backend = InterruptedBackend()
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        ops.defer_cancel_cleanup = True
        with self.assertRaises(InterruptedError):
            ops.send(b"\x22", timeout=20, initialization_mode=2)
        self.assertTrue(ops.poisoned)
        self.assertIsNone(ops.channel)

    def test_owned_worker_deadline_defer_requires_confirmed_primitive(self):
        class LateConfirmed(DriverPrimitive):
            def invoke(self, operation, fields, **options):
                result = super().invoke(operation, fields, **options)
                if operation == "write_messages":
                    self.now += 1
                return result

        backend = LateConfirmed()
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        ops.defer_cancel_cleanup = True
        with self.assertRaises(TimeoutError):
            ops.send(b"\x22", timeout=20, initialization_mode=2, deadline=10.5)
        self.assertFalse(ops.poisoned)
        self.assertEqual(ops.channel, 9)
        self.assertEqual(
            ops.send(b"\xa3", timeout=20, initialization_mode=2, deadline=20), 0
        )
        self.assertEqual(ops.close(), 0)

    def test_rebind_retains_channel_and_identical_selected_configuration(self):
        backend = DriverPrimitive()
        ops = native_operations(backend)
        ops.adopt_channel(9, configured=True)
        plan = get_comm_frame(ops.profile, b"\x3e", bus_id=0x12, driver=DRIVER)
        ops.rebind(ops.profile, plan, bus_id=0x12)
        self.assertEqual(ops.channel, 9)
        self.assertEqual(ops.setup(), 0)
        self.assertFalse(backend.calls)
        table = ops.profile.catalog.management.sections[13]
        changed = bytearray(table.payload)
        struct.pack_into("<H", changed, 8, 0x760)
        ops.profile.catalog.management.sections[13] = replace(
            table, payload=bytes(changed)
        )
        plan = get_comm_frame(ops.profile, b"\x3e", bus_id=0x12, driver=DRIVER)
        ops.rebind(ops.profile, plan, bus_id=0x12)
        self.assertEqual(
            ops._frame_message(b"\x3e").data[:4], bytes.fromhex("00000760")
        )
        self.assertEqual(ops.setup(), 0)
        self.assertTrue(backend.calls)

    def test_rebind_rejects_protocol_change_before_mutating_owned_context(self):
        backend = DriverPrimitive()
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        old_profile = ops.profile
        different = selected_profile(0x11)
        plan = get_comm_frame(different, b"\x22", bus_id=0x11, driver=DRIVER)
        with self.assertRaises(ValueError):
            ops.rebind(different, plan, bus_id=0x11)
        self.assertIs(ops.profile, old_profile)
        self.assertEqual((ops.channel, ops.bus_id), (9, 0x12))
        self.assertFalse(backend.calls)

    def test_pending_limit_executes_literal_tester_exchange_without_overwriting_resend(
        self,
    ):
        backend = DriverPrimitive(
            [native_can(bytes.fromhex("7f2278")), native_can(b"\x7e")]
        )
        ops = native_operations(backend)
        ops.adopt_channel(9)
        written = []
        ops.set_packet_log(lambda data: written.append(data) or len(data))
        ops.pending_limit = 1
        self.assertEqual(ops.send(b"\x22", timeout=25, initialization_mode=2), 0)
        previous, tick = ops.last_message, ops.last_send_tick
        self.assertEqual(ops.receive(maximum=64, timeout=50).code, 0x90020323)
        writes = [f for n, f, _ in backend.calls if n == "write_messages"]
        self.assertEqual(
            [f["messages"][0].data for f in writes],
            [bytes.fromhex("000007e022"), bytes.fromhex("000007e03e")],
        )
        self.assertIs(ops.last_message, previous)
        self.assertEqual(ops.last_send_tick, tick)
        self.assertFalse(ops._recovering_pending)
        self.assertEqual(written, [b"22\\n", b"7F2278\\n", b"3E\\n", b"7E\\n"])

    def test_burst_state_gates_active_test_and_cleared_category_skips_close_exchange(
        self,
    ):
        backend = DriverPrimitive()
        profile = selected_profile(flags=0x14)
        functions = profile.catalog.management.sections[18]
        rows = bytearray(functions.payload)
        struct.pack_into("<H", rows, 3 * 16 + 2, 0xD1)
        profile.catalog.management.sections[18] = replace(
            functions, payload=bytes(rows)
        )
        ops = native_operations(backend, profile=profile, native_variant="psa")
        ops.adopt_channel(9, owned=True)
        self.assertEqual(ops.send(b"\x30\x01", timeout=20, initialization_mode=2), 0)
        self.assertFalse(ops.active_test)
        ops.set_burst_mode_state(1)
        self.assertEqual(ops.send(b"\x30\x01", timeout=20, initialization_mode=2), 0)
        self.assertTrue(ops.active_test)
        self.assertTrue(ops.timestamp_unwrap)
        ops.set_burst_mode_state(0)
        self.assertFalse(ops.active_test)
        ops.set_preinit_d1_suppressed(0)
        ops.clear_runtime_context()
        backend.calls.clear()
        self.assertEqual(ops.pre_initialize(), 0)
        self.assertEqual(ops.finish_bus_session(), 0)
        self.assertEqual(ops.close(), 0)
        self.assertEqual([n for n, _, _ in backend.calls], ["disconnect"])

    def test_cleanup_host_boundaries_preserve_only_unreleased_ownership(self):
        from scripts.frame_transport import J2534Result

        class BoundaryCleanup(DriverPrimitive):
            boundary: (
                Literal[
                    "cancelled_before",
                    "deadline_before",
                    "cancelled_after",
                    "deadline_after",
                ]
                | None
            ) = "deadline_before"
            operation = "stop_message_filter"

            def invoke(self, operation, fields, **options):
                if operation == self.operation and self.boundary:
                    self.calls.append((operation, fields, options["deadline"]))
                    return J2534Result(host_boundary=self.boundary)
                return super().invoke(operation, fields, **options)

        for operation in ("stop_message_filter", "disconnect"):
            for boundary in (
                "deadline_before",
                "deadline_after",
                "cancelled_before",
                "cancelled_after",
            ):
                with self.subTest(operation=operation, boundary=boundary):
                    backend = BoundaryCleanup()
                    backend.operation, backend.boundary = operation, boundary
                    ops = native_operations(backend)
                    ops.adopt_channel(9, owned=True)
                    ops.filter_handles[:] = [31]
                    with self.assertRaises(
                        TimeoutError
                        if boundary.startswith("deadline")
                        else InterruptedError
                    ):
                        ops.close()
                    released = boundary.endswith("_after")
                    if operation == "stop_message_filter":
                        self.assertEqual(ops.filter_handles, [] if released else [31])
                        self.assertEqual(ops.channel, 9)
                    else:
                        self.assertEqual(ops.filter_handles, [])
                        self.assertEqual(ops.channel, None if released else 9)
                        self.assertEqual(ops.owns_channel, not released)
                    backend.boundary = None
                    self.assertEqual(ops.close(), 0)
                    self.assertIsNone(ops.channel)

    def test_typed_host_boundary_preserves_counts_and_no_io_observation(self):
        from scripts.frame_transport import J2534Result

        class Wrapped(DriverPrimitive):
            boundary: (
                Literal[
                    "cancelled_before",
                    "deadline_before",
                    "cancelled_after",
                    "deadline_after",
                ]
                | None
            ) = None
            confirmed_count = 1

            def invoke(self, operation, fields, **options):
                if operation == "write_messages" and self.boundary:
                    if self.boundary.endswith("_before"):
                        return J2534Result(host_boundary=self.boundary)
                    return J2534Result(
                        count=self.confirmed_count, host_boundary=self.boundary
                    )
                return super().invoke(operation, fields, **options)

        for boundary in (
            "cancelled_before",
            "deadline_before",
            "cancelled_after",
            "deadline_after",
        ):
            backend = Wrapped()
            backend.boundary = boundary
            ops = native_operations(backend)
            ops.adopt_channel(9, owned=True)
            ops.defer_cancel_cleanup = True
            with self.assertRaises(
                InterruptedError if boundary.startswith("cancelled") else TimeoutError
            ):
                ops.send(b"\x22", timeout=20, initialization_mode=2)
            self.assertFalse(ops.poisoned)
            self.assertEqual(ops.channel, 9)
            backend.boundary = None
            self.assertEqual(ops.close(), 0)
        backend = Wrapped()
        backend.boundary = "cancelled_after"
        backend.confirmed_count = 0
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        ops.defer_cancel_cleanup = True
        with self.assertRaises(OSError):
            ops.send(b"\x22", timeout=20, initialization_mode=2)
        self.assertTrue(ops.poisoned)
        self.assertIsNone(ops.channel)
        with self.assertRaises(ValueError):
            J2534Result(count=1, host_boundary="cancelled_before")

    def test_host_clock_failure_after_confirmed_write_can_use_owned_cleanup_clock(self):
        class BrokenClock(DriverPrimitive):
            bad = False

            def invoke(self, operation, fields, **options):
                result = super().invoke(operation, fields, **options)
                if operation == "write_messages":
                    self.bad = True
                return result

            def clock(self):
                return float("nan") if self.bad else self.now

        backend = BrokenClock()
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        ops.defer_cancel_cleanup = True
        with self.assertRaises(ValueError):
            ops.send(b"\x22", timeout=20, initialization_mode=2)
        self.assertEqual(ops.last_confirmed_clock, 10)
        self.assertFalse(ops.poisoned)
        self.assertEqual(ops.channel, 9)
        backend.bad = False
        self.assertEqual(ops.close(), 0)

    def test_iso_pending_recovery_uses_interrupt_and_restores_after_confirmed_status(
        self,
    ):
        data = bytes.fromhex("81f0e07e")
        backend = DriverPrimitive([NativeMessage(4, 0, 0, 0, len(data), data)])
        ops = native_operations(backend, bus=0x11)
        ops.adopt_channel(9)
        self.assertEqual(ops.recover_pending(timeout=50), 0)
        self.assertAlmostEqual(backend.now, 11)
        self.assertFalse(ops.write_without_wait)
        configs = [
            f["input"]
            for n, f, _ in backend.calls
            if n == "ioctl" and f["ioctl_id"] == 2
        ]
        self.assertEqual(
            configs,
            [
                (NativeConfig(0x10500, 1),),
                (NativeConfig(0x1000B, 0),),
                (NativeConfig(0x10500, 0),),
                (NativeConfig(0x1000B, 0),),
            ],
        )
        write = next(f for n, f, _ in backend.calls if n == "write_messages")
        self.assertEqual(write["timeout"], 0)
        self.assertEqual(write["messages"][0].data, bytes.fromhex("81e0f03e"))
        self.assertIsNone(ops.last_message)

    def test_uncertain_pending_tester_write_does_not_issue_interrupt_restore_io(self):
        backend = DriverPrimitive(fault_at=4)
        ops = native_operations(backend, bus=0x11)
        ops.adopt_channel(9, owned=True)
        ops.defer_cancel_cleanup = True
        with self.assertRaises(OSError):
            ops.recover_pending(timeout=50)
        self.assertTrue(ops.poisoned)
        self.assertIsNone(ops.channel)
        self.assertEqual(
            [n for n, _, _ in backend.calls],
            ["ioctl", "ioctl", "ioctl", "write_messages", "disconnect"],
        )

    def test_partial_negative_does_not_advance_native_timestamp_rollover_state(self):
        backend = DriverPrimitive(
            [
                native_can(b"\x62", stamp=0xFFFFFF00),
                native_can(bytes.fromhex("7f2213"), stamp=0x10),
                native_can(b"\x62", stamp=0xFFFFFFF0),
            ]
        )
        ops = native_operations(backend)
        ops.adopt_channel(9)
        ops.set_burst_mode_state(1)
        first = ops.receive(maximum=64, timeout=20)
        self.assertEqual(ops.receive(maximum=64, timeout=20).code, 0x90020321)
        last = ops.receive(maximum=64, timeout=20)
        self.assertGreaterEqual(last.timestamp, first.timestamp)
        self.assertLess(last.timestamp - first.timestamp, 1)

    def test_confirmed_write_is_logged_before_host_post_boundary_failure(self):
        backend = DriverPrimitive(cancel_at=2)
        ops = native_operations(backend)
        ops.adopt_channel(9, owned=True)
        ops.defer_cancel_cleanup = True
        written = []
        ops.set_packet_log(lambda data: written.append(data) or len(data))
        with self.assertRaises(InterruptedError):
            ops.send(b"\x22", timeout=20, initialization_mode=2)
        self.assertEqual(written, [b"22\\n"])
        self.assertFalse(ops.poisoned)
        self.assertEqual(ops.close(), 0)


class NativeMultiMonTests(unittest.TestCase):
    def joined(
        self,
        version: Literal[12, 18] = 18,
        *,
        backend=None,
        targets_count=2,
        bus=0x12,
        flags=3,
        startup=True,
        tester=True,
        close58=False,
    ):
        from scripts.frame_transport import NativeMultiMonOperations
        from scripts.monitor_dual import DualTarget

        profiles, targets = {}, []
        for index in range(targets_count):
            profile = selected_profile(bus=bus, version=version, flags=flags)
            category, address = 42 + index, 0x7E0 + index
            category_record = bytearray(profile.category_record)
            struct.pack_into("<H", category_record, 68, category)
            sections = dict(profile.catalog.management.sections)
            for slot, width in ((13, 24 if version == 12 else 28), (18, 16)):
                section = sections[slot]
                data = bytearray(section.payload)
                for offset in range(0, len(data), width):
                    struct.pack_into("<H", data, offset, category)
                if slot == 13:
                    struct.pack_into("<H", data, 8, address)
                sections[slot] = replace(section, payload=bytes(data))
            if close58:
                function_data = bytearray(sections[18].payload)
                struct.pack_into("<H", function_data, 16 + 2, 0x58)
                sections[18] = replace(sections[18], payload=bytes(function_data))
            functions = [
                row
                for row in sections[18].rows(16)
                if (startup or struct.unpack_from("<H", row, 2)[0] != 0x67)
                and (tester or struct.unpack_from("<H", row, 2)[0] != 0x7F)
            ]
            functions.sort(key=lambda row: struct.unpack_from("<HH", row))
            sections[18] = replace(
                sections[18], count=len(functions), payload=b"".join(functions)
            )
            can = bytearray(sections[14].payload)
            struct.pack_into("<I", can, 4, 500000 + index * 100000)
            sections[14] = replace(sections[14], payload=bytes(can))
            sections[16] = replace(sections[16], payload=bytes(category_record))
            sections[29] = Section(
                29, 0, 1, False, struct.pack("<II", 1000, 200) + bytes(8)
            )
            profile.catalog.management = replace(
                profile.catalog.management,
                sections=sections,
                sha256=f"authored-multimon-{version}-{category}",
            )
            profile = replace(profile, category_record=bytes(category_record))
            ecu = f"ecu-{category}"
            profiles[ecu] = profile
            targets.append(
                DualTarget(
                    ecu,
                    address,
                    address | 8,
                    bus,
                    flags,
                    category,
                    1,
                    entry_parameter=address,
                )
            )
        backend = backend or DriverPrimitive()
        operations = NativeMultiMonOperations(
            targets,
            profiles,
            backend,
            driver=DRIVER,
            native_build=version,
            source_identity=f"authored native source{version}",
            device_kind=8,
            clock=backend.clock,
            wait=backend.wait,
            cancelled=backend.cancelled,
        )
        return operations, backend

    def test_two_selected_targets_share_one_channel_and_skip_ordinary_initialization(
        self,
    ):
        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            with self.subTest(version=version):
                ops, backend = self.joined(version)
                self.assertEqual(backend.calls, [])
                self.assertEqual(ops.connect_multi_mon(deadline=20), 0)
                for target in ops.targets:
                    assert target.entry_parameter is not None
                    self.assertEqual(
                        ops.entry_comm_system_info(
                            target.command_id,
                            target.protocol,
                            target.entry_parameter,
                            deadline=20,
                        ),
                        0,
                    )
                backend.calls.clear()
                self.assertEqual(
                    ops.send_multi_mon(
                        42,
                        b"\x21\x10",
                        timeout=77,
                        bus=0x12,
                        argument_6=1,
                        deadline=20,
                    ),
                    0,
                )
                self.assertEqual(
                    ops.send_multi_mon(
                        43,
                        b"\x21\x11",
                        timeout=88,
                        bus=0x12,
                        deadline=20,
                    ),
                    0,
                )
                writes = [f for op, f, _ in backend.calls if op == "write_messages"]
                self.assertEqual(
                    [f["messages"][0].data for f in writes],
                    [
                        bytes.fromhex("000007e02110"),
                        bytes.fromhex("000007e12111"),
                    ],
                )
                self.assertEqual([f["timeout"] for f in writes], [77, 88])
                self.assertEqual([f["channel_id"] for f in writes], [7, 7])
                configs = [
                    f["input"]
                    for op, f, _ in backend.calls
                    if op == "ioctl" and f["ioctl_id"] == 2
                ]
                self.assertEqual(
                    [config[0].value for config in configs], [500000, 600000]
                )
                backend.replies[:] = [native_can(b"\x61\x11\xaa", address=0x7E9)]
                result = ops.receive(maximum=4096, timeout=33, deadline=20)
                self.assertEqual(
                    (result.data, result.source_id), (b"\x61\x11\xaa", 0x7E9)
                )
                self.assertEqual(ops.close(disconnect_flag=1, deadline=20), 0)
                self.assertEqual(
                    sum(op == "disconnect" for op, _, _ in backend.calls), 1
                )

    def test_target_limit_and_unknown_selection_reject_before_wire_io(self):
        with self.assertRaises(ValueError):
            self.joined(targets_count=3)
        ops, backend = self.joined()
        with self.assertRaises(ValueError):
            ops.send_multi_mon(99, b"\x21", timeout=1, bus=0x12, deadline=20)
        with self.assertRaises(ValueError):
            ops.entry_comm_system_info(42, 0x12, 9, deadline=20)
        with self.assertRaises(ValueError):
            ops.send_multi_mon(42, bytes(65536), timeout=1, bus=0x12, deadline=20)
        self.assertEqual(backend.calls, [])

    def test_confirmed_connect_cancellation_retains_only_actual_owned_handle(self):
        from scripts.frame_transport import J2534Result

        class Boundary(DriverPrimitive):
            before = False

            def invoke(self, operation, fields, **options):
                if operation == "connect":
                    self.calls.append((operation, fields, options["deadline"]))
                    return (
                        J2534Result(host_boundary="cancelled_before")
                        if self.before
                        else J2534Result(handle=7, host_boundary="cancelled_after")
                    )
                return super().invoke(operation, fields, **options)

        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            for before in (True, False):
                with self.subTest(version=version, before=before):
                    backend = Boundary()
                    backend.before = before
                    ops, _ = self.joined(version, backend=backend)
                    ops.defer_cancel_cleanup = True
                    with self.assertRaises(InterruptedError):
                        ops.connect_multi_mon(deadline=20)
                    self.assertFalse(ops.control.poisoned)
                    self.assertFalse(ops.operations.poisoned)
                    self.assertEqual(ops.control.channel, None if before else 7)
                    self.assertEqual(
                        [name for name, _, _ in backend.calls], ["connect"]
                    )
                    self.assertEqual(ops.close(deadline=20), 0)
                    self.assertIsNone(ops.control.channel)

    def test_unconfirmed_write_count_poison_is_resource_only_in_both_builds(self):
        from scripts.frame_transport import J2534Result

        class ShortWrite(DriverPrimitive):
            def invoke(self, operation, fields, **options):
                if operation == "write_messages":
                    self.calls.append((operation, fields, options["deadline"]))
                    self.stopped = True
                    return J2534Result(count=0, host_boundary="cancelled_after")
                return super().invoke(operation, fields, **options)

        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            with self.subTest(version=version):
                ops, backend = self.joined(version, backend=ShortWrite())
                ops.connect_multi_mon(deadline=20)
                for target in ops.targets:
                    assert target.entry_parameter is not None
                    ops.entry_comm_system_info(
                        target.command_id,
                        target.protocol,
                        target.entry_parameter,
                        deadline=20,
                    )
                backend.calls.clear()
                ops.defer_cancel_cleanup = True
                with self.assertRaises(OSError):
                    ops.send_multi_mon(
                        42, b"\x21\x10", timeout=1, bus=0x12, deadline=20
                    )
                self.assertTrue(ops.operations.poisoned)
                self.assertTrue(ops.control.poisoned)
                self.assertIsNone(ops.control.channel)
                self.assertEqual(
                    sum(name == "write_messages" for name, _, _ in backend.calls), 1
                )
                self.assertEqual(
                    sum(name == "disconnect" for name, _, _ in backend.calls), 1
                )
                self.assertEqual(ops.close(deadline=20), 0)

    def test_native_activation_status_is_ignored_but_wire_status_is_returned(self):
        from scripts.frame_transport import J2534Result

        class WireError(DriverPrimitive):
            fail_write = False

            def invoke(self, operation, fields, **options):
                if operation == "write_messages" and self.fail_write:
                    self.calls.append((operation, fields, options["deadline"]))
                    return J2534Result(code=7)
                return super().invoke(operation, fields, **options)

        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            with self.subTest(version=version):
                ops, backend = self.joined(version, backend=WireError())
                assert isinstance(backend, WireError)
                ops.connect_multi_mon(deadline=20)
                for target in ops.targets:
                    assert target.entry_parameter is not None
                    ops.entry_comm_system_info(
                        target.command_id,
                        target.protocol,
                        target.entry_parameter,
                        deadline=20,
                    )
                backend.calls.clear()
                backend.config_failures[:] = [7]
                self.assertEqual(
                    ops.send_multi_mon(42, b"\x21", timeout=10, bus=0x12, deadline=20),
                    0,
                )
                self.assertEqual(
                    sum(name == "write_messages" for name, _, _ in backend.calls), 1
                )
                backend.fail_write = True
                self.assertEqual(
                    ops.send_multi_mon(43, b"\x21", timeout=10, bus=0x12, deadline=20),
                    0x91010007,
                )
                self.assertFalse(ops.operations.poisoned)
                self.assertFalse(ops.control.poisoned)
                self.assertEqual(ops.control.channel, 7)
                backend.calls.clear()
                with self.assertRaises(FrameTransportError):
                    ops.send_multi_mon(
                        42, bytes(MAX_DATA), timeout=1, bus=0x12, deadline=20
                    )
                self.assertEqual(backend.calls, [])
                backend.fail_write = False
                self.assertEqual(ops.close(deadline=20), 0)

    def test_shared_can_constructor_supports_selected_low8_and_restores_lease_flags(
        self,
    ):
        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            with self.subTest(version=version):
                ops, backend = self.joined(version, targets_count=1, bus=0x18)
                with self.assertRaises(FrameTransportError):
                    get_comm_frame(
                        ops.profiles[ops.targets[0].ecu],
                        b"\x21",
                        bus_id=0x18,
                        driver=DRIVER,
                    )
                self.assertEqual(ops.connect_multi_mon(deadline=20), 0)
                self.assertEqual(
                    ops.entry_comm_system_info(42, 0x18, 0x7E0, deadline=20), 0
                )
                ops.defer_cancel_cleanup = True
                self.assertTrue(ops.operations.defer_cancel_cleanup)
                original = ops.cancelled
                ops.cancelled = lambda: False
                self.assertIs(ops.cancelled, ops.operations.cancelled)
                self.assertEqual(
                    ops.send_multi_mon(42, b"\x21", timeout=1, bus=0x18, deadline=20), 0
                )
                written = [
                    f["messages"][0]
                    for name, f, _ in backend.calls
                    if name == "write_messages"
                ]
                self.assertEqual(
                    [(m.protocol_id, m.data) for m in written],
                    [(6, bytes.fromhex("000007e021"))],
                )
                self.assertEqual(ops.close(deadline=20), 0)
                ops.cancelled = original
                ops.defer_cancel_cleanup = False
                self.assertIs(ops.operations.cancelled, original)
                self.assertFalse(ops.operations.defer_cancel_cleanup)

    def test_multimon_uses_normal_can_pending_state_and_requires_only_tester_metadata(
        self,
    ):
        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            with self.subTest(version=version):
                backend = DriverPrimitive()
                with self.assertRaises(ValueError):
                    self.joined(version, backend=backend, flags=0x14, tester=False)
                self.assertEqual(backend.calls, [])
                ops, backend = self.joined(version, targets_count=1, startup=False)
                self.assertEqual(ops.operations.native_variant, "multi")
                self.assertFalse(ops.operations.pending_by_time)
                self.assertEqual(ops.operations.plan.startup_request, b"")
                self.assertEqual(ops.operations.plan.tester_request, b"\x3e")
                self.assertEqual(ops.connect_multi_mon(deadline=20), 0)
                self.assertEqual(
                    ops.entry_comm_system_info(42, 0x12, 0x7E0, deadline=20), 0
                )
                self.assertEqual(
                    ops.send_multi_mon(42, b"\x21", timeout=1, bus=0x12, deadline=20), 0
                )
                self.assertEqual(ops.close(deadline=20), 0)

    def test_multimon_filter_override_is_pure_and_retains_selected_context(self):
        ops, backend = self.joined(targets_count=1)
        lower = ops.operations
        previous = (lower.bus_id, lower.protocol_record, lower.plan)
        filters = lower._can_filters(bus_id=0x1A, protocol_record=lower.protocol_record)
        self.assertEqual([f.filter_type for f in filters], [1, 3])
        self.assertEqual(filters[0].pattern.data, bytes.fromhex("000007c0"))
        self.assertEqual(filters[1].flow_control.data, bytes.fromhex("000007e0"))
        functional = lower._can_filters(
            bus_id=0x32, protocol_record=lower.protocol_record
        )
        self.assertEqual(len(functional), 9)
        self.assertEqual(functional[0].mask.data, bytes.fromhex("000007f8"))
        self.assertEqual((lower.bus_id, lower.protocol_record, lower.plan), previous)
        with self.assertRaises(ValueError):
            lower._can_filters(bus_id=True)
        with self.assertRaises(ValueError):
            lower._can_filters(protocol_record=bytes(23))
        self.assertEqual(backend.calls, [])

    def test_multimon_phase5_disconnect_one_reconfigures_without_default_session_write(
        self,
    ):
        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            with self.subTest(version=version):
                ops, backend = self.joined(version, targets_count=1, flags=0x14)
                self.assertEqual(ops.connect_multi_mon(deadline=20), 0)
                self.assertEqual(
                    ops.entry_comm_system_info(42, 0x12, 0x7E0, deadline=20), 0
                )
                self.assertEqual(
                    ops.send_multi_mon(42, b"\x21", timeout=1, bus=0x12, deadline=20), 0
                )
                backend.calls.clear()
                self.assertEqual(ops.close(disconnect_flag=1, deadline=20), 0)
                self.assertEqual(
                    [name for name, _, _ in backend.calls],
                    [
                        "ioctl",
                        "start_message_filter",
                        "disconnect",
                    ],
                )
                self.assertEqual(ops.control.current_service, 0x10)
                self.assertEqual(ops.operations.current_service, 0x10)
                self.assertEqual(
                    ops.operations.request_state, 1 if version == 18 else 0
                )

    def test_multimon_broken_shared_clock_still_releases_resource_on_default_cleanup(
        self,
    ):
        ops, backend = self.joined(targets_count=1)
        ops.connect_multi_mon(deadline=20)
        ops.entry_comm_system_info(42, 0x12, 0x7E0, deadline=20)
        ops.send_multi_mon(42, b"\x21", timeout=1, bus=0x12, deadline=20)
        broken = lambda: float("nan")
        ops.operations.clock = ops.control.clock = broken
        backend.calls.clear()
        with self.assertRaises(ValueError):
            ops.close(deadline=float("inf"))
        self.assertEqual(backend.calls, [])
        self.assertEqual(ops.close(), 0)
        self.assertIsNone(ops.control.channel)
        self.assertEqual([name for name, _, _ in backend.calls], ["disconnect"])
        self.assertIsNotNone(ops.cleanup_error)
        self.assertIs(ops.control.clock, broken)
        self.assertEqual(ops.close(), 0)

    def test_confirmed_new_generation_resets_native_state_and_preserves_host_lease(
        self,
    ):
        from scripts.frame_transport import NativeFrameOperations

        ops, backend = self.joined(targets_count=1)
        lower = ops.operations
        written = []
        lower.set_packet_log(lambda data: written.append(data) or len(data))
        lower.defer_cancel_cleanup = True
        lower.current_service, lower.request_state = 0x10, 1
        lower.pending_count, lower.last_activity = 5, 100
        lower.active_test = lower.poisoned = True
        lower.preinit_d1_suppressed = 0
        lower.last_message = native_can(b"\x21")
        lower._now()
        callback, hooks = lower.cancelled, lower.packet_log_hooks
        lower.reset_released_runtime()
        self.assertEqual(
            (
                lower.current_service,
                lower.request_state,
                lower.pending_count,
                lower.last_activity,
            ),
            (0, 0, 0, 0),
        )
        self.assertFalse(lower.active_test)
        self.assertFalse(lower.poisoned)
        self.assertEqual(lower.preinit_d1_suppressed, 1)
        self.assertIsNone(lower.last_message)
        self.assertTrue(lower.defer_cancel_cleanup)
        self.assertIs(lower.cancelled, callback)
        self.assertEqual(lower.packet_log_hooks, hooks)
        self.assertEqual(lower.last_confirmed_clock, 10)
        lower.adopt_channel(7)
        with self.assertRaises(RuntimeError):
            lower.reset_released_runtime()
        self.assertEqual(backend.calls, [])
        self.assertIsInstance(lower, NativeFrameOperations)

    def test_multimon_low_a_close_uses_selected_58_without_dual_d1_policy(self):
        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            with self.subTest(version=version):
                ops, backend = self.joined(
                    version, targets_count=1, bus=0x1A, close58=True
                )
                ops.connect_multi_mon(deadline=20)
                ops.entry_comm_system_info(42, 0x1A, 0x7E0, deadline=20)
                ops.send_multi_mon(42, b"\x21", timeout=1, bus=0x1A, deadline=20)
                backend.calls.clear()
                backend.replies[:] = [native_can(b"\xc1")]
                self.assertEqual(ops.close(deadline=20), 0)
                self.assertEqual(
                    [name for name, _, _ in backend.calls],
                    [
                        "ioctl",
                        "write_messages",
                        "read_messages",
                        "disconnect",
                    ],
                )
                write = backend.calls[1][1]
                self.assertEqual(write["messages"][0].data, bytes.fromhex("000007e081"))
                self.assertEqual(write["timeout"], 1000)


class RuntimeEmptySeedTests(unittest.TestCase):
    def test_empty_runtime_descriptor_and_null_initialization_have_no_dummy_wire_byte(
        self,
    ):
        from scripts.frame_transport import runtime_frame_plan

        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            with self.subTest(version=version):
                profile = selected_profile(version=version)
                with self.assertRaises(FrameTransportError) as error:
                    get_comm_frame(profile, b"", bus_id=0x12, driver=DRIVER)
                self.assertEqual(error.exception.status, 0x90020701)
                plan = runtime_frame_plan(
                    profile,
                    b"",
                    native_build=version,
                    native_variant="normal",
                    bus_id=0x12,
                    driver=DRIVER,
                )
                self.assertEqual(plan.send.data, bytes.fromhex("000007e0"))
                backend = DriverPrimitive([native_can(b"\x50\x01")])
                ops = native_operations(
                    backend, version=version, profile=profile, plan=plan
                )
                self.assertEqual(backend.calls, [])
                self.assertEqual(ops.open(deadline=20), 0)
                self.assertEqual(
                    ops.send(None, timeout=10, initialization_mode=0, deadline=20), 0
                )
                writes = [
                    f["messages"][0].data
                    for name, f, _ in backend.calls
                    if name == "write_messages"
                ]
                self.assertEqual(writes, [bytes.fromhex("000007e01001")])
                self.assertEqual(
                    ops.send(None, timeout=10, initialization_mode=1, deadline=20),
                    0x90020701,
                )
                self.assertEqual(ops.close(deadline=20), 0)


class ManagementOnlyTransportTests(unittest.TestCase):
    def test_management_only_profile_needs_no_ecu_database_for_null_protocol_probe(
        self,
    ):
        from scripts.frame_transport import NativeFrameOperations, runtime_frame_plan
        from scripts.profiles import ProtocolProfile, VehicleProfile

        versions: tuple[Literal[12, 18], ...] = (12, 18)
        for version in versions:
            with self.subTest(version=version):
                from scripts.diagnostic_db import Language

                catalog = selected_profile(version=version).catalog
                catalog.language = Language(
                    Database(
                        4,
                        catalog.management.version,
                        "authored-empty-language",
                        {0: Section(0, 0, 0, False, b"")},
                    )
                )
                profile = catalog.build_protocol_profile(42)
                self.assertIsInstance(profile, ProtocolProfile)
                self.assertNotIsInstance(profile, VehicleProfile)
                self.assertEqual(profile.filename, "")
                self.assertIsNone(profile.ecu_database_sha256)
                self.assertFalse(hasattr(profile, "database"))
                self.assertEqual(
                    get_comm_frame(
                        profile, b"\x22", bus_id=0x12, driver=DRIVER
                    ).send.data,
                    bytes.fromhex("000007e022"),
                )
                plan = runtime_frame_plan(
                    profile,
                    b"",
                    native_build=version,
                    native_variant="normal",
                    bus_id=0x12,
                    driver=DRIVER,
                )
                backend = DriverPrimitive([native_can(b"\x50\x01")])
                ops = NativeFrameOperations(
                    profile,
                    plan,
                    backend,
                    native_build=version,
                    bus_id=0x12,
                    driver=DRIVER,
                    device_kind=8,
                    clock=backend.clock,
                    wait=backend.wait,
                )
                self.assertEqual(backend.calls, [])
                self.assertEqual(ops.open(deadline=20), 0)
                self.assertEqual(
                    ops.send(None, timeout=10, initialization_mode=0, deadline=20), 0
                )
                writes = [
                    fields["messages"][0].data
                    for name, fields, _ in backend.calls
                    if name == "write_messages"
                ]
                self.assertEqual(writes, [bytes.fromhex("000007e01001")])
                self.assertEqual(ops.close(deadline=20), 0)
