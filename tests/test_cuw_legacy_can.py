"""Authored primitive replay vectors for executable CAN helper contracts."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts.cuw_legacy_can import (
    CanController,
    CANMemory,
    CANProgress,
    CANTransferState,
    CommonCAN,
    ExecutableCANError,
    OriginalSeedKey,
    basic_conversion,
    calc_block_sizes,
    can_finish_ack,
    cancel_automatic_ig_off,
    ccan_functional_header,
    ccan_m16c_extra_regions,
    ccan_prepare_mode,
    change_reprogramming_mode,
    check_id_payloads,
    collate_seed_key,
    cpu_matches,
    flash_r32c_imported,
    flash_shrink_imported,
    legacy_diagnostic,
    location_headers,
    m16c_flash_regions,
    ordinary_flash_blocks,
    original_location_id,
    p5_collate_seed_key,
    p5_diagnostic,
    p5_session_control,
    parse_zv_records,
    prepare_can_addresses,
    prepare_p5_addresses,
    r32c_block_sizes,
    seed_key_four_round,
    select_block_ranges,
)
from scripts.cuw_legacy_engine import ExecutableIO, ExecutableJ2534Error
from scripts.j2534_2026 import NativeMessage
from scripts.programming import NativeTransportError

TX = bytes.fromhex("00000123")
RX = bytes.fromhex("00000456")


class Replay:
    def __init__(self, replies=()):
        self.replies = iter(replies)
        self.events = []
        self.echoes = []

    def __call__(self, event, remaining):
        self.events.append(event)
        if event["operation"] == "write_messages":
            data = event.get("data", event.get("messages", (b"",))[0])
            self.echoes.append(NativeMessage(6, data[:4], rx_status=9))
            return event["count"]
        if event["operation"] in ("wait", "ioctl", "set_timeout", "set_send_timeout"):
            return None
        if self.echoes:
            return [self.echoes.pop(0)]
        reply = next(self.replies)
        if isinstance(reply, BaseException):
            raise reply
        return [reply if isinstance(reply, NativeMessage) else NativeMessage(6, reply)]


class CommonCANTests(unittest.TestCase):
    def channel(self, replies=()):
        replay = Replay(replies)
        return CommonCAN(ExecutableIO(replay), TX, RX, padding=False), replay

    def test_native_cp_category_is_one_signed_byte_with_unsigned_protocol_view(self):
        error = ExecutableCANError(0xFF)
        self.assertEqual((error.native_code, error.code), (-1, 255))
        controller = CanController.__new__(CanController)
        controller.value_78, controller.value_80 = 0, 0x1234
        controller.capture(error)
        self.assertEqual(controller.value_78, 0xFFFFFFFF)
        self.assertEqual(controller.value_80, 0x1234)
        error.native_code = 0x80
        self.assertEqual((error.native_code, error.code), (-128, 128))
        error.code = 10
        self.assertEqual(error.native_code, 10)
        for invalid in (-129, 256, True):
            with self.assertRaises(ValueError):
                error.native_code = invalid

    def test_controller_rejects_foreign_recovery_ram_before_source_or_io(self):
        from dataclasses import replace

        from scripts.cuw_legacy_engine import ExecutableState
        from scripts.cuw_legacy_recovery import LegacyRecoveryStore
        from tests.test_cuw_legacy_engine import imported_context

        context = imported_context()
        store = LegacyRecoveryStore.from_context(
            context, "authored.cuw", "authored-driver"
        )
        events = []
        io = ExecutableIO(lambda event, remaining: events.append(event))
        for foreign in (
            replace(store, build=12),
            replace(store, container_sha256="0" * 64),
            replace(store, state=ExecutableState()),
        ):
            with (
                patch(
                    "scripts.cuw_legacy_engine.ExecutableImage",
                    side_effect=AssertionError("source read before validation"),
                ),
                self.assertRaisesRegex(ValueError, "recovery.*(RAM|context)"),
            ):
                CanController(replace(context, recovery_store=foreign), io)
        self.assertEqual(events, [])

    def test_ordinary_native_catch_continues_next_block_and_host_fault_escapes(self):
        from scripts.cuw_legacy_engine import ExecutableForeignNativeError

        for error in (ExecutableForeignNativeError("native"), OSError("host")):
            channel, _ = self.channel()
            calls, failures = [], []

            def check(index, *, wide, calls=calls, error=error):
                calls.append(("check", index))
                if index == 1:
                    raise error
                return True

            with (
                patch.object(channel, "ordinary_check_block", check),
                patch.object(
                    channel,
                    "ordinary_write_block",
                    lambda address, data, calls=calls, **kwargs: calls.append(
                        ("write", address, data)
                    ),
                ),
                patch.object(
                    channel,
                    "ordinary_inverify",
                    lambda index, calls=calls, **kwargs: calls.append(
                        ("inverify", index)
                    ),
                ),
                patch.object(
                    channel,
                    "ordinary_verify",
                    lambda index, data, calls=calls, **kwargs: calls.append(
                        ("verify", index, data)
                    ),
                ),
            ):

                def transfer(channel=channel, calls=calls, failures=failures):
                    ordinary_flash_blocks(
                        channel,
                        "1",
                        CANMemory(0, 2047, 1, 0),
                        b"a" * 1024 + b"b" * 1024,
                        wide=False,
                        begin_writing=lambda: calls.append(("begin",)),
                        set_error=lambda value: calls.append(("error", value)),
                        native_failures=failures,
                    )

                if isinstance(error, OSError):
                    with self.assertRaises(OSError) as raised:
                        transfer()
                    self.assertIs(raised.exception, error)
                    self.assertEqual(calls, [("begin",), ("check", 1)])
                else:
                    transfer()
                    self.assertEqual(failures, [error])
                    self.assertEqual(
                        calls,
                        [
                            ("begin",),
                            ("check", 1),
                            ("begin",),
                            ("check", 2),
                            ("error", 13),
                            ("write", 1024, b"b" * 1024),
                            ("error", 99),
                            ("inverify", 2),
                            ("error", 15),
                            ("verify", 2, b"b" * 1024),
                            ("error", 99),
                        ],
                    )

    def test_original_location_id_preserves_short_zeroed_and_pair_crt_rules(self):
        from scripts.cuw_legacy_engine import ExecutableForeignNativeError

        for text, expected in (
            ("", bytes(8)),
            ("98", b"\x98" + bytes(7)),
            (" F+F-F", bytes((15, 15, 241)) + bytes(5)),
            ("0108010000000720", bytes.fromhex("0108010000000720")),
        ):
            self.assertEqual(original_location_id(text), expected)
        self.assertEqual(
            location_headers(original_location_id("98")), (bytes(4), b"\0\0\x98\0")
        )
        for invalid in ("216", "F ", "0x", "gg", "  "):
            with self.assertRaises(ExecutableForeignNativeError):
                original_location_id(invalid)
        with self.assertRaises(ValueError):
            original_location_id("00" * 257)

    def test_m16c_query_only_read_timeout_is_native_false(self):
        channel, replay = self.channel([RX + b"\x7f"])
        self.assertEqual(channel.m16c_query(), 0x7F)
        self.assertEqual(
            [
                event["data"][4:]
                for event in replay.events
                if event["operation"] == "write_messages"
            ],
            [b"\xa8"],
        )
        timeout = ExecutableJ2534Error(1, 9)
        channel, _ = self.channel([timeout])
        self.assertIsNone(channel.m16c_query())
        error = ExecutableJ2534Error(1, 7)
        channel, _ = self.channel([error])
        with self.assertRaises(ExecutableJ2534Error) as raised:
            channel.m16c_query()
        self.assertIs(raised.exception, error)
        channel, replay = self.channel()
        channel.io = ExecutableIO(
            lambda event, remaining: (_ for _ in ()).throw(timeout)
        )
        with self.assertRaises(ExecutableJ2534Error) as raised:
            channel.m16c_query()
        self.assertIs(raised.exception, timeout)

    def test_original_seed_key_binds_instruction_producer_and_runtime_cpu(self):
        for build, start, table, constructor in (
            (12, 0x451400, 0x59E85C, 0x40E310),
            (18, 0x47F0C4, 0x5F6EE8, 0x419BDC),
        ):
            values = (0x1234, 0x5678, 0x9ABC, 0xDEF0)
            code = {}
            for index, value in enumerate(values):
                address = start + index * 21
                code[address] = (
                    b"\x68"
                    + value.to_bytes(4, "little")
                    + b"\x68"
                    + (table + index * 0x10C).to_bytes(4, "little")
                    + b"\xe8"
                    + (constructor - address - 15).to_bytes(4, "little", signed=True)
                )
            image = SimpleNamespace(
                read=lambda address, size, code=code: code[address][:size]
            )
            with patch("scripts.cuw_legacy_engine.ExecutableImage", return_value=image):
                codec = OriginalSeedKey(SimpleNamespace(build=build, cpus=(object(),)))
                seed = bytes((1, 2, 3, 4))
                self.assertEqual(
                    codec(0, seed),
                    bytes(
                        (
                            1 ^ 0x12 ^ 0x9A,
                            2 ^ 0x34 ^ 0xBC,
                            3 ^ 0x56 ^ 0xDE,
                            4 ^ 0x78 ^ 0xF0,
                        )
                    ),
                )
                for bad_index in (-1, 1, True):
                    with self.assertRaises(ValueError):
                        codec(bad_index, seed)
                code[start] = bytes(15)
                with self.assertRaises(ValueError):
                    OriginalSeedKey(SimpleNamespace(build=build, cpus=(object(),)))

    def test_automatic_ig_off_did_update_and_native_fallback(self):
        tx, rx = TX + b"\xe9", RX + b"\xe9"
        for replies, expected in (
            (
                [b"\x50\x03" + bytes(4), b"\x62\x20\x01\x40\x01", b"\x6e\x20\x01"],
                [b"\x10\x03", b"\x22\x20\x01", b"\x2e\x20\x01\x40\x41"],
            ),
            ([b"\x7f\x10\x12", b"\x7f\x10\x11"], [b"\x10\x03", b"\x10\x70"]),
        ):
            replay = Replay([rx + reply for reply in replies])
            channel = CommonCAN(
                ExecutableIO(replay), tx, rx, padding=False, read_timeout_ms=1000
            )
            cancel_automatic_ig_off(channel)
            self.assertEqual(
                [
                    event["data"][5:]
                    for event in replay.events
                    if event["operation"] == "write_messages"
                ],
                expected,
            )
        error = ExecutableJ2534Error(1, 9)
        replay = Replay([error])
        channel = CommonCAN(
            ExecutableIO(replay), tx, rx, padding=False, read_timeout_ms=1000
        )
        cancel_automatic_ig_off(channel)
        self.assertEqual(
            len(
                [
                    event
                    for event in replay.events
                    if event["operation"] == "write_messages"
                ]
            ),
            1,
        )

    def test_legacy_diagnostic_pending_and_busy_have_distinct_counters(self):
        channel, replay = self.channel(
            [
                RX + b"\x7f\x10\x21",
                RX + b"\x7f\x10\x78",
                RX + b"\x50",
            ]
        )
        channel.set_timeout(1000)
        self.assertEqual(
            legacy_diagnostic(
                channel, b"\x10\x70", b"\x50", 1, 78, busy_retries=1, pending_reads=1
            ),
            b"\x50",
        )
        writes = [
            event["data"][4:]
            for event in replay.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes, [b"\x10\x70", b"\x10\x70"])
        self.assertEqual(channel.timeout_ms, 1000)

    def test_ordinary_block_width_and_exact_busy_values(self):
        for wide, index, expected in (
            (False, 256, b"\x25\xff"),
            (True, 257, b"\x26\x01\x00\x01\x00"),
        ):
            channel, replay = self.channel(
                [
                    RX + b"\x3c",
                    RX + b"\x3c",
                    RX + b"\x80",
                    RX + b"\x3c",
                    RX + b"\x3c",
                    RX + b"\x00",
                    RX + b"\x3c",
                ]
            )
            channel.ordinary_erase(index, wide=wide)
            writes = [
                e["data"][4:]
                for e in replay.events
                if e["operation"] == "write_messages"
            ]
            self.assertEqual(writes, [expected, b"\x50", b"\x50"])
        channel, replay = self.channel(
            [RX + b"\x3c", RX + b"\x3c", RX + b"\x10", RX + b"\x3c"]
        )
        with self.assertRaises(ExecutableCANError) as raised:
            channel.ordinary_erase(1, wide=False)
        self.assertEqual(raised.exception.code, 12)
        self.assertEqual(len([e for e in replay.events if e["operation"] == "wait"]), 1)

    def test_ordinary_verify_does_not_accept_other_low_nibble_busy(self):
        channel, replay = self.channel(
            [RX + b"\x3c", RX + b"\x3c", RX + b"\x3c", RX + b"\x40", RX + b"\x3c"]
        )
        with self.assertRaises(ExecutableCANError) as raised:
            channel.ordinary_verify(1, bytes(256), wide=False)
        self.assertEqual(raised.exception.code, 15)
        writes = [
            e["data"][4:] for e in replay.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(writes, [b"\x15\x00", bytes(256), b"\x50"])

    def test_ordinary_write_uses_exact_busy40_and_address24(self):
        channel, replay = self.channel(
            [
                RX + b"\x3c",
                RX + b"\x3c",
                RX + b"\x3c",
                RX + b"\x40",
                RX + b"\x3c",
                RX + b"\x3c",
                RX + b"\x00",
                RX + b"\x3c",
            ]
        )
        channel.ordinary_write_block(0x123456, bytes(1024))
        writes = [
            e["data"][4:] for e in replay.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes, [b"\x41", b"\x12\x34\x56\xff", bytes(1024), b"\x50", b"\x50"]
        )
        channel, replay = self.channel(
            [RX + b"\x3c", RX + b"\x3c", RX + b"\x3c", RX + b"\x10", RX + b"\x3c"]
        )
        with self.assertRaises(ExecutableCANError) as raised:
            channel.ordinary_write_block(0, bytes(1024))
        self.assertEqual(raised.exception.code, 13)

    def test_collate_security_and_mode_use_literal_native_calls(self):
        channel, replay = self.channel(
            [RX + b"\x67\x01abcd", RX + b"\x67\x02", RX + b"\x50\x00"]
        )
        channel.timeout_ms = 1000
        seeds = []

        def key(seed):
            seeds.append(seed)
            return b"wxyz"

        collate_seed_key(channel, key)
        change_reprogramming_mode(channel, 2)
        writes = [
            e["data"][4:] for e in replay.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(seeds, [b"abcd"])
        self.assertEqual(writes, [b"\x27\x01", b"\x27\x02wxyz", b"\x10\x02"])
        self.assertEqual(
            [e["milliseconds"] for e in replay.events if e["operation"] == "wait"],
            [0, 100, 0, 0],
        )

    def test_collate_transport_timeout_maps22_before_key(self):
        channel, _replay = self.channel([NativeTransportError(16)])
        channel.timeout_ms = 1000
        called = []
        with self.assertRaises(ExecutableCANError) as raised:
            collate_seed_key(channel, lambda seed: (called.append(seed), b"abcd")[1])
        self.assertEqual(raised.exception.code, 22)
        self.assertEqual(called, [])

    def test_ordinary_block_loop_exact_wire_and_preflight(self):
        ack = RX + b"\x3c"
        status0 = [ack, RX + b"\x00", ack]
        replies = [ack, ack, RX + b"\x01", ack]
        replies += [ack, *status0]  # Erase after the failed blank check.
        replies += [ack, ack, *status0]  # Start, address, data then status.
        replies += [ack, *status0]  # Inverify.
        replies += [ack] + [value for _ in range(4) for value in [ack, *status0]]
        channel, replay = self.channel(replies)
        amounts = []
        ordinary_flash_blocks(
            channel,
            "authored",
            CANMemory(0x1000, 0x13FF, 1, 0),
            bytes(1024),
            wide=False,
            progress=amounts.append,
        )
        writes = [
            e["data"][4:] for e in replay.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes[:9],
            [
                b"\x35\x00",
                b"\x50",
                b"\x25\x00",
                b"\x50",
                b"\x41",
                b"\x00\x10\x00\xff",
                bytes(1024),
                b"\x50",
                b"\x47\x00",
            ],
        )
        self.assertEqual(sum(amounts), 2048)
        channel, replay = self.channel()
        with self.assertRaises(ValueError):
            ordinary_flash_blocks(
                channel, "authored", CANMemory(0, 2047, 1, 0), bytes(1024), wide=False
            )
        self.assertEqual(replay.events, [])

    def test_collate_exact_negative_7f27_maps23(self):
        channel, _replay = self.channel([RX + b"\x7f\x27\x22"])
        channel.timeout_ms = 1000
        with self.assertRaises(ExecutableCANError) as raised:
            collate_seed_key(channel, lambda _seed: b"abcd")
        self.assertEqual(raised.exception.code, 23)

    def test_ccan_functional_header_uses_native_boolean_cpu_index(self):
        locations = (
            bytes.fromhex("0100020003000400"),
            bytes.fromhex("1111222233334444"),
        )
        self.assertEqual(
            ccan_functional_header(("authored", "17"), locations),
            bytes.fromhex("00000400"),
        )
        for value in ("17", "54", "90", "18"):
            self.assertEqual(
                ccan_functional_header((value, "authored"), locations),
                bytes.fromhex("00004444"),
            )
        with self.assertRaises(ValueError):
            ccan_functional_header(("17",), locations[:1])

    def test_ccan_m16c_cpu_specific_extra_regions(self):
        self.assertEqual(ccan_m16c_extra_regions("90"), ((0xFF0000, 0x10000),))
        self.assertEqual(
            ccan_m16c_extra_regions("17"),
            ((0xFA000, 0x2000), (0xFC000, 0x2000), (0xFE000, 0x2000)),
        )
        self.assertEqual(
            sum(size for _, size in ccan_m16c_extra_regions("18")), 0x18000
        )
        rows = ccan_m16c_extra_regions("54")
        self.assertEqual(len(rows), 18)
        self.assertEqual(
            rows[7:10], ((0xE000, 0x2000), (0x10000, 0x10000), (0x20000, 0x10000))
        )
        self.assertEqual(rows[-1], (0xA0000, 0x20000))
        self.assertEqual(ccan_m16c_extra_regions("authored"), ())

    def test_m16c_regions_consume_image_in_order_and_preflight(self):
        channel, replay = self.channel(
            [RX + b"\x80\x0c", RX + b"\x80\x0c", RX + b"\x00"]
        )
        amounts = []
        m16c_flash_regions(
            channel, bytes(range(256)), ((0x1000, 256),), progress=amounts.append
        )
        writes = [e for e in replay.events if e["operation"] == "write_messages"]
        self.assertEqual(writes[1]["data"], TX + b"\xa1\x10\x00\xd0")
        batches = [e["messages"] for e in writes if "messages" in e]
        self.assertEqual(
            batches,
            [
                (TX + b"\xa2\x10\x00", TX + bytes(range(256))),
                (TX + b"\xa3\x10\x00", TX + bytes(range(256))),
            ],
        )
        self.assertEqual(amounts, [256, 256])
        self.assertEqual(replay.events[-1], {"operation": "wait", "milliseconds": 3000})
        channel, replay = self.channel()
        with self.assertRaises(ValueError):
            m16c_flash_regions(channel, bytes(256), ((0x1000, 512),))
        self.assertEqual(replay.events, [])

    def test_can_prepare_owns_filters_and_literal_mask_session_order(self):
        from scripts.cuw_legacy_addresses import CAddress

        class PrepareReplay(Replay):
            def __call__(self, event, remaining):
                if event["operation"] in (
                    "get_channel_padding",
                    "get_timeout",
                    "get_send_timeout",
                    "start_filter",
                    "stop_filter",
                ):
                    self.events.append(event)
                    return {
                        "get_channel_padding": False,
                        "get_timeout": 1000,
                        "get_send_timeout": 1000,
                        "start_filter": 42,
                        "stop_filter": None,
                    }[event["operation"]]
                return super().__call__(event, remaining)

        replay = PrepareReplay(
            [RX + b"\x67\x01abcd", RX + b"\x67\x02", RX + b"\x50", RX + b"\x50"]
        )
        io = ExecutableIO(replay)
        result = prepare_can_addresses(
            io,
            (CAddress(bytes.fromhex("4101230004560000")),),
            bytes.fromhex("00000720"),
            lambda _index, _seed: b"wxyz",
            mode=2,
            repeat_mode=True,
            retry_mode=False,
        )
        self.assertEqual(result, (0,))
        writes = [
            e["data"] for e in replay.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes,
            [
                TX + b"\x27\x01",
                TX + b"\x27\x02wxyz",
                *([bytes.fromhex("00000720a027")] * 3),
                TX + b"\x10\x02",
                TX + b"\x10\x02",
            ],
        )
        self.assertEqual(
            replay.events[-1], {"operation": "stop_filter", "filter_id": 42}
        )
        self.assertFalse(io.owns_resource("stop_filter", filter_id=42))

    def test_can_prepare_empty_retry_checks_cancel_after_cleanup(self):
        from scripts.cuw_legacy_addresses import CAddress

        cancelled = [False]

        class PrepareReplay(Replay):
            def __call__(self, event, remaining):
                operation = event["operation"]
                if operation == "stop_filter":
                    cancelled[0] = True
                    return None
                if operation in (
                    "get_channel_padding",
                    "get_timeout",
                    "get_send_timeout",
                    "start_filter",
                ):
                    return {
                        "get_channel_padding": False,
                        "get_timeout": 1000,
                        "get_send_timeout": 1000,
                        "start_filter": 42,
                    }[operation]
                return super().__call__(event, remaining)

        replay = PrepareReplay([NativeTransportError(16)])
        io = ExecutableIO(replay, cancelled=lambda: cancelled[0])
        with self.assertRaises(InterruptedError):
            prepare_can_addresses(
                io,
                (CAddress(bytes.fromhex("4101230004560000")),),
                bytes(4),
                lambda _index, _seed: bytes(4),
                mode=2,
                repeat_mode=False,
                retry_mode=True,
            )
        self.assertFalse(io.owns_resource("stop_filter", filter_id=42))

    def test_p5_pending_receives_without_resend_and_restores5530(self):
        replay = Replay([RX + b"\x7f\x31\x78", RX + b"\x71\x01\x10\x03"])
        io = ExecutableIO(replay, local_seconds_of_day=lambda: 10)
        channel = CommonCAN(io, TX, RX, padding=False, read_timeout_ms=1000)
        self.assertEqual(
            p5_diagnostic(channel, b"\x31\x01\x10\x03", b"\x71\x01\x10\x03", 4, 25),
            b"\x71\x01\x10\x03",
        )
        self.assertEqual(
            [
                e["milliseconds"]
                for e in replay.events
                if e["operation"] == "set_timeout"
            ],
            [5530, 1000],
        )
        self.assertEqual(
            len([e for e in replay.events if e["operation"] == "write_messages"]), 1
        )

    def test_p5_pending_midnight_expiry_emits_one3e(self):
        replay = Replay([RX + b"\x7f\x31\x78", RX + b"\x7f\x31\x78"])
        times = iter((86399, 86399, 179))
        io = ExecutableIO(replay, local_seconds_of_day=lambda: next(times))
        channel = CommonCAN(io, TX, RX, padding=False, read_timeout_ms=1000)
        with self.assertRaises(ExecutableCANError) as raised:
            p5_diagnostic(channel, b"\x31", b"\x71", 1, 25)
        self.assertEqual(raised.exception.code, 25)
        self.assertEqual(
            [
                e["data"][4:]
                for e in replay.events
                if e["operation"] == "write_messages"
            ],
            [b"\x31", b"\x3e"],
        )
        self.assertEqual(channel.timeout_ms, 1000)

    def test_p5_busy_does_not_resend_and_seed_has_no100ms_delay(self):
        channel, replay = self.channel([RX + b"\x7f\x27\x21"])
        channel.timeout_ms = 1000
        with self.assertRaises(ExecutableCANError) as raised:
            p5_diagnostic(channel, b"\x27\x01", b"\x67\x01", 6, 16)
        self.assertEqual(raised.exception.code, 16)
        self.assertEqual(
            len([e for e in replay.events if e["operation"] == "write_messages"]), 1
        )
        channel, replay = self.channel([RX + b"\x67\x01abcd", RX + b"\x67\x02"])
        channel.timeout_ms = 1000
        p5_collate_seed_key(channel, lambda _seed: b"wxyz")
        self.assertEqual(
            [e["milliseconds"] for e in replay.events if e["operation"] == "wait"],
            [0, 0],
        )

    def test_can_metadata_mode_and_finish_ack_selectors(self):
        self.assertEqual(ccan_prepare_mode("51", "11"), (0x60, True))
        self.assertEqual(ccan_prepare_mode("3", "authored"), (2, True))
        self.assertEqual(ccan_prepare_mode("51", "other"), (2, False))
        self.assertTrue(can_finish_ack("0", ("authored", "216")))
        self.assertTrue(can_finish_ack("1", ("22",)))
        self.assertFalse(can_finish_ack("0", ("22",)))
        self.assertFalse(can_finish_ack("1", ("216",)))

    def test_p5_session_preserves_literal_wrong_sid27_catch(self):
        for reply, code in (
            (NativeTransportError(16), 55),
            (RX + b"\x7f\x27\x22", 56),
            (RX + b"\x7f\x10\x22", 41),
            (RX + b"\x50\x02", 41),
        ):
            channel, _replay = self.channel([reply])
            channel.timeout_ms = 1000
            with self.assertRaises(ExecutableCANError) as raised:
                p5_session_control(channel)
            self.assertEqual(raised.exception.code, code)
        channel, _replay = self.channel([RX + b"\x50\x02\x00\x32\x01\xf4"])
        channel.timeout_ms = 1000
        p5_session_control(channel)

    def test_nonfinal_verify_busy_then_cpass_retains_status_and_fails15(self):
        for ordinary, busy in ((False, 0x40), (True, 0x20)):
            ack = RX + b"\x3c"
            channel, replay = self.channel(
                [ack, ack, ack, RX + bytes((busy,)), ack, NativeTransportError(16)]
            )
            with self.assertRaises(ExecutableCANError) as raised:
                if ordinary:
                    channel.ordinary_verify(1, bytes(512), wide=False)
                else:
                    channel.verify(1, 1, bytes(512))
            self.assertEqual(raised.exception.code, 15)
            writes = [
                e["data"][4:]
                for e in replay.events
                if e["operation"] == "write_messages"
            ]
            self.assertEqual(writes.count(bytes(256)), 1)
            self.assertEqual(writes.count(b"\x50"), 2)

    def test_shrink_stage_uses_native_ram_flags_and_resets_error99(self):
        from dataclasses import replace
        from unittest.mock import patch

        from tests.test_cuw_legacy_engine import imported_context

        class Tables:
            def __init__(self, context):
                pass

            def descriptor_rows(self):
                return (("15", 5, True), ("16", 6, True), ("", 0, False))

            def range_rows(self):
                return (("", ((1, 0),)),)

            def remap_cpu(self, value):
                return "16" if value == "15" else None

        ack = RX + b"\x3c"
        status0 = [ack, RX + b"\x00", ack]
        replies = [ack, *status0, ack, ack, *status0, ack, *status0, ack]
        replies += [value for _ in range(4) for value in [ack, *status0]]
        channel, _replay = self.channel(replies)
        context = replace(imported_context(), cpu_types=("15",))
        with patch("scripts.cuw_legacy_sil.SilTables", Tables):
            flash_shrink_imported(
                context,
                channel,
                0,
                0,
                extended=True,
                persist=False,
                memory=CANMemory(0, 1023, 1, 6),
            )
        self.assertTrue(context.state.writing_end_block)
        self.assertEqual(context.state.pass_thru_error_code, 99)
        self.assertEqual(context.state.cpu_type_overrides, {})
        self.assertEqual(context.cpu_types, ("15",))

    def test_p5_prepare_session_security_mask_routine_chronology(self):
        from scripts.cuw_legacy_addresses import P5Address

        class PrepareReplay(Replay):
            def __call__(self, event, remaining):
                if event["operation"] in (
                    "get_channel_padding",
                    "get_timeout",
                    "get_send_timeout",
                    "start_filter",
                    "stop_filter",
                ):
                    self.events.append(event)
                    return {
                        "get_channel_padding": False,
                        "get_timeout": 1000,
                        "get_send_timeout": 1000,
                        "start_filter": 42,
                        "stop_filter": None,
                    }[event["operation"]]
                return super().__call__(event, remaining)

        replay = PrepareReplay(
            [
                RX + b"\x50\x02\x00\x32\x01\xf4",
                RX + b"\x67\x01abcd",
                RX + b"\x67\x02",
                RX + b"\x71\x01\x10\x03",
            ]
        )
        io = ExecutableIO(replay)
        result = prepare_p5_addresses(
            io,
            (P5Address(bytes.fromhex("00012300045600")),),
            bytes.fromhex("00000720"),
            lambda _index, _seed: b"wxyz",
            retry_mode=False,
        )
        self.assertEqual(result, (0,))
        writes = [
            e["data"] for e in replay.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes,
            [
                TX + b"\x10\x02",
                TX + b"\x27\x01",
                TX + b"\x27\x02wxyz",
                *([bytes.fromhex("00000720a027")] * 3),
                TX + b"\x31\x01\x10\x03",
            ],
        )
        self.assertFalse(io.owns_resource("stop_filter", filter_id=42))
        self.assertEqual(
            [e["milliseconds"] for e in replay.events if e["operation"] == "wait"],
            [0, 0, 0, 100, 100, 100, 0],
        )

    def test_zv_records_write_verify_phase_counts_and_literal_commands(self):
        image = b"ZV\x00\x00\x03abc" + b"ZV\x01\x00\x01\xaa\xbbd"
        self.assertEqual(parse_zv_records(image), ((0, 8), (8, 8)))
        ack = RX + b"\x3c"
        status0 = [ack, RX + b"\x00", ack]
        replies = [ack, ack, *status0, ack, *status0] * 2

        class ProgressReplay(Replay):
            def __call__(self, event, remaining):
                if event["operation"] == "notification":
                    self.events.append(event)
                    return None
                return super().__call__(event, remaining)

        replay = ProgressReplay(replies)
        io = ExecutableIO(replay)
        channel = CommonCAN(io, TX, RX, padding=False)
        progress = CANProgress(io, (len(image),))
        account = lambda length, completed, base: progress.account_phase(
            0, length, completed, base
        )
        channel.zv_write(image, progress=account)
        channel.zv_verify(image, progress=account)
        writes = [
            e["data"][4:] for e in replay.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes,
            [
                b"\x42\x00\x00\x00\x01\xff",
                image[:8],
                b"\x50",
                image[8:],
                b"\x50",
                b"\x17\x00\x00\x00\x01\xff",
                image[:8],
                b"\x50",
                image[8:],
                b"\x50",
            ],
        )
        self.assertEqual(progress.counts, [32])
        self.assertEqual(
            [
                e["values"]
                for e in replay.events
                if e["operation"] == "notification" and e["field"] == "writing_percent"
            ],
            [(25,), (50,), (75,), (100,)],
        )

    def test_zv_short_final_chunk_and_truncated_header(self):
        image = b"ZV\x00\x03\xfd" + b"A" * 1021
        ack = RX + b"\x3c"
        channel, replay = self.channel(
            [ack, ack, ack, RX + b"\x00", ack, ack, ack, RX + b"\x00", ack]
        )
        channel.zv_write(image)
        writes = [
            e["data"][4:] for e in replay.events if e["operation"] == "write_messages"
        ]
        self.assertEqual([len(value) for value in writes], [6, 1024, 1, 2, 1])
        self.assertEqual(writes[3], b"AA")
        for invalid in (b"ZV\x01\x00\x00", b"ZV\x00\x00\x03ab"):
            channel, replay = self.channel()
            with self.assertRaises(ValueError):
                channel.zv_write(invalid)
            self.assertEqual(replay.events, [])

    def test_r32c_static_geometry_and_local_endblock_are_distinct(self):
        from dataclasses import replace
        from unittest.mock import patch

        from tests.test_cuw_legacy_engine import imported_context

        class Image:
            def __init__(self, context):
                pass

            def read(self, address, size):
                if address == 0x5839B1:
                    return bytes.fromhex("a158515d00a378006200")
                if address == 0x5D5158:
                    return (0x1000).to_bytes(4, "little")
                if 0x1000 <= address < 0x1004:
                    return b"136\0"[address - 0x1000 : address - 0x1000 + size]
                if address == 0x620078:
                    return b"".join(
                        value.to_bytes(4, "little") for value in (0, 1, 1, 1)
                    ) + bytes(120)
                raise AssertionError((address, size))

        class Tables:
            def __init__(self, context):
                pass

            def descriptor_rows(self):
                return (("136", 1, True), ("", 0, False))

        ack = RX + b"\x3c"
        status0 = [ack, RX + b"\x00", ack]
        replies = [
            ack,
            NativeMessage(6, RX, rx_status=2),
            RX + bytes.fromhex("0000000003ff010100"),
            ack,
        ]
        replies += [ack, *status0, ack, ack, *status0, ack, *status0, ack]
        replies += [value for _ in range(4) for value in [ack, *status0]]
        channel, _replay = self.channel(replies)
        context = replace(imported_context(), cpu_types=("136",))
        transfer = CANTransferState()
        with (
            patch("scripts.cuw_legacy_engine.ExecutableImage", Image),
            patch("scripts.cuw_legacy_sil.SilTables", Tables),
        ):
            self.assertEqual(r32c_block_sizes(context, "136"), (1024,))
            flash_r32c_imported(
                context, channel, 0, 0, transfer, extended=True, persist=False
            )
        self.assertTrue(transfer.end_block)
        self.assertFalse(context.state.writing_end_block)
        self.assertEqual(context.state.pass_thru_error_code, 99)

    def test_ordinary_block_invalid_index_fails_before_io(self):
        for method in ("ordinary_check_block", "ordinary_erase", "ordinary_inverify"):
            channel, replay = self.channel()
            with self.assertRaises(ValueError):
                getattr(channel, method)(257, wide=False)
            self.assertEqual(replay.events, [])

    def test_status_discards_unmatched_header_and_nonack(self):
        channel, replay = self.channel(
            [
                TX + b"\x3c",
                RX + b"\x3c\x00",
                RX + b"\x3c",
                RX + b"\x20",
                RX + b"\x3c",
            ]
        )
        self.assertEqual(channel.status(), 0x20)
        self.assertEqual(
            replay.events[1],
            {
                "operation": "write_messages",
                "protocol_id": 6,
                "tx_flags": 0,
                "data": TX + b"\x50",
                "count": 1,
            },
        )

    def test_native_ack_failure_retries_exactly_four(self):
        channel, replay = self.channel([NativeTransportError(9) for _ in range(4)])
        with self.assertRaises(ExecutableCANError) as raised:
            channel.status()
        self.assertEqual(raised.exception.code, 4)
        self.assertEqual(
            sum(e["operation"] == "write_messages" for e in replay.events), 4
        )

    def test_raw_status_read_error_does_not_retry(self):
        channel, replay = self.channel([RX + b"\x3c", NativeTransportError(16)])
        with self.assertRaises(NativeTransportError):
            channel.status()
        self.assertEqual(
            sum(e["operation"] == "write_messages" for e in replay.events), 1
        )

    def test_memory_three_and_four_byte_fields(self):
        for wide, payload in [
            (False, bytes.fromhex("123456000100abce00")),
            (True, bytes.fromhex("1234567800000100abce00")),
        ]:
            channel, _ = self.channel(
                [
                    RX + b"\x3c",
                    NativeMessage(6, RX, rx_status=2),
                    RX + payload,
                    RX + b"\x3c",
                ]
            )
            result = channel.memory(wide)
            self.assertEqual(
                result, CANMemory(0x12345678 if wide else 0x123456, 256, 0xAB, 0xCE)
            )

    def test_memory_driver_category_covers_body_and_final_ack(self):
        for ordinary in (False, True):
            for final_ack in (False, True):
                error = ExecutableJ2534Error(-128, 7)
                replies: list[bytes | NativeMessage | ExecutableJ2534Error] = [
                    RX + b"\x3c"
                ]
                if final_ack:
                    replies += [
                        NativeMessage(6, RX, rx_status=2),
                        RX
                        + bytes.fromhex("123456000100abce")
                        + (b"" if ordinary else b"\0"),
                    ]
                replies.append(error)
                channel, _ = self.channel(replies)
                with self.assertRaises(ExecutableJ2534Error) as caught:
                    (channel.memory_ordinary if ordinary else channel.memory)()
                self.assertIs(caught.exception, error)
                self.assertEqual((error.native_code, error.driver_status), (10, 7))

    def test_finish_preserves_extended_header(self):
        replay = Replay()
        channel = CommonCAN(ExecutableIO(replay), TX + b"\xfe", RX, padding=False)
        channel.finish(acknowledge=False)
        self.assertEqual(replay.events[1]["data"], TX + b"\xfe\x80")
        self.assertEqual(replay.events[1]["tx_flags"], 0x80)

    def test_callback_cancellation_wins_over_driver_error(self):
        cancelled = False

        def action(event, remaining):
            nonlocal cancelled
            cancelled = True
            raise NativeTransportError(9)

        channel = CommonCAN(
            ExecutableIO(action, cancelled=lambda: cancelled), TX, RX, padding=False
        )
        with self.assertRaises(InterruptedError):
            channel.ack()

    def test_malformed_provider_frame_is_host_error(self):
        channel, _ = self.channel([b"bad"])
        with self.assertRaises(ValueError):
            channel.ack()

    def test_write_waits_for_real_tx_indication(self):
        events = []
        replies = iter(
            [
                NativeMessage(6, TX, rx_status=0x1F),
                NativeMessage(6, RX),
                NativeMessage(6, TX, rx_status=9),
            ]
        )

        def action(event, remaining):
            events.append(event)
            if event["operation"] == "ioctl":
                return None
            return 1 if event["operation"] == "write_messages" else [next(replies)]

        CommonCAN(ExecutableIO(action), TX, RX, padding=False).write(b"\x25")
        self.assertEqual(
            [event["operation"] for event in events],
            ["ioctl", "write_messages"] + ["read_messages"] * 3,
        )

    def test_mode2_requires_real_indication_and_padding_context(self):
        channel, _ = self.channel(
            [
                NativeMessage(6, RX + b"\x00", rx_status=2),
                NativeMessage(6, RX + b"\x01", rx_status=16),
                RX + b"\x02",
            ]
        )
        channel.padding = True
        self.assertEqual(channel.read(mode=2, padding=True), RX + b"\x02")
        channel, _ = self.channel([])
        with self.assertRaises(ValueError):
            channel.read(mode=2, padding=True)

    def test_mode1_wrong_indication_has_original_error999(self):
        channel, _ = self.channel([NativeMessage(6, RX, rx_status=9)])
        with self.assertRaises(NativeTransportError) as raised:
            channel.read(mode=1)
        self.assertEqual(raised.exception.code, 999)

    def test_check_id_batch_and_wait_variants(self):
        location = bytes.fromhex("0102030405060708")
        expected = (
            b"\x00",
            b"\x00",
            bytes.fromhex("080704030201"),
            bytes.fromhex("0605"),
            bytes.fromhex("44332211"),
        )
        self.assertEqual(check_id_payloads(location, 0x11223344), expected)
        for wait in (None, 7):
            channel, replay = self.channel(
                [RX + b"\x3c", NativeMessage(6, RX, rx_status=2), RX + b"\x91"]
            )
            self.assertEqual(
                channel.check_id(
                    location, 0x11223344, interframe_ms=wait, first_timeout_ms=10000
                ),
                RX + b"\x91",
            )
            writes = [e for e in replay.events if e["operation"] == "write_messages"]
            if wait is None:
                self.assertEqual(
                    writes[0]["messages"], tuple(TX + value for value in expected)
                )
                self.assertEqual(writes[0]["count"], 5)
            else:
                self.assertEqual(
                    [e["data"] for e in writes[:-1]], [TX + value for value in expected]
                )
                self.assertEqual(
                    sum(e["operation"] == "wait" for e in replay.events), 4
                )
            self.assertEqual(writes[-1]["data"], TX + b"\x3c")

    def test_executable_geometry_cpu_branches(self):
        vectors = [
            ("4", 0x90000, (0x10000, 0x70000, 0x10000)),
            ("5", 0x50000, (0x10000, 0x40000)),
            ("6", 0x10000, (0x10000, 0)),
            ("7", 0x60000, (0x4000, 0x58000)),
            ("19", 0x2345, (0x1000, 0x1000)),
            ("73", 0x1000, (0x1000,)),
            ("216", 0x50000, (0x40000, 0x10000)),
            ("other", 0x2500, (0x2000, 0x500)),
        ]
        for cpu, length, expected in vectors:
            with self.subTest(cpu=cpu):
                self.assertEqual(
                    calc_block_sizes(
                        cpu, CANMemory(0x10000, 0x10000 + length - 1, 8, 0)
                    ),
                    expected,
                )
        with self.assertRaises(ValueError):
            calc_block_sizes("other", CANMemory(0, 0x1000, 0, 0))

    def test_verify_chunk_progress_and_opcode(self):
        status = [RX + b"\x3c", RX + b"\x00", RX + b"\x3c"]
        channel, replay = self.channel(
            [RX + b"\x3c", RX + b"\x3c", *status, RX + b"\x3c", *status]
        )
        progress = []
        channel.verify(2, 3, b"\xab" * 512, progress=progress.append)
        self.assertEqual(progress, [256, 256])
        writes = [
            event["data"]
            for event in replay.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes,
            [
                TX + bytes.fromhex("1600010002"),
                TX + b"\xab" * 256,
                TX + b"\x50",
                TX + b"\xab" * 256,
                TX + b"\x50",
            ],
        )

    def test_native_range_table_order_and_open_final_end(self):
        rows = (("7", ((1, 1), (2, 0), (0, 0))), ("", ((1, 0),)))
        self.assertEqual(select_block_ranges("7", (16, 32, 64), rows), ((1, 1), (2, 3)))
        self.assertEqual(select_block_ranges("other", (16, 32), rows), ((1, 2),))
        self.assertEqual(
            select_block_ranges("7", (16, 32), (("", ((1, 0),)), *rows)), ((1, 2),)
        )
        with self.assertRaises(ValueError):
            select_block_ranges("7", (16,), rows)

    def test_write_block_first_and_continuation_frames(self):
        status = [RX + b"\x3c", RX + b"\x00", RX + b"\x3c"]
        channel, replay = self.channel(
            [RX + b"\x3c", RX + b"\x3c", *status, RX + b"\x3c", RX + b"\x3c", *status]
        )
        progress = []
        channel.write_block(
            0x123456, b"\xab" * 2048, initial_wait_ms=10, progress=progress.append
        )
        self.assertEqual(progress, [1024, 1024])
        writes = [
            event["data"]
            for event in replay.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes,
            [
                TX + b"\x41",
                TX + bytes.fromhex("123456ff"),
                TX + b"\xab" * 1024,
                TX + b"\x50",
                TX + b"\x45",
                TX + b"\xab" * 1024,
                TX + b"\x50",
            ],
        )

    def test_progress_failure_stops_before_data_ack(self):
        channel, replay = self.channel([RX + b"\x3c"])

        def progress(count):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            channel.write_block(0x1234, b"\x00" * 1024, progress=progress)
        self.assertEqual(
            [
                event["data"]
                for event in replay.events
                if event["operation"] == "write_messages"
            ],
            [TX + b"\x41", TX + bytes.fromhex("001234ff"), TX + b"\x00" * 1024],
        )

    def test_prepare_reprogramming_fill_and_retry(self):
        for kind, count in ((13, 1024), (15, 256)):
            channel, replay = self.channel(
                [NativeTransportError(9), RX + b"\xff", RX + b"\x3c"]
            )
            channel.prepare_reprogramming(kind)
            writes = [
                event["data"]
                for event in replay.events
                if event["operation"] == "write_messages"
            ]
            self.assertEqual(writes, [TX + b"\x05", TX + bytes(count), TX + b"\x05"])
            self.assertEqual(
                [
                    event["milliseconds"]
                    for event in replay.events
                    if event["operation"] == "wait"
                ],
                [3000],
            )
        channel, _ = self.channel([NativeTransportError(16)])
        with self.assertRaises(ExecutableCANError) as raised:
            channel.prepare_reprogramming(1)
        self.assertEqual(raised.exception.code, 20)

    def test_explicit_four_round_material_codec(self):
        seed = bytes.fromhex("01020304")
        self.assertEqual(
            basic_conversion(seed, bytes.fromhex("1020")), bytes.fromhex("03041122")
        )
        materials = (b"\x10\x20", b"\x30\x40", b"\x50\x60", b"\x70\x80")
        self.assertEqual(
            seed_key_four_round(seed, materials), bytes.fromhex("414243c4")
        )

    def test_progress_native_whole_array_order_and_two_image_denominator(self):
        events = []
        runtime = ExecutableIO(lambda event, remaining: events.append(event))
        progress = CANProgress(runtime, (1024, 512))
        progress.account(1, 256)
        self.assertEqual(
            events,
            [
                {
                    "operation": "notification",
                    "field": "writing_bytes",
                    "values": (0, 256),
                },
                {
                    "operation": "notification",
                    "field": "writing_percent",
                    "values": (0, 25),
                },
            ],
        )
        progress.account(0, 1024)
        self.assertEqual(progress.percentages, [50, 25])

    def test_ordinary_memory75_and_native_ack_only76_fallback(self):
        for extended in (False, True):
            replies = (
                [NativeTransportError(9), RX + b"\x3c"] if extended else [RX + b"\x3c"]
            )
            payload = bytes.fromhex("12000012ffff4090") + (b"\x00" if extended else b"")
            channel, replay = self.channel(
                [
                    *replies,
                    NativeMessage(6, RX, rx_status=2),
                    RX + payload,
                    RX + b"\x3c",
                ]
            )
            self.assertEqual(
                channel.memory_ordinary(),
                (CANMemory(0x120000, 0x12FFFF, 64, 0x90), extended),
            )
            self.assertEqual(
                [
                    event["data"]
                    for event in replay.events
                    if event["operation"] == "write_messages"
                ],
                [TX + b"\x75"] + ([TX + b"\x76"] if extended else []),
            )

    def test_m16c_supplied_password_batch_and_detail_bits(self):
        for cpu, first in (
            ("54", "a0f0ff0b07"),
            ("90", "a00200df07"),
            ("17", "a0dfff0f07"),
        ):
            channel, replay = self.channel([RX + bytes.fromhex("000c")])
            channel.m16c_password(cpu, 0x11223344)
            writes = [
                event
                for event in replay.events
                if event["operation"] == "write_messages"
            ]
            self.assertEqual(writes[0]["count"], 2)
            self.assertEqual(
                writes[0]["messages"],
                (
                    TX + bytes.fromhex(first),
                    TX
                    + bytes.fromhex("11223344")
                    + (bytes.fromhex("726638") if cpu in ("54", "90") else bytes(3)),
                ),
            )
            self.assertEqual(writes[1]["data"], TX + b"\xa4")
        channel, _ = self.channel([RX + bytes.fromhex("0c00")])
        with self.assertRaises(ExecutableCANError) as raised:
            channel.m16c_password("54", 0)
        self.assertEqual(raised.exception.code, 7)

    def test_m16c_page_program_and_verify_exact_batches(self):
        for verify, response in ((False, bytes.fromhex("8000")), (True, b"\x00")):
            channel, replay = self.channel([RX + response])
            progress = []
            channel.m16c_page(
                0x123400, b"\xab" * 256, verify=verify, progress=progress.append
            )
            writes = [
                event
                for event in replay.events
                if event["operation"] == "write_messages"
            ]
            batch = writes[0 if verify else 1]
            self.assertEqual(
                batch["messages"],
                (
                    TX + bytes((0xA3 if verify else 0xA2, 0x34, 0x12)),
                    TX + b"\xab" * 256,
                ),
            )
            self.assertEqual(
                writes[-1]["data"], TX + bytes((0xA8 if verify else 0xA4,))
            )
            self.assertEqual(progress, [256])
        channel, _ = self.channel([RX + bytes.fromhex("8002")])
        with self.assertRaises(ExecutableCANError) as raised:
            channel.m16c_page(0, bytes(256))
        self.assertEqual(raised.exception.code, 13)

    def test_m16c_erase_poll_and_error_codes(self):
        channel, replay = self.channel(
            [RX + bytes.fromhex("0000"), RX + bytes.fromhex("8000")]
        )
        channel.m16c_erase(0x1234FF)
        self.assertEqual(
            [
                event["data"]
                for event in replay.events
                if event["operation"] == "write_messages"
            ],
            [TX + b"\xa6", TX + bytes.fromhex("a13412d0"), TX + b"\xa4", TX + b"\xa4"],
        )
        channel, _ = self.channel([RX + bytes.fromhex("9000")])
        with self.assertRaises(ExecutableCANError) as raised:
            channel.m16c_erase(0x1234FF)
        self.assertEqual(raised.exception.code, 12)

    def test_location_headers_use_actual_executable_fields(self):
        self.assertEqual(location_headers(bytes.fromhex("0456012308090a0b")), (TX, RX))
        self.assertEqual(
            location_headers(bytes.fromhex("0100020000000000")),
            (bytes.fromhex("00000200"), bytes.fromhex("00000100")),
        )
        with self.assertRaises(ValueError):
            location_headers(b"\x00" * 7)

    def test_native_driver_category_mutation_keeps_driver_status(self):
        events = []

        def action(event, remaining):
            events.append(event)
            if event["operation"] == "ioctl":
                return
            raise NativeTransportError(9)

        channel = CommonCAN(ExecutableIO(action), TX, RX, padding=False)
        with self.assertRaises(ExecutableJ2534Error) as raised:
            channel.erase(1, 1)
        self.assertEqual(
            (
                raised.exception.native_code,
                raised.exception.driver_status,
                raised.exception.code,
            ),
            (12, 9, 9),
        )
        self.assertEqual(len(events), 2)

    def test_erase_keeps_passthru_status4_but_verify_replaces_it15(self):
        channel, _ = self.channel(
            [RX + b"\x3c", *[NativeTransportError(9) for _ in range(4)]]
        )
        with self.assertRaises(ExecutableCANError) as raised:
            channel.erase(1, 1)
        self.assertEqual(raised.exception.code, 4)
        channel, _ = self.channel(
            [RX + b"\x3c", RX + b"\x3c", *[NativeTransportError(9) for _ in range(4)]]
        )
        with self.assertRaises(ExecutableCANError) as raised:
            channel.verify(1, 1, bytes(256))
        self.assertEqual(raised.exception.code, 15)
        self.assertIsInstance(raised.exception.__cause__, ExecutableCANError)

    def test_nonfinal_verify_typed_status_failure_is_ignored_without_retry(self):
        channel, replay = self.channel(
            [
                RX + b"\x3c",
                RX + b"\x3c",
                NativeTransportError(9),
                RX + b"\x3c",
                RX + b"\x3c",
                RX + b"\x00",
                RX + b"\x3c",
            ]
        )
        channel.verify(1, 2, bytes(512))
        self.assertEqual(
            sum(event.get("data") == TX + b"\x50" for event in replay.events), 2
        )

    def test_p5_cpu_vector_is_runtime_order_and_rejects_sparse_rows(self):
        from dataclasses import replace

        from scripts.cuw_legacy_can import p5_cpu_order
        from tests.test_cuw_legacy_engine import imported_context

        original = imported_context()
        context = replace(original, controller="CP5CanFlashWriter")
        for build in (12, 18):
            with self.subTest(build=build):
                current = replace(
                    context,
                    build=build,
                    source_cpu_indices=(7,),
                    image_source_cpu_indices=(3,),
                )
                self.assertEqual(p5_cpu_order(current), (0,))
                sparse = replace(
                    current.native, selected=replace(current.native.selected, index=2)
                )
                bad = replace(
                    current,
                    native=sparse,
                    cpus=(sparse,),
                    state=replace(current.state, write_cpu_index=2),
                )
                with self.assertRaisesRegex(ValueError, "contiguous runtime"):
                    p5_cpu_order(bad)

    def test_native_exception_domain_retains_can_identity(self):
        from scripts.cuw_legacy_engine import ExecutableNativeError

        error = ExecutableCANError(17)
        self.assertIsInstance(error, ExecutableNativeError)
        self.assertIsInstance(error, ValueError)
        self.assertNotIsInstance(error, NativeTransportError)
        self.assertEqual((error.code, error.native_code), (17, 17))

    def test_different_header_batch_waits_only_for_first_transmit(self):
        from scripts.cuw_legacy_channel import ChannelState

        events = []
        other = bytes.fromhex("00000789")

        def action(event, remaining):
            events.append(event)
            if event["operation"] == "ioctl":
                return None
            if event["operation"] == "write_messages":
                return event["count"]
            return [
                NativeMessage(6, other, rx_status=9),
                NativeMessage(6, TX, rx_status=9),
            ]

        # Return one TX frame per read, preserving the native count=1 contract.
        echoes = iter((other, TX))

        def one_frame(event, remaining):
            if event["operation"] == "read_messages":
                events.append(event)
                return [NativeMessage(6, next(echoes), rx_status=9)]
            return action(event, remaining)

        state = ChannelState(
            protocol=6, padding=True, read_timeout=321, send_timeout=654
        )
        channel = CommonCAN.from_io(ExecutableIO(one_frame), TX, RX, state=state)
        frames = (TX + b"\x50", other + b"\x65")
        channel.write_frames(frames)
        self.assertEqual(
            [event["operation"] for event in events],
            ["ioctl", "write_messages", "read_messages", "read_messages"],
        )
        self.assertEqual(events[1]["messages"], frames)
        self.assertEqual((events[1]["count"], events[1]["tx_flags"]), (2, 0x40))
        self.assertEqual(events[1]["timeout_ms"], 654)

    def test_group_read_tracks_headers_classes_counts_and_arrival_order(self):
        from scripts.cuw_legacy_channel import ChannelState

        other = bytes.fromhex("00000789fe")
        rounds = iter(
            (
                [
                    NativeMessage(6, other + b"ignored", rx_status=9),
                    NativeMessage(6, other[:4] + b"\xffwrong-extension"),
                ],
                [
                    NativeMessage(6, other + b"second", rx_status=16),
                    NativeMessage(6, RX + b"indication", rx_status=2),
                ],
                [NativeMessage(6, RX + b"first")],
            )
        )
        events = []

        def action(event, remaining):
            events.append(event)
            return next(rounds)

        state = ChannelState(protocol=6, padding=False, read_timeout=765)
        channel = CommonCAN.from_io(ExecutableIO(action), TX, RX, state=state)
        self.assertEqual(
            channel.read_selected((RX, other)), (other + b"second", RX + b"first")
        )
        self.assertEqual([event["count"] for event in events], [2, 2, 1])
        self.assertTrue(all(event["timeout_ms"] == 765 for event in events))
        self.assertEqual(channel.received, 5)

    def test_group_read_duplicates_and_native_failure_are_not_retried(self):
        from scripts.cuw_legacy_channel import ChannelState

        state = ChannelState(protocol=6, padding=False)
        events = []
        error = ExecutableJ2534Error(1, 9)
        results = iter(([NativeMessage(6, RX + b"one")], error))

        def action(event, remaining):
            events.append(event)
            value = next(results)
            if isinstance(value, BaseException):
                raise value
            return value

        channel = CommonCAN.from_io(ExecutableIO(action), TX, RX, state=state)
        with self.assertRaises(ExecutableJ2534Error) as caught:
            channel.read_selected((RX, RX))
        self.assertIs(caught.exception, error)
        self.assertEqual([event["count"] for event in events], [2, 1])
        self.assertEqual(error.native_code, 1)
        # A fresh call cannot expose the failed invocation's partial output.
        channel.io = ExecutableIO(
            lambda event, remaining: [NativeMessage(6, RX + b"two")]
        )
        self.assertEqual(channel.read_selected((RX,)), (RX + b"two",))

    def test_finish_uses_explicit_native_functional_header(self):
        functional = bytes.fromhex("00000720")
        replay = Replay()
        channel = CommonCAN(ExecutableIO(replay), TX, RX, padding=False)
        channel.finish(acknowledge=False, request_header=functional)
        write = next(
            event for event in replay.events if event["operation"] == "write_messages"
        )
        self.assertEqual(write["data"], functional + b"\x80")
        self.assertEqual(channel.request, TX)

    def test_bound_protocol5_writes_without_flags_or_transmit_read(self):
        from scripts.cuw_legacy_channel import ChannelState

        events = []

        def action(event, remaining):
            events.append(event)
            if event["operation"] == "write_messages":
                return event["count"]
            if event["operation"] == "ioctl":
                return None
            self.fail("Raw protocol5 write must not read a transmit indication")

        state = ChannelState(protocol=5, padding=True, send_timeout=678)
        channel = CommonCAN.from_io(ExecutableIO(action), TX, RX, state=state)
        channel.write(b"\xa0\x27")
        channel.write_many((b"\x80", b"\x65"))
        self.assertEqual(
            [event["operation"] for event in events],
            ["ioctl", "write_messages", "ioctl", "write_messages"],
        )
        for event in events[1::2]:
            self.assertEqual(
                (event["protocol_id"], event["tx_flags"], event["timeout_ms"]),
                (5, 0, 678),
            )
        self.assertEqual(events[1]["data"], TX + b"\xa0\x27")
        self.assertEqual(events[3]["messages"], (TX + b"\x80", TX + b"\x65"))
        state.protocol = 0
        with self.assertRaisesRegex(ValueError, "protocol5 or6"):
            channel.write(b"\x80")
        self.assertEqual(len(events), 4)

    def test_shared_native_channel_ram_survives_provider_staleness(self):
        from scripts.cuw_legacy_channel import ChannelState

        state = ChannelState(read_timeout=321, send_timeout=654, padding=True)
        events = []

        def action(event, remaining):
            events.append(event)
            if event["operation"].startswith("get_"):
                self.fail("Bound native RAM must not be replaced by provider getters")

        io = ExecutableIO(action)
        first = CommonCAN.from_io(io, TX, RX, state=state)
        second = CommonCAN.from_io(io, RX, TX, state=state)
        first.set_timeout(5530)
        self.assertEqual((state.read_timeout, second.timeout_ms), (5530, 5530))
        second.set_send_timeout(987)
        self.assertEqual((state.send_timeout, first.send_timeout_ms), (987, 987))
        state.read_timeout = 5000
        state.padding = False
        self.assertEqual((first.timeout_ms, second.padding), (5000, False))
        self.assertEqual(
            [event["operation"] for event in events],
            ["set_timeout", "set_send_timeout"],
        )

    def test_snapshot_real_native_channel_fields_and_forward_timeouts(self):
        replay = Replay([RX + b"\x3c"])

        def action(event, remaining):
            if event["operation"] in (
                "get_channel_padding",
                "get_timeout",
                "get_send_timeout",
            ):
                return {
                    "get_channel_padding": True,
                    "get_timeout": 321,
                    "get_send_timeout": 654,
                }[event["operation"]]
            return replay(event, remaining)

        channel = CommonCAN.from_io(ExecutableIO(action), TX, RX)
        channel.command(b"\x65", error_code=19)
        self.assertEqual(replay.events[1]["tx_flags"], 0x40)
        self.assertEqual(replay.events[1]["timeout_ms"], 654)
        self.assertTrue(
            all(
                event["timeout_ms"] == 321
                for event in replay.events
                if event["operation"] == "read_messages"
            )
        )

    def test_native_padding_flags_and_clear_receive_chronology(self):
        replay = Replay()
        channel = CommonCAN(ExecutableIO(replay), TX + b"\xfe", RX, padding=True)
        channel.finish(acknowledge=False)
        self.assertEqual(
            replay.events[:2],
            [
                {"operation": "ioctl", "ioctl_id": 8, "input": None, "output": None},
                {
                    "operation": "write_messages",
                    "protocol_id": 6,
                    "tx_flags": 0xC0,
                    "data": TX + b"\xfe\x80",
                    "count": 1,
                },
            ],
        )

    def test_cpu_identity_first_match_and_both_native_masks(self):
        rows = (
            ("narrow", 3, False),
            ("wide", 0x37, True),
            ("narrow", 4, False),
            ("", 0, False),
        )
        self.assertTrue(cpu_matches("narrow", 0xB1, False, rows))
        self.assertTrue(cpu_matches("wide", 0xB7, True, rows))
        self.assertFalse(cpu_matches("narrow", 0x40, False, rows))
        self.assertFalse(cpu_matches("absent", 0, False, rows))
        self.assertFalse(cpu_matches("wide", 0x37, False, rows))


if __name__ == "__main__":
    unittest.main()
