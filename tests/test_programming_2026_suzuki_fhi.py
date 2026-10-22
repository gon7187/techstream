"""Authored synthetic wire and trust-boundary controls; no vendor bytes."""

import unittest
from dataclasses import replace

from scripts.native_modules import identify_native_module
from scripts.programming import NativeNegativeResponse, NativeProgrammingChannel
from scripts.programming_2026_suzuki_fhi import (
    FHICommands,
    FHIPrepareCommands,
    FHIUtils2026,
    SuzukiIdentification,
    SuzukiPrepareCommands,
    SuzukiRoutine,
    SuzukiUSBCommands,
    SuzukiUSBResult,
    SuzukiUSBWriteResult,
    SuzukiUtils2026,
    bind_native_context,
    execute_context,
    fhi_can_ids,
    fhi_exchange,
    fhi_response_status,
    first_suzuki_usb_write,
    get_suzuki_cid,
    native_fhi_program,
    native_suzuki_addresses,
    native_suzuki_program,
    prepare_fhi,
    prepare_suzuki_uds,
    require_identity,
    set_suzuki_baud_rate,
    suzuki_download,
    suzuki_elapsed_seconds,
    suzuki_exchange,
    suzuki_gateway_authorize,
    suzuki_get_identification,
    suzuki_poll_usb,
    suzuki_recheck_prepare_cid,
    suzuki_supports_wired_repro,
    suzuki_tester_information,
    suzuki_wait_time_for_igoffon,
    write_fhi,
    write_suzuki_uds,
    write_suzuki_usb,
)


class SuzukiIdentificationTests(unittest.TestCase):
    def setUp(self):
        self.identity = identify_native_module(
            "58db5e0494645ee4f665c714a0a59afa5e2765ce2f55c8505d31e5db76159283",
            "TCUWCanSuzukiUDSUtils.dll",
        )

    def test_driver_timeout_domains_do_not_treat_primary_enum_as_status(self):
        from scripts.j2534_2026 import NativeJ2534Error2026, NativePassThruError2026
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import (
            NativeJ2534Exception2026,
            NativePassThruException2026,
            NativeRuntime2026,
        )

        for error, timeout in (
            (NativeTransportError(16), True),
            (NativeJ2534Error2026(16), True),
            (NativeJ2534Exception2026(16, "authored", 0), True),
            (NativeJ2534Exception2026(5, "authored", 0), False),
            (NativePassThruError2026(16), False),
            (NativePassThruException2026(16, "authored", 0), False),
        ):

            def action(row, _, error=error):
                if row["operation"] == "get_timeout":
                    return 2000
                if row["operation"] == "write_messages":
                    return 1
                if row["operation"] == "read_specified_can_message":
                    raise error

            runtime = NativeRuntime2026(action)
            args = (
                self.identity,
                runtime,
                bytes.fromhex("000007e0"),
                bytes.fromhex("000007e8"),
                b"\x10\x81",
                b"\x50\x81",
            )
            if timeout:
                self.assertEqual(suzuki_exchange(*args, native_flag_10=True), b"")
            else:
                with self.assertRaises(type(error)):
                    suzuki_exchange(*args, native_flag_10=True)

    def test_empty_native_identifiers_preserve_error_three(self):
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeRuntime2026,
        )

        request, response = bytes.fromhex("000007e0"), bytes.fromhex("000007e8")
        for method, did, width in (
            ("hardware_id", bytes.fromhex("f191"), 11),
            ("software_id", bytes.fromhex("f188"), 16),
        ):
            payload = b"\x62" + did + bytes(width)
            channel = NativeProgrammingChannel(
                lambda *_, payload=payload: payload, "authored"
            )
            with self.assertRaises(CommonResponseError) as generic:
                getattr(SuzukiIdentification(self.identity, channel), method)()
            self.assertEqual(generic.exception.code, 3)
            short = NativeProgrammingChannel(
                lambda *_, payload=payload: payload[:-1], "authored"
            )
            with self.assertRaises(CommonResponseError) as truncated:
                getattr(SuzukiIdentification(self.identity, short), method)()
            self.assertEqual(truncated.exception.code, 3)

            def action(row, _, did=did, payload=payload):
                if row["operation"] == "get_timeout":
                    return 2000
                if row["operation"] == "write_messages":
                    self.assertEqual(row["data"], request + b"\x22" + did)
                    return 1
                if row["operation"] == "read_specified_can_message":
                    return response + payload

            utility = SuzukiUtils2026(
                self.identity,
                NativeRuntime2026(action, native_cancelled=lambda: False),
            )
            with self.assertRaises(CommonResponseError) as raw:
                getattr(utility, method)(request, response)
            self.assertEqual(raw.exception.code, 3)

    def test_literal_requests_and_native_fixed_fields(self):
        requests = []
        replies = {
            b"\x22\xf1\x91": b"\x62\xf1\x91ABCDEFGHIJKEXTRA",
            b"\x22\xf1\x88": b"\x62\xf1\x88ABC\0DEFGHIJKLMNOEXTRA",
            b"\x22\xf1\x89": b"\x62\xf1\x89\x01\xaf",
        }

        def exchange(ecu, request):
            self.assertEqual(ecu, "authored")
            requests.append(request)
            return replies[request]

        utility = SuzukiIdentification(
            self.identity, NativeProgrammingChannel(exchange, "authored")
        )
        self.assertEqual(utility.hardware_id(), b"ABCDEFGHIJK")
        self.assertEqual(utility.software_id(), b"ABC")
        self.assertEqual(utility.software_version(), "01AF")
        self.assertEqual(requests, list(replies))

    def test_native_utility_object_copy_move_and_single_batch_binding(self):
        import copy

        from scripts.programming_2026_common import NativeRuntime2026

        calls = []
        request, response = bytes.fromhex("000007e0"), bytes.fromhex("000007e8")
        last = b""

        def action(row, _):
            nonlocal last
            calls.append(row)
            operation = row["operation"]
            if operation == "get_timeout":
                return 2000
            if operation == "write_messages":
                last = row.get("data", row.get("messages", (b"",))[0])[4:]
                return row["count"]
            if operation == "read_specified_can_message":
                replies = {
                    b"\x22\xf1\x91": b"\x62\xf1\x91ABCDEFGHIJK",
                    b"\x22\xf1\x88": b"\x62\xf1\x88ABCDEFGHIJKLMNOP",
                    b"\x22\xf1\x89": b"\x62\xf1\x89\xbe\xef",
                    b"\x31\x01\xc0\x01\x00": b"\x71\x01\xc0\x01",
                }
                return response + replies[last]
            if operation == "read_specified_can_messages":
                return (response + b"\x62\xf1\x90A",)

        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        utility = SuzukiUtils2026(self.identity, runtime)
        copied, moved = copy.copy(utility), utility.move()
        self.assertIs(copied.runtime, runtime)
        self.assertIs(moved.runtime, utility.runtime)
        self.assertEqual(calls, [])
        self.assertEqual(utility.wait_time_for_igoffon(), 0)
        self.assertEqual(copied.hardware_id(request, response), b"ABCDEFGHIJK")
        self.assertEqual(moved.software_id(request, response), b"ABCDEFGHIJKLMNOP")
        self.assertEqual(utility.software_version(request, response), "BEEF")
        utility.routine_control(SuzukiRoutine.KIND_0, request, response)
        destination = SuzukiUtils2026(self.identity, NativeRuntime2026(lambda *_: None))
        self.assertIs(destination.assign(utility), destination)
        self.assertIs(destination.move_assign(copied).runtime, runtime)
        fhi_identity = identify_native_module(
            "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
            "TCUWFHIUtils.dll",
        )
        fhi = FHIUtils2026(fhi_identity, runtime)
        fhi_copy, fhi_move = copy.copy(fhi), fhi.move()
        self.assertIs(fhi_copy.runtime, fhi.runtime)
        self.assertIs(fhi_move.runtime, fhi.runtime)
        self.assertEqual(
            fhi.send(request, response, b"\x22\xf1\x90", b"\x62\xf1\x90", minimum=4),
            b"\x62\xf1\x90A",
        )
        self.assertIs(fhi_copy.assign(fhi).runtime, runtime)
        self.assertIs(fhi_copy.move_assign(fhi_move).runtime, runtime)
        with self.assertRaises(TypeError):
            utility.assign(fhi)
        with self.assertRaises(TypeError):
            fhi.assign(utility)

    def test_distinct_native_cancellation_flags_and_receive_order(self):
        from scripts.programming_2026_common import (
            NativeException2026,
            NativeRuntime2026,
        )

        request, response = bytes.fromhex("000007e0"), bytes.fromhex("000007e8")
        events = []
        native_values = iter((False, False))
        replies = iter(
            (response + bytes.fromhex("7f2278"), response + bytes.fromhex("62100404"))
        )

        def native_cancelled():
            events.append("native_cancelled")
            return next(native_values)

        def action(row, _):
            operation = row["operation"]
            events.append(operation)
            if operation == "get_timeout":
                return 2000
            if operation == "write_messages":
                return 1
            if operation == "read_specified_can_message":
                return next(replies)
            if operation == "read_specified_can_messages":
                return (response + bytes.fromhex("62100404"),)

        self.assertEqual(
            suzuki_exchange(
                self.identity,
                NativeRuntime2026(action, native_cancelled=native_cancelled),
                request,
                response,
                bytes.fromhex("221004"),
                bytes.fromhex("621004"),
                native_flag_9=True,
            ),
            bytes.fromhex("62100404"),
        )
        self.assertEqual(events.count("native_cancelled"), 2)
        self.assertLess(
            events.index("write_messages"), events.index("native_cancelled")
        )
        self.assertLess(
            events.index("native_cancelled"), events.index("read_specified_can_message")
        )
        native_values = iter((True,))
        events.clear()
        with self.assertRaises(NativeException2026) as stopped:
            suzuki_exchange(
                self.identity,
                NativeRuntime2026(action, native_cancelled=native_cancelled),
                request,
                response,
                bytes.fromhex("221004"),
                bytes.fromhex("621004"),
                native_flag_9=True,
            )
        self.assertEqual(stopped.exception.messages(), ("",))
        self.assertNotIn("read_specified_can_message", events)
        self.assertEqual(events.count("write_messages"), 1)
        events.clear()
        with self.assertRaises(ValueError):
            suzuki_exchange(
                self.identity,
                NativeRuntime2026(action),
                request,
                response,
                b"\x22",
                b"\x62",
                native_flag_9=True,
            )
        self.assertEqual(events, [])
        fhi_identity = identify_native_module(
            "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
            "TCUWFHIUtils.dll",
        )
        native_values = iter((True,))
        with self.assertRaises(NativeException2026):
            fhi_exchange(
                fhi_identity,
                NativeRuntime2026(action, native_cancelled=native_cancelled),
                (request + bytes.fromhex("221004"),),
                (response,),
                bytes.fromhex("621004"),
                native_flag_8=True,
            )
        self.assertNotIn("read_specified_can_messages", events)
        events.clear()
        self.assertEqual(
            fhi_exchange(
                fhi_identity,
                NativeRuntime2026(action, native_cancelled=native_cancelled),
                (request + bytes.fromhex("221004"),),
                (response,),
                bytes.fromhex("621004"),
                native_flag_8=False,
            ),
            (bytes.fromhex("62100404"),),
        )
        self.assertNotIn("native_cancelled", events)

    def test_fhi_batch_preserves_duplicate_response_records(self):
        from scripts.programming_2026_common import NativeRuntime2026

        identity = identify_native_module(
            "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
            "TCUWFHIUtils.dll",
        )
        response = bytes.fromhex("000007e8")

        def action(row, _):
            if row["operation"] == "get_timeout":
                return 2000
            if row["operation"] == "write_messages":
                return row["count"]
            if row["operation"] == "read_specified_can_messages":
                self.assertEqual(row["addresses"], (response, response))
                return (response + b"\x50\x02A", response + b"\x50\x02B")

        requests = (bytes.fromhex("000007e01002"), bytes.fromhex("000007e11002"))
        self.assertEqual(
            fhi_exchange(
                identity,
                NativeRuntime2026(action),
                requests,
                (response, response),
                b"\x50\x02",
            ),
            (b"\x50\x02A", b"\x50\x02B"),
        )

    def test_malformed_and_negative_response(self):
        for response in (
            b"\x62\xf1\x88short",
            b"\x62\xf1\x89" + bytes(16),
            b"\x62\xf1\x88" + bytes(16),
            b"",
        ):
            with self.subTest(response=response), self.assertRaises(ValueError):
                SuzukiIdentification(
                    self.identity,
                    NativeProgrammingChannel(
                        lambda *_, result=response: result, "authored"
                    ),
                ).software_id()
        with self.assertRaises(NativeNegativeResponse):
            SuzukiIdentification(
                self.identity,
                NativeProgrammingChannel(lambda *_: b"\x7f\x22\x31", "authored"),
            ).software_id()

    def test_pending_receive_only_and_cancel_boundary(self):
        calls = []
        channel = NativeProgrammingChannel(
            lambda *args: calls.append(args) or b"\x7f\x22\x78",
            "authored",
            receive=lambda _: b"\x62\xf1\x89\x00\x01",
        )
        self.assertEqual(
            SuzukiIdentification(self.identity, channel).software_version(), "0001"
        )
        self.assertEqual(len(calls), 1)
        with self.assertRaises(InterruptedError):
            SuzukiIdentification(
                self.identity,
                NativeProgrammingChannel(
                    lambda *_: self.fail("I/O after cancellation"),
                    "authored",
                    cancelled=lambda: True,
                ),
            ).software_version()

    def test_fault_timeout_and_post_callback_cancellation(self):
        from scripts.programming import NativeTransportError

        def fault(*_):
            raise NativeTransportError(9)

        with self.assertRaises(NativeTransportError):
            SuzukiIdentification(
                self.identity, NativeProgrammingChannel(fault, "authored")
            ).software_version()
        now = [0.0]

        def slow(*_):
            now[0] = 2.0
            return b"\x62\xf1\x89\x00\x01"

        with self.assertRaises(TimeoutError):
            SuzukiIdentification(
                self.identity,
                NativeProgrammingChannel(
                    slow, "authored", timeout=1, clock=lambda: now[0]
                ),
            ).software_version()
        cancelled = [False]

        def cancel(*_):
            cancelled[0] = True
            return b"\x62\xf1\x89\x00\x01"

        with self.assertRaises(InterruptedError):
            SuzukiIdentification(
                self.identity,
                NativeProgrammingChannel(
                    cancel, "authored", cancelled=lambda: cancelled[0]
                ),
            ).software_version()

    def test_literal_native_routines(self):
        requests = []

        def exchange(_, request):
            requests.append(request)
            return b"\x71" + request[1:4]

        utility = SuzukiIdentification(
            self.identity, NativeProgrammingChannel(exchange, "authored")
        )
        for routine in SuzukiRoutine:
            utility.routine_control(routine)
        self.assertEqual(
            requests,
            [b"\x31\x01\xc0\x01\x00", b"\x31\x01\xff\x00\x00", b"\x31\x01\xff\x01\x00"],
        )
        with self.assertRaises(TypeError):
            utility.routine_control(0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            SuzukiIdentification(
                self.identity,
                NativeProgrammingChannel(lambda *_: b"\x71\x01\xff\x01", "authored"),
            ).routine_control(SuzukiRoutine.KIND_0)

    def test_fhi_native_address_selection_and_padding(self):
        identity = identify_native_module(
            "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
            "TCUWFHIUtils.dll",
        )
        addresses = (bytes.fromhex("07e00107e80000"), bytes.fromhex("07e10207e90000"))
        self.assertEqual(
            fhi_can_ids(identity, "31", addresses),
            (bytes.fromhex("000007e0"), bytes.fromhex("000007e8")),
        )
        self.assertEqual(
            fhi_can_ids(identity, "32", addresses),
            (bytes.fromhex("000007e1"), bytes.fromhex("000007e9")),
        )
        for malformed in ((), addresses[:1], (bytes(6), bytes(7))):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                fhi_can_ids(identity, "31", malformed)
        with self.assertRaises(ValueError):
            fhi_can_ids(self.identity, "31", addresses)

    def test_literal_native_set_baudrate_and_validation(self):
        from scripts.programming_2026_common import NativeRuntime2026

        calls = []
        runtime = NativeRuntime2026(
            lambda action, remaining: calls.append((action, remaining))
        )
        set_suzuki_baud_rate(self.identity, runtime, 500000)
        self.assertEqual(
            calls[0][0],
            {"operation": "control_io", "ioctl": 2, "parameters": ((1, 500000),)},
        )
        self.assertGreater(calls[0][1], 0)
        for invalid in (True, -1, 0x100000000):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                set_suzuki_baud_rate(self.identity, runtime, invalid)
        with self.assertRaises(TypeError):
            set_suzuki_baud_rate(
                self.identity, NativeRuntime2026(lambda *_: True), 500000
            )

    def test_fhi_pending_negative_and_final_response_status(self):
        identity = identify_native_module(
            "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
            "TCUWFHIUtils.dll",
        )
        first, second = bytes.fromhex("000007e8"), bytes.fromhex("000007e9")
        pending = first + bytes.fromhex("7f3178")
        negative = second + bytes.fromhex("7f3131")
        final = first + bytes.fromhex("7101")
        self.assertEqual(
            fhi_response_status(identity, 0x31, (pending, negative), (first, second)),
            ((), (first,), 1),
        )
        self.assertEqual(
            fhi_response_status(identity, 0x31, (pending, final), (first, second)),
            ((final,), (second,), 0),
        )
        short = second + b"\x7f"
        self.assertEqual(
            fhi_response_status(identity, 0x31, (short,), (second,)), ((short,), (), 0)
        )
        for frames in ((b"x",), (bytes(4129),)):
            with self.assertRaises(ValueError):
                fhi_response_status(identity, 0x31, frames, (first,))

    def test_literal_suzuki_download_and_timeout_restore(self):
        from scripts.programming_2026_common import NativeRuntime2026

        identity = identify_native_module(
            "39e1fb5f196cdc3081742880cff66bdbaec149d176e8d00fd76ce397608c8a81",
            "TCUWCanSuzukiUDSFlashWriter.dll",
        )
        wire, actions = [], []

        def exchange(_, request):
            wire.append(request)
            if request[0] == 0x34:
                return b"\x74\x20\x10"
            return (b"\x76" + request[1:2]) if request[0] == 0x36 else b"\x77"

        def action(row, _):
            actions.append(row)
            return 777 if row["operation"] == "get_send_timeout" else None

        self.assertEqual(
            suzuki_download(
                identity,
                NativeProgrammingChannel(exchange, "authored"),
                NativeRuntime2026(action),
                bytes.fromhex("0000100000"),
                b"ABCDE",
                3,
            ),
            5,
        )
        self.assertEqual(
            wire,
            [
                bytes.fromhex("340f45000010000000000005"),
                b"\x36\x01ABC",
                b"\x36\x02DE",
                b"\x37",
            ],
        )
        self.assertEqual(
            actions,
            [
                {"operation": "get_send_timeout"},
                {"operation": "set_send_timeout", "milliseconds": 1127},
                {"operation": "notify_done_size", "value": 3},
                {"operation": "notify_progress", "value": 60},
                {"operation": "notify_done_size", "value": 5},
                {"operation": "notify_progress", "value": 100},
                {"operation": "set_send_timeout", "milliseconds": 777},
            ],
        )
        wire.clear()

        def fault(_, request):
            wire.append(request)
            return b"\x74\x20\x10" if request[0] == 0x34 else b"\x7f\x36\x72"

        with self.assertRaises(NativeNegativeResponse):
            suzuki_download(
                identity,
                NativeProgrammingChannel(fault, "authored"),
                NativeRuntime2026(action),
                bytes(5),
                b"ABCDE",
                3,
            )
        self.assertEqual(
            actions[-1], {"operation": "set_send_timeout", "milliseconds": 777}
        )
        self.assertNotIn(b"\x37", wire)

    def test_suzuki_download_counter_wrap_and_preflight_budget(self):
        from scripts.programming_2026_common import NativeRuntime2026

        identity = identify_native_module(
            "39e1fb5f196cdc3081742880cff66bdbaec149d176e8d00fd76ce397608c8a81",
            "TCUWCanSuzukiUDSFlashWriter.dll",
        )
        requests = []

        def exchange(_, request):
            requests.append(request)
            if request[0] == 0x34:
                return b"\x74\x20\x10"
            return (b"\x76" + request[1:2]) if request[0] == 0x36 else b"\x77"

        runtime = NativeRuntime2026(
            lambda row, _: 10 if row["operation"] == "get_send_timeout" else None
        )
        suzuki_download(
            identity,
            NativeProgrammingChannel(exchange, "authored"),
            runtime,
            bytes(5),
            bytes(257),
            1,
        )
        self.assertEqual(
            [request[1] for request in requests if request[0] == 0x36][-3:], [255, 0, 1]
        )
        requests.clear()
        with self.assertRaises(ValueError):
            suzuki_download(
                identity,
                NativeProgrammingChannel(exchange, "authored"),
                runtime,
                bytes(5),
                bytes(65535),
                1,
            )
        self.assertEqual(requests, [])

    def test_literal_usb_commands_and_status_byte(self):
        identity = identify_native_module(
            "d48d438117ae5fa043811028636d1ddd3c0368f7e6d09f66ee7b341b073e251e",
            "TCUWCanSuzukiUSBReproUDSFlashWriter.dll",
        )
        requests = []

        def exchange(_, request):
            requests.append(request)
            return (
                b"\x6e\xcf\x80"
                if request[0] == 0x2E
                else b"\x71" + request[1:] + b"\x06"
            )

        usb = SuzukiUSBCommands(
            identity, NativeProgrammingChannel(exchange, "authored")
        )
        usb.enable_usb_repro()
        self.assertEqual([usb.routine(kind) for kind in range(3)], [0, 6, 6])
        self.assertEqual(
            requests,
            [
                bytes.fromhex("2ecf8001"),
                bytes.fromhex("3101da00"),
                bytes.fromhex("3101d915"),
                bytes.fromhex("3101da01"),
            ],
        )
        with self.assertRaises(ValueError):
            usb.routine(3)
        with self.assertRaises(ValueError):
            SuzukiUSBCommands(
                identity,
                NativeProgrammingChannel(
                    lambda *_: bytes.fromhex("7101d915"), "authored"
                ),
            ).routine(1)

    def test_fhi_literal_download_upload_routines_and_chunks(self):
        identity = identify_native_module(
            "e4fcf4a111e60bce6a807fbdde5296d6b180ed29a6196631dcdfbdfd8f48d576",
            "TCUWCanFHIFlashWriter.dll",
        )
        requests = []
        replies = [
            bytes.fromhex("74200010"),
            bytes.fromhex("75200010"),
            bytes.fromhex("71010201"),
            bytes.fromhex("71010202"),
            b"\xf7ABC",
            b"\xf6",
            b"\x77",
        ]

        def exchange(_, request):
            requests.append(request)
            return replies.pop(0)

        fhi = FHICommands(identity, NativeProgrammingChannel(exchange, "authored"))
        self.assertEqual(fhi.request_area(bytes.fromhex("00100000"), 3), 11)
        self.assertEqual(
            fhi.request_area(bytes.fromhex("00100000"), 3, upload=True), 15
        )
        fhi.routine(0x201)
        fhi.routine(0x202)
        fhi.verify_chunk(bytes.fromhex("00100000"), b"ABC")
        fhi.write_chunk(bytes.fromhex("00100000"), b"ABC")
        fhi.exit_area()
        self.assertEqual(
            requests,
            [
                bytes.fromhex("3404440010000000000003"),
                bytes.fromhex("3504440010000000000003"),
                bytes.fromhex("31010201ffffffff"),
                bytes.fromhex("3101020201"),
                bytes.fromhex("b700100000"),
                bytes.fromhex("b600100000") + b"ABC",
                b"\x37",
            ],
        )
        with self.assertRaises(ValueError):
            FHICommands(
                identity, NativeProgrammingChannel(lambda *_: b"\x74\x20", "authored")
            ).request_area(bytes(4), 1)
        with self.assertRaises(ValueError):
            FHICommands(
                identity, NativeProgrammingChannel(lambda *_: b"\xf7ABD", "authored")
            ).verify_chunk(bytes(4), b"ABC")

    def test_native_elapsed_filetime_primitive_and_uint32(self):
        from scripts.programming_2026_common import NativeRuntime2026

        observed = []
        values = iter((100, 30000101))

        def convert(row, _):
            observed.append(row)
            return next(values)

        stamp = (2026, 10, 2, 20, 12, 0, 0, 0)
        self.assertEqual(
            suzuki_elapsed_seconds(
                self.identity, NativeRuntime2026(convert), stamp, stamp
            ),
            3,
        )
        self.assertEqual(
            observed,
            [{"operation": "system_time_to_file_time", "system_time": stamp}] * 2,
        )
        for ticks, expected in (((30, 20), 0), ((0, 10000000 * (0x100000000 + 2)), 2)):
            results = iter(ticks)
            self.assertEqual(
                suzuki_elapsed_seconds(
                    self.identity,
                    NativeRuntime2026(lambda *_, observed=results: next(observed)),
                    stamp,
                    stamp,
                ),
                expected,
            )
        with self.assertRaises(ValueError):
            suzuki_elapsed_seconds(
                self.identity, NativeRuntime2026(lambda *_: None), stamp, stamp
            )

    def test_gateway_explicit_observation_retry_and_filter_cleanup(self):
        from scripts.programming_2026_common import NativeRuntime2026

        seed, key = bytes(range(16)), bytes(range(256))
        wire, actions = [], []
        replies = iter((b"\x7f\x27\x37", b"\x67\x13" + seed, b"\x67\x14"))

        def exchange(_, request):
            wire.append(request)
            return next(replies)

        def action(row, _):
            actions.append(row)
            return 7 if row["operation"] == "start_flow_control_filter" else None

        suzuki_gateway_authorize(
            self.identity,
            NativeProgrammingChannel(exchange, "00000751"),
            NativeRuntime2026(action),
            {seed: key},
            with_filter=True,
        )
        self.assertEqual(wire, [b"\x27\x13", b"\x27\x13", b"\x27\x14" + key])
        self.assertEqual(actions[1], {"operation": "wait", "milliseconds": 10100})
        self.assertEqual(actions[-1], {"operation": "stop_filter", "identifier": 7})
        wire.clear()

        def unknown_seed(_, request):
            wire.append(request)
            return b"\x67\x13" + bytes(16)

        with self.assertRaises(PermissionError):
            suzuki_gateway_authorize(
                self.identity,
                NativeProgrammingChannel(unknown_seed, "00000751"),
                NativeRuntime2026(action),
                {seed: key},
                with_filter=True,
            )
        self.assertEqual(wire, [b"\x27\x13"])
        self.assertEqual(actions[-1], {"operation": "stop_filter", "identifier": 7})

    def test_wired_capability_literal_and_j2534_error_policy(self):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import NativeRuntime2026

        requests = []

        def exchange(_, request):
            requests.append(request)
            return bytes.fromhex("62100404")

        self.assertTrue(
            suzuki_supports_wired_repro(
                self.identity,
                NativeProgrammingChannel(exchange, "00000751"),
                NativeRuntime2026(lambda *_: None),
            )
        )
        self.assertEqual(requests, [bytes.fromhex("221004")])
        for code in (9, 16):

            def fault(*_, status=code):
                raise NativeTransportError(status)

            self.assertFalse(
                suzuki_supports_wired_repro(
                    self.identity,
                    NativeProgrammingChannel(fault, "00000751"),
                    NativeRuntime2026(lambda *_: None),
                )
            )

        def fault_other(*_):
            raise NativeTransportError(7)

        with self.assertRaises(NativeTransportError):
            suzuki_supports_wired_repro(
                self.identity,
                NativeProgrammingChannel(fault_other, "00000751"),
                NativeRuntime2026(lambda *_: None),
            )

    def test_fhi_primitive_batch_pending_negative_retry_and_cleanup(self):
        from scripts.programming_2026_common import NativeRuntime2026

        identity = identify_native_module(
            "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
            "TCUWFHIUtils.dll",
        )
        request = bytes.fromhex("000007e031010201ffffffff")
        address = bytes.fromhex("000007e8")
        reads = iter(
            (
                (address + bytes.fromhex("7f3178"),),
                (address + bytes.fromhex("7f3131"),),
                (address + bytes.fromhex("71010201"),),
            )
        )
        actions = []

        def action(row, _):
            actions.append(row)
            if row["operation"] == "get_timeout":
                return 2000
            if row["operation"] == "write_messages":
                return row["count"]
            if row["operation"] == "read_specified_can_messages":
                return next(reads)
            return None

        self.assertEqual(
            fhi_exchange(
                identity,
                NativeRuntime2026(action),
                (request,),
                (address,),
                bytes.fromhex("71010201"),
                minimum=4,
            ),
            (bytes.fromhex("71010201"),),
        )
        self.assertEqual(
            [row for row in actions if row["operation"] == "write_messages"],
            [{"operation": "write_messages", "messages": (request,), "count": 1}] * 2,
        )
        self.assertIn({"operation": "set_timeout", "milliseconds": 5000}, actions)
        self.assertEqual(
            actions[-1], {"operation": "set_timeout", "milliseconds": 2000}
        )
        actions.clear()

        def endless_pending(row, remaining):
            if row["operation"] == "read_specified_can_messages":
                actions.append(row)
                return (address + bytes.fromhex("7f3178"),)
            return action(row, remaining)

        from scripts.programming_2026_common import CommonResponseError

        with self.assertRaises(CommonResponseError):
            fhi_exchange(
                identity,
                NativeRuntime2026(endless_pending),
                (request,),
                (address,),
                b"\x71",
                pending_limit=1,
            )
        self.assertIn(
            {
                "operation": "write_messages",
                "messages": (request[:4] + b"\x3e",),
                "count": 1,
            },
            actions,
        )
        self.assertEqual(
            actions[-1], {"operation": "set_timeout", "milliseconds": 2000}
        )

    def test_suzuki_native_pending_mutex_and_silent_flag(self):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeRuntime2026,
        )

        request, address = bytes.fromhex("00000751"), bytes.fromhex("00000761")
        results = iter(
            (
                address + bytes.fromhex("7f2278"),
                NativeTransportError(9),
                address + bytes.fromhex("62100404"),
            )
        )
        actions = []

        def action(row, _):
            actions.append(row)
            if row["operation"] == "get_timeout":
                return 2000
            if row["operation"] == "write_messages":
                return 1
            if row["operation"] == "read_specified_can_message":
                result = next(results)
                if isinstance(result, Exception):
                    raise result
                return result
            return None

        self.assertEqual(
            suzuki_exchange(
                self.identity,
                NativeRuntime2026(action),
                request,
                address,
                bytes.fromhex("221004"),
                bytes.fromhex("621004"),
                minimum=4,
            ),
            bytes.fromhex("62100404"),
        )
        self.assertEqual(
            sum(row["operation"] == "write_messages" for row in actions), 1
        )
        self.assertEqual(sum(row["operation"] == "lock" for row in actions), 3)
        self.assertEqual(sum(row["operation"] == "unlock" for row in actions), 5)
        self.assertEqual(
            actions[-1], {"operation": "set_timeout", "milliseconds": 2000}
        )
        results = iter((NativeTransportError(16),))
        self.assertEqual(
            suzuki_exchange(
                self.identity,
                NativeRuntime2026(action),
                request,
                address,
                bytes.fromhex("1081"),
                bytes.fromhex("5081"),
                native_flag_10=True,
            ),
            b"",
        )
        results = iter((address + bytes.fromhex("5081"),))
        with self.assertRaises(CommonResponseError):
            suzuki_exchange(
                self.identity,
                NativeRuntime2026(action),
                request,
                address,
                bytes.fromhex("1081"),
                bytes.fromhex("5081"),
                native_flag_10=True,
            )

    def test_fhi_prepare_literal_controls_and_observed_authorization(self):
        from scripts.programming_2026_common import NativeRuntime2026

        identity = identify_native_module(
            "a7160955022d5090f6274957892c4aae079ab66da74c0d3d391e104008f188b0",
            "TCUWCanFHIPrepareWriter.dll",
        )
        utility = identify_native_module(
            "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
            "TCUWFHIUtils.dll",
        )
        request, address = bytes.fromhex("000007e0"), bytes.fromhex("000007e8")
        seed, key = b"SEED", b"KEY!"
        replies = iter(
            (
                address + b"\xc5\x02",
                address + b"\x68\x03",
                address + b"\x67\x61" + seed,
                address + b"\x67\x62",
            )
        )
        writes = []

        def action(row, _):
            if row["operation"] == "get_timeout":
                return 2000
            if row["operation"] == "write_messages":
                writes.extend(row["messages"])
                return row["count"]
            if row["operation"] == "read_specified_can_messages":
                return (next(replies),)
            return None

        prepare = FHIPrepareCommands(identity, utility, NativeRuntime2026(action))
        prepare.disable_dtc((request,), (address,))
        prepare.communication_control(request, (address,))
        prepare.authorize(request, address, {seed: key})
        self.assertEqual(
            writes,
            [
                request + b"\x85\x02",
                request + b"\x28\x03\x01",
                request + b"\x27\x61",
                request + b"\x27\x62" + key,
            ],
        )
        replies = iter((address + b"\x67\x61" + bytes(4),))
        with self.assertRaises(PermissionError):
            prepare.authorize(request, address, {seed: key})
        self.assertEqual(writes[-1], request + b"\x27\x61")

    def test_suzuki_getter_lifecycle_and_native_cid_assembly(self):
        from scripts.programming_2026_common import NativeRuntime2026

        identity = identify_native_module(
            "b63abaebe764c6067ec5013c44c16f3c47cc6ebe6abfd84b0e93d3681c0b6315",
            "TCUWCanSuzukiUDSSoftwareIDGetter.dll",
        )
        actions, requests = [], []
        request, response = bytes.fromhex("000007e0"), bytes.fromhex("000007e8")

        def action(row, _):
            actions.append(row)
            return 11 if row["operation"] == "start_flow_control_filter" else None

        def exchange(_, payload):
            requests.append(payload)
            values = {
                bytes.fromhex("22f189"): bytes.fromhex("62f1890123"),
                bytes.fromhex("22f188"): bytes.fromhex("62f188") + b"S" * 16,
                bytes.fromhex("22f191"): bytes.fromhex("62f191") + b"H" * 11,
            }
            return values[payload]

        self.assertEqual(
            suzuki_get_identification(
                identity,
                self.identity,
                NativeRuntime2026(action),
                NativeProgrammingChannel(exchange, request.hex()),
                request,
                response,
                baudrate_kbps=500,
                receive_timeout_ms=1234,
            ),
            b"H" * 11 + b"_" + b"S" * 16 + b"_0123",
        )
        self.assertEqual(
            requests,
            [bytes.fromhex("22f189"), bytes.fromhex("22f188"), bytes.fromhex("22f191")],
        )
        self.assertEqual(
            [row["operation"] for row in actions],
            [
                "connect",
                "set_timeout",
                "control_io",
                "start_flow_control_filter",
                "stop_filter",
                "disconnect",
            ],
        )
        actions.clear()
        with self.assertRaises(ValueError):
            suzuki_get_identification(
                identity,
                self.identity,
                NativeRuntime2026(action),
                NativeProgrammingChannel(lambda *_: b"bad", request.hex()),
                request,
                response,
                baudrate_kbps=500,
                receive_timeout_ms=1234,
            )
        self.assertEqual(
            [row["operation"] for row in actions][-2:], ["stop_filter", "disconnect"]
        )
        from scripts.programming import NativeTransportError

        def cleanup_fault(row, remaining):
            if row["operation"] == "stop_filter":
                raise NativeTransportError(5)
            return action(row, remaining)

        cleanup_runtime = NativeRuntime2026(cleanup_fault)
        cleanup_result = SuzukiUSBResult()
        self.assertEqual(
            suzuki_get_identification(
                identity,
                self.identity,
                cleanup_runtime,
                NativeProgrammingChannel(exchange, request.hex()),
                request,
                response,
                baudrate_kbps=500,
                receive_timeout_ms=1234,
                result=cleanup_result,
            ),
            b"H" * 11 + b"_" + b"S" * 16 + b"_0123",
        )
        self.assertTrue(cleanup_result.success)
        self.assertEqual(
            cleanup_result.suppressed_cleanup_errors, ["NativeTransportError"]
        )
        self.assertEqual(actions[-1]["operation"], "disconnect")
        self.assertFalse(cleanup_runtime.owns_resource("stop_filter", identifier=11))
        self.assertEqual(cleanup_runtime.close(), [])
        for fault in (InterruptedError, TimeoutError, KeyboardInterrupt):
            with self.subTest(cleanup_boundary=fault.__name__):

                def host_cleanup_fault(row, remaining, fault=fault):
                    if row["operation"] == "stop_filter":
                        raise fault("authored host boundary")
                    return action(row, remaining)

                with self.assertRaises(fault):
                    suzuki_get_identification(
                        identity,
                        self.identity,
                        NativeRuntime2026(host_cleanup_fault),
                        NativeProgrammingChannel(exchange, request.hex()),
                        request,
                        response,
                        baudrate_kbps=500,
                        receive_timeout_ms=1234,
                    )
                self.assertEqual(actions[-1]["operation"], "disconnect")

    def test_native_suzuki_tester_info_and_month_day_bytes(self):
        identity = identify_native_module(
            "39e1fb5f196cdc3081742880cff66bdbaec149d176e8d00fd76ce397608c8a81",
            "TCUWCanSuzukiUDSFlashWriter.dll",
        )
        requests = []

        def exchange(_, request):
            requests.append(request)
            return b"\x6e" + request[1:3]

        info = bytes(range(17)).hex()
        stamp = (2026, 10, 2, 20, 12, 0, 0, 0)
        channel = NativeProgrammingChannel(exchange, "authored")
        suzuki_tester_information(identity, channel, info, stamp)
        self.assertEqual(
            requests,
            [
                bytes.fromhex("2ef198") + bytes(range(7, 17)),
                bytes.fromhex("2ef199") + b"1020",
            ],
        )
        requests.clear()
        with self.assertRaises(ValueError):
            suzuki_tester_information(identity, channel, info[:-2], stamp)
        self.assertEqual(requests, [])

    def test_actual_cuw2026_suzuki_metadata_adapter_and_archive_bounds(self):
        import hashlib
        import struct
        import zlib

        from scripts.calibration_2026 import parse_cuw_2026

        identity = identify_native_module(
            "39e1fb5f196cdc3081742880cff66bdbaec149d176e8d00fd76ce397608c8a81",
            "TCUWCanSuzukiUDSFlashWriter.dll",
        )
        text = "[Format]\nVersion=10\n[Vehicle]\nNumberOfCalibration=1\nByteNumberOfTransmitting=00000003\nCANIDTx_Func_USDT=07DF\n[CPU01]\nCPUImageName=authored.vbf\nStartAddress=0100001000\nSizeOfUncompressedDownloadData=00000008\nSizeOfDownloadData=00000004\n"
        payload = b"DATAextra"
        raw_containers = {}

        def container(metadata, images=(payload,)):
            def record(header, data):
                return (
                    struct.pack(">H", len(header))
                    + header
                    + struct.pack(">II", len(data), zlib.crc32(data))
                    + data
                )

            body = (
                record(b"authored.att", metadata.encode())
                + bytes((len(images),))
                + b"".join(record(b"authored.bin", image) for image in images)
            )
            raw = (
                b"\0CALIBRATION\0\x68"
                + bytes(4)
                + struct.pack(">I", 22 + len(body))
                + body
            )
            raw = raw[:14] + struct.pack(">I", zlib.crc32(raw[18:])) + raw[18:]
            raw_containers[metadata] = raw
            return parse_cuw_2026(raw)

        parsed = container(text)
        addressed = container(
            text.replace(
                "NumberOfCalibration=1",
                "NumberOfCalibration=1\nKindOfECU=31\nContactType=SUZUKI\nCANIDTx_Phys_USDT=07E01234\nCANIDRx_Phys_USDT=07E85678",
            )
        )
        self.assertEqual(
            native_suzuki_addresses(identity, addressed),
            (bytes.fromhex("000007e0"), bytes.fromhex("000007e8")),
        )
        with self.assertRaises(ValueError):
            native_suzuki_addresses(identity, parsed)
        from scripts.programming_2026_common import NativeParameter2026

        parameters = NativeParameter2026.from_csv(
            b"ParamFileKeySystemProtocolMicon,WaitTimeForIGOFFON,AlternateWaitTimeForIGOFFON,GetCANIDFunctionNameForFlashWrite,GetCANIDFunctionNameForGetCID\r\n31SUZUKI,-1,25,GetCanIDsFromCalibrationFileForSUZUKI,GetCanIDsFromCalibrationFileForSUZUKI\r\n"
        )
        self.assertEqual(
            suzuki_wait_time_for_igoffon(self.identity, parameters, addressed),
            0xFFFFFFFF,
        )
        self.assertEqual(
            suzuki_wait_time_for_igoffon(self.identity, parameters, addressed, kind=1),
            25,
        )
        self.assertEqual(
            suzuki_wait_time_for_igoffon(self.identity, parameters, addressed, kind=2),
            0,
        )
        self.assertEqual(suzuki_wait_time_for_igoffon(self.identity, parameters), 0)
        self.assertEqual(parameters.row_index, 0)
        for key, expected in (("31", 1), ("missing", -1)):
            parameters.set_keys(key, "", "SUZUKI")
            self.assertEqual(parameters.row_index, expected)
            self.assertEqual(
                suzuki_wait_time_for_igoffon(self.identity, parameters, addressed),
                0xFFFFFFFF,
            )
            self.assertEqual(parameters.row_index, expected)
        multi = container(
            "[Format]\nVersion=7\n[Vehicle]\nNumberOfCalibration=3\nKindOfECU=31\nContactType=SUZUKI\n[CPU01]\nCPUType=FIRST\nCPUImageName=one.vbf\n[CPU02]\nCPUType=SECOND\nCPUImageName=two.vbf\n[CPU03]\n",
            (b"one", b"two"),
        )
        from scripts.calibration_2026 import (
            native2026_cpu_count,
            native2026_metadata,
            native2026_metadata_for_cpu,
        )
        from scripts.programming_2026_suzuki_fhi import _parameter_keys

        metadata = native2026_metadata(multi)
        self.assertEqual(native2026_cpu_count(metadata), 2)
        second = native2026_metadata_for_cpu(metadata, 1)
        self.assertEqual(second.cpu.values["cputype"], "SECOND")
        self.assertEqual(_parameter_keys(second), ("31", "FIRST", "SUZUKI"))
        multi_parameters = NativeParameter2026.from_csv(
            b"ParamFileKeySystemProtocolMicon,WaitTimeForIGOFFON\r\n31SUZUKIFIRST,11\r\n31SUZUKISECOND,22\r\n"
        )
        self.assertEqual(
            suzuki_wait_time_for_igoffon(self.identity, multi_parameters, multi), 11
        )
        self.assertEqual(multi_parameters.row_index, 0)
        selected = NativeParameter2026.from_csv(
            b"ParamFileKeySystemProtocolMicon,GetCANIDFunctionNameForFlashWrite,CanIDForGetCID\r\n31SUZUKI,GetCanIDsFromParamForGetCID,07D0/07D8\r\n"
        )
        self.assertEqual(
            native_suzuki_addresses(identity, addressed, parameters=selected),
            (bytes.fromhex("000007d0"), bytes.fromhex("000007d8")),
        )
        with self.assertRaises(ValueError):
            native_suzuki_addresses(
                identity, addressed, parameters=selected, phase="PrepareWrite"
            )
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import NativeRuntime2026

        prepare_identity = identify_native_module(
            "bb34e610990a7b9b2fa4957feb9e9c8eadb79fda221cfbf833bf664eeda80c39",
            "TCUWCanSuzukiUDSPrepareWriter.dll",
        )
        wire = []
        seed, key = b"S" * 16, b"K" * 16
        replies = iter(
            (
                NativeTransportError(9),
                NativeTransportError(16),
                NativeTransportError(9),
                bytes.fromhex("5002003201f4"),
                b"\x67\x01" + seed,
                b"\x67\x02",
                b"\x67\x01" + b"X" * 16,
                bytes.fromhex("5044003201f4"),
                b"\x62\x10\x18ABCDEFG00",
                b"\x67\x29" + seed,
                b"\x67\x2a",
            )
        )

        def action(row, _):
            if row["operation"] == "get_timeout":
                return 2000
            if row["operation"] == "write_messages":
                wire.append(row["data"])
                return 1
            if row["operation"] == "read_specified_can_message":
                value = next(replies)
                if isinstance(value, Exception):
                    raise value
                return bytes.fromhex("000007e8") + value

        commands = SuzukiPrepareCommands(
            prepare_identity, self.identity, NativeRuntime2026(action), addressed
        )
        commands.extended_session()
        commands.disable_dtc()
        commands.communication_control()
        commands.programming_session()
        commands.authorize({seed: key})
        with self.assertRaises(PermissionError):
            commands.authorize({seed: key})
        commands.programming_session(usb=True)
        commands.authorize({seed: key}, usb=True)
        self.assertEqual(
            wire,
            [
                bytes.fromhex(value)
                for value in (
                    "000007df1083",
                    "000007df858200",
                    "000007df288301",
                    "000007e01002",
                    "000007e02701",
                )
            ]
            + [
                bytes.fromhex("000007e02702") + key,
                bytes.fromhex("000007e02701"),
                bytes.fromhex("000007e01044"),
                bytes.fromhex("000007e0221018"),
                bytes.fromhex("000007e02729"),
                bytes.fromhex("000007e0272a") + key,
            ],
        )
        from scripts.programming_2026_common import (
            CommonResponseError,
            NotificationBool,
        )

        write_wire, write_actions = [], []
        failed = False
        last_request = b""

        def writer_action(row, _):
            nonlocal last_request
            write_actions.append(row)
            operation = row["operation"]
            if operation in ("get_timeout", "get_send_timeout"):
                return 2000
            if operation == "start_flow_control_filter":
                return 99
            if operation == "get_system_time":
                return (2026, 10, 2, 20, 1, 2, 3, 4)
            if operation == "write_messages":
                last_request = row["data"][4:]
                write_wire.append(row["data"])
                return 1
            if operation == "read_specified_can_message":
                sid = last_request[0]
                if sid == 0x10:
                    raise NativeTransportError(16)
                if sid == 0x36 and failed:
                    return bytes.fromhex("000007e87f3672")
                positive = {
                    0x2E: b"\x6e" + last_request[1:3],
                    0x31: b"\x71" + last_request[1:4],
                    0x34: b"\x74\x20\x10",
                    0x36: b"\x76" + last_request[1:2],
                    0x37: b"\x77",
                    0x11: b"\x51\x01",
                }[sid]
                return bytes.fromhex("000007e8") + positive

        notification = NotificationBool()
        writer_runtime = NativeRuntime2026(writer_action)
        writer_runtime.own("stop_sync_periodic_message")
        state = write_suzuki_uds(
            identity,
            self.identity,
            writer_runtime,
            addressed,
            notification,
            parameters=parameters,
            tester_info="00" * 17,
        )
        self.assertTrue(state.success)
        self.assertFalse(writer_runtime.owns_resource("stop_sync_periodic_message"))
        self.assertFalse(notification)
        self.assertEqual(
            write_wire,
            [
                bytes.fromhex(value)
                for value in (
                    "000007e02ef19800000000000000000000",
                    "000007e02ef19931303230",
                    "000007e03101ff0000",
                    "000007e0340f45010000100000000008",
                    "000007e03601444154",
                    "000007e0360241",
                    "000007e037",
                    "000007e03101ff0100",
                    "000007e01101",
                    "000007df1081",
                )
            ],
        )
        self.assertEqual(
            write_actions[-2:],
            [
                {"operation": "stop_filter", "identifier": 99},
                {"operation": "stop_sync_periodic_message"},
            ],
        )
        failed = True
        state = SuzukiUSBResult()
        with self.assertRaises(CommonResponseError):
            write_suzuki_uds(
                identity,
                self.identity,
                NativeRuntime2026(writer_action),
                addressed,
                notification,
                parameters=parameters,
                tester_info="00" * 17,
                result=state,
            )
        self.assertEqual(
            (state.success, state.progress, state.error_status, state.recovery_needed),
            (False, 0, 2, False),
        )
        self.assertTrue(notification)
        count_before = len(write_wire)
        length_state = SuzukiUSBResult()
        with self.assertRaises(CommonResponseError) as length_error:
            write_suzuki_uds(
                identity,
                self.identity,
                NativeRuntime2026(writer_action),
                addressed,
                NotificationBool(),
                parameters=parameters,
                tester_info="short",
                result=length_state,
            )
        self.assertEqual(length_error.exception.code, 0x54)
        self.assertEqual(len(write_wire), count_before)
        self.assertEqual(length_state.error_status, 1)
        from types import SimpleNamespace
        from unittest.mock import patch

        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import NativeCentralGatewayKey2026

        # This authored Suzuki path supplies its own engine bytes. The engine
        # constructor now also requires a source-issued central gateway key; the
        # key is not consumed here, so bind an explicit test substitute rather
        # than pretending the authored bytes are an authenticated CUW2026 image.
        with (
            patch(
                "scripts.cuw_2026.identity_2026",
                return_value=SimpleNamespace(sha256="authored-engine"),
            ),
            patch("scripts.cuw_2026.gateway_authentication2026", return_value=None),
            patch.object(
                NativeCentralGatewayKey2026, "from_native_module", return_value=None
            ),
        ):
            engine = CUWEngine2026(b"authored")
        engine.configure(struct.pack("<IIddII", 1, 0, 1, 2, 0, 0))
        engine.load_cuw(
            raw_containers[
                next(value for value in raw_containers if "CANIDTx_Phys_USDT=" in value)
            ]
        )
        cid_replies = iter(
            (
                bytes.fromhex("62f1890102"),
                b"\x62\xf1\x88SOFTWARE00000000",
                b"\x62\xf1\x91HARDWARE000",
                bytes.fromhex("62f1890102"),
                b"\x62\xf1\x88SOFTWARE00000000",
                b"\x62\xf1\x91HARDWARE000",
                b"\x62\xf1\x89",
            )
        )

        def cid_action(row, _):
            if row["operation"] == "get_timeout":
                return 2000
            if row["operation"] == "start_flow_control_filter":
                return 8
            if row["operation"] == "write_messages":
                return 1
            if row["operation"] == "read_specified_can_message":
                return bytes.fromhex("000007e8") + next(cid_replies)

        cid = b"HARDWARE000_SOFTWARE00000000_0102"
        self.assertEqual(
            suzuki_recheck_prepare_cid(
                prepare_identity,
                self.identity,
                NativeRuntime2026(cid_action, native_cancelled=engine.native_cancelled),
                addressed,
                parameters,
                engine.suzuki_state,
                cid,
            ),
            cid,
        )
        self.assertEqual(engine.suzuki_state.value, 0)
        prepare_parameters = NativeParameter2026.from_csv(
            b"ParamFileKeySystemProtocolMicon,GetCANIDFunctionNameForPrepareWrite,GetCANIDFunctionNameForGetCID,ReceiveTimeoutBeforeFlashWrite\r\n31SUZUKI,GetCanIDsFromCalibrationFileForSUZUKI,GetCanIDsFromCalibrationFileForSUZUKI,2000\r\n"
        )
        prepare_wire, prepare_actions = [], []
        prepare_last = b""
        prepare_response_address = b""
        prepare_filters = 0
        unknown_seed = False
        fail_prepare_filter = False

        def prepare_action(row, _):
            nonlocal prepare_last, prepare_response_address, prepare_filters
            prepare_actions.append(row)
            operation = row["operation"]
            if operation == "stop_filter" and fail_prepare_filter:
                raise RuntimeError("authored filter cleanup fault")
            if operation == "observe_authorization_key":
                self.assertEqual(row["seed"], seed)
                return b"G" * 256 if row["key_length"] == 256 else key
            if operation == "get_timeout":
                return 2000
            if operation == "start_flow_control_filter":
                prepare_filters += 1
                return prepare_filters
            if operation == "write_messages":
                prepare_last = row["data"][4:]
                prepare_response_address = bytes.fromhex(
                    "00000761"
                    if row["data"][:4] == bytes.fromhex("00000751")
                    else "000007e8"
                )
                prepare_wire.append(row["data"])
                return 1
            if operation == "read_specified_can_message":
                if prepare_last in (b"\x10\x83", b"\x85\x82\x00", b"\x28\x83\x01"):
                    raise NativeTransportError(16)
                positive = {
                    b"\x27\x13": b"\x67\x13" + seed,
                    b"\x31\x01\xc0\x01\x00": b"\x71\x01\xc0\x01",
                    b"\x10\x02": bytes.fromhex("5002003201f4"),
                    b"\x27\x01": b"\x67\x01" + (b"X" * 16 if unknown_seed else seed),
                }.get(prepare_last)
                if positive is None:
                    positive = b"\x67" + prepare_last[1:2]
                return prepare_response_address + positive

        prepare_runtime = NativeRuntime2026(prepare_action)
        self.assertTrue(
            prepare_suzuki_uds(
                prepare_identity,
                self.identity,
                prepare_runtime,
                addressed,
                prepare_parameters,
                engine.suzuki_state,
                cid,
                {seed: b"G" * 256},
                {seed: key},
            ).success
        )
        self.assertEqual(
            prepare_wire,
            [
                bytes.fromhex("000007df1083"),
                bytes.fromhex("000007512713"),
                bytes.fromhex("000007512714") + b"G" * 256,
                bytes.fromhex("000007513101c00100"),
                bytes.fromhex("000007df858200"),
                bytes.fromhex("000007df288301"),
                bytes.fromhex("000007e01002"),
                bytes.fromhex("000007e02701"),
                bytes.fromhex("000007e02702") + key,
            ],
        )
        self.assertTrue(prepare_runtime.owns_resource("stop_sync_periodic_message"))
        self.assertEqual(prepare_runtime.close(), [])
        observed_runtime = NativeRuntime2026(prepare_action)
        with self.assertRaisesRegex(ValueError, "Source-issued online controller"):
            prepare_suzuki_uds(
                prepare_identity,
                self.identity,
                observed_runtime,
                addressed,
                prepare_parameters,
                engine.suzuki_state,
                cid,
                None,
                None,
            )
        self.assertEqual(observed_runtime.close(), [])
        observed_runtime = NativeRuntime2026(prepare_action)
        self.assertTrue(
            prepare_suzuki_uds(
                prepare_identity,
                self.identity,
                observed_runtime,
                addressed,
                prepare_parameters,
                engine.suzuki_state,
                cid,
                {seed: b"G" * 256},
                None,
            ).success
        )
        self.assertEqual(observed_runtime.close(), [])
        unknown_seed = True
        preparation_state = SuzukiUSBResult()
        with self.assertRaises(PermissionError):
            prepare_suzuki_uds(
                prepare_identity,
                self.identity,
                NativeRuntime2026(prepare_action),
                addressed,
                prepare_parameters,
                engine.suzuki_state,
                cid,
                {seed: b"G" * 256},
                {seed: key},
                result=preparation_state,
            )
        self.assertEqual(preparation_state.error_status, 1)
        self.assertEqual(prepare_actions[-1]["operation"], "stop_sync_periodic_message")
        unknown_seed = False
        fail_prepare_filter = True
        filter_fault_runtime = NativeRuntime2026(prepare_action)
        filter_fault = prepare_suzuki_uds(
            prepare_identity,
            self.identity,
            filter_fault_runtime,
            addressed,
            prepare_parameters,
            engine.suzuki_state,
            cid,
            {seed: b"G" * 256},
            {seed: key},
        )
        self.assertTrue(filter_fault.success)
        self.assertEqual(filter_fault.cleanup_errors, [])
        self.assertEqual(
            filter_fault.suppressed_cleanup_errors, ["RuntimeError", "RuntimeError"]
        )
        self.assertTrue(
            filter_fault_runtime.owns_resource("stop_sync_periodic_message")
        )
        self.assertEqual(prepare_actions[-1]["operation"], "stop_filter")

        fhi_identity = identify_native_module(
            "e4fcf4a111e60bce6a807fbdde5296d6b180ed29a6196631dcdfbdfd8f48d576",
            "TCUWCanFHIFlashWriter.dll",
        )
        fhi_utility = identify_native_module(
            "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
            "TCUWFHIUtils.dll",
        )
        fhi_parameters = NativeParameter2026.from_csv(
            b'ParamFileKeySystemProtocolMicon,StartAddress,GetCANIDFunctionNameForFlashWrite,CanIDForPrepareWrite\r\n31SUZUKI,0100,GetCanIDsFromParamForPrepareWrite,"07E0/07E8\n07E1/07E9"\r\n'
        )
        fhi_program = native_fhi_program(
            fhi_identity, fhi_utility, addressed, fhi_parameters
        )
        self.assertEqual((fhi_program.area_length, fhi_program.data), (9, payload))
        fhi_wire = []
        fhi_actions = []
        fhi_last = b""
        fhi_fail = False
        fhi_reset_fault = False

        def fhi_action(row, _):
            nonlocal fhi_last
            fhi_actions.append(row)
            operation = row["operation"]
            if (
                operation == "notify_done_size"
                and row["value"] == 0
                and fhi_reset_fault
            ):
                raise CommonResponseError(0x99)
            if operation == "get_timeout":
                return 2000
            if operation == "start_flow_control_filter":
                return 12
            if operation == "write_messages":
                fhi_last = row["messages"][0][4:]
                fhi_wire.append(row["messages"][0])
                return 1
            if operation == "read_specified_can_messages":
                sid = fhi_last[0]
                if sid == 0xB6 and fhi_fail:
                    return (bytes.fromhex("000007e87fb672"),)
                if sid == 0xB7:
                    offset = int.from_bytes(fhi_last[1:], "big") - 0x100
                    positive = b"\xf7" + payload[offset : offset + 4]
                else:
                    positive = {
                        0x34: bytes.fromhex("74200007"),
                        0x35: bytes.fromhex("75200005"),
                        0x31: b"\x71" + fhi_last[1:4],
                        0x37: b"\x77",
                        0xB6: b"\xf6",
                    }[sid]
                return (bytes.fromhex("000007e8") + positive,)

        fhi_notification = NotificationBool()
        self.assertTrue(
            write_fhi(
                fhi_identity,
                fhi_utility,
                NativeRuntime2026(fhi_action),
                addressed,
                fhi_parameters,
                fhi_notification,
            ).success
        )
        self.assertFalse(fhi_notification)
        self.assertEqual(
            fhi_wire,
            [
                bytes.fromhex(value)
                for value in (
                    "000007e034042201000009",
                    "000007e031010201ffffffff",
                    "000007e0b70100",
                    "000007e0b70104",
                    "000007e0b70108",
                    "000007e037",
                    "000007e03101020201",
                    "000007e035042201000009",
                    "000007e0b6010044415441",
                    "000007e0b6010465787472",
                    "000007e0b6010861",
                    "000007e037",
                )
            ],
        )
        self.assertEqual(
            fhi_actions[-2:],
            [
                {"operation": "stop_filter", "identifier": 12},
                {"operation": "set_timeout", "milliseconds": 2000},
            ],
        )

        def fhi_cleanup_fault(row, remaining):
            if row["operation"] == "stop_filter":
                raise NativeTransportError(5)
            return fhi_action(row, remaining)

        fhi_cleanup_runtime = NativeRuntime2026(fhi_cleanup_fault)
        fhi_cleanup_state = write_fhi(
            fhi_identity,
            fhi_utility,
            fhi_cleanup_runtime,
            addressed,
            fhi_parameters,
            fhi_notification,
        )
        self.assertTrue(fhi_cleanup_state.success)
        self.assertEqual(fhi_cleanup_state.cleanup_errors, [])
        self.assertEqual(
            fhi_cleanup_state.suppressed_cleanup_errors, ["NativeTransportError"]
        )
        self.assertTrue(fhi_cleanup_runtime.owns_resource("stop_filter", identifier=12))
        self.assertFalse(fhi_notification)
        fhi_fail = True
        fhi_state = SuzukiUSBResult()
        with self.assertRaises(CommonResponseError):
            write_fhi(
                fhi_identity,
                fhi_utility,
                NativeRuntime2026(fhi_action),
                addressed,
                fhi_parameters,
                fhi_notification,
                result=fhi_state,
            )
        self.assertEqual(
            (fhi_state.success, fhi_state.error_status, fhi_state.progress),
            (False, 2, 0),
        )
        self.assertTrue(fhi_notification)
        self.assertEqual(
            [row["operation"] for row in fhi_actions[-4:]],
            ["stop_filter", "notify_done_size", "notify_progress", "set_timeout"],
        )
        fhi_actions.clear()
        fhi_reset_fault = True
        fhi_state = SuzukiUSBResult()
        with self.assertRaises(CommonResponseError) as tail_fault:
            write_fhi(
                fhi_identity,
                fhi_utility,
                NativeRuntime2026(fhi_action),
                addressed,
                fhi_parameters,
                fhi_notification,
                result=fhi_state,
            )
        self.assertEqual(tail_fault.exception.code, 0x99)
        self.assertEqual(
            [row["operation"] for row in fhi_actions[-2:]],
            ["stop_filter", "notify_done_size"],
        )
        fhi_prepare_identity = identify_native_module(
            "a7160955022d5090f6274957892c4aae079ab66da74c0d3d391e104008f188b0",
            "TCUWCanFHIPrepareWriter.dll",
        )
        fhi_prepare_parameters = NativeParameter2026.from_csv(
            b'ParamFileKeySystemProtocolMicon,GetCANIDFunctionNameForPrepareWrite,CanIDForPrepareWrite\r\n31SUZUKI,GetCanIDsFromParamForPrepareWrite,"07E0/07E8\n07E1/07E9"\r\n'
        )
        prepare_fhi_wire = []
        prepare_fhi_last = b""
        probe_timeout = None
        fhi_prepare_filter_count = 0
        fhi_prepare_actions = []

        def fhi_prepare_action(row, _):
            nonlocal prepare_fhi_last, fhi_prepare_filter_count
            operation = row["operation"]
            fhi_prepare_actions.append(row)
            if operation == "observe_authorization_key":
                self.assertEqual(
                    (row["family"], row["stage"], row["seed"], row["key_length"]),
                    ("fhi", "ecu", b"S" * 4, 4),
                )
                return b"K" * 4
            if operation == "get_timeout":
                return 2000
            if operation == "start_flow_control_filter":
                fhi_prepare_filter_count += 1
                return fhi_prepare_filter_count
            if operation == "write_messages":
                messages = row.get("messages", (row.get("data"),))
                prepare_fhi_wire.extend(messages)
                prepare_fhi_last = messages[0][4:]
                return len(messages)
            if operation == "read_specified_can_message":
                if row["address"] == probe_timeout:
                    raise NativeTransportError(9)
                return row["address"] + b"\x49\x00"
            if operation == "read_specified_can_messages":
                if prepare_fhi_last[0] == 0x10:
                    positive = b"\x50" + prepare_fhi_last[1:2]
                elif prepare_fhi_last == b"\x85\x02":
                    positive = b"\xc5\x02"
                elif prepare_fhi_last == b"\x28\x03\x01":
                    positive = b"\x68\x03"
                elif prepare_fhi_last == b"\x27\x61":
                    positive = b"\x67\x61" + b"S" * 4
                else:
                    positive = b"\x67\x62"
                return tuple(address + positive for address in row["addresses"])

        fhi_prepared = prepare_fhi(
            fhi_prepare_identity,
            fhi_utility,
            NativeRuntime2026(fhi_prepare_action),
            addressed,
            fhi_prepare_parameters,
            {b"S" * 4: b"K" * 4},
        )
        self.assertTrue(fhi_prepared.success)
        self.assertFalse(fhi_prepared.skipped_after_probe_timeout)
        self.assertTrue(fhi_prepared.ect_present)
        self.assertEqual(
            prepare_fhi_wire,
            [
                bytes.fromhex(value)
                for value in (
                    "000007e00900",
                    "000007e10900",
                    "000007e01063",
                    "000007e11063",
                    "000007b08502",
                    "000007df8502",
                    "000007df280301",
                    "000007e02761",
                    "000007e027624b4b4b4b",
                    "000007e01062",
                )
            ],
        )
        self.assertTrue(
            prepare_fhi(
                fhi_prepare_identity,
                fhi_utility,
                NativeRuntime2026(fhi_prepare_action),
                addressed,
                fhi_prepare_parameters,
                None,
            ).success
        )
        probe_timeout = bytes.fromhex("000007e9")
        prepare_fhi_wire.clear()
        no_ect = prepare_fhi(
            fhi_prepare_identity,
            fhi_utility,
            NativeRuntime2026(fhi_prepare_action),
            addressed,
            fhi_prepare_parameters,
            {b"S" * 4: b"K" * 4},
        )
        self.assertTrue(no_ect.success)
        self.assertFalse(no_ect.ect_present)
        self.assertNotIn(bytes.fromhex("000007e11063"), prepare_fhi_wire)
        probe_timeout = bytes.fromhex("000007e8")
        prepare_fhi_wire.clear()
        skipped = prepare_fhi(
            fhi_prepare_identity,
            fhi_utility,
            NativeRuntime2026(fhi_prepare_action),
            addressed,
            fhi_prepare_parameters,
            {},
        )
        self.assertTrue(skipped.success)
        self.assertTrue(skipped.skipped_after_probe_timeout)
        self.assertEqual(
            prepare_fhi_wire,
            [bytes.fromhex("000007e00900"), bytes.fromhex("000007e10900")],
        )
        probe_timeout = None
        with self.assertRaises(PermissionError):
            prepare_fhi(
                fhi_prepare_identity,
                fhi_utility,
                NativeRuntime2026(fhi_prepare_action),
                addressed,
                fhi_prepare_parameters,
                {b"X" * 4: b"K" * 4},
            )
        self.assertEqual(
            [action["operation"] for action in fhi_prepare_actions[-4:]],
            ["stop_filter", "stop_filter", "stop_filter", "set_timeout"],
        )
        suzuki_recheck_prepare_cid(
            prepare_identity,
            self.identity,
            NativeRuntime2026(cid_action, native_cancelled=engine.native_cancelled),
            addressed,
            parameters,
            engine.suzuki_state,
            b"different",
        )
        self.assertEqual(engine.suzuki_state.value, 1)
        usb_identity = identify_native_module(
            "d48d438117ae5fa043811028636d1ddd3c0368f7e6d09f66ee7b341b073e251e",
            "TCUWCanSuzukiUSBReproUDSFlashWriter.dll",
        )
        skip_actions = []
        skipped_usb = write_suzuki_usb(
            usb_identity,
            self.identity,
            NativeRuntime2026(lambda row, _: skip_actions.append(row)),
            addressed,
            parameters,
            engine.suzuki_state,
            NotificationBool(),
        )
        self.assertTrue(skipped_usb.success)
        self.assertTrue(skipped_usb.skipped_for_persistent_state)
        self.assertEqual(skipped_usb.persistent_native_state, 1)
        self.assertEqual(skip_actions, [{"operation": "notify_progress", "value": 100}])
        recheck_failure = SuzukiUSBResult()
        self.assertIsNone(
            suzuki_recheck_prepare_cid(
                prepare_identity,
                self.identity,
                NativeRuntime2026(cid_action, native_cancelled=engine.native_cancelled),
                addressed,
                parameters,
                engine.suzuki_state,
                cid,
                result=recheck_failure,
            )
        )
        self.assertEqual(recheck_failure.error_status, 1)
        self.assertEqual(recheck_failure.report()["native_primary_error"], 3)
        self.assertEqual(engine.suzuki_state.value, 0)
        retry_text = next(
            value for value in raw_containers if "CANIDTx_Phys_USDT=" in value
        ).replace("CANIDTx_Phys_USDT=07E01234", "CANIDTx_Phys_USDT=07951234")
        retry_container = container(retry_text)
        with (
            patch(
                "scripts.cuw_2026.identity_2026",
                return_value=SimpleNamespace(sha256="authored-engine"),
            ),
            patch("scripts.cuw_2026.gateway_authentication2026", return_value=None),
            patch.object(
                NativeCentralGatewayKey2026, "from_native_module", return_value=None
            ),
        ):
            retry_engine = CUWEngine2026(b"authored")
        retry_engine.configure(struct.pack("<IIddII", 1, 0, 1, 2, 0, 0))
        retry_engine.load_cuw(raw_containers[retry_text])
        retry_engine.suzuki_state.mark_usb_retry_fault()
        retry_actions = []

        def retry_action(row, _):
            retry_actions.append(row)
            if row["operation"] == "get_timeout":
                return 2000
            if row["operation"] == "start_flow_control_filter":
                return 9
            if row["operation"] == "write_messages":
                return 1
            if row["operation"] == "read_specified_can_message":
                return bytes.fromhex("000007e862f189")

        retry_result = prepare_suzuki_uds(
            prepare_identity,
            self.identity,
            NativeRuntime2026(
                retry_action, native_cancelled=retry_engine.native_cancelled
            ),
            retry_container,
            prepare_parameters,
            retry_engine.suzuki_state,
            cid,
            None,
            None,
        )
        self.assertFalse(retry_result.success)
        self.assertEqual(retry_result.error_status, 1)
        self.assertEqual(retry_result.report()["native_primary_error"], 3)
        self.assertEqual(retry_engine.suzuki_state.value, 0)
        self.assertNotIn(
            "set_local_time_to_previous_send_time",
            [row["operation"] for row in retry_actions],
        )
        from scripts.j2534_2026 import NativeJ2534Error2026

        cleanup_replies = iter(
            (
                bytes.fromhex("62f1890102"),
                b"\x62\xf1\x88SOFTWARE00000000",
                b"\x62\xf1\x91HARDWARE000",
            )
        )

        def recheck_cleanup_fault(row, remaining):
            if row["operation"] == "stop_filter":
                raise NativeJ2534Error2026(5)
            if row["operation"] == "read_specified_can_message":
                return bytes.fromhex("000007e8") + next(cleanup_replies)
            return retry_action(row, remaining)

        suppressed = SuzukiUSBResult()
        cleanup_runtime = NativeRuntime2026(
            recheck_cleanup_fault, native_cancelled=retry_engine.native_cancelled
        )
        self.assertEqual(
            suzuki_recheck_prepare_cid(
                prepare_identity,
                self.identity,
                cleanup_runtime,
                retry_container,
                prepare_parameters,
                retry_engine.suzuki_state,
                b"different",
                result=suppressed,
            ),
            cid,
        )
        self.assertEqual(retry_engine.suzuki_state.value, 1)
        self.assertEqual(suppressed.suppressed_cleanup_errors, ["NativeJ2534Error2026"])
        self.assertEqual(suppressed.cleanup_errors, [])
        self.assertTrue(cleanup_runtime.owns_resource("stop_filter", identifier=9))
        usb_wire, usb_actions = [], []
        usb_last = b""
        enable_failures, poll_failures, d915_failures = 2, 1, 1
        reset_fault = None

        def usb_action(row, _):
            nonlocal usb_last, enable_failures, poll_failures, d915_failures
            usb_actions.append(row)
            operation = row["operation"]
            if operation == "get_timeout":
                return 2000
            if operation == "start_flow_control_filter":
                return 17
            if operation == "write_messages":
                usb_last = row["data"][4:]
                usb_wire.append(usb_last)
                return 1
            if operation == "read_specified_can_message":
                if usb_last[0] == 0x2E:
                    if enable_failures:
                        enable_failures -= 1
                        raise NativeTransportError(9)
                    positive = bytes.fromhex("6ecf80")
                elif usb_last == bytes.fromhex("3103da00"):
                    if poll_failures:
                        poll_failures -= 1
                        raise NativeTransportError(16)
                    positive = bytes.fromhex("7103da0006")
                elif usb_last == bytes.fromhex("3101d915"):
                    status = 0 if d915_failures else 1
                    d915_failures = 0
                    positive = bytes.fromhex("7101d915") + bytes((status,))
                elif usb_last == bytes.fromhex("3101da01"):
                    if reset_fault == "transport":
                        raise NativeTransportError(16)
                    positive = bytes.fromhex("7101da01") + bytes(
                        (0 if reset_fault == "status" else 1,)
                    )
                else:
                    positive = bytes.fromhex("7101da00")
                return bytes.fromhex("000007e8") + positive

        usb_written = write_suzuki_usb(
            usb_identity,
            self.identity,
            NativeRuntime2026(usb_action),
            addressed,
            parameters,
            engine.suzuki_state,
            NotificationBool(),
        )
        self.assertTrue(usb_written.success)
        self.assertEqual(
            usb_wire,
            [
                bytes.fromhex(value)
                for value in (
                    "2ecf8001",
                    "2ecf8001",
                    "2ecf8001",
                    "3101da00",
                    "3103da00",
                    "3103da00",
                    "3101d915",
                    "3101d915",
                    "3101da01",
                )
            ],
        )
        reset_fault = "status"
        with self.assertRaises(CommonResponseError) as bad_reset:
            write_suzuki_usb(
                usb_identity,
                self.identity,
                NativeRuntime2026(usb_action),
                addressed,
                parameters,
                engine.suzuki_state,
                NotificationBool(),
            )
        self.assertEqual(bad_reset.exception.code, 0x19)
        self.assertEqual(engine.suzuki_state.value, 0)
        reset_fault = "transport"
        reset_state = SuzukiUSBWriteResult()
        count_before = usb_wire.count(bytes.fromhex("3101da01"))
        with self.assertRaises(CommonResponseError) as failed_reset:
            write_suzuki_usb(
                usb_identity,
                self.identity,
                NativeRuntime2026(usb_action),
                addressed,
                parameters,
                engine.suzuki_state,
                NotificationBool(),
                result=reset_state,
            )
        self.assertEqual(failed_reset.exception.code, 0x409)
        self.assertEqual(usb_wire.count(bytes.fromhex("3101da01")) - count_before, 4)
        self.assertEqual(
            (engine.suzuki_state.value, reset_state.persistent_native_state), (2, 2)
        )
        getter_identity = identify_native_module(
            "b63abaebe764c6067ec5013c44c16f3c47cc6ebe6abfd84b0e93d3681c0b6315",
            "TCUWCanSuzukiUDSSoftwareIDGetter.dll",
        )
        cid_replies = iter(
            (
                bytes.fromhex("62f1890102"),
                b"\x62\xf1\x88SOFTWARE00000000",
                b"\x62\xf1\x91HARDWARE000",
            )
        )
        self.assertEqual(
            get_suzuki_cid(
                getter_identity,
                self.identity,
                NativeRuntime2026(cid_action, native_cancelled=engine.native_cancelled),
                addressed,
                parameters,
            ),
            cid,
        )
        from scripts.programming_2026_common import bind_native_parameter2026

        selected_bytes, utility_bytes = (
            b"authored getter registry fixture",
            b"authored utility registry fixture",
        )
        fixture_getter = replace(
            getter_identity, sha256=hashlib.sha256(selected_bytes).hexdigest()
        )
        fixture_utility = replace(
            self.identity, sha256=hashlib.sha256(utility_bytes).hexdigest()
        )
        usb_module_bytes = b"authored USB writer registry fixture"
        fixture_usb = replace(
            usb_identity, sha256=hashlib.sha256(usb_module_bytes).hexdigest()
        )
        binding_csv = b"ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID,GetCANIDFunctionNameForGetCID\r\n31SUZUKI,TCUWCanSuzukiUDSSoftwareIDGetter.dll,GetCanIDsFromCalibrationFileForSUZUKI\r\n"
        selected_binding = bind_native_parameter2026(
            addressed, {"31SUZUKI.ini": binding_csv}, "get_cid", encoded=False
        )
        material = {"selected_module": selected_bytes, "utils_module": utility_bytes}
        source_observations = {"suzuki_state": engine.suzuki_state}

        def fixture_identity(digest, name=""):
            for item in (fixture_getter, fixture_utility, fixture_usb):
                if digest == item.sha256 and (not name or name == item.module_name):
                    return item
            return identify_native_module(digest, name)

        with patch(
            "scripts.programming_2026_suzuki_fhi.identify_native_module",
            side_effect=fixture_identity,
        ):
            bound = bind_native_context(
                addressed,
                1,
                (),
                selected_binding,
                fixture_getter,
                material,
                source_observations,
            )
            cid_replies = iter(
                (
                    bytes.fromhex("62f1890102"),
                    b"\x62\xf1\x88SOFTWARE00000000",
                    b"\x62\xf1\x91HARDWARE000",
                )
            )
            canonical_result = execute_context(
                bound,
                NativeRuntime2026(cid_action, native_cancelled=engine.native_cancelled),
            )
            self.assertEqual(canonical_result["state"], "read_completed")
            self.assertEqual(canonical_result["identifiers"], [cid.decode("latin1")])
            self.assertFalse(canonical_result["programming_completed"])
            self.assertIsNone(canonical_result["native_return"])
            from scripts.j2534_2026 import (
                NativeJ2534Error2026,
                NativePassThruError2026,
            )
            from scripts.programming_2026_common import CommonResponseError

            def caught_body_fault(row, remaining):
                if row["operation"] == "control_io":
                    raise NativeJ2534Error2026(5)
                return cid_action(row, remaining)

            ordinary_native_failure = execute_context(
                bound,
                NativeRuntime2026(
                    caught_body_fault, native_cancelled=engine.native_cancelled
                ),
            )
            self.assertEqual(ordinary_native_failure["state"], "failed")
            self.assertFalse(ordinary_native_failure["native_success"])
            self.assertEqual(ordinary_native_failure["identifiers"], [])
            self.assertEqual(ordinary_native_failure["native_primary_error"], 1)
            self.assertEqual(ordinary_native_failure["native_passthru_error"], 5)

            for error in (
                CommonResponseError(0x22),
                CommonResponseError(0x409),
                CommonResponseError(0x19),
                NativePassThruError2026(9),
                NativeJ2534Error2026(5),
            ):
                with (
                    patch(
                        "scripts.programming_2026_suzuki_fhi.get_suzuki_cid",
                        side_effect=error,
                    ),
                    self.assertRaises(type(error)) as raised,
                ):
                    execute_context(bound, NativeRuntime2026(cid_action))
                self.assertIs(raised.exception, error)
            with self.assertRaises(ValueError):
                execute_context(
                    replace(bound, addresses=()),
                    NativeRuntime2026(
                        cid_action, native_cancelled=engine.native_cancelled
                    ),
                )
            with self.assertRaises(ValueError):
                bind_native_context(
                    addressed,
                    1,
                    (),
                    selected_binding,
                    fixture_getter,
                    material,
                    {**source_observations, "data": b"manual override"},
                )
            import tempfile
            from pathlib import Path

            from scripts.cuw_persistence import (
                CUWPersistence,
                RecoveryCalibration,
                ReproInfoState,
            )

            usb_csv = b"ParamFileKeySystemProtocolMicon,DLLFileNameForFlashWrite,GetCANIDFunctionNameForFlashWrite\r\n31SUZUKI,TCUWCanSuzukiUSBReproUDSFlashWriter.dll,GetCanIDsFromCalibrationFileForSUZUKI\r\n"
            usb_binding = bind_native_parameter2026(
                addressed, {"31SUZUKI.ini": usb_csv}, "write", encoded=False
            )
            usb_material = {
                "selected_module": usb_module_bytes,
                "utils_module": utility_bytes,
            }
            with self.assertRaises(ValueError):
                bind_native_context(
                    addressed,
                    1,
                    (),
                    usb_binding,
                    fixture_usb,
                    usb_material,
                    source_observations,
                )
            with tempfile.TemporaryDirectory() as recovery_root:
                persistence = CUWPersistence(
                    Path(recovery_root),
                    ReproInfoState(
                        (
                            RecoveryCalibration(
                                "authored.cuw",
                                next(
                                    data
                                    for data in raw_containers.values()
                                    if hashlib.sha256(data).hexdigest()
                                    == engine.source_sha256
                                ),
                            ),
                        )
                    ),
                )
                engine.bind_persistence(persistence)
                self.assertIs(
                    engine.suzuki_state.notification, persistence.notification
                )
                engine.suzuki_state.mark_usb_retry_fault()
                usb_bound = bind_native_context(
                    addressed,
                    1,
                    (),
                    usb_binding,
                    fixture_usb,
                    usb_material,
                    source_observations,
                )
                skip_calls = []
                skipped = execute_context(
                    usb_bound,
                    NativeRuntime2026(lambda row, _: skip_calls.append(row)),
                )
                self.assertIs(skipped["native_return"], True)
                self.assertTrue(skipped["skipped_for_persistent_state"])
                self.assertEqual(
                    skip_calls, [{"operation": "notify_progress", "value": 100}]
                )
                self.assertEqual(list(Path(recovery_root).iterdir()), [])
            engine.apply_cpu_type(0, "OVERRIDE")
            with self.assertRaises(ValueError):
                bind_native_context(
                    addressed,
                    1,
                    (),
                    selected_binding,
                    fixture_getter,
                    material,
                    source_observations,
                )
            current_binding = bind_native_parameter2026(
                addressed,
                {
                    "31SUZUKIOVERRIDE.ini": binding_csv.replace(
                        b"GetCANIDFunctionNameForGetCID\r\n31SUZUKI,",
                        b"GetCANIDFunctionNameForGetCID,ReceiveTimeoutBeforeGetCID\r\n31SUZUKIOVERRIDE,",
                    ).replace(
                        b"GetCanIDsFromCalibrationFileForSUZUKI\r\n",
                        b"GetCanIDsFromCalibrationFileForSUZUKI,77\r\n",
                    )
                },
                "get_cid",
                encoded=False,
                metadata_state=engine.native_metadata,
            )
            current_bound = bind_native_context(
                addressed,
                1,
                (),
                current_binding,
                fixture_getter,
                material,
                source_observations,
            )
            self.assertEqual(current_bound.selection, current_binding)
            cid_replies = iter(
                (
                    bytes.fromhex("62f1890102"),
                    b"\x62\xf1\x88SOFTWARE00000000",
                    b"\x62\xf1\x91HARDWARE000",
                )
            )
            current_calls = []

            def current_action(row, remaining):
                current_calls.append(row)
                return cid_action(row, remaining)

            current_read = execute_context(
                current_bound,
                NativeRuntime2026(
                    current_action, native_cancelled=engine.native_cancelled
                ),
            )
            self.assertEqual(current_read["state"], "read_completed")
            self.assertIn(
                {"operation": "set_timeout", "milliseconds": 77}, current_calls
            )
        with self.assertRaises(ValueError):
            bind_native_context(
                addressed,
                1,
                (),
                selected_binding,
                fixture_getter,
                material,
                source_observations,
            )
        program = native_suzuki_program(identity, parsed)
        self.assertEqual(program.start_address, bytes.fromhex("0100001000"))
        self.assertEqual(
            (
                program.data,
                program.download_length,
                program.max_block_data,
                program.post_request_address,
            ),
            (b"DATA", 8, 3, bytes.fromhex("000007df")),
        )
        self.assertEqual(program.container_sha256, parsed.digest)
        self.assertEqual(program.archive_sha256, hashlib.sha256(payload).hexdigest())
        fallback = native_suzuki_program(
            identity,
            container(
                text.replace(
                    "SizeOfUncompressedDownloadData=00000008",
                    "SizeOfUncompressedDownloadData=00000000",
                )
            ),
        )
        self.assertEqual(fallback.download_length, 4)
        with self.assertRaises(ValueError):
            native_suzuki_program(
                identity,
                container(
                    text.replace(
                        "SizeOfDownloadData=00000004", "SizeOfDownloadData=00000020"
                    )
                ),
            )
        with self.assertRaises(ValueError):
            native_suzuki_program(
                identity, container(text.replace("Version=10", "Version=6"))
            )

    def test_usb_native_status_polling_progress_regression_and_timeout(self):
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeRuntime2026,
        )

        identity = identify_native_module(
            "d48d438117ae5fa043811028636d1ddd3c0368f7e6d09f66ee7b341b073e251e",
            "TCUWCanSuzukiUSBReproUDSFlashWriter.dll",
        )
        statuses = iter((0, 2, 6))
        requests, actions = [], []

        def exchange(_, request):
            requests.append(request)
            return bytes.fromhex("7103da00") + bytes((next(statuses),))

        def action(row, _):
            actions.append(row)
            if row["operation"] == "get_system_time":
                return (2026, 10, 2, 20, 12, 0, 0, 0)
            if row["operation"] == "system_time_to_file_time":
                return 0
            return None

        result = suzuki_poll_usb(
            identity,
            self.identity,
            NativeProgrammingChannel(exchange, "authored"),
            NativeRuntime2026(action),
        )
        self.assertEqual(
            result, {"native_status": 6, "progress": [20, 30, 80], "completed": False}
        )
        self.assertEqual(requests, [bytes.fromhex("3103da00")] * 3)
        statuses = iter((2, 0))
        with self.assertRaises(CommonResponseError) as caught:
            suzuki_poll_usb(
                identity,
                self.identity,
                NativeProgrammingChannel(exchange, "authored"),
                NativeRuntime2026(action),
            )
        self.assertEqual(caught.exception.code, 0x407)
        statuses = iter((7,))
        with self.assertRaises(CommonResponseError) as caught:
            suzuki_poll_usb(
                identity,
                self.identity,
                NativeProgrammingChannel(exchange, "authored"),
                NativeRuntime2026(action),
            )
        self.assertEqual(caught.exception.code, 0x408)
        statuses = iter((0, 0))
        ticks = iter((0, 3000000000))

        def elapsed_action(row, remaining):
            return (
                next(ticks)
                if row["operation"] == "system_time_to_file_time"
                else action(row, remaining)
            )

        with self.assertRaises(CommonResponseError) as caught:
            suzuki_poll_usb(
                identity,
                self.identity,
                NativeProgrammingChannel(exchange, "authored"),
                NativeRuntime2026(elapsed_action),
            )
        self.assertEqual(caught.exception.code, 0x406)

    def test_first_usb_writer_full_wire_path_and_recovery_state(self):
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeRuntime2026,
            NotificationBool,
        )

        identity = identify_native_module(
            "d48d438117ae5fa043811028636d1ddd3c0368f7e6d09f66ee7b341b073e251e",
            "TCUWCanSuzukiUSBReproUDSFlashWriter.dll",
        )
        request, response = bytes.fromhex("000007e0"), bytes.fromhex("000007e8")
        actions, requests, notified = [], [], []
        notification = NotificationBool()
        notification.set_event_handler(
            notified, lambda _target, value: notified.append(value)
        )

        def action(row, _):
            actions.append(row)
            if row["operation"] == "start_flow_control_filter":
                return 8
            return None

        def exchange(_, payload):
            requests.append(payload)
            if payload[0] == 0x2E:
                return bytes.fromhex("6ecf80")
            if payload[1] == 3:
                return b"\x71" + payload[1:] + b"\x06"
            return b"\x71" + payload[1:] + b"\x01"

        result = first_suzuki_usb_write(
            identity,
            self.identity,
            NativeProgrammingChannel(exchange, request.hex()),
            NativeRuntime2026(action),
            request,
            response,
            notification,
            wait_for_igoffon_value=12,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.progress, 100)
        self.assertFalse(notification)
        self.assertEqual(notified, [])
        notification.assign(True)
        self.assertEqual(notified, [True])
        self.assertEqual(
            requests,
            [
                bytes.fromhex(value)
                for value in (
                    "2ecf8001",
                    "3101da00",
                    "3103da00",
                    "3101d915",
                    "3101da01",
                )
            ],
        )
        self.assertEqual(
            [row["operation"] for row in actions][-3:],
            ["notify_igoffon_wait", "stop_filter", "stop_sync_periodic_message"],
        )
        state = SuzukiUSBResult()

        def fail_result(_, payload):
            return (
                bytes.fromhex("7103da0007") if payload[1] == 3 else exchange(_, payload)
            )

        with self.assertRaises(CommonResponseError):
            first_suzuki_usb_write(
                identity,
                self.identity,
                NativeProgrammingChannel(fail_result, request.hex()),
                NativeRuntime2026(action),
                request,
                response,
                notification,
                wait_for_igoffon_value=12,
                result=state,
            )
        self.assertEqual(
            (state.success, state.progress, state.error_status, state.recovery_needed),
            (False, 0, 1, True),
        )
        self.assertEqual(
            [row["operation"] for row in actions][-2:],
            ["stop_filter", "stop_sync_periodic_message"],
        )

    def test_usb_retries_do_not_consume_host_cancellation_or_deadline(self):
        from scripts.programming_2026_common import NativeRuntime2026, NotificationBool

        identity = identify_native_module(
            "d48d438117ae5fa043811028636d1ddd3c0368f7e6d09f66ee7b341b073e251e",
            "TCUWCanSuzukiUSBReproUDSFlashWriter.dll",
        )
        address = bytes.fromhex("000007e0")
        for stage in ("2ecf8001", "3103da00", "3101da01"):
            for fault in (InterruptedError, TimeoutError):
                with self.subTest(stage=stage, fault=fault.__name__):
                    attempted = []

                    def exchange(
                        _, payload, attempted=attempted, stage=stage, fault=fault
                    ):
                        attempted.append(payload.hex())
                        if payload.hex() == stage:
                            raise fault("authored host boundary")
                        if payload[0] == 0x2E:
                            return bytes.fromhex("6ecf80")
                        return (
                            b"\x71"
                            + payload[1:]
                            + bytes((6 if payload[1] == 3 else 1,))
                        )

                    def action(row, _):
                        return (
                            8
                            if row["operation"] == "start_flow_control_filter"
                            else None
                        )

                    with self.assertRaises(fault):
                        first_suzuki_usb_write(
                            identity,
                            self.identity,
                            NativeProgrammingChannel(exchange, address.hex()),
                            NativeRuntime2026(action),
                            address,
                            bytes.fromhex("000007e8"),
                            NotificationBool(),
                            wait_for_igoffon_value=0,
                        )
                    self.assertEqual(attempted.count(stage), 1)

    def test_identity_forgery_and_wrong_module(self):
        with self.assertRaises(ValueError):
            require_identity(replace(self.identity, engine_sha256="0" * 64))
        wrong = identify_native_module(
            "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
            "TCUWFHIUtils.dll",
        )
        with self.assertRaises(ValueError):
            SuzukiIdentification(
                wrong, NativeProgrammingChannel(lambda *_: b"", "authored")
            )


if __name__ == "__main__":
    unittest.main()


class SuzukiGetterBoundaryTests(unittest.TestCase):
    """Authored providers for the getter's exact native/host catch boundaries."""

    def setUp(self):
        from scripts.programming_2026_common import NativeRuntime2026

        self.runtime_type = NativeRuntime2026
        self.getter = identify_native_module(
            "b63abaebe764c6067ec5013c44c16f3c47cc6ebe6abfd84b0e93d3681c0b6315",
            "TCUWCanSuzukiUDSSoftwareIDGetter.dll",
        )
        self.utility = identify_native_module(
            "58db5e0494645ee4f665c714a0a59afa5e2765ce2f55c8505d31e5db76159283",
            "TCUWCanSuzukiUDSUtils.dll",
        )
        self.request = bytes.fromhex("000007e0")
        self.response = bytes.fromhex("000007e8")
        self.cid = b"H" * 11 + b"_" + b"S" * 16 + b"_0123"

    class _State:
        def __init__(self):
            self.error_kind = 7
            self.primary_error = 44
            self.passthru_error = 55

        def record_native_error(self, kind, primary, passthru=None):
            if kind is not None:
                self.error_kind = kind
            self.primary_error = primary
            if passthru is not None:
                self.passthru_error = passthru

    def _invoke(
        self, *, action_fault=None, exchange_fault=None, state=None, result=None
    ):
        from types import SimpleNamespace

        actions = []
        replies = {
            bytes.fromhex("22f189"): bytes.fromhex("62f1890123"),
            bytes.fromhex("22f188"): b"\x62\xf1\x88" + b"S" * 16,
            bytes.fromhex("22f191"): b"\x62\xf1\x91" + b"H" * 11,
        }

        def action(row, _):
            actions.append(row["operation"])
            if action_fault is not None and row["operation"] == action_fault[0]:
                raise action_fault[1]
            if row["operation"] == "start_flow_control_filter":
                return 11
            return None

        def exchange(_, payload):
            if exchange_fault is not None:
                raise exchange_fault
            return replies[payload]

        result = result or SuzukiUSBResult()
        runtime = self.runtime_type(action)
        context = SimpleNamespace(controller_state=state or self._State())
        value = suzuki_get_identification(
            self.getter,
            self.utility,
            runtime,
            NativeProgrammingChannel(exchange, self.request.hex()),
            self.request,
            self.response,
            baudrate_kbps=500,
            receive_timeout_ms=1234,
            address_context=context,
            result=result,
        )
        return value, result, context.controller_state, actions, runtime

    def test_success_returns_vector_and_sets_separate_saved_bool(self):
        value, result, _, actions, _ = self._invoke()
        self.assertEqual(value, self.cid)
        self.assertTrue(result.success)
        self.assertTrue(result.native_return_reached)
        self.assertEqual(actions[-2:], ["stop_filter", "disconnect"])

    def test_cj_native_body_fault_sets_primary_and_driver_fields(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        _, result, state, _, _ = self._invoke(
            action_fault=("control_io", NativeJ2534Error2026(5))
        )
        self.assertFalse(result.success)
        self.assertEqual((state.primary_error, state.passthru_error), (1, 5))

    def test_cpassthru_native_body_fault_preserves_old_driver_field(self):
        from scripts.j2534_2026 import NativePassThruError2026

        state = self._State()
        _, result, state, _, _ = self._invoke(
            action_fault=("control_io", NativePassThruError2026(9)), state=state
        )
        self.assertFalse(result.success)
        self.assertEqual((state.primary_error, state.passthru_error), (9, 55))

    def test_explicit_native_catchall_preserves_both_old_error_fields(self):
        from scripts.programming_2026_common import NativeException2026

        state = self._State()
        _, result, state, _, _ = self._invoke(
            action_fault=("control_io", NativeException2026("native")), state=state
        )
        self.assertFalse(result.success)
        self.assertEqual((state.primary_error, state.passthru_error), (44, 55))

    def test_host_body_fault_propagates_same_object(self):
        fault = RuntimeError("provider body fault")
        with self.assertRaises(RuntimeError) as raised:
            self._invoke(action_fault=("control_io", fault))
        self.assertIs(raised.exception, fault)

    def test_native_stop_filter_fault_suppresses_without_clearing_saved_bool(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        _, result, _, actions, runtime = self._invoke(
            action_fault=("stop_filter", NativeJ2534Error2026(5))
        )
        self.assertTrue(result.success)
        self.assertEqual(result.suppressed_cleanup_errors, ["NativeJ2534Error2026"])
        self.assertEqual(actions[-1], "disconnect")
        self.assertFalse(runtime.owns_resource("stop_filter", identifier=11))

    def test_host_stop_filter_fault_propagates_same_object(self):
        fault = RuntimeError("provider cleanup fault")
        with self.assertRaises(RuntimeError) as raised:
            self._invoke(action_fault=("stop_filter", fault))
        self.assertIs(raised.exception, fault)

    def test_native_disconnect_fault_propagates_without_return_receipt(self):
        from scripts.j2534_2026 import NativePassThruError2026

        fault = NativePassThruError2026(9)
        result = SuzukiUSBResult()
        with self.assertRaises(NativePassThruError2026) as raised:
            self._invoke(action_fault=("disconnect", fault), result=result)
        self.assertIs(raised.exception, fault)
        self.assertFalse(result.native_return_reached)

    def test_host_disconnect_fault_propagates_same_object_without_receipt(self):
        fault = RuntimeError("disconnect fault")
        result = SuzukiUSBResult()
        with self.assertRaises(RuntimeError) as raised:
            self._invoke(action_fault=("disconnect", fault), result=result)
        self.assertIs(raised.exception, fault)
        self.assertFalse(result.native_return_reached)
