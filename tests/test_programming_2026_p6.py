"""Authored synthetic vectors; no vendor fixture or physical-device execution."""

import unittest
from dataclasses import replace

from scripts.programming_2026_p6 import (
    DCMPRL2026,
    DCMPRLContext,
    dcmprl_key,
    decode_p6_cids,
)


def authored_metadata(metadata: bytes) -> bytes:
    from scripts.calibration_2026 import encode_metadata_string_2026

    rows = []
    for row in metadata.split(b"\n"):
        key, separator, value = row.partition(b"=")
        if separator and key.lower() in (b"nonce", b"serviceauthkey", b"ecuauthkey"):
            carriage = b"\r" if value.endswith(b"\r") else b""
            row = (
                key
                + b"="
                + encode_metadata_string_2026(
                    value.rstrip(b"\r").decode("latin1")
                ).encode("ascii")
                + carriage
            )
        rows.append(row)
    return b"\n".join(rows)


def authored_container(
    metadata: bytes, image: bytes | tuple[bytes, ...] = b"authored image"
):
    import struct
    import zlib

    from scripts.calibration import CalibrationContainer
    from scripts.calibration_2026 import parse_cuw_2026

    def record(header, data):
        return (
            struct.pack(">H", len(header))
            + header
            + struct.pack(">II", len(data), zlib.crc32(data))
            + data
        )

    metadata = authored_metadata(metadata)
    images = (image,) if isinstance(image, bytes) else image
    tail = (
        record(b"attach.att", metadata)
        + bytes((len(images),))
        + b"".join(record(b"authored", item) for item in images)
    )
    raw = b"\0CALIBRATION\0\x09" + bytes(4) + struct.pack(">I", 22 + len(tail)) + tail
    container = parse_cuw_2026(
        raw[:14] + struct.pack(">I", zlib.crc32(raw[18:])) + raw[18:]
    )
    assert isinstance(container, CalibrationContainer)
    return container


class Wire:
    def __init__(self, rows):
        self.rows = list(rows)
        self.request_address = b"\0\0\x01\x02\x03"
        self.response_address = b"\0\0\x04\x05\x06"
        self.events = []
        self.now = 0.0
        self.stop = False
        self.index = 0
        self.fail_at = None
        self.cancel_at = None
        self.pending = []

    def touch(self):
        self.index += 1
        if self.index == self.fail_at:
            raise OSError("authored fault")
        if self.index == self.cancel_at:
            self.stop = True

    def action(self, event, remaining):
        self.events.append(event)
        if event["operation"] not in ("stop_filter", "disconnect") and not (
            event["operation"] == "set_timeout" and event["milliseconds"] == 444
        ):
            self.touch()
        if event["operation"] == "write_messages":
            expected, response = self.rows.pop(0)
            if event["data"] != self.request_address + expected:
                raise AssertionError((expected, event["data"]))
            self.pending.insert(0, response)
            return 1
        if event["operation"] == "read_specified_can_message":
            return self.response_address + self.pending.pop(0)
        if event["operation"] == "wait":
            self.now += event["milliseconds"] / 1000
        if event["operation"] == "get_timeout":
            return 444
        if event["operation"] in ("start_filter", "start_flow_control_filter"):
            return 17
        return None

    def runner(self, **changes):
        context = replace(
            DCMPRLContext(b"\x01\x02\x03", b"\x04\x05\x06", False, False, 200, 1000),
            **changes,
        )
        return DCMPRL2026(
            context,
            self.action,
            clock=lambda: self.now,
            cancelled=lambda: self.stop,
            native_cancelled=lambda: False,
        )


def flash_rows(data):
    result = [(b"\x31\x01\x02\x00", b"\x71\x01\x02\x00")]
    for offset in range(0, len(data), 1024):
        block = data[offset : offset + 1024]
        result.append(
            (
                b"\x34\x00\x33"
                + offset.to_bytes(3, "big")
                + len(block).to_bytes(3, "big"),
                b"\x74\x30\x00\x00\x40",
            )
        )
        for sequence, pos in enumerate(range(0, len(block), 60), 1):
            result.append(
                (
                    bytes((0x36, sequence)) + block[pos : pos + 60],
                    b"\x76" + bytes((sequence,)),
                )
            )
        result.append((b"\x37" + (sum(block) & 65535).to_bytes(2, "big"), b"\x77"))
    return result + [
        (b"\x31\x02\x02\x00\x01", b"\x71\x02\x02\x00\x01"),
        (b"\x11\x01", b"\x51\x01"),
    ]


class DCMTests(unittest.TestCase):
    def test_actual_engine_progress_uses_ordered_index_not_parser_cpu(self):
        from tests.test_cuw_engine_worker import (
            EngineWorker2026Tests,
            calibration,
            make_controller,
        )

        wire = Wire([(b"\x31\x01\x02\x00", b"bad")])
        runner = wire.runner(flash_size=1)
        engine = EngineWorker2026Tests().engine(calibration(cpus=2))
        self.addCleanup(engine.close)
        controller = make_controller(runner.runtime)
        worker = engine.bind_worker(controller)
        # Array-layout unit fixture; it does not claim a complete3ddf0 producer.
        worker._cpu_orders_by_file = ((1, 0),)
        engine.select_target(1, 1, controller=controller)
        state = engine.dh_state
        self.assertEqual((state.global_cpu_index, state.native_cpu_index), (1, 0))
        state.set_native_count(0, 5)
        state.set_native_count(1, 9)
        state.set_native_percentage(0, 10)
        state.set_native_percentage(1, 20)
        runner = DCMPRL2026(runner.context, runtime=runner.runtime, engine_state=state)
        self.assertEqual((runner.state["progress"], runner.state["percent"]), (5, 10))
        from scripts.programming_2026_common import CommonResponseError

        with self.assertRaises(CommonResponseError):
            runner.flash(b"a")
        self.assertEqual(state.transferred_bytes[:2], (0, 9))
        self.assertEqual(state.progress[:2], (0, 20))

    def test_key_byte_wrap_and_validation(self):
        self.assertEqual(dcmprl_key(b"\xff\xff"), b"\x3a\x11")
        for bad in (b"", b"1", b"123", bytearray(b"12")):
            with self.assertRaises(ValueError):
                dcmprl_key(bad)  # pyright: ignore[reportArgumentType]

    def test_getter_both_native_selectors(self):
        for prl, sub, expected in (
            (False, 0x26, "ABCDEFGHIJKLMNOPQRST"),
            (True, 0x27, "ABCDE"),
        ):
            wire = Wire(
                [(bytes((0x21, sub)), bytes((0x61, sub)) + b"ABCDEFGHIJKLMNOPQRSTMORE")]
            )
            runner = wire.runner(prl=prl)
            self.assertEqual(runner.get_version(delay_ms=1000), expected)
            self.assertEqual(
                [e["operation"] for e in wire.events][-2:],
                ["stop_filter", "disconnect"],
            )

    def test_prepare_retry_and_first_attempt(self):
        for retry in (False, True):
            rows = (
                [(b"\x27\x01", b"\x67\x01\x12\x34"), (b"\x27\x02\x6f\x59", b"\x67\x02")]
                if retry
                else []
            )
            wire = Wire(rows + [(b"\x11\x01", b"\x51\x01")])
            self.assertTrue(wire.runner().prepare(retry=retry)["complete"])
            self.assertFalse(wire.rows)
            self.assertEqual(
                wire.events[-2:],
                [
                    {"operation": "stop_filter", "identifier": 17},
                    {"operation": "set_timeout", "milliseconds": 444},
                ],
            )

    def test_native_prepare_failure_retains_retry_required_flag(self):
        wire = Wire([(b"\x11\x01", b"bad")])
        runner = wire.runner()
        with self.assertRaises(ValueError):
            runner.prepare(retry=False)
        self.assertTrue(runner.state["retry_required"])
        self.assertFalse(runner.state["complete"])

    def test_dcm_failure_tail_callback_fault_escapes_before_timeout_or_next_callback(
        self,
    ):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeException2026,
        )

        for field in ("count", "percent"):
            for error in (
                LookupError("authored callback fault"),
                InterruptedError("authored host cancellation"),
                KeyboardInterrupt(),
                NativeTransportError(5),
                CommonResponseError(0x29, b"bad"),
                NativeException2026("authored native cancellation"),
            ):
                wire = Wire([(b"\x31\x01\x02\x00", b"bad")])
                runner = wire.runner(flash_size=1)
                runner.state.update(progress=49, percent=71)
                original = runner.runtime.cleanup_action

                def cleanup(
                    event,
                    remaining,
                    error=error,
                    field=field,
                    wire=wire,
                    original=original,
                ):
                    if event["operation"] == "progress" and event.get("field") == field:
                        wire.events.append(event)
                        raise error
                    return original(event, remaining)

                runner.runtime.cleanup_action = cleanup
                with self.subTest(field=field, error=type(error).__name__):
                    with self.assertRaises(type(error)) as caught:
                        runner.flash(b"a")
                    self.assertIs(caught.exception, error)
                    self.assertFalse(runner.state["complete"])
                    self.assertTrue(runner.state["native_cleanup_escape"])
                    self.assertEqual(wire.events[-1]["field"], field)
                    self.assertEqual(runner.state["progress"], 0)
                    self.assertEqual(
                        runner.state["percent"], 71 if field == "count" else 0
                    )
                    self.assertTrue(
                        runner.runtime.owns_resource("set_timeout", milliseconds=444)
                    )

    def test_native_filter_cleanup_failure_preserves_business_bool_and_timeout_cleanup(
        self,
    ):
        from scripts.programming import NativeTransportError

        for operation in ("prepare", "flash"):
            rows = (
                [(b"\x11\x01", b"\x51\x01")]
                if operation == "prepare"
                else flash_rows(b"a")
            )
            wire = Wire(rows)
            runner = wire.runner(flash_size=1)
            original = runner.runtime.cleanup_action

            def cleanup(event, remaining, original=original):
                if event["operation"] == "stop_filter":
                    raise NativeTransportError(5)
                return original(event, remaining)

            runner.runtime.cleanup_action = cleanup
            result = (
                runner.prepare(retry=False)
                if operation == "prepare"
                else runner.flash(b"a")
            )
            self.assertTrue(result["complete"])
            self.assertEqual(result["cleanup_errors"], [])
            self.assertEqual(
                result["native_suppressed_cleanup_errors"], ["NativeTransportError"]
            )
            self.assertTrue(runner.runtime.owns_resource("stop_filter", identifier=17))
            self.assertEqual(
                wire.events[-1], {"operation": "set_timeout", "milliseconds": 444}
            )

    def test_native_flash_failure_stops_filter_before_progress_reset_and_timeout_restore(
        self,
    ):
        from scripts.programming_2026_common import CommonResponseError

        wire = Wire([(b"\x31\x01\x02\x00", b"bad")])
        runner = wire.runner(flash_size=1)
        with self.assertRaises(CommonResponseError):
            runner.flash(b"a")
        operations = [e["operation"] for e in wire.events]
        count = next(
            i
            for i, e in enumerate(wire.events)
            if e["operation"] == "progress" and e["field"] == "count"
        )
        self.assertLess(operations.index("stop_filter"), count)
        self.assertEqual(
            wire.events[count + 1],
            {"operation": "progress", "field": "percent", "value": 0},
        )
        self.assertEqual(
            wire.events[-1], {"operation": "set_timeout", "milliseconds": 444}
        )

    def test_flash_wire_boundaries_and_denso_timing(self):
        data = bytes(range(256)) * 4 + b"extra"
        for denso in (False, True):
            wire = Wire(flash_rows(data))
            result = wire.runner(denso_dcm=denso, flash_size=len(data)).flash(data)
            self.assertEqual(result["transferred"], len(data))
            self.assertEqual(result["progress"], 2 * len(data))
            self.assertTrue(result["complete"])
            self.assertFalse(wire.rows)

    def test_concrete_notification_assignment_runs_handler_without_external_event(self):
        from scripts.programming_2026_common import NotificationBool

        wire = Wire(flash_rows(b"a"))
        values = []

        def handler(target, value):
            assert isinstance(target, list)
            target.append(value)

        notification = NotificationBool(context=values, handler=handler)
        runner = wire.runner(flash_size=1)
        runner.notification = notification
        self.assertTrue(runner.flash(b"a")["complete"])
        self.assertEqual(values, [True, False])
        self.assertFalse(bool(notification))
        self.assertFalse(
            any(e["operation"] == "programming_notification" for e in wire.events)
        )

    def test_flash_countdown_callback_precedes_filter_and_observes_each_decrement(self):
        wire = Wire(flash_rows(b"a"))
        result = wire.runner(flash_size=1).flash(b"a")
        countdown = [
            (index, event["value"])
            for index, event in enumerate(wire.events)
            if event["operation"] == "progress"
            and event["field"] == "wait_remaining_ms"
        ]
        self.assertEqual([value for _, value in countdown], [1000, 500, 0])
        self.assertLess(
            countdown[0][0],
            next(
                index
                for index, event in enumerate(wire.events)
                if event["operation"] == "start_flow_control_filter"
            ),
        )
        for index, _ in countdown[1:]:
            self.assertEqual(
                wire.events[index - 1], {"operation": "wait", "milliseconds": 500}
            )
        self.assertEqual(result["wait_remaining_ms"], 0)

    def test_receive_only_pending(self):
        wire = Wire([(b"\x21\x26", b"\x7f\x21\x78")])
        wire.pending = [b"\x61\x26READY"]
        self.assertEqual(wire.runner().get_version(), "READY")
        self.assertFalse(wire.rows)

    def test_fault_and_cancellation_at_every_flash_boundary(self):
        data = b"x" * 61
        baseline = Wire(flash_rows(data))
        baseline.runner(flash_size=len(data)).flash(data)
        for boundary in range(1, baseline.index + 1):
            for field, error in (("fail_at", OSError), ("cancel_at", InterruptedError)):
                with self.subTest(boundary=boundary, field=field):
                    wire = Wire(flash_rows(data))
                    setattr(wire, field, boundary)
                    runner = wire.runner(flash_size=len(data))
                    with self.assertRaises(error):
                        runner.flash(data)
                    self.assertFalse(runner.state["complete"])
                    if (
                        any(
                            e["operation"] == "start_flow_control_filter"
                            for e in wire.events
                        )
                        and boundary > 4
                    ):
                        self.assertTrue(
                            any(e["operation"] == "stop_filter" for e in wire.events)
                        )

    def test_fault_cancel_and_malformed_every_prepare_and_getter_stage(self):
        cases = (
            ([(b"\x21\x26", b"\x61\x26VALUE")], lambda r: r.get_version()),
            (
                [
                    (b"\x27\x01", b"\x67\x01\x12\x34"),
                    (b"\x27\x02\x6f\x59", b"\x67\x02"),
                    (b"\x11\x01", b"\x51\x01"),
                ],
                lambda r: r.prepare(retry=True),
            ),
        )
        for rows, run in cases:
            baseline = Wire(rows)
            run(baseline.runner())
            for boundary in range(1, baseline.index + 1):
                for field, error in (
                    ("fail_at", OSError),
                    ("cancel_at", InterruptedError),
                ):
                    wire = Wire(rows)
                    setattr(wire, field, boundary)
                    runner = wire.runner()
                    with (
                        self.subTest(boundary=boundary, field=field),
                        self.assertRaises(error),
                    ):
                        run(runner)
                    self.assertFalse(runner.state["complete"])
            for index in range(len(rows)):
                corrupt = rows.copy()
                corrupt[index] = (rows[index][0], b"bad")
                wire = Wire(corrupt)
                runner = wire.runner()
                with self.assertRaises(ValueError):
                    run(runner)
                self.assertFalse(runner.state["complete"])

    def test_truncated_download_stops_before_transfer(self):
        rows = flash_rows(b"a")
        rows[1] = (rows[1][0], b"\x74\x30")
        wire = Wire(rows)
        runner = wire.runner(flash_size=1)
        with self.assertRaises(ValueError):
            runner.flash(b"a")
        self.assertEqual(runner.state["transferred"], 0)

    def test_metadata_and_countdown_bounds(self):
        wire = Wire([])
        with self.assertRaises(ValueError):
            wire.runner().flash(b"x")
        self.assertFalse(wire.events)
        with self.assertRaises(ValueError):
            Wire([]).runner(wait_after_flashing_ms=1)
        for bad in (-1, True, 1, 120500):
            wire = Wire([])
            with self.assertRaises(ValueError):
                wire.runner().get_version(delay_ms=bad)
            self.assertFalse(wire.events)

    def test_p6_record_decoder_has_native_17_byte_stride(self):
        record = b"CALIBRATION-00001"
        self.assertEqual(len(record), 17)
        response = b"\x62\xf1\x88\x01\x00\x80" + record[:16]
        self.assertEqual(decode_p6_cids(response), ("CALIBRATION-0000",))
        maximum = b"\x62\xf1\x88\xf2\0" + (b"\x80" + b"A" * 16) * 242
        self.assertEqual(len(decode_p6_cids(maximum)), 242)
        for bad in (response[:-1], response + b"x", b"\x62\xf1\x88\0\0"):
            with self.assertRaises(ValueError):
                decode_p6_cids(bad)


class Phase6Tests(unittest.TestCase):
    def test_getter_refreshes_question_and_filters_placeholder(self):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_p6 import Phase6Node, get_phase6_cids

        now = [0.0]
        reads = [
            b"\x62\xf1\x88\x01\0\x80" + b"?".ljust(16, b"\0"),
            b"\x62\xf1\x88\x02\0\x80"
            + b"VALID".ljust(16, b"\0")
            + b"\x80"
            + b"0123456789#".ljust(16, b"\0"),
        ]
        events = []

        def action(event, remaining):
            events.append(event)
            op = event["operation"]
            if op == "get_timeout":
                return 1000
            if op == "start_flow_control_filter":
                return 5
            if op == "write_messages":
                self.assertEqual(event["data"], b"\x18\xda\x12\xe0\x22\xf1\x88")
                return 1
            if op == "wait":
                now[0] += event["milliseconds"] / 1000
            if op == "read_specified_can_message":
                return b"\x18\xda\xe0\x12" + reads.pop(0)

        runtime = NativeRuntime2026(
            action, clock=lambda: now[0], native_cancelled=lambda: False
        )
        result = get_phase6_cids(
            runtime,
            (Phase6Node(b"\x12", 0),),
            receive_timeout_ms=300,
            programming_started_at=0,
            initial_delay_seconds=0,
            unresolved_retry_seconds=2,
        )
        self.assertEqual(
            result,
            ({"target_hex": "12", "cids": ("VALID",), "programming_dtc": False},),
        )
        self.assertFalse(reads)
        self.assertEqual(sum(e["operation"] == "stop_filter" for e in events), 2)
        self.assertEqual(events[-1]["operation"], "disconnect")

    def test_both_retry_exports_reset_selected_native_target(self):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_p6 import process_before_ig_off_on_at_retry

        events = []

        def action(event, remaining):
            events.append(event)
            return 1

        process_before_ig_off_on_at_retry(NativeRuntime2026(action), b"\x42")
        self.assertEqual(
            events,
            [
                {
                    "operation": "write_messages",
                    "protocol": 6,
                    "tx_flags": 256,
                    "data": b"\x18\xda\x42\xe0\x11\x01",
                    "count": 1,
                }
            ],
        )


class Phase6BranchTests(unittest.TestCase):
    def wire(self, rows):
        from scripts.programming_2026_common import NativeRuntime2026

        wire = Wire(rows)
        wire.request_address = b"\x18\xda\x12\xe0"
        wire.response_address = b"\x18\xda\xe0\x12"
        return wire, NativeRuntime2026(
            wire.action,
            clock=lambda: wire.now,
            cancelled=lambda: wire.stop,
            native_cancelled=lambda: False,
        )

    def run_getter(self, runtime, **changes):
        from scripts.programming_2026_p6 import Phase6Node, get_phase6_cids

        return get_phase6_cids(
            runtime,
            (Phase6Node(b"\x12", 0),),
            receive_timeout_ms=300,
            programming_started_at=0,
            initial_delay_seconds=0,
            unresolved_retry_seconds=0,
            **changes,
        )

    def test_dtc_fallback_permits_native_read_failure(self):
        wire, runtime = self.wire(
            [
                (b"\x22\xf1\x88", b"bad"),
                (b"\x19\x17\x01\x12", b"\x59\x17\x12\0\xe3\x04\x51\x01"),
            ]
        )
        result = self.run_getter(runtime, check_dtcs=True)
        self.assertTrue(result[0]["programming_dtc"])
        self.assertEqual(result[0]["cids"], ())
        self.assertFalse(wire.rows)

    def test_native_callback_before_request_skips_pdu_but_no_id_policy_still_fails(
        self,
    ):
        from scripts.programming_2026_common import CommonResponseError

        wire, runtime = self.wire([])
        queries = []

        def native_cancelled():
            queries.append(len(wire.events))
            return True

        runtime.native_cancelled = native_cancelled
        with self.assertRaises(CommonResponseError) as caught:
            self.run_getter(runtime)
        self.assertEqual(caught.exception.code, 3)
        self.assertEqual(len(queries), 1)
        self.assertEqual(
            wire.events[queries[0] - 1]["operation"], "start_flow_control_filter"
        )
        self.assertFalse(any(e["operation"] == "write_messages" for e in wire.events))

    def test_native_callback_in_cid_receive_throws_after_write(self):
        from scripts.programming_2026_common import CommonResponseError

        wire, runtime = self.wire([(b"\x22\xf1\x88", b"unused")])
        queries = iter((False, True))
        runtime.native_cancelled = lambda: next(queries)
        with self.assertRaises(CommonResponseError) as caught:
            self.run_getter(runtime)
        self.assertEqual(caught.exception.code, 9999)
        self.assertFalse(wire.rows)
        self.assertFalse(
            any(e["operation"] == "read_specified_can_message" for e in wire.events)
        )

    def test_native_skip_during_refresh_does_not_retain_previous_question_cid(self):
        from scripts.programming_2026_common import CommonResponseError
        from scripts.programming_2026_p6 import Phase6Node, get_phase6_cids

        response = b"\x62\xf1\x88\x01\0\x80" + b"?".ljust(16, b"\0")
        wire, runtime = self.wire([(b"\x22\xf1\x88", response)])
        queries = iter((False, False, True))
        runtime.native_cancelled = lambda: next(queries)
        with self.assertRaises(CommonResponseError) as caught:
            get_phase6_cids(
                runtime,
                (Phase6Node(b"\x12", 0),),
                receive_timeout_ms=300,
                programming_started_at=0,
                initial_delay_seconds=0,
                unresolved_retry_seconds=10,
            )
        self.assertEqual(caught.exception.code, 3)
        self.assertEqual(
            sum(e["operation"] == "write_messages" for e in wire.events), 1
        )

    def test_native_pre_request_skip_can_be_accepted_by_programming_dtc(self):
        wire, runtime = self.wire(
            [(b"\x19\x17\x01\x12", b"\x59\x17\x12\0\xe3\x04\x51\x01")]
        )
        queries = iter((True, False, False, False))
        runtime.native_cancelled = lambda: next(queries)
        result = self.run_getter(runtime, check_dtcs=True)
        self.assertEqual(result[0]["cids"], ())
        self.assertTrue(result[0]["programming_dtc"])
        self.assertFalse(wire.rows)

    def test_only_native_driver_status9_and16_allow_dtc_fallback(self):
        from scripts.programming import NativeTransportError

        for status in (9, 16, 7):
            wire, runtime = self.wire(
                [
                    (b"\x22\xf1\x88", b"discarded"),
                    (b"\x19\x17\x01\x12", b"\x59\x17\x12\0\xe3\x04\x51\x01"),
                ]
            )
            original = wire.action
            failed = False

            def action(event, remaining, wire=wire, status=status, original=original):
                nonlocal failed
                if event["operation"] == "read_specified_can_message" and not failed:
                    failed = True
                    wire.pending.pop(0)
                    raise NativeTransportError(status)
                return original(event, remaining)

            runtime.action = action
            if status in (9, 16):
                self.assertTrue(
                    self.run_getter(runtime, check_dtcs=True)[0]["programming_dtc"]
                )
                self.assertFalse(wire.rows)
            else:
                with self.assertRaises(NativeTransportError):
                    self.run_getter(runtime, check_dtcs=True)
                self.assertEqual(len(wire.rows), 1)

    def test_native_receive_cancel_can_be_suppressed_by_later_programming_dtc(self):
        wire, runtime = self.wire(
            [
                (b"\x22\xf1\x88", b"discarded"),
                (b"\x19\x17\x01\x12", b"\x59\x17\x12\0\xe3\x04\x51\x01"),
            ]
        )
        original = wire.action

        def action(event, remaining):
            if event["operation"] == "write_messages" and event["data"].endswith(
                b"\x19\x17\x01\x12"
            ):
                wire.pending.clear()
            return original(event, remaining)

        runtime.action = action
        queries = iter((False, True, False, False, False))
        runtime.native_cancelled = lambda: next(queries)
        result = self.run_getter(runtime, check_dtcs=True)
        self.assertTrue(result[0]["programming_dtc"])
        self.assertEqual(result[0]["cids"], ())
        self.assertFalse(wire.rows)

    def test_dtc_wrong_status_does_not_hide_failure(self):
        from scripts.programming_2026_common import CommonResponseError

        wire, runtime = self.wire(
            [
                (b"\x22\xf1\x88", b"bad"),
                (b"\x19\x17\x01\x12", b"\x59\x17\x12\0\xe3\x04\x51\0"),
            ]
        )
        with self.assertRaises(CommonResponseError):
            self.run_getter(runtime, check_dtcs=True)
        self.assertEqual(wire.events[-1]["operation"], "disconnect")

    def test_outer_disconnect_fault_does_not_replace_original_cid_error(self):
        from scripts.programming_2026_common import CommonResponseError

        _, runtime = self.wire([(b"\x22\xf1\x88", b"bad")])
        original = runtime.cleanup_action

        def cleanup(event, remaining):
            if event["operation"] == "disconnect":
                raise OSError("authored disconnect fault")
            return original(event, remaining)

        runtime.cleanup_action = cleanup
        with self.assertRaises(CommonResponseError) as caught:
            self.run_getter(runtime)
        self.assertEqual(caught.exception.code, 3)
        self.assertIn("OSError", caught.exception.__notes__[0])

    def test_getter_fault_and_cancellation_every_boundary(self):
        response = b"\x62\xf1\x88\x01\0\x80" + b"VALID".ljust(16, b"\0")
        rows = [(b"\x22\xf1\x88", response)]
        baseline, runtime = self.wire(rows)
        self.run_getter(runtime)
        for boundary in range(1, baseline.index + 1):
            for field, error in (("fail_at", OSError), ("cancel_at", InterruptedError)):
                wire, runtime = self.wire(rows)
                setattr(wire, field, boundary)
                with (
                    self.subTest(boundary=boundary, field=field),
                    self.assertRaises(error),
                ):
                    self.run_getter(runtime)
                self.assertEqual(wire.events[-1]["operation"], "disconnect")


class DCMMetadataTests(unittest.TestCase):
    def test_native_getter_host_records_retain_identifier_and_unwritten_contact_bytes(
        self,
    ):
        from scripts.programming_2026_p6 import dcmprl_getter_host_records

        original = b"\x78\x56\x34\x12OLD-ID\0X"
        contact = b"previous\0".ljust(33, b"z")
        for percent, prl in ((0, True), (1, True), (0, False)):
            record, updated = dcmprl_getter_host_records(
                original, contact, first_cpu_percent=percent, prl=prl
            )
            self.assertEqual(record, bytes(4) + b"OLD-ID\0X")
            self.assertEqual(
                updated, b"CAN\0" + contact[4:] if percent == 0 and prl else contact
            )
        with self.assertRaises(ValueError):
            dcmprl_getter_host_records(b"", contact, first_cpu_percent=0, prl=True)

    def test_actual_container_binds_image_classifications_and_build(self):
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_p6 import native_dcmprl_plan

        attached = b"[Format]\nVersion=10\n[Vehicle]\nByteNumberOfTransmitting=03\nKindOfECU=8\nNumberOfCalibration=1\n[CPU01]\nCPUType=31\nCPUImageName=main\n"
        container = authored_container(attached)
        module = identify_native_module(
            "3ac9050d5cae2a94a77aff79d61680a58bb80f08a5571ed70b7fe0f1b2d54deb",
            "TCUWCanDCMPRLFlashWriter.dll",
        )
        plan = native_dcmprl_plan(
            container,
            0,
            module,
            request_id=b"\x01\x02\x03",
            response_id=b"\x04\x05\x06",
            parameters={
                "ReceiveTimeoutBeforeGetCID": 300,
                "FlagToHoldSFormatRecords": False,
                "WaitTimeAfterEndOfFlashing": 1000,
            },
        )
        self.assertEqual(plan.image, b"authored image")
        self.assertTrue(plan.context.prl)
        self.assertFalse(plan.context.denso_dcm)
        self.assertNotIn("authored image", repr(plan))
        for bad in (
            replace(module, cuw_build="18"),
            replace(module, sha256="0" * 64),
            replace(module, module_name="TCUWCanCommonFlashWriter.dll"),
        ):
            with self.assertRaises(ValueError):
                native_dcmprl_plan(
                    container,
                    0,
                    bad,
                    request_id=b"\x01\x02\x03",
                    response_id=b"\x04\x05\x06",
                    parameters={},
                )


class DCMArchiveTests(unittest.TestCase):
    def test_actual_srecord_materialization_separates_length_and_flash_size(self):
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_p6 import native_dcmprl_plan

        def srecord(kind, address, data=b""):
            body = bytes((len(data) + 3,)) + address.to_bytes(2, "big") + data
            return (
                b"S"
                + str(kind).encode()
                + (body + bytes((~sum(body) & 255,))).hex().encode()
            )

        image = b"\n".join(
            (srecord(1, 0x1000, b"a"), srecord(1, 0x1004, b"b"), srecord(9, 0))
        )
        metadata = b"[Format]\nVersion=8\n[Vehicle]\nKindOfECU=8\nNumberOfCalibration=1\n[CPU01]\nCPUType=31\nCPUImageName=main\n"
        module = identify_native_module(
            "3ac9050d5cae2a94a77aff79d61680a58bb80f08a5571ed70b7fe0f1b2d54deb",
            "TCUWCanDCMPRLFlashWriter.dll",
        )
        plan = native_dcmprl_plan(
            authored_container(metadata, image),
            0,
            module,
            request_id=b"\x01\x02\x03",
            response_id=b"\x04\x05\x06",
            parameters={
                "ReceiveTimeoutBeforeGetCID": 300,
                "FlagToHoldSFormatRecords": False,
                "WaitTimeAfterEndOfFlashing": 1000,
            },
        )
        self.assertEqual(plan.image, b"a\xff\xff\xffb")
        self.assertEqual(plan.context.flash_size, 2)
        self.assertTrue(plan.context.denso_dcm)
        empty_classification = native_dcmprl_plan(
            authored_container(
                metadata.replace(b"KindOfECU=8\n", b"").replace(b"CPUType=31\n", b""),
                image,
            ),
            0,
            module,
            request_id=b"\x01\x02\x03",
            response_id=b"\x04\x05\x06",
            parameters={
                "ReceiveTimeoutBeforeGetCID": 300,
                "WaitTimeAfterEndOfFlashing": 1000,
                "FlagToHoldSFormatRecords": False,
            },
        )
        self.assertFalse(empty_classification.context.prl)
        self.assertFalse(empty_classification.context.denso_dcm)
        for selected in (None, True, 0):
            parameters = {
                "ReceiveTimeoutBeforeGetCID": 300,
                "WaitTimeAfterEndOfFlashing": 1000,
            }
            if selected is not None:
                parameters["FlagToHoldSFormatRecords"] = selected
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                native_dcmprl_plan(
                    authored_container(metadata, image),
                    0,
                    module,
                    request_id=b"\x01\x02\x03",
                    response_id=b"\x04\x05\x06",
                    parameters=parameters,
                )
        with self.assertRaises(ValueError):
            native_dcmprl_plan(
                authored_container(metadata, b":01100000618E\n:00000001FF"),
                0,
                module,
                request_id=b"\x01\x02\x03",
                response_id=b"\x04\x05\x06",
                parameters={
                    "ReceiveTimeoutBeforeGetCID": 300,
                    "FlagToHoldSFormatRecords": False,
                    "WaitTimeAfterEndOfFlashing": 1000,
                },
            )
        rows = flash_rows(plan.image)
        rows[0] = (b"\x31\x01\x02\x01", b"\x71\x01\x02\x01")
        rows[-2] = (b"\x31\x02\x02\x01\x01", b"\x71\x02\x02\x01\x01")
        wire = Wire(rows)
        runner = DCMPRL2026(plan.context, wire.action, clock=lambda: wire.now)
        self.assertEqual(runner.flash(plan.image)["percent"], 250)


class Phase6PrepareMetadataTests(unittest.TestCase):
    def test_logical_metadata_uses_first_block_pending_and_native_units(self):
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_p6 import native_phase6_prepare_context

        text = (
            "[Format]\nVersion=400\n[Vehicle]\nContactType=Phase6\nNumberOfNode=1\n[Node01]\n"
            "RequiredSpecReproVer=03\nNumberOfLogicalBlock=1\nDiagID=12\n"
            "WakeUpTimeAfterReset=A\nEmissionsRelatedSystem=A\nWaitTimeAfterProgrammingSession=2\n"
            "Protocol=02\nNumberOfGateway=1\n01_GatewayMode=00\nServiceAuthKey="
            + bytes(range(16)).hex()
            + "\n"
            "[LogicalBlock101]\nNewCID=authored\nNumberOfTargets=0\nReproMethod=02\n"
            "Nonce=" + bytes(range(16)).hex() + "\nP4ServerMaxTime=03\n"
            "[ReproData101]\nStartAddress=00001000\nLength=00000004\n"
        ).encode()
        container = authored_container(text, b"data")
        module = identify_native_module(
            "a47f8ddd907901b629cd5baca6148fb705c6b557f7905e4774ab5b15ec5ae47f",
            "TCUWP6CanReprostdPrepareWriter.dll",
        )
        context = native_phase6_prepare_context(container, module, node=1)
        self.assertEqual(
            (
                context.wake_ms,
                context.emissions_delay_ms,
                context.wait_after_programming_ms,
                context.pending_limit,
            ),
            (500, 100, 100, 180),
        )
        self.assertTrue(context.can_fd)
        self.assertEqual(context.gateway_mode, "00")
        self.assertEqual(context.service_auth_key, bytes(range(16)))
        self.assertNotIn(bytes(range(16)).hex(), repr(context))
        self.assertEqual(
            native_phase6_prepare_context(
                authored_container(text.replace(b"P4ServerMaxTime=03\n", b""), b"data"),
                module,
                node=1,
            ).pending_limit,
            180,
        )
        self.assertEqual(
            native_phase6_prepare_context(
                authored_container(
                    text.replace(b"P4ServerMaxTime=03", b"P4ServerMaxTime="), b"data"
                ),
                module,
                node=1,
            ).pending_limit,
            0,
        )


class PreparePhase6Wire:
    def __init__(self):
        target_request = b"\x18\xda\x12\xe0"
        target_response = b"\x18\xda\xe0\x12"
        self.rows = [
            (b"\x18\xda\x1c\xe0\x31\x01\xdb\x05", b"\x18\xda\xe0\x1c\x71\x01\xdb\x05"),
            (
                b"\x18\xda\x1c\xe0\x31\x03\xdb\x05",
                b"\x18\xda\xe0\x1c\x71\x03\xdb\x05\0\0",
            ),
            (b"\x18\xdb\xef\xe0\x10\x83", None),
            (b"\0\0\x07\x77\x10\x83", None),
            (b"\0\0\x07\x7f\xfe\x10\x83", None),
            (b"\x18\xda\x72\xe0\x22\x21\x03", b"\x18\xda\xe0\x72\x62\x21\x03\0\0"),
            (b"\0\0\x07\x77\x85\x82", None),
            (b"\0\0\x07\x7f\xfe\x85\x82", None),
            (b"\x18\xdb\xef\xe0\x28\x83\x01", None),
            (b"\0\0\x07\x77\x28\x81\x01", None),
            (b"\0\0\x07\x7f\xfe\x28\x81\x01", None),
            (b"\0\0\x07\x77\x28\x83\x01", None),
            (b"\0\0\x07\x7f\xfe\x28\x83\x01", None),
            (target_request + b"\x10\x02", target_response + b"\x50\x02\0\0\0\0"),
            (
                target_request + b"\x27\x01",
                target_response + b"\x67\x01" + bytes(range(16)),
            ),
            (target_request + b"\x27\x02" + b"K" * 16, target_response + b"\x67\x02"),
        ]
        self.pending = []
        self.events = []
        self.now = 0.0
        self.index = 0
        self.fail_at = None
        self.cancel_at = None
        self.cancelled = False

    def action(self, event, remaining):
        self.events.append(event)
        cleanup = event["operation"] in (
            "stop_filter",
            "stop_sync_periodic",
            "unlock",
        ) or (event["operation"] == "set_timeout" and event["milliseconds"] == 111)
        if not cleanup:
            self.index += 1
            if self.index == self.fail_at:
                raise OSError("authored failure")
            if self.index == self.cancel_at:
                self.cancelled = True
        operation = event["operation"]
        if operation == "wait":
            self.now += event["milliseconds"] / 1000
        if operation == "get_timeout":
            return 111
        if operation == "get_protocol_id":
            return 6
        if operation == "start_flow_control_filter":
            return len(self.events)
        if operation == "write_messages":
            expected, response = self.rows.pop(0)
            if expected != event["data"]:
                raise AssertionError((expected, event["data"]))
            if response is not None:
                self.pending.append(response)
            return 1
        if operation == "read_specified_can_message":
            return self.pending.pop(0)
        if operation == "decrypt_secret_info":
            return b"D" * 16
        if operation == "calculate_security_key":
            return b"K" * 16

    def run(self, gateway_mode="01", gateway_kind=0):
        from unittest.mock import patch

        from scripts import programming_2026_common as common
        from scripts.programming_2026_common import NativeRuntime2026, SecretInfoClient
        from scripts.programming_2026_p6 import Phase6PrepareContext, prepare_phase6

        runtime = NativeRuntime2026(
            self.action,
            timeout=60,
            clock=lambda: self.now,
            cancelled=lambda: self.cancelled,
            native_cancelled=lambda: False,
        )
        records = ((0, b"authored private crypto input"),) + tuple(
            (i, b"") for i in range(1, 64)
        )
        client = SecretInfoClient(b"authored", records, "authored")
        # Synthetic crypto boundary only; production issuance still requires
        # authenticated native bytes and is independently checked privately.
        with patch.dict(common._SECRET_INFO_CLIENTS, {id(client): client}):
            client.authorize(b"authored")
        context = Phase6PrepareContext(
            b"\x12", 100, 20, 30, 180, True, gateway_mode, bytes(range(16))
        )

        def run():
            with patch.dict(common._SECRET_INFO_CLIENTS, {id(client): client}):
                return prepare_phase6(
                    runtime, context, client, retry=False, gateway_kind=gateway_kind
                )

        return runtime, run


class Phase6PrepareTests(unittest.TestCase):
    def test_native_filter_cleanup_fault_preserves_success_and_periodic_ownership(self):
        from scripts.programming import NativeTransportError

        wire = PreparePhase6Wire()
        runtime, run = wire.run()
        original = runtime.cleanup_action

        def cleanup(event, remaining):
            last_filter = next(
                (
                    entry
                    for entry in reversed(wire.events)
                    if entry["operation"] == "start_flow_control_filter"
                ),
                {},
            )
            if (
                event["operation"] == "stop_filter"
                and last_filter.get("request_address") == b"\x18\xda\x12\xe0"
            ):
                raise NativeTransportError(5)
            return original(event, remaining)

        runtime.cleanup_action = cleanup
        state = run()
        self.assertTrue(state["complete"])
        self.assertTrue(runtime.owns_resource("stop_sync_periodic"))
        self.assertEqual(
            state["native_suppressed_cleanup_errors"], ["NativeTransportError"]
        )

    def test_native_broadcast_periodic_and_security_chronology(self):
        wire = PreparePhase6Wire()
        runtime, run = wire.run()
        result = run()
        self.assertTrue(result["complete"])
        self.assertTrue(result["periodic_owned"])
        self.assertFalse(wire.rows)
        starts = [e for e in wire.events if e["operation"] == "start_sync_periodic"]
        self.assertEqual([e["delay_ms"] for e in starts], [1000, 1000, 1000, 0])
        self.assertEqual(starts[0]["frames"][0], (b"\x18\xdb\xef\xe0\x3e\x80", 256))
        security = [
            e
            for e in wire.events
            if e["operation"] == "write_messages"
            and e["data"].startswith(b"\x18\xda\x12\xe0\x27")
        ]
        self.assertEqual([e["tx_flags"] for e in security], [0x180100, 0x180100])
        self.assertEqual(runtime.close(), [])
        self.assertEqual(wire.events[-1]["operation"], "stop_sync_periodic")

    def test_native_key_failure_35_maps_security_error_3ea(self):
        from scripts.programming_2026_common import CommonResponseError

        for negative, code in ((b"\x7f\x27\x35", 0x3EA), (b"\x7f\x27\x36", 0x11)):
            wire = PreparePhase6Wire()
            wire.rows[-1] = (wire.rows[-1][0], b"\x18\xda\xe0\x12" + negative)
            runtime, run = wire.run()
            with self.assertRaises(CommonResponseError) as caught:
                run()
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(runtime._resources, [])

    def test_failure_and_cancel_every_prepare_boundary(self):
        baseline = PreparePhase6Wire()
        _, run = baseline.run()
        run()
        for boundary in range(1, baseline.index + 1):
            for field, error in (("fail_at", OSError), ("cancel_at", InterruptedError)):
                wire = PreparePhase6Wire()
                setattr(wire, field, boundary)
                runtime, run = wire.run()
                with (
                    self.subTest(boundary=boundary, field=field),
                    self.assertRaises(error),
                ):
                    run()
                self.assertEqual(runtime.close(), [])
                self.assertEqual(runtime._resources, [])


class Phase6GatewayTests(unittest.TestCase):
    def test_cached_native_gateway_byte_is_preserved_and_skips_discovery(self):
        for value in (3, 255):
            wire = PreparePhase6Wire()
            runtime, run = wire.run(gateway_mode="00", gateway_kind=value)
            result = run()
            self.assertTrue(result["complete"])
            self.assertEqual(result["gateway_kind"], value)
            self.assertFalse(wire.rows)
            self.assertEqual(runtime.close(), [])

    def test_gateway_discovery_collation_and_all_four_routine_modes(self):
        import struct
        from pathlib import Path

        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.cuw_online import OnlineKeyController2026
        from scripts.programming_2026_common import ControlCommPhase2026
        from tests.test_calibration_2026 import cpu_text, cuw
        from tests.test_cuw_online import capture, configuration, step

        root = Path("runtime/no-car-21/recovered")
        if not all(
            (root / name).is_file() for name in ("CUW.dll", "TCUWControlCommPhase.dll")
        ):
            self.skipTest("Authenticated static CUW2026 images absent")
        wire = PreparePhase6Wire()
        request, response = b"\0\0\x07\x50\x5f", b"\0\0\x07\x58\x5f"
        wire.rows.insert(2, (request + b"\x3e\0", response + b"\x7e\0"))
        ig = next(
            i
            for i, row in enumerate(wire.rows)
            if row[0] == b"\x18\xda\x72\xe0\x22\x21\x03"
        )
        wire.rows[ig + 1 : ig + 1] = [
            (request + b"\x27\x21", response + b"\x67\x21" + bytes(range(16))),
            (request + b"\x27\x22" + b"G" * 256, response + b"\x67\x22"),
            (request + b"\x31\x01\x10\x11", response + b"\x71\x01\x10\x11"),
            (request + b"\x31\x03\x10\x11", response + b"\x71\x03\x10\x11\x01"),
        ]
        dtc = next(
            i
            for i, row in enumerate(wire.rows)
            if row[0] == b"\0\0\x07\x7f\xfe\x85\x82"
        )
        wire.rows[dtc + 1 : dtc + 1] = [
            (request + b"\x31\x01\x10\x12", response + b"\x71\x01\x10\x12"),
            (request + b"\x31\x03\x10\x12", response + b"\x71\x03\x10\x12\x01"),
        ]
        runtime, run = wire.run(gateway_mode="00")
        engine = CUWEngine2026((root / "CUW.dll").read_bytes())
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(
            cuw(cpu_text() + "NumberOfTargets=1\n01_TargetCalibration=0751\n")
        )
        worker = engine.bind_worker(
            ControlCommPhase2026(
                identity_2026(
                    (root / "TCUWControlCommPhase.dll").read_bytes(),
                    "TCUWControlCommPhase.dll",
                ),
                runtime,
            )
        )
        engine.set_vin(b"JT123456789012345")
        online = OnlineKeyController2026(worker, configuration())
        chronology = capture(
            online,
            bytes(range(16)),
            [step("online.SetReprogrammingKey", (b"47" * 256).hex(), elapsed_ms=25)],
        )
        runtime.bind_p5_online(
            online,
            chronology,
            advance_clock=lambda seconds: setattr(wire, "now", wire.now + seconds),
        )
        result = run()
        self.assertEqual(result["gateway_kind"], 1)
        self.assertTrue(result["complete"])
        self.assertFalse(wire.rows)
        self.assertTrue(chronology.used)
        self.assertEqual(online.modal_history, (1, 0))
        self.assertEqual(runtime.close(), [])


class Phase6FlashHelperTests(unittest.TestCase):
    def channel(self, rows):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_p6 import Phase6FlashChannel

        wire = Wire(rows)
        wire.request_address = b"\x18\xda\x12\xe0"
        wire.response_address = b"\x18\xda\xe0\x12"

        def action(event, remaining):
            result = wire.action(event, remaining)
            return 501 if event["operation"] == "get_send_timeout" else result

        runtime = NativeRuntime2026(
            action,
            timeout=60,
            clock=lambda: wire.now,
            cancelled=lambda: wire.stop,
            native_cancelled=lambda: False,
        )
        return wire, Phase6FlashChannel(
            runtime, b"\x12", pending_limit=180, can_fd=True
        )

    def test_phase6_pending_uses_native_local_seconds_and_midnight_wrap(self):
        from scripts.programming_2026_common import CommonResponseError

        for limit in (2, 3):
            rows = [(b"\x11\x01", b"\x7f\x11\x78")]
            if limit == 2:
                rows.append((b"\x3e\0", b"unused"))
            wire, channel = self.channel(rows)
            wire.pending = [b"\x7f\x11\x78", b"\x51\x01"]
            seconds = iter((86399, 86399, 1))
            channel.runtime.local_seconds_of_day = lambda seconds=seconds: next(seconds)
            if limit == 2:
                with self.assertRaises(CommonResponseError) as caught:
                    channel.call(b"\x11\x01", b"\x51\x01", 2, 0x18, limit)
                self.assertEqual(caught.exception.code, 0x18)
            else:
                self.assertEqual(
                    channel.call(b"\x11\x01", b"\x51\x01", 2, 0x18, limit),
                    b"\x51\x01",
                )
            self.assertFalse(wire.rows)
            writes = [
                e["data"][4:] for e in wire.events if e["operation"] == "write_messages"
            ]
            self.assertEqual(
                writes, [b"\x11\x01", b"\x3e\0"] if limit == 2 else [b"\x11\x01"]
            )

    def test_download_sequence_wrap_and_native_timeout(self):
        data = b"x" * 260
        rows = [(b"\x34\x11\x44\0\0\x10\0\0\0\x01\x04", b"\x74\x10\x03")]
        rows += [
            (bytes((0x36, i & 255)) + b"x", bytes((0x76, i & 255)))
            for i in range(1, 261)
        ]
        rows += [(b"\x37", b"\x77")]
        wire, channel = self.channel(rows)
        self.assertEqual(channel.transfer(0x1000, data, data_format=0x11), 260)
        self.assertEqual(channel.transferred, 260)
        self.assertFalse(wire.rows)
        self.assertEqual(
            [
                e["milliseconds"]
                for e in wire.events
                if e["operation"] == "set_send_timeout"
            ],
            [1161, 501],
        )

    def test_p6_transfer_fault_cancel_and_length_failure_boundaries(self):
        rows = [
            (b"\x34\x01\x44\0\0\0\0\0\0\0\x02", b"\x74\x10\x03"),
            (b"\x36\x01x", b"\x76\x01"),
            (b"\x36\x02y", b"\x76\x02"),
            (b"\x37", b"\x77"),
        ]
        baseline, channel = self.channel(rows)
        channel.transfer(0, b"xy")
        for boundary in range(1, baseline.index + 1):
            for field, error in (("fail_at", OSError), ("cancel_at", InterruptedError)):
                wire, channel = self.channel(rows)
                setattr(wire, field, boundary)
                with (
                    self.subTest(boundary=boundary, field=field),
                    self.assertRaises(error),
                ):
                    channel.transfer(0, b"xy")
                if any(e["operation"] == "set_send_timeout" for e in wire.events):
                    self.assertEqual(
                        [
                            e["milliseconds"]
                            for e in wire.events
                            if e["operation"] == "set_send_timeout"
                        ][-1],
                        501,
                    )
        for malformed in (b"\x74\0\x40", b"\x74\x20\x40", b"\x74\x10\x02"):
            wire, channel = self.channel([(rows[0][0], malformed)])
            with self.assertRaises(ValueError):
                channel.transfer(0, b"xy")
            self.assertEqual(channel.transferred, 0)

    def test_all_native_flash_routine_modes(self):
        signature = b"s" * 64
        rows = [
            (b"\x31\x01\xdd\0\x01\0\x40" + signature, b"\x71\x01\xdd\0\x02\x02\0"),
            (b"\x31\x01\xff\0\x44\0\0\x10\0\0\0\0\x10", b"\x71\x01\xff\0"),
            (b"\x31\x01\xdd\x01\x01\0\x40" + signature, b"\x71\x01\xdd\x01\x02\x02\0"),
            (b"\x31\x01\xdd\x02", b"\x71\x01\xdd\x02\x02\x02"),
        ]
        wire, channel = self.channel(rows)
        channel.routine(0, signature=signature)
        channel.routine(1, address=0x1000, length=16)
        channel.routine(2, signature=signature)
        channel.routine(3)
        self.assertFalse(wire.rows)

    def test_programming_information_dids_tester_padding_and_native_bcd_date(self):
        from datetime import date

        tester, device = bytes(range(16)), bytes(range(16, 32))
        wire, channel = self.channel(
            [
                (b"\x2e\xf1\x20GTS" + tester + b"\0\x20\x26\x10\x20", b"\x6e\xf1\x20"),
                (b"\x2e\xf0\x50" + device, b"\x6e\xf0\x50"),
            ]
        )
        channel.write_programming_information(1, tester, date(2026, 10, 20), device)
        self.assertFalse(wire.rows)
        wire, channel = self.channel([])
        with self.assertRaises(ValueError):
            channel.write_programming_information(0, tester, date(2026, 10, 20), device)
        self.assertFalse(wire.events)

    def test_transfer_ack_mismatch_keeps_acknowledged_byte_count_and_restores(self):
        rows = [
            (b"\x34\x01\x44\0\0\0\0\0\0\0\x02", b"\x74\x10\x03"),
            (b"\x36\x01x", b"\x76\x01"),
            (b"\x36\x02y", b"\x76\x01"),
        ]
        wire, channel = self.channel(rows)
        with self.assertRaises(ValueError):
            channel.transfer(0, b"xy")
        self.assertEqual(channel.transferred, 1)
        self.assertEqual(
            wire.events[-1], {"operation": "set_send_timeout", "milliseconds": 501}
        )


class Phase6MetadataTests(unittest.TestCase):
    def test_imported_nodes_use_actual_hexadecimal_wake_units(self):
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_p6 import Phase6Node, native_phase6_nodes

        text = b"[Format]\nVersion=101\n[Vehicle]\nNumberOfNode=1\n[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\nDiagID=12\nWakeUpTimeAfterReset=A\n[CPU11]\nCPUImageName=main\n"
        container = authored_container(text)
        module = identify_native_module(
            "8a1cea69f3c971fe8b148f062503fcfdc8135bb6a56aa3b16bca238313a0fae5",
            "TCUWP6CanCIDGetter.dll",
        )
        self.assertEqual(
            native_phase6_nodes(container, module), (Phase6Node(b"\x12", 500),)
        )
        bad = authored_container(text.replace(b"DiagID=12", b"DiagID=012"))
        with self.assertRaises(ValueError):
            native_phase6_nodes(bad, module)


class Phase6MainFlashTests(unittest.TestCase):
    def test_prior_actual_notification_is_retained_before_first_assignment(self):
        from datetime import date

        from scripts.programming_2026_common import (
            CommonResponseError,
            NotificationBool,
        )
        from scripts.programming_2026_p6 import flash_phase6

        rows = self.rows()
        rows[0] = (rows[0][0], b"bad")
        _, runtime, _, _ = self.runner(rows)
        state = {}
        notification = NotificationBool(value=True)
        with self.assertRaises(CommonResponseError):
            flash_phase6(
                runtime,
                self.plan(),
                tester_id=b"t",
                system_date=date(2026, 10, 20),
                state=state,
                notification=notification,
            )
        self.assertTrue(bool(notification))
        self.assertEqual(state["error_result"], 2)
        self.assertFalse(state["retry_required"])

    def test_actual_notification_value_changes_before_failing_handler(self):
        from datetime import date

        from scripts.programming_2026_common import (
            CommonResponseError,
            NotificationBool,
        )
        from scripts.programming_2026_p6 import flash_phase6

        values = []

        def handler(target, value):
            target.append(value)
            self.assertTrue(bool(notification))
            raise CommonResponseError(0x99)

        notification = NotificationBool(context=values, handler=handler)
        wire, runtime, _, _ = self.runner()
        state = {}
        with self.assertRaises(CommonResponseError) as caught:
            flash_phase6(
                runtime,
                self.plan(),
                tester_id=b"t",
                system_date=date(2026, 10, 20),
                state=state,
                notification=notification,
            )
        self.assertEqual(caught.exception.code, 0x99)
        self.assertEqual(values, [True])
        self.assertEqual(state["error_result"], 2)
        self.assertFalse(state["retry_required"])
        self.assertFalse(
            any(
                e["operation"] == "notify" and e["field"] == "notification"
                for e in wire.events
            )
        )

    def plan(self, method="00"):
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_p6 import native_phase6_flash_plan

        text = (
            "[Format]\nVersion=400\n[Vehicle]\nContactType=Phase6\nNumberOfNode=1\n"
            "[Node01]\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=1\nDiagID=12\nProtocol=02\nWakeUpTimeAfterReset=02\n"
            "[LogicalBlock101]\nNewCID=authored\nNumberOfTargets=0\nReproMethod="
            + method
            + "\nNonce="
            + bytes(range(16)).hex()
            + "\n"
            "[ReproData101]\nStartAddress=00002000\nLength=00000002\nTransferLength=00000002\nCheckData="
            + (b"v" * 64).hex()
            + "\n"
            "[EraseAndReproRoutine101]\nStartAddress=00001000\nLength=00000001\nTransferLength=00000001\nCheckData="
            + (b"a" * 64).hex()
            + "\n"
            "[EraseMemory101]\nStartAddress=00002000\nLength=00000002\n"
        ).encode()
        if method != "00":
            text += (
                "[DeltaOrCompressionReproData101]\nStartAddress=00002000\nLength=00000007\nTransferLength=00000009\nCheckData="
                + (b"v" * 64).hex()
                + "\n"
            ).encode()
        module = identify_native_module(
            "f5d0182f6461675407b88ac7ff0771ff5660fab07a7f4e525def24d7c4932279",
            "TCUWP6CanReprostdFlashWriter.dll",
        )
        return native_phase6_flash_plan(
            authored_container(
                text, b"xy" if method == "00" else (b"ignored", b"r", b"z")
            ),
            module,
            node=1,
        )

    def rows(self):
        return [
            (b"\x2e\xf1\x20GTSt" + bytes(16) + b"\x20\x26\x10\x20", b"\x6e\xf1\x20"),
            (b"\x2e\xf0\x50" + bytes(range(16)), b"\x6e\xf0\x50"),
            (b"\x34\x01\x44\0\0\x10\0\0\0\0\x01", b"\x74\x10\x04"),
            (b"\x36\x01xy", b"\x76\x01"),
            (b"\x37", b"\x77"),
            (b"\x31\x01\xdd\0\x01\0\x40" + b"a" * 64, b"\x71\x01\xdd\0\x02\x02\0"),
            (b"\x31\x01\xff\0\x44\0\0\x20\0\0\0\0\x02", b"\x71\x01\xff\0"),
            (b"\x34\x01\x44\0\0\x20\0\0\0\0\x02", b"\x74\x10\x04"),
            (b"\x36\x01xy", b"\x76\x01"),
            (b"\x37", b"\x77"),
            (b"\x31\x01\xdd\x01\x01\0\x40" + b"v" * 64, b"\x71\x01\xdd\x01\x02\x02\0"),
            (b"\x31\x01\xdd\x02", b"\x71\x01\xdd\x02\x02\x02"),
            (b"\x11\x01", b"\x51\x01"),
        ]

    def runner(self, rows=None):
        from scripts.programming_2026_common import NativeRuntime2026

        wire = Wire(self.rows() if rows is None else rows)
        wire.request_address = b"\x18\xda\x12\xe0"
        wire.response_address = b"\x18\xda\xe0\x12"
        broadcasts = []
        observations = []

        def action(event, remaining):
            if event["operation"] == "write_messages" and event["data"] in (
                b"\x18\xdb\xef\xe0\x10\x81",
                b"\0\0\x07\x77\x10\x81",
                b"\0\0\x07\x7f\xfe\x10\x81",
            ):
                wire.events.append(event)
                wire.touch()
                broadcasts.append((event["data"], event["tx_flags"]))
                return 1
            result = wire.action(event, remaining)
            if event["operation"] == "notify":
                value = event["value"]
                observations.append(
                    (event["field"], value.copy() if isinstance(value, dict) else value)
                )
            return 501 if event["operation"] == "get_send_timeout" else result

        runtime = NativeRuntime2026(
            action,
            timeout=60,
            clock=lambda: wire.now,
            cancelled=lambda: wire.stop,
            native_cancelled=lambda: False,
        )
        runtime.own("stop_sync_periodic")
        return wire, runtime, broadcasts, observations

    def test_actual_cuw_plan_and_full_native_order(self):
        from datetime import date

        from scripts.programming_2026_p6 import flash_phase6

        plan = self.plan()
        self.assertEqual(plan.blocks[0].pending_limit, 180)
        self.assertEqual(plan.blocks[0].authentication, b"a" * 64)
        self.assertEqual(plan.blocks[0].routine.data, b"xy")
        wire, runtime, broadcasts, observations = self.runner()
        state = flash_phase6(
            runtime, plan, tester_id=b"t", system_date=date(2026, 10, 20)
        )
        self.assertTrue(state["complete"])
        self.assertEqual(state["transferred"], 4)
        self.assertEqual(state["counts"], {0: 4})
        self.assertEqual(state["percentages"], {0: 150})
        self.assertFalse(wire.rows)
        self.assertEqual(
            broadcasts,
            [
                (b"\x18\xdb\xef\xe0\x10\x81", 0x100),
                (b"\0\0\x07\x77\x10\x81", 0),
                (b"\0\0\x07\x7f\xfe\x10\x81", 0x80),
            ],
        )
        self.assertEqual(
            [v for k, v in observations if k == "notification"], [True, False]
        )
        self.assertEqual(wire.events[-1]["operation"], "stop_filter")
        self.assertFalse(runtime.owns_resource("stop_sync_periodic"))

    def test_full_native_fault_and_cancel_at_every_boundary(self):
        from datetime import date

        from scripts.programming_2026_p6 import flash_phase6

        plan = self.plan()
        baseline, runtime, _, _ = self.runner()
        flash_phase6(runtime, plan, tester_id=b"t", system_date=date(2026, 10, 20))
        for boundary in range(1, baseline.index + 1):
            for field, error in (("fail_at", OSError), ("cancel_at", InterruptedError)):
                wire, runtime, _, _ = self.runner()
                setattr(wire, field, boundary)
                state = {}
                with (
                    self.subTest(boundary=boundary, field=field),
                    self.assertRaises(error),
                ):
                    flash_phase6(
                        runtime,
                        plan,
                        tester_id=b"t",
                        system_date=date(2026, 10, 20),
                        state=state,
                    )
                self.assertFalse(state["complete"])
                self.assertEqual(state["counts"], {0: state["transferred"]})
                self.assertNotIn("error_result", state)
                self.assertFalse(runtime.owns_resource("stop_sync_periodic"))
                if not (field == "fail_at" and boundary == 1) and any(
                    e["operation"] == "start_flow_control_filter" for e in wire.events
                ):
                    self.assertTrue(
                        any(e["operation"] == "stop_filter" for e in wire.events)
                    )

    def test_delta_skips_erase_and_compression_uses_exact_data_format(self):
        from datetime import date

        from scripts.programming_2026_p6 import Phase6Transfer, flash_phase6

        original = self.plan()
        for data_format in (0x11, 0x21):
            block = replace(
                original.blocks[0],
                erase=None if data_format == 0x21 else original.blocks[0].erase,
                method_type=2 if data_format == 0x21 else 3,
                contents=(Phase6Transfer(0x2000, 7, 9, b"xy", data_format),),
            )
            plan = replace(original, blocks=(block,))
            rows = self.rows()
            rows[7] = (
                bytes((0x34, data_format, 0x44)) + b"\0\0\x20\0\0\0\0\x07",
                b"\x74\x10\x04",
            )
            if data_format == 0x21:
                rows.pop(6)
            wire, runtime, _, _ = self.runner(rows)
            self.assertTrue(
                flash_phase6(
                    runtime, plan, tester_id=b"t", system_date=date(2026, 10, 20)
                )["complete"]
            )
            self.assertFalse(wire.rows)


class Phase6StreamHelperTests(unittest.TestCase):
    def test_native_srecord_window_status_checksum_address_and_count(self):
        from scripts.programming_2026_common import CommonResponseError
        from scripts.programming_2026_p6 import parse_phase6_srecord_window

        line = b"S1061000616263C3"
        for size in range(len(line)):
            self.assertEqual(parse_phase6_srecord_window(line[:size]).status, 2)
        for suffix in (b"", b"\r", b"\n"):
            record = parse_phase6_srecord_window(line + suffix)
            self.assertEqual(record.status, 1)
            self.assertIsNone(record.address)
            self.assertEqual(record.payload, b"abc")
        for suffix in (b"\r\n", b"\n\r", b"S9030000FC"):
            record = parse_phase6_srecord_window(line + suffix)
            self.assertEqual(record.status, 0)
            self.assertEqual(record.address, 0x1000)
            self.assertEqual(record.payload, b"abc")
        # Native S5 accepts two-, three- and four-byte count encodings in mode1.
        for record, expected in (
            (b"S5031234B6S", 0x1234),
            (b"S5041234565FS", 0x123456),
            (b"S50512345678E6S", 0x12345678),
        ):
            parsed = parse_phase6_srecord_window(record)
            self.assertEqual(parsed.address, expected)
            self.assertEqual(parsed.payload, b"")
        for malformed, code in (
            (b"S1061000616263C2S", 0x3F6),
            (b"S1061000616263CZ", 0x3F7),
            (b"S604000001FA", 0x3F6),
            (b"S904000000FBS", 0x3F6),
        ):
            with self.assertRaises(CommonResponseError) as caught:
                parse_phase6_srecord_window(malformed)
            self.assertEqual(caught.exception.code, code)

    def test_native_binary_windows_inclusive_end_zero_padding_and_overrun(self):
        from scripts.programming_2026_p6 import phase6_binary_stream_blocks

        self.assertEqual(
            tuple(phase6_binary_stream_blocks(b"_abc_", 1, 3, 7, 4)),
            (b"abc\0", bytes(3)),
        )
        self.assertEqual(
            tuple(phase6_binary_stream_blocks(b"abcdef", 0, 5, 6, 4)), (b"abcd", b"ef")
        )
        with self.assertRaises(ValueError):
            tuple(phase6_binary_stream_blocks(b"abcdef", 0, 5, 3, 4))
        data = b"x" * (0x500000 + 9)
        blocks = tuple(
            phase6_binary_stream_blocks(data, 0, len(data) - 1, len(data), 4093)
        )
        self.assertEqual(b"".join(blocks), data)
        self.assertTrue(all(len(block) == 4093 for block in blocks[:-1]))
        for start, end in ((-1, 1), (0, 6), (3, 2)):
            with self.assertRaises(ValueError):
                tuple(phase6_binary_stream_blocks(b"abcdef", start, end, 6, 4))


class Phase6BoundsTests(unittest.TestCase):
    def test_cpu_boundary_without_actual_engine_rejected_before_communication(self):
        from datetime import date

        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_p6 import flash_phase6

        original = Phase6MainFlashTests().plan()
        plan = replace(
            original,
            blocks=original.blocks + (replace(original.blocks[0], cpu_index=1),),
            cpu_flash_sizes=((0, 3), (1, 3)),
        )
        events = []
        with self.assertRaisesRegex(ValueError, "actual active engine worker"):
            flash_phase6(
                NativeRuntime2026(lambda event, remaining: events.append(event)),
                plan,
                tester_id=b"t",
                system_date=date(2026, 10, 20),
            )
        self.assertFalse(events)


class Phase6CleanupRegressionTests(unittest.TestCase):
    def test_native_success_filter_fault_preserves_bool_and_completed_progress(self):
        from datetime import date

        from scripts.programming import NativeTransportError
        from scripts.programming_2026_p6 import flash_phase6

        helper = Phase6MainFlashTests()
        _, runtime, _, _ = helper.runner()
        original = runtime.cleanup_action

        def cleanup(event, remaining):
            if event["operation"] == "stop_filter":
                raise NativeTransportError(5)
            return original(event, remaining)

        runtime.cleanup_action = cleanup
        state = flash_phase6(
            runtime, helper.plan(), tester_id=b"t", system_date=date(2026, 10, 20)
        )
        self.assertTrue(state["complete"])
        self.assertEqual(state["transferred"], 4)
        self.assertEqual(
            state["native_suppressed_cleanup_errors"], ["NativeTransportError"]
        )
        self.assertTrue(runtime.owns_resource("stop_filter", identifier=17))

    def test_owned_periodic_cleanup_once_and_original_error_survives_notify_fault(self):
        from datetime import date

        from scripts.programming_2026_common import CommonResponseError
        from scripts.programming_2026_p6 import flash_phase6

        helper = Phase6MainFlashTests()
        wire, runtime, _, _ = helper.runner()
        action = runtime.action

        def fail(event, remaining):
            if event["operation"] == "write_messages":
                raise CommonResponseError(0x22)
            if event["operation"] == "notify":
                raise RuntimeError("authored cleanup observer failure")
            return action(event, remaining)

        runtime.action = fail
        state = {}
        with self.assertRaises(CommonResponseError) as caught:
            flash_phase6(
                runtime,
                helper.plan(),
                tester_id=b"t",
                system_date=date(2026, 10, 20),
                state=state,
            )
        self.assertEqual(caught.exception.code, 0x22)
        self.assertEqual(
            sum(e["operation"] == "stop_sync_periodic" for e in wire.events), 1
        )
        self.assertEqual(state["cleanup_errors"], ["RuntimeError"])
        self.assertIn("RuntimeError", str(caught.exception.__notes__))
        self.assertFalse(runtime.owns_resource("stop_filter", identifier=17))
        self.assertTrue(state["retry_required"])

    def test_success_filter_cleanup_fault_cannot_leave_complete_true(self):
        from datetime import date

        from scripts.programming_2026_p6 import flash_phase6

        helper = Phase6MainFlashTests()
        wire, runtime, _, _ = helper.runner()
        action = runtime.action
        failed = False

        def fail(event, remaining):
            nonlocal failed
            if event["operation"] == "stop_filter" and not failed:
                failed = True
                raise OSError("authored final filter failure")
            return action(event, remaining)

        runtime.cleanup_action = fail
        state = {}
        with self.assertRaisesRegex(OSError, "final filter"):
            flash_phase6(
                runtime,
                helper.plan(),
                tester_id=b"t",
                system_date=date(2026, 10, 20),
                state=state,
            )
        self.assertFalse(state["complete"])
        self.assertEqual(state["stage"], "filter_cleanup")
        self.assertFalse(runtime.owns_resource("stop_filter", identifier=17))
        self.assertFalse(wire.rows)


class Phase6SRecordStreamTests(unittest.TestCase):
    def test_native_group_selection_record_boundaries_and_zero_counter_restart(self):
        from scripts.programming_2026_p6 import (
            Phase6SRecordStream,
            phase6_srecord_stream_blocks,
        )

        source = b"_S1061000616263C3\r\nS9030000FC\r\n"
        stream = Phase6SRecordStream(source, len(source) - 1, ((0x1000, 1),))
        self.assertEqual(
            tuple(phase6_srecord_stream_blocks(stream, 0x1000, 7, 4)),
            ((1, b"abc\0"), (1, bytes(3))),
        )
        self.assertEqual(
            tuple(phase6_srecord_stream_blocks(stream, 0x1000, 2, 4)), ((1, b"ab"),)
        )
        zero = replace(stream, groups=((0x1000, 0),))
        self.assertEqual(
            tuple(phase6_srecord_stream_blocks(zero, 0x1000, 7, 4)),
            ((1, bytes(4)), (2, bytes(3))),
        )
        with self.assertRaises(ValueError):
            tuple(phase6_srecord_stream_blocks(stream, 0x1001, 7, 4))

    def test_native_srecord_malformed_first_address_and_record_overrun(self):
        from scripts.programming_2026_p6 import (
            Phase6SRecordStream,
            phase6_srecord_stream_blocks,
        )

        for source in (
            b"_S1061000616263C3\r\nS1061000616263C3\r\n",
            b"_S1060FFF616263C5\r\n",
            b"_S1061000616263",
            b"_S1061000616263C2\r\n",
        ):
            stream = Phase6SRecordStream(source, len(source) - 1, ((0x1000, 1),))
            with self.subTest(source=source), self.assertRaises(ValueError):
                tuple(phase6_srecord_stream_blocks(stream, 0x1000, 6, 4))

    def test_native_window_refill_rewinds_only_unconsumed_record(self):
        from scripts.programming_2026_p6 import (
            Phase6SRecordStream,
            phase6_srecord_stream_blocks,
        )

        # Long authored S0 records straddle the native5-MiB read boundary.
        raw = bytes((255, 0, 0)) + b"h" * 252
        header = b"S0" + (raw + bytes((~sum(raw) & 255,))).hex().encode() + b"\r\n"
        source = b"_" + header * 10200 + b"S1061000616263C3\r\nS9030000FC\r\n"
        stream = Phase6SRecordStream(source, len(source) - 1, ((0, 1),))
        self.assertEqual(
            tuple(phase6_srecord_stream_blocks(stream, 0, 3, 4)), ((1, b"abc"),)
        )


class Phase6ArchiveAssociationTests(unittest.TestCase):
    def test_actual_compression_and_delta_cuw_archives_drive_native_wire(self):
        from datetime import date

        from scripts.programming_2026_p6 import flash_phase6

        helper = Phase6MainFlashTests()
        for method, data_format in (("02", 0x11), ("03", 0x21)):
            plan = helper.plan(method)
            self.assertEqual(plan.blocks[0].routine.data, b"r")
            self.assertEqual(plan.blocks[0].contents[0].data, b"z")
            self.assertEqual(plan.blocks[0].contents[0].transfer_length, 9)
            self.assertEqual(plan.cpu_flash_sizes, ((0, 2),))
            rows = helper.rows()
            rows[3] = (b"\x36\x01r", b"\x76\x01")
            rows[7] = (
                bytes((0x34, data_format, 0x44)) + b"\0\0\x20\0\0\0\0\x07",
                b"\x74\x10\x04",
            )
            rows[8] = (b"\x36\x01z", b"\x76\x01")
            if method == "03":
                rows.pop(6)
                self.assertIsNone(plan.blocks[0].erase)
            wire, runtime, _, _ = helper.runner(rows)
            state = flash_phase6(
                runtime, plan, tester_id=b"t", system_date=date(2026, 10, 20)
            )
            self.assertTrue(state["complete"])
            self.assertEqual(state["counts"], {0: 2})
            self.assertEqual(state["percentages"], {0: 100})
            self.assertFalse(wire.rows)


class Phase6LargeIntegrationTests(unittest.TestCase):
    def test_authenticated_300mib_source_to_logical_plan_to_native_wire(self):
        import struct
        import tempfile
        import zlib
        from datetime import date
        from pathlib import Path

        from scripts.cuw_large import CHUNK_SIZE, MIN_SIZE, native_large_cuw_2026
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_p6 import flash_phase6, native_phase6_flash_plan

        metadata = (
            "[Format]\nVersion=500\n[Vehicle]\nProtocol=02\nContactType=Phase6\nNumberOfNode=2\n"
            "[Node01]\nProtocol=02\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=1\nDiagID=12\nWakeUpTimeAfterReset=02\n"
            "[LogicalBlock101]\nNewCID=authored\nReproMethod=00\nNumberOfTargets=0\nNonce="
            + bytes(range(16)).hex()
            + "\nWholeReproFileName=whole.srec\n"
            "[ReproData101]\nStartAddress=00002000\nLength=00000002\nTransferLength=00000001\nCheckData="
            + (b"v" * 64).hex()
            + "\n"
            "[EraseAndReproRoutine101]\nStartAddress=00001000\nLength=00000001\nTransferLength=00000001\nCheckData="
            + (b"a" * 64).hex()
            + "\n"
            "[EraseMemory101]\nStartAddress=00002000\nLength=00000002\n"
            "[Node02]\nProtocol=02\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=1\nDiagID=13\n"
            "[LogicalBlock201]\nNewCID=unused\nReproMethod=00\nNumberOfTargets=0\nNonce=00000000000000000000000000000000\nWholeReproFileName=unused.binx\n"
            "[ReproData201]\nStartAddress=00003000\nLength=00000001\n"
        ).encode()
        metadata = authored_metadata(metadata)
        image = b"S10410007279\r\nS10420007A61\r\nS9030000FC\r\n"

        def record(name, data):
            return (
                struct.pack(">H", len(name))
                + name
                + struct.pack(">II", len(data), zlib.crc32(data))
                + data
            )

        for binary in (False, True):
            if binary:
                metadata = metadata.replace(b"whole.srec", b"whole.binx")
                image = b"xy"
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "authored.cuw"
                prefix = bytearray(
                    b"\0CALIBRATION\0\x0c" + bytes(4) + struct.pack(">I", MIN_SIZE)
                )
                prefix += record(b"INI", metadata) + b"\x02" + record(b"whole", image)
                filler_size = MIN_SIZE - len(prefix) - 10
                zeros, crc = bytes(CHUNK_SIZE), 0
                for offset in range(0, filler_size, CHUNK_SIZE):
                    crc = zlib.crc32(
                        zeros[: min(CHUNK_SIZE, filler_size - offset)], crc
                    )
                prefix += struct.pack(">HII", 0, filler_size, crc)
                with path.open("wb") as target:
                    target.write(prefix)
                    target.truncate(MIN_SIZE)
                crc = 0
                with path.open("rb") as source:
                    source.seek(18)
                    while chunk := source.read(CHUNK_SIZE):
                        crc = zlib.crc32(chunk, crc)
                with path.open("r+b") as target:
                    target.seek(14)
                    target.write(struct.pack(">I", crc))
                with native_large_cuw_2026(path) as container:
                    module = identify_native_module(
                        "f5d0182f6461675407b88ac7ff0771ff5660fab07a7f4e525def24d7c4932279",
                        "TCUWP6CanReprostdFlashWriter.dll",
                    )
                    plan = native_phase6_flash_plan(container, module, node=1)
                    self.assertEqual(plan.blocks[0].routine.native_length, len(image))
                    self.assertEqual(len(plan.blocks[0].routine.data), 0x144)
                    self.assertIsNotNone(plan.blocks[0].routine.backing)
                    helper = Phase6MainFlashTests()
                    rows = helper.rows()
                    if not binary:
                        rows[3] = (b"\x36\x01r", b"\x76\x01")
                        rows[8] = (b"\x36\x01z", b"\x76\x01")
                    wire, runtime, _, _ = helper.runner(rows)
                    state = flash_phase6(
                        runtime, plan, tester_id=b"t", system_date=date(2026, 10, 20)
                    )
                    self.assertTrue(state["complete"])
                    self.assertEqual(state["transferred"], 4 if binary else 2)
                    self.assertEqual(state["counts"], {0: 6 if binary else 3})
                    self.assertEqual(state["percentages"], {0: 300 if binary else 100})
                    self.assertFalse(wire.rows)
                    fault_wire, fault_runtime, _, _ = helper.runner(rows)
                    original_action = fault_runtime.action
                    closed = False

                    def close_at_download(
                        event, remaining, original_action=original_action
                    ):
                        nonlocal closed
                        result = original_action(event, remaining)
                        if (
                            event["operation"] == "write_messages"
                            and event["data"].startswith(b"\x18\xda\x12\xe0\x34")
                            and not closed
                        ):
                            closed = True
                            container.close()
                        return result

                    fault_runtime.action = close_at_download
                    failed_state = {}
                    with self.assertRaises(ValueError):
                        flash_phase6(
                            fault_runtime,
                            plan,
                            tester_id=b"t",
                            system_date=date(2026, 10, 20),
                            state=failed_state,
                        )
                    self.assertFalse(failed_state["complete"])
                    self.assertEqual(failed_state["transferred"], 0)
                    self.assertEqual(failed_state["counts"], {0: 0})
                    self.assertEqual(
                        [
                            event["milliseconds"]
                            for event in fault_wire.events
                            if event["operation"] == "set_send_timeout"
                        ][-1],
                        501,
                    )
                    self.assertEqual(
                        sum(
                            event["operation"] == "stop_sync_periodic"
                            for event in fault_wire.events
                        ),
                        1,
                    )
                wire, runtime, _, _ = Phase6MainFlashTests().runner()
                with self.assertRaises(ValueError):
                    flash_phase6(
                        runtime, plan, tester_id=b"t", system_date=date(2026, 10, 20)
                    )
                self.assertFalse(wire.events)


class Phase6MethodCompatibilityTests(unittest.TestCase):
    def test_actual2026_known_method_types_keep_exact_phase6_format_selection(self):
        from datetime import date

        from scripts.programming_2026_p6 import flash_phase6

        helper = Phase6MainFlashTests()
        for method, method_type in (
            ("01", 1),
            ("05", 1),
            ("07", 2),
            ("08", 2),
            ("09", 3),
            ("0A", 3),
        ):
            plan = helper.plan(method)
            block = plan.blocks[0]
            self.assertEqual(block.method_type, method_type)
            self.assertEqual(block.contents[0].data_format, 1)
            rows = helper.rows()
            rows[3] = (b"\x36\x01r", b"\x76\x01")
            if method_type == 1:
                rows[7] = (rows[7][0], b"\x74\x10\x09")
                rows[8] = (b"\x36\x01ignored", b"\x76\x01")
            else:
                rows[7] = (b"\x34\x01\x44\0\0\x20\0\0\0\0\x07", b"\x74\x10\x04")
                rows[8] = (b"\x36\x01z", b"\x76\x01")
                if method_type == 2:
                    rows.pop(6)
            wire, runtime, _, _ = helper.runner(rows)
            state = flash_phase6(
                runtime, plan, tester_id=b"t", system_date=date(2026, 10, 20)
            )
            self.assertEqual(state["counts"], {0: 8 if method_type == 1 else 0})
            self.assertEqual(
                state["percentages"], {0: 350 if method_type == 1 else 100}
            )
            self.assertFalse(wire.rows)


class Phase6OverflowTests(unittest.TestCase):
    def test_imported_cpu_transfer_sum_cannot_wrap_native_uint32(self):
        original = Phase6MainFlashTests().plan()
        overflow = replace(original.blocks[0].contents[0], transfer_length=0xFFFFFFFF)
        block = replace(original.blocks[0], contents=(overflow,))
        with self.assertRaisesRegex(ValueError, "overflows"):
            replace(original, blocks=(block,))


class DCMNativeCallbackTests(unittest.TestCase):
    def test_native_timeout_or_disconnect_tail_fault_escapes_without_business_return(
        self,
    ):
        from scripts.programming import NativeTransportError

        for operation in ("get_cid", "prepare", "flash"):
            rows = (
                [(b"\x21\x26", b"\x61\x26READY")]
                if operation == "get_cid"
                else [(b"\x11\x01", b"\x51\x01")]
                if operation == "prepare"
                else flash_rows(b"a")
            )
            wire = Wire(rows)
            runner = wire.runner(flash_size=1)
            original = runner.runtime.cleanup_action
            failure = NativeTransportError(5)

            def cleanup(
                event,
                remaining,
                operation=operation,
                original=original,
                failure=failure,
            ):
                if (operation == "get_cid" and event["operation"] == "disconnect") or (
                    operation != "get_cid"
                    and event["operation"] == "set_timeout"
                    and event["milliseconds"] == 444
                ):
                    raise failure
                return original(event, remaining)

            runner.runtime.cleanup_action = cleanup
            with self.assertRaises(NativeTransportError) as caught:
                if operation == "get_cid":
                    runner.get_version()
                elif operation == "prepare":
                    runner.prepare(retry=False)
                else:
                    runner.flash(b"a")
            self.assertIs(caught.exception, failure)
            self.assertTrue(runner.state["native_cleanup_escape"])
            self.assertFalse(runner.state["complete"])

    def test_untyped_cleanup_value_error_keeps_original_host_exception(self):
        wire = Wire([(b"\x11\x01", b"\x51\x01")])
        runner = wire.runner()
        original = runner.runtime.cleanup_action

        def cleanup(event, remaining):
            if event["operation"] == "stop_filter":
                raise ValueError("authored host cleanup error")
            return original(event, remaining)

        runner.runtime.cleanup_action = cleanup
        with self.assertRaisesRegex(ValueError, "host cleanup"):
            runner.prepare(retry=False)
        self.assertFalse(runner.state["complete"])

    def test_host_cancel_during_native_callback_takes_precedence_over_empty_success(
        self,
    ):
        wire = Wire([])
        runner = wire.runner()

        def native_cancelled():
            wire.stop = True
            return True

        runner.runtime.native_cancelled = native_cancelled
        with self.assertRaises(InterruptedError):
            runner.get_version()
        self.assertFalse(runner.state["complete"])
        self.assertEqual(
            [e["operation"] for e in wire.events][-2:], ["stop_filter", "disconnect"]
        )

    def test_native_default_countdown_and_distinct_cancel_return(self):
        from scripts.programming_2026_common import NativeRuntime2026

        for cancel_at in (None, 1):
            wire = Wire([(b"\x21\x26", b"\x61\x26READY")])
            queries = 0

            def native_cancelled(cancel_at=cancel_at):
                nonlocal queries
                queries += 1
                return queries == cancel_at

            runtime = NativeRuntime2026(
                wire.action,
                timeout=60,
                clock=lambda wire=wire: wire.now,
                native_cancelled=native_cancelled,
            )
            client = DCMPRL2026(
                DCMPRLContext(b"\x01\x02\x03", b"\x04\x05\x06", False, False, 200, 0),
                runtime=runtime,
            )
            self.assertEqual(client.get_version(), "READY" if cancel_at is None else "")
            self.assertTrue(client.state["complete"])
            self.assertEqual(
                sum(
                    e["operation"] == "wait" and e["milliseconds"] == 500
                    for e in wire.events
                ),
                14 if cancel_at is None else 1,
            )
            self.assertEqual(queries, 15 if cancel_at is None else 1)
            self.assertEqual(
                client.state.get("native_cancelled", False), cancel_at is not None
            )
            self.assertEqual(bool(wire.rows), cancel_at is not None)

    def test_native_cancel_in_receive_throws_after_pdu_and_still_releases(self):
        from scripts.programming_2026_common import (
            NativeException2026,
            NativeRuntime2026,
        )

        wire = Wire([(b"\x21\x26", b"\x61\x26READY")])
        runtime = NativeRuntime2026(
            wire.action,
            timeout=60,
            clock=lambda: wire.now,
            native_cancelled=lambda: True,
        )
        client = DCMPRL2026(
            DCMPRLContext(b"\x01\x02\x03", b"\x04\x05\x06", False, False, 200, 0),
            runtime=runtime,
        )
        with self.assertRaises(NativeException2026):
            client.get_version(delay_ms=0)
        self.assertFalse(wire.rows)
        self.assertFalse(
            any(
                event["operation"] == "read_specified_can_message"
                for event in wire.events
            )
        )
        self.assertEqual(
            [event["operation"] for event in wire.events][-2:],
            ["stop_filter", "disconnect"],
        )
        self.assertFalse(client.state["complete"])

    def test_prepare_reuses_runtime_and_preserves_callers_connection(self):
        from scripts.programming_2026_common import NativeRuntime2026

        wire = Wire([(b"\x11\x01", b"\x51\x01")])
        runtime = NativeRuntime2026(wire.action, timeout=60, clock=lambda: wire.now)
        runtime.own("disconnect")
        client = DCMPRL2026(
            DCMPRLContext(b"\x01\x02\x03", b"\x04\x05\x06", False, False, 200, 0),
            runtime=runtime,
        )
        self.assertTrue(client.prepare(retry=False)["complete"])
        self.assertIs(client.runtime, runtime)
        self.assertTrue(runtime.owns_resource("disconnect"))
        self.assertFalse(
            any(event["operation"] == "disconnect" for event in wire.events)
        )
        self.assertEqual(runtime.close(), [])


class P6CanonicalBindingTests(unittest.TestCase):
    def test_actual_selected_row_rejects_unknown_module_bytes_and_overrides(self):
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_p6 import bind_native_context

        text = b"[Format]\nVersion=10\n[Vehicle]\nContactType=CAN\nKindOfECU=8\nByteNumberOfTransmitting=03\nNumberOfCalibration=1\n[CPU01]\nCPUImageName=authored\n"
        container = authored_container(text)
        table = b"ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID\r\n8CAN,TCUWCanDCMPRLVersionGetter.dll\r\n"
        selection = bind_native_parameter2026(
            container, {"8CAN.ini": table}, "get_cid", encoded=False
        )
        identity = identify_native_module(
            "3f35bfda7714eb206f1a529c5de395cb817d6a47de5fb38a1afd43629d3713ab",
            "TCUWCanDCMPRLVersionGetter.dll",
        )
        for observations in ({}, {"manual_geometry": 123}):
            with self.subTest(observations=observations), self.assertRaises(ValueError):
                bind_native_context(
                    container,
                    1,
                    (),
                    selection,
                    identity,
                    {"selected_module": b"authored unregistered bytes"},
                    observations,
                )

    def test_unissued_context_rejected_before_primitive_calls(self):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_p6 import P6ExecutionContext, execute_context

        forged = object.__new__(P6ExecutionContext)
        events = []
        with self.assertRaisesRegex(ValueError, "not issued"):
            execute_context(
                forged, NativeRuntime2026(lambda event, remaining: events.append(event))
            )
        self.assertFalse(events)
