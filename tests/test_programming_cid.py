import unittest

from scripts.programming import (
    NativePendingTimeout,
    NativeProgrammingChannel,
    NativeTransportError,
)
from scripts.programming_cid import (
    ChargeBus,
    CIDNode,
    decode_software_ids,
    ethernet_diagnostic_lifecycle,
    get_cids,
    supported_rob,
)

NODE = CIDNode(b"\x07\x00", b"\x07\x08")
SOFTWARE = b"\x62\xf1\x81\x01" + b"EXAMPLE-ID".ljust(16, b"\0")


class Harness:
    def __init__(self, family="unified", fail=None):
        self.family, self.fail = family, fail
        self.events = []
        self.requests = []
        self.n = 0
        self.timeout = 123

    def action(self, event, remaining):
        self.events.append(event)
        self.n += 1
        if self.n == self.fail:
            raise OSError("injected host fault")
        if event["operation"] == "get_timeout":
            return self.timeout
        if event["operation"] == "set_timeout":
            self.timeout = event["milliseconds"]
        if event["operation"] == "write_diagnostic":
            return 1
        if event["operation"] == "control_io":
            return 0
        if event["operation"] == "read_messages":
            return b"\xc0\x00\x02\x01" if event["protocol"] == 0x8205 else b""
        if event["operation"] == "read_tcp_message":
            return b"\x0e\x80\x01\x00\x10" + bytes(4)
        if event["operation"] in ("start_filter", "start_periodic"):
            return self.n

    def exchange(self, ecu, request):
        if self.family == "ethernet":
            self.assert_frame(request)
            request = request[12:]
        self.requests.append((ecu, request))
        if request == b"\x22\xf1\x81":
            response = SOFTWARE
        elif request == b"\x31\x01\x10\x00":
            response = b"\x71\x01\x10\x00\x10" + bytes(31)
        elif request == b"\xab\x01":
            response = b"\xeb\x01\xf0\x21"
        elif request == b"\x22\x01\x28":
            response = b"\x62\x01\x28\x01\x02" + b"SLAVE".ljust(12, b"\0")
        elif request == b"\x22\x01\x05":
            response = b"\x62\x01\x05ASSEMBLY"
        elif request == b"\x22\xf1\x8c":
            response = b"\x62\xf1\x8cSERIAL"
        elif request == b"\x22\x02\x10":
            response = b"\x62\x02\x10\x01\x02"
        elif request == b"\x22\x1f\xff":
            response = b"\x62\x1f\xffSWIN"
        else:
            response = bytes((request[0] + 0x40,)) + request[1:]
        return (
            bytes.fromhex(ecu) + b"\x0e\x80" + response
            if self.family == "ethernet"
            else response
        )

    @staticmethod
    def assert_frame(request):
        assert request[:4] == b"\x02\xfd\x80\x01"
        assert int.from_bytes(request[4:8], "big") == len(request) - 8
        assert request[8:10] == b"\x0e\x80"

    def run(self, nodes=None, **kwargs):
        if nodes is None:
            nodes = (
                (CIDNode(NODE.request_id, NODE.request_id),)
                if self.family == "ethernet"
                else (NODE,)
            )
        return get_cids(
            self.action,
            self.exchange,
            nodes,
            family=self.family,
            mode=kwargs.pop("mode", 2),
            receive_timeout_ms=800,
            **kwargs,
        )


class ModernCIDTests(unittest.TestCase):
    def test_native_output_is_completion_not_compatibility(self):
        for version in (12, 18):
            h = Harness()
            original = h.exchange
            h.exchange = lambda ecu, request, original=original: (
                b"\x71\x01\x10\x00" + bytes(32)
                if request == b"\x31\x01\x10\x00"
                else original(ecu, request)
            )
            result = h.run(version=version, mode=1)
            self.assertIs(result["native_result"], True)
            self.assertFalse(result["compatible"])
        self.assertIs(Harness("ethernet").run()["native_result"], True)

    def test_last_cleanup_callback_cancellation_and_deadline_propagate(self):
        for family in ("unified", "ethernet"):
            for boundary in ("cancel", "deadline"):
                h = Harness(family)
                action = h.action
                now, cancelled = [0.0], [False]

                def last(
                    event,
                    remaining,
                    action=action,
                    now=now,
                    cancelled=cancelled,
                    boundary=boundary,
                ):
                    result = action(event, remaining)
                    if event["operation"] == "disconnect":
                        cancelled[0] = boundary == "cancel"
                        now[0] = 30 if boundary == "deadline" else 0
                    return result

                h.action = last
                error = InterruptedError if boundary == "cancel" else TimeoutError
                with self.assertRaises(error):
                    h.run(
                        clock=lambda now=now: now[0],
                        cancelled=lambda cancelled=cancelled: cancelled[0],
                    )

    def test_native_pending_read_errors_restore_without_resend(self):
        for version in (12, 18):
            h = Harness()
            original = h.exchange
            now = [0.0]
            reads = []

            def exchange(ecu, request, h=h, original=original):
                if request == b"\x22\xf1\x81":
                    h.requests.append((ecu, request))
                    return b"\x7f\x22\x78"
                return original(ecu, request)

            def receive(ecu, reads=reads, now=now):
                reads.append(ecu)
                now[0] += 1
                if len(reads) <= 4:
                    raise NativeTransportError(9 if len(reads) % 2 else 16)
                return SOFTWARE

            h.exchange = exchange
            h.run(
                version=version, mode=1, receive=receive, clock=lambda now=now: now[0]
            )
            self.assertEqual(len(reads), 5)
            self.assertEqual(sum(p == b"\x22\xf1\x81" for _, p in h.requests), 1)
            self.assertIn({"operation": "set_timeout", "milliseconds": 1530}, h.events)
            self.assertEqual(h.timeout, 123)

    def test_native_pending_expiry_writes_once_and_host_boundaries_do_not(self):
        for boundary in ("native", "deadline", "cancel"):
            h = Harness()
            now = [0.0]
            stopped = [False]
            h.exchange = lambda ecu, request: b"\x7f\x22\x78"

            def receive(ecu, now=now, stopped=stopped, boundary=boundary):
                now[0] = 180 if boundary == "native" else 3
                stopped[0] = boundary == "cancel"
                return b"\x7f\x22\x78"

            expected = (
                NativePendingTimeout
                if boundary == "native"
                else (InterruptedError if boundary == "cancel" else TimeoutError)
            )
            with self.subTest(boundary=boundary), self.assertRaises(expected):
                h.run(
                    version=12,
                    mode=2,
                    receive=receive,
                    clock=lambda now=now: now[0],
                    timeout=1000 if boundary == "native" else 2,
                    cancelled=lambda stopped=stopped: stopped[0],
                )
            writes = [e for e in h.events if e["operation"] == "write_diagnostic"]
            self.assertEqual(len(writes), int(boundary == "native"))
            if writes:
                self.assertEqual(writes[0]["payload_hex"], "3e")
            self.assertEqual(h.timeout, 123)
            self.assertEqual(h.events[-1]["operation"], "disconnect")

    def test_pending_expiry_write_fault_preserves_uncertainty_and_timeout(self):
        for accepted in (0, None, OSError("injected write fault")):
            h = Harness()
            now = [0.0]
            action = h.action

            def failing(event, remaining, accepted=accepted, action=action):
                result = action(event, remaining)
                if event["operation"] == "write_diagnostic":
                    if isinstance(accepted, Exception):
                        raise accepted
                    return accepted
                return result

            def receive(ecu, now=now):
                now[0] = 180
                return b"\x7f\x22\x78"

            h.action = failing
            h.exchange = lambda ecu, request: b"\x7f\x22\x78"
            with self.assertRaises(OSError):
                h.run(
                    version=12,
                    receive=receive,
                    timeout=1000,
                    clock=lambda now=now: now[0],
                )
            self.assertEqual(h.timeout, 123)
            self.assertEqual(h.events[-1]["operation"], "disconnect")

    def test_optional_native_pending_expiry_keeps_main_identifiers(self):
        h = Harness()
        original = h.exchange
        now = [0.0]
        optional = {b"\x22\x01\x28", b"\x22\x01\x05", b"\x22\xf1\x8c", b"\x22\x02\x10"}
        h.exchange = lambda ecu, request: (
            b"\x7f\x22\x78" if request in optional else original(ecu, request)
        )

        def receive(ecu):
            now[0] += 180
            return b"\x7f\x22\x78"

        result = h.run(receive=receive, clock=lambda now=now: now[0], timeout=2000)
        self.assertEqual(result["nodes"][0]["software_ids"], ["EXAMPLE-ID"])
        self.assertEqual(sum(e["operation"] == "write_diagnostic" for e in h.events), 4)
        self.assertEqual(h.timeout, 123)

    def test_optional_native_prefix_mismatch_but_not_malformed_payload(self):
        for response in (b"\x63unexpected", b"", bytes(4096)):
            h = Harness()
            original = h.exchange
            h.exchange = lambda ecu, request, response=response, original=original: (
                response if request == b"\x22\x01\x28" else original(ecu, request)
            )
            if response == b"\x63unexpected":
                result = h.run()
                self.assertEqual(result["nodes"][0]["software_ids"], ["EXAMPLE-ID"])
            else:
                with self.assertRaises(ValueError):
                    h.run()
            self.assertEqual(h.timeout, 123)

    def test_all_optional_native_minimum_failures_remain_optional(self):
        responses = {
            b"\x22\x01\x28": b"\x62\x01\x28",
            b"\x22\x01\x05": b"\x62\x01\x05",
            b"\x22\xf1\x8c": b"\x62\xf1\x8c",
            b"\x22\x02\x10": b"\x62\x02\x10",
        }
        for selected_request, response in responses.items():
            h = Harness()
            original = h.exchange
            h.exchange = (
                lambda ecu, request, selected_request=selected_request, response=response, original=original: (
                    response if request == selected_request else original(ecu, request)
                )
            )
            result = h.run()
            self.assertEqual(result["nodes"][0]["software_ids"], ["EXAMPLE-ID"])
            self.assertEqual(h.timeout, 123)

    def test_channel_factory_cannot_drop_native_pending_transport_policy(self):
        h = Harness()
        with self.assertRaises(TypeError):
            h.run(version=12, channel_factory=NativeProgrammingChannel)
        self.assertFalse(h.requests)

    def test_verified_versions_keep_native_wire_paths_separate(self):
        node = CIDNode(b"\x07\x92", b"\x07\x9a", wake_ms=1)
        for version in (12, 18):
            for mode in (1, 2):
                with self.subTest(version=version, mode=mode):
                    h = Harness()
                    result = h.run((node,), version=version, mode=mode)
                    self.assertEqual(result["version"], version)
                    self.assertEqual(result["nodes"][0]["software_ids"], ["EXAMPLE-ID"])
                    if version == 12:
                        self.assertEqual(h.requests, [("0792", b"\x22\xf1\x81")])
                        self.assertFalse(result["compatibility_evaluated"])
                        self.assertIsNone(result["compatible"])
                    else:
                        self.assertGreater(len(h.requests), 1)
        for family, options in (
            ("ethernet", {}),
            ("unified", {"charge_bus": ChargeBus(NODE)}),
        ):
            h = Harness(family)
            with self.assertRaises(ValueError):
                h.run(version=12, **options)
            self.assertFalse(h.events)

    def test_version12_extended_filters_native_timeout_and_each_io_fault(self):
        node = CIDNode(b"\x07\x00\x01", b"\x07\x08\x01", True)
        for mode in (1, 2):
            baseline = Harness()
            baseline.run((node,), version=12, mode=mode)
            for index in range(1, len(baseline.events) + 1):
                h = Harness(fail=index)
                with self.subTest(mode=mode, index=index), self.assertRaises(OSError):
                    h.run((node,), version=12, mode=mode)
                if index > 1:
                    self.assertEqual(h.events[-1]["operation"], "disconnect")
            for error in (NativeTransportError(9), OSError("wire")):
                h = Harness()
                h.exchange = lambda ecu, request, error=error: (_ for _ in ()).throw(
                    error
                )
                if isinstance(error, NativeTransportError):
                    self.assertTrue(
                        h.run(
                            (node,),
                            version=12,
                            mode=mode,
                            timeout_allowing_id=node.request_id,
                        )["nodes"][0]["timed_out"]
                    )
                else:
                    with self.assertRaises(OSError):
                        h.run((node,), version=12, mode=mode)
                self.assertEqual(h.events[-1]["operation"], "disconnect")

    def test_both_families_modes(self):
        for family in ("unified", "ethernet"):
            for mode in (1, 2):
                with self.subTest(family=family, mode=mode):
                    h = Harness(family)
                    result = h.run(mode=mode)
                    self.assertEqual(result["nodes"][0]["software_ids"], ["EXAMPLE-ID"])
                    if mode == 1:
                        self.assertTrue(result["compatible"])
                    else:
                        self.assertEqual(
                            result["nodes"][0]["slave_cid"],
                            [{"node": 2, "cid": "SLAVE"}],
                        )
                        self.assertEqual(result["nodes"][0]["assembly_p5"], "ASSEMBLY")
                    self.assertEqual(h.events[-1]["operation"], "disconnect")
                    self.assertIn(
                        {"operation": "set_timeout", "milliseconds": 123}, h.events
                    )

    def test_charge_extended_and_swin(self):
        h = Harness()
        result = h.run(
            (CIDNode(b"\x07\x00\x01", b"\x07\x08\x01", True, 10),),
            charge_bus=ChargeBus(NODE, 30),
        )
        self.assertEqual(result["nodes"][0]["assembly_p5"], "ASSEMBLY")
        requests = [request for _, request in h.requests]
        self.assertIn(b"\x31\x01\x11\x7e", requests)
        self.assertEqual(requests[-2:], [b"\x31\x02\x11\x7e", b"\x10\x01"])
        self.assertIn({"operation": "set_bs_to_ecu", "enabled": False}, h.events)
        self.assertEqual(
            sum(e["operation"] == "start_filter" for e in h.events),
            sum(e["operation"] == "stop_filter" for e in h.events),
        )

    def test_fcm_swin_and_native_optional_failure(self):
        h = Harness()
        exchange = h.exchange

        def failing_optional(ecu, request):
            if request == b"\x22\x01\x05":
                raise NativeTransportError(99)
            return exchange(ecu, request)

        h.exchange = failing_optional
        result = h.run((CIDNode(b"\x07\x92", b"\x07\x9a"),))
        entry = result["nodes"][0]
        self.assertEqual(entry["swin"], "SWIN")
        self.assertEqual(entry["assembly_p5"], "")
        self.assertEqual(entry["optional_errors"]["assembly_p5"]["code"], 99)

    def test_all_identity_helpers_preserve_native_optional_errors(self):
        for family in ("unified", "ethernet"):
            for request, field in (
                (b"\x22\x01\x28", "slave_cid"),
                (b"\x22\x02\x10", "cbest"),
                (b"\x22\xf1\x8c", "serial"),
            ):
                h = Harness(family)
                exchange = h.exchange

                def failing(
                    ecu,
                    request,
                    failed_request=request,
                    exchange=exchange,
                    family=family,
                ):
                    if (
                        request[12:] if family == "ethernet" else request
                    ) == failed_request:
                        raise NativeTransportError(99)
                    return exchange(ecu, request)

                h.exchange = failing
                entry = h.run()["nodes"][0]
                self.assertEqual(entry[field], [] if field == "slave_cid" else "")
                self.assertEqual(entry["optional_errors"][field]["code"], 99)

    def test_ethernet_ads_swin(self):
        h = Harness("ethernet")
        result = h.run((CIDNode(b"\x01\x00", b"\x01\x00"),))
        self.assertEqual(result["nodes"][0]["swin"], "SWIN")
        self.assertLess(
            [e["operation"] for e in h.events].index("logical_disconnect"),
            [e["operation"] for e in h.events].index("disconnect"),
        )

    def test_every_successful_io_can_fault_and_cleanup_attempts_continue(self):
        base = Harness()
        base.run(charge_bus=ChargeBus(NODE, 1))
        for index in range(1, len(base.events) + 1):
            h = Harness(fail=index)
            with self.subTest(index=index), self.assertRaises(OSError):
                h.run(charge_bus=ChargeBus(NODE, 1))
            if index > 1:
                self.assertEqual(h.events[-1]["operation"], "disconnect")

    def test_ethernet_lifecycle_every_io_failure(self):
        baseline = Harness("ethernet")
        baseline.run()
        for index in range(1, len(baseline.events) + 1):
            h = Harness("ethernet", fail=index)
            with self.subTest(index=index), self.assertRaises(OSError):
                h.run()
            if index > 1:
                self.assertEqual(h.events[-1]["operation"], "disconnect")
        queues = [e for e in baseline.events if e["operation"] == "queue_messages"]
        self.assertEqual(queues[0]["payload_hex"], "ffffffff3458ff00000100000000")
        self.assertEqual(queues[1]["payload_hex"], "02fd0005000000070e800000000000")
        self.assertEqual(
            [
                e["protocol"]
                for e in baseline.events
                if e["operation"] == "logical_disconnect"
            ],
            [0x8206, 0x8205, 0x8203],
        )

    def test_each_wire_io_failure_restores_resources(self):
        base = Harness()
        base.run(charge_bus=ChargeBus(NODE))
        for index in range(len(base.requests)):
            h = Harness()
            exchange = h.exchange
            calls = 0

            def fault(ecu, request, index=index, exchange=exchange):
                nonlocal calls
                calls += 1
                if calls == index + 1:
                    raise OSError("wire fault")
                return exchange(ecu, request)

            h.exchange = fault
            with self.subTest(index=index), self.assertRaises(OSError):
                h.run(charge_bus=ChargeBus(NODE))
            self.assertEqual(h.events[-1]["operation"], "disconnect")
            self.assertIn({"operation": "set_timeout", "milliseconds": 123}, h.events)

    def test_only_native_9_16_allowed_on_exact_id(self):
        for code in (9, 16, 99):
            h = Harness()

            def fault(ecu, request, code=code):
                raise NativeTransportError(code)

            h.exchange = fault
            if code in (9, 16):
                self.assertTrue(
                    h.run(timeout_allowing_id=NODE.request_id)["nodes"][0]["timed_out"]
                )
            else:
                with self.assertRaises(NativeTransportError):
                    h.run(timeout_allowing_id=NODE.request_id)
        h = Harness()
        h.exchange = lambda ecu, request: (_ for _ in ()).throw(TimeoutError())
        with self.assertRaises(TimeoutError):
            h.run(timeout_allowing_id=NODE.request_id)

    def test_pending_is_receive_only(self):
        h = Harness()
        exchange = h.exchange
        h.exchange = lambda ecu, request: (
            b"\x7f\x22\x78" if request == b"\x22\xf1\x81" else exchange(ecu, request)
        )
        result = h.run(receive=lambda ecu: SOFTWARE)
        self.assertEqual(result["nodes"][0]["software_ids"], ["EXAMPLE-ID"])
        self.assertNotIn(b"\x22\xf1\x81", [request for _, request in h.requests])

    def test_strict_decode_and_inputs(self):
        for bad in (
            b"",
            SOFTWARE[:-1],
            SOFTWARE + b"X",
            b"\x62\xf1\x81\0",
            b"\x62\xf1\x80" + SOFTWARE[3:],
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                decode_software_ids(bad)
        with self.assertRaises(ValueError):
            supported_rob(b"\x71\x01\x10\x00")
        with self.assertRaises(ValueError):
            CIDNode(b"a", b"b")
        h = Harness()
        with self.assertRaises(ValueError):
            h.run(mode=True)
        self.assertFalse(h.events)

    def test_ethernet_bad_routing_and_late_setup_cleanup(self):
        for response in (None, b"", b"123456789", bytes(10)):
            h = Harness("ethernet")
            action = h.action

            def bad_route(event, remaining, response=response, action=action):
                value = action(event, remaining)
                return response if event["operation"] == "read_tcp_message" else value

            h.action = bad_route
            with self.subTest(response=response), self.assertRaises(ValueError):
                h.run()
            self.assertEqual(
                [
                    e["protocol"]
                    for e in h.events
                    if e["operation"] == "logical_disconnect"
                ],
                [0x8206, 0x8205, 0x8203],
            )
        h = Harness("ethernet")
        now = [0.0]
        action = h.action
        cleanup_times = []

        def late_connect(event, remaining):
            value = action(event, remaining)
            if event["operation"] == "logical_connect":
                now[0] = 31.0
            if event["operation"] in ("logical_disconnect", "disconnect"):
                cleanup_times.append(remaining)
            return value

        h.action = late_connect
        with self.assertRaises(TimeoutError):
            h.run(clock=lambda now=now: now[0])
        self.assertEqual(h.events[-1]["operation"], "disconnect")
        self.assertTrue(all(value > 0 for value in cleanup_times))

    def test_cancel_during_routing_does_not_yield_active_session(self):
        h = Harness("ethernet")
        cancel = [False]
        action = h.action

        def cancel_routing(event, remaining):
            value = action(event, remaining)
            if event["operation"] == "read_tcp_message":
                cancel[0] = True
            return value

        with (
            self.assertRaises(InterruptedError),
            ethernet_diagnostic_lifecycle(
                cancel_routing, 30, clock=lambda: 0, cancelled=lambda: cancel[0]
            ),
        ):
            self.fail("Cancelled routing must not yield an active session")
        self.assertEqual(
            [e["protocol"] for e in h.events if e["operation"] == "logical_disconnect"],
            [0x8206, 0x8205, 0x8203],
        )

    def test_short_unified_support_bitmap_and_strict_ethernet_minimum(self):
        for family in ("unified", "ethernet"):
            h = Harness(family)
            exchange = h.exchange

            def short(ecu, request, exchange=exchange, family=family):
                if (
                    request[12:] if family == "ethernet" else request
                ) == b"\x31\x01\x10\x00":
                    payload = b"\x71\x01\x10\x00\x10\x00\x00"
                    return (
                        bytes.fromhex(ecu) + b"\x0e\x80" + payload
                        if family == "ethernet"
                        else payload
                    )
                return exchange(ecu, request)

            h.exchange = short
            if family == "unified":
                self.assertTrue(h.run(mode=1)["compatible"])
            else:
                with self.assertRaises(ValueError):
                    h.run(mode=1)

    def test_compatibility_fastpath_and_full_rob_flags(self):
        response = b"\x71\x01\x10\x00\x18\x00\x18" + bytes(29)
        self.assertEqual(supported_rob(response), (1, 0x11, 0x21, 0x31))
        h = Harness()
        exchange = h.exchange
        h.exchange = lambda ecu, request: (
            b"\x62\xf1\x81\x01" + b"!EXAMPLE".ljust(16, b"\0")
            if request == b"\x22\xf1\x81"
            else exchange(ecu, request)
        )
        self.assertTrue(h.run(mode=1)["compatible"])
        self.assertFalse(h.requests)

    def test_no_placeholder_resource_and_cancel_cleanup(self):
        h = Harness()
        action = h.action

        def missing(event, remaining):
            value = action(event, remaining)
            return None if event["operation"] == "start_filter" else value

        h.action = missing
        with self.assertRaises(ValueError):
            h.run()
        self.assertEqual(h.events[-1]["operation"], "disconnect")
        h = Harness()
        with self.assertRaises(InterruptedError):
            h.run(cancelled=lambda: len(h.requests) > 0)
        self.assertEqual(h.events[-1]["operation"], "disconnect")


if __name__ == "__main__":
    unittest.main()
