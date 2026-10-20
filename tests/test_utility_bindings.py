"""Authored native callback vectors, with no device or proprietary fixture."""

import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path

from scripts.demo import _ddb, create_demo
from scripts.profiles import VehicleCatalog
from scripts.script_vm import UtilityResource
from scripts.toyota import CommandFrame
from scripts.toyota_session import (
    Cancelled,
    CommandSpec,
    Limits,
    NativeStatus,
    SessionError,
    ToyotaSession,
)
from scripts.utility import UtilityRuntime
from scripts.utility_bindings import SupportCache, SupportRecord, UtilityBindings


def bindings(
    exchange: Callable[[str, bytes], bytes] = lambda ecu, request: b"abcdef",
    **kwargs,
) -> UtilityBindings:
    keys = (
        "initialize_0",
        "initialize_1",
        "finalize",
        "mode_1",
        "mode_3",
        "start_extended_0",
        "start_extended_1",
        "end_extended_0",
        "end_extended_1",
        "thread_0",
        "thread_1",
        "thread_2",
        "thread_3",
    )
    commands = {
        name: CommandSpec(CommandFrame(bytes((index + 1, 3, 17, 6))), check="raw")
        for index, name in enumerate(keys)
    }
    return UtilityBindings(
        ToyotaSession(exchange, "authored-ecu", commands, limits=Limits(seconds=1)),
        operations={name: name for name in keys},
        ecu_id=123,
        protocol=0x108,
        wait=lambda seconds: None,
        **kwargs,
    )


def cache(*, support: bytes = bytes((0, 4, 1, 0, 6, 3))) -> SupportCache:
    offsets = (0,) + (0x1020,) * 255
    return SupportCache(
        {(4, 23, 8, 42): SupportRecord(offsets, support, b"abcdef")},
        selected=(8, 23, 42),
    )


class BindingTests(unittest.TestCase):
    def call(self, host: UtilityBindings, name: str, *args: str) -> tuple[int, dict]:
        values = {"INT01": 1, "INT02": 0, "INT03": 0, "BYTE01": b"\0"}
        return host(name, args, values), values

    def test_metadata_lowbyte_progress_consumption_and_literal_temporary(self):
        host = bindings()
        self.assertEqual(
            self.call(host, "GetEcuId", "INT01"),
            (0, {"INT01": 123, "INT02": 0, "INT03": 0, "BYTE01": b"\0"}),
        )
        status, values = self.call(host, "GetComProtocol", "INT01")
        self.assertEqual((status, values["INT01"]), (0, 8))
        self.assertEqual(host("GetEcuId", ("0",), {}), 0)
        host.press_progress()
        self.assertEqual(self.call(host, "GetProgButton")[0], 1)
        self.assertEqual(self.call(host, "GetProgButton")[0], 0)

    def test_settings_are_forwarded_without_transport_or_success_stubs(self):
        settings: list[tuple[str, int]] = []
        host = bindings(configure=lambda name, value: settings.append((name, value)))
        for name in (
            "SetNrLimitTime",
            "SetResponseNoCheck",
            "SetUseReqMode30_3BFuncFlag",
        ):
            self.assertEqual(self.call(host, name, "42")[0], 0)
        self.assertEqual(
            settings,
            [
                ("SetNrLimitTime", 42),
                ("SetResponseNoCheck", 0),
                ("SetUseReqMode30_3BFuncFlag", 1),
            ],
        )
        with self.assertRaises(SessionError):
            self.call(bindings(), "SetNrLimitTime", "100")

    def test_selected_mode_and_extended_operations(self):
        calls: list[bytes] = []
        host = bindings(lambda ecu, request: calls.append(request) or b"abcdef")
        for name, arg in (
            ("ChangeSessionMode", "1"),
            ("ChangeSessionMode", "259"),
            ("StartExtendedSessionP5", "0"),
            ("EndExtendedSessionP5", "2"),
        ):
            self.assertEqual(self.call(host, name, arg)[0], 0)
        assert host.session is not None
        self.assertEqual(
            calls,
            [
                host.session.commands[key].frame.request
                for key in ("mode_1", "mode_3", "start_extended_0", "end_extended_1")
            ],
        )
        self.assertEqual(self.call(host, "ChangeSessionMode", "2")[0], 99)
        self.assertEqual(
            self.call(
                bindings(lambda ecu, request: b"short"), "ChangeSessionMode", "1"
            )[0],
            3,
        )

    def test_native_status_and_inout_results_are_distinct(self):
        def failed(ecu: str, request: bytes) -> bytes:
            raise NativeStatus(0x90020323)

        host = bindings(failed)
        for name in ("InitialCom", "FinalCom"):
            result, values = self.call(host, name, "INT01")
            self.assertEqual((result, values["INT01"]), (0, 0x90020323))
        self.assertEqual(self.call(host, "StartExtendedSessionP5", "1")[0], 0x90020323)
        self.assertEqual(self.call(host, "ChangeSessionMode", "3")[0], 0x90020323)

    def test_missing_descriptors_providers_and_unknown_callbacks_fail(self):
        host = UtilityBindings(None)
        for name, args in (
            ("InitialCom", ("1",)),
            ("FinalCom", ("1",)),
            ("GetEcuId", ("INT01",)),
            ("GetComProtocol", ("INT01",)),
            ("SleepThread", ("1",)),
            ("StartComThread", ("0",)),
            ("StopComThread", ("0",)),
            ("Unknown", ()),
        ):
            with self.subTest(name=name), self.assertRaises(SessionError):
                host(name, args, {"INT01": 0})
        self.assertEqual(host("StartExtendedSessionP5", ("1",), {}), 99)
        host = bindings()
        host.operations.pop("mode_1")
        with self.assertRaises(SessionError):
            self.call(host, "ChangeSessionMode", "1")

    def test_arity_types_uint32_and_outputs_are_validated_before_io(self):
        calls = []
        host = bindings(lambda ecu, request: calls.append(request) or b"abcdef")
        for name in (
            "ChangeSessionMode",
            "SetNrLimitTime",
            "InitialCom",
            "GetEcuId",
            "GetComProtocol",
            "SleepThread",
            "StartExtendedSessionP5",
            "EndExtendedSessionP5",
            "StartComThread",
            "StopComThread",
        ):
            for args in ((), ("BYTE01",), ("4294967296",), ("unselected",), ("1", "2")):
                with self.subTest(name=name, args=args):
                    self.assertEqual(
                        host(name, args, {"BYTE01": b"a"}),
                        -1 if name in {"GetEcuId", "GetComProtocol"} else 99,
                    )
        self.assertEqual(
            host("GetThreadRecvData", ("1", "BYTE01"), {"BYTE01": b"x"}), 99
        )
        self.assertEqual(host("StartComThread", ("4",), {}), 99)
        self.assertEqual(host("GetThreadStatus", ("1",), {}), 99)
        self.assertEqual(calls, [])

    def test_support_bit_contract_all_arities_contexts_and_masks(self):
        host = bindings(support=cache())
        for extras in ((), ("0",), ("8", "23"), ("8", "23", "42")):
            result, values = self.call(
                host, "ChkA8SptInfoForBitWrap", "0", "5", "2", "4", *extras, "INT02"
            )
            self.assertEqual(
                (result, values["INT02"]), (0, 0 if len(extras) in (0, 1, 3) else 83)
            )
        for inputs, expected in (
            (("0", "5", "1", "4"), 22),
            (("1", "5", "2", "4"), 22),
            (("0", "0", "2", "4"), 22),
            (("0", "5", "2", "3"), 84),
            (("0", "5", "2", "4", "0", "23"), 83),
        ):
            result, values = self.call(host, "ChkA8SptInfoForBitWrap", *inputs, "INT02")
            self.assertEqual((result, values["INT02"]), (0, expected))
        host.support = cache(support=b"\0\4")
        result, values = self.call(
            host, "ChkA8SptInfoForBitWrap", "0", "5", "2", "4", "INT02"
        )
        self.assertEqual((result, values["INT02"]), (0, 99))

    def test_support_receive_lookup_two_mutations_and_reply_bounds(self):
        host = bindings(support=cache())
        for extras in ((), ("0",), ("8", "23"), ("8", "23", "42")):
            result, values = self.call(
                host,
                "GetSptTableDataPosRecvData",
                "0",
                "3",
                "4",
                *extras,
                "INT02",
                "INT03",
            )
            self.assertEqual(
                (result, values["INT02"], values["INT03"]),
                (0, 0, 0) if len(extras) == 2 else (0, 1, 100),
            )
        with self.assertRaises(SessionError):
            self.call(
                host, "GetSptTableDataPosRecvData", "0", "6", "4", "INT02", "INT03"
            )
        with self.assertRaises(SessionError):
            self.call(bindings(), "ChkA8SptInfoForBitWrap", "0", "5", "2", "4", "INT02")

    def test_sleep_is_bounded_and_cancellable(self):
        host = bindings()
        durations: list[float] = []
        host.wait = durations.append
        self.assertEqual(self.call(host, "SleepThread", "125")[0], 0)
        self.assertAlmostEqual(sum(durations), 0.125)
        assert host.session is not None
        host.session.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            self.call(host, "SleepThread", "1")
        host.session.cancelled = lambda: False
        ticks = iter((0.0, 2.0))
        host.session.clock = lambda: next(ticks)
        with self.assertRaisesRegex(SessionError, "deadline"):
            self.call(host, "SleepThread", "1")

    def test_all_polling_workers_repeat_and_keep_terminal_full_reply(self):
        for index in range(3):
            requests: list[bytes] = []

            def exchange(ecu: str, request: bytes, requests=requests) -> bytes:
                requests.append(request)
                if len(requests) == 3:
                    return b"cleanup"
                return b"\x71" + request[1:4] + bytes((1 if len(requests) == 1 else 2,))

            host = bindings(exchange)
            self.assertEqual(self.call(host, "StartComThread", str(index))[0], 15)
            assert host._worker is not None
            host._worker.join(1)
            self.assertEqual(self.call(host, "StopComThread", "0")[0], 0)
            result, values = self.call(host, "GetThreadRecvData", "4", "INT02")
            self.assertEqual((result, values["INT02"]), (0, 2))
            self.assertEqual(len(requests), 3)
            with self.assertRaises(SessionError):
                self.call(host, "GetThreadRecvData", "5", "INT02")

    def test_index_three_waits_single_send_and_cleanup(self):
        calls: list[bytes] = []

        def exchange(ecu: str, request: bytes) -> bytes:
            calls.append(request)
            return b"\x71" + request[1:4]

        host = bindings(exchange)
        self.assertEqual(self.call(host, "StartComThread", "3")[0], 0)
        self.assertEqual(len(calls), 1)
        host = bindings(lambda ecu, request: b"bad")
        self.assertEqual(self.call(host, "StartComThread", "3")[0], 111)

    def test_busy_race_abort_and_transport_ownership(self):
        entered, release = threading.Event(), threading.Event()
        calls: list[bytes] = []

        def exchange(ecu: str, request: bytes) -> bytes:
            calls.append(request)
            if len(calls) == 1:
                entered.set()
                if not release.wait(2):
                    raise AssertionError("Authored exchange was not aborted")
            return b"\x71" + request[1:4] + b"\x02"

        host = bindings(exchange, abort=release.set)
        self.assertEqual(self.call(host, "StartComThread", "1")[0], 15)
        self.assertTrue(entered.wait(1))
        self.assertEqual(self.call(host, "StartComThread", "2")[0], 15)
        self.assertEqual(self.call(host, "GetThreadStatus")[0], 15)
        self.assertEqual(self.call(host, "ChangeSessionMode", "1")[0], 15)
        self.assertEqual(self.call(host, "StopComThread", "1")[0], 0)
        self.assertEqual(len(calls), 2)

    def test_thread_native_fault_short_reply_and_cleanup_failure(self):
        for fault, expected in ((b"bad", 3), (NativeStatus(77), 77)):
            calls: list[bytes] = []

            def exchange(ecu: str, request: bytes, calls=calls, fault=fault) -> bytes:
                calls.append(request)
                if len(calls) == 1:
                    if isinstance(fault, NativeStatus):
                        raise fault
                    return fault
                return b"cleanup"

            host = bindings(exchange)
            self.call(host, "StartComThread", "0")
            assert host._worker is not None
            host._worker.join(1)
            self.assertEqual(self.call(host, "StopComThread", "0")[0], expected)
            self.assertEqual(len(calls), 2)
        host = bindings(lambda ecu, request: b"x" * 0x1021)
        self.call(host, "StartComThread", "1")
        assert host._worker is not None
        host._worker.join(1)
        with self.assertRaises(BaseExceptionGroup):
            self.call(host, "StopComThread", "0")

    def test_thread_cancellation_and_deadline_cleanup_are_not_success(self):
        for cancel in (True, False):
            calls: list[bytes] = []
            host = bindings()
            assert host.session is not None
            session = host.session
            now = [0.0]
            session.clock = lambda now=now: now[0]

            def exchange(
                ecu: str,
                request: bytes,
                calls=calls,
                cancel=cancel,
                session=session,
                now=now,
            ) -> bytes:
                calls.append(request)
                if len(calls) == 1:
                    if cancel:
                        session.cancelled = lambda: True
                    else:
                        now[0] = 2.0
                return b"\x71" + request[1:4] + b"\x02"

            session.exchange = exchange
            self.call(host, "StartComThread", "0")
            assert host._worker is not None
            host._worker.join(1)
            with self.assertRaises(Cancelled if cancel else SessionError):
                self.call(host, "GetThreadStatus")
            self.assertEqual(len(calls), 2)

    def test_support_record_rejects_invalid_buffers(self):
        for offsets, support in (
            ((0,), b""),
            ((0x1021,) * 256, b""),
            ((0,) * 256, b"x" * 0x1021),
        ):
            with self.assertRaises(ValueError):
                SupportRecord(offsets, support, b"")

    def test_actual_xml_callback_mutations_precede_out_assignment(self):
        resource = UtilityResource(
            b"authored",
            ET.fromstring("""<UTILITY><FUNCTION><FUNCID>demo</FUNCID><STORAGE>
            <DATA DATAID="INT01"/><DATA DATAID="INT02"/><DATA DATAID="INT03"/>
            </STORAGE><BLOCK ID="B1" TYPE="G002"><FASTACTION>
            <CALLFUNC NAME="GetEcuId" OUT="INT03">"INT01"</CALLFUNC>
            <CALLFUNC NAME="InitialCom" OUT="INT03">"INT02"</CALLFUNC>
            <CALLFUNC NAME="GetSptTableDataPosRecvData" OUT="INT01">"0","3","4","INT02","INT03"</CALLFUNC>
            <ACTION MODE="BLOCK" NEXT="END"/>
            </FASTACTION></BLOCK></FUNCTION></UTILITY>"""),
        )
        report = UtilityRuntime(resource, library=bindings(support=cache())).run("demo")
        self.assertEqual(report["storage"], {"INT01": 0, "INT02": 1, "INT03": 100})

    def test_synchronous_cancel_deadline_and_partial_reply_bounds(self):
        host = bindings()
        assert host.session is not None
        host.session.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            self.call(host, "InitialCom", "INT01")
        host.session.cancelled = lambda: False
        ticks = iter((0.0, 0.0, 2.0))
        host.session.clock = lambda: next(ticks)
        with self.assertRaisesRegex(SessionError, "deadline"):
            self.call(host, "ChangeSessionMode", "1")

        def exchange(ecu: str, request: bytes) -> bytes:
            raise NativeStatus(77, b"x" * 0x1021)

        with self.assertRaisesRegex(SessionError, "partial reply"):
            self.call(bindings(exchange), "ChangeSessionMode", "1")

    def test_cooperative_stop_does_not_abort_transport_or_poll_again(self):
        entered, release = threading.Event(), threading.Event()
        calls: list[bytes] = []
        aborted: list[bool] = []

        def exchange(ecu: str, request: bytes) -> bytes:
            calls.append(request)
            if len(calls) == 1:
                entered.set()
                if not release.wait(2):
                    raise AssertionError("Authored release missing")
            return b"\x71" + request[1:4] + b"\x01"

        host = bindings(exchange, abort=lambda: aborted.append(True))
        self.call(host, "StartComThread", "0")
        self.assertTrue(entered.wait(1))
        stopped = threading.Event()
        result: list[int] = []

        def stop() -> None:
            result.append(self.call(host, "StopComThread", "0")[0])
            stopped.set()

        waiter = threading.Thread(target=stop)
        waiter.start()
        self.assertTrue(host._stop.wait(1))
        self.assertEqual(host("StartComThread", (), {}), 15)
        release.set()
        self.assertTrue(stopped.wait(1))
        waiter.join(1)
        self.assertEqual((result, aborted, len(calls)), ([0], [], 2))

    def test_native_exception_cannot_hide_post_io_cancel_or_deadline(self):
        for cancel in (True, False):
            host = bindings()
            assert host.session is not None
            session = host.session
            now = [0.0]
            session.clock = lambda now=now: now[0]

            def exchange(
                ecu: str, request: bytes, session=session, now=now, cancel=cancel
            ) -> bytes:
                if cancel:
                    session.cancelled = lambda: True
                else:
                    now[0] = 2.0
                raise NativeStatus(77)

            session.exchange = exchange
            with self.assertRaises(Cancelled if cancel else SessionError):
                self.call(host, "InitialCom", "INT01")


class NativeProfileBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        source = create_demo(Path(self.directory.name) / "demo")
        self.profile = VehicleCatalog(source / "Techstream_DB_NA").build_profile(1)
        self.broker = {0x74: 23, 0xAB: 42, 0x6F: 0x14, 0x70: 0x12, 0x73: 1}
        self.requests: list[bytes] = []
        self.lifecycle: list[tuple] = []
        self.keepalive: list[bool] = []
        self.settings: list[tuple[str, int]] = []

    def exchange(self, ecu: str, request: bytes) -> bytes:
        self.requests.append(request)
        if request[0] == 0x10:
            return b"\x50" + request[1:2] + bytes(4)
        return b"\x71" + request[1:4] + b"\x02"

    def host(self, **kwargs) -> UtilityBindings:
        return UtilityBindings.from_profile(
            self.profile,
            ToyotaSession(self.exchange, "selected-ecu", {}),
            broker=self.broker,
            initialize=lambda context, refresh: (
                self.lifecycle.append((context, refresh)) or 13
            ),
            finalize=lambda: self.lifecycle.append(("finalize",)) or 17,
            configure=lambda name, value: self.settings.append((name, value)),
            keepalive=self.keepalive.append,
            wait=lambda seconds: None,
            **kwargs,
        )

    def test_native_factory_driver_lifecycle_is_not_fake_diagnostic_request(self):
        host = self.host()
        values: dict[str, int | bytes] = {"INT01": 1}
        self.assertEqual(host("InitialCom", ("INT01",), values), 0)
        self.assertEqual(values["INT01"], 13)
        self.assertEqual(self.lifecycle, [(self.broker, True)])
        self.assertEqual(self.requests, [])
        self.assertEqual(host("FinalCom", ("INT01",), values), 0)
        self.assertEqual(values["INT01"], 17)
        self.assertEqual(self.lifecycle[-1], ("finalize",))
        self.assertEqual(host("GetEcuId", ("INT01",), values), 0)
        self.assertEqual(values["INT01"], 1)

    def test_exact_native_session_sequence_keepalive_cache_and_no_guessed_ddb_join(
        self,
    ):
        host = self.host()
        self.assertEqual(host("StartExtendedSessionP5", ("1",), {}), 0)
        self.assertEqual(self.requests, [b"\x10\x01", b"\x10\x03"])
        self.assertEqual(self.keepalive, [True])
        self.assertEqual(host("ChangeSessionMode", ("3",), {}), 0)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(host("EndExtendedSessionP5", ("1",), {}), 0)
        self.assertEqual(self.requests[-1], b"\x10\x01")
        self.assertEqual(self.keepalive, [True, False])
        assert host.session is not None
        self.assertTrue(
            all(
                "matching_selected_ddb=" not in spec.provenance
                for spec in host.session.commands.values()
            )
        )
        self.assertEqual(host.provenance["physical"], "PHYSICAL_UNCONFIRMED")
        self.assertEqual(
            host.provenance["broker"],
            {f"{key:X}": value for key, value in self.broker.items()},
        )

    def test_native_factory_matches_actual_selected_ddb_only_when_bytes_match(self):
        management = self.profile.catalog.management
        sections = {
            slot: (section.count, section.payload)
            for slot, section in management.sections.items()
        }
        count, payload = sections[0]
        # Authored demo's first variable is two bytes at its directory's end.
        location = count * 6
        sections[0] = count, payload[:location] + b"\x10\x01" + payload[location + 2 :]
        path = self.profile.catalog.root / "Toyota.ddb"
        path.write_bytes(_ddb(1, sections))
        self.profile = VehicleCatalog(path.parent).build_profile(1)
        host = self.host()
        assert host.session is not None
        spec = host.session.commands[str(host.operations["mode_1"])]
        self.assertIn("matching_selected_ddb=DDB:", spec.provenance)
        self.assertIn("function=16", spec.provenance)
        spec = host.session.commands[str(host.operations["thread_0"])]
        self.assertNotIn("matching_selected_ddb=", spec.provenance)

    def test_native_factory_p5_reply_predicates_and_cleanup_on_failed_end(self):
        for reply, expected in ((b"", 3), (b"\x50\x02", 7)):
            host = self.host()
            assert host.session is not None
            host.session.exchange = lambda ecu, request, reply=reply: reply
            self.assertEqual(host("StartExtendedSessionP5", ("1",), {}), expected)
            self.assertEqual(self.keepalive, [])
            self.assertEqual(host("EndExtendedSessionP5", ("1",), {}), expected)
            self.assertEqual(self.keepalive.pop(), False)
        host = self.host()
        assert host.session is not None
        host.session.exchange = lambda ecu, request: b"\x50\x01"
        self.assertEqual(host("ChangeSessionMode", ("1",), {}), 3)

    def test_native_factory_thread_ecu_variants_and_all_four_workers(self):
        for index, ecu_id, expected in (
            (0, 0x1F2, "31031014"),
            (0, 1, "31031106"),
            (1, 1, "31031101"),
            (2, 1, "31031103"),
            (3, 0x1AE, "31011106"),
            (3, 1, "31011014ffff"),
        ):
            self.requests.clear()
            self.broker[0x73] = ecu_id
            host = self.host()
            result = host("StartComThread", (str(index),), {})
            self.assertEqual(result, 0 if index == 3 else 15)
            assert host._worker is not None
            host._worker.join(1)
            self.assertEqual(host("GetThreadStatus", (), {}), 0)
            self.assertEqual(self.requests[0], bytes.fromhex(expected))
            self.assertEqual(len(self.requests), 1 if index == 3 else 2)

    def test_native_factory_requires_context_valid_transport_pair_and_p5_gate(self):
        self.broker.pop(0x74)
        with self.assertRaisesRegex(SessionError, "broker context"):
            self.host()
        self.broker[0x74] = 23
        self.broker[0x70] = 0
        with self.assertRaisesRegex(SessionError, "selector pair"):
            self.host()
        self.broker[0x70] = 0x12
        self.broker[0x6F] = 4
        host = self.host()
        self.assertEqual(host("StartExtendedSessionP5", ("1",), {}), 99)
        self.assertEqual(self.requests, [])

    def test_native_lifecycle_errors_still_obey_cancel_deadline_and_status_bounds(self):
        host = self.host()
        assert host.session is not None

        def initialize(refresh: bool) -> int:
            assert host.session is not None
            host.session.cancelled = lambda: True
            raise NativeStatus(77)

        host._initialize = initialize
        with self.assertRaises(Cancelled):
            host("InitialCom", ("0",), {})
        host.session.cancelled = lambda: False
        host._initialize = lambda refresh: -1
        with self.assertRaisesRegex(SessionError, "invalid status"):
            host("InitialCom", ("0",), {})

    def test_applied_but_cancelled_mode_transition_invalidates_cache_and_stops_keepalive(
        self,
    ):
        host = self.host()
        assert host.session is not None
        self.assertEqual(host("ChangeSessionMode", ("3",), {}), 0)

        def cancelled_after_apply(ecu: str, request: bytes) -> bytes:
            assert host.session is not None
            result = self.exchange(ecu, request)
            host.session.cancelled = lambda: True
            return result

        host.session.exchange = cancelled_after_apply
        with self.assertRaises(Cancelled):
            host("EndExtendedSessionP5", ("1",), {})
        self.assertEqual(self.keepalive, [True, False])
        host.session.cancelled = lambda: False
        host.session.exchange = self.exchange
        before = len(self.requests)
        self.assertEqual(host("ChangeSessionMode", ("3",), {}), 0)
        self.assertEqual(len(self.requests), before + 1)
        self.assertEqual(self.requests[-1], b"\x10\x03")

    def test_post_io_deadline_and_keepalive_failure_never_reuse_known_mode(self):
        for failure in ("deadline", "keepalive"):
            host = self.host()
            assert host.session is not None
            self.assertEqual(host("ChangeSessionMode", ("3",), {}), 0)
            now = [0.0]
            host.session.clock = lambda now=now: now[0]

            def exchange(ecu: str, request: bytes, now=now) -> bytes:
                result = self.exchange(ecu, request)
                now[0] = 20.0
                return result

            def keepalive(enabled: bool) -> None:
                raise OSError("Authored keepalive failure")

            if failure == "deadline":
                host.session.exchange = exchange
            else:
                host._keepalive = keepalive
            with self.assertRaises(SessionError if failure == "deadline" else OSError):
                host("EndExtendedSessionP5", ("1",), {})
            host.session.exchange = self.exchange
            host._keepalive = self.keepalive.append
            before = len(self.requests)
            self.assertEqual(host("ChangeSessionMode", ("3",), {}), 0)
            self.assertEqual(len(self.requests), before + 1)


if __name__ == "__main__":
    unittest.main()
