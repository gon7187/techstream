"""Authored context/lifecycle checks; no OEM resources or device execution."""

import ast
import copy
import hashlib
import json
import re
import runpy
import struct
import threading
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

from scripts.j2534_2026 import PrimitiveResult
from scripts.utility_ex import (
    _BROKER_GLOBAL_BASES,
    _BROKER_KEYS,
    _DRIVER_SLOTS,
    _NK_ANY_MODE_WRAPPERS,
    _NK_CANCEL_GETTERS,
    _NK_PRE_MODE_ARGUMENT_WRITES,
    _NK_VARIANT_WRAPPERS,
    _NK_WRAPPER_SOURCE_LIMITS,
    _NK_WRAPPERS,
    _SIS_DRIVER_SLOTS,
    _TY_MODE_OVERRIDES,
    _TY_THREAD_WRAPPERS,
    _WORKER_RESULT_GLOBALS,
    SOURCES,
    UtilityDriverBinding,
    UtilityEx2TY,
    UtilityExContext,
    UtilityExEngine,
    UtilityImportBinding,
    UtilityP6DriverBinding,
    UtilitySISDriverBinding,
    UtilityWorker,
)
from tests.private_evidence import require_private


class Host:
    def __init__(self):
        self.values = {0x6F: 4, 0x70: 0x11}
        self.events = []
        self.data = {}
        self.elapsed = 0
        self.waits = []
        self.after_sleep = lambda: None

    def get_parameter(self, key):
        self.events.append(("get", key))
        return self.values.get(key, 0)

    def get_data_size(self, key):
        self.events.append(("data_size", key))
        return len(self.data[key])

    def get_data(self, key):
        self.events.append(("data", key))
        return self.data[key]

    def set_parameter(self, key, value):
        self.events.append(("set", key, value))
        self.values[key] = value
        return 1

    def write_parameters(self):
        self.events.append(("write",))
        return 1

    def refresh_parameters(self):
        pass

    def ticks(self):
        return self.elapsed & 0xFFFFFFFF

    def sleep(self, milliseconds):
        self.waits.append(milliseconds)
        self.elapsed += milliseconds
        self.after_sleep()


def authored_context():
    data = b"authored lifecycle fixture, not a native source image"
    digest = hashlib.sha256(data).hexdigest()
    # Test the context mechanism without claiming any native algorithm provenance.
    with patch.dict(SOURCES, {digest: "authored"}):
        return UtilityExContext(data, Host(), None, None)


class UtilityContextTests(unittest.TestCase):
    def test_native_timer_primitives_retain_callback_until_successful_kill(self):
        context = authored_context()
        calls = []

        def callback(hwnd, message, timer_id, tick):
            calls.append((hwnd, message, timer_id, tick))

        def start(hwnd, timer_id, interval, supplied):
            self.assertEqual((hwnd, timer_id, interval), (0, 0, 2000))
            self.assertIs(supplied, callback)
            return 73

        context.win32_exports = {
            "SetTimer": start,
            "KillTimer": lambda hwnd, timer_id: False,
        }
        self.assertEqual(context.set_timer(0, 0, 2000, callback), 73)
        timers = context.state["utility_ex:win32_timers"]
        self.assertIsInstance(timers, dict)
        assert isinstance(timers, dict)
        self.assertIs(timers[73], callback)
        callback(0, 0x113, 73, 2000)
        self.assertEqual(calls, [(0, 0x113, 73, 2000)])
        self.assertEqual(context.kill_timer(0, 73), 0)
        self.assertIn(73, timers)
        context.win32_exports = {"KillTimer": lambda hwnd, timer_id: True}
        self.assertEqual(context.kill_timer(0, 73), 1)
        self.assertNotIn(73, timers)
        with self.assertRaises(ValueError):
            context.kill_timer(1, 73)

    def test_module_data_reader_initialized_zero_fill_and_bounds(self):
        data = bytearray(0x240)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x86, 1)
        struct.pack_into("<H", data, 0x94, 0xE0)
        struct.pack_into("<H", data, 0x98, 0x10B)
        struct.pack_into("<I", data, 0x98 + 28, 0x10000000)
        struct.pack_into("<I", data, 0x98 + 60, 0x200)
        struct.pack_into("<IIII", data, 0x178 + 8, 0x80, 0x1000, 0x40, 0x200)
        data[0x200:0x204] = b"test"
        context = authored_context()
        context.module_bytes = bytes(data)
        self.assertEqual(context.read_module_data(0x10001000, 4), b"test")
        self.assertEqual(context.read_module_data(0x1000103E, 4), bytes(4))
        self.assertEqual(context.read_module_data(0x10000000, 2), b"MZ")
        with self.assertRaises(ValueError):
            context.read_module_data(0x1000107F, 2)
        with self.assertRaises(ValueError):
            context.read_module_data(0xFFFFFFFF, 2)
        context.module_bytes = bytes(data[:0x220])
        with self.assertRaises(ValueError):
            context.read_module_data(0x1000101F, 4)

    def test_worker_running_retains_async_memory_lease(self):
        worker = UtilityWorker(authored_context())
        entered, release = threading.Event(), threading.Event()

        def body():
            entered.set()
            release.wait(2)
            return 7

        self.assertFalse(worker.running)
        self.assertEqual(worker.start(body, 10000), 15)
        self.assertTrue(entered.wait(1))
        self.assertTrue(worker.running)
        release.set()
        assert worker._thread is not None
        worker._thread.join(1)
        self.assertFalse(worker.running)
        self.assertEqual(worker.get_status(), 7)

    def test_individual_ini_primitives_preserve_native_arguments_and_bounds(self):
        context = authored_context()
        calls = []

        def integer(section, key, default, filename):
            calls.append((section, key, default, filename))
            return default

        def string(section, key, default, output, capacity, filename):
            calls.append((section, key, default, capacity, filename))
            value = default[: max(0, capacity - 1)]
            output[: len(value)] = value
            if capacity:
                output[len(value)] = 0
            return len(value)

        context.win32_exports = {
            "GetPrivateProfileIntA": integer,
            "GetPrivateProfileStringA": string,
        }
        self.assertEqual(
            context.get_private_profile_int_a(b"section", b"key", 42, b"authored.ini"),
            42,
        )
        output = bytearray(4)
        self.assertEqual(
            context.get_private_profile_string_a(
                b"section", b"key", b"authored", output, 4, b"authored.ini"
            ),
            3,
        )
        self.assertEqual(output, b"aut\0")
        self.assertEqual(calls[0], (b"section", b"key", 42, b"authored.ini"))
        with self.assertRaises(ValueError):
            context.get_private_profile_int_a(b"bad\0", b"key", 0, b"authored.ini")
        with self.assertRaises(ValueError):
            context.get_private_profile_string_a(
                b"s", b"k", b"", output, 5, b"authored.ini"
            )
        context.win32_exports = {"GetPrivateProfileStringA": lambda *args: 4}
        with self.assertRaises(ValueError):
            context.get_private_profile_string_a(
                b"s", b"k", b"", output, 4, b"authored.ini"
            )

    def test_native_parameter_reads_live_host_without_changing_snapshot(self):
        context = authored_context()
        assert isinstance(context.host, Host)
        old = context.broker(0x6F)
        context.host.values[0x6F] = 52
        context.host.values[0xC9] = 0xFFFFFFFF
        self.assertEqual(context.native_parameter(0x6F), 52)
        self.assertEqual(context.native_parameter(0xC9), 0xFFFFFFFF)
        self.assertEqual(context.broker(0x6F), old)

    def test_direct_native_sleep_keeps_single_call_during_cancellation(self):
        context = authored_context()
        assert isinstance(context.host, Host)
        context._cancel.set()
        context.native_sleep(250)
        self.assertEqual(context.host.waits, [250])
        context.sleep(250)
        self.assertEqual(context.host.waits, [250])

    def test_unknown_native_source_rejected(self):
        with self.assertRaises(ValueError):
            UtilityExContext(b"unregistered", Host(), None, None)

    def test_native_parameter_statuses_and_uint32(self):
        context = authored_context()
        self.assertEqual(context.mode, 4)
        self.assertEqual(context.set_parameter(0x70, 0x22), 1)
        self.assertEqual(context.broker(0x70), 0x11)
        self.assertEqual(context.write_parameters(), 1)
        context.refresh_parameters()
        self.assertEqual(context.broker(0x70), 0x22)
        with self.assertRaises(ValueError):
            context.set_parameter(0x70, -1)

    def test_sleep_slices_native_cancel_and_tick_wrap(self):
        context = authored_context()
        host = context.host
        self.assertIsInstance(host, Host)
        assert isinstance(host, Host)
        host.after_sleep = context._cancel.set
        context.sleep(2000)
        self.assertEqual(host.waits, [100])
        host.elapsed = 0xFFFFFFFF + 3
        self.assertEqual(context.ticks(), 2)

    def test_broker_data_uses_separate_native_size_and_data_producers(self):
        context = authored_context()
        host = context.host
        assert isinstance(host, Host)
        host.data[500] = bytes.fromhex("2a00000001000000")
        self.assertEqual(context.broker_data(500), host.data[500])
        self.assertEqual(host.events[-2:], [("data_size", 500), ("data", 500)])
        with self.assertRaises(KeyError):
            context.broker_data(501)

    def test_context_state_isolated(self):
        a, b = authored_context(), authored_context()
        a.state["saved-address"] = 64
        self.assertEqual(b.state, {})


class WorkerTests(unittest.TestCase):
    def test_native_result_globals_publish_start_completion_and_preserve_early_fault(
        self,
    ):
        context = authored_context()
        for source, field in _WORKER_RESULT_GLOBALS.items():
            worker = UtilityWorker(context)
            release = threading.Event()
            with patch.dict(SOURCES, {context.module_sha256: source}):
                try:
                    self.assertEqual(
                        worker.start(
                            lambda release=release: (release.wait(2) and 23) or 23,
                            10000,
                        ),
                        15,
                    )
                    self.assertEqual(context.state[field], 15)
                finally:
                    release.set()
                    self.assertEqual(worker.stop(), 23)
                self.assertEqual(context.state[field], 23)

                def early_publication(field=field):
                    context.state[field] = 71
                    raise OSError("cleanup failed after native publication")

                self.assertEqual(worker.start(early_publication, 10000), 15)
                with self.assertRaisesRegex(OSError, "cleanup failed"):
                    worker.get_status()
                self.assertEqual(context.state[field], 71)

    def test_start_busy_result_and_explicit_join(self):
        worker = UtilityWorker(authored_context())
        entered, release = threading.Event(), threading.Event()

        def body():
            entered.set()
            release.wait(2)
            return 1234

        self.assertEqual(worker.start(body, 2000), 15)
        self.assertTrue(entered.wait(1))
        self.assertEqual(worker.start(lambda: 0, 1), 16)
        release.set()
        self.assertEqual(worker.stop(), 1234)
        self.assertFalse(worker.context.is_cancelled())

    def test_worker_host_fault_propagates_original_after_join(self):
        worker = UtilityWorker(authored_context())
        error = OSError("authored provider failure")

        def body():
            raise error

        worker.start(body, 1000)
        with self.assertRaises(OSError) as caught:
            worker.stop()
        self.assertIs(caught.exception, error)

    def test_restart_surfaces_unobserved_worker_failure_before_new_body(self):
        worker = UtilityWorker(authored_context())
        error = OSError("unobserved failure")

        def body():
            raise error

        worker.start(body, 1000)
        assert worker._thread is not None
        assert worker._thread is not None
        worker._thread.join(1)
        with self.assertRaises(OSError) as caught:
            worker.start(lambda: 7, 1000)
        self.assertIs(caught.exception, error)
        self.assertIsNone(worker._thread)
        self.assertEqual(worker.start(lambda: 7, 1000), 15)
        self.assertEqual(worker.stop(), 7)

    def test_timeout_retains_worker_until_cooperative_release(self):
        worker = UtilityWorker(authored_context())
        release = threading.Event()

        def body():
            release.wait(2)
            return 0

        worker.start(body, 1000)
        try:
            with self.assertRaises(TimeoutError):
                worker.stop(0)
            self.assertTrue(worker.context.is_cancelled())
            self.assertEqual(worker.start(lambda: 0, 1), 16)
        finally:
            release.set()
            self.assertEqual(worker.stop(1000), 0)

    def test_missing_handle_running_status_becomes99(self):
        worker = UtilityWorker(authored_context())
        worker.status = 15
        self.assertEqual(worker.get_status(), 99)
        self.assertEqual(worker.stop(), 0)


class NativeWrapperTests(unittest.TestCase):
    def test_engines_on_one_context_share_native_busy_worker(self):
        first = self.engine()
        second = UtilityExEngine(first.context)
        second.supported_bodies = first.supported_bodies
        release = threading.Event()
        first.run_body = lambda export, args=(), release=release: (
            (release.wait(2) and 7) or 7
        )
        self.assertIs(first.worker, second.worker)
        first.context._parameters[0x6F] = 3
        with patch.dict(SOURCES, {first.context.module_sha256: "NK18"}):
            try:
                self.assertEqual(first.invoke("Ex2ABS_01_BeginSolenoidDrive", (1,)), 15)
                self.assertEqual(
                    second.invoke("Ex2ABS_01_BeginSolenoidDrive", (2,)), 16
                )
            finally:
                release.set()
                self.assertEqual(second.worker.stop(), 7)
            self.assertEqual(first.worker.get_status(), 7)

    def test_ty_inline_support_and_always_zero_scheduler_return(self):
        engine = self.engine()
        engine.supported_bodies = lambda: ()
        with patch.dict(SOURCES, {engine.context.module_sha256: "TY12"}):
            for export in (
                "Ex2DP2_11_SupportCheck",
                "Ex2DP2_12_GetSupportBitInformation",
            ):
                engine.context._parameters[0x6F] = 20
                self.assertEqual(engine.invoke(export, (bytearray(16),)), 0)
                self.assertIsNone(engine.worker._thread)
                engine.context._parameters[0x6F] = 4
                with self.assertRaises(LookupError):
                    engine.invoke(export, (bytearray(16),))
        for source in ("TY12", "TY18", "TYPlus"):
            release = threading.Event()
            engine = self.engine()
            engine.supported_bodies = lambda: ("Ex2PI_01_GetAbsoTime",)
            engine.run_body = lambda export, args=(), release=release: (
                (release.wait(2) and 7) or 7
            )
            with patch.dict(SOURCES, {engine.context.module_sha256: source}):
                engine.context._parameters[0x6F] = 20
                self.assertEqual(
                    engine.invoke("Ex2PI_01_GetAbsoTime", (bytearray(4),)), 0
                )
                self.assertIsNone(engine.worker._thread)
                engine.context._parameters[0x6F] = 4
                try:
                    self.assertEqual(
                        engine.invoke("Ex2PI_01_GetAbsoTime", (bytearray(4),)), 0
                    )
                    self.assertEqual(
                        engine.invoke("Ex2PI_01_GetAbsoTime", (bytearray(4),)), 0
                    )
                finally:
                    release.set()
                    self.assertEqual(engine.worker.stop(), 7)

    def test_all4_native_cancel_getter_keys_are_source_specific(self):
        for source, getters in _NK_CANCEL_GETTERS.items():
            engine = self.engine()
            engine.run_body = lambda export, args=(), engine=engine: (
                engine.context._cancel.set() or 27
            )
            with (
                patch.dict(SOURCES, {engine.context.module_sha256: source}),
                patch.object(engine.context, "comm") as comm,
            ):
                comm.return_value.cancellation_counters.return_value = {
                    f"native_rva:{rva:x}": value
                    for rva, value in zip(getters, (0, 1, 1, 0, 0))
                }
                self.assertEqual(engine.invoke("Ex2ECD_11_InitCrankTimeValue"), 15)
                self.assertEqual(engine.worker.get_status(), 28)

    def engine(self):
        context = authored_context()
        engine = UtilityExEngine(context)
        engine.supported_bodies = lambda: tuple(_NK_WRAPPERS)
        return engine

    def test_direct_abi_output_reference_void_mode_and_arity(self):
        engine = self.engine()
        output = bytearray(1)
        seen = []

        def body(export, args=()):
            seen.append(args)
            return -1

        engine.run_body = body
        with patch.dict(SOURCES, {engine.context.module_sha256: "NK18"}):
            self.assertEqual(engine.invoke("Ex2ECD_12_GetSupportInfo", (output,)), -1)
            self.assertIs(seen[0][0], output)
            self.assertIsNone(engine.invoke("Ex2SMRT_SetProgressTimeOutFlg"))
            self.assertEqual(len(seen), 1)
            with self.assertRaises(ValueError):
                engine.invoke("Ex2ECD_12_GetSupportInfo")
            engine.context._parameters[0x6F] = 3
            self.assertIsNone(engine.invoke("Ex2SMRT_SetProgressTimeOutFlg"))
            self.assertEqual(len(seen), 2)

    def test_conditional_worker_busy_and_no_unknown_body_success(self):
        engine = self.engine()
        engine.context._parameters[0x6F] = 3
        release = threading.Event()
        engine.run_body = lambda export, args=(), release=release: (
            (release.wait(2) and 7) or 7
        )
        with patch.dict(SOURCES, {engine.context.module_sha256: "NK18"}):
            try:
                self.assertEqual(engine.invoke("Ex2ABS_EndAirBleed_TRC", (1, 1)), 15)
                self.assertEqual(engine.invoke("Ex2ABS_EndAirBleed_TRC", (2, 1)), 16)
            finally:
                release.set()
                self.assertEqual(engine.worker.stop(), 7)
            self.assertEqual(engine.invoke("Ex2ABS_EndAirBleed_TRC", (1, 0)), 7)
            engine.supported_bodies = lambda: ()
            with self.assertRaises(LookupError):
                engine.invoke("Ex2ABS_EndAirBleed_TRC", (1, 1))

    def test_normalization_requiring_unbound_actual_counters_fails_closed(self):
        engine = self.engine()

        def body(export, args=()):
            engine.context._cancel.set()
            return 27

        engine.run_body = body
        with (
            patch.dict(SOURCES, {engine.context.module_sha256: "NK18"}),
            patch.object(
                engine.context,
                "comm",
                side_effect=LookupError("counter binding unavailable"),
            ),
        ):
            self.assertEqual(engine.invoke("Ex2ECD_11_InitCrankTimeValue"), 15)
            with self.assertRaisesRegex(LookupError, "counter binding"):
                engine.worker.get_status()

    def test_cancel_normalization_uses_actual_counter_snapshot(self):
        for status, updates, expected in (
            (27, {}, 28),
            (27, {"native_rva:17340": 1}, 29),
            (27, {"native_rva:17350": 1}, 29),
            (2, {}, 2),
            (2, {"native_rva:17370": 1}, 30),
        ):
            with self.subTest(status=status, updates=updates):
                engine = self.engine()
                counters = {
                    f"native_rva:{rva}": 0
                    for rva in (17340, 17350, 17360, 17370, 17380)
                }
                counters.update(updates)

                def body(export, args=(), engine=engine, status=status):
                    engine.context._cancel.set()
                    return status

                engine.run_body = body
                with (
                    patch.dict(SOURCES, {engine.context.module_sha256: "NK18"}),
                    patch.object(engine.context, "comm") as comm,
                ):
                    comm.return_value.cancellation_counters.return_value = counters
                    self.assertEqual(engine.invoke("Ex2ECD_11_InitCrankTimeValue"), 15)
                    self.assertEqual(engine.worker.get_status(), expected)
                    comm.return_value.cancellation_counters.assert_called_once_with()

    def test_exact_source_reviewed_powertrain_packet_matches_bound_contracts(self):
        root = Path(__file__).resolve().parents[1]
        packet = root / "analysis/evidence/no-car-83/nk-owner95-wrapper-import.json"
        if not packet.exists():
            self.skipTest("Private exact-source wrapper packet unavailable")
        for row in json.loads(packet.read_text())["rows"]:
            with self.subTest(source=row["module_sha256"], export=row["export"]):
                mode, dispatch, timeout, arity, void, normalize = (
                    _NK_VARIANT_WRAPPERS.get(SOURCES[row["module_sha256"]], {}).get(
                        row["export"], _NK_WRAPPERS[row["export"]]
                    )
                )
                self.assertEqual(mode, row["mode_predicate"].get("value", ()))
                self.assertEqual(
                    dispatch, "thread" if row["dispatch"] == "scheduler" else "direct"
                )
                self.assertEqual(timeout, row["timeout_ms"])
                self.assertEqual(arity, row["native_argument_arity"])
                self.assertEqual(void, row["return_abi"] == "native-void")
                self.assertEqual(normalize, row["finish_normalization"] != "none")
                for anchor in row["anchors"]:
                    # Reanalysis may rename derived C labels; exact ASM is stable.
                    if anchor["path"].endswith(".asm"):
                        self.assertEqual(
                            hashlib.sha256(
                                (root / anchor["path"]).read_bytes()
                            ).hexdigest(),
                            anchor["sha256"],
                        )

    def test_exact_source_ty_template_packet_matches_bound_contracts(self):
        root = Path(__file__).resolve().parents[1]
        packet = root / "analysis/evidence/no-car-83/ty-template-wrappers.json"
        if not packet.exists():
            self.skipTest("Private exact-source wrapper packet unavailable")
        for row in json.loads(packet.read_text())["rows"]:
            with self.subTest(source=row["source_sha256"], export=row["export"]):
                self.assertEqual(
                    _TY_THREAD_WRAPPERS[SOURCES[row["source_sha256"]]][row["export"]],
                    (row["arity"], row["timeout_ms"]),
                )
                path = root / row["c_path"]
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(), row["c_sha256"]
                )
                self.assertEqual(
                    hashlib.sha256(path.with_suffix(".asm").read_bytes()).hexdigest(),
                    row["asm_sha256"],
                )

    def test_cgw_native_session_crypto_retry_and_cleanup_contract(self):
        # Published AES128 single-block vector; no supplied OEM key in fixtures.
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        seed = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        encrypted = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")

        class Comm:
            def __init__(self, replies):
                self.replies = iter(replies)
                self.events = []

            def read_target(self):
                return 0x7E0, 9

            def read_field(self, field):
                if field != "native_rva:121f0":
                    raise AssertionError(field)
                return 73

            def configure(self, field, value):
                self.events.append((field, value))

            def select_target(self, first, second=0):
                self.events.append(("target", first, second))

            def initialize(self, mode=0):
                self.events.append(("initialize", mode))
                return 0

            def exchange_plain(self, request):
                self.events.append(("wire", request))
                response = next(self.replies)
                if isinstance(response, BaseException):
                    raise response
                return response

            def finalize(self):
                self.events.append(("finalize",))

        for current, transitions in ((1, (0x88,)), (0x88, ()), (9, (0x89, 0x88))):
            engine = self.engine()
            engine.context.state["native_global:100f8190"] = 73
            replies = [(0, b""), (0, bytes((0, current)))]
            replies += [(0, b"\x00\x00")] * len(transitions)
            replies += [(0, b"\x00\x01" + seed), (0, b"\x00\x02\x00")]
            comm = Comm(replies)
            with (
                patch.object(engine.context, "comm", return_value=comm),
                patch.object(
                    engine.context, "read_module_data", return_value=key + b"\x00"
                ) as module_read,
            ):
                self.assertEqual(engine._cgw_security_ty18(), 0)
            module_read.assert_called_once_with(0x100DA1D8, 17)
            wires = [event[1] for event in comm.events if event[0] == "wire"]
            self.assertEqual(
                wires,
                [b"\x3e\x00", b"\x10\x5f"]
                + [bytes((0x10, value)) for value in transitions]
                + [b"\x27\x01\x04", b"\x27\x02" + encrypted],
            )
            self.assertEqual(
                comm.events[-5:],
                [
                    ("finalize",),
                    ("native_rva:121d0", 73),
                    ("native_rva:11f50", 0),
                    ("native_rva:11f60", 0),
                    ("target", 0x7E0, 9),
                ],
            )
        engine = self.engine()
        replies = [(0, b"\x7e\x00"), (0, b"\x50\x88")]
        replies += [(0, b"\x67\x01" + seed), (7, b""), (7, b"")] * 3
        replies += [(0, b"\x50\x01")]
        comm = Comm(replies)
        with (
            patch.object(engine.context, "comm", return_value=comm),
            patch.object(
                engine.context, "read_module_data", return_value=key + b"\x00"
            ),
        ):
            self.assertEqual(engine._cgw_security_ty18(), 10005)
        self.assertIsInstance(engine.context.host, Host)
        assert isinstance(engine.context.host, Host)
        self.assertEqual(engine.context.host.waits, [10000, 10000])
        for replies, expected in (
            ([(0, b"\x7e\x01")], 10001),
            ([(0, b""), (0, b"\x50")], 10002),
            ([(0, b""), (0, b"\x50\x01"), (7, b"")], 10003),
            ([(0, b""), (0, b"\x50\x09"), (7, b"")], 10004),
            ([(0, b""), (0, b"\x50\x88")] + [(7, b"")] * 3 + [(7, b"")], 10006),
            (
                [(0, b""), (0, b"\x50\x88")]
                + [(7, b"")] * 3
                + [(0, b"\x50\x09"), (7, b"")],
                10007,
            ),
        ):
            comm = Comm(replies)
            with patch.object(engine.context, "comm", return_value=comm):
                self.assertEqual(engine._cgw_security_ty18(), expected)
            self.assertEqual(comm.events[-1], ("target", 0x7E0, 9))
        failure = OSError("authored SDK failure")
        comm = Comm([failure])
        with (
            patch.object(engine.context, "comm", return_value=comm),
            self.assertRaises(OSError) as caught,
        ):
            engine._cgw_security_ty18()
        self.assertIs(caught.exception, failure)
        self.assertEqual(comm.events[-1], ("target", 0x7E0, 9))

    def test_nk96_any_mode_and_ordered_byte_constant_store_schema(self):
        from scripts import utility_ex as kernel

        require_private("runtime/no-car-83")
        helpers = runpy.run_path("runtime/no-car-83/bind_wrapper_packets.py")
        mode = helpers["nk96_mode"]
        store_index = helpers["nk96_store_index"]
        self.assertEqual(mode({"mode_predicate": "any"}), ())
        self.assertEqual(mode({"mode_predicate": "context.mode in (4, 20)"}), (4, 20))
        self.assertEqual(store_index({"constant": 0, "width_bits": 8}, 1), -1)
        for invalid in (
            {"constant": 1, "width_bits": 8},
            {"constant": 0, "width_bits": 16},
            {"constant": 0, "width_bits": 8, "argument_index": 0},
            {"argument_index": 1},
        ):
            with self.assertRaises(AssertionError):
                store_index(invalid, 1)
        engine = self.engine()
        engine.context._parameters[0x6F] = 4
        first, second, untouched = (
            "native_global:1014a694",
            "native_global:1014a695",
            "native_global:1014a696",
        )
        engine.context.state.update({first: 255, second: 255, untouched: 73})
        output = bytearray(1)
        export = "Ex2ABS_01_BeginSolenoidDrive"
        writes = (
            (first, -1, None, None),
            (second, -1, None, None),
            ("native_global:1014a5b0", 0, None, None),
        )
        with (
            patch.dict(SOURCES, {engine.context.module_sha256: "NK18"}),
            patch.dict(kernel._NK_PRE_MODE_ARGUMENT_WRITES, {("NK18", export): writes}),
        ):
            self.assertEqual(engine.invoke(export, (output,)), 99)
        self.assertEqual(
            (engine.context.state[first], engine.context.state[second]), (0, 0)
        )
        self.assertEqual(engine.context.state[untouched], 73)
        self.assertIs(engine.context.state["native_global:1014a5b0"], output)

    def test_cgw_void_export_and_machine_eax_are_distinct(self):
        engine = self.engine()
        release = threading.Event()
        engine._cgw_security_ty18 = lambda: (release.wait(2) and 10005) or 10005
        with patch.dict(SOURCES, {engine.context.module_sha256: "TY18"}):
            try:
                self.assertEqual(
                    engine.invoke_machine("_Ex2ComSecurityAccessCGW@0"), 15
                )
                self.assertEqual(
                    engine.invoke_machine("_Ex2ComSecurityAccessCGW@0"), 16
                )
                self.assertIsNone(engine.invoke("_Ex2ComSecurityAccessCGW@0"))
                with self.assertRaises(ValueError):
                    engine.invoke_machine("_Ex2ComSecurityAccessCGW@0", (1,))
            finally:
                release.set()
                self.assertEqual(engine.worker.stop(), 10005)

    def test_ty_unconditional_void_wrapper_keeps_worker_status_and_buffer(self):
        engine = self.engine()
        export = "Ex2PLG_01_FinalCom"
        output = bytearray(1)
        seen = []
        engine.context._parameters[0x6F] = 0xFFFFFFFF
        engine.supported_bodies = lambda: (export,)
        engine.run_body = lambda export, args=(): seen.append(args[0]) or 71
        with patch.dict(SOURCES, {engine.context.module_sha256: "TY18"}):
            self.assertIsNone(engine.invoke(export, (output,)))
            self.assertEqual(engine.worker.get_status(), 71)
            self.assertIs(seen[0], output)
            with self.assertRaises(ValueError):
                engine.invoke(export)

    def test_ty_thread_wrapper_preserves_output_reference(self):
        engine = self.engine()
        engine.context._parameters[0x6F] = 20
        output = bytearray(1)
        seen = []
        engine.supported_bodies = lambda: ("Ex2ECD_59_Dummy",)

        def body(export, args=()):
            seen.append(args[0])
            return 1001

        engine.run_body = body
        with patch.dict(SOURCES, {engine.context.module_sha256: "TY18"}):
            self.assertEqual(engine.start_export("Ex2ECD_59_Dummy", (output,)), 15)
            self.assertEqual(engine.worker.get_status(), 1001)
            self.assertIs(seen[0], output)
            with self.assertRaises(ValueError):
                engine.invoke("Ex2ECD_59_Dummy")
            engine.context._parameters[0x6F] = 4
            self.assertEqual(engine.invoke("Ex2ECD_59_Dummy", (output,)), 99)

    def test_abs29_public_wrappers_admit_exact_ty18_and_plus_pairs(self):
        root = Path(__file__).resolve().parents[1]
        images = {
            "TY18": root
            / "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            "TYPlus": root
            / "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
        }
        exports = ("Ex2ABS_29_SupportCheck", "Ex2ABS_29_ShiftDealerMode")
        for source, image in images.items():
            for export in exports:
                with self.subTest(source=source, export=export):
                    require_private(image)
                    self.assertEqual(_TY_THREAD_WRAPPERS[source][export], (0, 10000))
                    for mode in (20, 21):
                        host = Host()
                        host.values[0x6F] = mode
                        context = UtilityExContext(image.read_bytes(), host, None, None)
                        engine = UtilityEx2TY(context)
                        body_calls = []
                        engine.run_body = lambda export, args=(), calls=body_calls: (
                            calls.append((export, args)) or 47
                        )
                        self.assertIn(export, engine.supported_bodies())
                        with self.assertRaises(ValueError):
                            engine.invoke(export, (bytearray(),))
                        self.assertEqual(engine.invoke(export), 15)
                        self.assertEqual(engine.worker.get_status(), 47)
                        self.assertEqual(body_calls, [(export, ())])
                        context._parameters[0x6F] = 4
                        self.assertEqual(engine.invoke(export), 99)

    def test_newer_nk_end_erase_cannot_inherit_older_argument_abi(self):
        for source in ("NKDS4", "NKPlus"):
            engine = self.engine()
            engine.context._parameters[0x6F] = 3
            seen = []

            def body(export, args=(), seen=seen):
                seen.append(args)
                return 0

            engine.run_body = body
            with patch.dict(SOURCES, {engine.context.module_sha256: source}):
                with self.assertRaises(ValueError):
                    engine.invoke("Ex2SMRT_32_EndEraseMode", (0,))
                self.assertEqual(engine.invoke("Ex2SMRT_32_EndEraseMode"), 0)
                self.assertEqual(seen, [()])

    def test_owner97_wrapper_body_anchors_and_bound_contracts(self):
        root = Path(__file__).resolve().parents[1]
        packets = [
            root / f"analysis/evidence/no-car-83/ty-owner{owner}-wrapper-import.json"
            for owner in (
                83,
                97,
                101,
                102,
                103,
                111,
                115,
                116,
                117,
                118,
                120,
                121,
                122,
                123,
                124,
                125,
                126,
                127,
                128,
                129,
                130,
                131,
            )
        ]
        if not all(packet.exists() for packet in packets):
            self.skipTest("Private source-bound owner packet unavailable")
        for row in [
            row for packet in packets for row in json.loads(packet.read_text())["rows"]
        ]:
            with self.subTest(export=row["export"], source=row["source_sha256"]):
                if row["dispatch"] in ("thread", "conditional"):
                    self.assertEqual(
                        _TY_THREAD_WRAPPERS[SOURCES[row["source_sha256"]]][
                            row["export"]
                        ],
                        (row["arity"], row["timeout_ms"]),
                    )
                    self.assertEqual(
                        _TY_MODE_OVERRIDES.get(
                            (SOURCES[row["source_sha256"]], row["export"]), (20, 21)
                        ),
                        tuple(row["modes"]),
                    )
                    if row["export"] in (
                        "Ex2MS2MM_01_SendMessage",
                        "Ex2MS2BSRL_01_SendMessage",
                    ):
                        self.assertIn("== 0x34", (root / row["c_path"]).read_text())
                        self.assertEqual(tuple(row["modes"]), (52,))
                for node in (
                    [row]
                    + row.get("branches", [])
                    + row.get("callbacks", [])
                    + row.get("additional_callbacks", [])
                    + row.get("callback_branches", [])
                    + row.get("conditional_branches", [])
                ):
                    for prefix in ("", "body_"):
                        for suffix in ("c", "asm"):
                            key = f"{prefix}{suffix}_path"
                            if key in node and node[key] is not None:
                                self.assertEqual(
                                    hashlib.sha256(
                                        (root / node[key]).read_bytes()
                                    ).hexdigest(),
                                    node[f"{prefix}{suffix}_sha256"],
                                )

    def test_owner96_exact_variant_wrapper_contracts(self):
        root = Path(__file__).resolve().parents[1]
        packet = root / "analysis/evidence/no-car-83/nk-owner96-wrapper-import.json"
        if not packet.exists():
            self.skipTest("Private source-bound owner packet unavailable")
        for variant in json.loads(packet.read_text())["variants"]:
            source = SOURCES[variant["module_sha256"]]
            for row in variant["wrapper_descriptors"]:
                with self.subTest(source=source, export=row["export"]):
                    contract = _NK_VARIANT_WRAPPERS.get(source, {}).get(
                        row["export"], _NK_WRAPPERS.get(row["export"])
                    )
                    self.assertIsNotNone(contract)
                    assert contract is not None
                    prefix = (
                        "context.mode "
                        if "mode_argument_index" not in row
                        else f"args[{row['mode_argument_index']}] "
                    )
                    predicate = row["mode_predicate"].removeprefix(prefix)
                    self.assertIn(predicate.split()[0], ("==", "in"))
                    self.assertEqual(
                        contract[0], ast.literal_eval(predicate.split(maxsplit=1)[1])
                    )
                    self.assertEqual(contract[1], row["scheduler_kind"])
                    self.assertEqual(contract[2], row["timeout_ms"])
                    self.assertEqual(contract[3], len(row["arguments"]))
                    self.assertEqual(contract[4], row["return_kind"] == "void")
                    for anchor in row["source"]:
                        self.assertEqual(
                            hashlib.sha256(
                                (root / anchor["path"]).read_bytes()
                            ).hexdigest(),
                            anchor["sha256"],
                        )

    def test_selected_cmn_busy_call_updates_actual_shared_fields_before_rejection(self):
        from scripts.utility_ex_lifecycle import UtilityExSelectedCMNFields

        bases = {
            "NK12": 0x100E5DD8,
            "NK18": 0x1014AA40,
            "NKDS4": 0x101B1E70,
            "NKPlus": 0x101BCF70,
        }
        for source, base in bases.items():
            engine = self.engine()
            engine.context.module_sha256 = next(
                sha for sha, label in SOURCES.items() if label == source
            )
            release = threading.Event()
            engine.worker.start(
                lambda release=release: (release.wait(2) and 7) or 7, 10000
            )
            try:
                self.assertEqual(
                    engine.context.start_selected_cmn(2000, 1, b"\x3e\x00", 2), 16
                )
                fields = engine.context.state["utility_ex:selected_cmn_fields"]
                self.assertIsInstance(fields, UtilityExSelectedCMNFields)
                assert isinstance(fields, UtilityExSelectedCMNFields)
                self.assertEqual(
                    (
                        fields.interval_ms,
                        fields.request_length,
                        fields.skip_response_validation,
                    ),
                    (2000, 2, 1),
                )
                self.assertEqual(fields.request[:2], b"\x3e\x00")
                self.assertEqual(engine.context.state[f"native_global:{base:x}"], 2000)
                self.assertEqual(
                    engine.context.state[f"native_global:{base + 0x110:x}"], 2
                )
                self.assertEqual(engine.context.start_selected_cmn(4000), 16)
                self.assertIs(
                    engine.context.state["utility_ex:selected_cmn_fields"], fields
                )
                self.assertEqual(fields.request_length, 0)
                self.assertEqual(fields.request[:2], b"\x3e\x00")
                self.assertEqual(fields.interval_ms, 4000)
                controlled_base = {
                    "NK12": 0x100E5EF0,
                    "NK18": 0x1014AB58,
                    "NKDS4": 0x101B1D58,
                    "NKPlus": 0x101BCE58,
                }[source]
                self.assertEqual(
                    engine.context.start_selected_cmn_controlled(
                        3000, 1, 0, b"\x21", 1
                    ),
                    16,
                )
                controlled = engine.context.state[
                    "utility_ex:selected_cmn_fields:controlled"
                ]
                self.assertIsInstance(controlled, UtilityExSelectedCMNFields)
                assert isinstance(controlled, UtilityExSelectedCMNFields)
                self.assertIsNot(controlled, fields)
                self.assertEqual(controlled.request[:2], b"\x21\x00")
                self.assertEqual(
                    (controlled.finalize_on_exit, controlled.stop_on_error), (1, 1)
                )
                self.assertEqual(
                    engine.context.state[f"native_global:{controlled_base + 4:x}"], 1
                )
                self.assertEqual(fields.interval_ms, 4000)
                self.assertEqual(fields.request_length, 0)
                engine.context._parameters[0x6F] = 4
                engine.context._parameters[0x70] = 17
                self.assertIsNone(engine.invoke("Ex2STR_41_StartKeepAlive"))
                self.assertEqual(engine.invoke("Ex2STR_42_StartKeepAlive"), 16)
                engine.context._parameters[0x70] = 0
                fields.interval_ms = 77
                self.assertIsNone(engine.invoke("Ex2STR_41_StartKeepAlive"))
                self.assertEqual(fields.interval_ms, 77)
            finally:
                release.set()
                self.assertEqual(engine.worker.stop(), 7)

    def test_absent_nk12_native_void_export_never_returns_synthetic_success(self):
        engine = self.engine()
        with patch.dict(SOURCES, {engine.context.module_sha256: "NK12"}):
            for mode in (0, 4):
                engine.context._parameters[0x6F] = mode
                with self.assertRaises(LookupError):
                    engine.invoke("_Ex2STR_43_StartKeepAliveThread@4", (bytearray(4),))

    def test_ecd_keepalive_mode_is_unrestricted_but_broker_protocol_is_guarded(self):
        export = "Ex2ECD_09_StartKeepAlive"
        for source in ("NK12", "NK18", "NKDS4", "NKPlus"):
            engine = self.engine()
            engine.supported_bodies = lambda: (export,)
            engine.run_body = lambda export, args=(): 0
            engine.context._parameters[0x6F] = 0xFFFFFFFF
            with patch.dict(SOURCES, {engine.context.module_sha256: source}):
                for protocol in (17, 33, 81):
                    engine.context._parameters[0x70] = protocol
                    self.assertEqual(engine.invoke(export), 0)
                engine.context._parameters[0x70] = 18
                self.assertEqual(engine.invoke(export), 99)

    def test_native_void_thread_starts_callback_but_exposes_no_status_return(self):
        export = "_Ex2STR_43_StartKeepAliveThread@4"
        for source in ("NK18", "NKDS4", "NKPlus"):
            engine = self.engine()
            engine.supported_bodies = lambda: (export,)
            engine.run_body = lambda export, args=(): 71
            output = bytearray(4)
            engine.context._parameters[0x6F] = 4
            with patch.dict(SOURCES, {engine.context.module_sha256: source}):
                self.assertIsNone(engine.invoke(export, (output,)))
                self.assertEqual(engine.worker.get_status(), 71)
                self.assertEqual(engine.worker.timeout_ms, 10000)
                engine.context._parameters[0x6F] = 0
                self.assertIsNone(engine.invoke(export, (output,)))

    def test_smrt48_argument_mode_guard_is_independent_of_context_mode(self):
        engine = self.engine()
        export = "Ex2SMRT_48_ReadVINCode"
        output = bytearray(32)
        engine.supported_bodies = lambda: (export,)
        engine.run_body = lambda export, args=(): 71
        for source in ("NK18", "NKDS4", "NKPlus"):
            with patch.dict(SOURCES, {engine.context.module_sha256: source}):
                engine.context._parameters[0x6F] = 3
                for argument in (4, 20):
                    self.assertEqual(engine.invoke(export, (argument, output)), 15)
                    self.assertEqual(engine.worker.stop(), 71)
                engine.context._parameters[0x6F] = 4
                self.assertEqual(engine.invoke(export, (3, output)), 99)
                with self.assertRaises(ValueError):
                    engine.invoke(export, (4,))

    def test_native_str_after_copies_output_pointers_before_mode_rejection(self):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-83")
        engine = self.engine()
        first, second = bytearray(4), bytearray(4)
        packet = json.loads(
            (
                root / "analysis/evidence/no-car-83/nk-owner95-wrapper-import.json"
            ).read_text()
        )
        for row in packet["rows"]:
            fields = row.get("pre_mode_guard_argument_globals") or row.get(
                "wrapper_argument_globals_before_mode_guard"
            )
            if not fields:
                continue
            source = SOURCES[row["module_sha256"]]
            engine.context._parameters[0x6F] = 0
            with patch.dict(SOURCES, {engine.context.module_sha256: source}):
                self.assertEqual(
                    engine.invoke(
                        row["export"],
                        tuple(
                            [first, second]
                            + [
                                bytearray(4)
                                for _ in range(row["native_argument_arity"] - 2)
                            ]
                        ),
                    ),
                    99,
                )
            for field, value in zip(fields, (first, second)):
                self.assertIs(engine.context.state["native_global:" + field], value)

    def test_str_permuted_and_zero_wrapper_stores_precede_mode_guard(self):
        engine = self.engine()
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-83")
        packet = json.loads(
            (
                root / "analysis/evidence/no-car-83/nk-owner95-wrapper-import.json"
            ).read_text()
        )
        checked = 0
        for row in packet["rows"]:
            stores = row.get("wrapper_stores_before_mode_guard")
            if not stores:
                continue
            args = tuple(
                bytearray([index]) for index in range(row["native_argument_arity"])
            )
            source = SOURCES[row["module_sha256"]]
            engine.context._parameters[0x6F] = 0
            with patch.dict(SOURCES, {engine.context.module_sha256: source}):
                self.assertEqual(engine.invoke(row["export"], args), 99)
            for field, value in stores:
                actual = engine.context.state["native_global:" + field]
                if value == "0":
                    self.assertEqual(actual, 0)
                else:
                    self.assertIs(actual, args[int(value.removeprefix("param_")) - 1])
            checked += 1
        self.assertGreaterEqual(checked, 12)

    def test_smrt41_conditional_pointer_globals_precede_mode_guard(self):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-83")
        packet = json.loads(
            (
                root / "analysis/evidence/no-car-83/nk-owner96-wrapper-import.json"
            ).read_text()
        )
        for variant in packet["variants"]:
            source = SOURCES[variant["module_sha256"]]
            row = next(
                r
                for r in variant["wrapper_descriptors"]
                if r["export"] == "Ex2SMRT_41_Online_Certification"
            )
            for flag in (0, 1):
                engine = self.engine()
                engine.context._parameters[0x6F] = 3
                old = object()
                for write in row["pre_mode_guard_argument_globals"]:
                    engine.context.state[write["field"]] = old
                args = (1, 2, 3, 4, 5, 6, 7, bytearray(b"metadata"), flag)
                with patch.dict(SOURCES, {engine.context.module_sha256: source}):
                    self.assertEqual(engine.invoke(row["export"], args), 99)
                for write in row["pre_mode_guard_argument_globals"]:
                    condition = write.get("when")
                    selected = not condition or (
                        (flag != 0) if "not_equals" in condition else (flag == 0)
                    )
                    self.assertIs(
                        engine.context.state[write["field"]],
                        args[write["argument_index"]] if selected else old,
                    )

    def test_ms2_wrappers_use_native_mode52_instead_of_mode20(self):
        for source in ("TY18", "TYPlus"):
            for export, args in (
                ("Ex2MS2MM_01_SendMessage", ()),
                ("Ex2MS2BSRL_01_SendMessage", (bytearray(16),)),
            ):
                engine = self.engine()
                engine.supported_bodies = lambda export=export: (export,)
                engine.run_body = lambda export, args=(): 123
                with patch.dict(SOURCES, {engine.context.module_sha256: source}):
                    engine.context._parameters[0x6F] = 20
                    self.assertEqual(engine.invoke(export, args), 99)
                    engine.context._parameters[0x6F] = 52
                    self.assertEqual(engine.invoke(export, args), 15)
                    self.assertEqual(engine.worker.get_status(), 123)

    def test_plus_abs50_wrapper_preserves_native_mode20_and22_branches(self):
        engine = self.engine()
        export = "Ex2ABS_50_ECBProhibitionControl"
        engine.supported_bodies = lambda: (export,)
        engine.run_body = lambda export, args=(): engine.context.mode
        with patch.dict(SOURCES, {engine.context.module_sha256: "NKPlus"}):
            for mode in (20, 22):
                engine.context._parameters[0x6F] = mode
                self.assertEqual(engine.invoke(export), 15)
                self.assertEqual(engine.worker.get_status(), mode)
            engine.context._parameters[0x6F] = 21
            self.assertEqual(engine.invoke(export), 99)


class SuppliedSourceTests(unittest.TestCase):
    def test_sol_admitted_str52_exact16_wrapper_metadata(self):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-95")
        packet_path = root / "analysis/evidence/no-car-95/str52-wrapper-packet.json"
        verdict_path = (
            root / "analysis/evidence/no-car-95/sol-review/component-verdict.json"
        )
        packet = json.loads(packet_path.read_text())
        verdict = json.loads(verdict_path.read_text())
        self.assertEqual(
            hashlib.sha256(packet_path.read_bytes()).hexdigest(),
            verdict["candidate_packet_sha256"],
        )
        self.assertEqual(
            verdict["verdict"], "PASS_EXACT16_COMPONENT_METADATA_ADMISSION"
        )
        self.assertEqual(len(packet["rows"]), 16)

        for row in packet["rows"]:
            source = SOURCES[row["module_sha256"]]
            export = row["export"]
            mode_values = row["mode_predicate"]["values"]
            mode = mode_values[0] if len(mode_values) == 1 else tuple(mode_values)
            expected = (
                mode,
                "thread",
                row["timeout_ms"],
                row["argument_count"],
                False,
                False,
            )
            self.assertEqual(_NK_VARIANT_WRAPPERS[source][export], expected)
            self.assertIn(source, _NK_WRAPPER_SOURCE_LIMITS[export])
            writes = tuple(
                (
                    f"native_global:{int(address, 16):x}",
                    int(argument.rsplit("_", 1)[1]) - 1,
                    None,
                    None,
                )
                for address, argument in row["ordered_stores_before_mode_and_busy"]
            )
            self.assertEqual(
                _NK_PRE_MODE_ARGUMENT_WRITES.get((source, export), ()), writes
            )

    def test_sol_admitted_abs52_exact_plus_wrapper_rows(self):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-102")
        packet_path = root / "analysis/evidence/no-car-102/reviewed-wrapper-packet.json"
        review_path = root / "analysis/evidence/no-car-102/sol-review/abs52-review.json"
        packet = json.loads(packet_path.read_text())
        review = json.loads(review_path.read_text())
        self.assertEqual(
            hashlib.sha256(packet_path.read_bytes()).hexdigest(),
            review["reviewed_sha256"][
                "analysis/evidence/no-car-102/reviewed-wrapper-packet.json"
            ],
        )
        rows = [
            row
            for row in packet["rows"]
            if row["source_sha256"]
            == "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce"
            and row["export"]
            in (
                "Ex2ABS_52_ReadBrakePadResidualThickness",
                "Ex2ABS_52_WriteBrakePadResidualThickness",
            )
        ]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["modes"], [20, 21])
            self.assertEqual(row["dispatch"], "thread")
            self.assertEqual((row["arity"], row["timeout_ms"]), (1, 10000))
            self.assertEqual(_TY_THREAD_WRAPPERS["TYPlus"][row["export"]], (1, 10000))
            for path_key, hash_key in (
                ("c_path", "c_sha256"),
                ("asm_path", "asm_sha256"),
                ("body_c_path", "body_c_sha256"),
                ("body_asm_path", "body_asm_sha256"),
            ):
                self.assertEqual(
                    hashlib.sha256((root / row[path_key]).read_bytes()).hexdigest(),
                    row[hash_key],
                )

    def test_sol_admitted_smrt55_exact21_metadata_and_all_anchors(self):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-96")
        packet_path = root / "analysis/evidence/no-car-96/smrt55-wrapper-candidate.json"
        verdict_path = (
            root
            / "analysis/evidence/no-car-96/sol-review/smrt55-admission-verdict.json"
        )
        handoff_path = root / "analysis/evidence/no-car-96/smrt55-decoded-handoff.json"
        packet = json.loads(packet_path.read_text())
        verdict = json.loads(verdict_path.read_text())
        handoff = json.loads(handoff_path.read_text())
        self.assertEqual(
            hashlib.sha256(packet_path.read_bytes()).hexdigest(),
            verdict["candidate_packet_sha256"],
        )
        self.assertEqual(
            verdict["reviewed_body_sha256"], packet["product_body"]["sha256"]
        )
        self.assertEqual(
            hashlib.sha256(
                (root / packet["product_body"]["path"]).read_bytes()
            ).hexdigest(),
            packet["product_body"]["sha256"],
        )
        self.assertEqual(len(packet["variants"]), 3)
        self.assertEqual(verdict["source_anchors_verified"], 124)

        pins = []

        def collect(value):
            if isinstance(value, dict):
                if isinstance(value.get("path"), str) and isinstance(
                    value.get("sha256"), str
                ):
                    pins.append(value)
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        collect(handoff)
        self.assertEqual(len(pins), 124)
        for pin in pins:
            self.assertEqual(
                hashlib.sha256((root / pin["path"]).read_bytes()).hexdigest(),
                pin["sha256"],
            )

        for variant in packet["variants"]:
            source = variant["name"]
            if source == "DS4":
                source = "NKDS4"
            elif source == "Plus":
                source = "NKPlus"
            for row in variant["exports"]:
                export = row["export"]
                contract = (
                    20,
                    row["dispatch"],
                    row["timeout_ms"],
                    row["consumed_arity"],
                    False,
                    False,
                )
                self.assertEqual(_NK_VARIANT_WRAPPERS[source][export], contract)
                self.assertIn(source, _NK_WRAPPER_SOURCE_LIMITS[export])
                if row["mode_predicate"] == "any":
                    self.assertTrue(_NK_ANY_MODE_WRAPPERS[(source, export)])
                writes = tuple(
                    (
                        item["field"],
                        -1 if "constant" in item else item["argument_index"],
                        None,
                        None,
                    )
                    for item in row.get("pre_mode_guard_argument_globals", [])
                )
                self.assertEqual(
                    _NK_PRE_MODE_ARGUMENT_WRITES.get((source, export), ()), writes
                )

    def test_actual_nk18_timer_exports_preserve_config_raw_timer_and_shared_status(
        self,
    ):
        context = self.nk_context()
        calls = []

        def start(hwnd, identifier, interval, callback):
            calls.append(("set", hwnd, identifier, interval))
            return 73

        def stop(hwnd, identifier):
            calls.append(("kill", hwnd, identifier))
            return 1

        context.win32_exports = {"SetTimer": start, "KillTimer": stop}
        engine = UtilityExEngine(context)
        self.assertIsNone(
            engine.invoke(
                "Ex2SetKeepAliveThread",
                (2000, bytearray(b"\x3e\x00extra"), 2, 2, 0x1F0, 1),
            )
        )
        self.assertEqual(
            context.state["native_bytes:10151894"], b"\x3e\x00" + bytes(0x101E)
        )
        self.assertEqual(context.state["native_global:101490e8"], 0xF0)
        self.assertIsNone(engine.invoke("Ex2StartKeepAliveThread"))
        self.assertEqual(calls, [("kill", 0, 0), ("set", 0, 0, 2000)])
        self.assertEqual(engine.invoke("Ex2GetKeepAliveStatus"), 15)
        context.state["native_global:101528b4"] = 7
        self.assertEqual(engine.invoke("Ex2GetKeepAliveStatus"), 7)
        self.assertIsNone(engine.invoke("Ex2StopKeepAliveThread", (0,)))
        self.assertEqual(calls[-1], ("kill", 0, 73))
        self.assertEqual(context.state["native_global:10151890"], 1)
        with self.assertRaises(ValueError):
            engine.invoke("Ex2SetKeepAliveThread", (2000, None, 1, 2, 0xF0, 1))

    def test_actual_str53_worker_entry_observes_busy_overwritten_native_references(
        self,
    ):
        context = self.nk_context()
        engine = UtilityExEngine(context)
        export = "Ex2STR_53_GetKeyStatus"

        class Comm:
            def configure(self, field, value):
                pass

            def exchange(self, request):
                return (
                    (0, b"\x61\x11\x20")
                    if request == b"\x21\x11"
                    else (0, b"\x61\x17\xa5")
                )

            def finalize(self):
                raise AssertionError("Native successful key query retains session")

        first = (bytearray(4), bytearray([0xCC]), bytearray([0xDD]))
        second = (bytearray(4), bytearray([0xEE]), bytearray([0xFF]))
        entered, release = threading.Event(), threading.Event()
        original_thread = threading.Thread

        def delayed_thread(*args, **kwargs):
            target = kwargs["target"]

            def delayed():
                entered.set()
                release.wait(2)
                target()

            kwargs["target"] = delayed
            return original_thread(*args, **kwargs)

        with (
            patch.object(context, "comm", return_value=Comm()),
            patch("scripts.utility_ex.threading.Thread", side_effect=delayed_thread),
        ):
            try:
                self.assertEqual(engine.invoke(export, first), 15)
                self.assertTrue(entered.wait(1))
                self.assertEqual(engine.invoke(export, second), 16)
                release.set()
                self.assertEqual(engine.worker.get_status(), 0)
                self.assertEqual((first[1], first[2]), (b"\xcc", b"\xdd"))
                self.assertEqual((second[1], second[2]), (b"\x0a", b"\x05"))
                self.assertIs(context.state["native_global:1014a7b4"], second[1])
            finally:
                release.set()
                engine.worker.stop()

    def test_all8_generic_timer_export_abi_and_shared_native_status(self):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-83")
        packet = json.loads(
            (
                root / "analysis/evidence/no-car-83/all8-timer-export-source.json"
            ).read_text()
        )
        queue = {
            row["sha256"]: row
            for row in json.loads(
                (root / "analysis/evidence/no-car-83/source-queue.json").read_text()
            )
        }
        for row in packet["rows"]:
            with self.subTest(source=row["source_sha256"]):
                for anchor in row["anchors"]:
                    self.assertEqual(
                        hashlib.sha256(
                            (root / anchor["path"]).read_bytes()
                        ).hexdigest(),
                        anchor["sha256"],
                    )
                context = UtilityExContext(
                    (root / queue[row["source_sha256"]]["input_path"]).read_bytes(),
                    Host(),
                    None,
                    None,
                )
                context.win32_exports = {
                    "SetTimer": lambda *args: 73,
                    "KillTimer": lambda *args: 1,
                }
                engine = UtilityExEngine(context)
                self.assertIsNone(
                    engine.invoke(
                        "Ex2SetKeepAliveThread", (2000, b"\x3e\x00", 2, 2, 0xF0, 1)
                    )
                )
                self.assertIsNone(engine.invoke("Ex2StartKeepAliveThread"))
                self.assertEqual(engine.invoke("Ex2GetKeepAliveStatus"), 15)
                context.state[f"native_global:{row['native_status_global']:x}"] = 7
                self.assertEqual(engine.invoke("Ex2GetKeepAliveStatus"), 7)
                self.assertIsNone(engine.invoke("Ex2StopKeepAliveThread", (0,)))

    def test_actual_ty18_controller_initialize_keeps_mode20_and_raw_sdk_status(self):
        context = self.context()
        calls = []

        def initialize(kind, output):
            calls.append(("initialize", kind))
            output[:] = (73).to_bytes(4, "little")
            return PrimitiveResult(status=17)

        def finalize():
            calls.append(("finalize",))
            return PrimitiveResult(status=9)

        context.driver_exports = {
            "J2534CtrlInitialize": initialize,
            "J2534CtrlFinalize": finalize,
        }
        engine = UtilityExEngine(context)
        context._parameters[0x6F] = 20
        self.assertEqual(engine.invoke("Ex2Initialize"), 17)
        self.assertEqual(calls, [("initialize", 1)])
        self.assertEqual(context.state["native_global:1011f768"], 0)
        self.assertEqual(set(context._drivers), {4, 6, 1})
        self.assertEqual(engine.invoke("Ex2Finalize"), 9)
        self.assertEqual(calls, [("initialize", 1), ("finalize",)])
        self.assertNotIn(f"utility_ex:can_pool:{context.module_sha256}", context.state)
        self.assertIsNone(
            context.state.get(f"utility_ex:sis_driver:{context.module_sha256}")
        )
        context._parameters[0x6F] = 4
        self.assertEqual(engine.invoke("Ex2Finalize"), 9)
        self.assertEqual(calls[-1], ("finalize",))

    def test_actual_ty18_doip_initialize_selects_exact_controller2_only20_20(self):
        from scripts.utility_ex_lifecycle import UtilityExSISDriver

        context = self.context()
        calls = []

        def initialize(kind, output):
            calls.append(kind)
            output[:] = (73).to_bytes(4, "little")
            return PrimitiveResult(status=17)

        exports: dict[str, Callable[..., object]] = {
            name: lambda *args: PrimitiveResult(status=0)
            for name in _SIS_DRIVER_SLOTS.values()
        }
        exports["J2534CtrlInitialize"] = initialize
        context.sis_driver_exports = exports
        engine = UtilityExEngine(context)
        for mode, broker in ((4, 20), (20, 17)):
            context._parameters[0x6F], context._parameters[0x70] = mode, broker
            self.assertIsNone(engine.invoke("_Ex2InitializeDoIP@0"))
        self.assertEqual(calls, [])
        context._parameters[0x6F] = context._parameters[0x70] = 20
        self.assertIsNone(engine.invoke("_Ex2InitializeDoIP@0"))
        self.assertEqual(calls, [2])
        driver = context.state[f"utility_ex:sis_driver:{context.module_sha256}"]
        self.assertIsInstance(driver, UtilityExSISDriver)
        assert isinstance(driver, UtilityExSISDriver)
        self.assertEqual(driver.controller, 73)
        self.assertIsNone(engine.invoke("_Ex2InitializeDoIP@0"))
        self.assertIs(
            context.state[f"utility_ex:sis_driver:{context.module_sha256}"], driver
        )
        self.assertEqual(calls, [2, 2])
        with self.assertRaises(ValueError):
            engine.invoke("_Ex2InitializeDoIP@0", (0,))

    def test_actual_typlus_doip_initialize_uses_three_argument_controller(self):
        from scripts.utility_ex_lifecycle import UtilityExSISDriver

        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-83")
        contract = json.loads(
            (
                root
                / "analysis/evidence/no-car-83/sol-review/plus-doip-export-source-contract.json"
            ).read_text()
        )
        for anchor in contract["anchors"]:
            self.assertEqual(
                hashlib.sha256((root / anchor["path"]).read_bytes()).hexdigest(),
                anchor["sha256"],
            )
        context = self.plus_context(
            "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce"
        )
        calls = []

        def initialize(*args):
            calls.append(args)
            self.assertEqual(len(args), 3)
            self.assertEqual((args[0], args[2]), (2, 0))
            self.assertIs(type(args[1]), bytearray)
            args[1][:] = (73).to_bytes(4, "little")
            return PrimitiveResult(status=17)

        context.sis_driver_exports = {
            name: lambda *args: PrimitiveResult(status=0)
            for name in _SIS_DRIVER_SLOTS.values()
        }
        context.sis_driver_exports["J2534CtrlInitialize"] = initialize
        engine = UtilityExEngine(context)
        for mode, protocol in ((20, 18), (21, 20)):
            context.state["native_global:1013fa40"] = mode
            context.state["native_global:1013fa44"] = protocol
            context.state["native_global:10135be4"] = 99
            self.assertIsNone(engine.invoke("Ex2InitializeDoIP"))
            self.assertEqual(context.state["native_global:10135be4"], 0)
        self.assertEqual(calls, [])

        context.state["native_global:1013fa40"] = 20
        context.state["native_global:1013fa44"] = 20
        self.assertIsNone(engine.invoke("Ex2InitializeDoIP"))
        driver = context.state[f"utility_ex:sis_driver:{context.module_sha256}"]
        self.assertIsInstance(driver, UtilityExSISDriver)
        assert isinstance(driver, UtilityExSISDriver)
        self.assertEqual(driver.controller, 73)
        self.assertIsNone(engine.invoke("Ex2InitializeDoIP"))
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0::2], (2, 0))
        self.assertEqual([bytes(call[1]) for call in calls], [b"I\0\0\0"] * 2)
        context.state["native_global:10135be4"] = 44
        with self.assertRaises(ValueError):
            engine.invoke("Ex2InitializeDoIP", (0,))
        self.assertEqual(context.state["native_global:10135be4"], 44)

        other = self.plus_context(context.module_sha256)
        other.sis_driver_exports = context.sis_driver_exports
        foreign = UtilityExSISDriver(other, other.sis_driver_binding())
        context.state[f"utility_ex:sis_driver:{context.module_sha256}"] = foreign
        with self.assertRaisesRegex(TypeError, "same-context"):
            engine.invoke("Ex2InitializeDoIP")

    def test_actual_typlus_doip_initialize_preserves_host_exception_identity(self):
        context = self.plus_context(
            "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce"
        )
        failure = OSError("controller host fault")

        def initialize(kind, output, flags):
            self.assertEqual((kind, flags), (2, 0))
            raise failure

        exports: dict[str, Callable[..., object]] = {
            name: lambda *args: PrimitiveResult(status=0)
            for name in _SIS_DRIVER_SLOTS.values()
        }
        exports["J2534CtrlInitialize"] = initialize
        context.sis_driver_exports = exports
        context.state["native_global:1013fa40"] = 20
        context.state["native_global:1013fa44"] = 20
        with self.assertRaises(OSError) as caught:
            UtilityExEngine(context).invoke("Ex2InitializeDoIP")
        self.assertIs(caught.exception, failure)

    def test_ty18_sis_driver_table_has_independent_v0500_readiness(self):
        context = self.context()
        root = Path(__file__).resolve().parents[1]
        packet = json.loads(
            (
                root / "analysis/evidence/no-car-83/ty18-sis-driver-source.json"
            ).read_text()
        )
        for anchor in packet["anchors"]:
            self.assertEqual(
                hashlib.sha256((root / anchor["path"]).read_bytes()).hexdigest(),
                anchor["sha256"],
            )
        exports: dict[str, Callable[..., object]] = {
            name: lambda *args: PrimitiveResult(status=0)
            for name in _SIS_DRIVER_SLOTS.values()
        }
        binding = UtilitySISDriverBinding(context, exports)
        self.assertTrue(binding.ready)
        self.assertFalse(binding.base_ready)
        self.assertEqual((binding.protocol, binding.oem_protocol), (0x800F, 0x810F))
        for offset, name in _SIS_DRIVER_SLOTS.items():
            self.assertEqual(packet["all_required_slots"][hex(offset)], name)
            self.assertEqual(binding.slot_offset(name), offset)
            self.assertIs(binding.resolve(offset), exports[name])
            missing = dict(exports)
            del missing[name]
            self.assertFalse(UtilitySISDriverBinding(context, missing).ready)
        self.assertFalse(UtilitySISDriverBinding(context, exports, loaded=False).ready)
        context.sis_driver_exports = exports
        self.assertIs(context.sis_driver_binding(), context.sis_driver_binding())
        context.driver_exports = {
            name: lambda *args: PrimitiveResult(status=0)
            for name in _DRIVER_SLOTS.values()
        }
        self.assertIsNot(context.sis_driver_binding(), context.driver_binding(6))
        with self.assertRaises(LookupError):
            UtilitySISDriverBinding(self.nk_context(), exports)
        with self.assertRaises(LookupError):
            binding.resolve(0x1098)

    def test_sil_driver_constructor_parameter_has_distinct_singleton(self):
        context = self.nk_context()
        context.driver_exports = {
            name: lambda *args: PrimitiveResult(status=0)
            for name in _DRIVER_SLOTS.values()
        }
        ordinary = context.driver_binding(6)
        sil = context.driver_binding(6, constructor_parameter=0xD)
        self.assertIsNot(ordinary, sil)
        self.assertIs(context.driver_binding(6, constructor_parameter=0xD), sil)
        self.assertEqual(ordinary.constructor_parameter, 0)
        self.assertEqual(sil.constructor_parameter, 0xD)
        self.assertEqual((ordinary.oem_protocol, sil.oem_protocol), (0x106, 0x106))

    def test_all8_standard_driver_literal_tables_and_each_missing_symbol(self):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-83")
        packet = json.loads(
            (
                root / "analysis/evidence/no-car-83/driver-constructors-all8.json"
            ).read_text()
        )
        queue = json.loads(
            (root / "analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for row in packet["rows"]:
            for anchor in row["anchors"]:
                self.assertEqual(
                    hashlib.sha256((root / anchor["path"]).read_bytes()).hexdigest(),
                    anchor["sha256"],
                )
            supplied = next(
                item for item in queue if item["sha256"] == row["source_sha256"]
            )
            context = UtilityExContext(
                (root / supplied["input_path"]).read_bytes(), Host(), None, None
            )
            exports: dict[str, Callable[..., object]] = {
                name: lambda *args: PrimitiveResult(status=0)
                for name in _DRIVER_SLOTS.values()
            }
            binding = UtilityDriverBinding(context, 4, exports)
            self.assertTrue(binding.ready)
            self.assertEqual(binding.oem_protocol, 0x104)
            for offset, name in _DRIVER_SLOTS.items():
                self.assertEqual(row["slots"][hex(offset)], name)
                self.assertEqual(binding.slot_offset(name), offset)
                self.assertIs(binding.resolve(offset), exports[name])
                missing = dict(exports)
                del missing[name]
                self.assertFalse(UtilityDriverBinding(context, 4, missing).ready)
            unloaded = UtilityDriverBinding(context, 4, exports, loaded=False)
            self.assertFalse(unloaded.ready)
            self.assertTrue(all(value is None for value in unloaded.slots.values()))
            if SOURCES[context.module_sha256] in ("NK12", "TY12"):
                with self.assertRaises(LookupError):
                    binding.controller_initialize()

    def nk_imports(self, engine):
        root = Path(__file__).resolve().parents[1]
        caller = (
            root
            / "artifacts/extracted/techstream-18-application/Techstream_Bin/IT3UtilitySpNK.dll"
        )
        packet = root / "analysis/evidence/no-car-83/it3-import-source-bindings.json"
        if not caller.exists() or not packet.exists():
            self.skipTest("Optional supplied IT3 caller/import proof unavailable")
        binding = UtilityImportBinding(caller.read_bytes(), engine)
        slots = {
            row["target_exports"][0]["name"]: row["iat_rva"]
            for row in json.loads(packet.read_text())["rows"]
            if row["source_sha256"] == binding.caller_sha256
        }
        return binding, slots

    def nk_context(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll"
        )
        if not path.is_file():
            self.skipTest("Optional supplied original NK18 image unavailable")
        return UtilityExContext(path.read_bytes(), Host(), None, None)

    def test_actual_nk_common_controller_iat_lifecycle_and_incomplete_mode_guard(self):
        context = self.nk_context()
        calls = []

        def initialize(mode, output):
            calls.append(("initialize", mode))
            output[:] = (99).to_bytes(4, "little")
            return PrimitiveResult(status=7)

        def finalize():
            calls.append(("finalize",))
            return PrimitiveResult(status=9)

        context.driver_exports = {
            "J2534CtrlInitialize": initialize,
            "J2534CtrlFinalize": finalize,
        }
        imports, slots = self.nk_imports(UtilityExEngine(context))
        context.state["native_global:1015185c"] = 1
        self.assertEqual(imports.invoke_iat(slots["Ex2Initialize"]), 7)
        self.assertEqual(context.state["native_global:1015185c"], 0)
        self.assertEqual(set(context._drivers), {1, 4, 6})
        self.assertEqual(imports.invoke_iat(slots["Ex2Finalize"]), 9)
        self.assertEqual(calls, [("initialize", 1), ("finalize",)])
        context._parameters[0x6F] = 20
        with self.assertRaisesRegex(LookupError, "lifecycle"):
            imports.invoke_iat(slots["Ex2Initialize"])
        with self.assertRaisesRegex(LookupError, "lifecycle"):
            imports.invoke_iat(slots["Ex2Finalize"])
        self.assertEqual(len(calls), 2)

    def test_actual_nk_battery_voltage_boundaries_and_native_ignored_statuses(self):
        for voltage, expected in (
            (9999, 102),
            (10000, 101),
            (12000, 101),
            (16000, 101),
            (16001, 102),
        ):
            with self.subTest(voltage=voltage):
                context = self.nk_context()
                events = []

                def connect(protocol, flags, output, events=events):
                    events.append(("connect", protocol, flags))
                    output[:] = (77).to_bytes(4, "little")
                    return PrimitiveResult(status=0)

                def ioctl(
                    handle, command, input_value, output, events=events, voltage=voltage
                ):
                    events.append(("ioctl", handle, command, input_value))
                    output[:4] = voltage.to_bytes(4, "little")
                    return PrimitiveResult(status=7)

                def disconnect(handle, events=events):
                    events.append(("disconnect", handle))
                    return PrimitiveResult(status=9)

                context.driver_exports = {
                    "PassThruConnect": connect,
                    "PassThruIoctl": ioctl,
                    "PassThruDisconnect": disconnect,
                }
                engine = UtilityExEngine(context)
                imports, slots = self.nk_imports(engine)
                self.assertEqual(
                    imports.invoke_iat(slots["Ex2CCU_01_ReadVBatt"]), expected
                )
                self.assertEqual(
                    events,
                    [("connect", 4, 0x200), ("ioctl", 77, 3, None), ("disconnect", 77)],
                )
                self.assertEqual(context.driver_binding(4)._voltage_handles, {77})
                self.assertEqual(context.state["native_global:10151854"], 0x1014AEF0)

    def test_actual_nk_voltage_connect_failure_and_host_fault_cleanup(self):
        context = self.nk_context()
        events = []

        def connect(protocol, flags, output):
            output[:] = (77).to_bytes(4, "little")
            return PrimitiveResult(status=1)

        def disconnect(handle):
            events.append(handle)
            return PrimitiveResult(status=0)

        context.driver_exports = {
            "PassThruConnect": connect,
            "PassThruDisconnect": disconnect,
        }
        engine = UtilityExEngine(context)
        self.assertEqual(engine.invoke("Ex2GetBattVolt", (bytearray(4),)), 90)
        self.assertEqual(engine.invoke("Ex2CCU_01_ReadVBatt"), 102)
        self.assertEqual(events, [])
        driver = context.driver_binding(4)

        def successful_connect(protocol, flags, output):
            output[:] = (77).to_bytes(4, "little")
            return PrimitiveResult(status=0)

        driver.slots[0x20] = successful_connect
        primary, cleanup = OSError("voltage ioctl"), OSError("voltage disconnect")

        def fail_ioctl(*args):
            raise primary

        def fail_disconnect(*args):
            raise cleanup

        driver.slots[0x2C], driver.slots[0x28] = fail_ioctl, fail_disconnect
        with self.assertRaises(BaseExceptionGroup) as caught:
            engine.invoke("Ex2GetBattVolt", (bytearray(4),))
        self.assertEqual(caught.exception.exceptions, (primary, cleanup))
        self.assertEqual(driver._voltage_handles, {77})

    def test_actual_nk_programming_voltage_retains_handle_and_boolean_control(self):
        context = self.nk_context()
        events = []

        def connect(protocol, flags, output):
            events.append(("connect", protocol, flags))
            output[:] = (77).to_bytes(4, "little")
            return PrimitiveResult(status=0)

        def voltage(pin, value):
            events.append(("voltage", pin, value))
            return PrimitiveResult(status=0)

        def disconnect(handle):
            events.append(("disconnect", handle))
            return PrimitiveResult(status=7)

        context.driver_exports = {
            "PassThruConnect": connect,
            "PassThruSetProgrammingVoltage": voltage,
            "PassThruDisconnect": disconnect,
        }
        engine = UtilityExEngine(context)
        imports, slots = self.nk_imports(engine)
        self.assertEqual(
            imports.invoke_iat(slots["Ex2CCU_01_SetProgrammingVoltage"]), 101
        )
        self.assertEqual(
            imports.invoke_iat(slots["Ex2CCU_01_SetProgrammingVoltage"]), 101
        )
        self.assertEqual(
            imports.invoke_iat(slots["Ex2CCU_01_ReProgrammingVoltage"]), 101
        )
        self.assertEqual(
            events,
            [
                ("connect", 4, 0x200),
                ("voltage", 15, 0xFFFFFFFE),
                ("voltage", 15, 0xFFFFFFFE),
                ("voltage", 15, 0xFFFFFFFF),
                ("disconnect", 77),
            ],
        )

        events.clear()
        context._parameters[0xFB] = 1
        self.assertEqual(engine.invoke("Ex2SetProgrammingVoltage", (2, 0xFFFFFFFE)), 0)
        self.assertEqual(engine.invoke("Ex2SetProgrammingVoltage", (2, 0xFFFFFFFF)), 0)
        self.assertEqual(
            events,
            [
                ("connect", 4, 0x200),
                ("voltage", 2, 0),
                ("voltage", 2, 1),
                ("disconnect", 77),
            ],
        )

    def test_actual_nk_voltage_native_errors_and_raw_output_contract(self):
        context = self.nk_context()

        def connect(protocol, flags, output):
            output[:] = (77).to_bytes(4, "little")
            return PrimitiveResult(status=1)

        context.driver_exports = {
            "PassThruConnect": connect,
            "PassThruSetProgrammingVoltage": lambda pin, voltage: PrimitiveResult(
                status=7
            ),
            "PassThruDisconnect": lambda handle: PrimitiveResult(status=9),
        }
        engine = UtilityExEngine(context)
        context.state["native_global:1015185c"] = 1
        self.assertEqual(
            engine.invoke("Ex2SetProgrammingVoltage", (15, 0xFFFFFFFE)), 90
        )
        self.assertEqual(context.state["native_global:1015185c"], 0)
        driver = context.driver_binding(4)
        self.assertEqual(driver._programming_handle, 77)

        def successful_connect(protocol, flags, output):
            output[:] = (88).to_bytes(4, "little")
            return PrimitiveResult(status=0)

        driver.slots[0x20] = successful_connect
        self.assertEqual(
            engine.invoke("Ex2SetProgrammingVoltage", (15, 0xFFFFFFFE)), 92
        )
        self.assertEqual(engine.invoke("Ex2CCU_01_ReProgrammingVoltage"), 102)
        self.assertEqual(driver._programming_phase, 1)
        self.assertEqual(driver._voltage_handles, {88})
        driver.slots[0x4C] = lambda pin, voltage: PrimitiveResult(status=0, value=1)
        with self.assertRaisesRegex(TypeError, "positional output"):
            engine.invoke("Ex2SetProgrammingVoltage", (15, 0xFFFFFFFF))
        with self.assertRaises(ValueError):
            engine.invoke("Ex2SetProgrammingVoltage", (15,))

    def context(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not path.is_file():
            self.skipTest("Optional supplied original TY18 image unavailable")
        return UtilityExContext(path.read_bytes(), Host(), None, None)

    def plus_context(self, source):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-83")
        queue = json.loads(
            (root / "analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        row = next(item for item in queue if item["sha256"] == source)
        return UtilityExContext(
            (root / row["input_path"]).read_bytes(), Host(), None, None
        )

    def test_typlus_sis_tables_and_controller_metadata(self):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-83")
        contract = json.loads(
            (
                root / "analysis/evidence/no-car-83/plus-driver-binding-contract.json"
            ).read_text()
        )
        context = self.plus_context(
            "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce"
        )
        names = set(_DRIVER_SLOTS.values()) | set(_SIS_DRIVER_SLOTS.values())
        exports: dict[str, Callable[..., object]] = {
            name: lambda *args: PrimitiveResult(status=0) for name in names
        }
        binding = UtilitySISDriverBinding(context, exports)
        for kind, table in (
            ("TYPlusSISBase", _DRIVER_SLOTS),
            ("TYPlusSIS", _SIS_DRIVER_SLOTS),
        ):
            profile = next(row for row in contract["profiles"] if row["kind"] == kind)
            self.assertEqual(
                profile["slots"], {hex(offset): name for offset, name in table.items()}
            )
            for anchor in profile["anchors"]:
                self.assertEqual(
                    hashlib.sha256((root / anchor["path"]).read_bytes()).hexdigest(),
                    anchor["sha256"],
                )
        self.assertTrue(binding.base_ready)
        self.assertTrue(binding.extended_ready)
        self.assertTrue(binding.ready)
        self.assertEqual(binding.profile, "TYPlus")
        self.assertEqual(binding.controller_initialize_arity, 3)
        output = bytearray(4)
        self.assertEqual(
            binding.controller_initialize_arguments(output), (2, output, 0)
        )
        self.assertFalse(
            UtilitySISDriverBinding(
                context,
                {
                    name: callback
                    for name, callback in exports.items()
                    if name != "PassThruQueueMsgs_v0500"
                },
            ).extended_ready
        )
        base_missing = {
            name: callback
            for name, callback in exports.items()
            if name != "PassThruConnect"
        }
        incomplete = UtilitySISDriverBinding(context, base_missing)
        self.assertTrue(incomplete.extended_ready)
        self.assertFalse(incomplete.base_ready)
        self.assertTrue(incomplete.ready)
        ty18 = UtilitySISDriverBinding(self.context(), exports)
        self.assertEqual(ty18.controller_initialize_arity, 2)
        self.assertEqual(ty18.controller_initialize_arguments(output), (2, output))
        with self.assertRaises(LookupError):
            UtilitySISDriverBinding(self.nk_context(), exports)

    def test_individual_json_primitives_enforce_kind_inputs_and_returns(self):
        context = self.plus_context(
            "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce"
        )
        calls = []
        context.json_exports = {
            "JsonDGetData": lambda *args: calls.append(("d", args)) or 65535,
            "JsonSGetData": lambda *args: calls.append(("s", args)) or "Toyota",
        }
        self.assertEqual(
            context.json_d_get_data(1, "ethernet", "sourcePortNumberTCP"), 65535
        )
        self.assertEqual(context.json_s_get_data(3, "vim", "name"), "Toyota")
        self.assertEqual(
            calls,
            [("d", (1, "ethernet", "sourcePortNumberTCP")), ("s", (3, "vim", "name"))],
        )
        for args in ((True, "s", "k"), (-1, "s", "k"), (1, "s\0x", "k"), (1, "s", "")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                context.json_d_get_data(*args)
        context.json_exports = {
            "JsonDGetData": lambda *args: PrimitiveResult(status=0, value=1)
        }
        with self.assertRaises(TypeError):
            context.json_d_get_data(1, "ethernet", "sourcePortNumberUDP")
        context.json_exports = {
            "JsonSGetData": lambda *args: "x" * (16 * 1024 * 1024 + 1)
        }
        with self.assertRaises(ValueError):
            context.json_s_get_data(3, "vim", "name")
        context.json_exports = {"JsonSGetData": lambda *args: b"not unicode"}
        with self.assertRaises(TypeError):
            context.json_s_get_data(3, "vim", "name")
        context.json_exports = {"Unexpected": lambda *args: "x"}
        with self.assertRaises(ValueError):
            context.json_s_get_data(3, "vim", "name")
        context.json_exports = None
        with self.assertRaises(LookupError):
            context.json_d_get_data(1, "ethernet", "sourcePortNumberUDP")

    def test_plus_p6_source_profiles_readiness_and_protocol_cache(self):
        sources = (
            "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce",
            "36dcdad2e72e29aae813db5576daf0168dd032b08a9cdda3841078dfb0b7b9fd",
        )
        for source in sources:
            context = self.plus_context(source)
            contract = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "analysis/evidence/no-car-83/plus-driver-binding-contract.json"
                ).read_text()
            )
            kind = "TYPlusP6" if source.startswith("821b") else "NKPlusP6"
            profile = next(row for row in contract["profiles"] if row["kind"] == kind)
            for anchor in profile["anchors"]:
                self.assertEqual(
                    hashlib.sha256(
                        (
                            Path(__file__).resolve().parents[1] / anchor["path"]
                        ).read_bytes()
                    ).hexdigest(),
                    anchor["sha256"],
                )
            exports: dict[str, Callable[..., object]] = {
                name: lambda *args: PrimitiveResult(status=0)
                for name in _DRIVER_SLOTS.values()
            }
            context.p6_driver_exports = exports
            context.driver_exports = exports
            raw_output = bytearray(4)

            def connect(
                protocol: int, flags: int, output: bytearray
            ) -> PrimitiveResult:
                output[:] = (37).to_bytes(4, "little")
                return PrimitiveResult(status=19)

            exports["PassThruConnect"] = connect
            for protocol in (6, 0x8012):
                binding = context.p6_driver_binding(protocol)
                self.assertIs(binding, context.p6_driver_binding(protocol))
                self.assertIsNot(binding, context.driver_binding(protocol))
                self.assertTrue(binding.ready)
                self.assertEqual(
                    (binding.protocol, binding.oem_protocol),
                    (protocol, protocol + 0x100),
                )
                self.assertEqual(binding.constructor_parameter, 0)
                self.assertEqual(
                    (binding.readiness_offset, binding.controller_handle_offset),
                    (0x20, 0x1C),
                )
                self.assertEqual(
                    {
                        hex(offset): name
                        for offset, name in binding.slots_by_offset.items()
                    },
                    profile["slots"],
                )
                self.assertEqual(
                    binding.invoke_raw("PassThruConnect", protocol, 0, raw_output), 19
                )
                self.assertEqual(int.from_bytes(raw_output, "little"), 37)
                other = 0x8012 if protocol == 6 else 6
                self.assertIsNot(binding, context.p6_driver_binding(other))
                for offset, name in binding.slots_by_offset.items():
                    self.assertEqual(binding.slot_offset(name), offset)
                    self.assertIs(binding.resolve(offset), exports[name])
                    missing = dict(exports)
                    del missing[name]
                    self.assertFalse(
                        UtilityP6DriverBinding(context, protocol, missing).ready
                    )
                unloaded = UtilityP6DriverBinding(
                    context, protocol, exports, loaded=False
                )
                self.assertFalse(unloaded.ready)
                self.assertTrue(all(slot is None for slot in unloaded.slots.values()))
                with self.assertRaises(LookupError):
                    binding.resolve(0x20)
                with self.assertRaises(LookupError):
                    binding.slot_offset("PassThruNotReviewed")
        with self.assertRaises(LookupError):
            self.context().p6_driver_binding(6)
        with self.assertRaises(LookupError):
            UtilityP6DriverBinding(self.context(), 6, {})
        with self.assertRaises(ValueError):
            context.p6_driver_binding(3)
        with self.assertRaises(ValueError):
            UtilityP6DriverBinding(context, 6, {"Unexpected": lambda: None})
        with self.assertRaises(LookupError):
            UtilityP6DriverBinding(self.context(), 6, {})

    def test_actual_ty_direct_signed_abi_and_scheduled_dummy_composition(self):
        context = self.context()
        engine = UtilityEx2TY(context)
        self.assertEqual(engine.invoke("Ex2ECD_67_CharToInt", (ord("x"),)), -1)
        self.assertEqual(engine.invoke("Ex2ECD_67_CharToInt", (ord("a"),)), 10)
        context._parameters[0x6F] = 20
        output = bytearray()
        self.assertEqual(engine.invoke("Ex2ECD_59_Dummy", (output,)), 15)
        self.assertEqual(engine.worker.get_status(), 1001)
        self.assertEqual(engine.invoke("Ex2FCHV_07_Overwrite", (output,)), 15)
        self.assertEqual(engine.worker.get_status(), 1000)

    def test_actual_ms2_pressure_direct_all_modes_and_zero_argument_workers(self):
        root = Path(__file__).resolve().parents[1]
        require_private(root / "analysis/evidence/no-car-83")
        packet = json.loads(
            (
                root / "analysis/evidence/no-car-83/ty-owner118-wrapper-import.json"
            ).read_text()
        )
        for row in packet["rows"]:
            if row["export"] != "Ex2MS2ABS_01_CheckPressureSensorValue":
                continue
            path = root / row["c_path"]
            self.assertTrue(
                any(value in path.read_text() for value in ("0x11ef68", "0x116fdc"))
            )
            queue = json.loads(
                (root / "analysis/evidence/no-car-83/source-queue.json").read_text()
            )
            source = next(
                item for item in queue if item["sha256"] == row["source_sha256"]
            )
            context = UtilityExContext(
                (root / source["input_path"]).read_bytes(), Host(), None, None
            )
            engine = UtilityEx2TY(context)
            for mode in (0, 4, 20, 52):
                context._parameters[0x6F] = mode
                for value, expected in (
                    (0x7F8A, 0),
                    (0x7F8B, 1),
                    (0x11EF67, 1),
                    (0x11EF68, 0),
                ):
                    self.assertEqual(engine.invoke(row["export"], (value,)), expected)
            for export in ("Ex2MS2ABS_05_SendMessage", "Ex2MS2EFI_02_SendMessage"):
                with self.assertRaises(ValueError):
                    engine.invoke(export, (bytearray(4),))

    def test_actual_all8_native_thread_status_export_and_anchor_identity(self):
        root = Path(__file__).resolve().parents[1]
        queue = root / "analysis/evidence/no-car-83/source-queue.json"
        anchors = root / "analysis/evidence/no-car-83/thread-status-all8.json"
        if not queue.exists() or not anchors.exists():
            self.skipTest("Optional supplied all8 source packet unavailable")
        for row in json.loads(queue.read_text()):
            with self.subTest(source=row["sha256"]):
                path = root / row["input_path"]
                if not path.exists():
                    self.skipTest("Optional supplied original image unavailable")
                engine = UtilityExEngine(
                    UtilityExContext(path.read_bytes(), Host(), None, None)
                )
                self.assertEqual(engine.context.module_sha256, row["sha256"])
                base = _BROKER_GLOBAL_BASES[SOURCES[row["sha256"]]]
                engine.context.state[f"native_global:{base:x}"] = 123
                engine.context.refresh_parameters()
                self.assertEqual(engine.context.state[f"native_global:{base:x}"], 0)
                self.assertEqual(engine.invoke("Ex2GetThreadStatus"), 0)
                engine.worker.status = 15
                self.assertEqual(engine.invoke("Ex2GetThreadStatus"), 99)
                with self.assertRaises(ValueError):
                    engine.invoke("Ex2GetThreadStatus", (0,))

        for row in json.loads(anchors.read_text()):
            for suffix in ("c", "asm"):
                self.assertEqual(
                    hashlib.sha256(
                        (root / row[f"{suffix}_path"]).read_bytes()
                    ).hexdigest(),
                    row[f"{suffix}_sha256"],
                )

    def test_actual_plus_broker22_conversion_and_same_value_refresh(self):
        root = Path(__file__).resolve().parents[1]
        queue = root / "analysis/evidence/no-car-83/source-queue.json"
        if not queue.exists():
            self.skipTest("Optional supplied all8 source packet unavailable")
        for row in json.loads(queue.read_text()):
            if SOURCES[row["sha256"]] not in ("NKPlus", "TYPlus"):
                continue
            with self.subTest(source=row["sha256"]):
                path = root / row["input_path"]
                if not path.exists():
                    self.skipTest("Optional supplied original image unavailable")
                host = Host()
                host.values.update({0x6F: 22, 0x74: 0x12, 0x155: 0x34, 0x15F: 0x56})
                context = UtilityExContext(path.read_bytes(), host, None, None)
                self.assertEqual(context.broker(0x74), 0x18DA12E0)
                self.assertEqual(context.broker(0x155), 0x18DA34F1)
                self.assertEqual(context.broker(0x15F), 0x18DB56F1)
                key = f"native_global:{_BROKER_GLOBAL_BASES[SOURCES[row['sha256']]]:x}"
                context.state[key] = 0xFFFFFFFF
                context.refresh_parameters()
                self.assertEqual(context.state[key], 0x18DA12E0)

    def test_broker_global_bases_and_order_are_exact_source_assignments(self):
        root = Path(__file__).resolve().parents[1]
        packet = root / "analysis/evidence/no-car-83/broker-source-map.json"
        if not packet.exists():
            self.skipTest("Private broker source packet unavailable")
        for row in json.loads(packet.read_text())["sources"]:
            with self.subTest(source=row["module_sha256"]):
                path = root / row["c"]
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(), row["c_sha256"]
                )
                assignments = re.findall(
                    r"_?DAT_([0-9a-f]+) = EbGetPara\((0x[0-9a-f]+)\);", path.read_text()
                )
                base = _BROKER_GLOBAL_BASES[SOURCES[row["module_sha256"]]]
                self.assertEqual(
                    [int(address, 16) for address, _ in assignments],
                    [base + index * 4 for index in range(len(assignments))],
                )
                self.assertEqual(
                    tuple(int(key, 16) for _, key in assignments),
                    _BROKER_KEYS[row["module_sha256"]],
                )

    def test_nk_full_export_ownership_preserves_every_original_slot(self):
        root = Path(__file__).resolve().parents[1]
        require_private(
            root / "analysis/evidence/no-car-83", root / "runtime/no-car-83"
        )
        ledger = json.loads(
            (
                root / "analysis/evidence/no-car-83/nk-full-export-ownership.json"
            ).read_text()
        )
        parser = runpy.run_path(str(root / "runtime/no-car-83/nk_export_ownership.py"))[
            "exports"
        ]
        queue = json.loads(
            (root / "analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for source in queue:
            if not SOURCES[source["sha256"]].startswith("NK"):
                continue
            data = (root / source["input_path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), source["sha256"])
            expected = {
                (row["ordinal"], row["rva"], row["name"]) for row in parser(data)
            }
            actual = {
                (row["ordinal"], row["rva"], row["name"])
                for row in ledger["rows"]
                if row["source_sha256"] == source["sha256"]
            }
            self.assertEqual(actual, expected)
        self.assertEqual(
            ledger["owner_counts"],
            {"83": 147, "UNASSIGNED": 2599, "95": 654, "96": 1065},
        )

    def test_four_large_ty18_pointer_imports_preserve_live_argument_identity(self):
        root = Path(__file__).resolve().parents[1]
        require_private(
            root / "analysis/evidence/no-car-142", root / "analysis/evidence/no-car-83"
        )
        packet = json.loads(
            (
                root
                / "analysis/evidence/no-car-142/native-pointer-caller-bindings.json"
            ).read_text()
        )
        queue = json.loads(
            (root / "analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        targets = {row["sha256"]: root / row["input_path"] for row in queue}
        for row in packet["rows"]:
            caller = (root / row["source_path"]).read_bytes()
            context = UtilityExContext(
                targets[row["target_sha256"]].read_bytes(), Host(), None, None
            )
            engine = UtilityExEngine(context)
            binding = UtilityImportBinding(caller, engine)
            buffer = bytearray(0xC4)
            with patch.object(engine, "invoke", return_value=15) as invoke:
                self.assertEqual(binding.invoke_iat(row["iat_rva"], (buffer,)), 15)
                self.assertEqual(
                    invoke.call_args.args[0], row["target_exports"][0]["name"]
                )
                self.assertIs(invoke.call_args.args[1][0], buffer)
            with self.assertRaises(ValueError):
                UtilityImportBinding(caller + b"tampered", engine)

    def test_actual_it3_import_thunks_dispatch_exact_caller_engine_pair(self):
        root = Path(__file__).resolve().parents[1]
        packet = root / "analysis/evidence/no-car-83/it3-import-source-bindings.json"
        queue = root / "analysis/evidence/no-car-83/source-queue.json"
        if not packet.exists() or not queue.exists():
            self.skipTest("Private source-bound import packet unavailable")
        targets = {
            row["sha256"]: root / row["input_path"]
            for row in json.loads(queue.read_text())
        }
        for row in json.loads(packet.read_text())["rows"]:
            if row["target_exports"][0]["name"] != "Ex2GetThreadStatus":
                continue
            with self.subTest(caller=row["source_sha256"]):
                caller_path, engine_path = (
                    root / row["source_path"],
                    targets[row["target_sha256"]],
                )
                if not caller_path.exists() or not engine_path.exists():
                    self.skipTest("Optional supplied original image unavailable")
                caller = caller_path.read_bytes()
                context = UtilityExContext(engine_path.read_bytes(), Host(), None, None)
                engine = UtilityExEngine(context)
                binding = UtilityImportBinding(caller, engine)
                self.assertEqual(binding.caller_sha256, row["source_sha256"])
                self.assertEqual(binding.invoke_iat(row["iat_rva"]), 0)
                engine.worker.status = 15
                self.assertEqual(binding.invoke_iat(row["iat_rva"]), 99)
                with self.assertRaises(LookupError):
                    binding.invoke_iat(0)
                with self.assertRaises(ValueError):
                    binding.invoke_iat(row["iat_rva"], (0,))
                with self.assertRaises(ValueError):
                    UtilityImportBinding(caller + b"tampered", engine)
                with (
                    patch.object(context, "module_sha256", "0" * 64),
                    self.assertRaises(ValueError),
                ):
                    UtilityImportBinding(caller, engine)

    def test_all36_fchv_public_wrappers_match_exact_body_inputs_and_outputs(self):
        root = Path(__file__).resolve().parents[1]
        generator = root / "runtime/no-car-111/exact_body_replay.py"
        if not generator.exists():
            self.skipTest("Private source-bound FCHV scenario generator unavailable")
        from scripts.utility_ex_ty import run_body
        from tests.test_utility_ex_fchv import Context, wire

        count = 0
        for sha, source, export, data, replies, expected in runpy.run_path(
            str(generator)
        )["scenarios"]():
            with self.subTest(source=sha, export=export):
                reference = Context(sha, list(replies))
                reference_host = Host()
                reference_host.values[0x6F] = 20
                reference_context = UtilityExContext(source, reference_host, None, None)
                expected_data = copy.deepcopy(data)
                with patch.object(reference_context, "comm", return_value=reference):
                    self.assertEqual(
                        run_body(export, (expected_data,), reference_context), expected
                    )
                communication = Context(sha, list(replies))
                host = Host()
                host.values[0x6F] = 20
                context = UtilityExContext(source, host, None, None)
                engine = UtilityEx2TY(context)
                with patch.object(context, "comm", return_value=communication):
                    self.assertEqual(engine.invoke(export, (data,)), 15)
                    thread = engine.worker._thread
                    assert thread is not None
                    thread.join(2)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(engine.worker.get_status(), expected)
                self.assertEqual(data, expected_data)
                self.assertEqual(wire(communication), wire(reference))
                self.assertIsNone(next(communication.replies, None))
                count += 1
        self.assertEqual(count, 36)

    def test_actual_source_broker_protocol_and_time_body_composition(self):
        context = self.context()
        engine = UtilityEx2TY(context)
        self.assertIn("Ex2FCHV_04_ChangeProtocol", engine.supported_bodies())
        self.assertEqual(engine.invoke("Ex2FCHV_04_ChangeProtocol", (0x22,)), 0)
        self.assertEqual(context.broker(0x6F), 0x22)
        host = context.host
        assert isinstance(host, Host)
        host.elapsed = 5
        self.assertEqual(
            engine.run_body("Ex2FCHV_04_CheckCanSendTime", (0xFFFFFFFE, 6)), 1
        )

    def test_actual_void_export_and_broker_primitive_chronology(self):
        context = self.context()
        host = context.host
        assert isinstance(host, Host)
        engine = UtilityEx2TY(context)
        host.events.clear()
        self.assertEqual(engine.invoke("Ex2FCHV_04_ChangeProtocol", (0x22,)), 0)
        self.assertEqual(
            host.events[:5],
            [
                ("set", 0x6F, 0x22),
                ("write",),
                ("get", 0x74),
                ("get", 0xAB),
                ("get", 0x6F),
            ],
        )
        self.assertIsNone(engine.invoke("Ex2SetParaFromBroker"))
        self.assertEqual(engine.invoke("Ex2GetThreadStatus"), 0)

    def test_actual_driver_table_slot_and_controller_return_abi(self):
        calls = []

        def initialize(mode, output):
            calls.append(mode)
            output[:] = bytes.fromhex("78563412")
            return PrimitiveResult(status=7, value=0x12345678)

        def finalize():
            calls.append("finalize")
            return PrimitiveResult(status=9)

        binding = UtilityDriverBinding(
            self.context(),
            4,
            {
                "J2534CtrlInitialize": initialize,
                "J2534CtrlFinalize": finalize,
            },
        )
        self.assertFalse(binding.ready)
        self.assertEqual(binding.oem_protocol, 0x104)
        self.assertIsNone(binding.resolve(0x20))
        self.assertIs(binding.resolve(0x54), initialize)
        self.assertEqual(binding.controller_initialize(), 7)
        self.assertEqual(binding.controller_finalize(), 9)
        self.assertEqual(calls, [1, "finalize"])
        with self.assertRaises(LookupError):
            binding.resolve(0x60)

    def test_actual_source_wrapper_mode_guard_and_unknown_wrapper(self):
        context = self.context()
        engine = UtilityEx2TY(context)
        self.assertEqual(
            engine.start_export("Ex2DOOR_01_StartConnectionHistoryClear"), 99
        )
        with self.assertRaises(LookupError):
            engine.start_export("Ex2UnreviewedWrapper")

    def test_unknown_business_export_never_routes_generic_callback(self):
        engine = UtilityEx2TY(self.context())
        with self.assertRaises(LookupError):
            engine.run_body("Ex2Unreviewed", ())


if __name__ == "__main__":
    unittest.main()
