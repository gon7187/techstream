"""Checks for recovered transaction branches; no vehicle, DLL or socket."""

import json
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
from scripts.utility_ex import UtilityDriverBinding, UtilityExContext
from scripts.utility_ex_comm import (
    P6_FIELD_OFFSETS,
    SHA_12_NK,
    SHA_12_TY,
    SHA_18_NK,
    SHA_18_TY,
    SHA_DS4_NK,
    SHA_DS4_TY,
    SHA_PLUS_NK,
    SHA_PLUS_TY,
    CommContext,
    DriverReceive,
    UtilityExBroadcastCANLower,
    UtilityExCANLower,
    UtilityExClassicScheduler,
    UtilityExComm,
    UtilityExDirectDriver,
    UtilityExDriverArbitration,
    UtilityExDriverPrimitives,
    UtilityExP3Lower,
    UtilityExP6BroadcastLower,
    UtilityExP6DataList,
    UtilityExP6Fields,
    UtilityExP6Lower,
    UtilityExP6Pool,
    UtilityExP6UDSScheduler,
    UtilityExPassThruPool,
    UtilityExSelectedPending,
    UtilityExSourceError,
    UtilityExSupportCache,
    UtilityExUDSScheduler,
    _published_state,
    elapsed,
    native_manager_protocol,
    p3_default_parameters,
    p6_configuration,
    pack_p3_request,
    pack_p6_request,
    pack_uds_request,
    select_native_manager,
    unpack_p3_response,
    unpack_p6_response,
    unpack_uds_response,
)


class Context:
    module_sha256 = "unreviewed"
    module_bytes = b""

    def __init__(self):
        self.cancelled = False
        self.state: dict[str, object] = {}
        self.tick = 0
        self.parameters: dict[int, int] = {}
        self.data: dict[int, bytes] = {}
        self.bindings: dict[int | tuple[int, int], object] = {}

    def broker(self, key):
        return self.parameters.get(key, 0)

    def native_parameter(self, key):
        return self.broker(key)

    def broker_data(self, key):
        return self.data.get(key, b"")

    def driver_binding(self, protocol, *, constructor_parameter=0):
        key = (protocol, constructor_parameter) if constructor_parameter else protocol
        if key not in self.bindings:
            raise UtilityExSourceError("No supplied raw DRIVER binding")
        return self.bindings[key]

    def is_cancelled(self):
        return self.cancelled

    def ticks(self):
        self.tick = (self.tick + 1) & 0xFFFFFFFF
        return self.tick

    def sleep(self, milliseconds):
        if threading.current_thread() is not threading.main_thread():
            time.sleep(milliseconds / 1000)
        self.tick = (self.tick + milliseconds) & 0xFFFFFFFF

    def native_sleep(self, milliseconds):
        self.sleep(milliseconds)


class Driver:
    def __init__(self, replies=(), send_status=0):
        self.replies = iter(replies)
        self.sent = []
        self.interrupted = []
        self.send_status = send_status

    def send(self, request):
        self.sent.append(request)
        return self.send_status

    def receive(self):
        return next(self.replies)

    def interrupt(self, timeout_ms):
        self.interrupted.append(timeout_ms)


class UtilityExCommunicationTests(unittest.TestCase):
    def engine(self, *replies, send_status=0):
        context, driver = Context(), Driver(replies, send_status)
        return UtilityExUDSScheduler(context, driver), driver, context

    def test_positive_and_wrong_service(self):
        for data, status in ((b"\x62\xf1\x90", 0), (b"\x63", 3), (b"", 3)):
            engine, driver, _ = self.engine(DriverReceive(0, data))
            self.assertEqual(engine.exchange(b"\x22\xf1\x90"), (status, data))
            self.assertEqual(driver.sent, [b"\x22\xf1\x90"])

    def test_busy_is_resent_and_has_separate_limit(self):
        engine, driver, _ = self.engine(DriverReceive(0x1B), DriverReceive(0x1B))
        engine.fields.busy_count = 2
        self.assertEqual(engine.exchange(b"\x22"), (0x1C, b""))
        self.assertEqual(len(driver.sent), 2)

    def test_pending_receives_without_resending(self):
        engine, driver, _ = self.engine(DriverReceive(5), DriverReceive(0, b"\x62"))
        self.assertEqual(engine.exchange(b"\x22"), (0, b"\x62"))
        self.assertEqual(driver.sent, [b"\x22"])

    def test_pending_count_exhaustion_interrupts_lower(self):
        engine, driver, _ = self.engine(DriverReceive(5), DriverReceive(5))
        engine.fields.receive_ms, engine.fields.receive_count = 0, 2
        self.assertEqual(engine.exchange(b"\x22"), (5, b""))
        self.assertEqual(driver.interrupted, [100])

    def test_no_response_limit_and_suppression(self):
        engine, driver, _ = self.engine(*(DriverReceive(2) for _ in range(3)))
        self.assertEqual(engine.exchange(b"\x22"), (2, b""))
        self.assertEqual(len(driver.sent), 3)
        engine, driver, _ = self.engine(DriverReceive(2))
        self.assertEqual(engine.exchange(b"\x3e\x80"), (0, b""))
        self.assertEqual(len(driver.sent), 1)

    def test_suppression_is_only_for_source_service_set(self):
        engine, driver, _ = self.engine(*(DriverReceive(2) for _ in range(3)))
        self.assertEqual(engine.exchange(b"\x22\x80"), (2, b""))
        self.assertEqual(len(driver.sent), 3)

    def test_send_fault_returns_without_receive(self):
        engine, driver, _ = self.engine(send_status=99)
        self.assertEqual(engine.exchange(b"\x22"), (99, b""))
        self.assertEqual(len(driver.sent), 1)

    def test_other_fault_retry_and_exception_cleanup(self):
        engine, driver, _ = self.engine(*(DriverReceive(7) for _ in range(3)))
        self.assertEqual(engine.exchange(b"\x22"), (7, b""))
        self.assertEqual(len(driver.sent), 3)
        engine, _, _ = self.engine()
        with self.assertRaises(StopIteration):
            engine.exchange(b"\x22")
        self.assertEqual(engine.fields.suppress_error, 0)

    def test_native_cancellation_retains_last_receive_status(self):
        engine, driver, context = self.engine(DriverReceive(2))
        context.cancelled = True
        self.assertEqual(engine.exchange(b"\x22"), (2, b""))
        self.assertEqual(driver.sent, [b"\x22"])

    def test_sessions_validate_echo_length_and_mode(self):
        for reply, expected in ((b"\x50\x03", 0), (b"\x50", 3), (b"\x50\x02", 7)):
            engine, _, _ = self.engine(DriverReceive(0, reply))
            self.assertEqual(engine.session(3, 0), expected)
            self.assertEqual(engine.fields.current_session, 3 if expected == 0 else 0)
        engine, driver, _ = self.engine()
        engine.fields.diagnostic_enabled = 0
        self.assertEqual(engine.session(3, 0), 0x16)
        self.assertEqual(driver.sent, [])

    def test_extended_session_runs_normal_first(self):
        engine, driver, _ = self.engine(
            DriverReceive(0, b"\x50\x01"), DriverReceive(0, b"\x50\x03")
        )
        self.assertEqual(engine.session(3, 0, normal_first=True), 0)
        self.assertEqual(driver.sent, [b"\x10\x01", b"\x10\x03"])

    def test_unported_worker_and_source_fail_closed(self):
        engine, driver, _ = self.engine()
        with self.assertRaises(UtilityExSourceError):
            engine.session(3)
        with self.assertRaises(UtilityExSourceError):
            UtilityExComm(Context())
        self.assertEqual(driver.sent, [])

    def test_native_can_packing_and_nrc_mapping(self):
        sent = pack_uds_request(0x7E0, b"\x22\xf1\x90")
        self.assertEqual(sent.data, b"\x00\x00\x07\xe0\x22\xf1\x90")
        for nrc, status in ((0x12, 0x16), (0x21, 0x1B), (0x78, 5), (0x31, 7)):
            wire = pack_uds_request(0x7E8, bytes((0x7F, 0x22, nrc)))
            received = unpack_uds_response(wire, 0x7E0)
            self.assertEqual(received.status, status)
            self.assertEqual(received.data, bytes((0x7F, 0x22, nrc)))
        self.assertEqual(unpack_uds_response(sent, 0x7E0).status, 3)
        malformed = pack_uds_request(0x7E8, b"\x7f\x22")
        self.assertEqual(unpack_uds_response(malformed, 0x7E0).status, 3)

    def test_claimed_known_hash_does_not_authorize_different_bytes(self):
        context = Context()
        context.module_sha256 = SHA_18_TY
        with self.assertRaisesRegex(UtilityExSourceError, "identity mismatch"):
            UtilityExComm(context)

    def test_pending_clears_suppressed_positive_state(self):
        engine, driver, _ = self.engine(
            DriverReceive(5), DriverReceive(2), DriverReceive(2), DriverReceive(2)
        )
        self.assertEqual(engine.exchange(b"\x3e\x80"), (2, b""))
        self.assertEqual(len(driver.sent), 3)

    def test_source_selected_manager_branch_order(self):
        self.assertEqual(select_native_manager(SHA_18_TY, 3, 0x11), 0x10118E00)
        self.assertEqual(select_native_manager(SHA_18_NK, 3, 0x11), 0x1014AEF0)
        self.assertEqual(select_native_manager(SHA_18_TY, 0, 0x21), 0x10119FC0)
        self.assertEqual(select_native_manager(SHA_18_TY, 0x13, 0x21), 0x10119FC0)
        self.assertEqual(select_native_manager(SHA_18_TY, 4, 0x51), 0x1011E5E0)
        self.assertEqual(select_native_manager(SHA_18_TY, 4, 0x12), 0x10118D70)
        self.assertEqual(select_native_manager(SHA_18_TY, 0x14, 0x12), 0x10118CA0)
        self.assertIsNone(select_native_manager(SHA_18_TY, 0, 0x11))
        self.assertIsNone(select_native_manager(SHA_18_TY, 0x13, 0x12))
        with self.assertRaises(UtilityExSourceError):
            select_native_manager("unreviewed", 3, 0x11)

    def test_exact_eight_selector_objects_and_version_mode_delta(self):
        sources = (
            (
                SHA_12_TY,
                (
                    0x100AB740,
                    0x100AB988,
                    0x100AFE40,
                    0x100AB868,
                    0x100ABA50,
                    0x100AB778,
                    0x100AB6F8,
                    0x100AB7C0,
                    0x100AB6C0,
                    0x100AB608,
                    0x100AB908,
                    0x100ABA08,
                ),
            ),
            (
                SHA_12_NK,
                (
                    0x100E6240,
                    0x100E6488,
                    0x100EA940,
                    0x100E6368,
                    0x100E6550,
                    0x100E6278,
                    0x100E61F8,
                    0x100E62C0,
                    0x100E61C0,
                    0x100E6108,
                    0x100E6408,
                    0x100E6508,
                ),
            ),
            (
                SHA_DS4_TY,
                (
                    0x1006AA38,
                    0x1006BCCC,
                    0x1006CED4,
                    0x1006BD7C,
                    0x1006F168,
                    0x1006F240,
                    0x1006CE88,
                    0x1006BC38,
                    0x1006CF08,
                    0x1006BBE8,
                    0x1006BD00,
                    0x100687D0,
                ),
            ),
            (
                SHA_DS4_NK,
                (
                    0x101B4208,
                    0x101B549C,
                    0x101B66A4,
                    0x101B554C,
                    0x101B8938,
                    0x101B8A10,
                    0x101B6658,
                    0x101B5408,
                    0x101B66D8,
                    0x101B53B8,
                    0x101B54D0,
                    0x101B1FA0,
                ),
            ),
            (
                SHA_PLUS_TY,
                (
                    0x10136D48,
                    0x10137FE8,
                    0x10139210,
                    0x101380A4,
                    0x1013E798,
                    0x1013F968,
                    0x101391C0,
                    0x10137F50,
                    0x10139248,
                    0x10137F00,
                    0x10138020,
                    0x10134AD0,
                ),
            ),
            (
                SHA_PLUS_NK,
                (
                    0x101BF318,
                    0x101C05B8,
                    0x101C17E0,
                    0x101C0674,
                    0x101C6D68,
                    0x101C7F38,
                    0x101C1790,
                    0x101C0520,
                    0x101C1818,
                    0x101C04D0,
                    0x101C05F0,
                    0x101BD0A0,
                ),
            ),
        )
        inputs = (
            (3, 0x11),
            (0x12, 0x11),
            (4, 0x11),
            (0, 0x21),
            (3, 0x51),
            (0x13, 0x1A),
            (0x13, 0x4A),
            (0x13, 0x5A),
            (4, 0x12),
            (0x14, 0x12),
            (4, 0x22),
            (0x15, 0x22),
        )
        for sha, expected in sources:
            with self.subTest(source=sha):
                self.assertEqual(
                    tuple(select_native_manager(sha, *i) for i in inputs), expected
                )
                self.assertEqual(
                    tuple(
                        native_manager_protocol(sha, manager) for manager in expected
                    ),
                    (1, 15, 6, 4, 3, 13, 13, 13, 5, 16, 8, 17),
                )
                self.assertEqual(select_native_manager(sha, 4, 0x51), expected[2])
                self.assertEqual(select_native_manager(sha, 0x13, 0x21), expected[3])
                self.assertIsNone(select_native_manager(sha, 0x13, 0x22))
                self.assertEqual(
                    select_native_manager(sha, 0x34, 0x12),
                    None if sha in (SHA_12_TY, SHA_12_NK) else expected[9],
                )

    def pool(self, replies=(), *, fail_disconnect=False, cancel_connect=False):
        context = Context()
        calls = []
        reads = iter(replies)

        def provider(operation, remaining):
            calls.append(operation)
            name = operation["operation"]
            if name == "PassThruConnect":
                if cancel_connect:
                    context.cancelled = True
                return PrimitiveResult(0, 42)
            if name == "PassThruReadMsgs":
                return next(reads)
            if name == "PassThruDisconnect":
                return PrimitiveResult(99 if fail_disconnect else 0)
            return PrimitiveResult(0, 1)

        device = J2534Device2026(
            provider, cancelled=context.is_cancelled, background_workers=False
        )
        return UtilityExPassThruPool(context, device), calls, context

    def test_pool_connect_sharing_duplicates_and_cleanup(self):
        pool, calls, _ = self.pool()
        self.assertEqual(pool.connect(6, 0x7E0), (0, 0))
        self.assertEqual(pool.connect(6, 0x7E1), (0, 1))
        self.assertEqual(pool.connect(6, 0x7E0), (13, 4))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["abi"], "legacy-wrapper3")
        self.assertNotIn("device_id", calls[0])
        self.assertEqual(pool.close(0), 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(pool.close(1), 0)
        self.assertEqual(calls[-1]["operation"], "PassThruDisconnect")
        self.assertEqual(pool.owned, set())

    def test_native12_pool_duplicate_key_ignores_extension_but_later_sources_do_not(
        self,
    ):
        for sha in (
            SHA_12_NK,
            SHA_12_TY,
            SHA_18_NK,
            SHA_18_TY,
            SHA_PLUS_NK,
            SHA_PLUS_TY,
        ):
            with self.subTest(source=sha):
                pool, _, context = self.pool()
                context.module_sha256 = sha
                self.assertEqual(pool.connect(6, 0x7E0, extra=1), (0, 0))
                expected = (13, 4) if sha in (SHA_12_NK, SHA_12_TY) else (0, 1)
                self.assertEqual(pool.connect(6, 0x7E0, extra=2), expected)
                pool.close(0)
                if expected == (0, 1):
                    pool.close(1)

    def test_plus_can_response_delta_and_native_uint32_address_wrap(self):
        for sha in (SHA_PLUS_NK, SHA_PLUS_TY):
            context = Context()
            context.module_sha256 = sha
            lower = object.__new__(UtilityExCANLower)
            lower.context = context
            for mode, delta in ((0x14, 8), (0x74, 16)):
                context.parameters[0x6F] = mode
                self.assertEqual(lower._response_delta(), delta)
                context.state[
                    f"native_global:{0x101C8010 if sha == SHA_PLUS_NK else 0x1013FA40:x}"
                ] = 0x74
                self.assertEqual(lower._response_delta(), 16)
                context.state.clear()
        response = NativeMessage(6, bytes.fromhex("000007f062f190"))
        self.assertEqual(unpack_uds_response(response, 0x7E0, 16).status, 0)
        self.assertEqual(unpack_uds_response(response, 0x7E0, 8).status, 3)
        wrapped = NativeMessage(6, bytes.fromhex("0000000062"))
        self.assertEqual(unpack_uds_response(wrapped, 0xFFFFFFF0, 16).status, 0)

    def test_pool_cancel_after_acquire_rolls_back_fresh_handle(self):
        pool, calls, _ = self.pool(cancel_connect=True)
        with self.assertRaises(InterruptedError):
            pool.connect(6, 0x7E0)
        self.assertEqual(
            [c["operation"] for c in calls], ["PassThruConnect", "PassThruDisconnect"]
        )
        self.assertEqual(pool.owned, set())
        self.assertEqual(pool.channels, [None] * 4)

    def test_pool_cancel_with_failed_cleanup_retains_handle(self):
        pool, _, _ = self.pool(cancel_connect=True, fail_disconnect=True)
        with self.assertRaises(InterruptedError):
            pool.connect(6, 0x7E0)
        self.assertEqual(pool.owned, {42})
        self.assertIsNotNone(pool.last_cleanup_error)

    def test_pool_demultiplexes_other_owner_and_drains_before_write(self):
        first = pack_uds_request(0x7E8, b"\x62")
        second = pack_uds_request(0x7E9, b"\x62")
        pool, calls, _ = self.pool(
            [PrimitiveResult(0, (second,)), PrimitiveResult(0, (first,))]
        )
        pool.connect(6, 0x7E0)
        pool.connect(6, 0x7E1)
        pool.route_filter(0, bytes([255]) * 4, first.data[:4])
        pool.route_filter(1, bytes([255]) * 4, second.data[:4])
        self.assertEqual(pool.read(0, 1000), (0, first))
        self.assertEqual(pool.queue, [(1, second)])
        self.assertEqual(pool.write(1, NativeMessage(99, b"request"), 1020), 0)
        self.assertEqual(pool.queue, [])
        self.assertEqual(calls[-1]["messages"][0].protocol_id, 6)

    def test_pool_queue_capacity_and_foreign_packet(self):
        second = pack_uds_request(0x7E9, b"\x62")
        pool, _, _ = self.pool([PrimitiveResult(0, (second,)) for _ in range(9)])
        pool.connect(6, 0x7E0)
        pool.connect(6, 0x7E1)
        pool.route_filter(1, bytes([255]) * 4, second.data[:4])
        self.assertEqual(pool.read(0, 1000), (3, None))
        self.assertEqual(len(pool.queue), 8)

    def test_pool_read_raw_buffer_empty_retries_and_typed_boundary(self):
        message = pack_uds_request(0x7E8, b"\x62")
        pool, _, _ = self.pool(
            [PrimitiveResult(9), PrimitiveResult(0x10), PrimitiveResult(0, (message,))]
        )
        pool.connect(6, 0x7E0)
        pool.route_filter(0, bytes([255]) * 4, message.data[:4])
        self.assertEqual(pool.read(0, 1000), (0, message))
        pool, _, _ = self.pool([PrimitiveResult(0, b"untyped")])
        pool.connect(6, 0x7E0)
        with self.assertRaises(ValueError):
            pool.read(0, 1000)

    def test_classic_scheduler_native_cancel_retains_actual_counters(self):
        context, driver = (
            Context(),
            Driver([DriverReceive(2), DriverReceive(0x1B), DriverReceive(0, b"\x62")]),
        )
        scheduler = UtilityExClassicScheduler(context, driver)
        self.assertEqual(scheduler.exchange(b"\x22"), (0, b"\x62"))
        self.assertEqual(
            scheduler.counters(),
            {
                "native_rva:17340": 0,
                "native_rva:17350": 1,
                "native_rva:17360": 100,
                "native_rva:17370": 0,
                "native_rva:17380": 3,
            },
        )
        context.cancelled = True
        driver.replies = iter([DriverReceive(0x1B, b"\x7f\x22\x21")])
        self.assertEqual(scheduler.exchange(b"\x22"), (0x1B, b"\x7f\x22\x21"))
        self.assertEqual(scheduler.fields.busy_count, 0)

    def test_classic_no_response_and_busy_exhaustion(self):
        scheduler = UtilityExClassicScheduler(Context(), Driver([DriverReceive(2)] * 3))
        self.assertEqual(scheduler.exchange(b"\x22"), (2, b""))
        self.assertEqual(scheduler.fields.no_response_count, 3)
        scheduler = UtilityExClassicScheduler(
            Context(), Driver([DriverReceive(0x1B)] * 2)
        )
        scheduler.fields.busy_limit = 2
        self.assertEqual(scheduler.exchange(b"\x22"), (0x1C, b""))
        self.assertEqual(scheduler.fields.busy_count, 2)

    def test_facade_cancellation_reads_actual_scheduler_globals(self):
        source = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll"
        )
        if not source.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        context = Context()
        context.module_sha256, context.module_bytes = SHA_18_NK, source.read_bytes()
        first = UtilityExClassicScheduler(context, Driver([DriverReceive(2)] * 3))
        comm = UtilityExComm(context)
        self.assertEqual(first.exchange(b"\x22"), (2, b""))
        self.assertEqual(comm.cancellation_counters()["native_rva:17370"], 3)
        second = UtilityExClassicScheduler(context, Driver([DriverReceive(0x1B)]))
        self.assertIs(first.fields, second.fields)
        second.fields.busy_ms = 400
        context.cancelled = True
        self.assertEqual(second.exchange(b"\x22"), (27, b""))
        self.assertEqual(
            comm.cancellation_counters(),
            {
                "native_rva:17340": 400,
                "native_rva:17350": 0,
                "native_rva:17360": 100,
                "native_rva:17370": 0,
                "native_rva:17380": 3,
            },
        )
        context.state["native_global:1015185c"] = 1
        counters = comm.cancellation_counters()
        self.assertEqual(context.state["native_global:1015185c"], 1)
        counters["native_rva:17340"] = 0
        self.assertEqual(comm.cancellation_counters()["native_rva:17340"], 400)
        for setter, getter, value in (
            ("native_rva:172f0", "native_rva:17380", 7),
            ("native_rva:17320", "native_rva:17360", 9),
            ("native_rva:17330", "native_rva:17340", 0),
        ):
            comm.configure(setter, value)
            self.assertEqual(comm.cancellation_counters()[getter], value)
            self.assertEqual(second.counters()[getter], value)
        comm.configure("native_rva:17390", 250)
        self.assertEqual(second.fields.busy_interval_ms, 250)
        for value in (-1, 0x100000000, True):
            with self.assertRaises(ValueError):
                comm.configure("native_rva:17320", value)

    def test_all_source_global_busy_setters_feed_shared_scheduler_fields(self):
        rows = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        cases = (
            (SHA_12_NK, "native_rva:fa90", "native_rva:faa0", "native_rva:fb00"),
            (SHA_18_NK, "native_rva:17320", "native_rva:17330", "native_rva:17390"),
            (SHA_DS4_NK, "native_rva:32450", "native_rva:32440", "native_rva:32460"),
            (SHA_PLUS_NK, "native_rva:33360", "native_rva:33350", "native_rva:33370"),
            (SHA_12_TY, "native_rva:b960", "native_rva:b970", None),
            (SHA_18_TY, "native_rva:121d0", "native_rva:121e0", "native_rva:12200"),
            (SHA_DS4_TY, "native_rva:7960", "native_rva:7950", None),
            (SHA_PLUS_TY, "native_rva:14320", "native_rva:14310", None),
        )
        for sha, limit, budget, delay in cases:
            with self.subTest(sha=sha):
                source = Path(
                    next(row["input_path"] for row in rows if row["sha256"] == sha)
                )
                if not source.is_file():
                    self.skipTest("Exact original BYOD modules are not supplied")
                context = Context()
                context.module_sha256, context.module_bytes = sha, source.read_bytes()
                comm = UtilityExComm(context)
                scheduler = UtilityExClassicScheduler(context, Driver())
                comm.configure(limit, 256)
                comm.configure(budget, 9000)
                self.assertEqual(scheduler.fields.busy_limit, 256)
                self.assertEqual(scheduler.fields.busy_ms, 9000)
                if delay is not None:
                    comm.configure(delay, 500)
                    self.assertEqual(scheduler.fields.busy_interval_ms, 500)

    def test_exact_native_counter_getters_are_different_for_all_nk_sources(self):
        rows = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        cases = (
            (SHA_12_NK, ("fab0", "fac0", "fad0", "fae0", "faf0")),
            (SHA_18_NK, ("17340", "17350", "17360", "17370", "17380")),
            (SHA_DS4_NK, ("321b0", "321a0", "321c0", "321e0", "321f0")),
            (SHA_PLUS_NK, ("330c0", "330b0", "330d0", "330f0", "33100")),
        )
        for sha, getters in cases:
            with self.subTest(sha=sha):
                path = Path(
                    next(row["input_path"] for row in rows if row["sha256"] == sha)
                )
                if not path.is_file():
                    self.skipTest("Exact original BYOD modules are not supplied")
                context = Context()
                context.module_sha256, context.module_bytes = sha, path.read_bytes()
                comm = UtilityExComm(context)
                scheduler = UtilityExClassicScheduler(context, Driver())
                fields = scheduler.fields
                fields.busy_ms, fields.busy_count, fields.busy_limit = 12, 34, 56
                fields.no_response_count, fields.no_response_limit = 78, 90
                self.assertEqual(
                    comm.cancellation_counters(),
                    {
                        "native_rva:" + getter: value
                        for getter, value in zip(getters, (12, 34, 56, 78, 90))
                    },
                )

    def test_ty18_global_busy_limit_changes_actual_retry_count(self):
        source = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not source.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        context = Context()
        context.module_sha256, context.module_bytes = SHA_18_TY, source.read_bytes()
        comm = UtilityExComm(context)
        driver = Driver([DriverReceive(27)] * 2)
        scheduler = UtilityExClassicScheduler(context, driver)
        comm.configure("native_rva:121d0", 2)
        self.assertEqual(scheduler.exchange(b"\x22"), (28, b""))
        self.assertEqual(len(driver.sent), 2)

    def test_native_dtcs_collect_frames_and_discard_later_headers(self):
        context = Context()
        context.module_sha256 = SHA_18_TY
        driver = Driver(
            (
                DriverReceive(0, b"\x53\x03\x12\x34"),
                DriverReceive(0, b"\x53\xff\x56\x78\x9a\xbc"),
            )
        )
        scheduler = UtilityExClassicScheduler(context, driver)
        self.assertEqual(
            scheduler.read_dtcs(), (0, b"\x53\x03\x12\x34\x56\x78\x9a\xbc")
        )
        self.assertEqual(driver.sent, [b"\x13\x80"])

    def test_native_dtcs_retry_only_before_first_accepted_frame(self):
        context = Context()
        context.module_sha256 = SHA_18_TY
        driver = Driver(
            (
                DriverReceive(27),
                DriverReceive(2),
                DriverReceive(0, b"\x53\x02\x12\x34"),
                DriverReceive(2),
            )
        )
        scheduler = UtilityExClassicScheduler(context, driver)
        self.assertEqual(scheduler.read_dtcs(0), (2, b"\x53\x02\x12\x34"))
        self.assertEqual(driver.sent, [b"\x13"] * 3)
        self.assertEqual(scheduler.fields.busy_count, 1)
        self.assertEqual(scheduler.fields.no_response_count, 1)
        driver = Driver((DriverReceive(27), DriverReceive(27)))
        scheduler = UtilityExClassicScheduler(context, driver)
        scheduler.fields.busy_limit = 2
        self.assertEqual(scheduler.read_dtcs(), (28, b""))
        self.assertEqual(len(driver.sent), 2)

    def test_native_dtcs_validate_echo_capacity_and_even_record_bytes(self):
        for data in (b"", b"\x53", b"\x54\x00", b"\x53\x01\x12", b"\x53\x01\x12\x34"):
            with self.subTest(data=data):
                context = Context()
                context.module_sha256 = SHA_18_TY
                scheduler = UtilityExClassicScheduler(
                    context, Driver((DriverReceive(0, data),))
                )
                self.assertEqual(scheduler.read_dtcs(capacity=2), (3, b""))
        context = Context()
        context.module_sha256 = SHA_18_TY
        driver = Driver((DriverReceive(0, b"\x53\x00"),))
        self.assertEqual(
            UtilityExClassicScheduler(context, driver).read_dtcs(), (0, b"\x53\x00")
        )
        context.module_sha256 = SHA_18_NK
        with self.assertRaises(UtilityExSourceError):
            UtilityExClassicScheduler(context, Driver()).read_dtcs()

    def test_p3_native_request_header_length_wrap_and_additive_checksum(self):
        message = pack_p3_request(0x33, b"\x22\xf1\x90")
        self.assertEqual(message.data, b"\x83\x33\xf0\x22\xf1\x90\x49")
        self.assertEqual(message.protocol_id, 0)
        message = pack_p3_request(0x133, bytes(0x100))
        self.assertEqual(message.data[:3], b"\x80\x33\xf0")
        self.assertEqual(message.data[-1], sum(message.data[:-1]) & 255)
        with self.assertRaises(ValueError):
            pack_p3_request(0x33, bytes(0x101D))

    def test_p3_native_response_preserves_nonbusy_negative_and_checks_source(self):
        for payload, status in (
            (b"\x62\xf1\x90", 0),
            (b"\x7f\x22\x78", 5),
            (b"\x7f\x22\x21", 27),
            (b"\x7f\x22\x33", 0),
        ):
            data = b"\x83\xf0\x33" + payload
            message = NativeMessage(1, data + bytes((sum(data) & 255,)))
            self.assertEqual(
                unpack_p3_response(message, 0x33), DriverReceive(status, payload)
            )
            self.assertEqual(unpack_p3_response(message, 0x34).status, 3)
            self.assertEqual(unpack_p3_response(message, 0x133).status, 3)
            invalid = NativeMessage(
                1, message.data[:-1] + bytes(((message.data[-1] + 1) & 255,))
            )
            self.assertEqual(unpack_p3_response(invalid, 0x33).status, 3)
        for data in (b"", b"\x80", b"\x80\xf0\x33"):
            self.assertEqual(unpack_p3_response(NativeMessage(1, data), 0x33).status, 3)

    def test_plus_ty_second_plain_fixed_object_has_distinct_native_fields(self):
        source = Path(
            "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll"
        )
        if not source.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        context = Context()
        context.module_sha256, context.module_bytes = SHA_PLUS_TY, source.read_bytes()
        first = UtilityExComm(context, "native:101392d0")
        second = UtilityExComm(context, "native:10135c58")
        second.configure_target(0x7C4, 0xE9)
        second.configure("native_rva:1e290", 1)
        self.assertIsNot(first._fields, second._fields)
        assert first._fields is not None and second._fields is not None
        self.assertEqual(
            (first._fields.primary_address, first._fields.receive_count), (0, 150)
        )
        self.assertEqual(
            (second._fields.primary_address, second._fields.receive_count), (0x7C4, 1)
        )
        with self.assertRaises(UtilityExSourceError):
            second.initialize()
        p6 = UtilityExComm(context, "native:1013e7d0")
        self.assertIsInstance(p6._fields, UtilityExP6Fields)
        self.assertIsNot(p6._fields, second._fields)

    def test_derived_selected_interrupt_ignores_lower_status_and_short_gate(self):
        context = Context()
        context.module_sha256 = SHA_18_NK

        class FaultDriver(Driver):
            def interrupt(self, timeout_ms):
                self.interrupted.append(timeout_ms)
                return 99

        driver = FaultDriver()
        selected = UtilityExSelectedPending(context, driver, derived=True)
        self.assertEqual(selected.interrupt(100), 5)
        context.state["native_global:1015185c"] = 1
        self.assertEqual(selected.interrupt(100), 20)
        self.assertEqual(driver.interrupted, [100, 100])
        selected.fields.short_circuit = 1
        context.state["native_global:1015185c"] = 1
        self.assertEqual(selected.interrupt(100), 0)
        self.assertEqual(context.state["native_global:1015185c"], 0)
        self.assertEqual(driver.interrupted, [100, 100])

    def test_selected_pending_count_abort_and_busy_reset_are_actual_globals(self):
        context = Context()
        context.module_sha256 = SHA_18_NK
        driver = Driver((DriverReceive(5, b"\x7f\x22\x78"),) * 2)
        selected = UtilityExSelectedPending(context, driver)
        selected.fields.pending_limit = 2
        selected.send(b"\x22")
        self.assertEqual(context.state["native_global:10151890"], 0)
        self.assertEqual(selected.receive().status, 5)
        self.assertEqual(driver.interrupted, [100])
        self.assertEqual(selected.fields.pending_count, 2)
        self.assertEqual(context.state["native_global:10151870"], 2)
        self.assertEqual(context.state["native_global:10151890"], 1)
        driver = Driver((DriverReceive(27),))
        selected = UtilityExSelectedPending(context, driver)
        self.assertEqual(selected.receive().status, 27)
        self.assertEqual(selected.fields.pending_count, 0)

    def test_selected_pending_time_budget_preserves_count_and_worker_handoff(self):
        context = Context()
        context.module_sha256 = SHA_18_NK
        context.state["native_global:10151890"] = 1
        context.state["native_global:101528b8"] = 1
        driver = Driver((DriverReceive(5), DriverReceive(5)))
        selected = UtilityExSelectedPending(context, driver)
        selected.fields.pending_ms = 2
        selected.fields.pending_limit = 999
        selected.send(b"\x22")
        self.assertEqual(context.state["native_global:10151890"], 1)
        self.assertEqual(selected.receive().status, 5)
        self.assertEqual(selected.fields.pending_count, 0)
        self.assertEqual(driver.interrupted, [100])

    def test_selected_pending_force_abort_is_distinct_from_outer_cancel(self):
        context = Context()
        context.module_sha256 = SHA_18_NK
        context.cancelled = True
        driver = Driver((DriverReceive(5), DriverReceive(0, b"\x62")))
        selected = UtilityExSelectedPending(context, driver)
        self.assertEqual(selected.receive(), DriverReceive(0, b"\x62"))
        self.assertEqual(driver.interrupted, [])
        context.state["native_global:1015185c"] = 1
        driver = Driver((DriverReceive(5, b"\x7f\x22\x78"),))
        selected = UtilityExSelectedPending(context, driver)
        self.assertEqual(selected.receive().status, 20)
        self.assertEqual(context.state["native_global:1015185c"], 0)
        self.assertEqual(driver.interrupted, [100])

    def test_selected_pending_continue_over_limit_and_preserve_interrupt_error(self):
        context = Context()
        context.module_sha256 = SHA_18_NK
        driver = Driver((DriverReceive(5), DriverReceive(5), DriverReceive(0, b"\x62")))
        selected = UtilityExSelectedPending(context, driver)
        selected.fields.pending_limit, selected.fields.continue_pending = 1, 1
        self.assertEqual(selected.receive(), DriverReceive(0, b"\x62"))
        self.assertEqual(selected.fields.pending_count, 2)
        self.assertEqual(driver.interrupted, [])

        class FaultDriver(Driver):
            def interrupt(self, timeout_ms):
                self.interrupted.append(timeout_ms)
                return 99

        driver = FaultDriver((DriverReceive(5),))
        selected = UtilityExSelectedPending(context, driver)
        context.state["native_global:1015185c"] = 1
        self.assertEqual(selected.receive().status, 99)
        self.assertEqual(context.state["native_global:1015185c"], 0)

    def test_all_nk_short_cleanup_setters_change_concrete_fixed_scheduler(self):
        rows = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        cases = (
            (SHA_12_NK, "native:100e9850", "native_rva:10fb0"),
            (SHA_18_NK, "native:1014f5e0", "native_rva:18840"),
            (SHA_DS4_NK, "native:101b6758", "native_rva:32b90"),
            (SHA_PLUS_NK, "native:101c18a0", "native_rva:33aa0"),
        )
        for sha, manager, setter in cases:
            with self.subTest(sha=sha):
                source = Path(
                    next(row["input_path"] for row in rows if row["sha256"] == sha)
                )
                if not source.is_file():
                    self.skipTest("Exact original BYOD modules are not supplied")
                context = Context()
                context.module_sha256, context.module_bytes = sha, source.read_bytes()
                comm = UtilityExComm(context, manager)
                self.assertIsNotNone(comm._fields)
                for value, count, ms, busy, retry, flag in (
                    (1, 1, 0, 1, 1, 1),
                    (0, 150, 180000, 255, 3, 0),
                    (0xFFFFFFFF, 1, 0, 1, 1, 1),
                ):
                    comm.configure(setter, value)
                    fields = comm._fields
                    assert fields is not None
                    self.assertEqual(
                        (
                            fields.receive_count,
                            fields.receive_ms,
                            fields.busy_count,
                            fields.retry_count,
                            fields.response_pending_seen,
                        ),
                        (count, ms, busy, retry, flag),
                    )
                    self.assertEqual(fields.busy_ms, 0)
                    driver = Driver((DriverReceive(2),) * retry)
                    scheduler = UtilityExUDSScheduler(context, driver, fields=fields)
                    self.assertEqual(scheduler.exchange(b"\x22"), (2, b""))
                    self.assertEqual(len(driver.sent), retry)

    def test_native_support_append_retains_duplicates_first_match_and_no_refresh_limit(
        self,
    ):
        for sha in (SHA_12_NK, SHA_18_NK, SHA_DS4_NK, SHA_PLUS_NK):
            with self.subTest(sha=sha):
                context = Context()
                context.module_sha256 = sha
                cache = UtilityExSupportCache(context)
                self.assertEqual(cache.append(b"\x09\x01\xff", 1, (0x7E0, 0), 6), 99)
                self.assertEqual(cache.append(b"\x09\x01\x00", 1, (0x7E0, 0), 6), 99)
                first = cache.snapshot(1, (0x7E0, 0), 6)
                assert first is not None
                self.assertEqual(first[0][:3], b"\x09\x01\xff")
                self.assertEqual(first[1][9], 0)
                for value in range(17):
                    self.assertEqual(
                        cache.append(b"\x05\x01\xff", 2, (value, 0), 6), 99
                    )
                self.assertEqual(len(cache.profiles), 19)
                with patch(
                    "scripts.utility_ex_comm.UtilityExSupportProfile",
                    side_effect=MemoryError,
                ):
                    self.assertEqual(cache.append(b"", 1, (0, 0), 6), 81)
                self.assertEqual(len(cache.profiles), 19)

    def test_all_nk_support_caches_bind_source_profiles_and_zero_filled_header(self):
        for sha in (SHA_12_NK, SHA_18_NK, SHA_DS4_NK, SHA_PLUS_NK):
            with self.subTest(sha=sha):
                context = Context()
                context.module_sha256 = sha
                driver = Driver((DriverReceive(0, b"\xe8"), DriverReceive(2)))
                scheduler = UtilityExClassicScheduler(context, driver)
                # A short E8 header with kind0 is accepted from the zeroed
                # backing, then the next lower error supplies the final status.
                self.assertEqual(scheduler.support_snapshot(0)[0], 2)
                self.assertEqual(driver.sent, [b"\xa8\x00"])
                driver = Driver(
                    (DriverReceive(0, b"\xe8\x02\x09\x01\xff"), DriverReceive(2))
                )
                scheduler = UtilityExClassicScheduler(context, driver)
                cache = UtilityExSupportCache(context)
                self.assertEqual(cache.refresh(scheduler, 2, (0x7B0, 0), 6), 0)
                result = cache.snapshot(2, (0x7B0, 0), 6)
                self.assertIsNotNone(result)
                assert result is not None
                self.assertEqual((result[0][:3], result[1][9]), (b"\x09\x01\xff", 0))
                self.assertIsNone(cache.snapshot(2, (0x7B0, 0), 16))

    def test_a8_snapshot_collects_multiple_frames_without_resending(self):
        context, driver = (
            Context(),
            Driver(
                [
                    DriverReceive(0, b"\xe8\x01\x09\x02\xff\xff"),
                    DriverReceive(0, b"\xe8\x01\x05\x01\x7f"),
                    DriverReceive(2),
                ]
            ),
        )
        scheduler = UtilityExClassicScheduler(context, driver)
        status, data, offsets = scheduler.support_snapshot(1)
        self.assertEqual(status, 0)
        self.assertEqual(len(data), 0x1020)
        self.assertEqual(data[:7], b"\x09\x02\xff\xff\x05\x01\x7f")
        self.assertEqual((offsets[9], offsets[5], offsets[8]), (0, 4, 0x1020))
        self.assertEqual(len(offsets), 256)
        self.assertEqual(driver.sent, [b"\xa8\x01"])

    def test_a8_snapshot_retries_only_before_first_accepted_frame(self):
        context, driver = (
            Context(),
            Driver(
                [
                    DriverReceive(27),
                    DriverReceive(2),
                    DriverReceive(0, b"\xe8\x02\x05\x01\xff"),
                    DriverReceive(27),
                ]
            ),
        )
        scheduler = UtilityExClassicScheduler(context, driver)
        self.assertEqual(scheduler.support_snapshot(2)[0], 0)
        self.assertEqual(driver.sent, [b"\xa8\x02"] * 3)
        self.assertEqual(scheduler.fields.busy_count, 1)
        self.assertEqual(scheduler.fields.no_response_count, 1)

    def test_a8_native_offset_zero_return_branch_and_duplicate_record(self):
        for replies, expected in (
            ([DriverReceive(2)] * 3, 2),
            ([DriverReceive(0, b"\xe8\x02"), DriverReceive(2)], 2),
            ([DriverReceive(0, b"\xe8\x03\x05\x01\xff")], 3),
            (
                [
                    DriverReceive(0, b"\xe8\x02\x05\x01\xff"),
                    DriverReceive(0, b"\xe8\x02\x05\x01\xff"),
                    DriverReceive(2),
                ],
                2,
            ),
        ):
            with self.subTest(expected=expected, replies=replies):
                scheduler = UtilityExClassicScheduler(Context(), Driver(replies))
                self.assertEqual(scheduler.support_snapshot(2)[0], expected)

    def test_a8_snapshot_short_record_uses_native_zero_filled_receive_tail(self):
        scheduler = UtilityExClassicScheduler(
            Context(),
            Driver([DriverReceive(0, b"\xe8\x01\x09\x03\xff"), DriverReceive(2)]),
        )
        status, data, offsets = scheduler.support_snapshot(1)
        self.assertEqual(status, 0)
        self.assertEqual(data[:5], b"\x09\x03\xff\0\0")
        self.assertEqual(offsets[9], 0)

    def test_a8_snapshot_cancellation_and_send_fault_do_not_claim_records(self):
        context = Context()
        context.cancelled = True
        driver = Driver([DriverReceive(27)])
        scheduler = UtilityExClassicScheduler(context, driver)
        self.assertEqual(scheduler.support_snapshot(1)[0], 27)
        self.assertEqual(scheduler.fields.busy_count, 0)
        scheduler = UtilityExClassicScheduler(Context(), Driver(send_status=99))
        self.assertEqual(scheduler.support_snapshot(1)[0], 99)
        for kind in (-1, 256, True):
            with self.assertRaises(ValueError):
                scheduler.support_snapshot(kind)

    def test_native_driver_lock_queue_per_protocol_and_timeout(self):
        context = Context()
        lock = UtilityExDriverArbitration(context)
        self.assertEqual(lock.acquire(1, 6, 1000), 0)
        self.assertEqual(lock.acquire(1, 6, 1000), 0)
        self.assertEqual(lock.waiters, [(1, 6)])
        self.assertEqual(lock.enroll(2, 6), 0)
        self.assertEqual(lock.enroll(3, 4), 0)
        self.assertFalse(lock.ready(2, 6))
        self.assertTrue(lock.ready(3, 4))
        self.assertEqual(lock.enroll(4, 4), 0)
        self.assertFalse(lock.ready(4, 4))
        self.assertEqual(lock.acquire(5, 1, 1000), 3)
        self.assertEqual(lock.acquire(2, 6, 250), 2)
        self.assertEqual(context.tick, 250)
        self.assertEqual(lock.waiters, [(1, 6), (3, 4), (4, 4)])
        self.assertEqual(lock.release(3), 1)
        self.assertTrue(lock.ready(4, 4))
        self.assertEqual(lock.release(3), 0)
        self.assertEqual(lock.acquire(7, 1, 0), 2)
        self.assertNotIn((7, 1), lock.waiters)

    def test_pool_exact_oem_and_nonstandard_wrapper_connect_branches(self):
        for mode, protocol, operation, native_protocol in (
            (0, 6, "PassThruConnect", 6),
            (13, 6, "PassThruConnect", 0x1000C),
            (0x15, 0x8005, "PassThruOemConnect", 0x8005),
        ):
            with self.subTest(mode=mode):
                calls = []

                def provider(arguments, remaining, calls=calls):
                    calls.append(arguments)
                    return PrimitiveResult(0, 42)

                context = Context()
                pool = UtilityExPassThruPool(context, J2534Device2026(provider))
                self.assertEqual(
                    pool.connect(
                        protocol,
                        0x7E0,
                        flags=128,
                        native_mode=mode,
                        oem_parameter=0x5566,
                    ),
                    (0, 0),
                )
                self.assertEqual(calls[0]["operation"], operation)
                self.assertEqual(calls[0]["protocol_id"], native_protocol)
                self.assertEqual(calls[0]["native_protocol"], protocol)
                self.assertEqual(
                    calls[0].get("oem_parameter"), 0x5566 if mode == 0x15 else None
                )
                self.assertEqual(pool.arbitration.waiters, [])

    def test_pool_native_connect_lock_failure_does_not_call_sdk(self):
        pool, calls, context = self.pool()
        pool.arbitration.enroll(1, 6)
        self.assertEqual(pool.connect(6, 0x7E0), (99, 4))
        self.assertEqual(context.tick, 3000)
        self.assertEqual(calls, [])
        self.assertEqual(pool.arbitration.waiters, [(1, 6)])
        self.assertEqual(pool.owned, set())

    def test_pool_native_disconnect_still_calls_sdk_after_lock_failure(self):
        pool, calls, context = self.pool()
        pool.connect(6, 0x7E0)
        pool.arbitration.enroll(1, 6)
        self.assertEqual(pool.close(0), 0)
        self.assertEqual(context.tick, 3000)
        self.assertEqual(calls[-1]["operation"], "PassThruDisconnect")
        self.assertEqual(pool.owned, set())
        self.assertEqual(pool.arbitration.waiters, [(1, 6)])

    def test_pool_read_lock_queue_arrival_interrupts_before_sdk_read(self):
        pool, calls, context = self.pool()
        pool.connect(6, 0x7E0)
        pool.arbitration.enroll(1, 6)
        message = NativeMessage(6, b"queued")
        sleep = context.sleep

        def arrival(milliseconds):
            sleep(milliseconds)
            pool.queue.append((0, message))

        context.sleep = arrival
        self.assertEqual(pool.read(0, 1000), (0, message))
        self.assertEqual(len(calls), 1)
        self.assertLess(context.tick, 200)
        self.assertEqual(pool.arbitration.waiters, [(1, 6)])

    def test_pool_read_lock_timeout_releases_host_waiter_without_sdk_read(self):
        pool, calls, context = self.pool()
        pool.connect(6, 0x7E0)
        pool.arbitration.enroll(1, 6)
        self.assertEqual(pool.read(0, 250), (2, None))
        self.assertEqual(len(calls), 1)
        self.assertLess(context.tick, 300)
        self.assertEqual(pool.arbitration.waiters, [(1, 6)])

    def typed_binding(self, overrides=None, *, constructor_parameter=0):
        context = Context()
        context.module_sha256 = SHA_18_NK
        names = (
            "PassThruConnect",
            "PassThruOemConnect",
            "PassThruDisconnect",
            "PassThruIoctl",
            "PassThruGetLastError",
            "PassThruWriteMsgs",
            "PassThruReadMsgs",
            "PassThruStartPeriodicMsg",
            "PassThruStopPeriodicMsg",
            "PassThruStartMsgFilter",
            "PassThruStopMsgFilter",
            "PassThruSetProgrammingVoltage",
            "PassThruReadVersion",
            "J2534CtrlInitialize",
            "J2534CtrlFinalize",
        )
        exports: dict[str, Callable[..., object]] = dict.fromkeys(
            names, lambda *arguments: PrimitiveResult()
        )
        exports.update(overrides or {})
        return context, UtilityDriverBinding(
            cast(UtilityExContext, context),
            6,
            exports,
            constructor_parameter=constructor_parameter,
        )

    def p3_lower(self, payloads=(), *, fast_statuses=(), write_status=0):
        calls = []
        reads, fast = iter(payloads), iter(fast_statuses)

        def connect(protocol, flags, output):
            calls.append(("connect", protocol, flags))
            output[:] = (74).to_bytes(4, "little")
            return PrimitiveResult()

        def ioctl(channel, kind, payload, output):
            calls.append(("ioctl", kind, payload))
            if kind == 5:
                status = next(fast, 0)
                if status:
                    return PrimitiveResult(status)
                data = b"\x83\xf0\x33\xc1\x01\x02"
                output[0] = NativeMessage(4, data + bytes((sum(data) & 255,)))
            elif kind == 1:
                payload[0] = (10, 55)
            return PrimitiveResult()

        def read(channel, messages, count, timeout):
            payload = next(reads)
            if type(payload) is int:
                return PrimitiveResult(payload)
            data = bytes(((len(payload) + 0x80) & 255, 0xF0, 0x33)) + payload
            messages[0] = NativeMessage(4, data + bytes((sum(data) & 255,)))
            return PrimitiveResult()

        def write(channel, messages, count, timeout):
            calls.append(("write", messages[0], timeout))
            return PrimitiveResult(write_status)

        context, binding = self.typed_binding(
            {
                "PassThruConnect": connect,
                "PassThruIoctl": ioctl,
                "PassThruReadMsgs": read,
                "PassThruWriteMsgs": write,
                "PassThruDisconnect": lambda channel: (
                    calls.append(("disconnect", channel)),
                    PrimitiveResult(),
                )[1],
            }
        )
        driver = UtilityExDirectDriver(
            context, UtilityExDriverPrimitives(context, binding), 4
        )
        context.bindings[4] = binding
        return UtilityExP3Lower(context, driver), calls, context

    def test_ty18_selected_pending_uses_own_native_globals_and_derived_interrupt(self):
        context = Context()
        context.module_sha256 = SHA_18_TY
        context.state["native_global:1011f768"] = 1
        context.state["native_global:1011f7a4"] = 1
        context.state["native_global:101207cc"] = 1
        driver = Driver([DriverReceive(5)])
        pending = UtilityExSelectedPending(context, driver, derived=True)
        pending.fields.pending_limit = 1
        self.assertEqual(pending.send(b"\x22"), 0)
        self.assertEqual(context.state["native_global:1011f7a4"], 1)
        self.assertEqual(pending.receive().status, 20)
        self.assertEqual(context.state["native_global:1011f77c"], 1)
        self.assertEqual(context.state["native_global:1011f768"], 0)
        self.assertNotIn("native_global:10151870", context.state)
        pending.fields.short_circuit = 1
        self.assertEqual(pending.interrupt(100), 0)

    def test_all_nk_selected_override_and_profile_are_literal_global_setters(self):
        cases = (
            (SHA_12_NK, 0xF830, 0xF840, 0x100EA9A8, 0x100EA9D0),
            (SHA_18_NK, 0x170A0, 0x170B0, 0x10151858, 0x10151880),
            (SHA_DS4_NK, 0x323D0, 0x323E0, 0x101B8B4C, 0x101B8B50),
            (SHA_PLUS_NK, 0x332E0, 0x332F0, 0x101C807C, 0x101C8080),
        )
        rows = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for sha, override, profile, override_global, profile_global in cases:
            with self.subTest(source=sha):
                context = Context()
                source = Path(
                    next(row["input_path"] for row in rows if row["sha256"] == sha)
                )
                context.module_sha256, context.module_bytes = sha, source.read_bytes()
                comm = UtilityExComm(context, "selected")
                comm.configure(f"native_rva:{override:x}", 0x12345678)
                comm.configure(f"native_rva:{profile:x}", 0x90ABCDEF)
                self.assertEqual(
                    context.state[f"native_global:{override_global:x}"], 0x12345678
                )
                self.assertEqual(
                    context.state[f"native_global:{profile_global:x}"], 0x90ABCDEF
                )

    def test_support_length_all_nk_sources_requires_current_object_and_exact_kind_codec(
        self,
    ):
        rows = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        cases = (
            (SHA_12_NK, 0x100EA9A4, 0x100E6240),
            (SHA_18_NK, 0x10151854, 0x1014AEF0),
            (SHA_DS4_NK, 0x101B8B44, 0x101B4208),
            (SHA_PLUS_NK, 0x101C8074, 0x101BF318),
        )
        for sha, pointer_global, selected in cases:
            with self.subTest(source=sha):
                context = Context()
                context.module_sha256 = sha
                context.module_bytes = Path(
                    next(row["input_path"] for row in rows if row["sha256"] == sha)
                ).read_bytes()
                comm = UtilityExComm(context)
                cache = comm._support_cache()
                for kind in (1, 2, 3):
                    self.assertEqual(
                        cache.append(b"\xc1\x04\x00\xff\x00\x01", kind, (0, 0), 1), 99
                    )
                self.assertEqual(comm.support_length(3, 0xC1), 0)
                context.state[f"native_global:{pointer_global:x}"] = selected
                self.assertEqual(comm.support_length(1, 0xC1), 0)
                self.assertEqual(comm.support_length(2, 0x1C1), 2)
                self.assertEqual(comm.support_length(3, 0xC1), 4)
                self.assertEqual(comm.support_length(3, 0xC2), 0)
                comm.select_target(1)
                self.assertEqual(comm.support_length(3, 0xC1), 0)
                context.state[f"native_global:{pointer_global:x}"] = 0
                comm.select_target(0)
                self.assertEqual(comm.support_length(3, 0xC1), 0)

    def test_actual_context_fixed_facade_composes_sdk_session_worker_and_nrc_fields(
        self,
    ):
        cases = (
            (
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll",
                "native:1014f5e0",
            ),
            (
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
                "native:1011d4f0",
            ),
            (
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
                "native:1011c400",
            ),
            (
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
                "native:1011a220",
            ),
        )
        for path, selector in cases:
            with self.subTest(selector=selector):
                self._assert_actual_fixed_facade(path, selector)

    def test_actual_ty18_sis_export_and_facade_keep_separate_native_schema(self):
        self._actual_sis_case(False)

    def test_actual_plus_sis_facade_keeps_own_json_controller_and_lower_schema(self):
        self._actual_sis_case(True)

    def _actual_sis_case(self, plus):
        from scripts.utility_ex import _DRIVER_SLOTS, _SIS_DRIVER_SLOTS, UtilityExEngine

        path = Path(
            "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll"
            if plus
            else "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not path.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        calls = []
        handles = iter((101, 102, 103, 104))
        measurements = iter((500, 8000, 12000))
        packets = [bytes(1), bytes(14), bytes(17)]
        for response in (
            b"\x50\x01",
            b"\x50\x03",
            b"\x62\x01",
            b"\x7f\x22\x33",
            b"\x50\x01",
        ):
            payload = bytes(4) + response
            packets.extend(
                (
                    b"\x02\xfd\x80\x02" + bytes(9),
                    b"\x02\xfd\x80\x01" + len(payload).to_bytes(4, "big"),
                    payload,
                )
            )
        incoming = iter(packets)

        def initialize(kind, output, *extra):
            calls.append(("controller", kind, *extra))
            output[:] = (51).to_bytes(4, "little")
            return PrimitiveResult(7)

        def connect(controller, protocol, flags, oem, kind, count, pins, output):
            calls.append(
                ("connect", controller, protocol, flags, oem, kind, count, pins)
            )
            output[:] = next(handles).to_bytes(4, "little")
            return PrimitiveResult()

        def logical(parent, protocol, flags, configuration, output):
            output[:] = next(handles).to_bytes(4, "little")
            return PrimitiveResult()

        def ioctl(handle, kind, payload, output):
            if kind == 3:
                output[:] = next(measurements).to_bytes(4, "little")
            elif kind == 0x8023:
                output[:] = (2).to_bytes(4, "little")
            return PrimitiveResult()

        def read(handle, message, count, timeout):
            data = next(incoming)
            message.data[: len(data)] = data
            message.native_14 = len(data)
            return PrimitiveResult()

        def queue(handle, message, count):
            calls.append(("queue", handle, bytes(message.data[: message.length])))
            return PrimitiveResult()

        def close(kind, handle):
            calls.append((kind, handle))
            return PrimitiveResult()

        exports: dict[str, Callable[..., object]] = dict.fromkeys(
            (_DRIVER_SLOTS | _SIS_DRIVER_SLOTS).values(),
            lambda *args: PrimitiveResult(),
        )
        exports.update(
            {
                "J2534CtrlInitialize": initialize,
                "PassThruConnect_v0500": connect,
                "PassThruLogicalConnect_v0500": logical,
                "PassThruIoctl_v0500": ioctl,
                "PassThruReadMsgs_v0500": read,
                "PassThruQueueMsgs_v0500": queue,
                "PassThruLogicalDisconnect_v0500": lambda handle: close(
                    "logical_close", handle
                ),
                "PassThruDisconnect_v0500": lambda handle: close(
                    "physical_close", handle
                ),
            }
        )

        class Host(Context):
            def get_parameter(self, key):
                return {
                    0x74: 0x701,
                    0x6F: 20,
                    0x70: 20,
                    503: 0x01020304,
                    504: 1500,
                    505: 2000,
                    506: 100,
                    507: 5000,
                    509: 0x26DE,
                    514: 0x0E80,
                    0x71: 0x22,
                }.get(key, 0)

            def get_data_size(self, key):
                return 0

            def get_data(self, key):
                return b""

            def set_parameter(self, key, value):
                return 0

            def write_parameters(self):
                return 0

        context = UtilityExContext(
            path.read_bytes(),
            Host(),
            None,
            None,
            sis_driver_exports=exports,
            json_exports={
                "JsonDGetData": lambda kind, section, key: 0,
                "JsonSGetData": lambda *args: "",
            },
            win32_exports={
                "GetPrivateProfileIntA": lambda section, key, default, filename: default
            },
        )
        if plus:
            # Direct concrete controller primitive until83's Plus export is joined.
            lifecycle = context.comm("native:10134b78")._sis_lifecycle(create=True)
            self.assertEqual(lifecycle.driver.initialize_controller(), 0)
        else:
            self.assertIsNone(UtilityExEngine(context).invoke("_Ex2InitializeDoIP@0"))
        comm = context.comm("native:10134b78" if plus else "native:1011e618")
        self.addCleanup(comm.finalize)
        self.assertEqual(comm.initialize(0), 0)
        self.assertEqual(
            calls[:2],
            [
                ("controller", 2, 0) if plus else ("controller", 2),
                ("connect", 51, 0x800F, 0, 0x22, 1, 4, (3, 11, 12, 13)),
            ],
        )
        comm.configure("native_1060", 1)
        self.assertEqual(comm.session(3, 1, normal_first=True), 0)
        self.assertEqual(comm.exchange(b"\x22\x01"), (0, b"\x62\x01"))
        self.assertEqual(comm.exchange(b"\x22\x02")[0], 7)
        self.assertEqual(
            comm.read_field("native_rva:1eb90" if plus else "native_rva:1ba20"), 108
        )
        with self.assertRaises(UtilityExSourceError):
            comm.read_field("native_10b0")
        comm.configure("native_lower_3c" if plus else "native_lower_38", 0x702)
        context._cancel.set()
        self.assertEqual(comm.cleanup_session(1, 1, stop_on_error=True), 0)
        self.assertTrue(context.is_cancelled())
        diagnostic = [
            call[2]
            for call in calls
            if call[0] == "queue" and call[2][2:4] == b"\x80\x01"
        ]
        self.assertEqual(diagnostic[-1][10:], b"\x07\x02\x10\x01")
        self.assertEqual(comm._sis_lifecycle().driver.address, 0x701)
        self.assertIsNone(comm.finalize())
        self.assertEqual(
            calls[-4:],
            [
                ("logical_close", 104),
                ("logical_close", 103),
                ("logical_close", 102),
                ("physical_close", 101),
            ],
        )

    def test_actual_modern_fixed_facades_run_source_specific_driver_and_cleanup(self):
        queue = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for sha, selector in (
            (SHA_DS4_NK, "native:101b6758"),
            (SHA_DS4_TY, "native:1006cf88"),
            (SHA_PLUS_NK, "native:101c18a0"),
            (SHA_PLUS_TY, "native:101392d0"),
            (SHA_PLUS_TY, "native:10135c58"),
            (SHA_PLUS_TY, "native:1013d6a8"),
            (SHA_PLUS_TY, "native:10136e10"),
        ):
            with self.subTest(source=sha, selector=selector):
                source = next(row for row in queue if row["sha256"] == sha)
                self._assert_actual_fixed_facade(source["input_path"], selector)

    def test_actual_plus_mode74_uses_source_response_address_delta16(self):
        queue = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for sha, selector in (
            (SHA_PLUS_NK, "native:101c18a0"),
            (SHA_PLUS_TY, "native:101392d0"),
        ):
            with self.subTest(source=sha):
                source = next(row for row in queue if row["sha256"] == sha)
                self._assert_actual_fixed_facade(
                    source["input_path"], selector, mode=0x74
                )

    def test_actual_12_fixed_facades_use_older_native_lower_layout(self):
        queue = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for sha, selector in (
            (SHA_12_NK, "native:100e9850"),
            (SHA_12_TY, "native:100aed50"),
        ):
            with self.subTest(source=sha):
                source = next(row for row in queue if row["sha256"] == sha)
                self._assert_actual_fixed_facade(source["input_path"], selector)

    def test_actual_all8_fixed_extended_and_oem_source_branches(self):
        queue = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for sha, selector in (
            (SHA_12_NK, "native:100e9850"),
            (SHA_12_TY, "native:100aed50"),
            (SHA_18_NK, "native:1014f5e0"),
            (SHA_18_TY, "native:1011d4f0"),
            (SHA_DS4_NK, "native:101b6758"),
            (SHA_DS4_TY, "native:1006cf88"),
            (SHA_PLUS_NK, "native:101c18a0"),
            (SHA_PLUS_TY, "native:101392d0"),
        ):
            for protocol in (0x22, 0x62):
                with self.subTest(source=sha, protocol=protocol):
                    source = next(row for row in queue if row["sha256"] == sha)
                    self._assert_actual_fixed_facade(
                        source["input_path"], selector, mode=0x15, protocol=protocol
                    )

    def test_actual_all8_direct_driver_uses_each_standard_constructor(self):
        from scripts.utility_ex import _DRIVER_SLOTS

        queue = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )

        class Host(Context):
            def get_parameter(self, key):
                return 0

            def get_data_size(self, key):
                return 0

            def get_data(self, key):
                return b""

            def set_parameter(self, key, value):
                return 0

            def write_parameters(self):
                return 0

        for row in queue:
            with self.subTest(source=row["sha256"]):
                calls = []

                def connect(protocol, flags, output, *, calls=calls):
                    calls.append(("connect", protocol, flags))
                    output[:] = (42).to_bytes(4, "little")
                    return PrimitiveResult()

                def disconnect(handle, *, calls=calls):
                    calls.append(("disconnect", handle))
                    return PrimitiveResult()

                _fake, binding = self.typed_binding(
                    {
                        "PassThruConnect": connect,
                        "PassThruDisconnect": disconnect,
                        "PassThruReadMsgs": lambda *args: PrimitiveResult(9),
                    }
                )
                exports = {
                    name: cast(Callable[..., object], binding.resolve(slot))
                    for slot, name in _DRIVER_SLOTS.items()
                }
                context = UtilityExContext(
                    Path(row["input_path"]).read_bytes(),
                    Host(),
                    None,
                    None,
                    driver_exports=exports,
                )
                driver = UtilityExDirectDriver(
                    context,
                    UtilityExDriverPrimitives(context, context.driver_binding(4)),
                    4,
                )
                self.assertEqual(driver.connect(0x33), 0)
                self.assertEqual(driver.connect(0x33), 13)
                self.assertEqual(driver.connect(0x34), 14)
                self.assertEqual(driver.write(NativeMessage(4, b"abc"), 1000), 0)
                self.assertEqual(driver.read(1000), (2, None))
                self.assertEqual(driver.ioctl(2, ((1, 9600),)), 0)
                self.assertEqual(driver.finalize(), 0)
                self.assertEqual(calls, [("connect", 4, 0x200), ("disconnect", 42)])

    def test_actual_broadcast_facade_keeps_functional_wire_and_physical_response_separate(
        self,
    ):
        from scripts.utility_ex_comm import _FIXED_OBJECTS

        rows = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for row in rows:
            selector = f"native:{_FIXED_OBJECTS[row['sha256']]:x}"
            for protocol in (0x12, 0x62):
                with self.subTest(source=row["sha256"], protocol=protocol):
                    self._assert_actual_fixed_facade(
                        row["input_path"],
                        selector,
                        broadcast=True,
                        mode=0x15,
                        protocol=protocol,
                    )
        row = next(row for row in rows if row["sha256"] == SHA_18_TY)
        for selector in ("native:1011c400", "native:1011b310"):
            self._assert_actual_fixed_facade(
                row["input_path"], selector, broadcast=True
            )

    def _assert_actual_fixed_facade(
        self, source_path, selector, *, broadcast=False, mode=0x14, protocol=0x12
    ):
        path = Path(source_path)
        if not path.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        replies = iter(
            (
                b"\x50\x01",
                b"\x50\x03",
                b"\x62\xf1\x90",
                b"\x7f\x22\x33",
                b"\x50\x01",
                b"\x71\x02",
                b"\x50\x01",
            )
        )
        calls = []
        filter_ids = iter((51, 52))

        def connect(protocol, flags, output):
            calls.append(("connect", protocol, flags))
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def oem_connect(protocol, flags, parameter, output):
            calls.append(("oem_connect", protocol, flags, parameter))
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def start_filter(channel, kind, mask, pattern, flow, output):
            calls.append(("filter", kind))
            output[:] = next(filter_ids).to_bytes(4, "little")
            return PrimitiveResult()

        def write(channel, messages, count, timeout):
            calls.append(("write", messages[0].data, timeout))
            return PrimitiveResult()

        def read(channel, messages, count, timeout):
            response_address = 0x7F0 if mode == 0x74 else 0x7E8
            messages[0] = NativeMessage(
                0x8005 if protocol == 0x62 else 6,
                response_address.to_bytes(4, "big")
                + (b"\x29" if protocol == 0x22 else b"")
                + next(replies),
            )
            return PrimitiveResult()

        def stop_filter(channel, identifier):
            calls.append(("stop_filter", identifier))
            return PrimitiveResult()

        def disconnect(channel):
            calls.append(("disconnect", channel))
            return PrimitiveResult()

        _, binding = self.typed_binding(
            {
                "PassThruConnect": connect,
                "PassThruOemConnect": oem_connect,
                "PassThruStartMsgFilter": start_filter,
                "PassThruWriteMsgs": write,
                "PassThruReadMsgs": read,
                "PassThruStopMsgFilter": stop_filter,
                "PassThruDisconnect": disconnect,
            }
        )
        names = (
            "PassThruConnect",
            "PassThruOemConnect",
            "PassThruDisconnect",
            "PassThruIoctl",
            "PassThruGetLastError",
            "PassThruWriteMsgs",
            "PassThruReadMsgs",
            "PassThruStartPeriodicMsg",
            "PassThruStopPeriodicMsg",
            "PassThruStartMsgFilter",
            "PassThruStopMsgFilter",
            "PassThruSetProgrammingVoltage",
            "PassThruReadVersion",
            "J2534CtrlInitialize",
            "J2534CtrlFinalize",
        )
        exports = {
            name: cast(
                Callable[..., object], binding.resolve(binding.slot_offset(name))
            )
            for name in names
        }

        class Host:
            def __init__(self):
                self.tick = 0

            def get_parameter(self, key):
                return {
                    0x6F: mode,
                    0x70: protocol,
                    0xAB: 0x29 if protocol == 0x22 else 0,
                    0x74: 0x7E0,
                    0xD3: 0xFFFFFFFF,
                    0xDD: 0xFFFFFFFF,
                }.get(key, 0)

            def get_data_size(self, key):
                return 8 if key == 500 else 0

            def get_data(self, key):
                return (
                    (1).to_bytes(4, "little") + (500000).to_bytes(4, "little")
                    if key == 500
                    else b""
                )

            def set_parameter(self, key, value):
                return 0

            def write_parameters(self):
                return 0

            def ticks(self):
                self.tick += 1
                return self.tick

            def sleep(self, milliseconds):
                if threading.current_thread() is not threading.main_thread():
                    time.sleep(milliseconds / 1000)
                self.tick += milliseconds

        context = UtilityExContext(
            path.read_bytes(), Host(), None, None, driver_exports=exports
        )
        comm = context.comm(selector)
        try:
            if context.module_sha256 in (SHA_DS4_NK, SHA_DS4_TY):
                comm.configure_target(0x7E0)
            self.assertEqual(comm.select_diagnostic_mode(0x101), 0)
            if broadcast:
                comm.configure_target(0x700, 0, 0x7DF, 0, 0x7E0)
                self.assertEqual(comm.select_diagnostic_mode(3), 0)
            self.assertEqual(comm.initialize(0), 0)
            self.assertEqual(comm.select_diagnostic_mode(3 if broadcast else 1), 0)
            self.assertEqual(comm.select_diagnostic_mode(2), 13)
            self.assertEqual(comm.select_diagnostic_mode(1 if broadcast else 3), 13)
            comm.configure("native_1064", 1)
            if context.module_sha256 == SHA_18_TY:
                comm.configure("native_rva:1a890", 2500)
            self.assertEqual(comm.session(3, 1, normal_first=True), 0)
            lifecycle = comm._fixed_lifecycle()
            self.assertTrue(lifecycle.worker_active)
            self.assertEqual(comm.exchange(b"\x22\xf1\x90"), (0, b"\x62\xf1\x90"))
            self.assertEqual(comm.exchange(b"\x22\xf1\x91"), (7, b"\x7f\x22\x33"))
            self.assertEqual(comm.read_field("native_10b0"), 108)
            self.assertEqual(comm.session(1, 1), 0)
            self.assertFalse(lifecycle.worker_active)
            context._cancel.set()
            self.assertEqual(comm.cleanup_exchange(b"\x31\x02"), (0, b"\x71\x02"))
            self.assertEqual(comm.cleanup_session(1, 1, stop_on_error=True), 0)
            self.assertEqual(lifecycle.fields.current_session, 1)
            self.assertFalse(lifecycle.worker_active)
            self.assertTrue(context.is_cancelled())
        finally:
            comm.finalize()
        self.assertEqual(
            calls[0],
            ("oem_connect", 0x8005, 0, 0)
            if protocol == 0x62
            else ("connect", 6, 0x80 if protocol == 0x22 else 0),
        )
        expected_timeout = 2500 if context.module_sha256 == SHA_18_TY else 1020
        self.assertTrue(
            all(call[2] == expected_timeout for call in calls if call[0] == "write")
        )
        self.assertEqual(
            calls[-3:], [("stop_filter", 51), ("stop_filter", 52), ("disconnect", 42)]
        )
        self.assertEqual(
            [call[1] for call in calls if call[0] == "write"],
            [
                (b"\0\0\x07\xdf" if broadcast else b"\0\0\x07\xe0")
                + (b"\x29" if protocol == 0x22 else b"")
                + payload
                for payload in (
                    b"\x10\x01",
                    b"\x10\x03",
                    b"\x22\xf1\x90",
                    b"\x22\xf1\x91",
                    b"\x10\x01",
                    b"\x31\x02",
                    b"\x10\x01",
                )
            ],
        )

    def test_actual_nk18_selected_facade_composes_raw_driver_and_native_p3(self):
        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll"
        )
        if not path.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        _, calls, context = self.p3_lower((b"\x62\xf1\x90",))
        context.module_bytes = path.read_bytes()
        context.parameters = {0x6F: 3, 0x70: 0x11, 0x74: 0x33, 0xAB: 0}
        context.data[500] = (1).to_bytes(4, "little") + (9600).to_bytes(4, "little")
        comm = UtilityExComm(context)
        self.assertEqual(comm.initialize(0), 0)
        self.assertEqual(calls[:2], [("connect", 4, 0x200), ("ioctl", 2, ((1, 9600),))])
        self.assertEqual(context.state["native_global:10151854"], 0x1014AEF0)
        self.assertEqual(comm.exchange(b"\x22\xf1\x90"), (0, b"\x62\xf1\x90"))
        self.assertEqual(calls[-1][1], pack_p3_request(0x33, b"\x22\xf1\x90", 4))
        self.assertEqual(comm.selected_protocol(), 1)
        comm.finalize()
        self.assertEqual(calls[-1], ("disconnect", 74))
        self.assertEqual(context.state["native_global:10151854"], 0)
        with self.assertRaises(UtilityExSourceError):
            comm.exchange(b"\x22")

    def test_actual_original_context_selected_p3_runs_all8_native_globals(
        self,
    ):
        from scripts.utility_ex import _DRIVER_SLOTS

        queue = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for sha, selected_global, reply, expected in (
            (SHA_12_NK, "native_global:100ea9a4", b"\x62\xf1\x90", 0),
            (SHA_12_TY, "native_global:100afea0", b"\x62\xf1\x90", 0),
            (SHA_DS4_NK, "native_global:101b8b44", b"\x62\xf1\x90", 0),
            (SHA_DS4_TY, "native_global:1006f378", b"\x62\xf1\x90", 0),
            (SHA_PLUS_NK, "native_global:101c8074", b"\x62\xf1\x90", 0),
            (SHA_PLUS_TY, "native_global:1013faa8", b"\x62\xf1\x90", 0),
            (
                SHA_18_NK,
                "native_global:10151854",
                b"\x62\xf1\x90",
                0,
            ),
            (
                SHA_18_TY,
                "native_global:1011f760",
                b"\x62\xf1\x90",
                0,
            ),
            (
                SHA_18_TY,
                "native_global:1011f760",
                b"\x63\xf1\x90",
                3,
            ),
        ):
            with self.subTest(source=sha):
                _, calls, supplied = self.p3_lower(
                    (reply, b"\xe8\x01\xc1\x01\xff", 9, b"\x53\x01\x12\x34")
                )
                binding = cast(UtilityDriverBinding, supplied.bindings[4])
                exports = {
                    name: cast(Callable[..., object], binding.resolve(slot))
                    for slot, name in _DRIVER_SLOTS.items()
                }

                class Host(Context):
                    def get_parameter(self, key):
                        return self.parameters.get(key, 0)

                    def get_data_size(self, key):
                        return len(self.data.get(key, b""))

                    def get_data(self, key):
                        return self.data.get(key, b"")

                    def set_parameter(self, key, value):
                        self.parameters[key] = value
                        return 0

                    def write_parameters(self):
                        return 0

                host = Host()
                host.parameters = {0x6F: 3, 0x70: 0x11, 0x74: 0x22}
                host.data[500] = (1).to_bytes(4, "little") + (9600).to_bytes(
                    4, "little"
                )
                path = Path(
                    next(row["input_path"] for row in queue if row["sha256"] == sha)
                )
                context = UtilityExContext(
                    path.read_bytes(), host, None, None, driver_exports=exports
                )
                comm = context.comm("selected")
                try:
                    self.assertEqual(comm.initialize_at(0x33, 1), 0)
                    self.assertEqual(comm.exchange(b"\x22\xf1\x90"), (expected, reply))
                    self.assertEqual(comm.selected_protocol(), 1)
                    self.assertEqual(comm.read_target(), (0x22, 0))
                    if sha == SHA_18_TY:
                        status, support, offsets = comm.support_snapshot(1)
                        self.assertEqual(status, 0)
                        self.assertEqual(support[:3], b"\xc1\x01\xff")
                        self.assertEqual(offsets[0xC1], 0)
                        self.assertEqual(comm.read_dtcs(), (0, b"\x53\x01\x12\x34"))
                finally:
                    comm.finalize()
                self.assertEqual(context.state[selected_global], 0)
                self.assertEqual(calls[-1], ("disconnect", 74))

    def test_actual_nk18_selected_legacy_p4_uses_distinct_lower_and_iso_wire(self):
        from scripts.utility_ex import _DRIVER_SLOTS
        from scripts.utility_ex_lifecycle import UtilityExLegacyP4Lower

        path = Path("artifacts/extracted/techstream-18-application/Techstream_Bin")
        for filename, sha, setter, manager in (
            ("UtilityExNK2.dll", SHA_18_NK, "native_rva:170a0", 0x1014C0B0),
            ("UtilityEx2TY.dll", SHA_18_TY, "native_rva:11f50", 0x10119FC0),
        ):
            _, calls, context = self.p3_lower()
            old_binding = cast(UtilityDriverBinding, context.bindings[4])
            exports = {
                name: cast(Callable[..., object], old_binding.resolve(slot))
                for slot, name in _DRIVER_SLOTS.items()
            }
            context.module_bytes = (path / filename).read_bytes()
            context.module_sha256 = sha
            context.bindings[4] = UtilityDriverBinding(
                cast(UtilityExContext, context), 4, exports
            )
            context.parameters = {0x6F: 0x12, 0x70: 0x11, 0x73: 0x5C, 0x74: 0x33}
            comm = UtilityExComm(context)
            comm.configure(setter, manager)
            self.assertEqual(comm.initialize(0), 0)
            lower = comm._selected_lower()
            self.assertIsInstance(lower, UtilityExLegacyP4Lower)
            self.assertEqual(comm.selected_protocol(), 4)
            self.assertEqual(lower.send(b"\x22\x01"), 0)
            payload = b"\x68\x6a\xf0\x22\x01"
            self.assertEqual(calls[-1][1].data, payload + bytes((sum(payload) & 255,)))
            if sha == SHA_18_NK:
                self.assertEqual(comm.append_support_profile(b"\x01\x01\xff", 1), 99)
                snapshot = comm.cached_support(1)
                assert snapshot is not None
                self.assertEqual(snapshot[0][:3], b"\x01\x01\xff")
            comm.finalize()
            self.assertEqual(calls[-1], ("disconnect", 74))

    def test_p3_complete_lower_initializes_configures_exchanges_and_finalizes(self):
        lower, calls, _ = self.p3_lower((b"\x62\xf1\x90",))
        lower.profile = 1
        self.assertEqual(lower.initialize(0x33, override=True), 0)
        self.assertEqual(
            calls[:2], [("connect", 4, 0x200), ("ioctl", 2, p3_default_parameters(1))]
        )
        self.assertEqual(calls[2][0:2], ("ioctl", 5))
        self.assertEqual(lower.send(b"\x22\xf1\x90"), 0)
        self.assertEqual(calls[-1][1], pack_p3_request(0x33, b"\x22\xf1\x90", 4))
        self.assertEqual(lower.receive(), DriverReceive(0, b"\x62\xf1\x90"))
        self.assertGreater(lower.last_receive_tick, 0)
        self.assertEqual(lower.finalize(), 0)
        self.assertFalse(lower.attached)
        self.assertEqual(lower.send(b"\x22"), 99)
        self.assertEqual(calls[-1], ("disconnect", 74))

    def test_p3_fast_init_retries_three_timeouts_and_cleans_failed_init(self):
        lower, calls, _ = self.p3_lower(fast_statuses=(9, 9, 9))
        self.assertEqual(lower.initialize(0x33, supplied=((1, 10400),)), 4)
        self.assertEqual(sum(call[:2] == ("ioctl", 5) for call in calls), 3)
        self.assertEqual(calls[1], ("ioctl", 2, ((1, 10400),)))
        self.assertEqual(calls[-1], ("disconnect", 74))
        self.assertFalse(lower.attached)
        lower, calls, _ = self.p3_lower(fast_statuses=(99,))
        self.assertEqual(lower.initialize(0x33), 4)
        self.assertEqual(sum(call[:2] == ("ioctl", 5) for call in calls), 1)

    def test_p3_interrupt_restores_config_reads_pending_and_ignores_final_fast_fault(
        self,
    ):
        lower, calls, context = self.p3_lower(
            (b"\x7f\x22\x78", b"\xc2"), fast_statuses=(0, 99)
        )
        self.assertEqual(lower.initialize(0x33), 0)
        calls.clear()
        self.assertEqual(lower.interrupt(100), 0)
        self.assertEqual(calls[0], ("ioctl", 1, [(10, 55)]))
        self.assertEqual(calls[1], ("ioctl", 2, ((10, 0),)))
        self.assertEqual(calls[2][1], pack_p3_request(0x33, b"\x82", 4))
        self.assertEqual(calls[3], ("ioctl", 2, ((10, 55),)))
        self.assertEqual(calls[-1][0:2], ("ioctl", 5))
        self.assertGreaterEqual(context.tick, 300)
        lower.finalize()

    def test_p3_interrupt_write_fault_restores_config_before_return(self):
        lower, calls, _ = self.p3_lower(write_status=9)
        self.assertEqual(lower.initialize(0x33), 0)
        calls.clear()
        self.assertEqual(lower.interrupt(100), 99)
        self.assertEqual(calls[-1], ("ioctl", 2, ((10, 55),)))
        self.assertFalse(any(call[:2] == ("ioctl", 5) for call in calls))
        lower.finalize()

    def test_p3_native_profiles_and_duplicate_reuse(self):
        self.assertEqual(
            p3_default_parameters(0), ((1, 9600), (20, 35), (9, 100), (10, 100))
        )
        first, second = p3_default_parameters(1), p3_default_parameters(0x12)
        self.assertEqual((len(first), len(second)), (15, 15))
        self.assertEqual((dict(first)[14], dict(second)[14]), (105, 110))
        self.assertEqual((dict(first)[9], dict(second)[9]), (200, 500))
        lower, calls, _ = self.p3_lower()
        self.assertEqual(lower.initialize(0x33), 0)
        count = len(calls)
        self.assertEqual(lower.initialize(0x33), 13)
        self.assertEqual(len(calls), count)
        self.assertEqual(lower.initialize(0x33, reuse=True), 0)
        self.assertEqual(sum(call[0] == "connect" for call in calls), 1)
        lower.finalize()

    def test_direct_singleton_driver_uses_actual_raw_sdk_without_logical_pool(self):
        calls = []

        def connect(protocol, flags, output):
            calls.append(("connect", protocol, flags))
            output[:] = (73).to_bytes(4, "little")
            return PrimitiveResult()

        def write(channel, messages, count, timeout):
            calls.append(("write", channel, messages[0], timeout))
            return PrimitiveResult()

        def read(channel, messages, count, timeout):
            calls.append(("read", channel, timeout))
            messages[0] = NativeMessage(4, b"\x83\xf0\x33\x62\x22\x00\x2a")
            return PrimitiveResult()

        def ioctl(channel, kind, payload, output):
            calls.append(("ioctl", channel, kind, payload))
            assert isinstance(output, bytearray)
            output[:] = b"test"
            return PrimitiveResult()

        def disconnect(channel):
            calls.append(("disconnect", channel))
            return PrimitiveResult()

        context, binding = self.typed_binding(
            {
                "PassThruConnect": connect,
                "PassThruWriteMsgs": write,
                "PassThruReadMsgs": read,
                "PassThruIoctl": ioctl,
                "PassThruDisconnect": disconnect,
            }
        )
        driver = UtilityExDirectDriver(
            context, UtilityExDriverPrimitives(context, binding), 4
        )
        self.assertEqual(driver.connect(0x33), 0)
        self.assertEqual(driver.connect(0x33), 13)
        self.assertEqual(driver.connect(0x34), 14)
        self.assertEqual(driver.write(pack_p3_request(0x33, b"\x22"), 1000), 0)
        self.assertEqual(calls[-1][2].protocol_id, 4)
        self.assertEqual(driver.read(500)[0], 0)
        output = bytearray(4)
        self.assertEqual(driver.ioctl(1, ((10, 0),), output), 0)
        self.assertEqual(output, b"test")
        self.assertEqual(driver.finalize(), 0)
        self.assertEqual(calls[0], ("connect", 4, 0x200))
        self.assertEqual(calls[-1], ("disconnect", 73))
        self.assertEqual(driver.read(100), (3, None))
        self.assertFalse(any("arbitration" in key for key in context.state))

    def test_direct_driver_sdk_status_mapping_and_failed_disconnect_ownership(self):
        read_status = iter((9, 16, 99))
        close_status = iter((99, 0))

        def connect(protocol, flags, output):
            output[:] = (77).to_bytes(4, "little")
            return PrimitiveResult()

        context, binding = self.typed_binding(
            {
                "PassThruConnect": connect,
                "PassThruReadMsgs": lambda *args: PrimitiveResult(next(read_status)),
                "PassThruWriteMsgs": lambda *args: PrimitiveResult(9),
                "PassThruIoctl": lambda *args: PrimitiveResult(9),
                "PassThruDisconnect": lambda *args: PrimitiveResult(next(close_status)),
            }
        )
        driver = UtilityExDirectDriver(
            context, UtilityExDriverPrimitives(context, binding), 4
        )
        self.assertEqual(driver.connect(0x33), 0)
        self.assertEqual([driver.read(100)[0] for _ in range(3)], [2, 2, 3])
        self.assertEqual(driver.ioctl(5), 2)
        self.assertEqual(driver.write(pack_p3_request(0x33, b"\x22"), 100), 3)
        self.assertEqual(driver.finalize(), 99)
        self.assertEqual(driver.handle, 77)
        self.assertEqual(driver.finalize(), 0)
        self.assertIsNone(driver.handle)

    def test_concrete_driver_binding_executes_native_positional_outputs(self):
        calls = []

        def connect(protocol, flags, output):
            calls.append(("connect", protocol, flags))
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def read(channel, messages, count, timeout):
            calls.append(("read", channel, timeout, int.from_bytes(count, "little")))
            messages[0] = NativeMessage(6, b"\0\0\x07\xe8\x62")
            count[:] = (1).to_bytes(4, "little")
            return PrimitiveResult()

        def write(channel, messages, count, timeout):
            calls.append(("write", channel, tuple(messages), timeout))
            return PrimitiveResult()

        context, binding = self.typed_binding(
            {
                "PassThruConnect": connect,
                "PassThruReadMsgs": read,
                "PassThruWriteMsgs": write,
            }
        )
        primitives = UtilityExDriverPrimitives(context, binding)
        pool = UtilityExPassThruPool(context, J2534Device2026(primitives))
        self.assertEqual(pool.connect(6, 0x7E0), (0, 0))
        pool.route_filter(0, bytes.fromhex("ffffffff"), bytes.fromhex("000007e8"))
        request = pack_uds_request(0x7E0, b"\x22")
        self.assertEqual(pool.write(0, request, 1000), 0)
        status, message = pool.read(0, 1000)
        self.assertEqual(status, 0)
        self.assertEqual(message, NativeMessage(6, b"\0\0\x07\xe8\x62"))
        self.assertEqual(calls[0], ("connect", 6, 0))
        self.assertEqual(calls[1], ("write", 42, (request,), 1000))
        self.assertEqual(calls[2], ("read", 42, 100, 1))

    def test_driver_binding_requires_raw_status_and_bounded_typed_outputs(self):
        context, binding = self.typed_binding(
            {"PassThruConnect": lambda *a: PrimitiveResult(0, 42)}
        )
        primitive = UtilityExDriverPrimitives(context, binding)
        operation = {"operation": "PassThruConnect", "protocol_id": 6, "flags": 0}
        with self.assertRaises(TypeError):
            primitive(operation, 1)

        def oversized(protocol, flags, output):
            output.append(1)
            return PrimitiveResult()

        context, binding = self.typed_binding({"PassThruConnect": oversized})
        with self.assertRaises(ValueError):
            UtilityExDriverPrimitives(context, binding)(operation, 1)
        binding.slots[0x20] = None
        binding.ready = False
        with self.assertRaises(UtilityExSourceError):
            UtilityExDriverPrimitives(context, binding)
        with self.assertRaises(TypeError):
            UtilityExDriverPrimitives(context, object())

    def can_lower(self, kind=0x10, replies=(), *, fault=None):
        context = Context()
        context.module_sha256 = SHA_18_NK
        calls = []
        incoming = iter(replies)
        filters = iter((21, 22))

        def provider(operation, remaining):
            calls.append(operation)
            if fault is not None:
                result = fault(operation)
                if result is not None:
                    return result
            name = operation["operation"]
            if name in ("PassThruConnect", "PassThruOemConnect"):
                return PrimitiveResult(0, 42)
            if name == "PassThruStartMsgFilter":
                return PrimitiveResult(0, next(filters))
            if name == "PassThruReadMsgs":
                return PrimitiveResult(0, (next(incoming),))
            return PrimitiveResult()

        pool = UtilityExPassThruPool(context, J2534Device2026(provider))
        return UtilityExCANLower(context, pool, kind), calls, context

    def test_native_pool_stop_filter_ignores_sdk_status_after_successful_lock(self):
        lower, calls, _ = self.can_lower(
            fault=lambda operation: (
                PrimitiveResult(99)
                if operation["operation"] == "PassThruStopMsgFilter"
                else None
            )
        )
        self.assertEqual(lower.initialize(0x7E0, supplied=((1, 500000),)), 0)
        assert lower.slot is not None
        self.assertEqual(lower.pool.stop_filter(lower.slot, 21), 0)
        self.assertNotIn((42, 21), lower.pool.filters)
        self.assertEqual(lower.finalize(), 0)
        self.assertEqual(calls[-1]["operation"], "PassThruDisconnect")

    def test_broadcast_lower_sends_functional_address_and_decodes_physical_response(
        self,
    ):
        for kind in (0x10, 0x13, 0x15):
            with self.subTest(kind=kind):
                normal, calls, context = self.can_lower(
                    replies=[
                        NativeMessage(
                            0x8005 if kind == 0x15 else 6, bytes.fromhex("000007e862")
                        )
                    ]
                )
                lower = UtilityExBroadcastCANLower(context, normal.pool, kind)
                self.assertEqual(
                    lower.initialize(
                        0x7E0, alternate_extra=0x7DF, supplied=((1, 500000),)
                    ),
                    0,
                )
                filters = [
                    call
                    for call in calls
                    if call["operation"] == "PassThruStartMsgFilter"
                ]
                self.assertEqual(filters[0]["mask"].data, bytes.fromhex("000007ff"))
                self.assertEqual(filters[0]["pattern"].data, bytes.fromhex("000007e8"))
                self.assertIsNone(filters[0]["flow_control"])
                self.assertEqual(
                    filters[1]["flow_control"].data, bytes.fromhex("000007e0")
                )
                self.assertEqual(lower.send(b"\x22"), 0)
                sent = next(
                    call for call in calls if call["operation"] == "PassThruWriteMsgs"
                )
                self.assertEqual(sent["messages"][0].data, bytes.fromhex("000007df22"))
                self.assertEqual(lower.receive(), DriverReceive(0, b"\x62"))
                self.assertEqual(lower.finalize(), 0)
                self.assertEqual(calls[-1]["operation"], "PassThruDisconnect")

    def test_concrete_can_lower_initialization_routing_packets_and_cleanup(self):
        lower, calls, _ = self.can_lower(
            replies=[NativeMessage(6, bytes.fromhex("000007e862"))]
        )
        self.assertEqual(lower.receive(), DriverReceive(99))
        self.assertEqual(lower.initialize(0x7E0, supplied=((1, 500000),)), 0)
        self.assertEqual(
            [c["operation"] for c in calls],
            [
                "PassThruConnect",
                "PassThruIoctl",
                "PassThruStartMsgFilter",
                "PassThruStartMsgFilter",
            ],
        )
        self.assertEqual(calls[2]["filter_type"], 1)
        self.assertEqual(calls[3]["filter_type"], 3)
        self.assertEqual(calls[3]["pattern"].data, bytes.fromhex("000007e8"))
        self.assertEqual(calls[3]["flow_control"].data, bytes.fromhex("000007e0"))
        self.assertEqual(lower.send(b"\x22"), 0)
        self.assertEqual(calls[-1]["messages"][0].data, bytes.fromhex("000007e022"))
        self.assertEqual(calls[-1]["timeout_ms"], 0x3FC)
        self.assertEqual(lower.receive(), DriverReceive(0, b"\x62"))
        self.assertGreater(lower.last_receive_tick, 0)
        self.assertEqual(lower.finalize(), 0)
        self.assertEqual(
            [
                c["filter_id"]
                for c in calls
                if c["operation"] == "PassThruStopMsgFilter"
            ],
            [21, 22],
        )
        self.assertEqual(calls[-1]["operation"], "PassThruDisconnect")
        self.assertEqual(lower.pool.owned, set())
        self.assertIsNone(lower.slot)
        self.assertEqual(lower.mutex.owner, 0)

    def test_can_lower_extended_pending_timeout_and_extension_contract(self):
        for kind, extra, pending_ms, prefix in (
            (0x10, 0, 5530, b""),
            (0x11, 0xFA, 5000, b"\xfa"),
        ):
            with self.subTest(kind=kind):
                address = bytes.fromhex("000007e8")
                lower, calls, _ = self.can_lower(
                    kind,
                    [
                        NativeMessage(6, address + prefix + b"\x7f\x22\x78"),
                        NativeMessage(6, address + prefix + b"\x62"),
                    ],
                )
                self.assertEqual(lower.initialize(0x7E0, extra=extra, override=True), 0)
                self.assertEqual(lower.send(b"\x22"), 0)
                self.assertEqual(calls[0]["flags"], 128 if kind == 0x11 else 0)
                self.assertEqual(
                    calls[-1]["messages"][0].data,
                    bytes.fromhex("000007e0") + prefix + b"\x22",
                )
                self.assertEqual(
                    lower.receive(), DriverReceive(5, b"\x7f\x22\x78", 116)
                )
                self.assertEqual(lower.timeout_ms, pending_ms)
                self.assertEqual(lower.receive(), DriverReceive(0, b"\x62"))
                lower.interrupt(100)
                self.assertEqual(lower.timeout_ms, pending_ms)
                lower.finalize()

    def test_can_lower_config_failure_releases_channel_and_mutex(self):
        lower, calls, _ = self.can_lower(
            fault=lambda op: (
                PrimitiveResult(9) if op["operation"] == "PassThruIoctl" else None
            )
        )
        self.assertEqual(lower.initialize(0x7E0, supplied=((1, 500000),)), 2)
        self.assertEqual(calls[-1]["operation"], "PassThruDisconnect")
        self.assertIsNone(lower.slot)
        self.assertEqual(lower.mutex.owner, 0)
        self.assertEqual(lower.pool.owned, set())

    def test_can_lower_manager_lock_and_connect_fault_do_not_strand_owner(self):
        lower, calls, context = self.can_lower()
        lower.mutex.owner = 1
        self.assertEqual(lower.initialize(0x7E0, override=True), 99)
        self.assertEqual(context.tick, 3000)
        self.assertEqual(calls, [])
        lower, calls, context = self.can_lower(
            fault=lambda op: (
                PrimitiveResult(99) if op["operation"] == "PassThruConnect" else None
            )
        )
        self.assertEqual(lower.initialize(0x7E0, override=True), 99)
        self.assertEqual(lower.mutex.owner, 0)
        self.assertIsNone(lower.slot)

    def test_native_fixed_fields_bind_configuration_and_actual_nrc_getter(self):
        source = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll"
        )
        if not source.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        context = Context()
        context.module_sha256, context.module_bytes = SHA_18_NK, source.read_bytes()
        comm = UtilityExComm(context, "native:1014f5e0")
        comm.configure("native_rva:18970", 0)
        comm.configure("native_rva:18990", 180000)
        comm.configure("native_1064", 1)
        comm.configure_parameters(((0x10103, 0x300000),))
        assert comm._fields is not None
        self.assertEqual(comm._fields.parameters, ((0x10103, 0x300000),))
        for parameters in ([(1, 2)], ((1, True),), ((1, 2, 3),)):
            with self.assertRaises(ValueError):
                comm.configure_parameters(cast(tuple[tuple[int, int], ...], parameters))
        scheduler = UtilityExUDSScheduler(
            context, Driver([DriverReceive(7, b"\x7f\x22\x33")]), fields=comm._fields
        )
        self.assertEqual(scheduler.exchange(b"\x22"), (7, b"\x7f\x22\x33"))
        self.assertEqual(comm.read_field("native_10b0"), 108)
        another = UtilityExComm(context, "native:1014f5e0")
        self.assertEqual(another.read_field("native_10b0"), 108)
        self.assertIs(another._fields, comm._fields)
        self.assertEqual(scheduler.fields.receive_count, 0)
        for field in ("native_1084", "native_global:1015185c"):
            with self.assertRaises(UtilityExSourceError):
                comm.read_field(field)

    def test_native_target_setter_preserves_two_dwords_and_global_getter_scope(self):
        source = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not source.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        context = Context()
        context.module_sha256, context.module_bytes = SHA_18_TY, source.read_bytes()
        comm = UtilityExComm(context)
        context.state["native_global:1011f768"] = 1
        comm.select_target(0x790, 0)
        self.assertEqual(context.state["native_global:1011f700"], 0x790)
        self.assertEqual(context.state["native_global:1011f704"], 0)
        self.assertEqual(context.state["native_global:1011f768"], 1)
        for identifier, second in ((-1, 0), (0, True), (0x100000000, 0)):
            with self.assertRaises(ValueError):
                comm.select_target(identifier, second)

    def test_plus_fixed_field_target_and_preconnect_protocol_configuration(self):
        source = Path(
            "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll"
        )
        if not source.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        context = Context()
        context.module_sha256, context.module_bytes = SHA_PLUS_TY, source.read_bytes()
        comm = UtilityExComm(context, "native:101392d0")
        self.assertEqual(comm.read_field("native_10b0"), 0)
        comm.configure("native_rva:1e290", 0)
        comm.configure("native_rva:1e2b0", 180000)
        comm.configure("native_rva:1e2d0", 0)
        comm.select_target(0x700, 0xF0)
        self.assertEqual(comm.read_target(), (0x700, 0xF0))
        self.assertEqual(comm.select_protocol(0x11), 0)
        comm.configure_target(0x750, 0xE9)
        assert comm._fields is not None
        self.assertEqual(comm._fields.primary_address, 0x750)
        self.assertEqual(comm._fields.extension, 0xE9)
        self.assertEqual(comm._fields.lower_kind, 0x11)
        self.assertTrue(comm._fields.target_configured)
        self.assertEqual(comm.select_protocol(0x12), 22)
        self.assertEqual(comm._fields.lower_kind, 0x11)
        self.assertEqual(comm.select_protocol(0), 0)
        comm.configure_target(0, 0)
        self.assertEqual(comm._fields.primary_address, 0x700)
        self.assertEqual(comm._fields.extension, 0xF0)
        self.assertEqual(comm._fields.lower_kind, 0)
        with self.assertRaises(ValueError):
            comm.configure_target(0, -1)

    def test_native_support_cache_capacity_before_wire_and_fault_preservation(self):
        context = Context()
        context.module_sha256 = SHA_18_NK
        driver = Driver(
            [
                reply
                for _ in range(16)
                for reply in (
                    DriverReceive(0, b"\xe8\x02\x05\x01\xff"),
                    DriverReceive(2),
                )
            ]
        )
        scheduler = UtilityExClassicScheduler(context, driver)
        cache = UtilityExSupportCache(context)
        for address in range(16):
            self.assertEqual(cache.refresh(scheduler, 2, (address, 0), 1), 0)
        self.assertEqual(len(driver.sent), 16)
        self.assertEqual(cache.refresh(scheduler, 2, (16, 0), 1), 80)
        self.assertEqual(len(driver.sent), 16)
        snapshot = cache.snapshot(2, (0, 0), 1)
        assert snapshot is not None
        self.assertEqual(snapshot[0][:3], b"\x05\x01\xff")
        self.assertEqual(snapshot[1][5], 0)
        driver.send_status = 99
        self.assertEqual(cache.refresh(scheduler, 2, (0, 0), 1), 99)
        self.assertEqual(cache.snapshot(2, (0, 0), 1), snapshot)
        self.assertIsNone(cache.snapshot(2, (0, 0), 6))
        self.assertIsNone(cache.snapshot(1, (0, 0), 1))

    def test_native_support_cache_allocation_status_and_typed_boundaries(self):
        context = Context()
        context.module_sha256 = SHA_18_NK
        scheduler = UtilityExClassicScheduler(
            context,
            Driver([DriverReceive(0, b"\xe8\x02\x05\x01\xff"), DriverReceive(2)]),
        )
        cache = UtilityExSupportCache(context)
        with patch(
            "scripts.utility_ex_comm.UtilityExSupportProfile", side_effect=MemoryError
        ):
            self.assertEqual(cache.refresh(scheduler, 2, (1, 0), 1), 81)
        self.assertEqual(cache.profiles, [])
        with self.assertRaises(ValueError):
            cache.snapshot(True, (1, 0), 1)
        with self.assertRaises(ValueError):
            cache.refresh(scheduler, 2, (1, -1), 1)
        with self.assertRaises(TypeError):
            cache.refresh(cast(UtilityExClassicScheduler, object()), 2, (1, 0), 1)

    def test_native_protocol_getters_are_object_types_not_wire_aliases(self):
        self.assertEqual(native_manager_protocol(SHA_18_NK, 0x1014AEF0), 1)
        self.assertEqual(native_manager_protocol(SHA_18_TY, 0x1011E5E0), 6)
        with self.assertRaises(UtilityExSourceError):
            native_manager_protocol(SHA_18_NK, 0x1014F5E0)
        with self.assertRaises(UtilityExSourceError):
            native_manager_protocol("unknown", 0x1014AEF0)

    def test_pool_failed_release_can_be_retried(self):
        pool, _, _ = self.pool(fail_disconnect=True)
        pool.connect(6, 0x7E0)
        self.assertEqual(pool.finalize(), 99)
        self.assertEqual(pool.owned, {42})
        pool.device.provider = lambda operation, remaining: PrimitiveResult(0)
        self.assertEqual(pool.finalize(), 0)
        self.assertEqual(pool.owned, set())
        self.assertEqual(pool.channels, [None] * 4)

    def test_actual_supplied_source_facade_blocks_unported_initialization(self):
        source = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not source.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        context = Context()
        context.module_sha256 = SHA_18_TY
        context.module_bytes = source.read_bytes()
        comm = UtilityExComm(context, "native:1011d4f0")
        self.assertEqual(comm.manager_address, 0x1011D4F0)
        with self.assertRaises(UtilityExSourceError):
            comm.initialize()
        comm.finalize()

    def test_extended_failure_does_not_publish_intermediate_normal_session(self):
        engine, _, _ = self.engine(
            DriverReceive(0, b"\x50\x01"), DriverReceive(0, b"\x50\x02")
        )
        engine.fields.current_session = 7
        self.assertEqual(engine.session(3, 0, normal_first=True), 7)
        self.assertEqual(engine.fields.current_session, 7)

    def test_pool_source_configuration_removes_2a_only_after_failure(self):
        pool, calls, _ = self.pool()
        pool.connect(6, 0x7E0)
        responses = iter((PrimitiveResult(9), PrimitiveResult(0)))
        pool.device.provider = lambda operation, remaining: (
            calls.append(operation),
            next(responses),
        )[1]
        original = ((1, 500000), (0x2A, 7), (0x23, 1))
        self.assertEqual(
            pool.configure_can(
                0, override=False, supplied=original, native_delay_ms=100
            ),
            0,
        )
        self.assertEqual(calls[-2]["input"], original)
        self.assertEqual(calls[-1]["input"], ((1, 500000), (0x23, 1)))
        self.assertEqual(pool._channel(0).delay_ms, 100)
        calls.clear()
        pool.device.provider = lambda operation, remaining: (
            calls.append(operation),
            PrimitiveResult(0),
        )[1]
        self.assertEqual(pool.configure_can(0, override=False, supplied=original), 0)
        self.assertEqual(len(calls), 1)

    def test_pool_shared_configuration_is_skipped_and_default_final_status_ignored(
        self,
    ):
        pool, calls, _ = self.pool()
        pool.connect(6, 0x7E0)
        pool.connect(6, 0x7E1)
        count = len(calls)
        self.assertEqual(pool.configure_can(1, override=False, supplied=((1, 1),)), 0)
        self.assertEqual(len(calls), count)
        responses = iter((PrimitiveResult(0), PrimitiveResult(0), PrimitiveResult(99)))
        pool.device.provider = lambda operation, remaining: (
            calls.append(operation),
            next(responses),
        )[1]
        self.assertEqual(pool.configure_can(0, override=True), 0)
        self.assertEqual(calls[-3]["input"], ((1, 500000),))
        self.assertEqual(calls[-2]["input"], ((0x23, 0),))
        self.assertEqual(calls[-1]["input"], ((0x2A, 0),))

    def test_cached_selected_facade_reenters_native_scope_for_every_call(self):
        source = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not source.is_file():
            self.skipTest("Exact original BYOD module is not supplied")
        context = Context()
        context.module_sha256 = SHA_18_TY
        context.module_bytes = source.read_bytes()
        comm = UtilityExComm(context)
        for call in (
            lambda: comm.initialize(),
            lambda: comm.configure("native_1080", 0),
            lambda: comm.exchange(b"\x22"),
            lambda: comm.session(3),
            lambda: comm.keepalive(False),
        ):
            context.state["native_global:1011f768"] = 1
            with self.assertRaises(UtilityExSourceError):
                call()
            self.assertEqual(context.state["native_global:1011f768"], 0)
        context.state["native_global:1011f768"] = 1
        comm.finalize()
        self.assertEqual(context.state["native_global:1011f768"], 0)

    def test_selected_can_facade_joins_direct_sdk_and_shared_a8_cache(self):
        from scripts.utility_ex import _DRIVER_SLOTS

        queue = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for source, mode, timeout, protocol in (
            (source, mode, timeout, protocol)
            for source in queue
            for mode, timeout, protocol in ((4, 1000, 5), (0x14, 0x3FC, 16))
        ):
            with self.subTest(source=source["sha256"], mode=mode):
                calls = []
                reads = iter((b"\x62", b"\xe8\x02\x09\x01\xff", 9))
                filters = iter((11, 12))

                def connect(native_protocol, flags, output, *, calls=calls):
                    calls.append(("connect", native_protocol, flags))
                    output[:] = (42).to_bytes(4, "little")
                    return PrimitiveResult()

                def start_filter(
                    channel, kind, mask, pattern, flow, output, *, filters=filters
                ):
                    output[:] = next(filters).to_bytes(4, "little")
                    return PrimitiveResult()

                def write(channel, messages, count, wait, *, calls=calls):
                    calls.append(("write", messages[0].data, wait))
                    return PrimitiveResult()

                def read(channel, messages, count, wait, *, reads=reads):
                    reply = next(reads)
                    if isinstance(reply, int):
                        return PrimitiveResult(reply)
                    messages[0] = NativeMessage(6, b"\0\0\x07\xe8" + reply)
                    return PrimitiveResult()

                context, binding = self.typed_binding(
                    {
                        "PassThruConnect": connect,
                        "PassThruStartMsgFilter": start_filter,
                        "PassThruWriteMsgs": write,
                        "PassThruReadMsgs": read,
                        "PassThruDisconnect": lambda channel, calls=calls: (
                            calls.append(("disconnect", channel)),
                            PrimitiveResult(),
                        )[1],
                    }
                )
                context.module_bytes = Path(source["input_path"]).read_bytes()
                context.parameters = {
                    0x6F: mode,
                    0x70: 0x12,
                    0x74: 0x7E0,
                    0xAB: 0,
                    0xD3: 0xFFFFFFFF,
                    0xDD: 0xFFFFFFFF,
                }

                class Host(Context):
                    def get_parameter(self, key):
                        return self.parameters.get(key, 0)

                    def get_data_size(self, key):
                        return len(self.data.get(key, b""))

                    def get_data(self, key):
                        return self.data.get(key, b"")

                    def set_parameter(self, key, value):
                        self.parameters[key] = value
                        return 0

                    def write_parameters(self):
                        return 0

                host = Host()
                host.parameters = context.parameters
                exports = {
                    name: cast(Callable[..., object], binding.resolve(slot))
                    for slot, name in _DRIVER_SLOTS.items()
                }
                context = UtilityExContext(
                    context.module_bytes, host, None, None, driver_exports=exports
                )
                comm = context.comm("selected")
                try:
                    self.assertEqual(comm.initialize(0), 0)
                    if context.module_sha256 == SHA_18_TY:
                        comm.configure("native_rva:121b0", 200)
                        if mode == 4:
                            timeout = 200
                    self.assertEqual(comm.exchange(b"\x22"), (0, b"\x62"))
                    self.assertEqual(comm.selected_protocol(), protocol)
                    if context.module_sha256 == SHA_18_NK:
                        self.assertEqual(comm.refresh_support_cache(2), 0)
                        profile = comm.cached_support(2)
                    else:
                        status, data, offsets = comm.support_snapshot(2)
                        self.assertEqual(status, 0)
                        profile = data, offsets
                    assert profile is not None
                    self.assertEqual(
                        (profile[0][:3], profile[1][9]), (b"\x09\x01\xff", 0)
                    )
                finally:
                    comm.finalize()
                self.assertEqual(calls[0], ("connect", 6, 0))
                self.assertEqual(calls[1], ("write", b"\0\0\x07\xe0\x22", timeout))
                self.assertEqual(calls[-1], ("disconnect", 42))

    def test_direct_sil_constructor_uses_wrapper_connect_but_native_message_protocol(
        self,
    ):
        calls = []

        def connect(protocol, flags, output):
            calls.append((protocol, flags))
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def write(channel, messages, count, timeout):
            calls.append(messages[0].protocol_id)
            return PrimitiveResult()

        context, binding = self.typed_binding(
            {"PassThruConnect": connect, "PassThruWriteMsgs": write},
            constructor_parameter=0xD,
        )
        driver = UtilityExDirectDriver(
            context, UtilityExDriverPrimitives(context, binding), 6
        )
        self.assertEqual(driver.connect(0x7E0, 0), 0)
        self.assertEqual(driver.write(NativeMessage(0, b"\x00"), 100), 0)
        self.assertEqual(calls, [(0x1000C, 0), 6])
        self.assertEqual(driver.finalize(), 0)

    def test_actual_all8_selected_classic_sil_and_extended_manager_matrix(self):
        from scripts.utility_ex import _DRIVER_SLOTS

        queue = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )

        class Host(Context):
            def get_parameter(self, key):
                return self.parameters.get(key, 0)

            def get_data_size(self, key):
                return len(self.data.get(key, b""))

            def get_data(self, key):
                return self.data.get(key, b"")

            def set_parameter(self, key, value):
                self.parameters[key] = value
                return 0

            def write_parameters(self):
                return 0

        for source in queue:
            for index, mode, protocol in (
                (8, 4, 0x12),
                (9, 0x14, 0x12),
                (10, 4, 0x22),
                (11, 0x14, 0x22),
                (5, 0x13, 0x1A),
                (6, 0x13, 0x4A),
                (7, 0x13, 0x5A),
            ):
                with self.subTest(source=source["sha256"], index=index):
                    calls = []
                    offset = {5: 0x20, 6: 0x100, 7: 0xC0}.get(index, 0)
                    extension = b"\x29" if index in (10, 11) else b""
                    response_address = 0x7E0 - offset if offset else 0x7E8
                    payloads = [b"\x62\x01", b"\x62\x01"]
                    if offset:
                        payloads.insert(
                            0, b"\xc1\xd0\x8f" if offset == 0x20 else b"\x50\xc0"
                        )
                        payloads.append(b"\xc2" if offset == 0x20 else b"\xc1\x81")
                    incoming = iter(payloads)
                    identifiers = iter(range(51, 70))

                    def connect(native_protocol, flags, output, *, calls=calls):
                        calls.append(("connect", native_protocol, flags))
                        output[:] = (42).to_bytes(4, "little")
                        return PrimitiveResult()

                    def read(
                        channel,
                        messages,
                        count,
                        timeout,
                        *,
                        incoming=incoming,
                        address=response_address,
                        extension=extension,
                    ):
                        messages[0] = NativeMessage(
                            6, address.to_bytes(4, "big") + extension + next(incoming)
                        )
                        return PrimitiveResult()

                    def write(channel, messages, count, timeout, *, calls=calls):
                        calls.append(("write", messages[0].data))
                        return PrimitiveResult()

                    def start(
                        channel,
                        kind,
                        mask,
                        pattern,
                        flow,
                        output,
                        *,
                        identifiers=identifiers,
                    ):
                        output[:] = next(identifiers).to_bytes(4, "little")
                        return PrimitiveResult()

                    def disconnect(channel, *, calls=calls):
                        calls.append(("disconnect", channel))
                        return PrimitiveResult()

                    _fake, binding = self.typed_binding(
                        {
                            "PassThruConnect": connect,
                            "PassThruReadMsgs": read,
                            "PassThruWriteMsgs": write,
                            "PassThruStartMsgFilter": start,
                            "PassThruDisconnect": disconnect,
                        }
                    )
                    exports = {
                        name: cast(Callable[..., object], binding.resolve(slot))
                        for slot, name in _DRIVER_SLOTS.items()
                    }
                    host = Host()
                    host.parameters = {
                        0x6F: mode,
                        0x70: protocol,
                        0x74: 0x7E0,
                        0xAB: 0x29 if extension else 0,
                        0xD3: 0xFFFFFFFF,
                        0xDD: 0xFFFFFFFF,
                    }
                    host.data[500] = (1).to_bytes(4, "little") + (500000).to_bytes(
                        4, "little"
                    )
                    context = UtilityExContext(
                        Path(source["input_path"]).read_bytes(),
                        host,
                        None,
                        None,
                        driver_exports=exports,
                    )
                    comm = context.comm("selected")
                    try:
                        self.assertEqual(comm.initialize(0), 0)
                        self.assertEqual(comm.exchange(b"\x22\x01"), (0, b"\x62\x01"))
                        self.assertEqual(
                            comm.exchange_plain(b"\x22\x01"), (0, b"\x62\x01")
                        )
                        self.assertIn(
                            (
                                "write",
                                bytes.fromhex("000007e0") + extension + b"\x22\x01",
                            ),
                            calls,
                        )
                    finally:
                        comm.finalize()
                    self.assertEqual(
                        calls[0],
                        ("connect", 0x1000C if offset else 6, 0x80 if extension else 0),
                    )
                    self.assertEqual(calls[-1], ("disconnect", 42))

    def test_actual_all8_selected_p3_derived_and_legacy_original_context_matrix(self):
        from scripts.utility_ex import _DRIVER_SLOTS
        from scripts.utility_ex_lifecycle import UtilityExByteArray

        queue = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )

        class Host(Context):
            def get_parameter(self, key):
                return self.parameters.get(key, 0)

            def get_data_size(self, key):
                return 0

            def get_data(self, key):
                return b""

            def set_parameter(self, key, value):
                return 0

            def write_parameters(self):
                return 0

        for source in queue:
            for index, mode, protocol, parameter_count in (
                (0, 3, 0x11, 4),
                (1, 0x12, 0x11, 16),
                (2, 4, 0x11, 4),
                (3, 3, 0x21, 9),
                (4, 3, 0x51, 9),
            ):
                with self.subTest(source=source["sha256"], index=index):
                    calls = []
                    tester = 0xF1 if index == 1 else 0xF0
                    frame = (
                        b"\x48\x6b\x33" if index == 3 else bytes((0x82, tester, 0x33))
                    ) + b"\x62\x01"
                    reply = frame + bytes((sum(frame) & 255,))
                    incoming = iter(
                        (reply, 9, reply, 9) if index == 3 else (reply, reply)
                    )

                    def connect(native_protocol, flags, output, *, calls=calls):
                        calls.append(("connect", native_protocol, flags))
                        output[:] = (42).to_bytes(4, "little")
                        return PrimitiveResult()

                    def ioctl(
                        channel, kind, payload, output, *, calls=calls, tester=tester
                    ):
                        calls.append(("ioctl", kind, payload))
                        if kind == 4:
                            self.assertIsInstance(output, UtilityExByteArray)
                            output.data[:] = b"\x08\x08"
                        elif kind == 5:
                            data = bytes((0x83, tester, 0x33, 0xC1, 1, 2))
                            output[0] = NativeMessage(
                                4, data + bytes((sum(data) & 255,))
                            )
                        return PrimitiveResult()

                    def read(channel, messages, count, timeout, *, incoming=incoming):
                        data = next(incoming)
                        if isinstance(data, int):
                            return PrimitiveResult(data)
                        messages[0] = NativeMessage(4, data)
                        return PrimitiveResult()

                    def write(channel, messages, count, timeout, *, calls=calls):
                        calls.append(("write", messages[0].data))
                        return PrimitiveResult()

                    def disconnect(channel, *, calls=calls):
                        calls.append(("disconnect", channel))
                        return PrimitiveResult()

                    _fake, binding = self.typed_binding(
                        {
                            "PassThruConnect": connect,
                            "PassThruIoctl": ioctl,
                            "PassThruReadMsgs": read,
                            "PassThruWriteMsgs": write,
                            "PassThruDisconnect": disconnect,
                        }
                    )
                    exports = {
                        name: cast(Callable[..., object], binding.resolve(slot))
                        for slot, name in _DRIVER_SLOTS.items()
                    }
                    host = Host()
                    host.parameters = {0x6F: mode, 0x70: protocol, 0x74: 0x33}
                    context = UtilityExContext(
                        Path(source["input_path"]).read_bytes(),
                        host,
                        None,
                        None,
                        driver_exports=exports,
                    )
                    comm = context.comm("selected")
                    try:
                        self.assertEqual(comm.initialize(1), 0)
                        self.assertEqual(len(calls[1][2]), parameter_count)
                        self.assertEqual(comm.exchange(b"\x22\x01"), (0, b"\x62\x01"))
                        self.assertEqual(
                            comm.exchange_plain(b"\x22\x01"), (0, b"\x62\x01")
                        )
                    finally:
                        comm.finalize()
                    data = (
                        b"\x68\x6a\xf0" if index == 3 else bytes((0x82, 0x33, tester))
                    ) + b"\x22\x01"
                    self.assertIn(("write", data + bytes((sum(data) & 255,))), calls)
                    self.assertEqual(calls[0], ("connect", 4, 0x200))
                    self.assertEqual(calls[-1], ("disconnect", 42))

    def test_all8_selected_pending_retains_exact_abort_counter_and_worker_globals(self):
        for sha, abort, count, handoff, owner in (
            (SHA_12_NK, 0x100EA9AC, 0x100EA9C0, 0x100EA9E0, 0x100EBA08),
            (SHA_12_TY, 0x100AFEA8, 0x100AFEBC, 0x100AFEE4, 0x100B0F0C),
            (SHA_18_NK, 0x1015185C, 0x10151870, 0x10151890, 0x101528B8),
            (SHA_18_TY, 0x1011F768, 0x1011F77C, 0x1011F7A4, 0x101207CC),
            (SHA_DS4_NK, 0x101B8B48, 0x101B8B64, 0x101B8B70, 0x101B8B74),
            (SHA_DS4_TY, 0x1006F37C, 0x1006F398, 0x1006F3A8, 0x1006F3AC),
            (SHA_PLUS_NK, 0x101C8078, 0x101C8094, 0x101C80A0, 0x101C80A4),
            (SHA_PLUS_TY, 0x1013FAAC, 0x1013FAC8, 0x1013FAD8, 0x1013FADC),
        ):
            with self.subTest(source=sha):
                context = Context()
                context.module_sha256 = sha
                context.state.update(
                    {
                        f"native_global:{count:x}": 7,
                        f"native_global:{handoff:x}": 1,
                        f"native_global:{owner:x}": 0,
                    }
                )
                driver = Driver((DriverReceive(5, b"\x7f\x22\x78"),))
                pending = UtilityExSelectedPending(context, driver, derived=True)
                self.assertEqual(pending.send(b"\x22"), 0)
                self.assertEqual(context.state[f"native_global:{count:x}"], 0)
                self.assertEqual(context.state[f"native_global:{handoff:x}"], 0)
                context.state[f"native_global:{abort:x}"] = 1
                self.assertEqual(pending.receive().status, 20)
                self.assertEqual(context.state[f"native_global:{abort:x}"], 0)
                self.assertEqual(context.state[f"native_global:{count:x}"], 1)
                self.assertEqual(context.state[f"native_global:{handoff:x}"], 1)
                self.assertEqual(driver.interrupted, [100])

    def test_uint32_wrap(self):
        self.assertEqual(elapsed(2, 0xFFFFFFFE), 4)

    def test_plus_p6_literal_can29_and_canfd_codec_has_reversed_target_bytes(self):
        for protocol, flags in ((6, 0x140), (0x8012, 0x180140)):
            request = pack_p6_request(0x18DAE0F1, b"\x22\xf1\x90", protocol)
            self.assertEqual(
                request,
                NativeMessage(
                    protocol, bytes.fromhex("18dae0f122f190"), tx_flags=flags
                ),
            )
            for payload, status, error in (
                (b"\x62\xf1\x90", 0, 0),
                (b"\x7f\x22\x78", 5, 116),
                (b"\x7f\x22\x21", 27, 104),
                (b"\x7f\x22\x12", 22, 101),
                (b"\x7f\x22\x33", 7, 108),
                (b"\x7f\x22", 3, 0),
            ):
                with self.subTest(protocol=protocol, payload=payload):
                    message = NativeMessage(
                        protocol, bytes.fromhex("18daf1e0") + payload
                    )
                    self.assertEqual(
                        unpack_p6_response(message, 0x18DAE0F1),
                        DriverReceive(status, payload, error),
                    )
            self.assertEqual(unpack_p6_response(request, 0x18DAE0F1), DriverReceive(3))
        for protocol in (4, 0x8005):
            with self.assertRaises(ValueError):
                pack_p6_request(0x18DAE0F1, b"\x22", protocol)

    def test_plus_p6_fields_have_own_literal_native_offsets_and_state(self):
        fields = UtilityExP6Fields()
        self.assertEqual(
            (
                fields.retry_count,
                fields.receive_count,
                fields.receive_ms,
                fields.native_109c,
                fields.busy_count,
                fields.busy_ms,
            ),
            (3, 150, 180000, 1000, 255, 0),
        )
        self.assertEqual(P6_FIELD_OFFSETS[0x10A4], "busy_count")
        self.assertEqual(P6_FIELD_OFFSETS[0x10A8], "busy_ms")
        self.assertEqual(P6_FIELD_OFFSETS[0x10B4], "native_error")
        self.assertEqual(P6_FIELD_OFFSETS[0x10B0], "pending_count")
        self.assertEqual(P6_FIELD_OFFSETS[0x10AC], "busy_interval_ms")
        fields.busy_count = 0
        self.assertEqual(UtilityExP6Fields().busy_count, 255)

    def test_p6_primary_retains_native_counters_and_pending_suppression(self):
        context = Context()
        fields = UtilityExP6Fields(response_pending_count=2, busy_count=2)
        driver = Driver([DriverReceive(2), DriverReceive(27), DriverReceive(27)])
        engine = UtilityExP6UDSScheduler(context, driver, fields=fields)
        self.assertEqual(engine.exchange(b"\x22"), (28, b""))
        self.assertEqual(
            (fields.no_response_seen, fields.busy_seen, fields.pending_count), (0, 2, 0)
        )
        fields.receive_ms, fields.receive_count = 0, 2
        driver = Driver([DriverReceive(5, b"\x7f\x22\x78")] * 2)
        engine = UtilityExP6UDSScheduler(context, driver, fields=fields)
        self.assertEqual(engine.exchange(b"\x22"), (5, b"\x7f\x22\x78"))
        self.assertEqual(
            (fields.pending_count, fields.suppress_positive, fields.suppress_error),
            (2, 0, 0),
        )
        self.assertEqual(driver.interrupted, [100])
        fields.receive_ms = 180000
        driver = Driver(
            [DriverReceive(5, b"\x7f\x22\x78"), DriverReceive(7, b"\x7f\x22\x10")]
        )
        engine = UtilityExP6UDSScheduler(context, driver, fields=fields)
        self.assertEqual(engine.exchange(b"\x22"), (5, b"\x7f\x22\x10"))
        self.assertEqual(
            (fields.pending_count, fields.native_error, fields.suppress_error),
            (0, 998, 0),
        )

    def test_p6_primary_pending_abort_reads_native108c_and_clears1088(self):
        context, fields = (
            Context(),
            UtilityExP6Fields(receive_ms=0, receive_count=1, retry_count=1),
        )
        for suppress, expected, interrupts in ((0, 20, [100]), (1, 0, [])):
            fields.response_pending_seen = suppress
            driver = Driver([DriverReceive(5, b"\x7f\x22\x78")])
            original_receive = driver.receive

            def receive(original_receive=original_receive):
                fields.receive_cancelled = 1
                return original_receive()

            driver.receive = receive
            engine = UtilityExP6UDSScheduler(context, driver, fields=fields)
            status, _ = engine.exchange(b"\x22")
            # 108c early success still passes through the primary SID validation.
            self.assertEqual(status, 3 if expected == 0 else expected)
            self.assertEqual(fields.receive_cancelled, 0)
            self.assertEqual(driver.interrupted, interrupts)

    def test_p6_configuration_rebuilds_literal_lists_and_last_broker_key_wins(self):
        for protocol, count in ((6, 5), (0x8012, 9)):
            values = p6_configuration(protocol, override=True, flags=1, timing=2)
            self.assertEqual(len(values), count)
            self.assertEqual(dict(values)[0x10103], 0x300000)
            self.assertEqual(dict(values)[0x10106], 50)
            values = p6_configuration(
                protocol,
                override=False,
                flags=0x1234,
                timing=73,
                broker_parameters=((1, 125000), (0x805C, 1), (0x805C, 9), (0x23, 100)),
            )
            self.assertEqual(dict(values)[1], 500000)
            self.assertEqual(dict(values)[0x10103], 0x1234)
            self.assertEqual(dict(values)[0x10106], 73)
            self.assertEqual(dict(values)[0x23], 100)
            self.assertEqual(dict(values)[0x2A], 0xFFFF)
            if protocol == 0x8012:
                self.assertEqual(dict(values)[0x805C], 9)
                self.assertEqual(dict(values)[0x805D], 0)
        with self.assertRaises(ValueError):
            p6_configuration(
                6, override=False, flags=0, timing=0, broker_parameters=((1, -1),)
            )

    def test_p6_raw_adapter_resolves_shifted_slots_and_positional_outputs(self):
        from scripts.utility_ex import _P6_DRIVER_SLOTS, UtilityP6DriverBinding

        for source in (SHA_PLUS_NK, SHA_PLUS_TY):
            context = Context()
            context.module_sha256 = source
            for protocol in (6, 0x8012):
                calls = []

                def connect(actual_protocol, flags, output, *, calls=calls):
                    calls.append((actual_protocol, flags))
                    output[:] = (71).to_bytes(4, "little")
                    return PrimitiveResult()

                exports: dict[str, Callable[..., object]] = {
                    name: lambda *args: PrimitiveResult()
                    for name in _P6_DRIVER_SLOTS.values()
                }
                exports["PassThruConnect"] = connect
                binding = UtilityP6DriverBinding(
                    cast(UtilityExContext, context), protocol, exports
                )
                self.assertEqual(binding.slot_offset("PassThruConnect"), 0x24)
                self.assertEqual(binding.slot_offset("PassThruIoctl"), 0x30)
                adapter = UtilityExDriverPrimitives(context, binding)
                self.assertEqual(
                    adapter(
                        {
                            "operation": "PassThruConnect",
                            "protocol_id": protocol,
                            "flags": 0x800,
                        },
                        1,
                    ),
                    PrimitiveResult(0, 71),
                )
                self.assertEqual(calls, [(protocol, 0x800)])

    def test_p6_lower_and_separate_pool_execute_literal_raw_sdk_lifecycle(self):
        from scripts.utility_ex import _P6_DRIVER_SLOTS, UtilityP6DriverBinding

        for source in (SHA_PLUS_NK, SHA_PLUS_TY):
            for protocol, kind in ((6, 0x17), (0x8012, 0x18)):
                context, calls = Context(), []
                context.module_sha256 = source
                context.parameters.update(
                    {
                        0x70: 0x78 if protocol == 0x8012 else 0x18,
                        0xD3: 0xFFFFFFFF,
                        0xDD: 0xFFFFFFFF,
                    }
                )

                def controller(mode, output, label, *, calls=calls):
                    calls.append(("controller", mode, label))
                    output[:] = (51).to_bytes(4, "little")
                    return PrimitiveResult(7)

                def connect(actual_protocol, flags, output, *, calls=calls):
                    calls.append(("connect", actual_protocol, flags))
                    output[:] = (42).to_bytes(4, "little")
                    return PrimitiveResult()

                def ioctl(handle, code, payload, output, *, calls=calls):
                    calls.append(("ioctl", handle, code, payload))
                    if code == 0x800C:
                        self.assertIsInstance(output, UtilityExP6DataList)
                        self.assertEqual(
                            (output.count, bytes(output.records)),
                            (1, b"\x4d" + bytes(11)),
                        )
                    return PrimitiveResult()

                def start_filter(
                    handle, code, mask, pattern, flow, output, *, calls=calls
                ):
                    calls.append(("filter", code, mask, pattern, flow))
                    output[:] = (73).to_bytes(4, "little")
                    return PrimitiveResult()

                def write(handle, messages, count, timeout, *, calls=calls):
                    calls.append(("write", messages[0], timeout))
                    return PrimitiveResult()

                def read(handle, messages, count, timeout, *, protocol=protocol):
                    messages[0] = NativeMessage(protocol, bytes.fromhex("18daf1e06201"))
                    return PrimitiveResult()

                exports: dict[str, Callable[..., object]] = dict.fromkeys(
                    _P6_DRIVER_SLOTS.values(), lambda *args: PrimitiveResult()
                )
                exports.update(
                    {
                        "J2534CtrlInitialize": controller,
                        "PassThruConnect": connect,
                        "PassThruIoctl": ioctl,
                        "PassThruStartMsgFilter": start_filter,
                        "PassThruWriteMsgs": write,
                        "PassThruReadMsgs": read,
                        "PassThruStopMsgFilter": lambda handle, identifier, calls=calls: (
                            (
                                calls.append(("stop", handle, identifier)),
                                PrimitiveResult(),
                            )[1]
                        ),
                        "PassThruDisconnect": lambda handle, calls=calls: (
                            calls.append(("disconnect", handle)),
                            PrimitiveResult(),
                        )[1],
                    }
                )
                binding = UtilityP6DriverBinding(
                    cast(UtilityExContext, context), protocol, exports
                )
                device = J2534Device2026(
                    UtilityExDriverPrimitives(context, binding),
                    background_workers=False,
                )
                pool = UtilityExP6Pool(context, device)
                if protocol == 0x8012:
                    self.assertEqual(pool.initialize_controller(), 7)
                    self.assertEqual(pool.controller_handle, 51)
                lower = UtilityExP6Lower(context, pool, kind)
                self.assertEqual(lower.initialize(0x18DAE0F1, override=True), 0)
                self.assertEqual(lower.send(b"\x22\x01"), 0)
                context.parameters[0x70] = 0x18 if protocol == 0x8012 else 0x78
                self.assertEqual(lower.send(b"\x22\x01"), 0)
                retained = [call[1] for call in calls if call[0] == "write"][-1]
                self.assertEqual(retained.protocol_id, protocol)
                self.assertEqual(
                    retained.tx_flags, 0x140 if protocol == 0x8012 else 0x180140
                )
                context.parameters[0x70] = 0x78 if protocol == 0x8012 else 0x18
                self.assertEqual(lower.receive(), DriverReceive(0, b"\x62\x01"))
                filters = [call for call in calls if call[0] == "filter"]
                self.assertEqual(len(filters), 1)
                self.assertEqual(filters[0][1], 3)
                self.assertEqual(filters[0][3].data, bytes.fromhex("18daf1e0"))
                self.assertEqual(filters[0][3].tx_flags, 0x140)
                self.assertEqual(
                    [call for call in calls if call[0] == "connect"],
                    [("connect", protocol, 0x800)],
                )
                query = [
                    call for call in calls if call[0] == "ioctl" and call[2] == 0x800C
                ]
                self.assertEqual(len(query), int(protocol == 0x8012))
                self.assertEqual(lower.finalize(), 0)
                self.assertEqual(calls[-2:], [("stop", 42, 73), ("disconnect", 42)])
                broadcast = UtilityExP6BroadcastLower(context, pool, kind)
                self.assertEqual(
                    broadcast.initialize(
                        0x18DAE0F1, alternate_extra=0x18DB00F1, override=True
                    ),
                    0,
                )
                self.assertEqual(broadcast.send(b"\x22\x01"), 0)
                self.assertEqual(broadcast.receive(), DriverReceive(0, b"\x62\x01"))
                wire = [call[1] for call in calls if call[0] == "write"][-1]
                self.assertEqual(wire.data, bytes.fromhex("18db00f12201"))
                flow = [call[4] for call in calls if call[0] == "filter"][-1]
                self.assertEqual(flow.data, bytes.fromhex("18db00f1"))
                self.assertEqual(flow.tx_flags, 0x140)
                self.assertEqual(broadcast.finalize(), 0)

    def test_p6_factory_bindings_share_four_slots_and_route_each_raw_protocol(self):
        from scripts.utility_ex import _P6_DRIVER_SLOTS, UtilityP6DriverBinding

        context, calls = Context(), []
        context.module_sha256 = SHA_PLUS_TY
        context.parameters[0x70] = 0x78

        def binding(protocol):
            def connect(actual, flags, output):
                calls.append(("connect", actual))
                output[:] = (protocol + 50).to_bytes(4, "little")
                return PrimitiveResult()

            exports: dict[str, Callable[..., object]] = dict.fromkeys(
                _P6_DRIVER_SLOTS.values(), lambda *args: PrimitiveResult()
            )
            exports["PassThruConnect"] = connect
            exports["PassThruDisconnect"] = lambda handle: (
                calls.append(("close", protocol, handle)),
                PrimitiveResult(),
            )[1]
            exports["PassThruIoctl"] = lambda handle, code, payload, output: (
                calls.append(("ioctl", protocol, code)),
                PrimitiveResult(),
            )[1]
            return UtilityP6DriverBinding(
                cast(UtilityExContext, context), protocol, exports
            )

        first, second = binding(6), binding(0x8012)
        device = J2534Device2026(
            UtilityExDriverPrimitives(context, first), background_workers=False
        )
        pool = UtilityExP6Pool(context, device)
        pool.register_binding(second)
        self.assertEqual(pool.connect(6, 1), (0, 0))
        self.assertEqual(pool.connect(0x8012, 1), (13, 4))
        self.assertEqual(pool.connect(0x8012, 2), (0, 1))
        self.assertEqual(pool.connect(6, 3), (0, 2))
        self.assertEqual(pool.connect(0x8012, 4), (0, 3))
        self.assertEqual(pool.connect(6, 5), (14, 4))
        self.assertEqual(
            [call for call in calls if call[0] == "connect"],
            [("connect", 6), ("connect", 0x8012)],
        )
        self.assertEqual(
            [call for call in calls if call[0] == "ioctl"], [("ioctl", 0x8012, 0x800C)]
        )
        self.assertEqual(pool.ioctl(1, 3), 0)
        self.assertEqual(len([call for call in calls if call[0] == "ioctl"]), 1)
        self.assertEqual(pool.finalize(), 0)
        self.assertEqual({call[1] for call in calls if call[0] == "close"}, {6, 0x8012})

    def test_actual_plus_p6_original_context_facade_and_cancel_safe_raw_sdk(self):
        from scripts.utility_ex import _P6_DRIVER_SLOTS

        rows = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for source, address in ((SHA_PLUS_NK, 0x101C6DA0), (SHA_PLUS_TY, 0x1013E7D0)):
            row = next(row for row in rows if row["sha256"] == source)
            for protocol in (6, 0x8012):
                calls, pending = [], []

                class Host(Context):
                    def get_parameter(self, key, protocol=protocol):
                        return {
                            0x6F: 0x16,
                            0x70: 0x78 if protocol == 0x8012 else 0x18,
                            0x74: 0xE0,
                            0xD3: 0xFFFFFFFF,
                            0xDD: 0xFFFFFFFF,
                        }.get(key, 0)

                    def get_data_size(self, key):
                        return 0

                    def get_data(self, key):
                        return b""

                    def set_parameter(self, key, value):
                        return 0

                    def write_parameters(self):
                        return 0

                def connect(actual, flags, output, *, calls=calls):
                    calls.append(("connect", actual, flags))
                    output[:] = (42).to_bytes(4, "little")
                    return PrimitiveResult()

                def start_filter(handle, kind, mask, pattern, flow, output):
                    output[:] = (73).to_bytes(4, "little")
                    return PrimitiveResult()

                def write(
                    handle, messages, count, timeout, *, pending=pending, calls=calls
                ):
                    request = messages[0].data[4:]
                    calls.append(("write", messages[0], timeout))
                    pending.append(bytes((request[0] + 0x40,)) + request[1:])
                    return PrimitiveResult()

                def read(
                    handle,
                    messages,
                    count,
                    timeout,
                    *,
                    protocol=protocol,
                    pending=pending,
                ):
                    messages[0] = NativeMessage(
                        protocol, bytes.fromhex("18daf1e0") + pending.pop(0)
                    )
                    return PrimitiveResult()

                exports: dict[str, Callable[..., object]] = dict.fromkeys(
                    _P6_DRIVER_SLOTS.values(), lambda *args: PrimitiveResult()
                )
                exports.update(
                    {
                        "PassThruConnect": connect,
                        "PassThruStartMsgFilter": start_filter,
                        "PassThruWriteMsgs": write,
                        "PassThruReadMsgs": read,
                        "PassThruStopMsgFilter": lambda handle, identifier, calls=calls: (
                            (
                                calls.append(("stop", handle, identifier)),
                                PrimitiveResult(),
                            )[1]
                        ),
                        "PassThruDisconnect": lambda handle, calls=calls: (
                            calls.append(("disconnect", handle)),
                            PrimitiveResult(),
                        )[1],
                    }
                )
                context = UtilityExContext(
                    Path(row["input_path"]).read_bytes(),
                    Host(),
                    None,
                    None,
                    p6_driver_exports=exports,
                )
                context.refresh_parameters()
                comm = context.comm(f"native:{address:x}")
                comm.configure_target(0x18DAE0F1)
                self.assertEqual(comm.initialize(), 0)
                self.assertEqual(comm.session(3, 0, normal_first=True), 0)
                self.assertEqual(comm.exchange(b"\x22\x01"), (0, b"\x62\x01"))
                self.assertEqual(comm.read_field("native_10a4"), 255)
                comm.configure("native_10a4", 0)
                self.assertEqual(comm.read_field("native_10a4"), 0)
                self.assertEqual(comm.read_field("native_10b0"), 0)
                self.assertEqual(comm.read_field("native_10b4"), 0)
                context._cancel.set()
                self.assertEqual(comm.cleanup_session(1, 1, stop_on_error=True), 0)
                self.assertTrue(context.is_cancelled())
                self.assertIsNone(comm.finalize())
                self.assertEqual(calls[-2:], [("stop", 42, 73), ("disconnect", 42)])
                wires = [call[1] for call in calls if call[0] == "write"]
                self.assertEqual(
                    [message.data[4:] for message in wires],
                    [b"\x10\x01", b"\x10\x03", b"\x22\x01", b"\x10\x01"],
                )
                self.assertTrue(
                    all(
                        message.tx_flags == (0x180140 if protocol == 0x8012 else 0x140)
                        for message in wires
                    )
                )

    def test_p6_native_foreign_and_post_connect_cancel_cleanup_matrix(self):
        from scripts.utility_ex import _P6_DRIVER_SLOTS, UtilityP6DriverBinding

        for source in (SHA_PLUS_NK, SHA_PLUS_TY):
            for protocol, kind in ((6, 0x17), (0x8012, 0x18)):
                for fault in ("connect", "config", "foreign", "cancel", "query"):
                    if fault == "query" and protocol == 6:
                        continue
                    context, calls = Context(), []
                    context.module_sha256 = source
                    context.parameters.update(
                        {
                            0x70: 0x78 if protocol == 0x8012 else 0x18,
                            0xD3: 0xFFFFFFFF,
                            0xDD: 0xFFFFFFFF,
                        }
                    )

                    def connect(actual, flags, output, *, fault=fault, context=context):
                        if fault == "connect":
                            return PrimitiveResult(9)
                        output[:] = (42).to_bytes(4, "little")
                        if fault == "cancel":
                            context.cancelled = True
                        return PrimitiveResult()

                    def ioctl(handle, code, payload, output, *, fault=fault):
                        if code == 0x800C and fault == "query":
                            return PrimitiveResult(9)
                        if code == 2 and fault == "foreign":
                            raise OSError("P6 individual SDK failure")
                        return PrimitiveResult(
                            9 if code == 2 and fault == "config" else 0
                        )

                    exports: dict[str, Callable[..., object]] = dict.fromkeys(
                        _P6_DRIVER_SLOTS.values(), lambda *args: PrimitiveResult()
                    )
                    exports.update(
                        {
                            "PassThruConnect": connect,
                            "PassThruIoctl": ioctl,
                            "PassThruDisconnect": lambda handle, calls=calls: (
                                calls.append(("close", handle)),
                                PrimitiveResult(),
                            )[1],
                        }
                    )
                    binding = UtilityP6DriverBinding(
                        cast(UtilityExContext, context), protocol, exports
                    )
                    device = J2534Device2026(
                        UtilityExDriverPrimitives(context, binding),
                        cancelled=context.is_cancelled,
                        background_workers=False,
                    )
                    pool = UtilityExP6Pool(context, device)
                    lower = UtilityExP6Lower(context, pool, kind)
                    if fault in ("foreign", "cancel"):
                        with self.assertRaises(
                            OSError if fault == "foreign" else InterruptedError
                        ):
                            lower.initialize(0x18DAE0F1, override=True)
                    else:
                        self.assertEqual(
                            lower.initialize(0x18DAE0F1, override=True),
                            2 if fault == "config" else 99,
                        )
                    self.assertEqual(pool.owned, set())
                    self.assertTrue(all(channel is None for channel in pool.channels))
                    self.assertEqual(
                        calls, [] if fault in ("connect", "query") else [("close", 42)]
                    )
                    self.assertEqual(context.cancelled, fault == "cancel")

    def test_input_boundaries(self):
        engine, _, _ = self.engine()
        for request in (b"", bytes(0x1020)):
            with self.assertRaises(ValueError):
                engine.exchange(request)
        with self.assertRaises(ValueError):
            DriverReceive(True)
        with self.assertRaises(ValueError):
            DriverReceive(0, bytes(0x1020))


class PublicationOwnerTests(unittest.TestCase):
    def test_concurrent_publication_yields_one_owner_and_one_lock(self):
        class Owner:
            def __init__(self, context):
                self.context = context
                self.lock = threading.Lock()
                time.sleep(0.01)

        context = cast(CommContext, SimpleNamespace(state={}))
        barrier = threading.Barrier(8)
        created: list[Owner] = []
        published: list[Owner] = []

        def factory() -> Owner:
            owner = Owner(context)
            created.append(owner)
            return owner

        def publish() -> None:
            barrier.wait()
            published.append(
                _published_state(
                    context,
                    "owner",
                    Owner,
                    factory,
                    "Concrete same-context owner required",
                )
            )

        threads = [threading.Thread(target=publish) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(created), 1)
        self.assertEqual(len({id(owner) for owner in published}), 1)
        self.assertIs(context.state["owner"], published[0])
        self.assertIs(published[0].lock, created[0].lock)

    def test_publication_rejects_a_foreign_context_owner(self):
        context = cast(CommContext, SimpleNamespace(state={}))
        foreign = SimpleNamespace(state={})

        class Owner:
            def __init__(self, owner_context):
                self.context = owner_context

        context.state["owner"] = Owner(foreign)
        with self.assertRaises(TypeError):
            _published_state(
                context,
                "owner",
                Owner,
                lambda: Owner(context),
                "Concrete same-context owner required",
            )


if __name__ == "__main__":
    unittest.main()
