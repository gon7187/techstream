"""Literal fixed manager to raw positional SDK checks, no device or DLL execution."""

import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import cast

from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
from scripts.utility_ex import (
    UtilityDriverBinding,
    UtilityExContext,
    UtilityP6DriverBinding,
    UtilitySISDriverBinding,
)
from scripts.utility_ex_comm import (
    _FIXED_OBJECTS,
    _MANAGER_OBJECTS,
    SHA_12_NK,
    SHA_12_TY,
    SHA_18_NK,
    SHA_18_TY,
    SHA_DS4_NK,
    SHA_DS4_TY,
    SHA_PLUS_NK,
    SHA_PLUS_TY,
    UDSFields,
    UtilityExComm,
    UtilityExDirectDriver,
    UtilityExDriverPrimitives,
    UtilityExP6Fields,
    UtilityExP6Pool,
    UtilityExPassThruPool,
    UtilityExSourceError,
)
from scripts.utility_ex_lifecycle import (
    UtilityExAlternateUDSFields,
    UtilityExAlternateUDSScheduler,
    UtilityExByteArray,
    UtilityExClassicCANLower,
    UtilityExFixedLifecycle,
    UtilityExLegacyP4Lower,
    UtilityExP3F1Lower,
    UtilityExP3SlowLower,
    UtilityExP3StrictLower,
    UtilityExP6Lifecycle,
    UtilityExSelectedCMNFields,
    UtilityExSelectedCMNWorker,
    UtilityExSelectedP5Worker,
    UtilityExSelectedTimerKeepalive,
    UtilityExSISDriver,
    UtilityExSISFields,
    UtilityExSISLifecycle,
    UtilityExSISLower,
    UtilityExSISMessage,
    UtilityExSISPins,
    UtilityExSISUDSScheduler,
    legacy_p4_parameters,
    p3_strict_parameters,
    stop_fixed_worker,
    utility_ex_cleanup_scope,
)


class Context:
    module_sha256 = SHA_18_NK
    module_bytes = b""

    def __init__(self):
        self.state: dict[str, object] = {}
        self.parameters = {0x6F: 0x14, 0x70: 0x12, 0x74: 0x7E0}
        self.tick = 0
        self.cancelled = False
        self.data: dict[int, bytes] = {}
        self.profile_calls: list[tuple] = []
        self.profile_value = b"0123456789abcdef"
        self.raw_bindings: dict[tuple[int, int], object] = {}
        self.native_sleeps: list[int] = []
        self.timer_calls: list[tuple] = []
        self.timers: dict[int, Callable[[int, int, int, int], None]] = {}

    def broker(self, key: int) -> int:
        return self.parameters.get(key, 0)

    def native_parameter(self, key: int) -> int:
        return self.broker(key)

    def broker_data(self, key: int) -> bytes:
        return self.data.get(key, b"")

    def driver_binding(
        self, protocol: int, *, constructor_parameter: int = 0
    ) -> object:
        return self.raw_bindings[(protocol, constructor_parameter)]

    def is_cancelled(self) -> bool:
        return self.cancelled

    def ticks(self) -> int:
        return self.tick

    def sleep(self, milliseconds: int) -> None:
        self.tick = (self.tick + milliseconds) & 0xFFFFFFFF

    def native_sleep(self, milliseconds: int) -> None:
        self.native_sleeps.append(milliseconds)
        if threading.current_thread() is not threading.main_thread():
            time.sleep(milliseconds / 1000)
        self.sleep(milliseconds)

    def read_module_data(self, address: int, size: int) -> bytes:
        return self.data.get(address, b"")[:size].ljust(size, b"\x00")

    def get_private_profile_int_a(self, section, key, default, filename) -> int:
        self.profile_calls.append(("int", section, key, default, filename))
        return default

    def get_private_profile_string_a(
        self, section, key, default, output, capacity, filename
    ) -> int:
        self.profile_calls.append(("string", section, key, default, capacity, filename))
        value = self.profile_value[: capacity - 1]
        output[: len(value) + 1] = value + b"\x00"
        return len(value)

    def json_d_get_data(self, kind: int, section: str, key: str) -> int:
        raise AssertionError("Individual JSON numeric primitive not supplied")

    def json_s_get_data(self, kind: int, section: str, key: str) -> str:
        raise AssertionError("Individual JSON string primitive not supplied")

    def set_timer(self, hwnd, identifier, interval_ms, callback) -> int:
        self.timer_calls.append(("set", hwnd, identifier, interval_ms))
        self.timers[55] = callback
        return 55

    def kill_timer(self, hwnd, identifier) -> int:
        self.timer_calls.append(("kill", hwnd, identifier))
        self.timers.pop(identifier, None)
        return 1


class LifecycleTest(unittest.TestCase):
    def test_p6_separate_lifecycle_session_worker_and_cleanup_both_images(self):
        from scripts.utility_ex import _P6_DRIVER_SLOTS

        for source, address in ((SHA_PLUS_NK, 0x101C6DA0), (SHA_PLUS_TY, 0x1013E7D0)):
            for protocol in (6, 0x8012):
                with self.subTest(source=source[:12], protocol=protocol):
                    responses = [
                        NativeMessage(protocol, bytes.fromhex("18dae007") + reply)
                        for reply in (
                            b"\x50\x03",
                            b"\x7e\x00",
                            b"\x7f\x3e\x21",
                            b"\x62\x01",
                            b"\x7f\x22\x33",
                            b"\x50\x01",
                        )
                    ]
                    base, context, calls = self.fixture(
                        responses, source=source, address=_FIXED_OBJECTS[source]
                    )
                    adapter = base.pool.device.provider
                    assert isinstance(adapter, UtilityExDriverPrimitives)
                    exports: dict[str, Callable[..., object]] = {}
                    for name in _P6_DRIVER_SLOTS.values():
                        function = adapter.binding.resolve(
                            adapter.binding.slot_offset(name)
                        )
                        assert function is not None
                        exports[name] = function
                    binding = UtilityP6DriverBinding(
                        cast(UtilityExContext, context), protocol, exports
                    )
                    pool = UtilityExP6Pool(
                        context,
                        J2534Device2026(
                            UtilityExDriverPrimitives(context, binding),
                            cancelled=context.is_cancelled,
                            background_workers=False,
                        ),
                    )
                    fields = UtilityExP6Fields(parameters=((1, 500000),))
                    manager = UtilityExP6Lifecycle(context, pool, fields, address)
                    self.addCleanup(manager.finalize)
                    context.parameters.update(
                        {0x6F: 0x16, 0x70: 0x78 if protocol == 0x8012 else 0x18}
                    )
                    with self.assertRaisesRegex(UtilityExSourceError, "P6 broadcast"):
                        manager.select_diagnostic_mode(3)
                    self.assertEqual(fields.diagnostic_enabled, 1)
                    self.assertEqual(manager.initialize(), 0)
                    self.assertEqual(manager.session(3, 0), 0)
                    manager.worker_active = True
                    manager._stop.clear()
                    context.tick = 2001
                    self.assertTrue(manager.worker_step())
                    self.assertEqual(manager.worker_status, 0)
                    context.tick = 4002
                    self.assertTrue(manager.worker_step())
                    self.assertEqual(manager.worker_status, 28)
                    self.assertEqual(manager.exchange(b"\x22\x01"), (0, b"\x62\x01"))
                    fields.retry_count = 1
                    self.assertEqual(
                        manager.exchange(b"\x22\x01"), (7, b"\x7f\x22\x33")
                    )
                    self.assertEqual(fields.native_error, 108)
                    write_slot = binding.slot_offset("PassThruWriteMsgs")
                    original_write = binding.slots[write_slot]
                    fault = RuntimeError("P6 foreign write fault")

                    def fail_write(*args, fault=fault):
                        raise fault

                    binding.slots[write_slot] = fail_write
                    with self.assertRaises(RuntimeError) as caught:
                        manager.exchange(b"\x22\x01")
                    self.assertIs(caught.exception, fault)
                    self.assertIsNotNone(manager.lower)
                    binding.slots[write_slot] = original_write
                    context.cancelled = True
                    self.assertEqual(manager.cleanup_session(1, 0), 0)
                    self.assertEqual(fields.current_session, 1)
                    self.assertTrue(context.cancelled)
                    self.assertEqual(manager.finalize(), 0)
                    self.assertEqual(fields.current_session, 0)
                    self.assertIn(("connect", protocol, 0x800), calls)
                    self.assertEqual(calls[-1], ("disconnect", 42))

    def test_all8_three_derived_p3_classes_use_distinct_wire_and_configuration(self):
        for source in _MANAGER_OBJECTS:
            for lower_class, parameter_count, strict, tester in (
                (UtilityExP3F1Lower, 16, True, 0xF1),
                (UtilityExP3StrictLower, 4, True, 0xF0),
                (UtilityExP3SlowLower, 9, False, 0xF0),
            ):
                with self.subTest(source=source[:12], lower=lower_class.__name__):
                    frames = []
                    for payload in (b"\x62\x01", b"\x7f\x22\x12"):
                        data = bytes((0x80 + len(payload), tester, 0x33)) + payload
                        frames.append(
                            NativeMessage(4, data + bytes((sum(data) & 255,)))
                        )
                    manager, context, calls = self.fixture(
                        frames,
                        protocol=4,
                        source=source,
                        address=_FIXED_OBJECTS[source],
                    )
                    adapter = manager.pool.device.provider
                    assert isinstance(adapter, UtilityExDriverPrimitives)
                    lower = lower_class(
                        context, UtilityExDirectDriver(context, adapter, 4)
                    )
                    self.addCleanup(lower.finalize)
                    ioctl_slot = adapter.binding.slot_offset("PassThruIoctl")
                    original = adapter.binding.slots[ioctl_slot]

                    def ioctl(
                        channel,
                        kind,
                        payload,
                        output,
                        *,
                        original=original,
                        tester=tester,
                    ):
                        assert original is not None
                        result = original(channel, kind, payload, output)
                        if kind == 4:
                            self.assertIsInstance(payload, UtilityExByteArray)
                            output.data[:] = b"\x08\x08"
                        elif kind == 5:
                            self.assertEqual(payload.data[2], tester)
                            data = bytes((0x83, tester, 0x33, 0xC1, 1, 2))
                            output[0] = NativeMessage(
                                4, data + bytes((sum(data) & 255,))
                            )
                        return result

                    adapter.binding.slots[ioctl_slot] = ioctl
                    self.assertEqual(lower.initialize(0x33, override=True), 0)
                    self.assertEqual(len(calls[1][2]), parameter_count)
                    self.assertEqual(lower.send(b"\x22\x01"), 0)
                    data = bytes((0x82, 0x33, tester, 0x22, 1))
                    self.assertIn(("write", data + bytes((sum(data) & 255,))), calls)
                    self.assertEqual(lower.receive().data, b"\x62\x01")
                    self.assertEqual(lower.receive().status, 0x16 if strict else 0)
                    self.assertEqual(lower.finalize(), 0)
                    self.assertEqual(calls[-1], ("disconnect", 42))

    def test_strict_p3_profile156_exists_after12_only(self):
        for source in _MANAGER_OBJECTS:
            with self.subTest(source=source[:12]):
                self.assertEqual(
                    len(p3_strict_parameters(0x156, source)),
                    4 if source in (SHA_12_NK, SHA_12_TY) else 15,
                )

    def test_all8_seven_classic_objects_drive_positional_sdk_and_cleanup(self):
        for source, objects in _MANAGER_OBJECTS.items():
            for index in (8, 9, 6, 5, 7, 10, 11):
                with self.subTest(source=source[:12], manager_index=index):
                    offset = {6: 0x100, 5: 0x20, 7: 0xC0}.get(index, 0)
                    extension = b"\x29" if index in (10, 11) else b""
                    address = 0x7E0 - offset if offset else 0x7E8
                    replies = [
                        NativeMessage(
                            6, address.to_bytes(4, "big") + extension + b"\x62\x01"
                        )
                    ]
                    if offset:
                        start = b"\xc1\xd0\x8f" if offset == 0x20 else b"\x50\xc0"
                        end = b"\xc2" if offset == 0x20 else b"\xc1\x81"
                        replies.insert(
                            0, NativeMessage(6, address.to_bytes(4, "big") + start)
                        )
                        replies.append(
                            NativeMessage(6, address.to_bytes(4, "big") + end)
                        )
                    manager, context, calls = self.fixture(
                        replies,
                        source=source,
                        address=_FIXED_OBJECTS[source],
                        constructor_parameter=0xD if offset else 0,
                    )
                    context.parameters[0xAB] = 0x29
                    adapter = manager.pool.device.provider
                    assert isinstance(adapter, UtilityExDriverPrimitives)
                    driver = UtilityExDirectDriver(context, adapter, 6)
                    lower = UtilityExClassicCANLower(context, driver, objects[index])
                    self.addCleanup(lower.finalize)
                    self.assertEqual(lower.initialize(0x7E0, override=True), 0)
                    self.assertEqual(lower.send(b"\x22\x01"), 0)
                    self.assertEqual(lower.receive().data, b"\x62\x01")
                    self.assertIn(
                        ("write", bytes.fromhex("000007e0") + extension + b"\x22\x01"),
                        calls,
                    )
                    self.assertEqual(
                        calls[0],
                        ("connect", 0x1000C if offset else 6, 0x80 if extension else 0),
                    )
                    self.assertEqual(lower.finalize(), 0)
                    self.assertEqual(calls[-1], ("disconnect", 42))

    def test_all8_classic_profile69_uses_source_specific_override_table(self):
        for source, objects in _MANAGER_OBJECTS.items():
            with self.subTest(source=source[:12]):
                manager, context, calls = self.fixture(
                    source=source, address=_FIXED_OBJECTS[source]
                )
                adapter = manager.pool.device.provider
                assert isinstance(adapter, UtilityExDriverPrimitives)
                lower = UtilityExClassicCANLower(
                    context, UtilityExDirectDriver(context, adapter, 6), objects[8]
                )
                self.addCleanup(lower.finalize)
                lower.profile = 0x69
                self.assertEqual(lower.initialize(0x7E0, override=True), 0)
                configuration = calls[1][2]
                self.assertIn(
                    (
                        0x10103,
                        0x300000 if source in (SHA_12_NK, SHA_12_TY) else 0x300004,
                    ),
                    configuration,
                )
                self.assertEqual(lower.finalize(), 0)

    def test_selected_lower10_timeout_only_affects_later_ordinary_class(self):
        for source, objects in _MANAGER_OBJECTS.items():
            for index in (8, 9, 10, 11):
                with self.subTest(source=source[:12], index=index):
                    message = NativeMessage(
                        6,
                        bytes.fromhex("000007e8")
                        + (b"\0" if index in (10, 11) else b"")
                        + b"\x62\x01",
                    )
                    manager, context, _calls = self.fixture(
                        [message], source=source, address=_FIXED_OBJECTS[source]
                    )
                    adapter = manager.pool.device.provider
                    assert isinstance(adapter, UtilityExDriverPrimitives)
                    lower = UtilityExClassicCANLower(
                        context,
                        UtilityExDirectDriver(context, adapter, 6),
                        objects[index],
                    )
                    self.addCleanup(lower.finalize)
                    lower.native_timeout_10 = 200
                    timeouts = []
                    adapter.binding.slots[
                        adapter.binding.slot_offset("PassThruWriteMsgs")
                    ] = lambda channel, messages, count, timeout, timeouts=timeouts: (
                        timeouts.append(timeout),
                        PrimitiveResult(),
                    )[1]
                    self.assertEqual(lower.initialize(0x7E0), 0)
                    self.assertEqual(lower.send(b"\x22\x01"), 0)
                    expected = (
                        0x3FC
                        if index in (9, 11)
                        else 200
                        if index == 8 and source not in (SHA_12_NK, SHA_12_TY)
                        else 1000
                    )
                    self.assertEqual(timeouts, [expected])
                    self.assertEqual(lower.receive().status, 0)
                    self.assertEqual(lower.timeout_ms, expected)

    def test_all8_classic_native_fault_host_fault_and_cancel_release_owned_sdk(self):
        for source, objects in _MANAGER_OBJECTS.items():
            for failure in ("native", "foreign", "cancel"):
                with self.subTest(source=source[:12], failure=failure):
                    manager, context, calls = self.fixture(
                        source=source, address=_FIXED_OBJECTS[source]
                    )
                    adapter = manager.pool.device.provider
                    assert isinstance(adapter, UtilityExDriverPrimitives)
                    lower = UtilityExClassicCANLower(
                        context, UtilityExDirectDriver(context, adapter, 6), objects[8]
                    )
                    self.addCleanup(lower.finalize)
                    foreign = RuntimeError("authored configuration primitive fault")

                    def ioctl(
                        channel,
                        kind,
                        payload,
                        output,
                        *,
                        failure=failure,
                        foreign=foreign,
                        context=context,
                    ):
                        if failure == "foreign":
                            raise foreign
                        if failure == "cancel":
                            context.cancelled = True
                        return PrimitiveResult(9 if failure == "native" else 0)

                    adapter.binding.slots[
                        adapter.binding.slot_offset("PassThruIoctl")
                    ] = ioctl
                    if failure == "native":
                        self.assertEqual(lower.initialize(0x7E0), 2)
                    else:
                        with self.assertRaises(
                            RuntimeError if failure == "foreign" else InterruptedError
                        ) as caught:
                            lower.initialize(0x7E0)
                        if failure == "foreign":
                            self.assertIs(caught.exception, foreign)
                    self.assertEqual(calls[-1], ("disconnect", 42))
                    self.assertIsNone(lower.driver.handle)
                    self.assertFalse(lower.attached)

    def test_common_finalize_inactive_ty18_managers_never_binds_sdk(self):
        context = Context()
        context.module_sha256 = SHA_18_TY
        for address in (0x1011D4F0, 0x1011C400, 0x1011B310, 0x1011A220, 0x1011E618):
            stop_fixed_worker(context, address, 1)
        self.assertFalse(context.raw_bindings)
        self.assertFalse(
            any(
                "driver" in key or "pool" in key or "lifecycle" in key
                for key in context.state
            )
        )
        with self.assertRaises(UtilityExSourceError):
            stop_fixed_worker(context, 0x1011E619, 1)

    def test_selected_p5_worker_plain_exchange_tick_gate_and_real_close(self):
        _manager, context, calls = self.fixture(
            [b"\x61\x00"], source=SHA_18_TY, address=0x1011D4F0
        )
        comm = self.selected_facade(context)
        self.assertEqual(comm.initialize(), 0)
        worker = UtilityExSelectedP5Worker(context, comm)
        worker.configure(2000, b"\x21\x00", 2, 0xF0)
        context.tick = 2000
        self.assertEqual(worker.worker_step(), 0)
        self.assertFalse(any(call[0] == "write" for call in calls))
        context.tick = 2001
        self.assertEqual(worker.worker_step(), 0)
        self.assertIn(("write", bytes.fromhex("000007e02100")), calls)
        worker.stop(1)
        self.assertEqual(calls[-1], ("disconnect", 42))

    def test_all8_selected_p5_worker_actual_facade_plain_scheduler_and_close(self):
        for source in _MANAGER_OBJECTS:
            with self.subTest(source=source[:12]):
                _manager, context, calls = self.fixture(
                    [b"\x61\x00"], source=source, address=_FIXED_OBJECTS[source]
                )
                comm = self.selected_facade(context)
                self.assertEqual(comm.initialize(), 0)
                worker = UtilityExSelectedP5Worker(context, comm)
                worker.configure(2000, b"\x21\x00", 2, 0xF0)
                context.tick = 2000
                self.assertEqual(worker.worker_step(), 0)
                self.assertFalse(any(call[0] == "write" for call in calls))
                context.tick += 1
                self.assertEqual(worker.worker_step(), 0)
                self.assertIn(("write", bytes.fromhex("000007e02100")), calls)
                worker.stop(1)
                self.assertEqual(calls[-1], ("disconnect", 42))

    def test_selected_p5_worker_exact_size_fault_and_foreign_error_observable(self):
        foreign = RuntimeError("authored SDK exception")
        _manager, context, _calls = self.fixture(
            [b"\x61\x00", foreign], source=SHA_18_TY, address=0x1011D4F0
        )
        comm = self.selected_facade(context)
        self.assertEqual(comm.initialize(), 0)
        self.addCleanup(comm.finalize)
        worker = UtilityExSelectedP5Worker(context, comm)
        worker.configure(0, b"\x21\x00", 3, 0xF0)
        context.tick += 1
        self.assertEqual(worker.worker_step(), 3)
        context.tick += 1
        with self.assertRaises(RuntimeError) as caught:
            worker.worker_step()
        self.assertIs(caught.exception, foreign)

    def test_worker_restart_retains_unobserved_host_exception(self):
        manager, context, _calls = self.fixture(source=SHA_18_TY, address=0x1011D4F0)
        foreign = RuntimeError("retained worker exception")
        manager.worker_error = foreign
        with self.assertRaises(RuntimeError) as caught:
            manager.keepalive(True)
        self.assertIs(caught.exception, foreign)
        worker = UtilityExSelectedP5Worker(context, self.selected_facade(context))
        worker.error = foreign
        with self.assertRaises(RuntimeError) as caught:
            worker.start()
        self.assertIs(caught.exception, foreign)
        with self.assertRaises(RuntimeError) as caught:
            worker.get_status()
        self.assertIs(caught.exception, foreign)

    def selected_facade(self, context: Context) -> UtilityExComm:
        original = Path(
            {
                SHA_12_NK: "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityExNK2.dll",
                SHA_18_NK: "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll",
                SHA_DS4_NK: "artifacts/extracted/gtsplus-application/Setup_PF/DS4/bin/UtilityExNK2_DS4.dll",
                SHA_PLUS_NK: "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityExNK2.dll",
                SHA_12_TY: "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
                SHA_18_TY: "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
                SHA_DS4_TY: "artifacts/extracted/gtsplus-application/Setup_PF/DS4/bin/UtilityEx2TY_DS4.dll",
                SHA_PLUS_TY: "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
            }[context.module_sha256]
        )
        if not original.is_file():
            self.skipTest(
                "Caller-owned exact NK image required for facade authentication"
            )
        context.module_bytes = original.read_bytes()
        return UtilityExComm(context, "selected")

    def fixture(
        self,
        replies=(),
        *,
        fault=None,
        source=SHA_18_NK,
        address=0x1014F5E0,
        constructor_parameter=0,
        protocol=6,
    ):
        context = Context()
        context.module_sha256 = source
        calls: list[tuple] = []
        incoming = iter(replies)
        handles = iter(range(21, 100))

        def connect(protocol, flags, output):
            calls.append(("connect", protocol, flags))
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def ioctl(channel, kind, payload, output):
            calls.append(("ioctl", kind, payload))
            if fault is not None:
                fault()
            return PrimitiveResult()

        def start_filter(channel, kind, mask, pattern, flow, output):
            calls.append(
                ("filter", kind, mask.data, pattern.data, flow.data if flow else None)
            )
            output[:] = next(handles).to_bytes(4, "little")
            return PrimitiveResult()

        def write(channel, messages, count, timeout):
            calls.append(("write", messages[0].data))
            return PrimitiveResult()

        def read(channel, messages, count, timeout):
            reply = next(incoming)
            if isinstance(reply, BaseException):
                raise reply
            if type(reply) is int:
                return PrimitiveResult(reply)
            if isinstance(reply, NativeMessage):
                messages[0] = reply
                return PrimitiveResult()
            messages[0] = NativeMessage(6, bytes.fromhex("000007e8") + reply)
            return PrimitiveResult()

        exports: dict[str, Callable[..., object]] = dict.fromkeys(
            (
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
            ),
            lambda *arguments: PrimitiveResult(),
        )
        exports.update(
            {
                "PassThruConnect": connect,
                "PassThruIoctl": ioctl,
                "PassThruStartMsgFilter": start_filter,
                "PassThruWriteMsgs": write,
                "PassThruReadMsgs": read,
                "PassThruStopMsgFilter": lambda channel, handle: (
                    calls.append(("stop_filter", handle)),
                    PrimitiveResult(),
                )[1],
                "PassThruDisconnect": lambda channel: (
                    calls.append(("disconnect", channel)),
                    PrimitiveResult(),
                )[1],
            }
        )
        binding = UtilityDriverBinding(
            cast(UtilityExContext, context),
            protocol,
            exports,
            constructor_parameter=constructor_parameter,
        )
        context.raw_bindings[(protocol, constructor_parameter)] = binding
        pool = UtilityExPassThruPool(
            context,
            J2534Device2026(
                UtilityExDriverPrimitives(context, binding),
                cancelled=context.is_cancelled,
                background_workers=False,
            ),
        )
        fields = UDSFields(parameters=((1, 500000),))
        manager = UtilityExFixedLifecycle(context, pool, fields, address)
        self.addCleanup(manager.finalize)
        return manager, context, calls

    def test_all_eight_literal_fixed_selector_variants_and_global_priority(self):
        cases = (
            (SHA_12_NK, 0x100E9850, 0x100EA978),
            (SHA_12_TY, 0x100AED50, 0x100AFE78),
            (SHA_18_NK, 0x1014F5E0, 0x101517F0),
            (SHA_18_TY, 0x1011D4F0, 0x1011F700),
            (SHA_DS4_NK, 0x101B6758, 0x101B8AD8),
            (SHA_DS4_TY, 0x1006CF88, 0x1006F308),
            (SHA_PLUS_NK, 0x101C18A0, 0x101C8008),
            (SHA_PLUS_TY, 0x101392D0, 0x1013FA38),
        )
        for source, address, base in cases:
            with self.subTest(source=source[:12]):
                manager, context, _ = self.fixture(source=source, address=address)
                old = source in (SHA_12_NK, SHA_12_TY)
                plus = source in (SHA_PLUS_NK, SHA_PLUS_TY)
                for mode, protocol, expected in (
                    (0x14, 0x12, 0x10),
                    (0x15, 0x22, 0x14),
                    (0x15, 0x62, 0x15),
                    (0x34, 0x12, 0 if old else 0x10),
                    (0x74, 0x12, 0x13 if plus else 0),
                    (0x74, 0x62, 0),
                ):
                    context.state[f"native_global:{base + 8:x}"] = mode
                    context.state[f"native_global:{base + 12:x}"] = protocol
                    self.assertEqual(manager._kind(), expected)
                context.state[f"native_global:{base:x}"] = 0x750
                manager._target_defaults()
                self.assertEqual(manager.fields.primary_address, 0x750)

    def classic_fixture(self, replies=(), *, p5=False, fault=None):
        manager, context, calls = self.fixture(replies, fault=fault)
        adapter = manager.pool.device.provider
        assert isinstance(adapter, UtilityExDriverPrimitives)
        driver = UtilityExDirectDriver(context, adapter, 6)
        lower = UtilityExClassicCANLower(
            context, driver, 0x1014AD90 if p5 else 0x1014AE60
        )
        self.addCleanup(lower.finalize)
        return lower, context, calls

    def legacy_p4_fixture(self, payloads=(), *, fast=False, source=SHA_18_NK):
        messages = []
        for response in payloads:
            if type(response) is int:
                messages.append(response)
            else:
                data = b"\x48\x6b\x33" + response
                messages.append(NativeMessage(4, data + bytes((sum(data) & 255,))))
        manager, context, calls = self.fixture(
            messages, protocol=4, source=source, address=_FIXED_OBJECTS[source]
        )
        context.parameters[0x73] = 0x5C if fast else 0
        adapter = manager.pool.device.provider
        assert isinstance(adapter, UtilityExDriverPrimitives)
        driver = UtilityExDirectDriver(context, adapter, 4)
        lower = UtilityExLegacyP4Lower(context, driver)
        self.addCleanup(lower.finalize)
        ioctl_slot = adapter.binding.slot_offset("PassThruIoctl")
        original = adapter.binding.slots[ioctl_slot]

        def ioctl(channel, kind, payload, output):
            assert original is not None
            original(channel, kind, payload, output)
            if kind == 4:
                self.assertIsInstance(payload, UtilityExByteArray)
                self.assertEqual(payload.data, b"\x33")
                output.data[:] = b"\x08\x08"
            elif kind == 5:
                data = b"\x83\xf0\x33\xc1\x01\x02"
                output[0] = NativeMessage(4, data + bytes((sum(data) & 255,)))
            return PrimitiveResult()

        adapter.binding.slots[ioctl_slot] = ioctl
        return lower, context, calls

    def test_all8_legacy_p4_slow_fast_init_wire_and_both_receive_methods(self):
        for source in _MANAGER_OBJECTS:
            for fast in (False, True):
                with self.subTest(source=source[:12], fast=fast):
                    lower, context, calls = self.legacy_p4_fixture(
                        [b"\x62\x01", b"\x62\x02", 9], fast=fast, source=source
                    )
                    lower.profile = 0x1EB if fast else 0
                    context.tick = 1
                    self.assertEqual(lower.initialize(0x33, override=True), 0)
                    self.assertEqual(calls[0], ("connect", 4, 0x200))
                    self.assertEqual(calls[1][2], legacy_p4_parameters(lower.profile))
                    self.assertEqual(lower.send(b"\x22\x01"), 0)
                    self.assertEqual(lower.receive_once().data, b"\x62\x01")
                    self.assertEqual(lower.receive().data, b"\x62\x02")
                    self.assertEqual(lower.finalize(), 0)
                    self.assertEqual(calls[-1], ("disconnect", 42))

    def test_legacy_p4_slow_init_literal_wire_and_receive_until_native_timeout(self):
        lower, context, calls = self.legacy_p4_fixture([b"\x62\x01", 9])
        context.tick = 1
        self.assertEqual(lower.initialize(0x33, override=True), 0)
        self.assertEqual(context.tick, 5000)
        self.assertEqual(calls[0], ("connect", 4, 0x200))
        self.assertEqual(calls[1][2], legacy_p4_parameters(0))
        self.assertEqual(lower.send(b"\x22\x01"), 0)
        data = bytes.fromhex("686af02201")
        self.assertEqual(calls[-1], ("write", data + bytes((sum(data) & 255,))))
        self.assertEqual(lower.receive().data, b"\x62\x01")
        self.assertEqual(lower.timeout_ms, 100)
        self.assertEqual(lower.finalize(), 0)

    def test_legacy_p4_vslot18_returns_first_frame_without_aggregate_read(self):
        lower, _, _ = self.legacy_p4_fixture([b"\x62\x01", 9])
        self.assertEqual(lower.initialize(0x33), 0)
        self.assertEqual(lower.receive_once().data, b"\x62\x01")
        self.assertEqual(lower.receive().status, 2)
        self.assertEqual(lower.finalize(), 0)

    def test_legacy_p4_fast_init_profile_and_pending_return(self):
        lower, _, calls = self.legacy_p4_fixture([b"\x7f\x22\x78"], fast=True)
        lower.profile = 0x1EB
        self.assertEqual(lower.initialize(0x33, override=True), 0)
        self.assertEqual(len(calls[1][2]), 15)
        self.assertEqual(calls[2][1], 5)
        self.assertEqual(lower.receive().status, 5)
        self.assertEqual(lower.finalize(), 0)

    def test_selected_classic_extended_literal_extension_filters_and_timeouts(self):
        for address, pending in ((0x1014C168, 5000), (0x1014C288, 5000)):
            with self.subTest(address=hex(address)):
                replies = [
                    NativeMessage(6, bytes.fromhex("000007e8297f2278")),
                    NativeMessage(6, bytes.fromhex("000007e82a6201")),
                ]
                manager, context, calls = self.fixture(replies)
                context.parameters[0xAB] = 0x29
                adapter = manager.pool.device.provider
                assert isinstance(adapter, UtilityExDriverPrimitives)
                driver = UtilityExDirectDriver(context, adapter, 6)
                lower = UtilityExClassicCANLower(context, driver, address)
                self.addCleanup(lower.finalize)
                lower.profile = 0x7B
                self.assertEqual(lower.initialize(0x7E0, override=True), 0)
                self.assertEqual(calls[0], ("connect", 6, 0x80))
                if address == 0x1014C168:
                    self.assertIn((0x10103, 0x300064), calls[1][2])
                self.assertEqual(lower.send(b"\x22\x01"), 0)
                self.assertEqual(calls[-1], ("write", bytes.fromhex("000007e0292201")))
                self.assertEqual(lower.receive().status, 5)
                self.assertEqual(lower.timeout_ms, pending)
                self.assertEqual(lower.receive().status, 3)
                self.assertEqual(lower.timeout_ms, pending)
                self.assertEqual(lower.finalize(), 0)

    def test_selected_sil_distinct_driver_and_literal_start_business_exit(self):
        for address, offset in (
            (0x1014AEA0, 0x100),
            (0x1014AF30, 0x20),
            (0x1014AF80, 0xC0),
        ):
            with self.subTest(address=hex(address)):
                start, end = (
                    (b"\xc1\xd0\x8f", b"\xc2")
                    if offset == 0x20
                    else (b"\x50\xc0", b"\xc1\x81")
                )
                header = (0x7E0 - offset).to_bytes(4, "big")
                manager, context, calls = self.fixture(
                    [
                        NativeMessage(6, header + response)
                        for response in (start, b"\x62\x01", end)
                    ],
                    constructor_parameter=0xD,
                )
                adapter = manager.pool.device.provider
                assert isinstance(adapter, UtilityExDriverPrimitives)
                driver = UtilityExDirectDriver(context, adapter, 6)
                lower = UtilityExClassicCANLower(context, driver, address)
                self.addCleanup(lower.finalize)
                self.assertEqual(lower.initialize(0x7E0), 0)
                self.assertEqual(calls[0], ("connect", 0x1000C, 0))
                self.assertEqual(lower.send(b"\x22\x01"), 0)
                self.assertEqual(lower.receive().data, b"\x62\x01")
                self.assertEqual(lower.finalize(), 0)
                self.assertEqual(calls[-2:], [("stop_filter", 21), ("disconnect", 42)])
                requests = [call[1][4:] for call in calls if call[0] == "write"]
                self.assertEqual(
                    requests,
                    [
                        b"\x81" if offset == 0x20 else b"\x10\xc0",
                        b"\x22\x01",
                        b"\x82" if offset == 0x20 else b"\x10\x81",
                    ],
                )

    def test_selected_sil_rejects_ordinary_singleton_before_resources(self):
        manager, context, calls = self.fixture()
        adapter = manager.pool.device.provider
        assert isinstance(adapter, UtilityExDriverPrimitives)
        driver = UtilityExDirectDriver(context, adapter, 6)
        with self.assertRaises(UtilityExSourceError):
            UtilityExClassicCANLower(context, driver, 0x1014AEA0)
        self.assertEqual(calls, [])

    def test_ty18_seven_selected_can_objects_use_own_globals_and_raw_sdk(self):
        for address, offset, extended in (
            (0x10118D70, 0, False),
            (0x10118CA0, 0, False),
            (0x10118DB0, 0x100, False),
            (0x10118E40, 0x20, False),
            (0x10118E90, 0xC0, False),
            (0x1011A078, 0, True),
            (0x1011A198, 0, True),
        ):
            with self.subTest(address=hex(address)):
                start, end = (
                    (b"\xc1\xd0\x8f", b"\xc2")
                    if offset == 0x20
                    else (b"\x50\xc0", b"\xc1\x81")
                )
                header = (0x7E0 - offset if offset else 0x7E8).to_bytes(4, "big")
                responses = [start, b"\x62\x01", end] if offset else [b"\x62\x01"]
                manager, context, calls = self.fixture(
                    [
                        NativeMessage(
                            6, header + (b"\x29" if extended else b"") + reply
                        )
                        for reply in responses
                    ],
                    source=SHA_18_TY,
                    address=0x1011D4F0,
                    constructor_parameter=0xD if offset else 0,
                )
                context.parameters[0xAB] = 0x33
                context.state.update(
                    {"native_global:1011f700": 0x7E0, "native_global:1011f704": 0x29}
                )
                adapter = manager.pool.device.provider
                assert isinstance(adapter, UtilityExDriverPrimitives)
                driver = UtilityExDirectDriver(context, adapter, 6)
                lower = UtilityExClassicCANLower(context, driver, address)
                self.addCleanup(lower.finalize)
                self.assertEqual(lower.initialize(0x7E0), 0)
                self.assertEqual(lower.send(b"\x22\x01"), 0)
                self.assertEqual(lower.receive().data, b"\x62\x01")
                expected = (
                    bytes.fromhex("000007e0")
                    + (b"\x29" if extended else b"")
                    + b"\x22\x01"
                )
                self.assertEqual(calls[-1], ("write", expected))
                self.assertEqual(lower.finalize(), 0)
                self.assertEqual(calls[-1], ("disconnect", 42))

    def test_selected_classic_uses_direct_singleton_raw_sdk_and_literal_filters(self):
        lower, context, calls = self.classic_fixture([b"\x62\x01", b"\x7f\x22\x78"])
        context.parameters[0xAB] = 0x29
        self.assertEqual(lower.initialize(0x7E0), 0)
        self.assertEqual(calls[0], ("connect", 6, 0))
        self.assertEqual(
            calls[3],
            (
                "filter",
                3,
                bytes.fromhex("ffffffffff"),
                bytes.fromhex("000007e829"),
                bytes.fromhex("000007e029"),
            ),
        )
        self.assertEqual(lower.send(b"\x22\x01"), 0)
        self.assertEqual(lower.receive().data, b"\x62\x01")
        self.assertEqual(lower.receive().status, 5)
        self.assertEqual(lower.timeout_ms, 5000)
        self.assertEqual(lower.finalize(), 0)
        self.assertEqual(
            calls[-3:], [("stop_filter", 21), ("stop_filter", 22), ("disconnect", 42)]
        )

    def test_selected_p5_timeout_and_noop_interrupt_are_source_specific(self):
        lower, _, calls = self.classic_fixture([b"\x7f\x22\x78"], p5=True)
        self.assertEqual(lower.initialize(0x7E0, override=True), 0)
        self.assertEqual(lower.send(b"\x22"), 0)
        self.assertEqual(lower.receive().status, 5)
        self.assertEqual(lower.timeout_ms, 5530)
        previous = len(calls)
        self.assertEqual(lower.interrupt(100), 0)
        self.assertEqual(len(calls), previous)

    def test_classic_config_native_failure_removes_only_parameter2a_then_retries(self):
        lower, context, calls = self.classic_fixture()
        context.data[500] = b"".join(
            value.to_bytes(4, "little") for value in (1, 500000, 0x2A, 7, 0x23, 33)
        )
        original = lower.driver.adapter.binding.slots[0x2C]
        attempts = 0

        def ioctl(channel, kind, payload, output):
            nonlocal attempts
            attempts += 1
            assert original is not None
            original(channel, kind, payload, output)
            return PrimitiveResult(9 if attempts == 1 else 0)

        lower.driver.adapter.binding.slots[0x2C] = ioctl
        self.assertEqual(lower.initialize(0x7E0), 0)
        self.assertEqual(calls[1], ("ioctl", 2, ((1, 500000), (0x2A, 7), (0x23, 33))))
        self.assertEqual(calls[2], ("ioctl", 2, ((1, 500000), (0x23, 33))))
        self.assertEqual(attempts, 2)

    def test_classic_native_filter_failure_is_ignored_but_channel_still_released(self):
        lower, _, calls = self.classic_fixture()
        lower.driver.adapter.binding.slots[0x44] = lambda *args: PrimitiveResult(9)
        self.assertEqual(lower.initialize(0x7E0), 0)
        self.assertEqual(lower.finalize(), 0)
        self.assertIn(("disconnect", 42), calls)
        self.assertFalse(lower.attached)

    def test_selected_classic_profile_presets_and_optional_parameters(self):
        lower, context, calls = self.classic_fixture()
        context.parameters.update({0xD3: 44, 0xDD: 66})
        lower.profile = 0xDC
        self.assertEqual(lower.initialize(0x7E0, reuse=True), 0)
        self.assertEqual(
            calls[1][2],
            (
                (1, 500000),
                (0x10103, 0x300000),
                (0x10106, 0x3FC),
                (0x2A, 3),
                (0x1010A, 0),
            ),
        )
        self.assertEqual(calls[2], ("ioctl", 2, ((0x23, 44),)))
        self.assertFalse(any(c[0] == "ioctl" and c[2] == ((0x2A, 66),) for c in calls))

    def test_selected_classic_disconnect_failure_retains_owner_for_retry(self):
        lower, _, calls = self.classic_fixture()
        self.assertEqual(lower.initialize(0x7E0), 0)
        statuses = iter((9, 0))

        def disconnect(channel):
            calls.append(("disconnect", channel))
            return PrimitiveResult(next(statuses))

        lower.driver.adapter.binding.slots[0x28] = disconnect
        self.assertEqual(lower.finalize(), 99)
        self.assertTrue(lower.attached)
        self.assertEqual(lower.driver.handle, 42)
        self.assertEqual(lower.finalize(), 0)
        self.assertFalse(lower.attached)
        self.assertIsNone(lower.driver.handle)

    def test_selected_classic_sdk_foreign_fault_retains_then_cleans_handle(self):
        def fault():
            raise RuntimeError("classic configure fault")

        lower, _, calls = self.classic_fixture(fault=fault)
        with self.assertRaisesRegex(RuntimeError, "classic configure fault"):
            lower.initialize(0x7E0)
        self.assertIn(("disconnect", 42), calls)
        self.assertFalse(lower.attached)

    def test_ty18_fixed_actual_raw_sdk_session_and_cleanup(self):
        manager, context, calls = self.fixture(
            [b"\x50\x01", b"\x50\x03", b"\x62\x01", b"\x50\x01"],
            source=SHA_18_TY,
            address=0x1011D4F0,
        )
        self.assertEqual(manager.initialize(), 0)
        self.assertEqual(manager.session(3, normal_first=True), 0)
        self.assertEqual(manager.exchange(b"\x22\x01"), (0, b"\x62\x01"))
        context.cancelled = True
        self.assertEqual(manager.cleanup_session(1, 1, stop_on_error=True), 0)
        self.assertEqual(manager.fields.current_session, 1)
        self.assertEqual(manager.finalize(), 0)
        self.assertEqual(calls[-1], ("disconnect", 42))

    def test_literal_raw_initialize_exchange_and_release(self):
        manager, _, calls = self.fixture([b"\x62\x01"])
        self.assertEqual(manager.initialize(), 0)
        self.assertEqual(manager.exchange(b"\x22\x01"), (0, b"\x62\x01"))
        self.assertEqual(manager.finalize(), 0)
        self.assertEqual(
            [c[0] for c in calls],
            [
                "connect",
                "ioctl",
                "filter",
                "filter",
                "write",
                "stop_filter",
                "stop_filter",
                "disconnect",
            ],
        )
        self.assertEqual(calls[4][1], bytes.fromhex("000007e02201"))
        self.assertEqual(manager.exchange(b"\x22"), (99, b""))

    def test_session_extended_starts_and_normal_stops_on_error(self):
        manager, _, _ = self.fixture([b"\x50\x01", b"\x50\x03", b"\x50\x02"])
        self.assertEqual(manager.initialize(), 0)
        self.assertEqual(manager.session(3, normal_first=True), 0)
        self.assertTrue(manager.worker_active)
        self.assertEqual(manager.fields.current_session, 3)
        self.assertEqual(manager.session(1, stop_on_error=True), 7)
        self.assertFalse(manager.worker_active)
        self.assertEqual(manager.fields.current_session, 3)

    def test_generic_normal_session_error_retains_worker_unconditional_helper_stops(
        self,
    ):
        manager, _, _ = self.fixture([b"\x50\x02", b"\x50\x02"])
        self.assertEqual(manager.initialize(), 0)
        manager.keepalive(True)
        self.assertEqual(manager.session(1, 1), 7)
        self.assertTrue(manager.worker_active)
        self.assertEqual(manager.session(1, 1, stop_on_error=True), 7)
        self.assertFalse(manager.worker_active)

    def test_session_foreign_fault_stops_worker_and_preserves_fault(self):
        error = RuntimeError("foreign SDK fault")
        manager, _, _ = self.fixture([error])
        self.assertEqual(manager.initialize(), 0)
        manager.keepalive(True)
        with self.assertRaisesRegex(RuntimeError, "foreign SDK fault"):
            manager.session(1, stop_on_error=True)
        self.assertFalse(manager.worker_active)

    def test_pending_cancel_and_malformed_echo(self):
        manager, _, _ = self.fixture([b"\x7f\x22\x78", b"\x50"])
        self.assertEqual(manager.initialize(), 0)
        manager.fields.receive_ms = 0
        manager.fields.receive_count = 1
        self.assertEqual(manager.exchange(b"\x22")[0], 5)
        self.assertEqual(manager.session(1, 0), 3)

    def test_all8_worker_uses_separate_alternate_limits(self):
        for source, address in _FIXED_OBJECTS.items():
            for replies, expected in (
                ([b"\x7f\x3e\x21"], 28),
                ([9], 2),
                ([b"\x7f\x3e\x78", b"\x7e\x00"], 5),
            ):
                with self.subTest(source=source[:12], status=expected):
                    manager, context, calls = self.fixture(
                        replies, source=source, address=address
                    )
                    self.assertEqual(manager.initialize(), 0)
                    manager.fields.retry_count = 10
                    manager.fields.busy_count = 255
                    manager.fields.receive_count = 150
                    if expected == 2:
                        adapter = manager.pool.device.provider
                        assert isinstance(adapter, UtilityExDriverPrimitives)
                        binding = adapter.binding
                        read = binding.slots[binding.slot_offset("PassThruReadMsgs")]
                        assert read is not None

                        def elapsed_read(*args, read=read, context=context):
                            result = read(*args)
                            context.tick += 60000
                            return result

                        binding.slots[binding.slot_offset("PassThruReadMsgs")] = (
                            elapsed_read
                        )
                    manager.worker_active = True
                    manager._stop.clear()
                    context.tick = 2001
                    self.assertTrue(manager.worker_step())
                    self.assertEqual(manager.worker_status, expected)
                    self.assertEqual(sum(call[0] == "write" for call in calls), 1)
                    self.assertEqual(manager.fields.suppress_error, 0)
                    manager.finalize()

    def test_alternate_preserves_error_on_positive_and_pending_error_returns7(self):
        for replies, expected, native in (
            ([b"\x7e\x00"], 0, 108),
            ([b"\x7f\x3e\x78", b"\x7f\x3e\x10"], 7, 998),
        ):
            manager, context, _calls = self.fixture(replies)
            self.assertEqual(manager.initialize(), 0)
            manager.fields.native_error = 108
            manager.alternate_fields.pending_limit = 2
            manager.worker_active = True
            manager._stop.clear()
            context.tick = 2001
            self.assertTrue(manager.worker_step())
            self.assertEqual(manager.worker_status, expected)
            self.assertEqual(manager.fields.native_error, native)
            self.assertEqual(manager.fields.suppress_error, 0)
            manager.finalize()

    def test_worker_strict_dual_clock_response_size_and_stop(self):
        manager, context, calls = self.fixture([b"\x7e\x00\x00"])
        self.assertEqual(manager.initialize(), 0)
        manager.keepalive(True)
        context.tick = 2000
        self.assertFalse(manager.worker_step())
        context.tick = 2001
        self.assertTrue(manager.worker_step())
        self.assertEqual(manager.worker_status, 3)
        self.assertEqual(calls[-1], ("write", bytes.fromhex("000007e03e00")))
        manager.keepalive(False)
        context.tick = 9000
        self.assertFalse(manager.worker_step())

    def test_real_background_worker_runs_and_joins_before_cleanup(self):
        manager, context, calls = self.fixture([b"\x7e\x00"])
        self.assertEqual(manager.initialize(), 0)
        complete = threading.Event()
        original = manager.worker_step

        def step():
            result = original()
            if result:
                complete.set()
            return result

        manager.worker_step = step
        manager.keepalive(True)
        context.tick = 2001
        self.assertTrue(complete.wait(1))
        self.assertIn(120, context.native_sleeps)
        self.assertEqual(manager.worker_status, 0)
        self.assertEqual(manager.finalize(), 0)
        self.assertIsNone(manager._thread)
        self.assertEqual(calls[-1], ("disconnect", 42))

    def test_real_background_worker_paces_virtual_native_sleep(self):
        manager, context, _calls = self.fixture()
        self.assertEqual(manager.initialize(), 0)
        steps = []

        def step():
            steps.append(time.monotonic())
            return False

        manager.worker_step = step
        manager.keepalive(True)
        time.sleep(0.30)
        manager.keepalive(False)
        self.assertGreaterEqual(len(steps), 1)
        self.assertLessEqual(len(steps), 4)
        self.assertGreaterEqual(len(context.native_sleeps), len(steps))
        self.assertEqual(manager.finalize(), 0)

    def test_background_native_sleep_fault_remains_observable_on_restart(self):
        manager, context, calls = self.fixture()
        self.assertEqual(manager.initialize(), 0)
        reached = threading.Event()
        error = RuntimeError("individual native Sleep fault")

        def fail_sleep(milliseconds):
            self.assertEqual(milliseconds, 120)
            reached.set()
            raise error

        context.native_sleep = fail_sleep
        manager.keepalive(True)
        self.assertTrue(reached.wait(1))
        manager.keepalive(False)
        self.assertIs(manager.worker_error, error)
        with self.assertRaises(RuntimeError) as caught:
            manager.keepalive(True)
        self.assertIs(caught.exception, error)
        self.assertEqual(manager.finalize(), 0)
        self.assertEqual(calls[-1], ("disconnect", 42))

    def test_worker_foreign_fault_is_observable_and_cleanup_still_runs(self):
        manager, context, calls = self.fixture([RuntimeError("worker SDK fault")])
        self.assertEqual(manager.initialize(), 0)
        manager.worker_active = True
        manager._stop.clear()
        context.tick = 2001
        with self.assertRaisesRegex(RuntimeError, "worker SDK fault"):
            manager.worker_step()
        self.assertEqual(manager.finalize(), 0)
        self.assertIn(("disconnect", 42), calls)

    def test_explicit_wire_cleanup_ignores_cancel_only_within_bounded_scope(self):
        manager, context, calls = self.fixture([b"\x71\x02"])
        self.assertEqual(manager.initialize(), 0)
        context.cancelled = True
        self.assertEqual(manager.cleanup_exchange(b"\x31\x02"), (0, b"\x71\x02"))
        self.assertTrue(context.cancelled)
        self.assertEqual(calls[-1], ("write", bytes.fromhex("000007e03102")))
        with self.assertRaises(InterruptedError):
            manager.exchange(b"\x22")
        self.assertEqual(manager.finalize(), 0)

    def test_cleanup_session_preserves_state_and_stops_worker_after_cancellation(self):
        manager, context, _ = self.fixture([b"\x50\x01"])
        self.assertEqual(manager.initialize(), 0)
        manager.fields.current_session = 3
        manager.keepalive(True)
        context.cancelled = True
        self.assertEqual(manager.cleanup_session(1, 1, stop_on_error=True), 0)
        self.assertEqual(manager.fields.current_session, 1)
        self.assertFalse(manager.worker_active)
        self.assertTrue(context.cancelled)
        self.assertEqual(manager.finalize(), 0)

    def test_selected_wire_cleanup_restores_scope_after_foreign_sdk_fault(self):
        lower, context, _ = self.classic_fixture([RuntimeError("release SDK fault")])
        self.assertEqual(lower.initialize(0x7E0), 0)
        context.cancelled = True
        with (
            self.assertRaisesRegex(RuntimeError, "release SDK fault"),
            utility_ex_cleanup_scope(lower),
        ):
            self.assertEqual(lower.send(b"\x31\x02"), 0)
            lower.receive()
        with self.assertRaises(InterruptedError):
            lower.send(b"\x22")
        self.assertTrue(context.cancelled)
        self.assertEqual(lower.finalize(), 0)

    def test_cancelled_host_still_releases_filter_and_physical_resources(self):
        manager, context, calls = self.fixture()
        self.assertEqual(manager.initialize(), 0)
        context.cancelled = True
        with self.assertRaises(InterruptedError):
            manager.exchange(b"\x22")
        self.assertEqual(manager.finalize(), 0)
        self.assertEqual(
            calls[-3:], [("stop_filter", 21), ("stop_filter", 22), ("disconnect", 42)]
        )

    def test_initialize_foreign_failure_releases_owned_handle(self):
        def fault():
            raise RuntimeError("host check failed")

        manager, _, calls = self.fixture(fault=fault)
        with self.assertRaisesRegex(RuntimeError, "host check failed"):
            manager.initialize()
        self.assertIn(("disconnect", 42), calls)
        self.assertIsNone(manager.lower)

    def test_worker_recovery_reselects_child_and_preserves_outer_state(self):
        manager, context, calls = self.fixture()
        self.assertEqual(manager.initialize(), 0)
        previous = manager.lower
        assert previous is not None
        previous.last_receive_tick = 345
        manager.fields.current_session = 3
        manager.alternate_fields.pending_limit = 11
        context.parameters[0x70] = 0x22
        self.assertEqual(manager._reopen(0x700), 0)
        self.assertIsNot(manager.lower, previous)
        assert manager.lower is not None
        self.assertEqual(manager.lower.kind, 0x11)
        self.assertEqual(manager.lower.address, 0x700)
        self.assertEqual(manager.lower.last_receive_tick, 345)
        self.assertEqual(manager.fields.current_session, 3)
        self.assertEqual(manager.alternate_fields.pending_limit, 11)
        self.assertEqual(sum(c[0] == "connect" for c in calls), 2)

    def test_defaults_preserve_retry_and_pending_and_reopen_tick(self):
        manager, _, calls = self.fixture()
        manager.fields.retry_count = 9
        manager.fields.response_pending_count = 7
        self.assertEqual(manager.initialize(), 0)
        assert manager.lower is not None
        manager.lower.last_receive_tick = 123
        self.assertEqual(manager.initialize(1), 0)
        assert manager.lower is not None
        self.assertEqual(manager.lower.last_receive_tick, 123)
        self.assertEqual(manager.fields.retry_count, 9)
        self.assertEqual(manager.fields.response_pending_count, 7)
        self.assertEqual(sum(c[0] == "connect" for c in calls), 2)

    def test_reinitialize_retains_active_worker_and_source_preserved_retry_fields(self):
        manager, _, _ = self.fixture()
        self.assertEqual(manager.initialize(), 0)
        manager.keepalive(True)
        thread = manager._thread
        manager.fields.suppress_error = 1
        manager.fields.native_error = 108
        self.assertEqual(manager.initialize(1), 0)
        self.assertIs(manager._thread, thread)
        self.assertTrue(manager.worker_active)
        self.assertEqual(manager.fields.suppress_error, 0)
        self.assertEqual(manager.fields.native_error, 0)

    def test_invalid_controls_and_source_fail_before_resources(self):
        manager, context, calls = self.fixture()
        with self.assertRaises(ValueError):
            manager.initialize(True)
        with self.assertRaises(ValueError):
            manager.configure_keepalive(1, bytes(0x1021), 2, 0)
        with self.assertRaises(TypeError):
            manager.keepalive(1)  # type: ignore[arg-type]
        context.module_sha256 = SHA_18_TY
        with self.assertRaises(UtilityExSourceError):
            UtilityExFixedLifecycle(context, manager.pool, manager.fields, 0x1014F5E0)
        self.assertEqual(calls, [])

    def test_gateway_vtable_cannot_alias_ordinary_can(self):
        manager, _context, calls = self.fixture()
        manager.fields.diagnostic_enabled = 3
        with self.assertRaisesRegex(UtilityExSourceError, "broadcast child"):
            manager.initialize()
        self.assertEqual(calls, [])

    def test_diagnostic_mode_selection_preserves_native_chronology(self):
        manager, _context, calls = self.fixture()
        self.assertEqual(manager.select_diagnostic_mode(0x102), 0)
        self.assertEqual(manager.fields.diagnostic_enabled, 2)
        self.assertEqual(manager.select_diagnostic_mode(3), 0)
        self.assertEqual(manager.fields.diagnostic_enabled, 3)
        self.assertEqual(manager.select_diagnostic_mode(2), 0)
        self.assertIsNone(manager.broadcast_lower)
        self.assertEqual(calls, [])
        self.assertEqual(manager.initialize(), 0)
        self.assertEqual(manager.select_diagnostic_mode(2), 0)
        self.assertEqual(manager.select_diagnostic_mode(1), 13)

    def test_broadcast_pending_child_functional_request_and_physical_reply(self):
        manager, _context, calls = self.fixture([b"\x62\x01"])
        manager.fields.alternate_address = 0x7E0
        manager.fields.alternate_extension = 0x7DF
        manager.fields.target_configured = True
        self.assertEqual(manager.select_diagnostic_mode(3), 0)
        child = manager.broadcast_lower
        self.assertIsNotNone(child)
        self.assertIsNone(manager.lower)
        self.assertEqual(calls, [])
        self.assertEqual(manager.initialize(), 0)
        self.assertIs(manager.lower, child)
        self.assertEqual(manager.exchange(b"\x22\x01"), (0, b"\x62\x01"))
        self.assertEqual(calls[-1], ("write", bytes.fromhex("000007df2201")))
        self.assertEqual(manager.finalize(), 0)
        self.assertIs(manager.broadcast_lower, child)
        self.assertEqual(manager.select_diagnostic_mode(1), 0)
        self.assertIsNone(manager.broadcast_lower)

    def test_fixed_reinitialize_uses_staged_child_parameters_and_live_override_flag(
        self,
    ):
        manager, context, calls = self.fixture()
        self.assertEqual(manager.initialize(), 0)
        manager.fields.parameters = ((1, 250000),)
        self.assertEqual(manager.initialize(), 0)
        configurations = [call[2] for call in calls if call[:2] == ("ioctl", 2)]
        self.assertEqual(configurations[-1], ((1, 500000),))
        context.data[500] = (1).to_bytes(4, "little") + (125000).to_bytes(4, "little")
        manager.fields.parameters = ()
        self.assertEqual(manager.initialize(), 0)
        configurations = [call[2] for call in calls if call[:2] == ("ioctl", 2)]
        self.assertEqual(configurations[-1], ((1, 125000),))

    def test_finalize_preserves_native_busy_budget_but_initialize_resets_it(self):
        manager, _context, _calls = self.fixture()
        self.assertEqual(manager.initialize(), 0)
        manager.fields.busy_ms = 1234
        self.assertEqual(manager.finalize(), 0)
        self.assertEqual(manager.fields.busy_ms, 1234)
        self.assertEqual(manager.initialize(), 0)
        self.assertEqual(manager.fields.busy_ms, 0)

    def test_broadcast_first_attach_uses_native_override_then_existing_child_broker(
        self,
    ):
        manager, context, calls = self.fixture()
        manager.fields.parameters = ()
        context.data[500] = (1).to_bytes(4, "little") + (250000).to_bytes(4, "little")
        self.assertEqual(manager.select_diagnostic_mode(3), 0)
        self.assertEqual(manager.initialize(), 0)
        configurations = [
            call[2]
            for call in calls
            if call[:2] == ("ioctl", 2) and any(key == 1 for key, _value in call[2])
        ]
        self.assertIn((1, 500000), configurations[-1])
        self.assertEqual(manager.initialize(), 0)
        configurations = [
            call[2]
            for call in calls
            if call[:2] == ("ioctl", 2) and any(key == 1 for key, _value in call[2])
        ]
        self.assertEqual(configurations[-1], ((1, 250000),))

    def test_selected_cmn_worker_validates_echo_and_cleans_actual_selected_sdk(self):
        _manager, context, calls = self.fixture([b"\x61\x01"])
        comm = self.selected_facade(context)
        self.assertEqual(comm.initialize(), 0)
        worker = UtilityExSelectedCMNWorker(context, comm)
        self.assertEqual(worker.run(2000, stop_on_error=True, finalize_on_exit=True), 3)
        self.assertEqual(context.tick, 2000)
        self.assertEqual(context.state["native_global:101528b4"], 3)
        self.assertEqual(context.state["native_global:1014af28"], 3)
        self.assertEqual(calls[-1], ("disconnect", 42))
        self.assertIn(("write", bytes.fromhex("000007e02100")), calls)

    def test_four_nk_cmn_pre_cancel_uses_exact_result_globals_and_no_wire(self):
        from scripts.utility_ex_comm import _classic_fields

        for source, result in (
            (SHA_12_NK, 0x100E6270),
            (SHA_18_NK, 0x1014AF28),
            (SHA_DS4_NK, 0x101B1F88),
            (SHA_PLUS_NK, 0x101BD088),
        ):
            with self.subTest(source=source[:12]):
                context = Context()
                context.module_sha256 = source
                context.cancelled = True
                comm = self.selected_facade(context)
                fields = _classic_fields(context)
                fields.busy_limit, fields.no_response_limit = 7, 8
                worker = UtilityExSelectedCMNWorker(context, comm)
                self.assertEqual(worker.run(2000), 0)
                self.assertEqual(context.state[f"native_global:{result:x}"], 0)
                self.assertEqual(
                    (fields.busy_limit, fields.no_response_limit), (100, 3)
                )
                self.assertEqual(context.tick, 0)

    def test_selected_timer_callback_success_then_native_failure_kills_and_closes(self):
        _manager, context, calls = self.fixture([b"\x61\x00", b"\x7f\x21\x33"])
        comm = self.selected_facade(context)
        self.assertEqual(comm.initialize(), 0)
        timer = UtilityExSelectedTimerKeepalive(context, comm)
        timer.configure(2000, b"\x21\x00", 2, 0xF0, 1)
        timer.start()
        self.assertEqual(context.timer_calls, [("kill", 0, 0), ("set", 0, 0, 2000)])
        callback = context.timers[55]
        self.assertIs(callback.__self__, timer)
        callback(0, 0x113, 55, 2000)
        self.assertEqual(timer.native_status, 15)
        self.assertEqual(timer.last_exchange_status, 0)
        callback(0, 0x113, 55, 4000)
        self.assertEqual(timer.native_status, 7)
        self.assertEqual(context.timer_calls[-1], ("kill", 0, 55))
        self.assertEqual(calls[-1], ("disconnect", 42))
        self.assertEqual(timer.active, 1)
        self.assertFalse(timer.busy or timer.in_callback)

    def test_selected_timer_recovery_target_does_not_overwrite_selected_global(self):
        _manager, context, _calls = self.fixture([b"\x61\x00"])
        comm = self.selected_facade(context)
        self.assertEqual(comm.initialize(), 0)
        timer = UtilityExSelectedTimerKeepalive(context, comm)
        timer.configure(2000, b"\x21\x00", 3, 0x33, 1)
        timer.start()
        before = comm.read_target()
        context.timers[55](0, 0x113, 55, 2000)
        self.assertEqual(comm.read_target(), before)
        self.assertEqual(timer.last_exchange_status, 3)
        self.assertEqual(timer.native_status, 15)
        timer.stop(1)

    def test_selected_timer_foreign_exception_releases_callback_flags_and_owned_sdk(
        self,
    ):
        failure = OSError("authored SDK read fault")
        _manager, context, calls = self.fixture([failure])
        comm = self.selected_facade(context)
        self.assertEqual(comm.initialize(), 0)
        timer = UtilityExSelectedTimerKeepalive(context, comm)
        timer.configure(2000, b"\x21\x00", 2, 0xF0, 0)
        timer.start()
        with self.assertRaises(OSError) as caught:
            context.timers[55](0, 0x113, 55, 2000)
        self.assertIs(caught.exception, failure)
        self.assertIs(timer.error, failure)
        self.assertFalse(timer.busy or timer.in_callback)
        timer.stop(1)
        self.assertEqual(calls[-1], ("disconnect", 42))

    def test_selected_cmn_custom_skips_echo_validation_then_observes_wait_cancel(self):
        _manager, context, calls = self.fixture([b"\x61\x7f"])
        comm = self.selected_facade(context)
        self.assertEqual(comm.initialize(), 0)
        original_sleep = context.native_sleep

        def sleep(milliseconds):
            original_sleep(milliseconds)
            if context.tick > 2000:
                context.cancelled = True

        context.native_sleep = sleep
        context.state["native_global:101528b4"] = 77
        worker = UtilityExSelectedCMNWorker(context, comm)
        self.assertEqual(
            worker.run(
                2000, b"\x21\x00", skip_response_validation=True, finalize_on_exit=True
            ),
            0,
        )
        self.assertEqual(context.state["native_global:101528b4"], 77)
        self.assertEqual(worker.iterations, 1)
        self.assertTrue(context.cancelled)
        self.assertNotIn(("disconnect", 42), calls)
        comm.finalize()
        self.assertEqual(calls[-1], ("disconnect", 42))

    def test_all_eight_timer_source_globals_configuration_and_os_ownership(self):
        for source, status_address, buffer_address in (
            (SHA_12_NK, 0x100EBA04, 0x100EA9E4),
            (SHA_18_NK, 0x101528B4, 0x10151894),
            (SHA_DS4_NK, 0x101B8B7C, 0x101B8B80),
            (SHA_PLUS_NK, 0x101C80AC, 0x101C80B0),
            (SHA_12_TY, 0x100B0F08, 0x100AFEE8),
            (SHA_18_TY, 0x101207C8, 0x1011F7A8),
            (SHA_DS4_TY, 0x1006F3B4, 0x1006F3B8),
            (SHA_PLUS_TY, 0x1013FAE4, 0x1013FAE8),
        ):
            with self.subTest(source=source[:12]):
                context = Context()
                context.module_sha256 = source
                comm = self.selected_facade(context)
                timer = UtilityExSelectedTimerKeepalive(context, comm)
                timer.timer_callback(0, 0x113, 0, 0)
                timer.configure(2000, b"\x3e\x00", 2, 0x1F0, 1)
                self.assertEqual(
                    context.state[f"native_bytes:{buffer_address:x}"],
                    b"\x3e\x00" + bytes(0x101E),
                )
                timer.start()
                self.assertEqual(context.state[f"native_global:{status_address:x}"], 15)
                context.state[f"native_global:{status_address:x}"] = 77
                self.assertEqual(timer.native_status, 77)
                timer.stop(0)
                self.assertFalse(context.timers)
                self.assertEqual(timer.active, 1)

    def test_timer_busy_stop_keeps_owned_lower_until_retry(self):
        _manager, context, calls = self.fixture()
        comm = self.selected_facade(context)
        self.assertEqual(comm.initialize(), 0)
        timer = UtilityExSelectedTimerKeepalive(context, comm)
        timer.configure(2000, b"\x21\x00", 2, 0xF0, 0)
        timer.start()
        timer.busy = True
        with self.assertRaises(TimeoutError):
            timer.stop(1)
        self.assertEqual(context.tick, 2000)
        self.assertNotIn(("disconnect", 42), calls)
        timer.busy = False
        timer.stop(1)
        self.assertEqual(calls[-1], ("disconnect", 42))

    def test_custom_cmn_live_fields_change_flags_and_interval_but_not_copied_payload(
        self,
    ):
        _manager, context, calls = self.fixture([b"\x61\x7f", b"\x61\x7f"])
        comm = self.selected_facade(context)
        self.assertEqual(comm.initialize(), 0)
        fields = UtilityExSelectedCMNFields(
            2000, b"\x21\x00", 2, skip_response_validation=1
        )
        original_sleep = context.native_sleep

        def sleep(milliseconds):
            original_sleep(milliseconds)
            fields.interval_ms = 1000
            fields.request = b"\x21\xff"
            if context.tick >= 2600:
                fields.skip_response_validation = 0
                fields.stop_on_error = 1
                fields.finalize_on_exit = 1

        context.native_sleep = sleep
        worker = UtilityExSelectedCMNWorker(context, comm)
        self.assertEqual(worker.run(fields), 3)
        self.assertEqual(worker.iterations, 2)
        self.assertEqual(context.tick, 3000)
        self.assertEqual(
            [call[1] for call in calls if call[0] == "write"],
            [bytes.fromhex("000007e02100")] * 2,
        )
        self.assertEqual(calls[-1], ("disconnect", 42))


class SISDriverTest(unittest.TestCase):
    def lower_fixture(self, incoming):
        driver, context, calls, _exports = self.fixture()
        context.state.update(
            {
                f"native_global:{address:x}": value
                for address, value in (
                    (0x1011F730, 0x01020304),
                    (0x1011F734, 1500),
                    (0x1011F738, 2000),
                    (0x1011F73C, 100),
                    (0x1011F75C, 0x22),
                )
            }
        )
        measurements = iter((500, 8000, 12000))

        def ioctl(handle, kind, payload, output):
            calls.append(("ioctl", kind))
            if kind == 3:
                output[:] = next(measurements).to_bytes(4, "little")
            elif kind == 0x8023:
                output[:] = (2).to_bytes(4, "little")
            return PrimitiveResult()

        driver.adapter.binding.slots[0x10A4] = ioctl
        driver.initialize_controller()
        lower = UtilityExSISLower(context, driver)
        self.addCleanup(lower.finalize)
        self.assertEqual(lower.initialize(0x701), 0)
        replies = iter(incoming)

        def read(handle, message, count, timeout):
            calls.append(("stream_read", int.from_bytes(count, "little"), timeout))
            data = next(replies)
            if isinstance(data, BaseException):
                raise data
            if type(data) is int:
                return PrimitiveResult(data)
            message.data[: len(data)] = data
            message.native_14 = len(data)
            return PrimitiveResult()

        driver.adapter.binding.slots[0x10AC] = read
        return lower, context, calls

    @staticmethod
    def packet(response):
        payload = bytes(4) + response
        return [b"\x02\xfd\x80\x01" + len(payload).to_bytes(4, "big"), payload]

    def fixture(self, fault=None, *, source=SHA_18_TY):
        from scripts.utility_ex import _DRIVER_SLOTS, _SIS_DRIVER_SLOTS

        context = Context()
        context.module_sha256 = source
        context.state[
            "native_global:1011f758"
            if source == SHA_18_TY
            else "native_global:1013fa90"
        ] = 0x0E80
        calls = []
        handles = iter((101, 102, 103, 104))

        def initialize(kind, output, *extra):
            if extra != (() if source == SHA_18_TY else (0,)):
                raise AssertionError("Source-specific controller ABI")
            calls.append(("initialize", kind, *extra))
            output[:] = (51).to_bytes(4, "little")
            return PrimitiveResult(7)  # Native f4c0 deliberately ignores status.

        def connect(controller, protocol, flags, oem, kind, count, pins, output):
            calls.append(
                ("connect", controller, protocol, flags, oem, kind, count, pins)
            )
            output[:] = next(handles).to_bytes(4, "little")
            if fault is not None:
                fault(context)
            return PrimitiveResult()

        def logical(parent, protocol, flags, configuration, output):
            calls.append(("logical", parent, protocol, flags, configuration))
            output[:] = next(handles).to_bytes(4, "little")
            return PrimitiveResult()

        def read(handle, message, count, timeout):
            calls.append(("read", handle, int.from_bytes(count, "little"), timeout))
            message.data[:3] = b"abc"
            message.native_14 = 3
            return PrimitiveResult()

        def queue(handle, message, count):
            calls.append(("queue", handle, bytes(message.data[: message.length])))
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
                "PassThruReadMsgs_v0500": read,
                "PassThruQueueMsgs_v0500": queue,
                "PassThruLogicalDisconnect_v0500": lambda handle: (
                    calls.append(("logical_disconnect", handle)),
                    PrimitiveResult(),
                )[1],
                "PassThruDisconnect_v0500": lambda handle: (
                    calls.append(("disconnect", handle)),
                    PrimitiveResult(),
                )[1],
            }
        )
        binding = UtilitySISDriverBinding(cast(UtilityExContext, context), exports)
        return UtilityExSISDriver(context, binding), context, calls, exports

    def test_plus_sis_uses_three_controller_arguments_and_individual_json_ports(self):
        driver, context, calls, _exports = self.fixture(source=SHA_PLUS_TY)
        context.state.update(
            {
                "native_global:1013fa68": 0x01020304,
                "native_global:1013fa6c": 1000,
                "native_global:1013fa70": 2000,
            }
        )
        json_calls = []

        def json_d(kind, section, key):
            json_calls.append((kind, section, key))
            return {"sourcePortNumberUDP": 0xC001, "sourcePortNumberTCP": 0xC002}[key]

        context.json_d_get_data = json_d
        self.assertEqual(driver.initialize_controller(), 0)
        self.assertEqual(calls[0], ("initialize", 2, 0))
        self.assertEqual(driver.connect(0x701, 0, 0, UtilityExSISPins(1, ())), 0)
        self.addCleanup(driver.finalize)
        self.assertEqual(driver.initialize_logical(), 0)
        self.assertEqual(
            json_calls,
            [
                (1, "ethernet", "sourcePortNumberUDP"),
                (1, "ethernet", "sourcePortNumberTCP"),
            ],
        )
        logical = [c for c in calls if c[0] == "logical"]
        self.assertEqual(logical[1][4], b"\x01\xc0")
        self.assertEqual(logical[2][4][:2], b"\x02\xc0")
        self.assertEqual(context.profile_calls, [])

    def test_plus_sis_fallback_compares_original_utf16_with_json_string(self):
        driver, context, _calls, _exports = self.fixture(source=SHA_PLUS_TY)
        context.data[0x100DF360] = "source-vim".encode("utf-16-le") + b"\0\0"
        json_calls = []

        def json_s(kind, section, key):
            json_calls.append((kind, section, key))
            return "source-vim"

        context.json_s_get_data = json_s
        lower = UtilityExSISLower(context, driver)
        self.assertTrue(lower._fallback_valid())
        self.assertEqual(json_calls, [(3, "vim", "name")])
        self.assertEqual(context.profile_calls, [])

    def test_sis_read_maps_hex10_buffer_empty_but_not_decimal10(self):
        driver, _context, _calls, _exports = self.fixture()
        driver.initialize_controller()
        self.assertEqual(driver.connect(0x701, 0, 0, UtilityExSISPins(1, ())), 0)
        self.addCleanup(driver.finalize)
        slot = driver.adapter.binding.slot_offset("PassThruReadMsgs_v0500")
        for status, expected in ((9, 2), (0x10, 2), (10, 3)):
            with self.subTest(status=status):
                driver.adapter.binding.slots[slot] = lambda *args, status=status: (
                    PrimitiveResult(status)
                )
                self.assertEqual(
                    driver.read(
                        0x800F, 1, UtilityExSISMessage(0x800F, bytearray(8), 8), 1000
                    ),
                    expected,
                )

    def test_exact_controller_physical_and_logical_sdk_abi(self):
        driver, context, calls, _exports = self.fixture()
        self.assertEqual(driver.initialize_controller(), 0)
        self.assertEqual(driver.controller, 51)
        self.assertEqual(
            driver.connect(0x701, 0, 0x22, UtilityExSISPins(1, (3, 11, 12, 13))), 0
        )
        self.assertEqual(
            calls[1], ("connect", 51, 0x800F, 0, 0x22, 1, 4, (3, 11, 12, 13))
        )
        self.assertEqual(driver.connect(0x701, 0, 0, UtilityExSISPins(1, ())), 13)
        self.assertEqual(driver.connect(0x702, 0, 0, UtilityExSISPins(1, ())), 14)
        context.state.update(
            {
                f"native_global:{address:x}": value
                for address, value in (
                    (0x1011F730, 0x01020304),
                    (0x1011F734, 1500),
                    (0x1011F738, 2000),
                )
            }
        )
        self.assertEqual(driver.initialize_logical(0, 0), 0)
        message = UtilityExSISMessage(0x8208, bytearray(15), 15)
        message.data[2:4] = b"\x80\x01"
        self.assertEqual(driver.queue(message, tcp=True), 0)
        self.assertEqual(
            calls[-1],
            ("queue", 104, b"\x02\xfd\x80\x01\x00\x00\x00\x07\x0e\x80" + bytes(5)),
        )
        self.assertEqual(driver.read(0x8208, 0x11, message, 5000), 0)
        self.assertEqual(bytes(message.data[: message.native_14]), b"abc")
        self.assertEqual(calls[-1], ("read", 104, 0x11, 5000))
        self.assertEqual(driver.finalize(), 0)
        self.assertEqual(
            calls[-4:],
            [
                ("logical_disconnect", 104),
                ("logical_disconnect", 103),
                ("logical_disconnect", 102),
                ("disconnect", 101),
            ],
        )
        self.assertEqual(driver.phase, 1)

    def test_sis_alternate_ack_timeout_does_not_use_primary_retry(self):
        lower, context, calls = self.lower_fixture([9])
        fields = UtilityExSISFields(retry_count=20)
        scheduler = UtilityExAlternateUDSScheduler(
            context, lower, fields, UtilityExAlternateUDSFields()
        )
        self.assertEqual(scheduler.exchange(b"\x22"), (2, b""))
        self.assertEqual(
            [c for c in calls if c[0] == "stream_read"], [("stream_read", 13, 100)]
        )

    def test_sis_alternate_single_payload_read_preserves_native_error(self):
        response = b"\x62" + bytes(0x101B)
        ack = b"\x02\xfd\x80\x02" + bytes(9)
        lower, context, calls = self.lower_fixture([ack, *self.packet(response)])
        fields = UtilityExSISFields(native_error=108)
        scheduler = UtilityExAlternateUDSScheduler(
            context, lower, fields, UtilityExAlternateUDSFields()
        )
        self.assertEqual(scheduler.exchange(b"\x22"), (0, response))
        self.assertEqual(fields.native_error, 108)
        self.assertEqual(
            [c[1] for c in calls if c[0] == "stream_read"], [13, 8, 0x1020]
        )

    def test_sis_alternate_pending_budget_is_independent_and_clears_flags(self):
        ack = b"\x02\xfd\x80\x02" + bytes(9)
        lower, context, calls = self.lower_fixture([ack, *self.packet(b"\x7f\x22\x78")])
        fields = UtilityExSISFields(receive_count=150)
        alternate = UtilityExAlternateUDSFields()
        scheduler = UtilityExAlternateUDSScheduler(context, lower, fields, alternate)
        self.assertEqual(scheduler.exchange(b"\x22"), (5, b"\x7f\x22\x78"))
        self.assertEqual(fields.pending_count, 1)
        self.assertEqual(fields.suppress_error, 0)
        self.assertEqual(len([c for c in calls if c[0] == "stream_read"]), 3)

    def test_sis_uds_positive_pending_and_exact_multiple_extra_read(self):
        ack = b"\x02\xfd\x80\x02" + bytes(9)
        for response in (b"\x62\x01", b"\x62" + bytes(0x101B)):
            with self.subTest(size=len(response)):
                packets = [ack, *self.packet(b"\x7f\x22\x78"), *self.packet(response)]
                if len(response) + 4 == 0x1020:
                    packets.append(b"")
                lower, context, calls = self.lower_fixture(packets)
                fields = UtilityExSISFields()
                scheduler = UtilityExSISUDSScheduler(context, lower, fields)
                self.assertEqual(scheduler.exchange(b"\x22\x01"), (0, response))
                reads = [call for call in calls if call[0] == "stream_read"]
                self.assertEqual(
                    reads[:3],
                    [
                        ("stream_read", 13, 100),
                        ("stream_read", 8, 5000),
                        ("stream_read", 7, 5000),
                    ],
                )
                self.assertEqual(reads[3][2], 0x26DE)
                self.assertEqual(fields.suppress_error, 0)
                if len(response) + 4 == 0x1020:
                    self.assertEqual(reads[-1], ("stream_read", 0, 0x26DE))

    def test_sis_uds_ack_and_native_nrc_faults_remain_distinct(self):
        for incoming, expected, native in (
            ([b"\x02\xfd\x80\x03" + bytes(9)], 12, 0),
            ([b"\x02\xfd\x80\x02" + bytes(9), *self.packet(b"\x7f\x22\x33")], 7, 108),
            ([b"\x02\xfd\x80\x02" + bytes(9), b"invalid!"], 99, 0),
        ):
            with self.subTest(expected=expected):
                lower, context, _calls = self.lower_fixture(incoming)
                fields = UtilityExSISFields(retry_count=1)
                scheduler = UtilityExSISUDSScheduler(context, lower, fields)
                self.assertEqual(scheduler.exchange(b"\x22\x01")[0], expected)
                self.assertEqual(fields.native_error, native)

    def test_sis_manager_session_worker_and_cancel_safe_session_full_sdk_lifecycle(
        self,
    ):
        driver, context, calls, _exports = self.fixture()
        context.state.update(
            {
                f"native_global:{address:x}": value
                for address, value in (
                    (0x1011F700, 0x701),
                    (0x1011F708, 0x14),
                    (0x1011F70C, 0x14),
                    (0x1011F730, 0x01020304),
                    (0x1011F734, 1500),
                    (0x1011F738, 2000),
                    (0x1011F73C, 100),
                    (0x1011F740, 5000),
                    (0x1011F748, 0x26DE),
                    (0x1011F75C, 0x22),
                )
            }
        )
        measurements = iter((500, 8000, 12000))
        ack = b"\x02\xfd\x80\x02" + bytes(9)
        responses = [bytes(1), bytes(14), bytes(17)]
        for response in (
            b"\x50\x01",
            b"\x50\x03",
            b"\x62\x01",
            b"\x7e\x00",
            b"\x50\x01",
        ):
            responses.extend([ack, *self.packet(response)])
        incoming = iter(responses)

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

        driver.adapter.binding.slots[0x10A4] = ioctl
        driver.adapter.binding.slots[0x10AC] = read
        driver.initialize_controller()
        fields = UtilityExSISFields(retry_count=7)
        manager = UtilityExSISLifecycle(context, driver, fields, 0x1011E618)
        self.addCleanup(manager.finalize)
        self.assertEqual(manager.initialize(), 0)
        self.assertEqual(manager.session(3, normal_first=True), 0)
        self.assertTrue(manager.worker_active)
        self.assertEqual(manager.exchange(b"\x22\x01"), (0, b"\x62\x01"))
        context.tick = 2001
        self.assertTrue(manager.worker_step())
        self.assertEqual(manager._worker_exit_status, 0)
        context.cancelled = True
        self.assertEqual(manager.cleanup_session(1, 1, stop_on_error=True), 0)
        self.assertEqual(fields.current_session, 1)
        self.assertFalse(manager.worker_active)
        self.assertEqual(fields.retry_count, 7)
        child = manager.lower
        self.assertEqual(manager.finalize(), 0)
        self.assertIs(manager.lower, child)
        self.assertEqual(fields.current_session, 0)
        self.assertEqual(
            calls[-4:],
            [
                ("logical_disconnect", 104),
                ("logical_disconnect", 103),
                ("logical_disconnect", 102),
                ("disconnect", 101),
            ],
        )

    def test_cancel_after_connect_keeps_handle_and_cleanup_releases_it(self):
        driver, context, calls, _exports = self.fixture(
            lambda context: setattr(context, "cancelled", True)
        )
        driver.initialize_controller()
        with self.assertRaises(InterruptedError):
            driver.connect(0x701, 0, 0, UtilityExSISPins(1, (3, 11, 12, 13)))
        self.assertEqual(driver.physical, 101)
        self.assertEqual(driver.finalize(), 0)
        self.assertEqual(calls[-1], ("disconnect", 101))
        self.assertTrue(context.cancelled)

    def test_failed_logical_disconnect_retains_owner_for_retry(self):
        driver, _context, calls, exports = self.fixture()
        driver.initialize_controller()
        driver.connect(0x701, 0, 0, UtilityExSISPins(1, ()))
        driver.logical_connect(0x8203, b"config")
        binding = driver.adapter.binding
        binding.slots[0x10D4] = lambda handle: PrimitiveResult(7)
        self.assertEqual(driver.finalize(), 3)
        self.assertEqual(driver.logical, {0x8203: 102})
        self.assertEqual(driver.physical, 101)
        binding.slots[0x10D4] = exports["PassThruLogicalDisconnect_v0500"]
        self.assertEqual(driver.finalize(), 0)
        self.assertEqual(calls[-1], ("disconnect", 101))

    def test_sis_lower_measured_init_then_actual_doip_request_and_read(self):
        driver, context, calls, _exports = self.fixture()
        context.state.update(
            {
                f"native_global:{address:x}": value
                for address, value in (
                    (0x1011F730, 0x01020304),
                    (0x1011F734, 1500),
                    (0x1011F738, 2000),
                    (0x1011F758, 0x0E80),
                    (0x1011F75C, 0x22),
                )
            }
        )
        measurements = iter((500, 8000, 12000))

        def ioctl(handle, kind, payload, output):
            calls.append(("ioctl", handle, kind, payload))
            if kind == 3:
                self.assertIsInstance(payload, UtilityExSISPins)
                output[:] = next(measurements).to_bytes(4, "little")
            elif kind == 0x8023:
                output[:] = (2).to_bytes(4, "little")
            return PrimitiveResult()

        driver.adapter.binding.slots[0x10A4] = ioctl
        driver.initialize_controller()
        lower = UtilityExSISLower(context, driver)
        self.addCleanup(lower.finalize)
        self.assertEqual(lower.initialize(0x0701), 0)
        self.assertEqual(
            context.profile_calls,
            [
                (
                    "int",
                    b"Ethernet",
                    b"SourcePortNumberUDP",
                    0,
                    b".\\EtherTimeParam.ini",
                ),
                (
                    "int",
                    b"Ethernet",
                    b"SourcePortNumberTCP",
                    0,
                    b".\\EtherTimeParam.ini",
                ),
            ],
        )
        self.assertEqual(lower.send(b"\x22\x01"), 0)
        self.assertEqual(
            calls[-1], ("queue", 104, bytes.fromhex("02fd8001000000060e8007012201"))
        )
        self.assertEqual(lower.receive_bytes(3), (0, b"abc"))
        self.assertEqual(lower.receive_bytes(2), (3, b""))
        context.cancelled = True
        with self.assertRaises(InterruptedError):
            lower.send(b"\x10\x01")
        with utility_ex_cleanup_scope(lower):
            self.assertEqual(lower.send(b"\x10\x01"), 0)
        self.assertTrue(context.cancelled)
        self.assertEqual(lower.finalize(), 0)

    def test_sis_credential_fallback_keeps_raw_fault_and_uses_individual_ini(self):
        for accepted in (True, False):
            with self.subTest(accepted=accepted):
                driver, context, calls, _exports = self.fixture()
                context.data.update(
                    {
                        0x100F81C0: b"AuthSection\x00",
                        0x100F81CC: b"AuthKey\x00",
                        0x100F81D4: b"auth.ini\x00",
                        0x100F81AC: b"0123456789abcdef\x00",
                    }
                )
                context.profile_value = b"0123456789abcdef" if accepted else b"rejected"

                def ioctl(handle, kind, payload, output, calls=calls):
                    calls.append(("ioctl", kind))
                    if kind == 3:
                        output[:] = (500).to_bytes(4, "little")
                    if kind == 0x8022 and int.from_bytes(payload, "little") == 0x125C:
                        return PrimitiveResult(9)
                    return PrimitiveResult()

                driver.adapter.binding.slots[0x10A4] = ioctl
                driver.initialize_controller()
                lower = UtilityExSISLower(context, driver)
                self.addCleanup(lower.finalize)
                self.assertEqual(lower.initialize(0x701), 0 if accepted else 2)
                self.assertEqual(
                    context.profile_calls[0],
                    ("string", b"AuthSection", b"AuthKey", b"", 17, b"auth.ini"),
                )
                self.assertEqual(driver.physical is not None, accepted)

    def test_cancel_after_logical_connect_retains_and_releases_both_handles(self):
        driver, context, calls, _exports = self.fixture()
        driver.initialize_controller()
        driver.connect(0x701, 0, 0, UtilityExSISPins(1, ()))

        def logical(parent, protocol, flags, configuration, output):
            output[:] = (201).to_bytes(4, "little")
            context.cancelled = True
            return PrimitiveResult()

        driver.adapter.binding.slots[0x10D0] = logical
        with self.assertRaises(InterruptedError):
            driver.logical_connect(0x8203, bytes(21))
        self.assertEqual(driver.logical, {0x8203: 201})
        self.assertEqual(driver.finalize(), 0)
        self.assertEqual(calls[-2:], [("logical_disconnect", 201), ("disconnect", 101)])


class LifecycleHardeningTests(unittest.TestCase):
    def test_p5_start_failure_leaves_no_unstarted_owner(self):
        from unittest import mock

        worker = object.__new__(UtilityExSelectedP5Worker)
        worker._thread = None
        worker._stop = threading.Event()
        worker.error = None
        worker.active = False
        worker.status = 0

        class FailingThread:
            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                raise RuntimeError("authored Thread.start failure")

        with (
            mock.patch("scripts.utility_ex_lifecycle.threading.Thread", FailingThread),
            self.assertRaises(RuntimeError),
        ):
            worker.start()
        self.assertFalse(worker.active)
        self.assertIsNone(worker._thread)
        # Retry/finalization must not join an unstarted thread.
        worker.stop()

    def test_cmn_cancel_preserves_newer_shared_timer_status(self):
        class Communication:
            def exchange(self, request):
                raise AssertionError("Cancelled CMN must not reach the wire")

            def configure(self, field, value):
                pass

            def finalize(self):
                pass

        context = Context()
        worker = object.__new__(UtilityExSelectedCMNWorker)
        worker.context = context
        worker.communication = cast(UtilityExComm, Communication())
        worker.native_status = 0x101528B4
        worker.native_result = 0x1014AF28
        worker.busy_setter = 0x17320
        worker.no_response_setter = 0x172F0
        worker.status = 0
        worker.error = None
        worker.iterations = 0
        status_key = f"native_global:{worker.native_status:x}"
        context.state[status_key] = 0
        original_sleep = context.native_sleep

        def sleep(milliseconds):
            original_sleep(milliseconds)
            if context.tick >= 2000:
                # The timer callback publishes a newer shared status while the
                # cancelled CMN worker still holds its entry snapshot.
                context.state[status_key] = 15
                context.cancelled = True

        context.native_sleep = sleep
        self.assertEqual(worker.run(2000), 0)
        self.assertEqual(context.state[status_key], 15)
        self.assertEqual(context.state[f"native_global:{worker.native_result:x}"], 0)


class ResumedLifecycleRegressionTests(unittest.TestCase):
    def test_cmn_cancel_does_not_republish_status_snapshot(self):
        for source in (SHA_12_NK, SHA_18_NK, SHA_DS4_NK, SHA_PLUS_NK):
            for custom in (False, True):
                with self.subTest(source=source[:12], custom=custom):
                    fixture = LifecycleTest()
                    _manager, context, _calls = fixture.fixture(
                        [b"\x61\x00"], source=source, address=_FIXED_OBJECTS[source]
                    )
                    comm = fixture.selected_facade(context)
                    self.assertEqual(comm.initialize(), 0)
                    timer = UtilityExSelectedTimerKeepalive(context, comm)
                    status_key = f"native_global:{timer.layout['status']:x}"
                    timer.native_status = 77

                    class InterleavedState(dict):
                        def __init__(self, values, key, owner):
                            super().__init__(values)
                            self.key = key
                            self.owner = owner
                            self.publication_writes = []
                            self.status_reads = 0

                        def get(self, key, default=None):
                            value = super().get(key, default)
                            if key == self.key:
                                self.status_reads += 1
                                if self.status_reads == 2:
                                    # The old exit read races with this real timer
                                    # publication and then writes its stale value.
                                    self.owner.native_status = 88
                            return value

                        def __setitem__(self, key, value):
                            if key == self.key:
                                self.publication_writes.append(value)
                            super().__setitem__(key, value)

                    state = InterleavedState(context.state, status_key, timer)
                    context.state = state
                    exchange = comm.exchange

                    def exchange_then_cancel(
                        request, exchange=exchange, context=context
                    ):
                        result = exchange(request)
                        context.cancelled = True
                        return result

                    comm.exchange = exchange_then_cancel
                    worker = UtilityExSelectedCMNWorker(context, comm)
                    if custom:
                        result = worker.run(
                            UtilityExSelectedCMNFields(0, b"\x21\x00", 2)
                        )
                    else:
                        result = worker.run(0)
                    if dict.get(state, status_key) != 88:
                        timer.native_status = 88
                    self.assertEqual(result, 0)
                    self.assertEqual(dict.get(state, status_key), 88)
                    self.assertEqual(state.publication_writes, [88])
                    comm.finalize()

    def test_cmn_stop_on_error_publishes_error_equal_to_entry_status(self):
        for source in (SHA_12_NK, SHA_18_NK, SHA_DS4_NK, SHA_PLUS_NK):
            for custom in (False, True):
                with self.subTest(source=source[:12], custom=custom):
                    fixture = LifecycleTest()
                    _manager, context, _calls = fixture.fixture(
                        [b"\x61\xff"], source=source, address=_FIXED_OBJECTS[source]
                    )
                    comm = fixture.selected_facade(context)
                    self.assertEqual(comm.initialize(), 0)
                    timer = UtilityExSelectedTimerKeepalive(context, comm)
                    status_key = f"native_global:{timer.layout['status']:x}"
                    timer.native_status = 3
                    exchange = comm.exchange

                    def exchange_then_publish(request, exchange=exchange, timer=timer):
                        result = exchange(request)
                        timer.native_status = 88
                        return result

                    comm.exchange = exchange_then_publish
                    worker = UtilityExSelectedCMNWorker(context, comm)
                    if custom:
                        result = worker.run(
                            UtilityExSelectedCMNFields(0, b"\x21\x00", 2, 0, 1)
                        )
                    else:
                        result = worker.run(0, stop_on_error=True)
                    self.assertEqual(result, 3)
                    self.assertEqual(context.state[status_key], 3)
                    comm.finalize()


if __name__ == "__main__":
    unittest.main()
