"""Authored DLC12 selected-DDB and literal DMCI observations; no hardware."""

import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.data_monitor import MonitorError
from scripts.demo import create_demo
from scripts.drive_recorder import (
    NativeCoreBuffer,
    NativeDmciCommand,
    NativeDmciList,
    NativeMonitorReply,
    NativeVimClient,
    NativeVimReply,
    RecorderCancelled,
    RecorderError,
)
from scripts.monitor_dlc12 import (
    DLC12MonitorRuntime,
    DLC12VoltageObservation,
    DLC12VoltageState,
    dlc12_notifications,
    dlc12_voltage_controller,
    dlc12_voltage_offset,
    selected_dlc12_monitor,
)
from scripts.profiles import VehicleCatalog


class DLC12Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = create_demo(Path(self.tmp.name) / "authored")
        self.profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
        freeze = bytearray(self.profile.database.sections[10].payload)
        freeze[79] = 1
        self.profile.database.sections[10] = replace(
            self.profile.database.sections[10], payload=bytes(freeze)
        )
        # Demo variable5 is two bytes; constructor needs literal send1/mask2.
        management = self.profile.catalog.management
        comm = bytearray(management.sections[17].payload)
        struct.pack_into("<3H", comm, 3 * 8 + 2, 4, 5, 0)
        management.sections[17] = replace(management.sections[17], payload=bytes(comm))
        self.observed: dict[int, bool] = dict.fromkeys(
            (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35), False
        )
        self.observed[27] = True

    def selected(self, *, observed_functions=None, connected_device=4, excluded=0):
        return selected_dlc12_monitor(
            self.profile,
            (1,),
            observed_functions=self.observed
            if observed_functions is None
            else observed_functions,
            connected_device=connected_device,
            interface_id=7,
            buffer_468=1,
            excluded=excluded,
        )

    def test_real_selected_profile_produces_literals_and_metadata(self):
        plan = self.selected()
        self.assertEqual(plan.packing.setup_requests, (b"\xa1\x01", b"\xe1\x02"))
        self.assertEqual(plan.layouts, ((1, 0, 0, 15),))
        signal = plan.metadata[0]
        self.assertEqual(
            (signal.name, signal.unit, signal.multiplier, signal.divisor),
            ("Engine speed", "rpm", 1, 4),
        )
        from scripts.monitor_support import monitor_source_identity

        self.assertEqual(
            plan.source_identity, monitor_source_identity(self.profile, "")
        )
        self.assertEqual(len(plan.source_identity), 7)
        self.assertEqual(plan.source_identity[6], self.profile.vehicle_name_key)
        self.assertEqual((plan.constructor_send, plan.constructor_mask), (12, 1))
        command = plan.commands.setup[1]
        self.assertEqual(command.values, (1, 7, 0, ((1, 2),), 2, (), 3, 0xFFFFFFFF))
        wire = NativeDmciCommand.from_neutral(
            command.command_id, command.values
        ).encode()
        self.assertEqual(
            wire.hex(),
            "0100000007000000000000000100000001000000010202000000010000000000000003000000ffffffff",
        )

    def test_modes_exclusion_and_observations(self):
        for function, mode, data_type in (
            (27, 0x800, 0),
            (28, 0x1000, 1),
            (29, 0x2000, 2),
        ):
            observed = dict.fromkeys(self.observed, False)
            observed[function] = True
            selected = self.selected(observed_functions=observed)
            self.assertEqual(selected.packing.mode, mode)
            self.assertEqual(selected.commands.setup[1].values[2], data_type)
            with self.assertRaises(MonitorError):
                self.selected(observed_functions=observed, excluded=mode)
        with self.assertRaises(MonitorError):
            self.selected(observed_functions={27: True})
        with self.assertRaises(MonitorError) as error:
            self.selected(connected_device=3)
        self.assertEqual(error.exception.code, 0xC0051302)
        with self.assertRaises(MonitorError):
            selected_dlc12_monitor(
                self.profile,
                (2,),
                observed_functions=self.observed,
                connected_device=4,
                interface_id=7,
                buffer_468=1,
            )

    def reply(self, chunks=(), *, buffers=None, stops=0):
        empty = NativeCoreBuffer((1, 0), b"")
        return NativeMonitorReply(
            0,
            NativeDmciList(
                (1, 0),
                tuple(
                    (identity, NativeCoreBuffer((1, 0), data))
                    for identity, data in chunks
                ),
            ),
            buffers or (empty, empty, empty, empty, empty),
            stops,
        )

    def client(self, replies=(), failure=None):
        replies = iter(replies)
        calls = []

        def exchange(request, *, deadline, cancelled):
            calls.append(request)
            command = int.from_bytes(request[:2], "little")
            if failure is not None and len(calls) == failure:
                raise OSError("authored transport fault")
            body = next(replies).encode() if command == 0x197F else bytes(4)
            return NativeVimReply(command | 0x80, 6, body).encode()

        return NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        ), calls

    def test_setup_cached_registration_and_complete_native_capture(self):
        raw = struct.pack("<I", 1000) + b"AB"
        client, calls = self.client(
            (
                self.reply(((1, raw[:3]), (99, b"ignored"))),
                self.reply(((1, raw[3:]),)),
            )
        )
        runtime = DLC12MonitorRuntime(self.selected(), client)
        runtime.setup()
        runtime.setup()
        self.assertEqual(calls[1][2:6], struct.pack("<I", 1))
        self.assertNotEqual(calls[1], calls[2])
        result = runtime.capture(max_polls=2, max_packets=1, timeout=3)
        self.assertEqual([(p.timestamp_ms, p.payload) for p in result], [(1000, b"AB")])
        self.assertEqual(
            [call[:2].hex() for call in calls],
            ["7f20", "7f16", "7f16", "7f18", "7f19", "7f19", "7f1a"],
        )
        self.assertEqual(calls[4], bytes.fromhex("7f19010000000100000001000000"))
        self.assertEqual(runtime.state, "stopped")

    def test_faults_cancel_and_budget_always_stop(self):
        for failure in (3, 4, 5):
            client, calls = self.client(
                (self.reply(((1, struct.pack("<I", 1) + b"AB"),)),), failure=failure
            )
            runtime = DLC12MonitorRuntime(self.selected(), client)
            runtime.setup()
            with self.assertRaises(OSError):
                runtime.capture(max_polls=1, max_packets=1, timeout=3)
            self.assertEqual(calls[-1][:2], bytes.fromhex("7f1a"))
            self.assertEqual(runtime.state, "fault")
        client, calls = self.client()
        runtime = DLC12MonitorRuntime(self.selected(), client)
        runtime.setup()
        with self.assertRaises(RecorderCancelled):
            runtime.capture(
                max_polls=1, max_packets=1, timeout=3, cancelled=lambda: True
            )
        self.assertEqual(calls[-1][:2], bytes.fromhex("7f1a"))
        client, calls = self.client((self.reply(),))
        runtime = DLC12MonitorRuntime(self.selected(), client)
        runtime.setup()
        with self.assertRaisesRegex(MonitorError, "poll budget"):
            runtime.capture(max_polls=1, max_packets=1, timeout=3)
        self.assertEqual(calls[-1][:2], bytes.fromhex("7f1a"))

    def test_notifications_literal_and_truncated_packet(self):
        empty = NativeCoreBuffer((1, 0), b"")
        reply = self.reply(
            buffers=(
                NativeCoreBuffer((1, 0), struct.pack("<I", 5) + b"x"),
                NativeCoreBuffer((1, 0), struct.pack("<IIIB", 99, 6, 7, 8) + b"x"),
                empty,
                empty,
                empty,
            ),
            stops=3,
        )
        notifications = dlc12_notifications(reply)
        self.assertEqual(notifications.errors, ((5, 19, 0), (6, 7, 8)))
        self.assertEqual(notifications.stop_count, 3)
        client, calls = self.client((self.reply(((1, b"x"),), stops=1),))
        runtime = DLC12MonitorRuntime(self.selected(), client)
        runtime.setup()
        with self.assertRaisesRegex(RecorderError, "Truncated"):
            runtime.capture(max_polls=1, max_packets=1, timeout=3)
        self.assertEqual(calls[-1][:2], bytes.fromhex("7f1a"))

    def test_constructor_and_setup_fault_cleanup_delete_twice(self):
        for failure in (1, 2):
            client, calls = self.client(failure=failure)
            runtime = DLC12MonitorRuntime(self.selected(), client)
            with self.assertRaises(OSError):
                runtime.setup()
            self.assertEqual(
                [call[:2].hex() for call in calls[-3:]], ["7f21", "7f21", "0200"]
            )
            self.assertFalse(runtime.created)
            self.assertEqual(runtime.state, "fault")
        client, calls = self.client()
        runtime = DLC12MonitorRuntime(self.selected(), client)
        runtime.setup()
        runtime.close()
        count = len(calls)
        runtime.close()
        self.assertEqual(len(calls), count)
        self.assertEqual(runtime.state, "closed")

    def test_malformed_selection_and_input_budgets_do_not_touch_transport(self):
        with self.assertRaises(MonitorError):
            self.selected(excluded=True)
        with self.assertRaises(MonitorError):
            selected_dlc12_monitor(
                self.profile,
                (1,),
                observed_functions=self.observed,
                connected_device=4,
                interface_id=7,
                buffer_468=99,
            )
        client, calls = self.client()
        runtime = DLC12MonitorRuntime(self.selected(), client)
        with self.assertRaises(MonitorError):
            runtime.capture(max_polls=1, max_packets=1, timeout=1)
        self.assertEqual(calls, [])
        runtime.setup()
        count = len(calls)
        for operation in (
            lambda: runtime.capture(max_polls=0, max_packets=1, timeout=1),
            lambda: runtime.capture(max_polls=1, max_packets=True, timeout=1),
            lambda: runtime.capture(max_polls=1, max_packets=1, timeout=float("nan")),
            lambda: runtime.capture(max_polls=1, max_packets=1, timeout=1, max_bytes=0),
        ):
            with self.assertRaises((MonitorError, RecorderError)):
                operation()
            self.assertEqual(len(calls), count)

    def test_native_error_notification_and_aggregate_byte_bound_stop(self):
        empty = NativeCoreBuffer((1, 0), b"")
        error = self.reply(
            buffers=(
                NativeCoreBuffer((1, 0), struct.pack("<I", 0x90051007)),
                empty,
                empty,
                empty,
                empty,
            )
        )
        client, calls = self.client((error,))
        runtime = DLC12MonitorRuntime(self.selected(), client)
        runtime.setup()
        with self.assertRaises(MonitorError) as caught:
            runtime.capture(max_polls=1, max_packets=1, timeout=3)
        self.assertEqual(caught.exception.code, 0x90051007)
        self.assertEqual(calls[-1][:2], bytes.fromhex("7f1a"))
        client, calls = self.client((self.reply(((1, struct.pack("<I", 1) + b"AB"),)),))
        runtime = DLC12MonitorRuntime(self.selected(), client)
        runtime.setup()
        with self.assertRaisesRegex(RecorderError, "byte budget"):
            runtime.capture(max_polls=1, max_packets=1, timeout=3, max_bytes=5)
        self.assertEqual(calls[-1][:2], bytes.fromhex("7f1a"))

    def test_native_negative_dmci_status_faults_and_cleanup(self):
        calls = []

        def exchange(request, *, deadline, cancelled):
            calls.append(request)
            command = int.from_bytes(request[:2], "little")
            status = 0x90051007 if command == 0x167F else 0
            return NativeVimReply(command | 0x80, 6, struct.pack("<I", status)).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        runtime = DLC12MonitorRuntime(self.selected(), client)
        with self.assertRaisesRegex(RecorderError, "0x90051007"):
            runtime.setup()
        self.assertEqual(runtime.state, "fault")
        self.assertEqual(
            [call[:2].hex() for call in calls], ["7f20", "7f16", "7f21", "7f21", "0200"]
        )

    def test_voltage_calibration_observations_and_all_state_modes(self):
        observation = DLC12VoltageObservation(0, True, ((True, b"\x04\0"),) * 4)
        self.assertEqual(observation.setup_ioctl, 0xFFFEFF84)
        self.assertEqual(dlc12_voltage_offset(20, 3, 2, observation), (14, None))
        self.assertEqual(dlc12_voltage_offset(0, 0xFFFFFFFF, 1, observation), (4, None))
        setup_failed = DLC12VoltageObservation(1, False, ())
        self.assertEqual(setup_failed.setup_ioctl, 0xFFFEFF90)
        self.assertEqual(dlc12_voltage_offset(20, 3, 2, setup_failed), (20, 0x90051203))
        read_failed = DLC12VoltageObservation(
            0, True, ((True, b"\x04\0"), (False, b""))
        )
        self.assertEqual(dlc12_voltage_offset(20, 3, 2, read_failed), (20, 0x90051204))
        with self.assertRaises(MonitorError):
            DLC12VoltageObservation(0, True, ())
        with self.assertRaises(MonitorError):
            DLC12VoltageObservation(0, True, ((False, b""), (True, b"\0\0")))
        with self.assertRaises(MonitorError):
            dlc12_voltage_offset(20, 3, 0, observation)
        category = bytearray(self.profile.category_record)
        category[68:70] = (0x68).to_bytes(2, "little")
        self.profile = replace(self.profile, category_record=bytes(category))
        management = self.profile.catalog.management
        functions = bytearray(management.sections[18].payload)
        for position in range(0, len(functions), 16):
            struct.pack_into("<H", functions, position, 0x68)
        management.sections[18] = replace(
            management.sections[18], payload=bytes(functions)
        )
        arguments = {
            "observed_functions": self.observed,
            "connected_device": 4,
            "interface_id": 7,
            "buffer_468": 0x68,
        }
        with self.assertRaises(MonitorError):
            selected_dlc12_monitor(self.profile, (1,), **arguments)
        for mode in (0, 1, 2):
            state = DLC12VoltageState(mode, 42)
            result = selected_dlc12_monitor(
                self.profile,
                (1,),
                voltage_state=state,
                voltage_observations={1: observation},
                **arguments,
            )
            self.assertEqual(result.metadata[0].offset, (0, 0xFFFFFFFF, 42)[mode])
            self.assertEqual(state.cached_offset, (42, 0xFFFFFFFF, 42)[mode])

    def test_all_disposal_failures_still_attempt_remaining_cleanup(self):
        for failure in (3, 4, 5):
            client, calls = self.client(failure=failure)
            runtime = DLC12MonitorRuntime(self.selected(), client)
            runtime.setup()
            with self.assertRaises(OSError):
                runtime.close()
            self.assertEqual(
                [call[:2].hex() for call in calls],
                ["7f20", "7f16", "7f21", "7f21", "0200"],
            )
            self.assertEqual(runtime.state, "fault")

    def test_cancel_during_poll_and_deadline_after_exchange_stop(self):
        for mode in ("cancel", "deadline"):
            calls = []
            now = [0.0]
            cancelled = [False]

            def exchange(
                request,
                *,
                deadline,
                cancelled,
                calls=calls,
                mode=mode,
                cancel_flag=cancelled,
                now=now,
            ):
                calls.append(request)
                command = int.from_bytes(request[:2], "little")
                if command == 0x197F:
                    if mode == "cancel":
                        cancel_flag[0] = True
                    else:
                        now[0] = 10
                    body = self.reply().encode()
                else:
                    body = bytes(4)
                return NativeVimReply(command | 0x80, 6, body).encode()

            client = NativeVimClient(
                exchange,
                clock=lambda now=now: now[0],
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
            )
            runtime = DLC12MonitorRuntime(self.selected(), client)
            runtime.setup()
            with self.assertRaises(
                RecorderCancelled if mode == "cancel" else TimeoutError
            ):
                runtime.capture(
                    max_polls=1,
                    max_packets=1,
                    timeout=3,
                    cancelled=lambda cancelled=cancelled: cancelled[0],
                )
            self.assertEqual(calls[-1][:2], bytes.fromhex("7f1a"))

    def test_old12_and18_pattern_fields_feed_selected_monitor(self):
        for width in (20, 24):
            self.profile = replace(
                self.profile,
                database=replace(
                    self.profile.database,
                    version=0x0100030C if width == 20 else 0x0100032F,
                ),
            )
            pattern = bytearray(width)
            struct.pack_into("<I", pattern, 0, 6)
            if width == 20:
                struct.pack_into("<H", pattern, 10, 257)
            else:
                struct.pack_into("<I", pattern, 4, 257)
            old = self.profile.database.sections[14]
            self.profile.database.sections[14] = replace(old, payload=bytes(pattern))
            result = self.selected()
            self.assertEqual(
                result.metadata[0].patterns, ((0, "Example state", 257, 0),)
            )

    def test_nonzero_change_mode_status_is_cleanup_failure(self):
        calls = []

        def exchange(request, *, deadline, cancelled):
            calls.append(request)
            command = int.from_bytes(request[:2], "little")
            return NativeVimReply(
                command | 0x80, 6, struct.pack("<I", 9 if command == 2 else 0)
            ).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        runtime = DLC12MonitorRuntime(self.selected(), client)
        runtime.setup()
        with self.assertRaises(MonitorError) as caught:
            runtime.close()
        self.assertEqual(caught.exception.code, 9)
        self.assertEqual(runtime.state, "fault")
        self.assertEqual(
            [call[:2].hex() for call in calls], ["7f20", "7f16", "7f21", "7f21", "0200"]
        )

    def test_shipped_auxiliary_voltage_controller_negative_branches(self):
        self.assertEqual(
            dlc12_voltage_controller("start", mode_mask=0, interface_present=False), 0
        )
        self.assertEqual(
            dlc12_voltage_controller("start", mode_mask=0x40, interface_present=False),
            0xC0050001,
        )
        self.assertEqual(
            dlc12_voltage_controller("start", mode_mask=0x40, interface_present=True),
            0x90051201,
        )
        self.assertEqual(
            dlc12_voltage_controller("stop", mode_mask=0, interface_present=False),
            0xC0050001,
        )
        self.assertEqual(
            dlc12_voltage_controller("stop", mode_mask=0x40, interface_present=True),
            0x90051202,
        )
        with self.assertRaises(MonitorError):
            dlc12_voltage_controller("sample", mode_mask=0x40, interface_present=True)


class DLC12ControllerTests(unittest.TestCase):
    observed: dict[int, bool]
    setUp = DLC12Tests.setUp
    selected = DLC12Tests.selected
    reply = DLC12Tests.reply
    client = DLC12Tests.client

    def controller(self, replies=(), failure=None):
        from scripts.monitor_dlc12 import DLC12Controller

        client, calls = self.client(replies, failure)
        return DLC12Controller(client), calls

    def test_export_flags_queue_dispatch_order_and_source_negative_commands(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage

        controller, calls = self.controller()
        self.assertEqual(controller.check_start(7).flags28, 1)
        self.assertEqual(controller.check_start(0x42).flags20, 1)
        self.assertEqual(controller.check_start(9).status, 0xC0050404)
        for command in (9, 0x89, 7, 0x42, 0xFFFFFFFF):
            message = DLC12ControlMessage(command)
            controller.enqueue(message)
            result = controller.run_one()
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.status, 0x90050405)
            self.assertTrue(message.completed.is_set())
            self.assertEqual(
                list(controller.trace)[-3:],
                [("finish", command), ("error", 0x90050405), ("stop", 0)],
            )
        self.assertEqual(calls, [])

    def test_controller_queue_and_history_budgets(self):
        from unittest.mock import patch

        from scripts.monitor_dlc12 import DLC12ControlMessage

        controller, calls = self.controller()
        with patch("scripts.monitor_dlc12.MAX_ITEMS", 3):
            from scripts.monitor_dlc12 import DLC12Controller

            controller = DLC12Controller(controller.client, maximum_queued=3)
        for code in (1, 2, 3, 4):
            controller.post_error(code)
        self.assertEqual(
            list(controller.trace), [("error", 2), ("error", 3), ("error", 4)]
        )
        for _ in range(3):
            controller.enqueue(DLC12ControlMessage(9))
        with self.assertRaises(MonitorError):
            controller.enqueue(DLC12ControlMessage(9))
        self.assertEqual(len(controller.queue), 3)
        self.assertEqual(calls, [])

    def test_selected_command_start_stop_and_repeat_state(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage

        controller, calls = self.controller()
        start = DLC12ControlMessage(0xC, self.selected())
        stop = DLC12ControlMessage(0xA)
        controller.enqueue(start)
        controller.enqueue(stop)
        result = controller.run_one()
        assert result is not None
        self.assertEqual((result.status, result.flags20), (0, 1))
        self.assertEqual(controller.active_mask, 0x800)
        self.assertEqual([call[:2].hex() for call in calls], ["7f20", "7f16", "7f18"])
        self.assertFalse(stop.completed.is_set())
        controller.run_one()
        self.assertTrue(stop.completed.is_set())
        self.assertEqual(controller.active_mask, 0)
        self.assertEqual(calls[-1][:2].hex(), "7f1a")
        with self.assertRaises(MonitorError):
            controller.enqueue(start)

    def test_native_single_system_and_primary_slot_constraints(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage

        for count, slot in ((0, 0), (2, 0), (1, 1), (1, 2)):
            controller, calls = self.controller()
            message = DLC12ControlMessage(
                0x38, self.selected(), system_count=count, slot_index=slot
            )
            controller.enqueue(message)
            result = controller.run_one()
            assert result is not None
            self.assertEqual(result.status, 0xC0050001)
            self.assertEqual(calls, [])

    def test_three_slots_reuse_lookup_error_aggregation_and_overflow(self):
        from scripts.drive_recorder import native_monitor_buffer

        controller, _ = self.controller()
        for category in (1, 0x68, 999):
            buffer = native_monitor_buffer(
                category,
                (),
                ((0, 2),),
                (),
                phase=0,
                allocation_size=32,
                name=b"authored",
                text_encoding="ascii",
            )
            index = controller.register_buffer(buffer)
            self.assertEqual(index, (1, 0x68, 999).index(category))
            self.assertIs(controller.buffer_by_category(category), buffer)
            self.assertEqual(controller.register_buffer(buffer), index)
        extra = native_monitor_buffer(
            2,
            (),
            ((0, 2),),
            (),
            phase=0,
            allocation_size=32,
            name=b"authored",
            text_encoding="ascii",
        )
        with self.assertRaises(MonitorError) as caught:
            controller.register_buffer(extra)
        self.assertEqual(caught.exception.code, 0xC0050001)
        controller.post_error(55)
        self.assertEqual(
            [controller.buffer_error(i) for i in range(4)], [55, 55, 55, 55]
        )
        controller.run_one(wait_status=0x102)
        self.assertEqual(controller.trace[-1], ("stop", 0))

    def test_recording_settings_bind_actual_selected_metadata_and_commands(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage, DLC12RecordingBufferSpec

        controller, calls = self.controller()
        selected = self.selected()
        spec = DLC12RecordingBufferSpec(selected, (1,), 0, 128, b"authored", "ascii")
        message = DLC12ControlMessage(0x57, selected, recording=(spec,))
        controller.enqueue(message)
        result = controller.run_one()
        assert result is not None and result.settings is not None
        self.assertEqual(result.settings.commands, selected.commands)
        self.assertEqual(result.settings.buffers[0].value_before_buffer, 1)
        self.assertEqual(result.settings.buffers[0].signal_table.table_id, 4)
        self.assertEqual(controller.active_mask, 0)
        self.assertEqual(
            [call[:2].hex() for call in calls],
            ["7f20", "7f16", "7f18", "7f1a", "7f21", "7f21", "0200"],
        )
        assert controller.runtime is not None
        self.assertFalse(controller.runtime.created)

    def test_recording_bounds_fail_before_metadata_conversion(self):
        from unittest.mock import patch

        from scripts.monitor_dlc12 import (
            MAX_BYTES,
            DLC12ControlMessage,
            DLC12RecordingBufferSpec,
        )

        selected = self.selected()
        spec = DLC12RecordingBufferSpec(selected, (1,), 0, 128, b"authored", "ascii")
        invalid = (
            (spec,) * 4,
            (replace(spec, allocation_size=MAX_BYTES), spec),
            (replace(spec, allocation_size=True),),
        )
        for recording in invalid:
            controller, calls = self.controller()
            controller.enqueue(DLC12ControlMessage(0x57, selected, recording=recording))
            with patch.object(
                DLC12RecordingBufferSpec,
                "native",
                side_effect=AssertionError("conversion reached"),
            ) as convert:
                result = controller.run_one()
                self.assertFalse(convert.called)
            assert result is not None
            self.assertTrue(result.failed)
            self.assertEqual(calls, [])

    def test_recording_rejects_foreign_source_identity_before_transport(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage, DLC12RecordingBufferSpec

        selected = self.selected()
        foreign = [replace(selected, database_sha256="f" * 64)]
        for index, value in (
            (1, "f" * 64),
            (2, "e" * 64),
            (3, 99),
            (4, b"foreign category"),
            (5, (99,)),
            (6, 99),
        ):
            identity = list(selected.source_identity)
            identity[index] = value
            foreign.append(replace(selected, source_identity=tuple(identity)))
        for plan in foreign:
            controller, calls = self.controller()
            spec = DLC12RecordingBufferSpec(plan, (1,), 0, 128, b"authored", "ascii")
            controller.enqueue(DLC12ControlMessage(0x57, selected, recording=(spec,)))
            result = controller.run_one()
            assert result is not None
            self.assertTrue(result.failed)
            self.assertEqual(calls, [])

    def test_recording_same_source_requires_matching_acquisition_plan(self):
        from unittest.mock import patch

        from scripts.monitor_dlc12 import DLC12ControlMessage, DLC12RecordingBufferSpec

        selected = self.selected()
        other = replace(
            selected, packing=replace(selected.packing, frame_sizes=((0, 3),))
        )
        self.assertEqual(other.source_identity, selected.source_identity)
        controller, calls = self.controller()
        spec = DLC12RecordingBufferSpec(other, (1,), 0, 128, b"authored", "ascii")
        controller.enqueue(DLC12ControlMessage(0x57, selected, recording=(spec,)))
        with patch.object(
            DLC12RecordingBufferSpec,
            "native",
            side_effect=AssertionError("conversion reached"),
        ) as convert:
            result = controller.run_one()
            self.assertFalse(convert.called)
        assert result is not None
        self.assertTrue(result.failed)
        self.assertEqual(calls, [])
        clone = replace(selected)
        self.assertIsNot(clone, selected)
        controller, calls = self.controller()
        spec = replace(spec, selected=clone)
        controller.enqueue(DLC12ControlMessage(0x57, selected, recording=(spec,)))
        result = controller.run_one()
        assert result is not None
        self.assertEqual(result.status, 0)
        self.assertEqual(len(calls), 7)

    def test_recording_settings_cleanup_faults_attempt_every_disposal_step(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage, DLC12RecordingBufferSpec

        selected = self.selected()
        spec = DLC12RecordingBufferSpec(selected, (1,), 0, 128, b"authored", "ascii")
        for failure in range(4, 8):
            with self.subTest(failure=failure):
                controller, calls = self.controller(failure=failure)
                message = DLC12ControlMessage(0x57, selected, recording=(spec,))
                controller.enqueue(message)
                result = controller.run_one()
                assert result is not None and controller.runtime is not None
                self.assertTrue(result.failed)
                self.assertTrue(message.completed.is_set())
                self.assertIsInstance(message.exception, OSError)
                self.assertEqual(
                    [call[:2].hex() for call in calls],
                    ["7f20", "7f16", "7f18", "7f1a", "7f21", "7f21", "0200"],
                )
                self.assertFalse(controller.runtime.created)
                self.assertEqual(controller.active_mask, 0)

    def test_queue_fault_shutdown_cancellation_and_completion(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage

        controller, calls = self.controller(failure=3)
        message = DLC12ControlMessage(0xC, self.selected())
        controller.enqueue(message)
        result = controller.run_one()
        assert result is not None
        self.assertTrue(result.failed)
        self.assertTrue(message.completed.is_set())
        self.assertIsInstance(message.exception, OSError)
        self.assertEqual(controller.trace[1], ("finish", 0xC))
        controller, calls = self.controller()
        message = DLC12ControlMessage(0xC, self.selected())
        controller.enqueue(message)
        controller.run_one(cancelled=lambda: True)
        self.assertTrue(message.completed.is_set())
        self.assertIsInstance(message.exception, RecorderCancelled)
        self.assertEqual(calls, [])
        pending = DLC12ControlMessage(0xA)
        controller.enqueue(pending)
        controller.run_one(wait_status=1)
        self.assertTrue(pending.completed.is_set())
        self.assertTrue(controller.closed)

    def test_failed_start_disposes_owned_interface(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage

        controller, calls = self.controller(failure=3)
        message = DLC12ControlMessage(0xC, self.selected())
        controller.enqueue(message)
        result = controller.run_one()
        assert result is not None and controller.runtime is not None
        self.assertTrue(result.failed)
        self.assertIsInstance(message.exception, OSError)
        self.assertEqual(
            [call[:2].hex() for call in calls],
            ["7f20", "7f16", "7f18", "7f1a", "7f21", "7f21", "0200"],
        )
        self.assertFalse(controller.runtime.created)

    def test_shutdown_disposes_after_stop_failure(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage

        controller, calls = self.controller(failure=4)
        controller.enqueue(DLC12ControlMessage(0xC, self.selected()))
        controller.run_one()
        with self.assertRaises(OSError):
            controller.run_one(wait_status=1)
        assert controller.runtime is not None
        self.assertEqual(
            [call[:2].hex() for call in calls],
            ["7f20", "7f16", "7f18", "7f1a", "7f21", "7f21", "0200"],
        )
        self.assertFalse(controller.runtime.created)
        self.assertTrue(controller.closed)

    def test_rejected_buffer_registration_preserves_existing_state(self):
        from scripts.drive_recorder import native_monitor_buffer

        controller, _ = self.controller()
        original = native_monitor_buffer(
            1,
            (),
            ((0, 2),),
            (),
            phase=0,
            allocation_size=32,
            name=b"authored",
            text_encoding="ascii",
        )
        controller.register_buffer(original)
        reader = controller.readers[1]
        controller.errors[0] = 17
        invalid = (
            replace(original, buffer_size=2),
            replace(
                original,
                frame_table=replace(
                    original.frame_table, payload=struct.pack("<IHH", 1, 0, 0)
                ),
            ),
        )
        for buffer in invalid:
            with self.assertRaises(RecorderError):
                controller.register_buffer(buffer)
            self.assertIs(controller.slots[0], original)
            self.assertIs(controller.readers[1], reader)
            self.assertEqual(controller.errors[0], 17)

    def test_selected_secondary_recording_slot_is_native_failure(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage, DLC12RecordingBufferSpec

        selected = self.selected()
        secondary = replace(selected, buffer_468=999)
        specs = tuple(
            DLC12RecordingBufferSpec(plan, (1,), 0, 128, b"authored", "ascii")
            for plan in (selected, secondary)
        )
        controller, calls = self.controller()
        controller.enqueue(DLC12ControlMessage(0x57, selected, recording=specs))
        result = controller.run_one()
        assert result is not None
        self.assertEqual(result.status, 0xC0050001)
        self.assertEqual(calls, [])

    def active_fixture(self):
        from scripts.diagnostic_db import Section
        from scripts.monitor_dlc12 import selected_dlc12_active_operation

        category = bytearray(self.profile.category_record)
        category[72] = 1
        self.profile = replace(self.profile, category_record=bytes(category))
        record = bytearray(92)
        struct.pack_into("<H", record, 56, 10)
        struct.pack_into("<H", record, 64, 1)
        struct.pack_into("<H", record, 74, 2)
        record[82] = 7
        pattern = bytearray(24)
        struct.pack_into("<HH", pattern, 0, 1, 44)
        pattern[20] = 1
        self.profile.database.sections[11] = Section(11, 0, 1, False, bytes(record))
        self.profile.database.sections[12] = Section(12, 0, 1, False, bytes(pattern))
        protocol = bytearray(28)
        struct.pack_into("<H", protocol, 0, 1)
        struct.pack_into("<HH", protocol, 6, 0x123, 0x456)
        protocol[24] = 0x12
        self.profile.catalog.management.sections[13] = Section(
            13, 0, 1, False, bytes(protocol)
        )
        return selected_dlc12_active_operation(
            self.profile, 10, 9, observed_bus_id=0x12
        )

    def test_selected_active_request_headers_and_real_queue_B(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage

        operation = self.active_fixture()
        self.assertEqual(operation.headers, (0x456, 0x45E, 0xFFFFFFFF))
        self.assertEqual(operation.command.values, (0x456, b"\x07\x09", 44))
        observed = dict.fromkeys(self.observed, False)
        observed[29] = True
        selected = self.selected(observed_functions=observed)
        controller, calls = self.controller()
        controller.enqueue(DLC12ControlMessage(0xC, selected))
        controller.run_one()
        message = DLC12ControlMessage(0xB, active=operation)
        controller.enqueue(message)
        result = controller.run_one()
        assert result is not None
        self.assertEqual(result.status, 0)
        self.assertEqual(calls[-1][:2], bytes.fromhex("7f1b"))
        self.assertEqual(calls[-1][2:].hex(), "56040000010000000200000007092c00")
        self.assertIs(controller.active_operation, operation)

    def test_active_operation_rejects_foreign_source_identity(self):
        from scripts.monitor_dlc12 import DLC12ControlMessage

        operation = self.active_fixture()
        observed = dict.fromkeys(self.observed, False)
        observed[29] = True
        selected = self.selected(observed_functions=observed)
        for foreign in (
            replace(operation, database_sha256="f" * 64),
            replace(operation, source_identity=("foreign",)),
        ):
            controller, calls = self.controller()
            controller.enqueue(DLC12ControlMessage(0xC, selected))
            controller.run_one()
            controller.enqueue(DLC12ControlMessage(0xB, active=foreign))
            result = controller.run_one()
            assert result is not None
            self.assertEqual(result.status, 0xC0050001)
            self.assertNotIn(bytes.fromhex("7f1b"), [call[:2] for call in calls])

    def test_native_active_missing_bus_and_mode_rejection(self):
        from scripts.monitor_dlc12 import (
            DLC12ControlMessage,
            selected_dlc12_active_operation,
        )

        self.active_fixture()
        for bus, expected in ((None, 0xC0040601), (0, 0xC0040602)):
            with self.assertRaises(MonitorError) as caught:
                selected_dlc12_active_operation(
                    self.profile, 10, 9, observed_bus_id=bus
                )
            self.assertEqual(caught.exception.code, expected)
        controller, _ = self.controller()
        controller.enqueue(DLC12ControlMessage(0xB))
        result = controller.run_one()
        assert result is not None
        self.assertEqual(result.status, 0x90050405)
        controller.enqueue(DLC12ControlMessage(0xC, self.selected()))
        controller.run_one()
        controller.enqueue(DLC12ControlMessage(0xB))
        result = controller.run_one()
        assert result is not None
        self.assertEqual(result.status, 0xC005100D)

    def test_native_protocol_header_branch_literals_and_rejections(self):
        from scripts.monitor_dlc12 import dlc12_protocol_headers

        vectors = (
            (0x11, (0x8056F0, 0xFFFFFFFF, 0xC034F0)),
            (0x21, (0x686AF0, 0x486B56, 0xFFFFFFFF)),
            (0x31, (0xC034F0, 0x80F056, 0xFFFFFFFF)),
            (0x51, (0x8056F0, 0xFFFFFFFF, 0xC034F0)),
            (0x12, (0x56, 0x5E, 0xFFFFFFFF)),
            (0x22, (0x80005678, 0x80005E56, 0xFFFFFFFF)),
            (0x32, (0x34, 0x5E, 0xFFFFFFFF)),
            (5, (0x56, 0xFFFFFFFF, 0xFFFFFFFF)),
            (6, (0x616AF0, 0x416B56, 0xFFFFFFFF)),
            (7, (0x686AF0, 0x486B56, 0xFFFFFFFF)),
            (0x18, (0xD8DA56F0, 0xD8DAF056, 0xFFFFFFFF)),
            (0x38, (0xD8DB34F0, 0xD8DAF056, 0xFFFFFFFF)),
            (12, (0x56, 0xFFFFFFFF, 0xFFFFFFFF)),
        )
        for bus, expected in vectors:
            self.assertEqual(dlc12_protocol_headers(0, bus, 0x34, 0x56, 0x78), expected)
        self.assertEqual(
            dlc12_protocol_headers(0x80, 0x11, 0, 0x56),
            (0x8056F1, 0xFFFFFFFF, 0xFFFFFFFF),
        )
        for bus in (0, 3, 4, 10, 11, 0x41, 0x42, 0x28):
            with self.assertRaises(MonitorError):
                dlc12_protocol_headers(0, bus, 0x34, 0x56)

    def test_three_registered_streams_route_literal_chunks_and_stop(self):
        from scripts.drive_recorder import native_monitor_buffer
        from scripts.monitor_dlc12 import DLC12ControlMessage

        reply = self.reply(
            (
                (1, struct.pack("<I", 1) + b"AB"),
                (999, struct.pack("<I", 3) + b"OS"),
                (0x68, struct.pack("<I", 2) + b"VR"),
            ),
            stops=1,
        )
        controller, calls = self.controller((reply,))
        controller.enqueue(DLC12ControlMessage(0xC, self.selected()))
        controller.run_one()
        for category in (0x68, 999):
            controller.register_buffer(
                native_monitor_buffer(
                    category,
                    (),
                    ((0, 2),),
                    (),
                    phase=0,
                    allocation_size=32,
                    name=b"authored",
                    text_encoding="ascii",
                )
            )
        packets = controller.poll_registered()
        self.assertEqual(
            [
                (identity, packet.timestamp_ms, packet.payload)
                for identity, packet in packets
            ],
            [(1, 1, b"AB"), (999, 3, b"OS"), (0x68, 2, b"VR")],
        )
        self.assertEqual(
            calls[-2].hex(), "7f190100000003000000e70300006800000001000000"
        )
        self.assertEqual(calls[-1][:2].hex(), "7f1a")
        self.assertEqual(controller.active_mask, 0)
