"""Portable authored lifecycle, admission, fault and ownership vectors."""

import unittest
from dataclasses import replace
from unittest.mock import patch

from scripts import cuw_legacy_channel as channel
from scripts.cuw_legacy_can import ExecutableCANError
from scripts.cuw_legacy_channel import (
    ChannelState,
    channel_state,
    close,
    disconnect,
    get_mode,
    reconnect,
    restore_state,
    set_mode,
)
from scripts.cuw_legacy_engine import (
    ExecutableForeignNativeError,
    ExecutableIO,
    ExecutableJ2534Error,
    executable_reconnect,
)
from scripts.programming import NativeTransportError
from tests.test_cuw_legacy_engine import imported_context


class Image:
    """Authored image data exercises extraction without distributing OEM bytes."""

    def __init__(self, context):
        self.context = context

    def read(self, address, size):
        strings = {
            0x1000: b"authored-first-driver",
            0x1100: b"authored-delayed-driver",
            0x59AE75: b"authored-shim",
            0x5F20EF: b"authored-shim",
            0x5F2387: b"authored-alternate-shim",
            0x59BAF0: b"authored-marker",
            0x5F3184: b"authored-marker",
            0x59BAC5: b"authored-version",
            0x5F311B: b"authored-version",
            0x5F2DD9: b"authored-prefix:",
        }
        for start, data in strings.items():
            data += b"\0"
            if start <= address < start + len(data):
                return data[address - start : address - start + size]
        words = {
            0x59AA70: 0x1000,
            0x59AA74: 0x1100,
            0x5F1CC8: 0x1000,
            0x5F1CCC: 0x1100,
            0x59BAE8: 10400,
            0x59BAEC: 500000,
            0x5F3178: 10400,
            0x5F317C: 500000,
            0x5F3180: 100000000,
            0x5F20AC: 3,
            0x5F20B0: 11,
            0x5F20B4: 12,
            0x5F20B8: 13,
        }
        return words[address].to_bytes(4, "little")[:size]


class Provider:
    def __init__(self, *, marker=False, version="authored", fault=None, mode=0):
        self.marker = marker
        self.version = version
        self.fault = fault
        self.mode = mode
        self.events = []
        self.next = 10

    def __call__(self, event, remaining):
        self.events.append(event)
        operation = event["operation"]
        if self.fault and self.fault(event):
            raise NativeTransportError(7)
        if operation == "get_symbol":
            if "marker" in event["symbol"] or event["symbol"].startswith("_"):
                return 900 if self.marker else 0
            return 901
        if operation == "call_symbol":
            return 0
        if operation == "passthru_read_version":
            return ("firmware", self.version, "api")
        if operation == "passthru_scan_for_devices":
            return 1
        if operation == "passthru_get_next_device":
            return "authored selected device"
        if operation == "ioctl" and event["ioctl_id"] == 0x800C:
            return (0x100, 3, self.mode, 0, 0, 0)
        if operation in (
            "load_library",
            "passthru_open",
            "passthru_connect",
            "start_filter",
        ):
            self.next += 1
            return self.next
        return None


class ChannelTests(unittest.TestCase):
    def context(self, build=18, state=None):
        return replace(
            imported_context(),
            build=build,
            observations={
                "legacy_channel_state": state or ChannelState(),
                "legacy_selected_driver": "authored-driver",
            },
        )

    def run_connect(self, build=18, protocol=3, provider=None, state=None):
        provider = provider or Provider()
        context = self.context(build, state)
        io = ExecutableIO(provider)
        with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
            reconnect(context, io, protocol)
        return context, io, provider

    def test_both_builds_connect_native_sil_filters_and_cleanup_order(self):
        for build in (12, 18):
            with self.subTest(build=build):
                context, io, provider = self.run_connect(build)
                state = channel_state(context)
                self.assertEqual(
                    (state.read_timeout, state.send_timeout, state.padding),
                    (0, 1000, True),
                )
                connect = next(
                    e for e in provider.events if e["operation"] == "passthru_connect"
                )
                self.assertEqual((connect["flags"], connect["baud"]), (0x1200, 10400))
                self.assertEqual(
                    [
                        e["name"]
                        for e in provider.events
                        if e["operation"] == "passthru_open"
                    ],
                    [None, None],
                )
                filters = [
                    e for e in provider.events if e["operation"] == "start_filter"
                ]
                self.assertEqual([e["pattern"].data for e in filters], [b"\0", b"\x80"])
                provider.events.clear()
                close(context, io)
                self.assertEqual(
                    [e["operation"] for e in provider.events],
                    [
                        "stop_filter",
                        "stop_filter",
                        "passthru_disconnect",
                        "passthru_close",
                        "passthru_unload_library",
                        "free_library",
                    ],
                )
                self.assertEqual(io.close(), [])

    def test_can_flags_are_zero_and_baud_is_not_2026_policy(self):
        context, io, provider = self.run_connect(protocol=6)
        event = next(e for e in provider.events if e["operation"] == "passthru_connect")
        self.assertEqual((event["flags"], event["baud"]), (0, 500000))
        close(context, io)

    def test_alternate_18_scans_and_preserves_distinct_connect_shape(self):
        context, io, provider = self.run_connect(state=ChannelState(api_version=1))
        event = next(e for e in provider.events if e["operation"] == "passthru_connect")
        self.assertEqual(
            [e["name"] for e in provider.events if e["operation"] == "passthru_open"],
            ["authored-prefix:authored selected device"] * 2,
        )
        self.assertEqual(event["logical_channels"], (3, 11, 12, 13))
        self.assertEqual((event["flags"], event["baud"]), (0, 100000000))
        self.assertFalse(any(e["operation"] == "start_filter" for e in provider.events))
        close(context, io)
        with (
            patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
            self.assertRaises(ValueError),
        ):
            reconnect(
                self.context(12, ChannelState(api_version=1)),
                ExecutableIO(Provider()),
                3,
            )

    def test_alternate_scan_enumeration_and_both_open_faults_cleanup(self):
        for operation in (
            "passthru_scan_for_devices",
            "passthru_get_next_device",
            "passthru_open",
        ):
            for occurrence in (1, 2):
                with self.subTest(operation=operation, occurrence=occurrence):
                    seen = 0

                    def fault(event, operation=operation, occurrence=occurrence):
                        nonlocal seen
                        if event["operation"] == operation:
                            seen += 1
                            return seen == occurrence
                        return False

                    provider = Provider(fault=fault)
                    io = ExecutableIO(provider)
                    context = self.context(state=ChannelState(api_version=1))
                    with (
                        patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
                        self.assertRaises(ExecutableJ2534Error),
                    ):
                        executable_reconnect(context, io, 6)
                    state = channel_state(context)
                    self.assertEqual(
                        (state.library, state.device, state.channel), (None,) * 3
                    )
                    self.assertEqual(io.close(), [])

    def test_alternate_invalid_enumeration_never_reaches_open(self):
        for operation, value, error in (
            ("passthru_scan_for_devices", 0, ExecutableJ2534Error),
            ("passthru_scan_for_devices", True, ValueError),
            ("passthru_get_next_device", "bad\x00name", ValueError),
            ("passthru_get_next_device", b"name", ValueError),
        ):
            with self.subTest(operation=operation, value=value):
                provider = Provider()

                def action(
                    event,
                    remaining,
                    operation=operation,
                    value=value,
                    provider=provider,
                ):
                    if event["operation"] == operation:
                        provider.events.append(event)
                        return value
                    return provider(event, remaining)

                io = ExecutableIO(action)
                context = self.context(state=ChannelState(api_version=1))
                with (
                    patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
                    self.assertRaises(error),
                ):
                    executable_reconnect(context, io, 6)
                self.assertFalse(
                    any(e["operation"] == "passthru_open" for e in provider.events)
                )
                self.assertEqual(io.close(), [])

    def test_alternate_marker_query_and_reconnect_use_shared_name_composition(self):
        context, io, provider = self.run_connect(
            protocol=6,
            state=ChannelState(api_version=1),
            provider=Provider(marker=True),
        )
        with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
            self.assertTrue(get_mode(context, io))
            executable_reconnect(context, io, 6)
        names = [
            e["name"] for e in provider.events if e["operation"] == "passthru_open"
        ]
        self.assertEqual(names, ["authored-prefix:authored selected device"] * 3)
        close(context, io)
        self.assertEqual(io.close(), [])

    def test_selected_library_produces_native_driver_kind_from_actual_name(self):
        for build in (12, 18):
            for name, expected in (
                ("authored-first-driver", 0),
                ("authored-delayed-driver", 1),
                ("authored-delayed-driver authored-first-driver", 0),
                ("unknown", 2),
                ("AUTHORED-DELAYED-DRIVER", 2),
            ):
                with self.subTest(build=build, name=name):
                    context = self.context(build)
                    with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
                        selected = channel.select_library(
                            context,
                            (name, "vendor", "selected-source-library", "config"),
                        )
                        self.assertEqual(selected.native_kind, expected)
                        self.assertEqual(
                            channel.selected_driver_delay(context), expected == 1
                        )
                        provider = Provider()
                        io = ExecutableIO(provider)
                        executable_reconnect(context, io, 6)
                        selected_load = next(
                            e
                            for e in provider.events
                            if e["operation"] == "passthru_load_library"
                        )
                        self.assertEqual(
                            selected_load["path"], "selected-source-library"
                        )
                        executable_reconnect(context, io, 3)
                        self.assertIs(channel_state(context).selected_library, selected)
                        self.assertEqual(
                            channel.selected_driver_delay(context), expected == 1
                        )
                    close(context, io)
                    self.assertEqual(io.close(), [])

    def test_selected_library_requires_source_model_and_valid_actual_fields(self):
        context = self.context()
        with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
            with self.assertRaises(ValueError):
                channel.selected_driver_delay(context)
            for fields in (
                ("name",),
                ("name", "vendor", "", "config"),
                ("bad\x00name", "vendor", "library", "config"),
            ):
                with self.subTest(fields=fields), self.assertRaises(ValueError):
                    channel.select_library(context, fields)  # pyright: ignore[reportArgumentType] - malformed ABI boundary vector
        provider = Provider()
        with self.assertRaises(ValueError):
            channel.select_library(context, ("name", "vendor", "library", "config"))
        self.assertEqual(provider.events, [])

    def test_marker_branch_calls_only_resolved_marker_twice(self):
        context, io, provider = self.run_connect(provider=Provider(marker=True))
        calls = [e for e in provider.events if e["operation"] == "call_symbol"]
        self.assertEqual(
            [(e["symbol"], e["args"]) for e in calls], [(900, (0, 0)), (900, (1, 0))]
        )
        self.assertFalse(
            any(e["operation"] == "passthru_read_version" for e in provider.events)
        )
        close(context, io)

    def test_mode_two_rejects_busy_device_and_cleans_all(self):
        provider = Provider(version="authored-version", mode=1)
        io = ExecutableIO(provider)
        context = self.context()
        with (
            patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
            self.assertRaises(ExecutableJ2534Error),
        ):
            reconnect(context, io, 6)
        self.assertIsNone(channel_state(context).device)
        self.assertEqual(io.close(), [])
        self.assertEqual(provider.events[-1]["operation"], "free_library")

    def test_every_acquisition_fault_rolls_back_only_owned_resources(self):
        for operation in (
            "get_symbol",
            "passthru_load_library",
            "passthru_open",
            "passthru_connect",
            "start_filter",
        ):
            with self.subTest(operation=operation):
                provider = Provider(
                    fault=lambda e, operation=operation: e["operation"] == operation
                )
                io = ExecutableIO(provider)
                context = self.context()
                with (
                    patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
                    self.assertRaises((ExecutableJ2534Error, NativeTransportError)),
                ):
                    reconnect(context, io, 3)
                self.assertEqual(io.close(), [])
                state = channel_state(context)
                self.assertIsNone(state.channel)
                self.assertIsNone(state.device)
                self.assertIsNone(state.library)

    def test_reconnect_drops_existing_channel_before_native_reopen(self):
        context, io, provider = self.run_connect()
        provider.events.clear()
        with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
            reconnect(context, io, 6)
        operations = [e["operation"] for e in provider.events]
        self.assertLess(
            operations.index("passthru_disconnect"),
            operations.index("passthru_connect"),
        )
        self.assertEqual(channel_state(context).protocol, 6)
        close(context, io)

    def test_source_sha_rejection_happens_before_any_provider_call(self):
        provider = Provider()
        with self.assertRaises(ValueError):
            reconnect(self.context(), ExecutableIO(provider), 3)
        self.assertEqual(provider.events, [])

    def test_forged_ownership_and_invalid_protocol_are_rejected(self):
        provider = Provider()
        for state in (ChannelState(library=9), ChannelState(device=9)):
            with (
                patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
                self.assertRaises(ValueError),
            ):
                reconnect(self.context(state=state), ExecutableIO(provider), 3)
        for protocol in (True, -1, 2**32):
            with self.assertRaises(ValueError):
                reconnect(self.context(), ExecutableIO(provider), protocol)
        self.assertEqual(provider.events, [])

    def test_cancellation_after_channel_acquisition_releases_all_resources(self):
        cancelled = [False]
        provider = Provider()

        def action(event, remaining):
            result = provider(event, remaining)
            if event["operation"] == "passthru_connect":
                cancelled[0] = True
            return result

        io = ExecutableIO(
            action, cancelled=lambda: cancelled[0], cleanup_action=provider
        )
        context = self.context()
        with (
            patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
            self.assertRaises(InterruptedError),
        ):
            reconnect(context, io, 3)
        self.assertEqual(io.close(), [])
        self.assertEqual(provider.events[-1]["operation"], "free_library")

    def test_disconnect_does_not_free_shared_shim(self):
        context, io, _provider = self.run_connect()
        disconnect(context, io)
        self.assertIsNotNone(channel_state(context).library)
        close(context, io)

    def test_saved_12_and_18_layouts_retain_timeouts_padding_and_filter_count(self):
        for build in (12, 18):
            data = bytearray(0x78 if build == 12 else 0xAC)
            read_at, send_at, count_at, flags_at = (
                (0x18, 0x1C, 0x28, 0x34) if build == 12 else (0x1C, 0x20, 0x3C, 0x48)
            )
            for offset, value in ((read_at, 77), (send_at, 88), (count_at, 1)):
                data[offset : offset + 4] = value.to_bytes(4, "little")
            data[flags_at + 2] = 1
            data[flags_at + 3] = 0
            state = restore_state(
                build, bytes(data), ExecutableIO(Provider()), driver_loaded=False
            )
            self.assertEqual(
                (
                    state.read_timeout,
                    state.send_timeout,
                    state.padding,
                    state.flag_66,
                    state.filter_count,
                ),
                (77, 88, False, True, 1),
            )
            context, io, provider = self.run_connect(build, state=state)
            self.assertEqual(
                len([e for e in provider.events if e["operation"] == "start_filter"]), 1
            )
            self.assertEqual(
                (state.read_timeout, state.send_timeout, state.padding), (77, 88, False)
            )
            close(context, io)
            data[flags_at + 3] = 2
            with self.assertRaises(ValueError):
                restore_state(
                    build, bytes(data), ExecutableIO(Provider()), driver_loaded=False
                )

    def test_native_disconnect_status_clears_active_ram_but_retains_host_owner(self):
        context, io, provider = self.run_connect(protocol=6)
        channel = channel_state(context).channel
        failed = [False]

        def fault(event):
            if event["operation"] == "passthru_disconnect" and not failed[0]:
                failed[0] = True
                return True
            return False

        provider.fault = fault
        disconnect(context, io)
        self.assertIsNone(channel_state(context).channel)
        self.assertTrue(io.owns_resource("passthru_disconnect", channel=channel))
        close(context, io)
        self.assertFalse(io.owns_resource("passthru_disconnect", channel=channel))
        self.assertEqual(io.close(), [])

    def test_native_stop_filter_fault_can_reconnect_without_losing_old_ownership(self):
        context, io, provider = self.run_connect()
        failed = [False]

        def fault(event):
            if event["operation"] == "stop_filter" and not failed[0]:
                failed[0] = True
                raise ExecutableJ2534Error(1, 7)
            return False

        provider.fault = fault
        with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
            reconnect(context, io, 3)
        self.assertTrue(channel_state(context).retired)
        close(context, io)
        self.assertEqual(io.close(), [])

    def test_reconnect_disconnect_swallows_each_native_exception_domain(self):
        for error in (ExecutableForeignNativeError("foreign"), ExecutableCANError(7)):
            with self.subTest(error=type(error).__name__):
                context, io, provider = self.run_connect()
                raised = False

                def fault(event, error=error):
                    nonlocal raised
                    if event["operation"] == "stop_filter" and not raised:
                        raised = True
                        raise error
                    return False

                provider.fault = fault
                with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
                    executable_reconnect(context, io, 6)
                self.assertTrue(raised)
                self.assertEqual(channel_state(context).protocol, 6)
                self.assertTrue(channel_state(context).retired)
                close(context, io)
                self.assertEqual(io.close(), [])

    def test_reconnect_disconnect_host_failures_preserve_identity_and_do_not_connect(
        self,
    ):
        for error in (
            OSError("host"),
            ValueError("host"),
            InterruptedError("host"),
            KeyboardInterrupt("host"),
        ):
            with self.subTest(error=type(error).__name__):
                context, io, provider = self.run_connect()
                provider.events.clear()

                def fault(event, error=error):
                    if event["operation"] == "stop_filter":
                        raise error
                    return False

                provider.fault = fault
                with (
                    patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
                    self.assertRaises(type(error)) as caught,
                ):
                    executable_reconnect(context, io, 6)
                self.assertIs(caught.exception, error)
                self.assertFalse(
                    any(e["operation"] == "passthru_connect" for e in provider.events)
                )
                provider.fault = None
                close(context, io)
                self.assertEqual(io.close(), [])

    def test_reconnect_connect_native_errors_propagate_identity(self):
        for error in (
            ExecutableJ2534Error(1, 7),
            ExecutableForeignNativeError("foreign"),
            ExecutableCANError(7),
        ):
            with self.subTest(error=type(error).__name__):
                provider = Provider()

                def fault(event, error=error):
                    if event["operation"] == "passthru_connect":
                        raise error
                    return False

                provider.fault = fault
                context = self.context()
                io = ExecutableIO(provider)
                with (
                    patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
                    self.assertRaises(type(error)) as caught,
                ):
                    executable_reconnect(context, io, 6)
                self.assertIs(caught.exception, error)
                self.assertIsNone(channel_state(context).library)
                self.assertEqual(io.close(), [])

    def test_marker_mode_query_native_close_open_close_and_device_zero_restore(self):
        context, io, provider = self.run_connect(
            protocol=6, provider=Provider(marker=True)
        )
        provider.events.clear()
        with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
            self.assertTrue(get_mode(context, io))
        calls = [e["args"] for e in provider.events if e["operation"] == "call_symbol"]
        self.assertEqual(calls, [(0, 0), (4, 0), (0, 0)])
        self.assertEqual(channel_state(context).device, 0)
        self.assertTrue(io.owns_resource("passthru_close", device=0))
        close(context, io)
        self.assertEqual(io.close(), [])

    def test_set_mode_generates_signed_byte_marker_arguments(self):
        context, io, provider = self.run_connect(
            protocol=6, provider=Provider(marker=True)
        )
        provider.events.clear()
        with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
            self.assertTrue(set_mode(context, io, -1))
        self.assertEqual(
            [e["args"] for e in provider.events if e["operation"] == "call_symbol"],
            [(0, 0), (-1, 0)],
        )
        close(context, io)

    def test_null_library_is_never_owned_or_freed(self):
        provider = Provider()

        def action(event, remaining):
            if event["operation"] == "load_library":
                provider.events.append(event)
                return 0
            return provider(event, remaining)

        context = self.context()
        io = ExecutableIO(action)
        with (
            patch("scripts.cuw_legacy_channel.ExecutableImage", Image),
            self.assertRaises(OSError),
        ):
            reconnect(context, io, 6)
        self.assertEqual([e["operation"] for e in provider.events], ["load_library"])
        self.assertIsNone(channel_state(context).library)
        self.assertEqual(io.close(), [])

    def test_missing_marker_library_falls_back_to_native_read_version(self):
        provider = Provider()

        def action(event, remaining):
            if (
                event["operation"] == "load_library"
                and event["path"] == "authored-driver"
            ):
                provider.events.append(event)
                return 0
            return provider(event, remaining)

        context = self.context()
        io = ExecutableIO(action)
        with patch("scripts.cuw_legacy_channel.ExecutableImage", Image):
            reconnect(context, io, 6)
        self.assertTrue(
            any(e["operation"] == "passthru_read_version" for e in provider.events)
        )
        self.assertFalse(
            any(
                e["operation"] == "free_library" and e["library"] == 0
                for e in provider.events
            )
        )
        close(context, io)


if __name__ == "__main__":
    unittest.main()
