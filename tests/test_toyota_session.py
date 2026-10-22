"""Authored replay vectors; never physical vehicle traffic."""

import json
import struct
import unittest
from typing import TYPE_CHECKING, Literal, cast
from unittest.mock import Mock, call, patch

if TYPE_CHECKING:
    from scripts.monitor_support import MonitorSupportCache
    from scripts.profiles import VehicleProfile

from scripts.diagnostic_db import Database, Section
from scripts.drive_recorder import (
    NativeCoreBuffer,
    NativeVimClient,
    NativeVimReply,
    encode_vim_command,
)
from scripts.toyota import SHORT_REPLY, CommandFrame, ToyotaCodecError
from scripts.toyota_session import (
    ActiveTest,
    Cancelled,
    CommandSpec,
    CountFamily,
    DtcFreeze,
    FreezeSample,
    FunctionCache,
    LegacyActiveQueue,
    Limits,
    NativeFrameSend,
    NativeStatus,
    P5ActiveQueue,
    SessionError,
    StatusRule,
    TeslaDtcDefinition,
    ToyotaSession,
    absolute_time_values,
    active_arguments_p5,
    active_reply_p5,
    active_request_dk,
    active_request_dlc12,
    active_request_p3,
    active_request_p4,
    active_request_psa,
    active_requests_p5,
    analyze_p5_diagnostic_reply_profile,
    apply_freeze_time_indices,
    assemble_absolute_log,
    associate_freeze,
    comm_did_request,
    comm_ecu_support_p4,
    comm_signal_data,
    compare_timestamp,
    decode_bcd32,
    decode_comm_pid_reply,
    diag_type,
    dk_iso_freeze_value,
    dtc_information,
    dtc_information_profile,
    dtc_metadata_p5_profile,
    dtc_metadata_profile,
    dtc_status_rules_profile,
    expand_supported_pid,
    ffd_existence_flag,
    ffd_type,
    format_dtc,
    freeze_support_code,
    freeze_support_request,
    health_check,
    index_freeze_samples,
    normalize_sienna_dtcs,
    order_freeze_samples,
    p5_data_id_samples,
    parse_dk_freeze,
    parse_dk_iso_dtcs,
    parse_dk_iso_freeze,
    parse_p5_dtcs,
    parse_p5_freeze,
    parse_psa_add_ht_dtcs,
    parse_psa_audio_dtcs,
    parse_psa_dtcs,
    parse_subaru_stored_freeze,
    parse_tesla_dtcs,
    routine_arguments_p5,
    routine_request_p5,
    routine_status_p5,
    routine_support_bit,
    scale_signal,
)


class Replay:
    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = []

    def __call__(self, ecu, request):
        self.calls.append((ecu, request))
        if not self.steps:
            raise AssertionError("Unexpected exchange")
        expected, result = self.steps.pop(0)
        if request != expected:
            raise AssertionError((request, expected))
        if isinstance(result, BaseException):
            raise result
        return result


def spec(request=b"\x18", **kwargs):
    return CommandSpec(CommandFrame(request), **kwargs)


def selected_profile(functions=(6, 7, 8, 9, 10, 11, 12, 107, 125, 126)):
    rows = []
    for key in functions:
        row = bytearray(16)
        struct.pack_into("<HH", row, 0, 0x23, key)
        rows.append(bytes(row))
    management = Database(
        1,
        0x01000312,
        "authored",
        {18: Section(18, 0, len(rows), False, b"".join(rows))},
    )
    profile = Mock(category=0x23, exception_ids=(), catalog=Mock(management=management))
    profile.records.return_value = ()
    return profile


class SessionTests(unittest.TestCase):
    def test_operation_freeze_p4_conditional_control_and_late_support(self):
        freeze = bytearray(84)
        freeze[79] = 2
        struct.pack_into("<HH", freeze, 62, 0, 7)
        cache = Mock()
        cache.support_bits.return_value = {2: b"\x01"}
        replay = Replay(
            [
                (b"\x12\x03\xaa\x02\x00\x00", b"\x52\x03\xaa\x02\x55"),
                (b"\x12\x03\x04\x02\x00\x00", b"\x52\x03\x04\x02\x66"),
            ]
        )
        session = ToyotaSession(
            replay, "ecu", {"operation": spec(b"\x12\x00\xaa\x00\x00\x00")}
        )
        self.assertEqual(
            session.freeze_operation_p4(
                "operation",
                bytes(freeze),
                3,
                0,
                support_cache=cast("MonitorSupportCache", cache),
            ),
            b"\x55",
        )
        self.assertEqual(
            session.freeze_operation_p4(
                "operation",
                bytes(freeze),
                3,
                4,
                support_cache=cast("MonitorSupportCache", cache),
            ),
            b"\x66",
        )
        self.assertFalse(replay.steps)

    def test_oseng_dtc_forced_current_request_and_zero_codes_do_not_terminate(self):
        profile = selected_profile()
        frame_map = {
            7: CommandFrame(b"\x17"),
            125: CommandFrame(b"\x10", b"\xff", b"\x50"),
            10: CommandFrame(b"\x18"),
        }
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=frame_map[function],
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        functions = Mock()
        functions.function.return_value = (False, 0)
        replay = Replay(
            [
                (b"\x17", b"\x57\x00\x04"),
                (b"\x10", b"\x50"),
                (b"\x13\x00\x00", bytes.fromhex("53 00 00 12 34 00 00")),
                (b"", bytes.fromhex("53 56 78")),
            ]
        )
        result = ToyotaSession(replay, "ecu", {}).dtcs_os_eng_profile(
            cast("VehicleProfile", profile), 1, cast(FunctionCache, functions)
        )
        self.assertEqual(result["codes"], [0x1234, 0x5678])
        self.assertFalse(replay.steps)

    def test_oseng_nonzero_count_checks_ffd_even_when_all_codes_zero(self):
        profile = selected_profile()
        frame_map = {
            8: CommandFrame(b"\x17"),
            11: CommandFrame(b"\x18"),
            6: CommandFrame(b"\x12\x00\x00", b"\x00\xff\xff"),
        }
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=frame_map[function],
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        profile.records.side_effect = lambda slot: (
            (b"\x00\x00\x01\x00",) if slot == 2 else ()
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        replay = Replay(
            [
                (b"\x17", bytes.fromhex("57 00 00 01")),
                (b"\x18", bytes.fromhex("58 00 00")),
                (b"\x12\x00\x01", bytes.fromhex("52 00 00")),
            ]
        )
        result = ToyotaSession(replay, "ecu", {}).dtcs_os_eng_profile(
            cast("VehicleProfile", profile), 2, cast(FunctionCache, functions)
        )
        self.assertEqual(result["codes"], [])
        functions.function.assert_called_once_with(1, 4, 3)
        self.assertFalse(replay.steps)

    def test_carb_dtc_masked_count_zero_skips_read(self):
        profile = selected_profile()
        profile.frame_records.return_value = (
            Mock(
                frame=CommandFrame(b"\x17", b"\x00\x00\xf0"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        functions = Mock()
        replay = Replay([(b"\x17", b"\x57\x00\x0f")])
        result = ToyotaSession(replay, "ecu", {}).dtcs_carb_profile(
            cast("VehicleProfile", profile), cast(FunctionCache, functions)
        )
        self.assertEqual(result["codes"], [])
        self.assertEqual(cast(dict[str, int], result["count_observation"])["count"], 0)
        profile.frame_records.assert_called_once_with(7)
        functions.function.assert_not_called()

    def test_carb_dtc_masked_count_nonzero_reads_function_a(self):
        profile = selected_profile()
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(b"\x17", b"\x00\x00\x0f")
                if function == 7
                else CommandFrame(b"\x18"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        functions = Mock()
        functions.function.return_value = (False, 0)
        replay = Replay(
            [(b"\x17", b"\x57\x00\xf1"), (b"\x18", bytes.fromhex("58 12 34 00 00"))]
        )
        result = ToyotaSession(replay, "ecu", {}).dtcs_carb_profile(
            cast("VehicleProfile", profile), cast(FunctionCache, functions)
        )
        self.assertEqual(result["codes"], [0x1234])
        self.assertEqual(cast(dict[str, int], result["count_observation"])["count"], 1)
        with self.assertRaises(ToyotaCodecError):
            ToyotaSession(Replay([]), "ecu", {}).dtcs_carb_profile(
                cast("VehicleProfile", profile),
                cast(FunctionCache, functions),
                diagnostic_type=2,
            )

    def test_no_frame_number_dtc_wrapper_uses_fixed_reply_code_positions(self):
        profile = selected_profile()
        frames = {7: b"\x17", 10: b"\x18", 6: b"\x12\x00\x00"}
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(frames[function]),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        profile.records.side_effect = lambda slot: (
            (b"\x00\x00\x03\x00", b"\x00\x00\x01\x00") if slot == 2 else ()
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        replay = Replay(
            [
                (b"\x17", b"\x57\x00\x01"),
                (b"\x18", bytes.fromhex("58 12 34 00 00")),
                (b"\x12\x00\x03", bytes.fromhex("52 00 12 34")),
                (b"\x12\x00\x01", bytes.fromhex("52 00 00 12 34")),
            ]
        )
        result = ToyotaSession(replay, "ecu", {}).dtcs_no_frame_number_profile(
            cast("VehicleProfile", profile), 1, cast(FunctionCache, functions)
        )
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234, True, 1),))
        self.assertFalse(replay.steps)

    def test_selected_dtc_metadata_failure_stops_before_continuation_or_retry(self):
        for family in ("kwp", "can"):
            with self.subTest(family=family):
                profile = selected_profile()
                settings = bytearray(16)
                settings[14] = 2
                profile.frame_records.return_value = (
                    Mock(
                        frame=CommandFrame(b"\x18"),
                        settings_record=bytes(settings),
                        provenance="selected",
                    ),
                )
                profile.records.side_effect = ToyotaCodecError(
                    "Selected metadata failure", 77
                )
                reply = (
                    bytes.fromhex("58 12 34 12 35 12 36")
                    if family == "kwp"
                    else bytes.fromhex("58 03 12 34")
                )
                replay = Replay([(b"\x18", reply)])
                session = ToyotaSession(replay, "ecu", {})
                with self.assertRaises(ToyotaCodecError) as raised:
                    if family == "kwp":
                        session.dtcs_profile(cast("VehicleProfile", profile), 10)
                    else:
                        session.dtcs_can_profile(
                            cast("VehicleProfile", profile),
                            1,
                            cast(FunctionCache, Mock()),
                        )
                self.assertEqual(raised.exception.code, 77)
                self.assertEqual(len(replay.calls), 1)

    def test_selected_can_visibility_filters_before_ffd_gate(self):
        profile = selected_profile()
        profile.frame_records.return_value = (
            Mock(
                frame=CommandFrame(b"\x18"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        row = bytearray(28)
        struct.pack_into("<H", row, 20, 0x1234)
        profile.records.return_value = (bytes(row),)
        functions = Mock()
        session = ToyotaSession(
            Replay([(b"\x18", bytes.fromhex("58 01 12 34"))]), "ecu", {}
        )
        result = session.dtcs_can_profile(
            cast("VehicleProfile", profile), 1, cast(FunctionCache, functions)
        )
        self.assertEqual(result, {"codes": [], "freeze_records": ()})
        functions.function.assert_not_called()

    def test_native_dtc_metadata_visibility_and_fallback(self):
        profile = selected_profile()
        row = bytearray(28)
        row[:12] = "P1234\0".encode("utf-16le")
        struct.pack_into("<II", row, 12, 2, 3)
        struct.pack_into("<H", row, 20, 0x1234)
        profile.records.return_value = (bytes(row),)
        profile.catalog.language.resolve.side_effect = lambda key: {
            1: "P1234-native",
            2: "native name",
            3: "comment",
        }[key]
        self.assertIsNone(dtc_metadata_profile(cast("VehicleProfile", profile), 0x1234))
        item = dtc_metadata_profile(
            cast("VehicleProfile", profile), 0x1234, include_disabled=True
        )
        self.assertEqual(
            item,
            {
                "code": 0x1234,
                "signature": "P1234",
                "name": "native name",
                "comment": "comment",
                "native_field_1c": 2,
            },
        )
        row[26] = 1
        profile.records.return_value = (bytes(row),)
        self.assertEqual(
            dtc_metadata_profile(cast("VehicleProfile", profile), 0x1234), item
        )
        self.assertEqual(
            dtc_metadata_profile(cast("VehicleProfile", profile), 0),
            {
                "code": 0,
                "signature": "P0000",
                "name": "???",
                "comment": "",
                "native_field_1c": 0,
            },
        )
        profile.records.reset_mock()
        fallback = dtc_metadata_profile(
            cast("VehicleProfile", profile), 0x1234, lookup_mode=1
        )
        assert fallback is not None
        self.assertEqual(fallback["name"], "???")
        profile.records.assert_not_called()

    def test_original_legacy_dtc_append_retains_duplicate_codes(self):
        replay = Replay([(b"\x18", bytes.fromhex("58 12 34 12 34 00 00"))])
        self.assertEqual(
            ToyotaSession(replay, "ecu", {"dtc": spec()}).dtcs("dtc"), [0x1234, 0x1234]
        )
        replay = Replay([(b"\x18", bytes.fromhex("58 02 12 34 12 34"))])
        self.assertEqual(
            ToyotaSession(replay, "ecu", {"dtc": spec()}).dtcs_can("dtc"),
            [0x1234, 0x1234],
        )
        self.assertEqual(parse_dk_iso_dtcs(b"\x11\x11\x00\x22"), [0x11, 0x11])

    def test_dlc12_selected_comtol_command_and_low_byte_count(self):
        profile = selected_profile()
        profile.frame_records.return_value = (
            Mock(frame=CommandFrame(b"\x03", b"\x12\x34")),
        )
        seen = []
        data = b"\x11\x11\x00\x22" + bytes(256)

        def exchange(request, *, deadline, cancelled):
            seen.append(request)
            return NativeVimReply(
                0x30FF, 6, bytes(4) + NativeCoreBuffer((1, 0), data).encode()
            ).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control"})
        )
        result = ToyotaSession(Replay([]), "ecu", {}).dtcs_dlc12_profile(
            cast("VehicleProfile", profile), client
        )
        self.assertEqual(result, [0x11, 0x11, 0, 0x22])
        self.assertEqual(seen, [encode_vim_command(0x307F, b"\x03\x12\x34")])
        profile.frame_records.assert_called_once_with(10)

    def test_dlc12_transport_nak_uses_original_comtol_status_mapping(self):
        profile = selected_profile()
        profile.frame_records.return_value = (
            Mock(frame=CommandFrame(b"\x03", b"\x12\x34")),
        )
        for native, expected in (
            (0x900D0017, 8),
            (0x900D0018, 8),
            (0x900D002C, 7),
            (77, 77),
        ):
            with self.subTest(native=native):
                client = NativeVimClient(
                    lambda request, *, native=native, **kwargs: NativeVimReply(
                        0x30FF, 0x15, b"", native
                    ).encode(),
                    capabilities=frozenset({"denso-vim-control"}),
                )
                session = ToyotaSession(Replay([]), "ecu", {})
                with self.assertRaises(NativeStatus) as raised:
                    session.dtcs_dlc12_profile(cast("VehicleProfile", profile), client)
                self.assertEqual(raised.exception.code, expected)

    def test_dlc12_native_status_and_post_io_cancel(self):
        profile = selected_profile()
        profile.frame_records.return_value = (
            Mock(frame=CommandFrame(b"\x03", b"\x12\x34")),
        )
        cancelled = [False]

        def exchange(request, *, deadline, cancelled):
            return NativeVimReply(
                0x30FF,
                6,
                struct.pack("<I", 77) + NativeCoreBuffer((1, 0), b"").encode(),
            ).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control"})
        )
        session = ToyotaSession(Replay([]), "ecu", {}, cancelled=lambda: cancelled[0])
        with self.assertRaises(NativeStatus) as raised:
            session.dtcs_dlc12_profile(cast("VehicleProfile", profile), client)
        self.assertEqual(raised.exception.code, 77)

        def cancel_exchange(request, *, deadline, cancelled):
            # The session policy must win even if an external provider throws.
            globals_cancel[0] = True
            raise NativeStatus(77)

        globals_cancel = cancelled
        client = NativeVimClient(
            cancel_exchange, capabilities=frozenset({"denso-vim-control"})
        )
        with self.assertRaises(Cancelled):
            session.dtcs_dlc12_profile(cast("VehicleProfile", profile), client)

    def test_can_profile_p4v2_type3_skips_ffd_and_first_frame_only(self):
        profile = selected_profile()
        profile.frame_records.return_value = (
            Mock(
                frame=CommandFrame(b"\x19"),
                settings_record=bytes(16),
                provenance="first",
            ),
            Mock(
                frame=CommandFrame(b"\x20"),
                settings_record=bytes(16),
                provenance="unused",
            ),
        )
        functions = Mock()
        replay = Replay([(b"\x19", b"\x59\x01\x12\x34")])
        result = ToyotaSession(replay, "ecu", {}).dtcs_can_profile(
            cast("VehicleProfile", profile),
            3,
            cast(FunctionCache, functions),
            family="p4_v2",
        )
        self.assertEqual(result["codes"], [0x1234])
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234),))
        profile.frame_records.assert_called_once_with(12)
        functions.function.assert_not_called()

    def test_can_profile_carbcan_type3_still_checks_ffd(self):
        profile = selected_profile()
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(
                    b"\x19" if function == 12 else b"\x12\x00\x00",
                    b"" if function == 12 else b"\x00\xff\xff",
                ),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        profile.records.side_effect = lambda slot: (
            (b"\x00\x00\x02\x00",) if slot == 2 else ()
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        replay = Replay(
            [
                (b"\x19", b"\x59\x01\x12\x34"),
                (b"", b"\x59\x00"),
                (b"\x12\x00\x02", b"\x52\x12\x34"),
            ]
        )
        result = ToyotaSession(replay, "ecu", {}).dtcs_can_profile(
            cast("VehicleProfile", profile),
            3,
            cast(FunctionCache, functions),
            family="carb_can",
        )
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234, True, 2),))
        functions.function.assert_called_once_with(1, 4, 3)
        self.assertFalse(replay.steps)

    def test_p4_freeze_discovers_support_after_wire_and_reuses_reply(self):
        order = []
        freeze = bytearray(84)
        freeze[79] = 2
        struct.pack_into("<HH", freeze, 62, 0, 15)
        cache = Mock()

        def support(kind):
            order.append("support")
            self.assertEqual(kind, 1)
            return {2: b"\x01\x00\x01"}

        cache.support_bits.side_effect = support

        def exchange(ecu, request):
            order.append("wire")
            self.assertEqual(request, b"\x12\x01\x00\x02\x00\x00")
            return b"\x52\x01\x00\x02\x11\x22"

        session = ToyotaSession(
            exchange, "ecu", {"ffd": spec(b"\x12\x00\x00\x00\x00\x00")}
        )
        responses = {}
        for _ in range(2):
            self.assertEqual(
                session.freeze_p4(
                    "ffd",
                    bytes(freeze),
                    1,
                    support_cache=cast("MonitorSupportCache", cache),
                    response_cache=responses,
                ),
                b"\x11\x00\x22",
            )
        self.assertEqual(order, ["wire", "support", "support"])
        cache.support_bits.side_effect = lambda kind: {}
        with self.assertRaises(ToyotaCodecError) as raised:
            session.freeze_p4(
                "ffd",
                bytes(freeze),
                1,
                support_cache=cast("MonitorSupportCache", cache),
                response_cache=responses,
            )
        self.assertEqual(raised.exception.code, 0xC0040001)

    def test_wo_count_reads_even_zero_count_and_attaches_selected_freezes(self):
        profile = selected_profile()
        frame_map = {
            7: (
                Mock(
                    frame=CommandFrame(b"\x17"),
                    settings_record=bytes(16),
                    provenance="count",
                ),
            ),
            10: (
                Mock(
                    frame=CommandFrame(b"\x18"),
                    settings_record=bytes(16),
                    provenance="codes",
                ),
            ),
            6: (
                Mock(
                    frame=CommandFrame(b"\x12\x00\x00", b"\x00\xff\xff"),
                    settings_record=bytes(16),
                    provenance="freeze",
                ),
            ),
        }
        profile.frame_records.side_effect = lambda function: frame_map[function]
        profile.records.side_effect = lambda slot: (
            (b"\x00\x00\x03\x00", b"\x00\x00\x01\x00") if slot == 2 else ()
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        replay = Replay(
            [
                (b"\x17", b"\x57\x00\x00"),
                (b"\x18", b"\x58\x12\x34\x00\x00"),
                (b"\x12\x00\x03", b"\x52\x12\x34"),
                (b"\x12\x00\x01", b"\x52\x12\x34"),
            ]
        )
        result = ToyotaSession(replay, "ecu", {}).dtcs_without_count_profile(
            cast("VehicleProfile", profile), 1, cast(FunctionCache, functions)
        )
        self.assertEqual(result["codes"], [0x1234])
        self.assertEqual(cast(dict[str, int], result["count_observation"])["count"], 0)
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234, True, 1),))
        functions.function.assert_called_once_with(1, 4, 3)
        self.assertFalse(replay.steps)

    def test_wo_count_preserves_one_budget_and_empty_list_skips_support(self):
        profile = selected_profile()
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(bytes((0x17 if function == 7 else 0x18,))),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        functions = Mock()
        replay = Replay([(b"\x17", b"\x57\x00\x01"), (b"\x18", b"\x58\x00")])
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=1))
        with self.assertRaises(SessionError):
            session.dtcs_without_count_profile(
                cast("VehicleProfile", profile), 1, cast(FunctionCache, functions)
            )
        self.assertEqual(len(replay.calls), 1)
        functions.function.assert_not_called()
        replay = Replay([(b"\x17", b"\x57\x00\x01"), (b"\x18", b"\x58\x00")])
        result = ToyotaSession(replay, "ecu", {}).dtcs_without_count_profile(
            cast("VehicleProfile", profile), 1, cast(FunctionCache, functions)
        )
        self.assertEqual(result["freeze_records"], ())
        functions.function.assert_not_called()
        profile.records.assert_not_called()

    def test_multi_freeze_info_selected_raw_comm_ecu_cache(self):
        rows = []
        for kind, begin, end in ((1, 0, 7), (2, 8, 15), (3, 0, 7)):
            row = bytearray(12)
            struct.pack_into("<HHH", row, 0, kind, begin, end)
            row[8] = 1
            rows.append(bytes(row))
        profile = selected_profile()
        profile.database.sections = {38: object()}
        profile.records.return_value = tuple(rows)
        profile.frame_records.return_value = (
            Mock(
                frame=CommandFrame(b"\x21\x00"),
                provenance="selected",
                settings_record=bytes(16),
            ),
        )
        cache = Mock()
        cache.support_bits.return_value = {1: b"\xff\xff"}
        cache.enabled_pids.return_value = {1: 2}
        functions = Mock()
        replay = Replay([(b"\x21\x01", b"\x61\x01\x12\x34")])
        session = ToyotaSession(replay, "ecu", {})
        result = session.multi_freeze_info(
            cast("VehicleProfile", profile),
            cast(FunctionCache, functions),
            support_cache=cast("MonitorSupportCache", cache),
        )
        self.assertEqual(
            result, {"supported": True, "out1": 18, "out2": 52, "out3": 18}
        )
        self.assertEqual(len(replay.calls), 1)
        functions.function.assert_not_called()
        cache.enabled_pids.assert_called_with(family="p4", kind=1, control=0)
        self.assertFalse(comm_ecu_support_p4(rows[0], {1: 2}, {1: b"\x00\x00"}))
        self.assertTrue(comm_ecu_support_p4(rows[0], {1: 2}, {1: b"\x01\x00"}))

    def test_comm_ecu_support_wide_native_dword_extraction(self):
        row = bytearray(12)
        row[8] = 1
        for end in (32, 39):
            struct.pack_into("<HH", row, 2, 0, end)
            self.assertTrue(
                comm_ecu_support_p4(bytes(row), {1: 5}, {1: b"\x01\0\0\0\0"})
            )
            self.assertFalse(comm_ecu_support_p4(bytes(row), {1: 5}, {1: bytes(5)}))
        struct.pack_into("<HH", row, 2, 0, 40)
        self.assertFalse(comm_ecu_support_p4(bytes(row), {1: 5}, {1: bytes(5)}))
        struct.pack_into("<HH", row, 2, 10, 9)
        with self.assertRaises(ToyotaCodecError) as error:
            comm_ecu_support_p4(bytes(row), {1: 5}, {1: bytes(5)})
        self.assertEqual(error.exception.code, 0xC0040102)

    def test_selected_comm_ecu_read_preserves_native_wide_dword(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            for end, expected in ((32, 0x02000000), (39, 1), (40, None)):
                with self.subTest(build=build, end=end):
                    profile = self.native_legacy_freeze_profile_fixture(
                        build, ((0x6B, b"\x21\0"),)
                    )
                    row = bytearray(12)
                    struct.pack_into("<HH", row, 2, 0, end)
                    row[8] = 1
                    operations = Mock()
                    operations.send.return_value = 0
                    operations.receive.return_value = SimpleNamespace(
                        code=0, data=b"\x61\x01\x01\0\0\0\0"
                    )
                    communication = NativeCommunication(
                        profile, operations, "ecu", bus_id=0x12, source_build=build
                    )
                    workflow = ToyotaWorkflows.from_communication(
                        communication,
                        observations=WorkflowObservations(
                            1, 0x12, source_version=build
                        ),
                    )
                    workflow._begin(source12_verified=True)
                    if expected is None:
                        with self.assertRaises(ToyotaCodecError) as error:
                            workflow.session.read_comm_ecu_p4(
                                profile, bytes(row), bytes((255,)) * 5
                            )
                        self.assertEqual(error.exception.code, SHORT_REPLY)
                    else:
                        self.assertEqual(
                            workflow.session.read_comm_ecu_p4(
                                profile, bytes(row), bytes((255,)) * 5
                            ),
                            expected,
                        )
                    self.assertEqual(operations.receive.call_count, 1)
                    self.assertEqual(operations.send.call_args.args[0], b"\x21\x01")
                    self.assertFalse(communication.closed)

    def test_multi_freeze_info_missing_table_function_fallback(self):
        profile = selected_profile()
        profile.database.sections = {}
        functions = Mock()
        functions.function.side_effect = [(True, 0x123), (True, 2), (True, 0xFFFFFFFE)]
        cache = Mock()
        session = ToyotaSession(Replay([]), "ecu", {})
        self.assertEqual(
            session.multi_freeze_info(
                cast("VehicleProfile", profile),
                cast(FunctionCache, functions),
                support_cache=cast("MonitorSupportCache", cache),
            ),
            {"supported": True, "out1": 0x123, "out2": 2, "out3": 0xFFFFFFFE},
        )
        self.assertEqual(
            [call.args for call in functions.function.call_args_list],
            [(1, 6, 4), (1, 6, 5), (1, 6, 6)],
        )
        cache.support_bits.assert_not_called()

    def test_profile_function_absence_native_code_preserves_malformed_descriptors(self):
        profile = selected_profile(functions=())
        session = ToyotaSession(Replay([]), "ecu", {})
        with self.assertRaises(ToyotaCodecError) as absent:
            session.freeze_diagnostic_code_profile(cast("VehicleProfile", profile), 1)
        self.assertEqual(absent.exception.code, 0xC0040101)
        profile.frame_records.assert_not_called()
        profile = selected_profile()
        profile.frame_records.side_effect = ValueError(
            "Ambiguous communication settings record"
        )
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            session.freeze_diagnostic_code_profile(cast("VehicleProfile", profile), 1)

    def test_freeze_diagnostic_code_selected_masks_patches_and_unwritten(self):
        profile = selected_profile()
        profile.frame_records.return_value = tuple(
            Mock(
                frame=CommandFrame(request, b"\x00\xff\xff"),
                provenance="selected",
                settings_record=bytes(16),
            )
            for request in (b"\x12\x00\x00", b"\x12\x00\x00\x00")
        )
        replay = Replay(
            [
                (b"\x12\x00\x05", NativeStatus(0x91010009)),
                (b"\x12\x05\x00\x00", b"\x52\x12\x34"),
            ]
        )
        session = ToyotaSession(replay, "ecu", {})
        self.assertEqual(
            session.freeze_diagnostic_code_profile(cast("VehicleProfile", profile), 5),
            0x1234,
        )
        profile.frame_records.assert_called_with(6)
        profile.frame_records.return_value = profile.frame_records.return_value[:1]
        session = ToyotaSession(
            Replay([(b"\x12\x00\x05", NativeStatus(0x91010009))]), "ecu", {}
        )
        self.assertIsNone(
            session.freeze_diagnostic_code_profile(
                cast("VehicleProfile", profile), 5, mask_flags=1
            )
        )
        session = ToyotaSession(
            Replay([(b"\x12\x00\x05", NativeStatus(0x91010009))]), "ecu", {}
        )
        with self.assertRaises(NativeStatus) as failure:
            session.freeze_diagnostic_code_profile(cast("VehicleProfile", profile), 5)
        self.assertEqual(failure.exception.code, 0x91010009)

    def test_oseng_count_probe_match_second_match_and_clear(self):
        settings = bytearray(16)
        struct.pack_into("<I", settings, 0, 50)

        def frame(request, expected=b""):
            return Mock(
                frame=CommandFrame(request, b"\xff\xff" if expected else b"", expected),
                provenance="selected",
                settings_record=bytes(settings),
            )

        mapping = {
            7: (frame(b"\x18"),),
            0x7D: (frame(b"\x19", b"\x59\x01"),),
            0x7E: (frame(b"\x1a", b"\x5a\x01"),),
        }
        for first, second, count, flag in (
            (b"\x59\x01", None, 9, 0),
            (b"\x59\x00", b"\x5a\x01", 9, 1),
            (b"\x59\x00", b"\x5a\x00", 0, 0),
        ):
            profile = selected_profile()
            profile.frame_records.side_effect = mapping.__getitem__
            steps = [(b"\x18", b"\x58\x00\x09"), (b"\x19", first)]
            if second is not None:
                steps.append((b"\x1a", second))
            session = ToyotaSession(Replay(steps), "ecu", {})
            result = session.count_dtcs_os_eng_profile(
                cast("VehicleProfile", profile), 1
            )
            self.assertEqual(
                (result["count"], result["native_40_idling"]), (count, flag)
            )

    def test_oseng_count_init_null_send_ignores_native_status(self):
        settings = bytearray(16)
        struct.pack_into("<I", settings, 0, 50)
        profile = selected_profile()
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(b"\x18" if function == 7 else b"\x19"),
                provenance="selected",
                settings_record=bytes(settings),
            ),
        )
        seen = []

        def send(_, call):
            seen.append(call.arguments)
            return 77

        session = ToyotaSession(
            Replay([(b"\x18", b"\x58\x00\x09"), (b"\x19", NativeStatus(0x91010009))]),
            "ecu",
            {},
            native_send=send,
        )
        result = session.count_dtcs_os_eng_profile(
            cast("VehicleProfile", profile), 1, connection_bus_id=0x22
        )
        self.assertEqual(result["count"], 9)
        self.assertEqual(seen, [(0x23, None, 0, 50, 0x22, 1, 1)])
        self.assertEqual(session.trace[-1]["native_status"], 77)
        self.assertIsNone(session.trace[-1]["request"])

    def test_kwp_profile_frame_chain_preserves_receive_state(self):
        frames = tuple(
            Mock(
                frame=CommandFrame(request),
                provenance="selected",
                settings_record=bytes(16),
            )
            for request in (b"\x18", b"\x19")
        )
        profile = selected_profile()
        profile.frame_records.return_value = frames
        replay = Replay(
            [
                (b"\x18", b"\x58\x00\x01\x00\x02\x00\x03"),
                (b"", NativeStatus(77)),
                (b"", b"\x59\x00\x04"),
            ]
        )
        session = ToyotaSession(replay, "ecu", {})
        self.assertEqual(
            session.dtcs_profile(cast("VehicleProfile", profile), 10), [1, 2, 3, 4]
        )
        self.assertFalse(replay.steps)
        profile.frame_records.assert_called_with(10)

    def test_count_with_codes_actual_list_and_single_shared_budget(self):
        frame = Mock(
            frame=CommandFrame(b"\x18"),
            provenance="selected",
            settings_record=bytes(16),
        )
        profile = selected_profile()
        profile.frame_records.return_value = (frame,)
        replay = Replay(
            [(b"\x18", b"\x58\x00\xff"), (b"\x18", b"\x58\x00\x01\x00\x02")]
        )
        session = ToyotaSession(replay, "ecu", {})
        result = session.count_dtcs_with_codes_profile(
            cast("VehicleProfile", profile), 1
        )
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["codes"], [1, 2])
        self.assertEqual(
            [call.args[0] for call in profile.frame_records.call_args_list], [7, 10]
        )
        replay = Replay([(b"\x18", b"\x58\x00\xff")])
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=1))
        with self.assertRaisesRegex(SessionError, "budget"):
            session.count_dtcs_with_codes_profile(cast("VehicleProfile", profile), 1)
        self.assertEqual(len(replay.calls), 1)

    def test_diagnostic_scope_db_selection_failure_chronology(self):
        events = []

        def get_mode(_):
            events.append("get")
            return bytes(16)

        def set_mode(_, mode):
            events.append("restore" if mode == bytes(16) else "install")

        def mode_factory():
            events.append("build-mode")
            return b"x" * 16

        session = ToyotaSession(
            Replay([]), "ecu", {}, native_get_mode=get_mode, native_set_mode=set_mode
        )
        with (
            self.assertRaises(ToyotaCodecError),
            session.diagnostic_scope(mode_factory),
        ):
            events.append("select-frames")
            raise ToyotaCodecError("Selected frames absent", 0xC0040101)
        self.assertEqual(
            events, ["get", "build-mode", "install", "select-frames", "restore"]
        )
        events.clear()

        def bad_factory():
            events.append("build-mode")
            raise ToyotaCodecError("Selected CARB row absent", 0xC0040101)

        with self.assertRaises(ToyotaCodecError), session.diagnostic_scope(bad_factory):
            self.fail("Mode factory failure yielded diagnostic scope")
        self.assertEqual(events, ["get", "build-mode"])

    def test_native_count_profile_joins_retry_and_dk_all_frames_first_reply(self):
        settings = bytearray(16)
        settings[14] = 1
        frame = Mock(
            frame=CommandFrame(b"\x18"),
            provenance="authored-selected",
            settings_record=bytes(settings),
        )
        profile = selected_profile()
        profile.frame_records.return_value = (frame,)
        replay = Replay([(b"\x18", NativeStatus(77)), (b"\x18", b"\x58\x00\x04")])
        session = ToyotaSession(replay, "ecu", {"preserved": spec(b"\x10")})
        self.assertEqual(
            session.count_dtcs_profile(cast("VehicleProfile", profile))["count"], 4
        )
        profile.frame_records.assert_called_with(7)
        self.assertEqual(tuple(session.commands), ("preserved",))
        frame2 = Mock(
            frame=CommandFrame(b"\x19"),
            provenance="authored-selected",
            settings_record=bytes(16),
        )
        profile.frame_records.return_value = (frame, frame2)
        replay = Replay([(b"\x18", b"\x12\x12\x34\x00\xff"), (b"\x19", b"\xff")])
        session = ToyotaSession(replay, "ecu", {})
        result = session.count_dtcs_dk_iso_profile(cast("VehicleProfile", profile), 99)
        self.assertEqual(result, {"diagnostic_type": 99, "count": 3})
        self.assertFalse(replay.steps)
        profile.frame_records.assert_called_with(7)

    def test_native_count_families_offsets_fallback_and_tt_exact_lengths(self):
        cases: list[tuple[CountFamily, int, bytes, int]] = [
            ("plain", 3, b"\x58\x00\x07", 7),
            ("p4", 1, b"\x58\x08", 8),
            ("ac", 2, b"\x58\x00\x09\x0a", 10),
            ("tt", 1, b"\x58\x00\x0b", 11),
            ("tt", 2, b"\x58\x00\x00\x0c", 12),
            ("tt", 1, b"\x58\x00\xff\xff\xff", 0),
        ]
        for family, kind, reply, expected in cases:
            replay = Replay([(b"\x18", NativeStatus(0x91010009)), (b"\x18\x01", reply)])
            session = ToyotaSession(
                replay, "ecu", {"a": spec(b"\x18"), "b": spec(b"\x18\x01")}
            )
            result = session.count_dtcs(["a", "b"], family=family, diagnostic_type=kind)
            self.assertEqual(result["count"], expected)
            self.assertEqual(result["selected_frame"], 1)
            if family == "p4":
                self.assertNotIn("shared_data_0d", result)
            else:
                self.assertEqual(result["shared_data_0d"], 1)

    def test_native_count_error_mapping_and_vgrs_bounded_drain(self):
        failures: tuple[tuple[CountFamily, int], ...] = (
            ("plain", 0x90040501),
            ("ac", 0x90040501),
            ("p4", 0x91010009),
            ("tt", 0x91010009),
            ("vgrs", 0x90040501),
        )
        for family, code in failures:
            session = ToyotaSession(
                Replay([(b"\x18", NativeStatus(0x91010009))]),
                "ecu",
                {"a": spec(b"\x18")},
            )
            with self.assertRaises(NativeStatus) as error:
                session.count_dtcs(["a"], family=family)
            self.assertEqual(error.exception.code, code)
        replay = Replay(
            [
                (b"\x18", b"\x58\x00\x03"),
                (b"", NativeStatus(77)),
                (b"", b"discarded"),
                (b"", NativeStatus(0x91010009)),
            ]
        )
        session = ToyotaSession(replay, "ecu", {"a": spec(b"\x18")})
        self.assertEqual(session.count_dtcs(["a"], family="vgrs")["count"], 3)
        self.assertFalse(replay.steps)
        session = ToyotaSession(
            lambda *_: b"\x58\x00\x03",
            "ecu",
            {"a": spec(b"\x18")},
            limits=Limits(exchanges=2),
        )
        with self.assertRaisesRegex(SessionError, "budget"):
            session.count_dtcs(["a"], family="vgrs")

    def test_native_count_selected_retry_and_immediate_status(self):
        replay = Replay([(b"\x18", b"\x00"), (b"\x18", b"\x58\x00\x05")])
        session = ToyotaSession(replay, "ecu", {"a": spec(b"\x18")})
        self.assertEqual(session.count_dtcs(["a"], retry_counts=[1])["count"], 5)
        replay = Replay([(b"\x18", NativeStatus(0x90020323))])
        session = ToyotaSession(replay, "ecu", {"a": spec(b"\x18")})
        with self.assertRaises(NativeStatus) as error:
            session.count_dtcs(["a"], retry_counts=[5])
        self.assertEqual(error.exception.code, 0x90020323)
        self.assertEqual(len(replay.calls), 1)

    def test_diagnostic_mode_literal_order_and_restore_on_native_error(self):
        for fail in (False, True):
            events = []
            old, temporary = bytes(range(16)), bytes(reversed(range(16)))

            def get_mode(_, events=events, old=old):
                events.append(("get",))
                return old

            def set_mode(_, mode, events=events):
                events.append(("set", mode))

            def exchange(_, request, fail=fail, events=events):
                events.append(("exchange", request))
                if fail:
                    raise NativeStatus(0x91010009)
                return b"\x54"

            session = ToyotaSession(
                exchange,
                "ecu",
                {"clear": spec(b"\x14")},
                native_get_mode=get_mode,
                native_set_mode=set_mode,
            )
            if fail:
                with self.assertRaises(NativeStatus):
                    session.diagnostic_sequence(["clear"], temporary)
            else:
                self.assertEqual(
                    session.diagnostic_sequence(["clear"], temporary), [b"\x54"]
                )
            self.assertEqual(
                events,
                [("get",), ("set", temporary), ("exchange", b"\x14"), ("set", old)],
            )

    def test_diagnostic_mode_cancel_restores_with_bounded_cleanup(self):
        flag = [False]
        modes = []

        def exchange(*_):
            flag[0] = True
            raise NativeStatus(77)

        def set_mode(_, mode):
            if flag[0]:
                raise AssertionError("Forward mode setter used after cancellation")
            modes.append(mode)

        session = ToyotaSession(
            exchange,
            "ecu",
            {"clear": spec(b"\x14")},
            cancelled=lambda: flag[0],
            native_get_mode=lambda _: bytes(16),
            native_set_mode=set_mode,
            native_cleanup_set_mode=lambda _, mode: modes.append(mode),
        )
        with self.assertRaises(Cancelled):
            session.diagnostic_sequence(["clear"], b"x" * 16)
        self.assertEqual(modes, [b"x" * 16, bytes(16)])
        self.assertEqual(session.trace[-2]["native_status"], 77)

    def test_selected_transaction_retains_frame_identity_and_patched_request(self):
        from scripts.profiles import SelectedFrame

        frames = [
            SelectedFrame(spec(b"\x22\x00\x00").frame, b"", b"", bytes([i]), str(i))
            for i in (1, 2)
        ]
        seen = []

        def transaction(ecu, command, request):
            seen.append((ecu, command, request))
            return b"\x62\x00\x00"

        replay = Replay([])
        session = ToyotaSession(
            replay,
            "ecu",
            {
                str(i): CommandSpec(frame.frame, selected=frame)
                for i, frame in enumerate(frames)
            },
            native_transaction=transaction,
        )
        self.assertEqual(session.sequence(["0", "1"]), [b"\x62\x00\x00"] * 2)
        self.assertIs(seen[0][1].selected, frames[0])
        self.assertIs(seen[1][1].selected, frames[1])
        session._begin()
        session._native_call(session.commands["0"], b"\x22\x12\x34", extended=True)
        self.assertIs(seen[-1][1].selected, frames[0])
        self.assertEqual(seen[-1][1].frame.request, b"\x22\x12\x34")
        self.assertTrue(seen[-1][1].extended)
        self.assertFalse(replay.calls)
        session._begin()
        replay.steps = [(b"", b"raw")]
        # Receive-only continuation retains the raw exchange contract.
        self.assertEqual(session._call(b""), b"raw")
        self.assertEqual(len(seen), 3)

    def test_selected_p5_status_rules_query_bits_and_commit_expected_mask(self):
        def row(kind, mask, expected):
            raw = bytearray(12)
            struct.pack_into("<I", raw, 0, kind)
            raw[8:10] = bytes((mask, expected))
            return bytes(raw)

        profile = Mock()
        profile.database.sections = {66: object()}
        profile.dtc_status_records.side_effect = lambda bit: {
            1: (row(1, 0xF0, 0x40), row(1, 2, 2)),
            0x80000000: (row(0x80000000, 8, 8),),
        }.get(bit, ())
        mask, rules = dtc_status_rules_profile(profile, 0x80000003)
        self.assertEqual(mask, 0x4A)
        self.assertEqual([rule.diag_type for rule in rules], [1, 1, 0x80000000])
        self.assertEqual(
            profile.dtc_status_records.call_args_list,
            [call(1), call(2), call(0x80000000)],
        )
        profile.dtc_status_records.side_effect = lambda _: (row(1, 0xFF, 0),)
        self.assertEqual(dtc_status_rules_profile(profile, 1), (0, ()))
        profile.records.return_value = (row(0x80000000, 8, 0),)
        self.assertEqual(
            dtc_status_rules_profile(profile)[1], (StatusRule(0x80000000, 8, 0),)
        )
        profile.records.return_value = ()
        with self.assertRaises(ToyotaCodecError) as error:
            dtc_status_rules_profile(profile)
        self.assertEqual(error.exception.code, 0xC0040101)
        profile.database.sections = {}
        with self.assertRaises(ToyotaCodecError) as error:
            dtc_status_rules_profile(profile)
        self.assertEqual(error.exception.code, 0xA0030107)
        with self.assertRaises(ValueError):
            dtc_status_rules_profile(profile, 0x100000000)

    def test_selected_p5_diagnostic_request_first_frame_subaru_and_capacity(self):
        from scripts.profiles import SelectedFrame

        profile = selected_profile((0xCD,))
        category = bytearray(76)
        category[72] = 0x20
        profile.category_record = bytes(category)
        profile.category = 0x2DA
        raw_function = bytearray(16)
        struct.pack_into("<HH", raw_function, 0, 0x2DA, 0xCD)
        profile.catalog.management.sections[18] = Section(
            18, 0, 1, False, bytes(raw_function)
        )
        rule = bytearray(12)
        rule[8:10] = b"\xf0\x40"
        profile.dtc_status_records.return_value = (bytes(rule),)
        frame = SelectedFrame(CommandFrame(b"\x19\x02\x00"), b"", b"", bytes(16), "CD")
        profile.frame_records.return_value = (frame, frame)
        seen = []

        def transaction(ecu, command, request):
            seen.append((command, request))
            return b"\x59\x02\xff"

        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=transaction)
        result = session.read_p5_diagnostic_reply_profile(
            profile, 1, native_cancel_value=0, connection_bus_id=0x14
        )
        self.assertTrue(result["read_succeeded"])
        self.assertEqual(result["maximum_groups"], 0x3FFF)
        self.assertEqual(seen[0][1], b"\x19\x02\xaf")
        self.assertIs(seen[0][0].selected, frame)
        self.assertEqual(seen[0][0].receive_capacity, 65535)
        profile.frame_records.assert_called_once_with(0xCD)
        session.read_p5_diagnostic_reply_profile(
            profile, 1, native_cancel_value=0, connection_bus_id=0x22
        )
        self.assertEqual(seen[-1][0].receive_capacity, 0x1000)
        with self.assertRaises(ToyotaCodecError) as error:
            session.read_p5_diagnostic_reply_profile(
                profile, 1, native_cancel_value=1, connection_bus_id=None
            )
        self.assertEqual(error.exception.code, 0xA0040003)
        self.assertEqual(len(seen), 2)

    def p5_existence_fixture(
        self, build: Literal[12, 18] = 18, function=0xCE, **kwargs
    ):
        from scripts.freeze_p5 import P5FreezeState
        from scripts.monitor_support import MonitorSupportCache
        from tests.test_freeze_p5 import profile as make_profile

        profile = make_profile(build, **kwargs)
        original = profile.catalog.management.sections[18]
        row = bytearray(original.payload)
        struct.pack_into("<H", row, 2, function)
        profile.catalog.management.sections[18] = Section(18, 0, 1, False, bytes(row))
        cache = MonitorSupportCache(profile, Mock(), "ecu", source_build=build)
        state = P5FreezeState(profile, source_build=build, cache=cache)
        return profile, state

    def p5_workflow_fixture(self, build: Literal[12, 18] = 18):
        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        profile, _state = self.p5_existence_fixture(build, function=0xCD)
        communication = NativeCommunication(
            profile, Mock(), "ecu", bus_id=0x12, source_build=build
        )
        return ToyotaWorkflows.from_communication(
            communication,
            observations=WorkflowObservations(1, 0x12, source_version=build),
        )

    def native_p5_metadata_workflow_fixture(self, build, reply, *, name_count=1):
        from types import SimpleNamespace

        from scripts.diagnostic_db import Language
        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_freeze_p5 import database

        profile, _state = self.p5_existence_fixture(build, function=0xCD)
        rows = []
        for code in (1, 2):
            row = bytearray(68)
            struct.pack_into("<II", row, 44, code, code)
            row[64] = 1
            rows.append(bytes(row))
        profile.database.sections[65] = Section(65, 0, 2, False, b"".join(rows))
        rules = []
        for bit in (1, 2):
            row = bytearray(12)
            struct.pack_into("<I", row, 0, bit)
            row[8:10] = bytes((bit, bit))
            rules.append(bytes(row))
        profile.database.sections[66] = Section(66, 0, 2, False, b"".join(rules))
        directory, data = bytearray(), bytearray()
        for number in range(name_count):
            encoded = (f"name{number + 1}\0").encode("utf-16le")
            directory += struct.pack("<IH", len(data), len(encoded))
            data += encoded
        profile.catalog.language = Language(
            database(build, 4, {0: (name_count, bytes(directory + data))})
        )
        operations = Mock()
        operations.send.return_value = 0
        operations.receive.return_value = SimpleNamespace(code=0, data=reply)
        communication = NativeCommunication(
            profile, operations, "ecu", bus_id=0x12, source_build=build
        )
        workflow = ToyotaWorkflows.from_communication(
            communication,
            observations=WorkflowObservations(1, 0x12, source_version=build),
        )
        return workflow, operations

    def test_p5_cd_later_language_fault_retains_first_and_duplicate_merges(self):
        from scripts.freeze_p5 import P5FreezeState

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            for reply, status, kind in (
                (bytes.fromhex("5902010000010100000201"), 1, 1),
                (bytes.fromhex("590203000001010000010200000201"), 3, 3),
            ):
                workflow, operations = self.native_p5_metadata_workflow_fixture(
                    build, reply
                )
                with self.assertRaises(ValueError):
                    workflow.session.dtcs_p5_profile(
                        workflow, 3, 0, native_cancel_value=0
                    )
                state = workflow.native_output["state"]
                assert isinstance(state, P5FreezeState)
                self.assertEqual(
                    [
                        (item.code, item.status, item.diag_type)
                        for item in state.diagnostics
                    ],
                    [(1, status, kind)],
                )
                self.assertTrue(workflow.native_output["communication_success"])
                self.assertEqual(operations.receive.call_count, 1)
                assert workflow._communication is not None
                self.assertFalse(workflow._communication.closed)

    def test_p5_sorts_all_before_timestamp_and_prunes_each_before_later_fault(self):
        from scripts.freeze_p5 import P5FreezeState

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            reply = bytes.fromhex("5902010000010100000201")
            workflow, _ops = self.native_p5_metadata_workflow_fixture(
                build, reply, name_count=2
            )
            flags = []

            def sort(state, diagnostic):
                if diagnostic.code == 2:
                    raise NativeStatus(77)

            with (
                patch.object(P5FreezeState, "sort_display_order", sort),
                patch.object(
                    P5FreezeState,
                    "set_timestamp_odometer_flags",
                    lambda state, diagnostic, flags=flags: flags.append(
                        diagnostic.code
                    ),
                ),
                self.assertRaises(NativeStatus),
            ):
                workflow.session.dtcs_p5_profile(workflow, 1, 0, native_cancel_value=0)
            self.assertEqual(flags, [])
            workflow, _ops = self.native_p5_metadata_workflow_fixture(
                build, reply, name_count=2
            )

            def associated(state, **kwargs):
                # Arrange a native zero-state item at the finalization boundary.
                state.diagnostics[0].status = 0
                return False, ()

            workflow.session.p5_freeze_existence_profile = Mock(side_effect=associated)

            def timestamp(state, diagnostic):
                if diagnostic.code == 2:
                    raise NativeStatus(78)

            with (
                patch.object(P5FreezeState, "set_timestamp_odometer_flags", timestamp),
                self.assertRaises(NativeStatus),
            ):
                workflow.session.dtcs_p5_profile(workflow, 1, 1, native_cancel_value=0)
            state = workflow.native_output["state"]
            assert isinstance(state, P5FreezeState)
            self.assertEqual([item.code for item in state.diagnostics], [2])

    def test_p5_second_sort_cancellation_precedes_all_timestamp_updates(self):
        from scripts.freeze_p5 import P5FreezeState

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            workflow, operations = self.native_p5_metadata_workflow_fixture(
                build, bytes.fromhex("5902010000010100000201"), name_count=2
            )
            flags = Mock()

            def sort(state, diagnostic):
                if diagnostic.code == 2:
                    raise Cancelled("authored cancellation at second native sort")

            with (
                patch.object(P5FreezeState, "sort_display_order", sort),
                patch.object(P5FreezeState, "set_timestamp_odometer_flags", flags),
                self.assertRaises(Cancelled),
            ):
                workflow.session.dtcs_p5_profile(workflow, 1, 0, native_cancel_value=0)
            flags.assert_not_called()
            self.assertEqual(operations.receive.call_count, 1)

    def test_p5_normal_outer_joins_each_analysis_only_then_stored_and_prunes(self):
        from scripts.freeze_p5 import P5FreezeState, P5SnapshotRequest

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            workflow = self.p5_workflow_fixture(build)
            session = workflow.session
            phases = []
            session.read_p5_diagnostic_reply_profile = Mock(
                return_value={
                    "reply": b"\x59\x02\x01\x00\x00\x01\x01",
                    "rules": (StatusRule(1, 1, 1),),
                    "maximum_groups": 0x3FF,
                    "read_succeeded": True,
                }
            )
            requests = (P5SnapshotRequest(1, [1]),)

            def existence(state, *, phases=phases, requests=requests, **kwargs):
                phases.append("existence")
                state.add_diagnostic(2)
                return True, requests

            session.p5_freeze_existence_profile = Mock(side_effect=existence)

            def each(state, selected, *, phases=phases, requests=requests, **kwargs):
                phases.append(("each", kwargs))
                self.assertIs(selected, requests)
                return {"communication_success": False}

            workflow.each_freeze_p5_core = Mock(side_effect=each)
            session.p5_stored_freeze_profile = Mock(
                side_effect=lambda *a, phases=phases, **kw: (
                    phases.append("stored") or False
                )
            )
            result = session.p5_diagnostics_core_profile(
                workflow, 1, 7, native_cancel_value=0
            )
            self.assertEqual(
                phases,
                [
                    "existence",
                    (
                        "each",
                        {
                            "begin": False,
                            "create_diagnostics": False,
                        },
                    ),
                    "stored",
                ],
            )
            state = result["state"]
            assert isinstance(state, P5FreezeState)
            self.assertEqual([item.code for item in state.diagnostics], [1])
            self.assertTrue(result["communication_success"])
            self.assertIs(workflow.native_output, result)

    def test_p5_normal_selected_cd_ce_cf77_to_actual43_signal_values(self):
        from types import SimpleNamespace

        from scripts.freeze_p5 import P5FreezeState
        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            signals = {
                signal: (99,) for signal in (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))
            }
            profile, _state = self.p5_existence_fixture(build, signals=signals)
            row = profile.catalog.management.sections[18].payload
            functions = []
            for function in (0xCD, 0xCE, 0xCF):
                selected = bytearray(row)
                struct.pack_into("<H", selected, 2, function)
                functions.append(bytes(selected))
            profile.catalog.management.sections[18] = Section(
                18, 0, 3, False, b"".join(functions)
            )
            rule = bytearray(12)
            struct.pack_into("<I", rule, 0, 1)
            rule[8:10] = b"\x01\x01"
            profile.database.sections[66] = Section(66, 0, 1, False, bytes(rule))
            operations = Mock()
            operations.send.return_value = 0
            operations.receive.side_effect = [
                SimpleNamespace(code=0, data=reply)
                for reply in (
                    b"\x59\x02\x01\x00\x00\x01\x01",
                    b"\x59\x03\x00\x00\x01\x01",
                    b"\x59\x04\x00\x00\x01\x00\x01\x01\x12\x34\x02\x05\x06",
                )
            ]
            communication = NativeCommunication(
                profile, operations, "ecu", bus_id=0x12, source_build=build
            )
            workflow = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(1, 0x12, source_version=build),
            )
            result = workflow.session.p5_diagnostics_core_profile(
                workflow, 1, 3, native_cancel_value=0
            )
            state = result["state"]
            assert isinstance(state, P5FreezeState)
            self.assertEqual([item.code for item in state.diagnostics], [1])
            diagnostic = state.diagnostics[0]
            self.assertEqual(diagnostic.status, 1)
            self.assertEqual(diagnostic.existence_flags, 1)
            self.assertEqual([item.pid for item in diagnostic.signals], [1, 2])
            self.assertEqual(
                [item.values[0].value for item in diagnostic.signals], [5, 6]
            )
            self.assertEqual(operations.receive.call_count, 3)
            self.assertFalse(communication.closed)

    def test_p5_subaru26b_selected_cd_ce_cf_uses_subaru_snapshot_parser(self):
        from types import SimpleNamespace

        from scripts.freeze_p5 import P5FreezeState
        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        signals = {
            signal: (99,) for signal in (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))
        }
        profile, _state = self.p5_existence_fixture(category_id=0x26B, signals=signals)
        row = profile.catalog.management.sections[18].payload
        functions = []
        for function in (0xCD, 0xCE, 0xCF):
            selected = bytearray(row)
            struct.pack_into("<HH", selected, 0, 0x26B, function)
            functions.append(bytes(selected))
        profile.catalog.management.sections[18] = Section(
            18, 0, 3, False, b"".join(functions)
        )
        rule = bytearray(12)
        struct.pack_into("<I", rule, 0, 1)
        rule[8:10] = b"\x01\x01"
        profile.database.sections[66] = Section(66, 0, 1, False, bytes(rule))
        operations = Mock()
        operations.send.return_value = 0
        operations.receive.side_effect = [
            SimpleNamespace(code=0, data=reply)
            for reply in (
                b"\x59\x02\x01\x00\x00\x01\x01",
                b"\x59\x03\x00\x00\x01\x01\x00\x00\x01\x10",
                b"\x59\x04\x00\x00\x01\x00\x01\x01\x12\x34\x05\x06",
                b"\x59\x04\x00\x00\x01\x00\x10\x01\x12\x34\x07\x08",
            )
        ]
        communication = NativeCommunication(
            profile, operations, "ecu", bus_id=0x12, source_build=18
        )
        workflow = ToyotaWorkflows.from_communication(
            communication, observations=WorkflowObservations(1, 0x12)
        )
        result = workflow.session.dtcs_p5_profile(workflow, 1, 3, native_cancel_value=0)
        state = result["state"]
        assert isinstance(state, P5FreezeState)
        self.assertTrue(state.subaru)
        self.assertEqual(state.diagnostics[0].normal_numbers, [1, 0x10])
        self.assertEqual(
            [value.value for value in state.diagnostics[0].signals[0].values], [5]
        )
        self.assertEqual(operations.receive.call_count, 4)
        self.assertFalse(communication.closed)

    def test_p5_subaru_stored_selected113_capture_skips_ce_and_cf(self):
        from dataclasses import replace
        from types import SimpleNamespace

        from scripts.freeze_p5 import P5FreezeState
        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        profile, _state = self.p5_existence_fixture(
            function=0x113,
            frame_request=bytes.fromhex("1903ff"),
            count=3,
            signals={0x4D: (1,), 0x4E: (2,), 0x4F: (3,)},
        )
        category = bytearray(profile.category_record)
        category[72] = 0x20
        profile = replace(profile, category_record=bytes(category))
        stored = profile.catalog.management.sections[18].payload
        cd = bytearray(stored)
        struct.pack_into("<H", cd, 2, 0xCD)
        profile.catalog.management.sections[18] = Section(
            18, 0, 2, False, bytes(cd) + stored
        )
        rule = bytearray(12)
        struct.pack_into("<I", rule, 0, 1)
        rule[8:10] = b"\x01\x01"
        profile.database.sections[66] = Section(66, 0, 1, False, bytes(rule))
        operations = Mock()
        operations.send.return_value = 0
        operations.receive.side_effect = [
            SimpleNamespace(code=0, data=bytes.fromhex(reply))
            for reply in (
                "59020112345601",
                "590301123456000112340a0302",
            )
        ]
        communication = NativeCommunication(
            profile, operations, "ecu", bus_id=0x12, source_build=18
        )
        workflow = ToyotaWorkflows.from_communication(
            communication, observations=WorkflowObservations(1, 0x12)
        )
        result = workflow.session.dtcs_p5_profile(workflow, 1, 7, native_cancel_value=0)
        state = result["state"]
        assert isinstance(state, P5FreezeState)
        self.assertTrue(state.subaru)
        diagnostic = state.diagnostics[0]
        self.assertEqual((diagnostic.code, diagnostic.status), (0x123456, 1))
        self.assertEqual(
            [signal.values[0].value for signal in diagnostic.signals], [10, 3, 2]
        )
        self.assertEqual(state.stored_numbers, [255])
        self.assertEqual(operations.receive.call_count, 2)
        self.assertTrue(result["communication_success"])
        self.assertFalse(communication.closed)

    def test_p5_bus14_more_than3ff_ce_groups_join_actual_each_consumer(self):
        from types import SimpleNamespace

        from scripts.freeze_p5 import P5FreezeState
        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        signals = {
            signal: (99,) for signal in (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))
        }
        profile, _state = self.p5_existence_fixture(signals=signals)
        ce = profile.catalog.management.sections[18].payload
        cf = bytearray(ce)
        struct.pack_into("<H", cf, 2, 0xCF)
        profile.catalog.management.sections[18] = Section(
            18, 0, 2, False, ce + bytes(cf)
        )
        count = 0x400
        existence = b"\x59\x03" + b"".join(
            code.to_bytes(3, "big") + b"\x01" for code in range(1, count + 1)
        )
        operations = Mock()
        operations.send.return_value = 0
        operations.receive.side_effect = [
            SimpleNamespace(code=0, data=existence),
            *(
                SimpleNamespace(code=0, data=b"\x59\x04\x00\x00\x00\x00")
                for _ in range(count)
            ),
        ]
        limits = Limits(exchanges=10000, seconds=60)
        communication = NativeCommunication(
            profile, operations, "ecu", bus_id=0x14, source_build=18, limits=limits
        )
        workflow = ToyotaWorkflows.from_communication(
            communication, observations=WorkflowObservations(1, 0x14), limits=limits
        )
        result = workflow.session.dtcs_p5_profile(workflow, 0, 3, native_cancel_value=0)
        state = result["state"]
        assert isinstance(state, P5FreezeState)
        self.assertEqual(len(state.diagnostics), count)
        self.assertEqual(state.diagnostic_limit, 0x3FFF)
        self.assertEqual(operations.receive.call_count, count + 1)
        self.assertEqual(state.diagnostics[-1].code, count)
        self.assertTrue(result["communication_success"])

    def test_p5_export_native_log14_status_precedence_and_build12_absence(self):
        for build, started, stopped, body_error, expected in (
            (18, 0, 0, 0, 0),
            (18, 0xC0040001, 0, 0, 0xC0040001),
            (18, 0, 0xC0040101, 0xA004020B, 0xA004020B),
            (12, 0xC0040001, 0xC0040101, 0, 0),
        ):
            workflow = self.p5_workflow_fixture(cast(Literal[12, 18], build))
            communication = workflow._communication
            assert communication is not None
            communication.start_comm_log = Mock(return_value=started)
            communication.stop_comm_log = Mock(return_value=stopped)
            session = workflow.session
            session.p5_diagnostics_core_profile = Mock(
                side_effect=NativeStatus(body_error) if body_error else None,
                return_value={"native_status": 0},
            )
            if expected:
                with self.assertRaises(ToyotaCodecError) as caught:
                    session.dtcs_p5_profile(
                        workflow, 1, 0, native_cancel_value=0, log_control=1
                    )
                self.assertEqual(caught.exception.code, expected)
            else:
                session.dtcs_p5_profile(
                    workflow, 1, 0, native_cancel_value=0, log_control=1
                )
            self.assertEqual(communication.start_comm_log.call_count, int(build == 18))
            self.assertEqual(
                communication.stop_comm_log.call_count,
                int(build == 18 and started == 0),
            )
            if build == 18:
                communication.start_comm_log.assert_called_once_with(0x14)
            self.assertFalse(communication.closed)

    def test_p5_normal_outer_all_masked_has_native_error_and_retains_state(self):
        workflow = self.p5_workflow_fixture()
        session = workflow.session
        session.read_p5_diagnostic_reply_profile = Mock(
            return_value={
                "reply": b"",
                "rules": (),
                "maximum_groups": 0x3FF,
                "read_succeeded": False,
            }
        )
        with self.assertRaises(NativeStatus) as caught:
            session.p5_diagnostics_core_profile(workflow, 0, 0, native_cancel_value=0)
        self.assertEqual(caught.exception.code, 0xA004020B)
        self.assertEqual(workflow.native_output["native_status"], 0xA004020B)
        self.assertIn("state", workflow.native_output)

    def test_p5_existence_exact_selected_groups_normalizes_prerequisites(self):
        profile, state = self.p5_existence_fixture()
        response = b"\x59\x03" + b"".join(
            code.to_bytes(3, "big") + bytes((number,))
            for code, number in (
                (1, 0x10),
                (1, 1),
                (1, 0x10),
                (2, 0x50),
                (3, 2),
                (3, 0x50),
                (4, 0),
            )
        )
        provider = Mock(return_value=response)
        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
        session._begin()
        succeeded, requests = session.p5_freeze_existence_profile(
            state, native_cancel_value=0, connection_bus_id=0x14
        )
        self.assertTrue(succeeded)
        self.assertEqual(
            [(item.code, item.numbers) for item in requests],
            [(1, [0x10, 1]), (3, [2, 0x50])],
        )
        self.assertEqual([item.code for item in state.diagnostics], [1, 3])
        self.assertEqual(
            [item.existence_flags for item in state.diagnostics], [1, 0x10]
        )
        self.assertEqual(provider.call_args.args[1].receive_capacity, 65535)
        self.assertEqual(
            provider.call_args.args[1].selected.function_record[2:4], b"\xce\x00"
        )
        self.assertIs(state.profile, profile)

    def test_p5_existence_native_masks_and_cancel_preserve_prior_state(self):
        for status in (0x91010009, 0xC0040001):
            _profile, state = self.p5_existence_fixture()
            state.add_diagnostic(1)
            provider = Mock(side_effect=NativeStatus(status))
            session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
            session._begin()
            self.assertEqual(
                session.p5_freeze_existence_profile(
                    state, native_cancel_value=0, connection_bus_id=1
                ),
                (False, ()),
            )
            self.assertEqual([item.code for item in state.diagnostics], [1])
            with self.assertRaises(ToyotaCodecError) as error:
                session.p5_freeze_existence_profile(
                    state, native_cancel_value=1, connection_bus_id=1
                )
            self.assertEqual(error.exception.code, 0xA0040003)
            provider.assert_called_once()

    def test_p5_existence_short_reply_native_success_and_build12_capacity(self):
        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            _profile, state = self.p5_existence_fixture(build)
            provider = Mock(return_value=b"\x59\x03")
            session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
            session._begin()
            self.assertEqual(
                session.p5_freeze_existence_profile(
                    state, native_cancel_value=0, connection_bus_id=0x14
                ),
                (True, ()),
            )
            self.assertEqual(
                provider.call_args.args[1].receive_capacity,
                65535 if build == 18 else 0x1000,
            )

    def test_p5_ce_d0_build12_has_no_connection_lookup_and_d0_cancel_precedes_bus(self):
        from types import SimpleNamespace

        from scripts.freeze_p5 import P5FreezeState
        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            for function in (0xCE, 0xD0):
                for cancelled in (0, 1):
                    profile, _state = self.p5_existence_fixture(
                        build, function=function
                    )
                    operations = Mock()
                    operations.send.return_value = 0
                    operations.receive.return_value = SimpleNamespace(
                        code=0, data=b"\x59\x03"
                    )
                    communication = NativeCommunication(
                        profile, operations, "ecu", bus_id=0x12, source_build=build
                    )
                    workflow = ToyotaWorkflows.from_communication(
                        communication,
                        observations=WorkflowObservations(
                            1, 0x12, source_version=build
                        ),
                    )
                    state = P5FreezeState(
                        profile, source_build=build, cache=communication.cache
                    )
                    session = workflow.session
                    workflow._begin(source12_verified=True)
                    session._begin()
                    method = (
                        session.p5_freeze_existence_profile
                        if function == 0xCE
                        else session.p5_stored_freeze_profile
                    )
                    expected = (
                        0xA0040003
                        if cancelled and (build == 12 or function == 0xD0)
                        else 0xC0040601
                        if build == 18
                        else 0
                    )
                    if expected:
                        with self.assertRaises(ToyotaCodecError) as error:
                            method(
                                state,
                                native_cancel_value=cancelled,
                                connection_bus_id=None,
                            )
                        self.assertEqual(error.exception.code, expected)
                        self.assertEqual(operations.receive.call_count, 0)
                    else:
                        self.assertEqual(
                            method(
                                state,
                                native_cancel_value=0,
                                connection_bus_id=None,
                            ),
                            (True, ()) if function == 0xCE else True,
                        )
                        self.assertEqual(operations.receive.call_count, 1)

    def test_p5_predictive_selected_cf_captures_all_before_native_analysis(self):
        from scripts.freeze_p5 import P5SnapshotRequest

        _profile, state = self.p5_existence_fixture(function=0xCF)
        state.add_diagnostic(1)
        requests = (P5SnapshotRequest(1, [0x10, 0x12]),)
        replies = [
            b"\x59\x04\x00\x00\x01\x00\x10\x01\x12\x34\x05\x06",
            b"\x59\x04\x00\x00\x01\x00\x12\x01\x12\x34\x07\x08",
        ]
        provider = Mock(side_effect=replies)
        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
        session._begin()
        self.assertTrue(
            session.p5_predictive_freeze_profile(state, requests, native_cancel_value=0)
        )
        diagnostic = state.diagnostics[0]
        self.assertEqual(diagnostic.existence_flags, 0x11)
        self.assertEqual(diagnostic.normal_numbers, [0x10, 0x12])
        self.assertEqual(
            [(item.index, item.kind) for item in diagnostic.signals[0].values],
            [(-111, 1), (-109, 2)],
        )
        self.assertEqual(
            [entry.args[2] for entry in provider.call_args_list],
            [b"\x19\x04\x00\x00\x01\x10", b"\x19\x04\x00\x00\x01\x12"],
        )

    def test_p5_predictive_prunes_masked_numbers_and_preserves_earlier_record_on_partial(
        self,
    ):
        from scripts.freeze_p5 import P5SnapshotRequest

        _profile, state = self.p5_existence_fixture(function=0xCF)
        state.add_diagnostic(1)
        requests = (P5SnapshotRequest(1, [0x10, 0x12]),)
        provider = Mock(
            side_effect=[
                NativeStatus(0x90020323),
                b"\x59\x04\x00\x00\x01\x00\x12\x02\x12\x34\x07\x08\xff",
            ]
        )
        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
        session._begin()
        self.assertTrue(
            session.p5_predictive_freeze_profile(state, requests, native_cancel_value=0)
        )
        self.assertEqual(requests[0].numbers, [0x12])
        self.assertEqual(state.diagnostics[0].existence_flags, 0x10)
        self.assertEqual(len(state.diagnostics[0].signals), 2)
        self.assertEqual(provider.call_count, 2)

    def test_normal_stored_ff_copies_native7c_for_new_and_existing_diagnostics(self):
        from types import SimpleNamespace

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            CommandStatus,
        )
        from scripts.diagnostic_db import Language
        from scripts.freeze_p5 import P5FreezeState
        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_freeze_p5 import database

        signals = {
            signal: (99,) for signal in (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))
        }
        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            for existing in (False, True):
                for requested in (255, 1):
                    with self.subTest(
                        build=build, existing=existing, requested=requested
                    ):
                        profile, _state = self.p5_existence_fixture(
                            build,
                            function=0xD0,
                            frame_request=bytes((0x19, 6, requested)),
                            signals=signals,
                        )
                        directory, data = bytearray(), bytearray()
                        for number in range(200):
                            encoded = (f"name{number + 1}\0").encode("utf-16le")
                            directory += struct.pack("<IH", len(data), len(encoded))
                            data += encoded
                        profile.catalog.language = Language(
                            database(build, 4, {0: (200, bytes(directory + data))})
                        )
                        operations = Mock()
                        operations.send.return_value = 0
                        operations.receive.return_value = SimpleNamespace(
                            code=0, data=bytes.fromhex("590601000001ff011234020506")
                        )
                        communication = NativeCommunication(
                            profile, operations, "ecu", bus_id=0x12, source_build=build
                        )
                        workflow = ToyotaWorkflows.from_communication(
                            communication,
                            observations=WorkflowObservations(
                                1, 0x12, source_version=build
                            ),
                        )
                        workflow._begin(source12_verified=True)
                        state = P5FreezeState(
                            profile, source_build=build, cache=communication.cache
                        )
                        if existing:
                            diagnostic = state.add_diagnostic(1, status=1, diag_type=1)
                            assert diagnostic is not None
                            diagnostic.stored_all = requested != 255
                        workflow.session._begin()
                        self.assertTrue(
                            workflow.session.p5_stored_freeze_profile(
                                state, native_cancel_value=0, connection_bus_id=0x12
                            )
                        )
                        self.assertEqual(len(state.diagnostics), 1)
                        diagnostic = state.diagnostics[0]
                        self.assertEqual(diagnostic.stored_all, requested == 255)
                        api = CommandAPI(CommandSource(build, SOURCE_SHA256[build]))
                        if build == 12:
                            result = api.compose_p5_diagnostics12(
                                CommandStatus(), state
                            )
                            report = api.p5_diagnostic_report12(result)
                        else:
                            result = api.compose_p5_diagnostics(CommandStatus(), state)
                            report = api.p5_diagnostic_report(result)
                        self.assertEqual(result.diagnostics[0].code, 1)
                        self.assertEqual(
                            result.diagnostics[0].stored_all, int(requested == 255)
                        )
                        document = json.loads(json.dumps(report))
                        self.assertEqual(
                            document["result"]["diagnostics"][0]["stored_all"],
                            int(requested == 255),
                        )
                        self.assertEqual(diagnostic.extended_numbers, [1])
                        self.assertEqual(diagnostic.diag_type, 9 if existing else 8)
                        self.assertEqual(operations.receive.call_count, 1)
                        self.assertEqual(
                            operations.send.call_args.args[0],
                            bytes((0x19, 6, requested)),
                        )
                        self.assertFalse(communication.closed)

    def test_p5_stored_concrete_d0_temp_state_then_merge(self):
        signals = {
            signal: (99,) for signal in (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))
        }
        _profile, state = self.p5_existence_fixture(function=0xD0, signals=signals)
        state.add_diagnostic(1, status=1, diag_type=1)
        response = b"\x59\x06\x01\x00\x00\x01\xff\x01\x12\x34\x02\x05\x06"
        provider = Mock(return_value=response)
        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
        session._begin()
        self.assertTrue(
            session.p5_stored_freeze_profile(
                state, native_cancel_value=0, connection_bus_id=0x14
            )
        )
        diagnostic = state.diagnostics[0]
        self.assertEqual((diagnostic.diag_type, diagnostic.status), (9, 1))
        self.assertEqual(diagnostic.extended_numbers, [1])
        self.assertEqual(diagnostic.existence_flags, 0x100)
        self.assertEqual(
            [(value.index, value.kind) for value in diagnostic.signals[0].values],
            [(0, 0x101)],
        )
        self.assertEqual(provider.call_args.args[1].receive_capacity, 65535)

    def test_p5_stored_all_masks_native_success_false_and_finite_fallback(self):
        _profile, state = self.p5_existence_fixture(function=0xD0)
        provider = Mock(side_effect=NativeStatus(0x91010009))
        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
        session._begin()
        self.assertFalse(
            session.p5_stored_freeze_profile(
                state, native_cancel_value=0, connection_bus_id=1
            )
        )
        self.assertEqual(provider.call_count, 15)
        self.assertEqual(
            [entry.args[2][2] for entry in provider.call_args_list], [0, *range(1, 15)]
        )
        self.assertEqual(state.diagnostics, [])

    def test_selected_p5_request_raw_retry_and_typed_native_once(self):
        from scripts.profiles import SelectedFrame

        profile = selected_profile((0xCD,))
        profile.category_record = bytes(76)
        row = bytearray(12)
        row[8:10] = b"\x01\x01"
        profile.dtc_status_records.return_value = (bytes(row),)
        settings = bytearray(16)
        settings[14] = 1
        frame = SelectedFrame(
            CommandFrame(b"\x19\x02\x00"), b"", b"", bytes(settings), "CD"
        )
        profile.frame_records.return_value = (frame,)
        replay = Replay(
            [(b"\x19\x02\x01", NativeStatus(77)), (b"\x19\x02\x01", b"\x59\x02\x01")]
        )
        session = ToyotaSession(replay, "ecu", {})
        self.assertTrue(
            session.read_p5_diagnostic_reply_profile(
                profile, 1, native_cancel_value=0, connection_bus_id=0x22
            )["read_succeeded"]
        )
        self.assertEqual(len(replay.calls), 2)
        provider = Mock(side_effect=NativeStatus(77))
        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
        with self.assertRaises(NativeStatus):
            session.read_p5_diagnostic_reply_profile(
                profile, 1, native_cancel_value=0, connection_bus_id=0x22
            )
        self.assertEqual(provider.call_count, 1)

    def test_selected_p5_version12_omits_subaru_and_connection_override(self):
        from scripts.profiles import SelectedFrame

        profile = selected_profile((0xCD,))
        rule = bytearray(12)
        rule[8:10] = b"\xf0\x40"
        profile.dtc_status_records.return_value = (bytes(rule),)
        profile.category_record = b""  # Native12 never queries category for this stage.
        frame = SelectedFrame(
            CommandFrame(b"\x19\x02\x00"), b"", b"", bytes(16), "CD12"
        )
        profile.frame_records.return_value = (frame,)
        seen = []

        def transaction(_, command, request):
            seen.append((command.receive_capacity, request))
            return b"\x59\x02\xff"

        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=transaction)
        for bus in (None, 0x14):
            result = session.read_p5_diagnostic_reply_profile(
                profile,
                1,
                native_cancel_value=0,
                connection_bus_id=bus,
                source_build=12,
            )
            self.assertEqual(result["maximum_groups"], 0x3FF)
        self.assertEqual(seen, [(0x1000, b"\x19\x02\x40")] * 2)

    def test_selected_p5_diagnostic_zero_mask_context_and_wire_errors(self):
        from scripts.profiles import SelectedFrame

        profile = selected_profile((0xCD,))
        profile.dtc_status_records.return_value = ()
        session = ToyotaSession(Replay([]), "ecu", {})
        result = session.read_p5_diagnostic_reply_profile(
            profile, 0, native_cancel_value=0, connection_bus_id=None
        )
        self.assertFalse(result["read_succeeded"])
        profile.frame_records.assert_not_called()
        rule = bytearray(12)
        rule[8:10] = b"\x01\x01"
        profile.dtc_status_records.return_value = (bytes(rule),)
        profile.category_record = bytes(76)
        frame = SelectedFrame(CommandFrame(b"\x19\x02\x00"), b"", b"", bytes(16), "CD")
        profile.frame_records.return_value = (frame,)
        with self.assertRaises(ToyotaCodecError) as error:
            session.read_p5_diagnostic_reply_profile(
                profile, 1, native_cancel_value=0, connection_bus_id=None
            )
        self.assertEqual(error.exception.code, 0xC0040601)
        for code in (
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
            77,
        ):
            session = ToyotaSession(
                Replay([(b"\x19\x02\x01", NativeStatus(code))]), "ecu", {}
            )
            if code == 77:
                with self.assertRaises(NativeStatus):
                    session.read_p5_diagnostic_reply_profile(
                        profile, 1, native_cancel_value=0, connection_bus_id=0x22
                    )
            else:
                result = session.read_p5_diagnostic_reply_profile(
                    profile, 1, native_cancel_value=0, connection_bus_id=0x22
                )
                self.assertFalse(result["read_succeeded"])

    def test_selected_transaction_cleanup_uses_explicit_bounded_provider(self):
        seen = []
        session = ToyotaSession(
            Replay([]),
            "ecu",
            {"stop": spec(b"\x14")},
            cancelled=lambda: True,
            native_transaction=lambda *_: self.fail(
                "Cancelled ordinary provider invoked"
            ),
            native_cleanup_transaction=lambda ecu, command, request: (
                seen.append((ecu, command, request)) or b"\x54"
            ),
        )
        session._begin()
        self.assertEqual(session._execute("stop", cleanup=True), b"\x54")
        self.assertEqual(seen[0][2], b"\x14")
        self.assertIs(seen[0][1], session.commands["stop"])
        session._remaining = 0
        with self.assertRaisesRegex(SessionError, "budget"):
            session._execute("stop", cleanup=True)
        self.assertEqual(len(seen), 1)

    def test_selected_transaction_policy_status_and_budget(self):
        flag = [False]

        def transaction(*_):
            flag[0] = True
            raise NativeStatus(77)

        session = ToyotaSession(
            Replay([]),
            "ecu",
            {"a": spec()},
            native_transaction=transaction,
            cancelled=lambda: flag[0],
        )
        with self.assertRaises(Cancelled):
            session.execute("a")
        self.assertEqual(session.trace[-1]["native_status"], 77)
        now = [0.0]

        def late(*_):
            now[0] = 2.0
            raise NativeStatus(78)

        session = ToyotaSession(
            Replay([]),
            "ecu",
            {"a": spec()},
            native_transaction=late,
            clock=lambda: now[0],
            limits=Limits(seconds=1),
        )
        with self.assertRaisesRegex(SessionError, "deadline"):
            session.execute("a")
        self.assertEqual(session.trace[-1]["native_status"], 78)
        session = ToyotaSession(
            Replay([]),
            "ecu",
            {"a": spec()},
            native_transaction=lambda *_: b"\x58",
            limits=Limits(exchanges=1),
        )
        with self.assertRaisesRegex(SessionError, "budget"):
            session.sequence(["a", "a"])
        self.assertEqual(len(session.trace), 1)

    def test_typed_native_transaction_does_not_duplicate_common_retries(self):
        provider = Mock(side_effect=NativeStatus(77))
        session = ToyotaSession(
            Replay([]), "ecu", {"count": spec()}, native_transaction=provider
        )
        with self.assertRaises(NativeStatus):
            session.count_dtcs(["count"], diagnostic_type=1, retry_counts=[2])
        self.assertEqual(provider.call_count, 1)
        row = bytearray(84)
        struct.pack_into("<HH", row, 62, 0, 7)
        row[79] = 1
        provider.reset_mock()
        session.commands["data"] = spec(b"\x21\x00")
        with self.assertRaises(NativeStatus):
            session._read_p4("data", bytes(row), b"\x01", None, retries=2)
        self.assertEqual(provider.call_count, 1)
        provider.reset_mock()
        with self.assertRaises(NativeStatus):
            session.dtcs_can("count", retries=2)
        self.assertEqual(provider.call_count, 1)
        raw = Replay(
            [
                (b"\x21\x01", NativeStatus(77)),
                (b"\x21\x01", NativeStatus(77)),
                (b"\x21\x01", b"\x61\x01\x42"),
            ]
        )
        session = ToyotaSession(raw, "ecu", {"data": spec(b"\x21\x00")})
        self.assertEqual(
            session._read_p4("data", bytes(row), b"\x01", None, retries=2), b"\x42"
        )
        self.assertEqual(len(raw.calls), 3)

    def test_routine_data_shared_selected_context_response_cache(self):
        replay = Replay([(b"\x31\x03\x12\x34", b"\x71\x03\x12\x34\x80")])
        session = ToyotaSession(replay, "ecu", {"status": spec(b"\x31\x03\x00\x00")})
        record = bytearray(24)
        struct.pack_into("<HH", record, 20, 0, 7)
        cache = {}
        for _ in range(2):
            result = session.routine_data_no_enable_list(
                0x1234,
                8,
                status_name="status",
                record=bytes(record),
                response_cache=cache,
            )
            self.assertEqual(result["value"], 0x80)
        self.assertEqual(len(replay.calls), 1)

    def test_native_send_literal_arguments_statuses_and_no_receive(self):
        calls = [
            NativeFrameSend("SendIntNoInit", 0x394, b"\x14\xff", 0x12345678, 50),
            NativeFrameSend("SendIntExtDualMon", 7, b"x" * 256, 500, 0x22),
        ]
        seen = []
        statuses = iter((0x90020323, 0))

        def send(ecu, call):
            seen.append((ecu, call.arguments))
            return next(statuses)

        replay = Replay([])
        session = ToyotaSession(replay, "ecu", {}, native_send=send)
        self.assertEqual(
            session.native_frame_sends(calls, ignore_status=True), [0x90020323, 0]
        )
        self.assertEqual(
            seen[0], ("ecu", (0x394, b"\x14\xff", 2, 0x12345678, 50, 0, 1))
        )
        self.assertEqual(seen[1][1][2], 256)
        self.assertFalse(replay.calls)
        self.assertTrue(all(event["send_only"] for event in session.trace))
        with self.assertRaises(ValueError):
            NativeFrameSend("SendIntNoInit", 1, b"x" * 256, 0, 0)

    def test_native_extended_send_ushort_bounds(self):
        for operation in ("SendIntExt", "SendIntNoInitExt"):
            with self.subTest(operation=operation):
                call = NativeFrameSend(operation, 1, b"x" * 65535, 500, 0x22)
                self.assertEqual(call.arguments[2], 65535)
                with self.assertRaises(ValueError):
                    NativeFrameSend(operation, 1, b"x" * 65536, 500, 0x22)

    def test_native_send_failures_policy_and_shared_budget(self):
        call = NativeFrameSend("SendIntNoInit", 0x394, b"\x14", 1, 50)
        with self.assertRaises(SessionError):
            ToyotaSession(Replay([]), "ecu", {}).native_frame_sends([call])
        session = ToyotaSession(Replay([]), "ecu", {}, native_send=lambda *_: 77)
        with self.assertRaises(NativeStatus) as error:
            session.native_frame_sends([call])
        self.assertEqual(error.exception.code, 77)
        session = ToyotaSession(
            Replay([]), "ecu", {}, limits=Limits(exchanges=1), native_send=lambda *_: 77
        )
        with self.assertRaisesRegex(SessionError, "budget"):
            session.native_frame_sends([call, call], ignore_status=True)
        self.assertEqual(len(session.trace), 1)
        for raised in (False, True):
            cancelled = [False]

            def send(*_, flag=cancelled, fail=raised):
                flag[0] = True
                if fail:
                    raise NativeStatus(77)
                return 77

            session = ToyotaSession(
                Replay([]),
                "ecu",
                {},
                native_send=send,
                cancelled=lambda flag=cancelled: flag[0],
            )
            with self.assertRaises(Cancelled):
                session.native_frame_sends([call], ignore_status=True)
        now = [0.0]

        def late_send(*_):
            now[0] = 2.0
            raise NativeStatus(77)

        session = ToyotaSession(
            Replay([]),
            "ecu",
            {},
            native_send=late_send,
            limits=Limits(seconds=1),
            clock=lambda: now[0],
        )
        with self.assertRaisesRegex(SessionError, "deadline"):
            session.native_frame_sends([call], ignore_status=True)
        self.assertEqual(session.trace[0]["native_status"], 77)

    def test_p5_zero_mask_ordinal_native_signed_division(self):
        record = bytearray(0x36)
        struct.pack_into("<H", record, 0x34, 0x1234)
        struct.pack_into("<HH", record, 0x28, 0, 15)
        row = bytearray(12)
        struct.pack_into("<HHH", row, 4, 0, 0, 2)
        start, release, _ = active_arguments_p5(
            bytes(record),
            [bytes(row)],
            bytes.fromhex("2f000003"),
            bytes.fromhex("2f000000"),
            0x4567,
            2,
            bytes(24),
        )
        self.assertEqual(start, bytes.fromhex("2f123403456701"))
        self.assertEqual(release, bytes.fromhex("2f12340001"))

    def test_dk_iso_freeze_groups_override_first_duplicates_and_selected_bits(self):
        reply = b"\x00\x12\xaa\xbb\x34\x80\x12\xcc\xdd"
        data = parse_dk_iso_freeze(reply, {0x12: 2}, {0x12: 1, 0x34: 1})
        self.assertEqual(data, {0x12: b"\xaa\xbb", 0x34: b"\x80"})
        row = bytearray(84)
        row[79] = 0x12
        struct.pack_into("<HH", row, 62, 8, 15)
        self.assertEqual(dk_iso_freeze_value(bytes(row), data), 0xBB)
        row[79] = 0x99
        with self.assertRaises(ToyotaCodecError) as failure:
            dk_iso_freeze_value(bytes(row), data)
        self.assertEqual(failure.exception.code, 0xC0040001)
        for freeze_lengths, pid_lengths, code in [
            ({}, {}, 0xC0040101),
            ({0x12: 0}, {0x12: 1}, 0xC0050102),
            ({0x12: 3}, {}, SHORT_REPLY),
        ]:
            with self.assertRaises(ToyotaCodecError) as failure:
                parse_dk_iso_freeze(b"\x00\x12\xaa", freeze_lengths, pid_lengths)
            self.assertEqual(failure.exception.code, code)

    def test_dk_iso_native_no_sid_retries_and_first_selected_frame(self):
        row = bytearray(84)
        row[78], row[79] = 2, 0x12
        struct.pack_into("<HH", row, 62, 0, 7)
        disabled = bytearray(row)
        disabled[77], disabled[79] = 2, 0x99
        replay = Replay(
            [
                (b"\x11", NativeStatus(0x90020323)),
                (b"\x11", b"\x00\x12\xaa"),
                (b"\x12", b"\xff"),
            ]
        )
        session = ToyotaSession(
            replay, "ecu", {"first": spec(b"\x11"), "second": spec(b"\x12")}
        )
        self.assertEqual(
            session.freeze_dk_iso(
                ["first", "second"],
                [bytes(row), bytes(disabled)],
                {0x12: 1},
                {},
                retries=1,
            ),
            {0: 0xAA},
        )
        self.assertFalse(replay.steps)
        replay = Replay([(b"\x18", b"\x12\x34\x00")])
        session = ToyotaSession(replay, "ecu", {"dtc": spec(b"\x18")})
        self.assertEqual(session.dtcs_dk_iso("dtc"), [0x12, 0x34])

    def test_absolute_pid_logs_selector_masked_failure_reads_then_omits_and_caches(
        self,
    ):
        setter = bytearray(24)
        setter[14], setter[21] = 0x20, 0x53
        first, year = bytearray(44), bytearray(44)
        struct.pack_into("<HH", first, 20, 0, 15)
        struct.pack_into("<HH", year, 20, 16, 23)
        first[39] = year[39] = 0x8F
        replay = Replay(
            [
                (b"\x30\x53\x20\x00\x01", b"\x70\x53\x01"),
                (b"\x21\x8f", b"\x61\x8f\x00\x01\x24"),
                (b"\x30\x53\x20\x00\x02", NativeStatus(0x90020323)),
                (b"\x21\x8f", b"\x61\x8f\x00\x02\x25"),
                (b"\x30\x53\x20\x00\x03", b"\x70\x53\x01"),
                (b"\x21\x8f", NativeStatus(0x91010009)),
            ]
        )
        session = ToyotaSession(
            replay, "ecu", {"set": spec(b"\x30"), "read": spec(b"\x21\x00")}
        )
        self.assertEqual(
            session.read_absolute_pid_logs(
                "set",
                "read",
                [1, 2, 3],
                bytes(setter),
                b"",
                [(0x8F, bytes(first), False), (0x91, bytes(year), True)],
                {0x8F: b"\x01\x01\x01"},
            ),
            [{"log_number": 1, "components": {1: 1, 3: 24}}],
        )
        self.assertFalse(replay.steps)
        self.assertEqual(len(replay.calls), 6)

    def test_absolute_pid_logs_bcd_and_selector_rejection_are_not_masked(self):
        setter = bytes(24)
        row = bytearray(44)
        row[39] = 0x91
        struct.pack_into("<HH", row, 20, 0, 7)
        for selector_reply, read_reply, code in [
            (b"\x70\x00\x00", None, 0xA0040207),
            (b"\x70\x00\x01", b"\x61\x91\xfa", 0xA0040208),
        ]:
            steps = [(b"\x30\x00\x00\x00\x01", selector_reply)]
            if read_reply is not None:
                steps.append((b"\x21\x91", read_reply))
            replay = Replay(steps)
            session = ToyotaSession(
                replay, "ecu", {"set": spec(b"\x30"), "read": spec(b"\x21\x00")}
            )
            with self.assertRaises(ToyotaCodecError) as failure:
                session.read_absolute_pid_logs(
                    "set",
                    "read",
                    [1],
                    setter,
                    b"",
                    [(0x91, bytes(row), True)],
                    {0x91: b"\x01"},
                )
            self.assertEqual(failure.exception.code, code)
            self.assertFalse(replay.steps)

    def test_absolute_pid_logs_one_budget_covers_selector_and_components(self):
        row = bytearray(44)
        row[39] = 0x8F
        struct.pack_into("<HH", row, 20, 0, 7)
        replay = Replay([(b"\x30\x00\x00\x00\x01", b"\x70\x00\x01")])
        session = ToyotaSession(
            replay,
            "ecu",
            {"set": spec(b"\x30"), "read": spec(b"\x21\x00")},
            limits=Limits(exchanges=1),
        )
        with self.assertRaises(SessionError):
            session.read_absolute_pid_logs(
                "set",
                "read",
                [1],
                bytes(24),
                b"",
                [(0x8F, bytes(row), False)],
                {0x8F: b"\x01"},
            )
        self.assertEqual(len(replay.calls), 1)

    def test_comm_did_native_mask_padding_and_reply_rejection(self):
        row = bytearray(24)
        struct.pack_into("<H", row, 4, 16)
        row[14], row[21] = 0x20, 0x53
        positions = b"\x01\x00\x01\x01\x00\x01"
        request = b"\x30\x53\x20\x00\x12\x34\x00"
        self.assertEqual(
            comm_did_request(b"\x30", bytes(row), positions, b"\x12\x34"), request
        )
        replay = Replay([(request, b"\x70\x53\x00"), (request, b"\x70\x53\x01")])
        session = ToyotaSession(replay, "ecu", {"send": spec(b"\x30", check="raw")})
        with self.assertRaises(ToyotaCodecError) as failure:
            session.send_comm_did("send", bytes(row), positions, b"\x12\x34")
        self.assertEqual(failure.exception.code, 0xA0040207)
        self.assertEqual(
            session.send_comm_did("send", bytes(row), positions, b"\x12\x34"),
            b"\x70\x53\x01",
        )
        with self.assertRaises(ToyotaCodecError):
            comm_did_request(b"\x30", bytes(row), b"\x01", b"x")
        with self.assertRaises(ToyotaCodecError):
            comm_did_request(b"\x30", bytes(row), positions, bytes(255))
        # Native appends commands beyond the support map, without truncation.
        struct.pack_into("<H", row, 4, 0)
        self.assertEqual(
            comm_did_request(b"\x30", bytes(row), b"", b"xy"), b"\x30\x53\x20xy"
        )

    def test_comm_signal_setdata_native_metadata_and_signed_value(self):
        for routine in (False, True):
            row = bytearray(36 if routine else 44)
            struct.pack_into("<iii", row, 0, 2, 1, 3)
            struct.pack_into("<HH", row, 20, 8, 15)
            struct.pack_into("<H", row, 24 if routine else 28, 0x4567)
            row[33 if routine else 40] = 1
            row[34 if routine else 41] = 2
            data = comm_signal_data(bytes(row), 0xFF, routine=routine, unit="V")
            self.assertEqual(
                (data["raw"], data["value"], data["display"]), (255, 1, " 0.01")
            )
            self.assertEqual(
                (data["unit"], data["selector"], data["bits"]), ("V", 2, 8)
            )
            self.assertEqual(data["native_58"], 0x4567)
            self.assertEqual(data["native_74"], 0)
            self.assertEqual((data["name"], data["short_name"]), ("", ""))
            self.assertEqual((data["multi_core_type"], data["multi_index"]), (1, 0))

    def test_legacy_active_session_step_bounds_and_cancel(self):
        queue = LegacyActiveQueue()
        queue.enqueue(b"\x02")
        replay = Replay([(b"\x30\x02", b"\x70\x01"), (b"\x30", b"\x70")])
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=1))
        self.assertEqual(session.legacy_active_step(queue, 0), b"\x70\x01")
        self.assertIsNone(session.legacy_active_step(queue, 1))
        queue.stop()
        self.assertEqual(session.legacy_active_step(queue, 2), b"\x70")
        self.assertFalse(replay.steps)
        flag = [False]

        def exchange(ecu, request):
            flag[0] = True
            return b"\x70"

        queue = LegacyActiveQueue()
        queue.enqueue(b"\x02")
        session = ToyotaSession(exchange, "ecu", {}, cancelled=lambda: flag[0])
        with self.assertRaises(Cancelled):
            session.legacy_active_step(queue, 0)
        self.assertEqual(
            queue.items[0].state, 1
        )  # reply not accepted after cancellation

    def test_legacy_active_ordinary_wire_reply_repeat_and_stop(self):
        queue = LegacyActiveQueue()
        queue.enqueue(b"\x01\x02", repeat_ms=10)
        self.assertEqual(queue.next_request(100), b"\x30\x01\x02")
        queue.accept(b"\x70\x01", 100)
        self.assertEqual((queue.items[0].state, queue.items[0].next_tick), (3, 110))
        self.assertIsNone(queue.next_request(109))
        self.assertIsNone(queue.next_request(110))
        self.assertEqual(queue.next_request(110), b"\x30\x01\x02")
        queue.accept(b"\x70\x01", 0xFFFFFFFF)
        self.assertEqual(queue.items[0].next_tick, 9)
        queue.stop(initialize=True)
        self.assertTrue(queue.init_flag)
        self.assertEqual(queue.next_request(0), b"\x30")
        queue.accept(b"\x70", 1)
        self.assertEqual(queue.items[0].state, 5)
        self.assertIsNone(queue.next_request(2))

    def test_legacy_active_ordinary_native_unknown_lengths_and_advance(self):
        queue = LegacyActiveQueue()
        queue.enqueue(b"a")
        queue.enqueue(b"b")
        queue.send_frame(0)
        queue.accept(b"\x70\x01\x02\x03", 0)
        self.assertEqual(queue.items[0].state, 1)  # Native length>3 leaves state.
        self.assertEqual(queue.next_request(0), b"\x30a")
        for reply, code in ((b"\x71", 0xE0000102), (b"\x70\x00\x00", 0xE00001CC)):
            with self.assertRaises(ToyotaCodecError) as failure:
                queue.accept(reply, 0)
            self.assertEqual(failure.exception.code, code)
        queue.accept(b"\x70\x01", 0)
        self.assertEqual(queue.items[0].state, 4)
        self.assertEqual(queue.next_request(0), b"\x30b")
        queue.enqueue(b"c")
        queue.skip_to_last()
        self.assertEqual(queue.send_frame(1), b"\x30c")

    def test_legacy_active_dk_native_tail_and_prune(self):
        queue = LegacyActiveQueue("dk")
        queue.enqueue(b"a")
        queue.enqueue(b"b")
        self.assertEqual(queue.send_frame(0), b"\x3db")
        queue.accept(b"\x7d", 10)
        self.assertEqual(queue.items[-1].state, 1)
        queue.enqueue(b"c")
        self.assertEqual(len(queue.items), 2)
        self.assertEqual(queue.items[0].request, b"\x3db")
        self.assertEqual(queue.send_frame(11), b"\x3dc")
        with self.assertRaises(ToyotaCodecError) as failure:
            queue.accept(b"\x70", 11)
        self.assertEqual(failure.exception.code, 0xE0030001)
        with self.assertRaises(SessionError):
            queue.stop()

    def test_legacy_active_psa_repeat_stop_delay_and_error_states(self):
        queue = LegacyActiveQueue("psa")
        queue.enqueue(b"\x31\x04\x20\xaa\xbb", repeat_ms=20)
        self.assertEqual(queue.send_frame(100), b"\x31\x04\x20\xaa\xbb")
        queue.accept(b"\x71\x04\x01\xff", 100)
        item = queue.items[-1]
        self.assertEqual(
            (item.request, item.state, item.next_tick), (b"\x31\x04\x01\xaa", 1, 120)
        )
        with self.assertRaises(ToyotaCodecError):
            queue.enqueue(b"\x30\x04\x00")
        queue.stop()
        self.assertEqual(queue.items[-1].request, b"\x31\x04\x11\xaa")
        self.assertIsNone(queue.send_frame(149))
        self.assertEqual(queue.send_frame(150), b"\x31\x04\x11\xaa")
        queue.accept(b"\x71\x04\x11", 150)
        self.assertEqual(queue.items[-1].state, 2)
        queue.enqueue(b"\x30\x04\x00")
        self.assertEqual(len(queue.items), 2)
        queue.send_frame(200)
        queue.accept(b"\x70\x04\x01", 200)
        self.assertEqual(queue.items[-1].state, 2)
        count = len(queue.items)
        queue.stop()  # no repeat deadline => native no-op
        self.assertEqual(len(queue.items), count)
        for status, code in ((0, 0xE00001CC), (3, 0xE0000106)):
            with self.assertRaises(ToyotaCodecError) as failure:
                queue.accept(bytes([0x70, 4, status]), 210)
            self.assertEqual(failure.exception.code, code)
            self.assertEqual(queue.last_tick, 210)

    def test_comm_pid_native_protocol_selection_support_and_bcd(self):
        row = bytearray(44)
        struct.pack_into("<HH", row, 20, 8, 15)
        struct.pack_into("<H", row, 34, 0x1234)
        row[39] = 0x8F
        replay = Replay(
            [
                (b"\x21\x8f", b"\x61\x8f\x24"),
                (b"\x22\x12\x34", b"\x62\x12\x34\x00\x25"),
                (b"\x22\x12\x34", b"\x62\x12\x34\x00\x26"),
                (b"\x22\x12\x34", b"\x62\x12\x34\x00\x27"),
            ]
        )
        session = ToyotaSession(
            replay,
            "ecu",
            {
                "ordinary": spec(b"\x21\x00"),
                "extended": spec(b"\x22\x00\x00"),
            },
        )
        self.assertEqual(
            session.read_comm_pid(
                "ordinary", bytes(row), 4, positions=b"\x00\x01", bcd=True
            ),
            24,
        )
        for category, expected in ((0x14, 25), (0x15, 26), (0x34, 27)):
            self.assertEqual(
                session.read_comm_pid("extended", bytes(row), category, bcd=True),
                expected,
            )
        self.assertFalse(replay.steps)
        with self.assertRaises(SessionError):
            session.read_comm_pid("ordinary", bytes(row), 0x16)
        self.assertEqual(len(replay.calls), 4)

    def test_comm_pid_late_support_after_data_and_cached_order(self):
        from scripts.monitor_support import MonitorSupportCache

        row = bytearray(44)
        struct.pack_into("<HH", row, 20, 8, 15)
        row[39] = 0x8F
        events = []
        support = Mock(spec=MonitorSupportCache)

        def masks(kind):
            events.append(("support", kind))
            return {0x8F: b"\x00\x01"}

        support.support_bits.side_effect = masks

        def exchange(_, request):
            events.append(("data", request))
            return b"\x61\x8f\x24"

        session = ToyotaSession(exchange, "ecu", {"read": spec(b"\x21\x00")})
        cache = {}
        self.assertEqual(
            session.read_comm_pid(
                "read", bytes(row), 4, support_cache=support, response_cache=cache
            ),
            0x24,
        )
        self.assertEqual(
            session.read_comm_pid(
                "read", bytes(row), 4, support_cache=support, response_cache=cache
            ),
            0x24,
        )
        self.assertEqual(
            events, [("data", b"\x21\x8f"), ("support", 1), ("support", 1)]
        )
        support.support_bits.return_value = {}
        support.support_bits.side_effect = None
        with self.assertRaises(ToyotaCodecError) as error:
            session.read_comm_pid("read", bytes(row), 4, support_cache=support)
        self.assertEqual(error.exception.code, 0xC0040001)
        # Wire failure never triggers support discovery.
        support.reset_mock()
        session = ToyotaSession(
            Replay([(b"\x21\x8f", NativeStatus(77))]),
            "ecu",
            {"read": spec(b"\x21\x00")},
        )
        with self.assertRaises(NativeStatus):
            session.read_comm_pid("read", bytes(row), 4, support_cache=support)
        support.support_bits.assert_not_called()

    def test_comm_pid_rejects_sid_short_bits_and_template_overread(self):
        row = bytearray(44)
        struct.pack_into("<HH", row, 20, 0, 7)
        for request, reply, code in [
            (b"\x22\x00\x00", b"\x00\x00\x00\x24", 0xA0040201),
            (b"\x22\x00\x00", b"\x62\x00\x00", SHORT_REPLY),
            (b"\x22\x00\x00\xff", b"\x62\x00\x00\x24", SHORT_REPLY),
        ]:
            replay = Replay([(request, reply)])
            session = ToyotaSession(replay, "ecu", {"read": spec(request, check="raw")})
            with self.assertRaises(ToyotaCodecError) as failure:
                session.read_comm_pid("read", bytes(row), 0x14)
            self.assertEqual(failure.exception.code, code)
        struct.pack_into("<HH", row, 20, 8, 15)
        replay = Replay([(b"\x22\x00\x00", b"\x62\x00\x00\x24")])
        session = ToyotaSession(replay, "ecu", {"read": spec(b"\x22\x00\x00")})
        with self.assertRaises(ToyotaCodecError):
            session.read_comm_pid("read", bytes(row), 0x14)

    def test_absolute_routine_logs_cache_bcd_skip_and_native_number_packing(self):
        def row(begin, end):
            result = bytearray(36)
            struct.pack_into("<HH", result, 20, begin, end)
            return bytes(result)

        components = [(1, row(0, 15), False), (3, row(16, 23), True)]
        replay = Replay(
            [
                (b"\x31\x01\x11\x04\x00\x01", b"\x71\x01\x11\x04"),
                (b"\x31\x03\x11\x04", b"\x71\x03\x11\x04\x00\x01\x24"),
                (b"\x31\x01\x11\x04\x00\x02", b"\x71\x01\x11\x04"),
                (b"\x31\x03\x11\x04", b"\x71\x03\x11\x04\x00\x02\xfa"),
                (b"\x31\x01\x11\x04\x00\x03", NativeStatus(0x90020323)),
                (b"\x31\x01\x11\x04\x00\x04", b"\x71\x01\x11\x04"),
                (b"\x31\x03\x11\x04", b"\x71\x03\x11\x04\x00\x04\x25"),
            ]
        )
        session = ToyotaSession(
            replay,
            "ecu",
            {
                "command": spec(b"\x31\x01\x00\x00"),
                "status": spec(b"\x31\x03\x00\x00"),
            },
        )
        self.assertEqual(
            session.read_absolute_routine_logs(
                "command",
                "status",
                [1, 2, 3, 4],
                components,
            ),
            [
                {"log_number": 1, "components": {1: 1, 3: 24}},
                {"log_number": 4, "components": {1: 4, 3: 25}},
            ],
        )
        self.assertFalse(replay.steps)
        self.assertEqual(decode_bcd32(0x99999999), 99999999)
        with self.assertRaises(ToyotaCodecError) as failure:
            decode_bcd32(0xA0000000)
        self.assertEqual(failure.exception.code, 0xA0040208)
        # No blanket nibble masking of invalid high digits.
        replay = Replay(
            [
                (b"\x31\x01\x11\x04\x00\x01", b"\x71\x01\x11\x04"),
                (b"\x31\x03\x11\x04", b"\x71\x03\x11\x04\x00\x01"),
            ]
        )
        session = ToyotaSession(
            replay,
            "ecu",
            {
                "command": spec(b"\x31\x01\x00\x00"),
                "status": spec(b"\x31\x03\x00\x00"),
            },
        )
        self.assertEqual(
            session.read_absolute_routine_logs(
                "command",
                "status",
                [0x10001],
                components[:1],
            ),
            [],
        )  # Wire number truncates, comparison retains all32 log bits.

    def test_absolute_routine_logs_budget_and_cancel_are_not_masked(self):
        row = bytearray(36)
        struct.pack_into("<HH", row, 20, 0, 7)
        commands = {
            "command": spec(b"\x31\x01\x00\x00"),
            "status": spec(b"\x31\x03\x00\x00"),
        }
        replay = Replay([(b"\x31\x01\x11\x04\x00\x01", b"\x71\x01\x11\x04")])
        session = ToyotaSession(replay, "ecu", commands, limits=Limits(exchanges=1))
        with self.assertRaises(SessionError):
            session.read_absolute_routine_logs(
                "command", "status", [1], [(1, bytes(row), False)]
            )
        self.assertEqual(len(replay.calls), 1)
        cancelled = [False]

        def exchange(ecu, request):
            cancelled[0] = True
            raise NativeStatus(0x90020323)

        session = ToyotaSession(
            exchange, "ecu", commands, cancelled=lambda: cancelled[0]
        )
        with self.assertRaises(Cancelled):
            session.read_absolute_routine_logs(
                "command", "status", [1, 2], [(1, bytes(row), False)]
            )

    def test_absolute_saved_log_twelve_components_sentinels_and_native_ranges(self):
        values = (7, 123, 99, 2, 31, 23, 59, 59, 1, 12, 59, 1)
        samples = [(index, value, 16) for index, value in enumerate(values, 1)]
        expected = dict(enumerate(values, 1))
        # Native ranges do not reject February31 or invent a year epoch.
        self.assertEqual(assemble_absolute_log(samples, 7), expected)
        pid_samples = [
            (identifier + 0x8E, value, bits) for identifier, value, bits in samples
        ]
        self.assertEqual(
            assemble_absolute_log(pid_samples, 7, pid_identifiers=True), expected
        )
        for component, value in (
            (1, 8),
            (2, 65535),
            (3, 100),
            (4, 0),
            (5, 32),
            (6, 24),
            (7, 60),
            (8, 60),
            (9, 2),
            (10, 13),
            (11, 60),
            (12, 2),
        ):
            changed = list(samples)
            changed[component - 1] = component, value, 16
            self.assertIsNone(assemble_absolute_log(changed, 7))
        self.assertIsNone(assemble_absolute_log([(1, 255, 8)], 255))
        self.assertEqual(assemble_absolute_log([(9, 1, 1)], 7), {9: 1})
        self.assertEqual(assemble_absolute_log([(3, 1, 8), (3, 2, 8)], 7), {3: 2})
        with self.assertRaises(ToyotaCodecError):
            assemble_absolute_log([(13, 0, 8)], 7)

    def test_specialized_native_helpers_check_sid_even_with_raw_descriptors(self):
        freeze = bytearray(84)
        freeze[79] = 0x21
        struct.pack_into("<HH", freeze, 62, 0, 7)
        active = bytearray(64)
        struct.pack_into("<HH", active, 40, 0, 7)
        cases = [
            (b"\x21\x00", lambda session: session.read_ecu_p3("raw", bytes(freeze))),
            (b"\x31\x01\x00\x00", lambda session: session.read_routine_data("raw", 1)),
            (
                b"\x22\x00\x00",
                lambda session: session.read_active_initial_p5("raw", bytes(active)),
            ),
            (
                b"\x12\x00\x00\x00",
                lambda session: session.freeze_dk_abs("raw", bytes(freeze), 7),
            ),
            (
                b"\x12\x00\x00\x00",
                lambda session: session.freeze_dk_roof("raw", bytes(freeze), 7),
            ),
            (
                b"\x12\x00\x00",
                lambda session: session.freeze_psa("raw", bytes(freeze), number=7),
            ),
            (
                b"\x12\x00\x00",
                lambda session: session.freeze_no_frame_number(
                    "raw", bytes(freeze), 7, {0x21: 1}
                ),
            ),
            (
                b"\x12\x00\x00\x00",
                lambda session: session.freeze_dk("raw", [bytes(freeze)], 7, {0x21: 1}),
            ),
            (b"\x19", lambda session: session.dtcs_tesla("raw", b"\xff" * 57, {})),
            (b"\x19", lambda session: session.dtcs_p5("raw", [])),
        ]
        for request, operation in cases:
            session = ToyotaSession(
                lambda ecu, wire: bytes(59), "ecu", {"raw": spec(request, check="raw")}
            )
            with self.subTest(request=request, operation=operation):
                with self.assertRaises(ToyotaCodecError) as error:
                    operation(session)
                self.assertEqual(error.exception.code, 0xA0040201)

    def test_routine_no_enable_flags_probe_command_status_and_shared_limits(self):
        commands = {
            "cc": spec(bytes.fromhex("31010000")),
            "d7": spec(bytes.fromhex("31030000")),
        }
        row = bytearray(24)
        struct.pack_into("<HH", row, 20, 4, 11)
        steps = [
            (bytes.fromhex("3101100155"), bytes.fromhex("71011001000020")),
            (bytes.fromhex("3101120055"), bytes.fromhex("7101120040")),
            (bytes.fromhex("3101120255"), bytes.fromhex("71011202bb")),
            (bytes.fromhex("31031202"), bytes.fromhex("71031202abcd")),
        ]
        session = ToyotaSession(
            Replay(steps.copy()), "ecu", commands, limits=Limits(exchanges=4)
        )
        self.assertEqual(
            session.routine_data_no_enable_list(
                0x1202,
                15,
                command_name="cc",
                status_name="d7",
                command=b"\x55",
                record=bytes(row),
            ),
            {"phase": 2, "supported": True, "value": 0xBC, "payload": b"\xab\xcd"},
        )
        session = ToyotaSession(
            Replay([(steps[0][0], bytes.fromhex("71011001000000"))]), "ecu", commands
        )
        self.assertEqual(
            session.routine_data_no_enable_list(
                0x1202, 3, command_name="cc", command=b"\x55"
            ),
            {"phase": 0, "supported": False, "value": None, "payload": None},
        )
        session = ToyotaSession(
            Replay([steps[0]]), "ecu", commands, limits=Limits(exchanges=1)
        )
        with self.assertRaises(SessionError):
            session.routine_data_no_enable_list(
                0x1202, 3, command_name="cc", command=b"\x55"
            )
        # Identical successful CC probe/command is served by native cache.
        replay = Replay(
            [(bytes.fromhex("3101100155"), bytes.fromhex("71011001000080"))]
        )
        session = ToyotaSession(replay, "ecu", commands, limits=Limits(exchanges=1))
        result = session.routine_data_no_enable_list(
            0x1001, 5, command_name="cc", command=b"\x55"
        )
        self.assertEqual(result["phase"], 1)
        self.assertIsNone(result["value"])
        self.assertEqual(result["payload"], bytes.fromhex("000080"))

    def test_routine_native_phase_failures_do_not_prevalidate_later_descriptors(self):
        replay = Replay([(bytes.fromhex("3101123455"), bytes.fromhex("7101123400"))])
        session = ToyotaSession(replay, "ecu", {"cc": spec(bytes.fromhex("31010000"))})
        with self.assertRaisesRegex(SessionError, "not selected"):
            session.routine_data_no_enable_list(
                0x1234, 12, command_name="cc", status_name="missing", command=b"\x55"
            )
        self.assertEqual(len(replay.calls), 1)
        replay = Replay([(bytes.fromhex("31011001"), bytes.fromhex("71011001000080"))])
        session = ToyotaSession(replay, "ecu", {"cc": spec(bytes.fromhex("31010000"))})
        with self.assertRaises(ToyotaCodecError) as error:
            session.routine_data_no_enable_list(0x1001, 5, command_name="cc")
        self.assertEqual(error.exception.code, 0xC0040001)
        self.assertEqual(len(replay.calls), 1)
        replay = Replay([(bytes.fromhex("31031234"), bytes.fromhex("7103123480"))])
        session = ToyotaSession(
            replay, "ecu", {"status": spec(bytes.fromhex("31030000"))}
        )
        with self.assertRaises(ToyotaCodecError):
            session.routine_data_no_enable_list(0x1234, 8, status_name="status")
        self.assertEqual(len(replay.calls), 1)

    def test_routine_support_tables_and_selected_flag8_signal(self):
        self.assertTrue(routine_support_bit(b"\x80", 0x0001, 1))
        self.assertTrue(routine_support_bit(b"\x01", 0x0701, 1))
        self.assertTrue(routine_support_bit(b"\x40", 0x1202, 2))
        self.assertFalse(routine_support_bit(b"\x80", 0x0002, 2))
        self.assertFalse(routine_support_bit(b"\x80", 0x1001, 1))
        with self.assertRaises(ToyotaCodecError) as error:
            routine_support_bit(b"\x80", 0x0801, 1)
        self.assertEqual(error.exception.code, SHORT_REPLY)
        with self.assertRaises(ToyotaCodecError):
            routine_support_bit(b"\x80", 0x1200, 2)
        row = bytearray(24)
        struct.pack_into("<HH", row, 20, 4, 11)
        replay = Replay([(bytes.fromhex("31031234"), bytes.fromhex("71031234abcd"))])
        session = ToyotaSession(
            replay, "ecu", {"signal": spec(bytes.fromhex("31030000"))}
        )
        self.assertEqual(
            session.read_routine_signal("signal", 0x1234, bytes(row)), 0xBC
        )

    def test_selected_routine_data_keeps_template_tail_and_four_byte_prefix(self):
        replay = Replay(
            [
                (bytes.fromhex("31011234aa55"), bytes.fromhex("71011234aabb")),
                (bytes.fromhex("31010000aa"), bytes.fromhex("71010000")),
            ]
        )
        session = ToyotaSession(
            replay, "ecu", {"rid": spec(bytes.fromhex("31010000aa"))}
        )
        self.assertEqual(session.read_routine_data("rid", 0x1234, b"\x55"), b"\xaa\xbb")
        self.assertEqual(session.read_routine_data("rid", 0), b"")
        session = ToyotaSession(
            Replay([(bytes.fromhex("31011234"), bytes.fromhex("710112"))]),
            "ecu",
            {"rid": spec(bytes.fromhex("31010000"))},
        )
        with self.assertRaises(ToyotaCodecError) as error:
            session.read_routine_data("rid", 0x1234)
        self.assertEqual(error.exception.code, SHORT_REPLY)

    def test_multi_freeze_receive_only_timeout_retry_and_packet_prefix(self):
        freeze = bytearray(84)
        freeze[79] = 0x21
        struct.pack_into("<HH", freeze, 62, 0, 15)
        command = bytes.fromhex("122107")
        replay = Replay(
            [
                (command, NativeStatus(0x91010009)),
                (command, bytes.fromhex("522107aa")),
                (b"", bytes.fromhex("522107bb")),
                (b"", NativeStatus(0x91010009)),
            ]
        )
        session = ToyotaSession(replay, "ecu", {"multi": spec(bytes.fromhex("120000"))})
        self.assertEqual(
            session.freeze_multi_p3("multi", bytes(freeze), 7, retries=1),
            bytes.fromhex("aabb"),
        )
        for status in (0x90020323, 0x90020321, 0xA0040201):
            replay = Replay(
                [(command, bytes.fromhex("522107aa")), (b"", NativeStatus(status))]
            )
            session = ToyotaSession(
                replay, "ecu", {"multi": spec(bytes.fromhex("120000"))}
            )
            with self.assertRaises(NativeStatus) as error:
                session.freeze_multi_p3("multi", bytes(freeze), 7, retries=3)
            self.assertEqual(error.exception.code, status)
            self.assertFalse(replay.steps)

    def psa_profile_fixture(self, *, template=b"\x12\x00\x00"):
        profile = selected_profile(functions=(6, 10))
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(b"\x18")
                if function == 10
                else CommandFrame(template, b"\x00\x00\xff\xff"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        return profile, functions

    def test_selected_psa_plain_retains_duplicates_and_prefix_mask_ffd(self):
        profile, functions = self.psa_profile_fixture()
        replay = Replay(
            [
                (b"\x18", b"\x58\x02\x12\x34\x00\x12\x34\x00"),
                (b"\x12\x00\x00", b"\x52\x00\x12\x34\xff"),
            ]
        )
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=2))
        result = session.dtcs_psa_profile(profile, 2, functions)
        self.assertEqual(result["codes"], [0x1234, 0x1234])
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234, True, 0),) * 2)
        self.assertFalse(replay.steps)

    def test_selected_psa_v2_counts_filtered_codes_before_descending_ffd(self):
        profile, functions = self.psa_profile_fixture()
        replay = Replay(
            [
                (b"\x18", b"\x58\x02\x12\x34\x29\x56\x78\x00"),
                (b"\x12\x00\x01", NativeStatus(77)),
                (b"\x12\x00\x00", b"\x52\x00\x56\x78"),
            ]
        )
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=3))
        result = session.dtcs_psa_profile(profile, 1, functions, family="v2")
        self.assertEqual(result["native_count"], 2)
        self.assertEqual(result["codes"], [0x5678])
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x5678, True, 0),))
        self.assertFalse(replay.steps)

    def test_selected_psa_no_status_dtc_keyed_ffd_and_boolean_gate(self):
        profile, functions = self.psa_profile_fixture(template=b"\x12\x00\x00\x00")
        functions.function.return_value = (True, 0)
        replay = Replay(
            [
                (b"\x18", b"\x58\x02\x12\x34\x12\x34"),
                (b"\x12\x00\x12\x34", b"\x52\x00\x12\x34"),
                (b"\x12\x00\x12\x34", NativeStatus(0x90020321)),
            ]
        )
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=3))
        result = session.dtcs_psa_profile(profile, 2, functions, family="no_status")
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234, True, 0),) * 2)
        functions.function.return_value = (False, 1)
        replay = Replay([(b"\x18", b"\x58\x01\x12\x34")])
        session = ToyotaSession(replay, "ecu", {})
        result = session.dtcs_psa_profile(profile, 2, functions, family="no_status")
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234),))
        self.assertFalse(replay.steps)

    def test_selected_psa_zero_overflow_leaves_native_out_count_unwritten(self):
        profile, functions = self.psa_profile_fixture()

        def frames(function):
            if function == 6:
                return (
                    Mock(
                        frame=CommandFrame(b"\x12\x00\x00", b"\x00\x00\xff\xff"),
                        settings_record=bytes(16),
                        provenance="selected",
                    ),
                )
            return tuple(
                Mock(
                    frame=CommandFrame(request),
                    settings_record=bytes(16),
                    provenance="selected",
                )
                for request in (b"\x18", b"\x19")
            )

        profile.frame_records.side_effect = frames
        replay = Replay([(b"\x18", b"\x58\x0a\x12\x34\x00"), (b"\x19", b"\x59\x00")])
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=2))
        result = session.dtcs_psa_profile(profile, 2, functions, family="v2")
        self.assertEqual(result["native_count"], 0)
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234),))
        self.assertFalse(replay.steps)

    def test_selected_psa_metadata_failure_precedes_overflow(self):
        profile, functions = self.psa_profile_fixture()
        replay = Replay([(b"\x18", b"\x58\x0a\x12\x34\x00")])
        profile.records.side_effect = ToyotaCodecError("selected metadata failure", 77)
        session = ToyotaSession(replay, "ecu", {})
        with self.assertRaises(ToyotaCodecError) as caught:
            session.dtcs_psa_profile(profile, 2, functions)
        self.assertEqual(caught.exception.code, 77)
        self.assertEqual(len(replay.calls), 1)
        self.assertFalse(functions.function.called)

    def information_profile_fixture(self, *, expanded=False, second=False):
        from scripts.profiles import VehicleProfile

        category = bytearray(76)
        category[72] = 0x34 if expanded else 4
        rows = []
        for index in range(1, 3 if second else 2):
            row = bytearray(68 if expanded else 28)
            signature = ("P123456" if expanded else f"P000{index}") + "\0"
            row[: len(signature) * 2] = signature.encode("utf-16le")
            if expanded:
                struct.pack_into("<IIII", row, 44, 0x123456, index, 3, 0)
                struct.pack_into("<H", row, 62, 123)
                row[64:66] = bytes((1, 4))
            else:
                struct.pack_into("<IIH", row, 12, index, 3, index)
                row[26] = 1
            rows.append(bytes(row))
        slot = 65 if expanded else 5
        database = Database(
            2,
            0x0100032F,
            "authored",
            {slot: Section(slot, 0, len(rows), False, b"".join(rows))},
        )
        language = Mock()
        language.resolve.side_effect = lambda key: {
            0: "",
            1: "first",
            2: "second",
            3: "comment",
        }[key]
        profile = VehicleProfile(Mock(language=language), bytes(category), database)
        return profile

    def test_selected_dtc_info_detail_highlighting_and_partial_status(self):
        profile = self.information_profile_fixture()
        details = []
        for index in (1, 2):
            row = bytearray(20)
            struct.pack_into("<IIHHH", row, 0, index, 2, 1, 42, 6 + index)
            row[16:18] = bytes((2, 3))
            details.append(bytes(row))
        profile.database.sections[47] = Section(47, 0, 2, False, b"".join(details))
        profile.database.sections[48] = Section(
            48, 0, 1, False, struct.pack("<HHB3x", 7, 99, 5)
        )
        result = dtc_information_profile(profile, "P0001")
        self.assertEqual(result["native_status"], 0xC0040101)
        items = result["items"]
        self.assertIsInstance(items, list)
        assert isinstance(items, list)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["highlighting"], [{"signal_key": 99, "field_04": 5}])
        self.assertEqual(items[0]["detail_field_0a"], 42)
        self.assertEqual(items[0]["name"], "first")

    def test_selected_dtc_info_hidden_and_uppercase_unknown_fallback(self):
        profile = self.information_profile_fixture()
        for query, count in ((None, 1), ("P0009", 1), ("p0009", 0), ("P4009", 0)):
            result = dtc_information_profile(profile, query)
            self.assertEqual(result["native_status"], 0)
            items = result["items"]
            assert isinstance(items, list)
            self.assertEqual(len(items), count)
            if query == "P0009":
                self.assertEqual(items[0]["name"], "???")
        row = bytearray(profile.database.sections[5].payload)
        row[26] = 0
        profile.database.sections[5] = Section(5, 0, 1, False, bytes(row))
        self.assertEqual(dtc_information_profile(profile, "P0001")["items"], [])

    def test_selected_dtc_info_later_success_overwrites_earlier_native_error(self):
        profile = self.information_profile_fixture(second=True)
        detail = bytearray(20)
        struct.pack_into("<IHHH", detail, 4, 0, 1, 0, 7)
        profile.database.sections[47] = Section(47, 0, 1, False, bytes(detail))
        result = dtc_information_profile(profile)
        self.assertEqual(result["native_status"], 0)
        items = result["items"]
        assert isinstance(items, list)
        self.assertEqual([x["signature"] for x in items], ["P0002"])

    def test_dtc_metadata_hydrates_duplicate_group_before_first_visibility(self):
        for expanded in (False, True):
            profile = self.information_profile_fixture(expanded=expanded)
            slot, _width, code_at, visible, name_at = (
                (65, 68, 44, 64, 48) if expanded else (5, 28, 20, 26, 12)
            )
            first = bytearray(profile.database.sections[slot].payload)
            first[visible] = 0
            second = bytearray(first)
            struct.pack_into("<I", second, name_at, 2)
            profile.database.sections[slot] = Section(
                slot, 0, 2, False, bytes(first + second)
            )
            lookup = dtc_metadata_p5_profile if expanded else dtc_metadata_profile
            code = struct.unpack_from("<I" if expanded else "<H", first, code_at)[0]
            self.assertIsNone(lookup(profile, code))
            language = cast(Mock, profile.catalog.language.resolve)
            self.assertEqual(language.call_count, 6 if expanded else 4)
            language.reset_mock()
            struct.pack_into("<I", second, name_at, 999)
            profile.database.sections[slot] = Section(
                slot, 0, 2, False, bytes(first + second)
            )

            def resolve(key):
                if key == 999:
                    raise ValueError("authored malformed selected language reference")
                return "selected"

            language.side_effect = resolve
            with self.assertRaisesRegex(ValueError, "malformed selected language"):
                lookup(profile, code)
            # The later matching row is hydrated even though FIRST is hidden.
            self.assertIn(call(999), language.call_args_list)

    def test_selected_p5_metadata_and_ordered_analyzer_merge(self):
        profile = self.information_profile_fixture(expanded=True)
        rules = (StatusRule(1, 1, 1), StatusRule(2, 2, 2))
        reply = bytes.fromhex("59 02 ff 12 34 56 01 12 34 56 02 00 00 01 01")
        result = analyze_p5_diagnostic_reply_profile(profile, reply, rules)
        self.assertEqual([item["code"] for item in result], [0x123456, 1])
        self.assertEqual(result[0]["diag_type"], 3)
        self.assertEqual(result[0]["status"], 3)
        self.assertEqual(result[0]["signature"], "P123456")
        self.assertEqual(result[0]["name"], "first")
        self.assertEqual(result[0]["division_name"], "comment")
        self.assertEqual(result[0]["native_field_2de"], 123)
        self.assertEqual(result[0]["native_field_2e0"], 4)
        self.assertEqual(result[1]["signature"], "P000001")
        # A duplicate merges before querying metadata or language again.
        self.assertEqual(cast(Mock, profile.catalog.language.resolve).call_count, 3)
        raw = bytearray(profile.database.sections[65].payload)
        raw[64] = 0
        profile.database.sections[65] = Section(65, 0, 1, False, bytes(raw))
        self.assertIsNone(dtc_metadata_p5_profile(profile, 0x123456))
        self.assertEqual(
            analyze_p5_diagnostic_reply_profile(profile, reply, rules)[0]["code"], 1
        )

    def test_selected_p5_analyzer_short_capacity_availability_and_missing_table(self):
        profile = self.information_profile_fixture(expanded=True)
        rules = (StatusRule(1, 1, 1),)
        for reply in (b"", bytes(6), bytes.fromhex("59 02 00 12 34 56 01")):
            self.assertEqual(
                analyze_p5_diagnostic_reply_profile(profile, reply, rules), []
            )
        reply = bytes.fromhex("59 02 01 12 34 56 01 00 00 01 01")
        with self.assertRaisesRegex(SessionError, "requested diagnostic types"):
            analyze_p5_diagnostic_reply_profile(profile, reply, ())
        self.assertEqual(
            analyze_p5_diagnostic_reply_profile(profile, reply, (), requested_types=1),
            [],
        )
        self.assertEqual(
            analyze_p5_diagnostic_reply_profile(
                profile, reply, rules, maximum_groups=1
            ),
            [],
        )
        # Availability reloads the requested bitset when its native cache is empty.
        row = bytearray(12)
        struct.pack_into("<I", row, 0, 1)
        row[8:10] = b"\x01\x01"
        profile.database.sections[66] = Section(66, 0, 1, False, bytes(row))
        self.assertEqual(
            len(
                analyze_p5_diagnostic_reply_profile(
                    profile, reply, (), requested_types=1
                )
            ),
            2,
        )
        profile = self.information_profile_fixture(expanded=True)
        del profile.database.sections[65]
        with self.assertRaises(ToyotaCodecError) as error:
            analyze_p5_diagnostic_reply_profile(profile, reply, rules)
        self.assertEqual(error.exception.code, 0xA0030107)

    def test_selected_dtc_info_p5_68_byte_layout_and_seven_character_fallback(self):
        profile = self.information_profile_fixture(expanded=True)
        result = dtc_information_profile(profile, "P123456")
        self.assertTrue(result["expanded"])
        items = result["items"]
        assert isinstance(items, list)
        self.assertEqual(items[0]["detail_field_11"], 4)
        self.assertEqual(items[0]["detail_field_0a"], 123)
        self.assertEqual(items[0]["diagnostic_field_0c"], 1)
        result = dtc_information_profile(profile, "U123ABC")
        items = result["items"]
        assert isinstance(items, list)
        self.assertEqual(items[0]["name"], "???")
        self.assertEqual(dtc_information_profile(profile, "P0001")["items"], [])

    def plain_profile_fixture(self, module):
        from scripts.profiles import VehicleProfile

        profile = selected_profile(functions=(7, 10))
        profile.dll_records.side_effect = lambda command: VehicleProfile.dll_records(
            profile, command
        )
        management = profile.catalog.management
        profile.catalog.management = Database(
            1, 0x0100032F, "authored", management.sections
        )
        row = bytearray(88)
        name = (module + "\0").encode("utf-16le")
        row[: len(name)] = name
        struct.pack_into("<H", row, 80, profile.category)
        row[86] = 0x13
        profile.catalog.management.sections[19] = Section(19, 0, 1, False, bytes(row))
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(b"\x17") if function == 7 else CommandFrame(b"\x18"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        functions = Mock()
        functions.function.return_value = (True, 0)
        return profile, functions

    def test_selected_can_p4_error_mask_differs_from_v2(self):
        profile = selected_profile(functions=(6, 10))
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(b"\x18")
                if function == 10
                else CommandFrame(b"\x12\x00\x00"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        profile.records.side_effect = lambda slot: (
            (b"\x00\x00\x07\x00",) if slot == 2 else ()
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        for family in ("p4", "p4_v2"):
            replay = Replay(
                [
                    (b"\x18", b"\x58\x01\x12\x34"),
                    (b"\x12\x00\x07", NativeStatus(0x90020321)),
                ]
            )
            session = ToyotaSession(replay, "ecu", {})
            if family == "p4":
                with self.assertRaises(NativeStatus) as caught:
                    session.dtcs_can_profile(profile, 1, functions, family=family)
                self.assertEqual(caught.exception.code, 0x90020321)
            else:
                result = session.dtcs_can_profile(profile, 1, functions, family=family)
                self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234),))
            self.assertFalse(replay.steps)

    def test_selected_dk_all_types_use_trailing_ffd_without_mask(self):
        profile = selected_profile(functions=(6, 12))
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(b"\x18")
                if function == 12
                else CommandFrame(b"\x12\x00\x00"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        profile.records.side_effect = lambda slot: (
            (b"\x00\x00\x07\x00",) if slot == 2 else ()
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        replay = Replay(
            [(b"\x18", b"\x58\x01\x12\x34"), (b"\x12\x00\x07", b"\x52\xff\xff\x12\x34")]
        )
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=2))
        result = session.dtcs_can_profile(profile, 3, functions, family="dk")
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234, True, 7),))
        self.assertFalse(replay.steps)

    def test_selected_dk_iso_wrapper_raw_first_byte_ffd(self):
        profile = selected_profile(functions=(6, 12))
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(b"\x18")
                if function == 12
                else CommandFrame(b"\x12"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        for reply in (b"\x34\x00", NativeStatus(0x91010009)):
            replay = Replay([(b"\x18", b"\x12\x34\x00"), (b"\x12", reply)])
            session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=2))
            result = session.dtcs_dk_iso_wrapper_profile(profile, 3, functions)
            self.assertEqual(result["codes"], [0x12, 0x34])
            self.assertEqual(
                result["freeze_records"],
                (
                    DtcFreeze(0x12),
                    DtcFreeze(0x34, not isinstance(reply, NativeStatus), 0),
                ),
            )
            self.assertFalse(replay.steps)

    def test_comm_pid_pure_decoder_matches_expansion_and_bcd_boundary(self):
        row = bytearray(44)
        struct.pack_into("<HH", row, 20, 0, 15)
        self.assertEqual(
            decode_comm_pid_reply(
                bytes(row), 4, b"\x21\x02", b"\x61\x02\x12", positions=b"\x01\x00"
            ),
            0x1200,
        )
        self.assertEqual(
            decode_comm_pid_reply(
                bytes(row), 0x14, b"\x22\x12\x34", b"\x62\x12\x34\x12\x34", bcd=True
            ),
            1234,
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            decode_comm_pid_reply(
                bytes(row), 0x14, b"\x22\x12\x34\x00", b"\x62\x12\x34\x12\x34"
            )
        self.assertEqual(caught.exception.code, SHORT_REPLY)
        with self.assertRaises(ToyotaCodecError) as caught:
            decode_comm_pid_reply(
                bytes(row), 0x14, b"\x22\x12\x34", b"\x00\x12\x34\x12\x34"
            )
        self.assertEqual(caught.exception.code, 0xA0040201)

    def test_plain_selected_count_module_zero_skips_read(self):

        profile, functions = self.plain_profile_fixture("GetDiagCodeCount.dll")
        replay = Replay([(b"\x17", b"\x57\x00\x00")])
        session = ToyotaSession(replay, "ecu", {})
        result = session.dtcs_plain_profile(profile, 1, functions)
        self.assertEqual(result["codes"], [])
        self.assertEqual(result["count_module"], "GetDiagCodeCount.dll")
        self.assertFalse(functions.function.called)
        self.assertEqual(len(replay.calls), 1)

    def test_plain_dll_selection_falls_back_first_command_row(self):
        profile, functions = self.plain_profile_fixture("GetDiagCodeCount.dll")
        row = bytearray(profile.catalog.management.sections[19].payload)
        struct.pack_into("<H", row, 80, 1)
        profile.catalog.management.sections[19] = Section(19, 0, 1, False, bytes(row))
        replay = Replay([(b"\x17", b"\x57\x00\x00")])
        session = ToyotaSession(replay, "ecu", {})
        self.assertEqual(session.dtcs_plain_profile(profile, 1, functions)["codes"], [])
        row[86] = 0x14
        profile.catalog.management.sections[19] = Section(19, 0, 1, False, bytes(row))
        with self.assertRaises(ToyotaCodecError) as caught:
            session.dtcs_plain_profile(profile, 1, functions)
        self.assertEqual(caught.exception.code, 0xC0040101)
        self.assertEqual(len(replay.calls), 1)

    def test_plain_p4_count_requires_existing_shared0d_after_wire(self):

        profile, functions = self.plain_profile_fixture("GetDiagCodeCountP4.dll")
        replay = Replay([(b"\x17", b"\x57\x01")])
        session = ToyotaSession(replay, "ecu", {})
        with self.assertRaises(ToyotaCodecError) as caught:
            session.dtcs_plain_profile(profile, 1, functions)
        self.assertEqual(caught.exception.code, 0xC0040601)
        self.assertEqual(len(replay.calls), 1)
        replay = Replay(
            [(b"\x17", b"\x57\x01"), (b"\x18", b"\x58\x12\x34\x00\x00\x00\x00")]
        )
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=2))
        result = session.dtcs_plain_profile(profile, 1, functions, shared_data_0d=0)
        self.assertEqual(result["codes"], [0x1234])
        self.assertFalse(replay.steps)

    def test_plain_count_clones_word_type_before_outer_dword_check(self):

        profile, functions = self.plain_profile_fixture("GetDiagCodeCount.dll")
        replay = Replay([(b"\x17", b"\x57\x00\x01")])
        session = ToyotaSession(replay, "ecu", {})
        with self.assertRaises(ToyotaCodecError) as caught:
            session.dtcs_plain_profile(profile, 0x10001, functions)
        self.assertEqual(caught.exception.code, 0xC0040001)
        self.assertEqual(len(replay.calls), 1)

    def test_selected_dk_at_two_passes_literal_init_and_second_label(self):
        profile = selected_profile(functions=(6, 12))
        frame_map = {12: CommandFrame(b"\x18"), 6: CommandFrame(b"\x12\x00\x00")}
        settings = struct.pack("<I", 1234) + bytes(12)
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=frame_map[function],
                settings_record=settings,
                provenance="selected",
            ),
        )
        profile.records.side_effect = lambda slot: (
            (b"\x00\x00\x07\x00",) if slot == 2 else ()
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        replay = Replay(
            [
                (b"\x18", b"\x58\x02\x12\x34\x56\x78"),
                (b"\x12\x00\x07", NativeStatus(0x91010009)),
                (b"\x12\x00\x07", b"\x52\x00\x00\x56\x78"),
            ]
        )
        sent = []

        def send(ecu, frame):
            self.assertEqual(len(replay.calls), 1)
            sent.append((ecu, frame.arguments))
            return 77

        session = ToyotaSession(
            replay, "ecu", {}, native_send=send, limits=Limits(exchanges=4)
        )
        result = session.dtcs_dk_at_profile(
            profile, 3, functions, connection_bus_id=0x22
        )
        self.assertEqual(
            result["freeze_records"], (DtcFreeze(0x1234), DtcFreeze(0x5678, True, 7))
        )
        self.assertEqual(result["freeze_labels"], ("", "1"))
        self.assertEqual(sent, [("ecu", (0x23, None, 0, 1234, 0x22, 1, 1))])
        self.assertFalse(replay.steps)

    def test_selected_dk_at_missing_connection_and_short_ffd_are_literal(self):
        profile = selected_profile(functions=(6, 10))
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(b"\x18")
                if function == 10
                else CommandFrame(b"\x12\x00\x00"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        profile.records.side_effect = lambda slot: (
            (b"\x00\x00\x07\x00",) if slot == 2 else ()
        )
        functions = Mock()
        functions.function.return_value = (True, 1)
        replay = Replay([(b"\x18", b"\x58\x01\x12\x34")])
        session = ToyotaSession(replay, "ecu", {})
        with self.assertRaises(ToyotaCodecError) as caught:
            session.dtcs_dk_at_profile(profile, 1, functions)
        self.assertEqual(caught.exception.code, 0xC0040601)
        self.assertEqual(len(replay.calls), 1)
        replay = Replay(
            [(b"\x18", b"\x58\x01\x12\x34"), (b"\x12\x00\x07", b"\x52\x12\x34")]
        )
        session = ToyotaSession(replay, "ecu", {}, native_send=lambda *_: 0)
        with self.assertRaises(ToyotaCodecError) as caught:
            session.dtcs_dk_at_profile(profile, 1, functions, connection_bus_id=0x22)
        self.assertEqual(caught.exception.code, SHORT_REPLY)
        self.assertFalse(replay.steps)

    def cgw_profile_fixture(self):
        from scripts.signal_lsb import LSBObservation, SignalLSB

        profile = selected_profile(functions=(10, 11, 12, 0x11))
        profile.database.sections = {10: None, 13: None, 14: None, 15: None}
        profile.catalog.language.resolve.return_value = "label"
        rows = []
        for signal in (1, 2):
            row = bytearray(84)
            struct.pack_into("<HHHHH", row, 56, signal, 0, 1, 0, 7)
            row[78:80] = bytes((2, 0x21))
            rows.append(bytes(row))
        physical = bytearray(24)
        struct.pack_into("<IIIHH", physical, 0, 1, 1, 0, 1, 1)
        unit = struct.pack("<IHHHH", 1, 1, 1, 0, 0)
        tables = {
            2: (b"\x00\x00\x07\x00",),
            10: tuple(rows),
            13: (bytes(physical),),
            14: (),
            15: (unit,),
        }
        profile.records.side_effect = lambda slot: tables.get(slot, ())
        profile.dtc_signal_checks.return_value = tuple(
            struct.pack("<4H", 1, signal, 0, 0) for signal in (1, 2)
        )
        profile.frame_records.side_effect = lambda function: (
            Mock(
                frame=CommandFrame(b"\x12\x00\x00\x00\x00\x00")
                if function == 0x11
                else CommandFrame(b"\x18"),
                settings_record=bytes(16),
                provenance="selected",
            ),
        )
        cache = Mock(profile=profile)
        cache.support_bits.return_value = {0x21: b"\x01"}
        lsb = Mock(spec=SignalLSB, cache=cache)
        lsb.p4.return_value = LSBObservation(2, 1, 0)
        functions = Mock()
        functions.function.return_value = (True, 1)
        return profile, tables, cache, lsb, functions

    def legacy_freeze_fixture(self):
        profile, tables, cache, lsb, _functions = self.cgw_profile_fixture()
        from scripts.profiles import SelectedFrame

        selected = SelectedFrame(
            CommandFrame(b"\x12\x00\x00\x00\x00\x00"), b"", b"", bytes(16), "selected"
        )
        profile.frame_records.side_effect = None
        profile.frame_records.return_value = (selected,)
        cache.ecu = "ecu"
        cache.source_build = 18
        cache.enabled_pids.side_effect = [{0x21: 1}, {0x21: 1}]
        cache.check_freeze_pid.return_value = True
        return profile, tables, cache, lsb

    def native_legacy_freeze_profile_fixture(self, build, frame_requests):
        profile, _state = self.p5_existence_fixture(build)
        directory, payload = bytearray(), bytearray()
        for _function, request in frame_requests:
            directory += struct.pack("<IH", len(payload), len(request))
            payload += request
        count = len(frame_requests)
        management = profile.catalog.management.sections
        management[0] = Section(0, 0, count, False, bytes(directory + payload))
        management[17] = Section(
            17,
            0,
            count,
            False,
            b"".join(
                struct.pack("<4H", index, index, 0, 0) for index in range(1, count + 1)
            ),
        )
        management[18] = Section(
            18,
            0,
            count,
            False,
            b"".join(
                struct.pack("<8H", 7, function, 1, index, 0, 1, 0, 0)
                for index, (function, _request) in sorted(
                    enumerate(frame_requests, 1), key=lambda item: item[1][0]
                )
            ),
        )
        row = bytearray(84)
        struct.pack_into("<5H", row, 56, 1, 0, 1, 0, 7)
        row[78], row[79] = 2, 0x21
        profile.database.sections[10] = Section(10, 0, 1, False, bytes(row))
        profile.database.sections[3] = Section(
            3, 0, 1, False, bytes((0, 0, 0, 0, 0x20, 1, 0, 0))
        )
        profile.database.sections[6] = Section(
            6,
            0,
            2,
            False,
            b"".join(bytes((0, 0, pid, 1, 0, 0, 0, 0)) for pid in (0x20, 0x21)),
        )
        return profile

    def test_hidden_freeze_query_hydrates_real_language_before_visibility(self):
        from scripts.diagnostic_db import Language
        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_freeze_p5 import database

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            profile, _state = self.p5_existence_fixture(build, function=0x11)
            row = bytearray(84)
            struct.pack_into("<I", row, 48, 2)
            profile.database.sections[10] = Section(10, 0, 1, False, bytes(row))
            encoded = "first\0".encode("utf-16le")
            profile.catalog.language = Language(
                database(
                    build, 4, {0: (1, struct.pack("<IH", 0, len(encoded)) + encoded)}
                )
            )
            operations = Mock()
            communication = NativeCommunication(
                profile, operations, "ecu", bus_id=0x12, source_build=build
            )
            workflow = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(1, 0x12, source_version=build),
            )
            with self.assertRaises(ValueError):
                workflow.session.freeze_legacy_profile(
                    profile,
                    "dk",
                    7,
                    support_cache=communication.cache,
                    lsb=SignalLSB(communication.cache, source_build=build),
                )
            operations.send.assert_not_called()

    def test_freeze_name_query_keeps_native_p4_and_raw_iso_wire_boundary(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            language_workflow, _operations = self.native_p5_metadata_workflow_fixture(
                build, b""
            )
            for family in ("p4", "iso"):
                profile = self.native_legacy_freeze_profile_fixture(
                    build,
                    (
                        (0x11, bytes.fromhex("120000000000")),
                        (0x13, bytes.fromhex("0100")),
                        (0x63, bytes.fromhex("122000")),
                    ),
                )
                row = bytearray(profile.database.sections[10].payload)
                struct.pack_into("<I", row, 48, 2)
                row[78] = 0
                profile.database.sections[10] = Section(10, 0, 1, False, bytes(row))
                profile.catalog.language = language_workflow.profile.catalog.language
                profile.database.sections[20] = Section(
                    20, 0, 1, False, bytes((0, 0, 0, 0, 0x21, 1, 0, 0))
                )
                operations = Mock()
                operations.send.return_value = 0
                observations = (
                    (
                        (0, bytes.fromhex("4100210101")),
                        (0x91010009, b""),
                        (0, bytes.fromhex("52200780")),
                    )
                    if family == "p4"
                    else ((0, bytes.fromhex("002105")),)
                )
                operations.receive.side_effect = [
                    SimpleNamespace(code=code, data=data) for code, data in observations
                ]
                communication = NativeCommunication(
                    profile, operations, "ecu", bus_id=0x12, source_build=build
                )
                workflow = ToyotaWorkflows.from_communication(
                    communication,
                    observations=WorkflowObservations(1, 0x12, source_version=build),
                )
                workflow._begin(source12_verified=True)
                lsb = SignalLSB(communication.cache, source_build=build)
                with self.assertRaises(ValueError):
                    if family == "p4":
                        workflow.session.freeze_p4_profile(
                            profile,
                            7,
                            1,
                            Mock(),
                            support_cache=communication.cache,
                            lsb=lsb,
                        )
                    else:
                        workflow.session.freeze_dk_iso_profile(
                            profile, communication, lsb=lsb
                        )
                self.assertEqual(
                    operations.receive.call_count, 3 if family == "p4" else 1
                )
                self.assertFalse(communication.closed)

    def native_cgw_fault_profile_fixture(self, build, *, dtc=False):
        from scripts.diagnostic_db import Language
        from tests.test_freeze_p5 import database

        frames = ((0x11, bytes.fromhex("120000000000")), (0x13, bytes.fromhex("0100")))
        if dtc:
            frames = ((10, b"\x18"), *frames)
        profile = self.native_legacy_freeze_profile_fixture(build, frames)
        first = profile.database.sections[10].payload
        second = bytearray(first)
        struct.pack_into("<H", second, 56, 2)
        struct.pack_into("<H", second, 60, 1 if dtc else 2)
        second[79] = 0x22
        freezes = first + bytes(second)
        if dtc:
            third = bytearray(second)
            struct.pack_into("<HHH", third, 56, 3, 0, 2)
            freezes += bytes(third)
        profile.database.sections[10] = Section(10, 0, 3 if dtc else 2, False, freezes)
        groups = []
        for identifier in range(1, 3 if dtc else 2):
            group = bytearray(12)
            struct.pack_into("<H", group, 4, identifier)
            group[8] = identifier
            groups.append(bytes(group))
        profile.database.sections[0] = Section(
            0, 0, len(groups), False, b"".join(groups)
        )
        checks = [(1, 1), (1, 2)] + ([(2, 3)] if dtc else [])
        profile.database.sections[1] = Section(
            1,
            0,
            len(checks),
            False,
            b"".join(
                struct.pack("<4H", group, signal, 0, 0) for group, signal in checks
            ),
        )
        retrieves = []
        for code, group in ((0x1234, 1), (0x5678, 2)) if dtc else ((0x1234, 1),):
            row = bytearray(10)
            struct.pack_into("<H", row, 0, code)
            row[2] = group
            retrieves.append(bytes(row))
        profile.database.sections[32] = Section(
            32, 0, len(retrieves), False, b"".join(retrieves)
        )
        profile.database.sections[5] = Section(5, 0, 0, False, b"")
        encoded = "first\0".encode("utf-16le")
        names = (
            b"".join(
                struct.pack("<IH", index * len(encoded), len(encoded))
                for index in range(20)
            )
            + encoded * 20
        )
        profile.catalog.language = Language(database(build, 4, {0: (20, names)}))
        return profile

    def test_cgw_retains_first_selected_output_on_second_metadata_fault(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            profile = self.native_cgw_fault_profile_fixture(build)
            operations = Mock()
            operations.send.return_value = 0
            operations.receive.side_effect = [
                SimpleNamespace(code=code, data=data)
                for code, data in (
                    (0, bytes.fromhex("5207002105")),
                    (0, bytes.fromhex("4100210101220101")),
                    (0x91010009, b""),
                    (0, bytes.fromhex("5207002206")),
                )
            ]
            communication = NativeCommunication(
                profile, operations, "ecu", bus_id=0x12, source_build=build
            )
            workflow = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(1, 0x12, source_version=build),
            )
            workflow._begin(source12_verified=True)
            functions = Mock()
            functions.function.return_value = (True, 1)
            output = []
            with self.assertRaises(ToyotaCodecError) as caught:
                workflow.session.freeze_cgw_profile(
                    profile,
                    0x1234,
                    7,
                    functions,
                    support_cache=communication.cache,
                    lsb=SignalLSB(communication.cache, source_build=build),
                    output=output,
                )
            self.assertEqual(caught.exception.code, 0xC0040101)
            self.assertEqual([item.value for item in output], [13])
            self.assertEqual(operations.receive.call_count, 4)
            self.assertFalse(communication.closed)

    def test_cgw_name_hydration_uses_only_actual_selected_signal_group(self):
        from functools import partial
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            for case in ("hidden_matching", "hidden_unrelated", "missing_table"):
                profile = self.native_cgw_fault_profile_fixture(build)
                first = profile.database.sections[10].payload[:84]
                second = bytearray(profile.database.sections[10].payload[84:])
                struct.pack_into(
                    "<I", second, 48, 21
                )  # Real language only has20 entries.
                second[78] = 0
                if case == "hidden_matching":
                    struct.pack_into("<H", second, 56, 1)
                profile.database.sections[10] = Section(
                    10, 0, 2, False, first + bytes(second)
                )
                checks = profile.database.sections[1].payload[:8]
                profile.database.sections[1] = Section(1, 0, 1, False, checks)
                if case == "missing_table":
                    del profile.database.sections[10]
                operations = Mock()
                operations.send.return_value = 0
                operations.receive.side_effect = [
                    SimpleNamespace(code=code, data=data)
                    for code, data in (
                        (0, bytes.fromhex("5207002105")),
                        (0, bytes.fromhex("4100210101")),
                        (0x91010009, b""),
                    )
                ]
                communication = NativeCommunication(
                    profile, operations, "ecu", bus_id=0x12, source_build=build
                )
                workflow = ToyotaWorkflows.from_communication(
                    communication,
                    observations=WorkflowObservations(1, 0x12, source_version=build),
                )
                workflow._begin(source12_verified=True)
                functions = Mock()
                functions.function.return_value = (True, 1)

                execute = partial(
                    workflow.session.freeze_cgw_profile,
                    profile,
                    0x1234,
                    7,
                    functions,
                    support_cache=communication.cache,
                    lsb=SignalLSB(communication.cache, source_build=build),
                )
                if case == "hidden_unrelated":
                    self.assertEqual([item.value for item in execute()], [13])
                    self.assertEqual(operations.receive.call_count, 3)
                elif case == "hidden_matching":
                    with self.assertRaises(ValueError):
                        execute()
                    operations.send.assert_not_called()
                    functions.function.assert_not_called()
                else:
                    with self.assertRaises(ToyotaCodecError) as caught:
                        execute()
                    self.assertEqual(caught.exception.code, 0xA0030107)
                    operations.send.assert_not_called()

    def test_selected_can_continuation_uses_actual_receive_without_empty_send(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            for extended, replies, retries, codes, sends in (
                (False, ((0, "58021234"), (0, "58025678")), 0, [0x1234, 0x5678], 1),
                (
                    True,
                    ((0, "58011234"), (0, "58015678"), (0, "5800")),
                    0,
                    [0x1234, 0x5678],
                    1,
                ),
                (
                    False,
                    ((0, "58021234"), (77, ""), (0, "58015678")),
                    1,
                    [0x1234, 0x5678],
                    1,
                ),
                (
                    False,
                    ((77, ""), (0, "58021234"), (77, "")),
                    1,
                    None,
                    2,
                ),
            ):
                with self.subTest(build=build, extended=extended, replies=replies):
                    profile = self.native_cgw_fault_profile_fixture(build, dtc=True)
                    row = bytearray(profile.catalog.management.sections[29].payload)
                    struct.pack_into("<I", row, 4, 321)
                    row[14] = retries
                    profile.catalog.management.sections[29] = Section(
                        29, 0, 1, False, bytes(row)
                    )
                    operations = Mock()
                    operations.send.return_value = 0
                    operations.receive.side_effect = [
                        SimpleNamespace(code=status, data=bytes.fromhex(data))
                        for status, data in replies
                    ]
                    communication = NativeCommunication(
                        profile, operations, "ecu", bus_id=0x12, source_build=build
                    )
                    workflow = ToyotaWorkflows.from_communication(
                        communication,
                        observations=WorkflowObservations(
                            1, 0x12, source_version=build
                        ),
                    )
                    workflow._begin(source12_verified=True)
                    session = workflow.session
                    session.native_communication = communication
                    selected = profile.frame_records(10)[0]
                    session.commands = {
                        "can": CommandSpec(selected.frame, selected=selected)
                    }
                    if codes is None:
                        with self.assertRaises(NativeStatus) as error:
                            session.dtcs_can("can", extended=extended, retries=retries)
                        self.assertEqual(error.exception.code, 77)
                    else:
                        self.assertEqual(
                            session.dtcs_can("can", extended=extended, retries=retries),
                            codes,
                        )
                    self.assertEqual(operations.send.call_count, sends)
                    self.assertEqual(operations.receive.call_count, len(replies))
                    self.assertTrue(
                        all(
                            call.args[0] == b"\x18"
                            for call in operations.send.call_args_list
                        )
                    )
                    self.assertEqual(
                        operations.receive.call_args.kwargs["maximum"],
                        4096 if extended else 255,
                    )
                    self.assertEqual(
                        operations.receive.call_args.kwargs["timeout"], 321
                    )
                    self.assertEqual(
                        operations.receive.call_args.kwargs["argument_5"], 0
                    )
                    self.assertEqual(operations.receive.call_args.kwargs["flags"], 100)
                    self.assertFalse(communication.closed)

    def test_cgw_initial_dtc_metadata_fault_retains_first_shared_output(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            profile = self.native_cgw_fault_profile_fixture(build, dtc=True)
            rows = []
            for code, name in ((0x1234, 1), (0x5678, 21)):
                row = bytearray(28)
                struct.pack_into("<I", row, 12, name)
                struct.pack_into("<H", row, 20, code)
                row[26] = 1
                rows.append(bytes(row))
            profile.database.sections[5] = Section(5, 0, 2, False, b"".join(rows))
            operations = Mock()
            operations.send.return_value = 0
            operations.receive.return_value = SimpleNamespace(
                code=0, data=bytes.fromhex("580212345678")
            )
            communication = NativeCommunication(
                profile, operations, "ecu", bus_id=0x12, source_build=build
            )
            workflow = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(1, 0x12, source_version=build),
            )
            workflow._begin(source12_verified=True)
            functions = Mock()
            output: dict[str, object] = {}
            with self.assertRaises(ValueError):
                workflow.session.dtcs_dk_cgw_profile(
                    profile,
                    1,
                    functions,
                    support_cache=communication.cache,
                    lsb=SignalLSB(communication.cache, source_build=build),
                    output=output,
                )
            self.assertEqual(output["codes"], [0x1234])
            self.assertEqual(output["freeze_records"], [DtcFreeze(0x1234)])
            self.assertEqual(operations.receive.call_count, 1)
            functions.function.assert_not_called()
            self.assertFalse(communication.closed)

    def test_cgw_dtc_output_retains_completed_association_before_later_failure(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            profile = self.native_cgw_fault_profile_fixture(build, dtc=True)
            profile.database.sections[2] = Section(2, 0, 1, False, bytes((0, 0, 7, 0)))
            operations = Mock()
            operations.send.return_value = 0
            operations.receive.side_effect = [
                SimpleNamespace(code=code, data=data)
                for code, data in (
                    (0, bytes.fromhex("580212345678")),
                    (0, bytes.fromhex("5207002105")),
                    (0, bytes.fromhex("4100210101220101")),
                    (0x91010009, b""),
                    (0, bytes.fromhex("5207002206")),
                )
            ]
            communication = NativeCommunication(
                profile, operations, "ecu", bus_id=0x12, source_build=build
            )
            workflow = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(1, 0x12, source_version=build),
            )
            workflow._begin(source12_verified=True)
            functions = Mock()
            functions.function.return_value = (True, 1)
            output: dict[str, object] = {}
            with self.assertRaises(ToyotaCodecError) as caught:
                workflow.session.dtcs_dk_cgw_profile(
                    profile,
                    1,
                    functions,
                    support_cache=communication.cache,
                    lsb=SignalLSB(communication.cache, source_build=build),
                    output=output,
                )
            self.assertEqual(caught.exception.code, 0xC0040101)
            self.assertEqual(output["codes"], [0x1234, 0x5678])
            self.assertEqual(
                output["freeze_records"],
                [DtcFreeze(0x1234, True, 7), DtcFreeze(0x5678)],
            )
            self.assertEqual(operations.receive.call_count, 5)
            self.assertFalse(communication.closed)

    def test_p4_export_actual_selected_support52_wire77_metadata43_both_builds(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            profile = self.native_legacy_freeze_profile_fixture(
                build,
                (
                    (0x11, bytes.fromhex("120000000000")),
                    (0x13, bytes.fromhex("0100")),
                    (0x63, bytes.fromhex("122000")),
                ),
            )
            operations = Mock()
            operations.send.return_value = 0
            operations.receive.side_effect = [
                SimpleNamespace(code=code, data=data)
                for code, data in (
                    (0, bytes.fromhex("4100210101")),
                    (0x91010009, b""),
                    (0, bytes.fromhex("52200780")),
                    (0, bytes.fromhex("5207002105")),
                )
            ]
            communication = NativeCommunication(
                profile, operations, "ecu", bus_id=0x12, source_build=build
            )
            workflow = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(1, 0x12, source_version=build),
            )
            workflow._begin(source12_verified=True)
            functions = Mock()
            functions.function.return_value = (False, 0)
            result = workflow.session.freeze_p4_profile(
                profile,
                7,
                1,
                functions,
                support_cache=communication.cache,
                lsb=SignalLSB(communication.cache, source_build=build),
            )
            values = result["signals"]
            assert isinstance(values, list)
            self.assertEqual([item.value for item in values], [13])
            self.assertEqual(operations.receive.call_count, 4)
            self.assertEqual(
                [item.args[0] for item in operations.send.call_args_list],
                [
                    bytes.fromhex("0100"),
                    bytes.fromhex("122007"),
                    bytes.fromhex("120700210000"),
                ],
            )
            self.assertFalse(communication.closed)

    def test_no_frame_number_actual_selected52_77_metadata_both_builds(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            profile = self.native_legacy_freeze_profile_fixture(
                build,
                (
                    (0x11, bytes.fromhex("120000")),
                    (0x63, bytes.fromhex("122000")),
                    (0x0F, bytes.fromhex("0120")),
                ),
            )
            operations = Mock()
            operations.send.return_value = 0
            operations.receive.side_effect = [
                SimpleNamespace(code=0, data=bytes.fromhex(reply))
                for reply in (
                    "522080",
                    "412080",
                    "522105",
                )
            ]
            communication = NativeCommunication(
                profile, operations, "ecu", bus_id=0x12, source_build=build
            )
            workflow = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(1, 0x12, source_version=build),
            )
            workflow._begin(source12_verified=True)
            result = workflow.session.freeze_legacy_profile(
                profile,
                "no_frame_number",
                7,
                support_cache=communication.cache,
                lsb=SignalLSB(communication.cache, source_build=build),
            )
            self.assertEqual([item.value for item in result], [13])
            self.assertEqual(
                [item.args[0] for item in operations.send.call_args_list],
                [
                    bytes.fromhex("122007"),
                    bytes.fromhex("0120"),
                    bytes.fromhex("122107"),
                ],
            )
            self.assertEqual(operations.receive.call_count, 3)
            self.assertFalse(communication.closed)

    def test_p4_export_support_data_then_circular_native_number_list(self):
        profile, _tables, cache, lsb = self.legacy_freeze_fixture()
        cache.enabled_pids.side_effect = None
        cache.enabled_pids.return_value = {0x21: 1}
        events = []
        cache.support_bits.side_effect = lambda **kw: (
            events.append("support") or {0x21: b"\xff"}
        )
        cache.enabled_pids.side_effect = lambda **kw: (
            events.append(("enabled", kw)) or {0x21: 1}
        )
        functions = Mock()
        functions.function.side_effect = lambda *args: (
            events.append("function") or (True, 1)
        )
        session = ToyotaSession(Mock(), "ecu", {})
        session._read_p4 = Mock(
            side_effect=lambda *a, **kw: events.append("wire") or b"\x05"
        )
        session.multi_freeze_info = Mock(
            return_value={
                "supported": True,
                "out1": 4,
                "out2": 0xF0,
                "out3": 0x20,
            }
        )
        seen = []
        session.freeze_diagnostic_code_profile = Mock(
            side_effect=lambda _profile, number, **kw: seen.append(number) or 7
        )
        result = session.freeze_p4_profile(
            profile, 3, 7, functions, support_cache=cache, lsb=lsb, multi_control=1
        )
        self.assertEqual(
            events[:2],
            [
                "support",
                (
                    "enabled",
                    {
                        "family": "p4_ignore",
                        "kind": 3,
                        "control": 3,
                    },
                ),
            ],
        )
        self.assertLess(events.index("wire"), events.index("function"))
        self.assertEqual(seen, [0x23, 0x13, 0xF3])
        self.assertEqual(result["native_numbers"], [3, 0x23, 0x13, 0xF3])
        self.assertTrue(result["native_available"])
        self.assertTrue(result["signals"])

    def test_p4_export_preserves_completed_signals_before_function_fault(self):
        profile, _tables, cache, lsb = self.legacy_freeze_fixture()
        cache.enabled_pids.side_effect = None
        cache.enabled_pids.return_value = {0x21: 1}
        functions = Mock()
        functions.function.side_effect = NativeStatus(0xC0040601)
        session = ToyotaSession(Mock(), "ecu", {})
        session._read_p4 = Mock(return_value=b"\x05")
        signals = []
        numbers = []
        output: dict[str, object] = {"signals": signals, "native_numbers": numbers}
        with self.assertRaises(NativeStatus):
            session.freeze_p4_profile(
                profile, 3, 7, functions, support_cache=cache, lsb=lsb, output=output
            )
        self.assertTrue(output["signals"])
        self.assertIs(output["signals"], signals)
        self.assertIs(output["native_numbers"], numbers)

    def test_legacy_freeze_selected_chronology_and_local_response_cache(self):
        profile, _tables, cache, lsb = self.legacy_freeze_fixture()
        events = []
        cache.enabled_pids.side_effect = lambda **kw: (
            events.append(("list", kw)) or {0x21: 1}
        )
        cache.check_freeze_pid.side_effect = lambda *a, **kw: (
            events.append(("support", a[0][56])) or True
        )
        provider = Mock(
            side_effect=lambda *a: (
                events.append(("wire", a[2])) or b"\x52\x21\x07\x00\x00\x00\x05"
            )
        )
        lsb.p4.side_effect = lambda *a, **kw: (
            events.append(("lsb", a[0])) or lsb.p4.return_value
        )
        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
        result = session.freeze_legacy_profile(
            profile, "plain", 7, support_cache=cache, lsb=lsb
        )
        self.assertEqual([item.value for item in result], [10, 10])
        self.assertEqual(
            [event[0] for event in events],
            ["list", "list", "support", "wire", "lsb", "support", "lsb"],
        )
        self.assertEqual(provider.call_args.args[2], b"\x12\x21\x07\x00\x00\x00")
        self.assertIs(
            provider.call_args.args[1].selected, profile.frame_records(0x11)[0]
        )
        cache.enabled_pids.assert_has_calls(
            [
                call(family="normal", kind=3, control=7),
                call(family="normal", kind=1, control=0),
            ]
        )

    def test_legacy_freeze_partial_output_on_fatal_metadata_failure(self):
        profile, _tables, cache, lsb = self.legacy_freeze_fixture()
        lsb.p4.side_effect = [lsb.p4.return_value, ToyotaCodecError("bad", 99)]
        session = ToyotaSession(
            Replay([]),
            "ecu",
            {},
            native_transaction=Mock(return_value=b"\x52\x21\x07\x00\x00\x00\x05"),
        )
        output = []
        with self.assertRaises(ToyotaCodecError) as error:
            session.freeze_legacy_profile(
                profile, "plain", 7, support_cache=cache, lsb=lsb, output=output
            )
        self.assertEqual(error.exception.code, 99)
        self.assertEqual(len(output), 1)
        self.assertEqual(session.commands, {})

    def test_legacy_freeze_abs_skips_native_status_but_plain_propagates(self):
        for family, count in cast(
            tuple[tuple[Literal["dk_abs", "plain"], int | None], ...],
            (("dk_abs", 0), ("plain", None)),
        ):
            profile, _tables, cache, lsb = self.legacy_freeze_fixture()
            provider = Mock(side_effect=NativeStatus(0x91010009))
            session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
            if count is None:
                with self.assertRaises(NativeStatus):
                    session.freeze_legacy_profile(
                        profile, family, 7, support_cache=cache, lsb=lsb
                    )
            else:
                self.assertEqual(
                    session.freeze_legacy_profile(
                        profile, family, 7, support_cache=cache, lsb=lsb
                    ),
                    (),
                )
                self.assertEqual(provider.call_count, 1)
            lsb.p4.assert_not_called()

    def test_legacy_roof_fixed_support_selector_and_wire_number(self):
        profile, _tables, cache, lsb = self.legacy_freeze_fixture()
        provider = Mock(return_value=b"\x52\x00\x05" + bytes(6))
        session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
        result = session.freeze_legacy_profile(
            profile, "roof", 7, support_cache=cache, lsb=lsb
        )
        self.assertEqual([item.value for item in result], [10, 10])
        self.assertEqual(provider.call_args.args[2], b"\x12\x01\x00\x07\x00\x00")
        cache.enabled_pids.assert_has_calls(
            [
                call(family="ext", kind=3, control=1),
                call(family="ext", kind=1, control=0),
            ]
        )

    def test_legacy_freeze_multi_uses_typed_stream_and_single_packet_cache(self):
        from scripts.monitor_support import MultiReceiveResult

        profile, _tables, cache, lsb = self.legacy_freeze_fixture()
        cache.multi_receive.return_value = MultiReceiveResult(
            0, (b"\x52\x21\x07\x00\x00\x00\x05",)
        )
        session = ToyotaSession(Replay([]), "ecu", {})
        result = session.freeze_legacy_profile(
            profile, "multi", 7, support_cache=cache, lsb=lsb
        )
        self.assertEqual([item.value for item in result], [10, 10])
        cache.multi_receive.assert_called_once()
        self.assertEqual(
            cache.multi_receive.call_args.args[0].frame.request,
            b"\x12\x21\x07\x00\x00\x00",
        )

    def test_legacy_freeze_cancellation_after_support_prevents_wire(self):
        profile, _tables, cache, lsb = self.legacy_freeze_fixture()
        cancelled = [False]

        def support(*args, **kwargs):
            cancelled[0] = True
            return True

        cache.check_freeze_pid.side_effect = support
        provider = Mock()
        session = ToyotaSession(
            Replay([]),
            "ecu",
            {},
            native_transaction=provider,
            cancelled=lambda: cancelled[0],
        )
        with self.assertRaises(Cancelled):
            session.freeze_legacy_profile(
                profile, "plain", 7, support_cache=cache, lsb=lsb
            )
        provider.assert_not_called()

    def test_legacy_dk_pid_order_then_native_source_order_and_hidden_offset(self):
        for hidden in (False, True):
            profile, tables, cache, lsb = self.legacy_freeze_fixture()
            first, second = map(bytearray, tables[10])
            first[79], second[79] = 0x22, 0x21
            first[77] = 2 if hidden else 0
            tables[10] = (bytes(first), bytes(second))
            tables[6] = (
                bytes((0, 0, 0x21, 1, 0, 0, 0, 0)),
                bytes((0, 0, 0x22, 1, 0, 0, 0, 0)),
            )
            profile.database.sections[6] = None
            provider = Mock(return_value=b"\x52\x00\x00\x00\x05\x07" + bytes(4))
            session = ToyotaSession(Replay([]), "ecu", {}, native_transaction=provider)
            result = session.freeze_legacy_profile(
                profile, "dk", 7, support_cache=cache, lsb=lsb
            )
            self.assertEqual(
                [item.value for item in result], [10] if hidden else [14, 10]
            )
            self.assertEqual(provider.call_args.args[2], b"\x12\x07\x00\x00\x00\x00")
            provider.assert_called_once()
            cache.enabled_pids.assert_not_called()
            cache.check_freeze_pid.assert_not_called()

    def test_legacy_dk_fatal_metadata_keeps_shared_output_atomic(self):
        profile, tables, cache, lsb = self.legacy_freeze_fixture()
        tables[6] = (bytes((0, 0, 0x21, 1, 0, 0, 0, 0)),)
        profile.database.sections[6] = None
        lsb.p4.side_effect = [lsb.p4.return_value, NativeStatus(99)]
        provider = Mock(return_value=b"\x52\x00\x00\x00\x05" + bytes(4))
        output = []
        with self.assertRaises(NativeStatus):
            ToyotaSession(
                Replay([]), "ecu", {}, native_transaction=provider
            ).freeze_legacy_profile(
                profile, "dk", 7, support_cache=cache, lsb=lsb, output=output
            )
        self.assertEqual(output, [])

    def test_legacy_psa_function_value_selects_number_or_dtc_without_support_lists(
        self,
    ):
        for numbered in (False, True):
            profile, _tables, cache, lsb = self.legacy_freeze_fixture()
            functions = Mock()
            functions.function.return_value = (False, int(numbered))
            provider = Mock(return_value=b"\x52\x00\x05")
            result = ToyotaSession(
                Replay([]), "ecu", {}, native_transaction=provider
            ).freeze_legacy_profile(
                profile,
                "psa",
                7,
                support_cache=cache,
                lsb=lsb,
                functions=functions,
                code=0x1234,
            )
            self.assertEqual([item.value for item in result], [10, 10])
            self.assertEqual(
                provider.call_args.args[2],
                b"\x12\x21\x07\x00\x00\x00"
                if numbered
                else b"\x12\x21\x12\x34\x00\x00",
            )
            cache.enabled_pids.assert_not_called()
            cache.check_freeze_pid.assert_not_called()
            self.assertEqual(functions.function.call_args_list, [call(1, 4, 3)] * 2)

    def test_legacy_no_frame_number_both_echo_lengths_use_freeze_pid_list(self):
        from scripts.profiles import SelectedFrame

        for reply in (b"\x52\x21\x07\x05", b"\x52\x21\x05"):
            profile, _tables, cache, lsb = self.legacy_freeze_fixture()
            profile.frame_records.return_value = (
                SelectedFrame(
                    CommandFrame(b"\x12\x00\x00"), b"", b"", bytes(16), "selected"
                ),
            )
            provider = Mock(return_value=reply)
            result = ToyotaSession(
                Replay([]), "ecu", {}, native_transaction=provider
            ).freeze_legacy_profile(
                profile, "no_frame_number", 7, support_cache=cache, lsb=lsb
            )
            self.assertEqual([item.value for item in result], [10, 10])
            cache.enabled_pids.assert_has_calls(
                [
                    call(family="no_frame_number", kind=3, control=7),
                    call(family="normal", kind=1, control=0),
                ]
            )

    def test_legacy_dk_at_init_then_dtc_gate_reuses_matching_payload(self):
        for mismatches in (0, 1, 2):
            profile, tables, cache, lsb = self.legacy_freeze_fixture()
            tables[6] = (bytes((0, 0, 0x21, 1, 0, 0, 0, 0)),)
            profile.database.sections[6] = None
            matching = b"\x52\x07\x00\x00\x05\x00\x00\x12\x34"
            provider = Mock(
                side_effect=[matching[:-2] + b"\xff\xff"] * mismatches + [matching]
            )
            send = Mock(return_value=77)
            session = ToyotaSession(
                Replay([]), "ecu", {}, native_transaction=provider, native_send=send
            )
            if mismatches == 2:
                with self.assertRaises(ToyotaCodecError) as error:
                    session.freeze_legacy_profile(
                        profile, "dk_at", 7, support_cache=cache, lsb=lsb, code=0x1234
                    )
                self.assertEqual(error.exception.code, 0x90040502)
                lsb.p4.assert_not_called()
            else:
                result = session.freeze_legacy_profile(
                    profile, "dk_at", 7, support_cache=cache, lsb=lsb, code=0x1234
                )
                self.assertEqual([item.value for item in result], [10, 10])
            self.assertEqual(provider.call_count, min(mismatches + 1, 2))
            self.assertEqual(
                send.call_args.args[1].arguments,
                (profile.category, None, 0, 0, 0, 1, 1),
            )
            cache.enabled_pids.assert_not_called()

    def test_selected_dk_iso_concrete_raw77_no_sid_then_profile_metadata(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB

        for build in cast(tuple[Literal[12, 18], ...], (12, 18)):
            profile, _state = self.p5_existence_fixture(build, function=0x11)
            rows = []
            for signal, begin in ((1, 0), (2, 8)):
                row = bytearray(84)
                struct.pack_into("<5H", row, 56, signal, 0, 1, begin, begin + 7)
                row[78], row[79] = 2, 0x21
                rows.append(bytes(row))
            profile.database.sections[10] = Section(10, 0, 2, False, b"".join(rows))
            definition = bytes((0, 0, 0, 0, 0x21, 2, 0, 0))
            profile.database.sections[20] = Section(20, 0, 1, False, definition)
            operations = Mock()
            operations.send.return_value = 0
            operations.receive.return_value = SimpleNamespace(
                code=0, data=b"\x00\x21\x05\x06"
            )
            communication = NativeCommunication(
                profile, operations, "ecu", bus_id=0x12, source_build=build
            )
            lsb = SignalLSB(communication.cache, source_build=build)
            result = ToyotaSession(Replay([]), "ecu", {}).freeze_dk_iso_profile(
                profile, communication, lsb=lsb
            )
            self.assertEqual([item.value for item in result], [13, 15])
            self.assertEqual(
                operations.send.call_args.args[0], b"\x19\x04\x00\x00\x00\x01"
            )
            self.assertEqual(operations.receive.call_count, 1)
            self.assertFalse(communication.closed)

    def test_selected_dk_iso_missing_freeze_pid_table_faults_after_raw_wire(self):
        from types import SimpleNamespace

        from scripts.native_communication import NativeCommunication
        from scripts.signal_lsb import SignalLSB

        profile, _state = self.p5_existence_fixture(function=0x11)
        operations = Mock()
        operations.send.return_value = 0
        operations.receive.return_value = SimpleNamespace(code=0, data=b"\0\x21\x05")
        communication = NativeCommunication(
            profile, operations, "ecu", bus_id=0x12, source_build=18
        )
        session = ToyotaSession(Replay([]), "ecu", {})
        with self.assertRaises(ToyotaCodecError) as caught:
            session.freeze_dk_iso_profile(
                profile,
                communication,
                lsb=SignalLSB(communication.cache, source_build=18),
            )
        self.assertEqual(caught.exception.code, 0xA0030107)
        self.assertEqual(operations.receive.call_count, 1)
        self.assertFalse(communication.closed)

    def test_p5_predictive_outer_selects_cf_even_with_empty_diagnostics(self):
        from dataclasses import replace

        from scripts.native_communication import NativeCommunication
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        profile, _state = self.p5_existence_fixture(function=0xCD)
        category = bytearray(profile.category_record)
        category[72] = 0x15
        profile = replace(profile, category_record=bytes(category))
        communication = NativeCommunication(
            profile, Mock(), "ecu", bus_id=0x12, source_build=18
        )
        workflow = ToyotaWorkflows.from_communication(
            communication, observations=WorkflowObservations(1, 0x12)
        )
        session = workflow.session
        session.read_p5_diagnostic_reply_profile = Mock(
            return_value={
                "reply": b"",
                "rules": (),
                "maximum_groups": 0x3FF,
                "read_succeeded": True,
            }
        )
        # Native15AE calls2B50 even for an empty list: frame-selection faults survive.
        session.p5_predictive_freeze_profile = Mock(
            side_effect=NativeStatus(0xC0040101)
        )
        with self.assertRaises(NativeStatus):
            session.p5_diagnostics_core_profile(workflow, 0, 3, native_cancel_value=0)
        self.assertEqual(session.p5_predictive_freeze_profile.call_args.args[1], ())
        self.assertIn("state", workflow.native_output)

    def test_selected_cgw_wire_then_metadata_and_second_signal_ffd(self):
        profile, _tables, cache, lsb, functions = self.cgw_profile_fixture()
        replay = Replay(
            [
                (b"\x18", b"\x58\x01\x12\x34"),
                (b"\x12\x07\x00\x21\x00\x00", b"\x52\x07\x00\x21\x03"),
            ]
        )
        session = ToyotaSession(replay, "ecu", {}, limits=Limits(exchanges=2))
        result = session.dtcs_dk_cgw_profile(
            profile, 1, functions, support_cache=cache, lsb=lsb
        )
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234, True, 7),))
        self.assertEqual(lsb.p4.call_count, 2)
        self.assertEqual(cache.support_bits.call_count, 2)
        self.assertEqual(functions.function.call_args_list, [call(1, 4, 3)] * 3)
        self.assertFalse(replay.steps)

    def test_selected_cgw_metadata_error_after_wire_is_fatal(self):
        profile, tables, cache, lsb, functions = self.cgw_profile_fixture()
        tables[15] = ()
        replay = Replay([(b"\x12\x07\x00\x21\x00\x00", b"\x52\x07\x00\x21\x03")])
        session = ToyotaSession(replay, "ecu", {})
        with self.assertRaises(ToyotaCodecError) as caught:
            session.freeze_cgw_profile(
                profile, 0x1234, 7, functions, support_cache=cache, lsb=lsb
            )
        self.assertEqual(caught.exception.code, 0xC0040101)
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(cache.support_bits.call_count, 1)
        self.assertFalse(lsb.p4.called)
        self.assertEqual(session.commands, {})

    def test_selected_cgw_negative_cache_omits_signals_and_type3_skips_ffd(self):
        profile, _tables, cache, lsb, functions = self.cgw_profile_fixture()
        replay = Replay([(b"\x12\x07\x00\x21\x00\x00", NativeStatus(0x90020323))])
        session = ToyotaSession(replay, "ecu", {})
        self.assertEqual(
            session.freeze_cgw_profile(
                profile, 0x1234, 7, functions, support_cache=cache, lsb=lsb
            ),
            (),
        )
        self.assertEqual(len(replay.calls), 1)
        self.assertFalse(cache.support_bits.called)
        functions.reset_mock()
        replay = Replay([(b"\x18", b"\x58\x01\x12\x34")])
        session = ToyotaSession(replay, "ecu", {})
        result = session.dtcs_dk_cgw_profile(
            profile, 3, functions, support_cache=cache, lsb=lsb
        )
        self.assertEqual(result["freeze_records"], (DtcFreeze(0x1234),))
        self.assertFalse(functions.function.called)

    def test_cgw_freeze_native_skips_cache_and_shared_budget(self):
        wide = bytearray(84)
        wide[78] = 2
        wide[79] = 0x21
        struct.pack_into("<HH", wide, 62, 0, 15)
        narrow = bytearray(wide)
        struct.pack_into("<H", narrow, 64, 7)
        command = bytes.fromhex("12070021")
        commands = {"cgw": spec(bytes.fromhex("12000000"))}
        replay = Replay([(command, bytes.fromhex("5221aa0000"))])
        session = ToyotaSession(replay, "ecu", commands, limits=Limits(exchanges=1))
        self.assertEqual(
            session.freeze_cgw(
                "cgw",
                [bytes(wide), bytes(narrow)],
                7,
                {0x21: b"\x01"},
                function_supported=True,
            ),
            {1: b"\xaa"},
        )
        self.assertEqual(
            session.freeze_cgw("missing", [], 7, {}, function_supported=False), {}
        )
        self.assertEqual(
            session.freeze_cgw("cgw", [bytes(84)], 7, {}, function_supported=True), {}
        )
        replay = Replay(
            [
                (command, bytes.fromhex("0021aa0000")),
                (command, bytes.fromhex("5221aa0000")),
            ]
        )
        # Even an explicitly raw host descriptor cannot bypass native SID checks.
        raw_commands = {"cgw": spec(bytes.fromhex("12000000"), check="raw")}
        session = ToyotaSession(replay, "ecu", raw_commands)
        self.assertEqual(
            session.freeze_cgw(
                "cgw", [bytes(narrow)] * 2, 7, {0x21: b"\x01"}, function_supported=True
            ),
            {1: b"\xaa"},
        )
        self.assertFalse(replay.steps)
        for status, cached in (
            (0x91010009, True),
            (0x90020323, True),
            (0x90020321, False),
        ):
            steps: list[tuple[bytes, bytes | NativeStatus]] = [
                (command, NativeStatus(status))
            ]
            if not cached:
                steps.append((command, bytes.fromhex("5221aa0000")))
            replay = Replay(steps)
            session = ToyotaSession(replay, "ecu", commands)
            result = session.freeze_cgw(
                "cgw", [bytes(narrow)] * 2, 7, {0x21: b"\x01"}, function_supported=True
            )
            self.assertEqual(result, {} if cached else {1: b"\xaa"})
            self.assertFalse(replay.steps)
        session = ToyotaSession(Replay([(command, NativeStatus(77))]), "ecu", commands)
        with self.assertRaises(NativeStatus):
            session.freeze_cgw(
                "cgw", [bytes(narrow)], 7, {0x21: b"\x01"}, function_supported=True
            )

    def test_dk_freeze_native_sequential_pid_groups_and_explicit_lengths(self):
        rows = []
        for pid in (1, 1, 2, 1):
            row = bytearray(84)
            row[79] = pid
            struct.pack_into("<HH", row, 62, 0, 7)
            rows.append(bytes(row))
        reply = bytes.fromhex("5201aabbccddee") + bytes(4)
        self.assertEqual(
            parse_dk_freeze(reply, 4, rows, {1: 2, 2: 1}),
            [b"\xaa\xbb", b"\xaa\xbb", b"\xcc", b"\xdd\xee"],
        )
        with self.assertRaises(SessionError):
            parse_dk_freeze(reply, 4, rows, {1: 2})
        with self.assertRaises(ToyotaCodecError) as error:
            parse_dk_freeze(reply[:-1], 4, rows, {1: 2, 2: 1})
        self.assertEqual(error.exception.code, SHORT_REPLY)
        invalid = bytearray(rows[0])
        struct.pack_into("<H", invalid, 64, 16)
        with self.assertRaises(ToyotaCodecError) as error:
            parse_dk_freeze(reply, 4, [bytes(invalid)], {1: 2})
        self.assertEqual(error.exception.code, 0xC0040102)

        replay = Replay([(bytes.fromhex("12077788"), reply)])
        session = ToyotaSession(replay, "ecu", {"dk": spec(bytes.fromhex("12007788"))})
        self.assertEqual(
            session.freeze_dk("dk", rows, 7, {1: 2, 2: 1}),
            [b"\xaa\xbb", b"\xaa\xbb", b"\xcc", b"\xdd\xee"],
        )
        self.assertFalse(replay.steps)
        self.assertEqual(session.freeze_dk("dk", [], 7, {}), [])

    def test_psa_freeze_number_and_dtc_requests_share_native_payload_prefix(self):
        freeze = bytearray(84)
        freeze[79] = 0x21
        struct.pack_into("<HH", freeze, 62, 0, 15)
        for template, request, selectors in (
            ("120000", "122107", {"number": 7}),
            ("12000000", "12211234", {"code": 0x1234}),
        ):
            replay = Replay([(bytes.fromhex(request), bytes.fromhex("5221aabb"))])
            session = ToyotaSession(
                replay, "ecu", {"psa": spec(bytes.fromhex(template))}
            )
            self.assertEqual(
                session.freeze_psa("psa", bytes(freeze), **selectors),
                bytes.fromhex("aabb"),
            )
            with self.assertRaises(ValueError):
                session.freeze_psa("psa", bytes(freeze))
            with self.assertRaises(ValueError):
                session.freeze_psa("psa", bytes(freeze), code=1, number=1)

    def test_dk_abs_freeze_patches_number_pid_and_removes_trailer(self):
        freeze = bytearray(84)
        freeze[79] = 0x99
        struct.pack_into("<HH", freeze, 62, 0, 15)
        # Request tail length does not alter this family's response window.
        replay = Replay([(bytes.fromhex("12057799ff"), bytes.fromhex("5205aabb1122"))])
        session = ToyotaSession(
            replay, "ecu", {"abs": spec(bytes.fromhex("12007700ff"))}
        )
        self.assertEqual(
            session.freeze_dk_abs("abs", bytes(freeze), 5), bytes.fromhex("aabb")
        )
        replay = Replay([(bytes.fromhex("12057799"), bytes.fromhex("5205aa1122"))])
        session = ToyotaSession(replay, "ecu", {"abs": spec(bytes.fromhex("12007700"))})
        with self.assertRaises(ToyotaCodecError) as error:
            session.freeze_dk_abs("abs", bytes(freeze), 5)
        self.assertEqual(error.exception.code, SHORT_REPLY)

    def test_roof_freeze_fixed_request_and_native_response_window(self):
        freeze = bytearray(84)
        freeze[79] = 0x99  # This family does not patch a PID from the Freeze row.
        struct.pack_into("<HH", freeze, 62, 0, 15)
        replay = Replay(
            [(bytes.fromhex("12017705"), bytes.fromhex("5201aabb11223344"))]
        )
        session = ToyotaSession(
            replay, "ecu", {"roof": spec(bytes.fromhex("12007700"))}
        )
        self.assertEqual(
            session.freeze_dk_roof("roof", bytes(freeze), 5), bytes.fromhex("aabb")
        )
        replay = Replay([(bytes.fromhex("12017705"), bytes.fromhex("5201aa11223344"))])
        session = ToyotaSession(
            replay, "ecu", {"roof": spec(bytes.fromhex("12007700"))}
        )
        with self.assertRaises(ToyotaCodecError) as error:
            session.freeze_dk_roof("roof", bytes(freeze), 5)
        self.assertEqual(error.exception.code, SHORT_REPLY)

    def test_freeze_omitted_frame_echo_uses_selected_pid_length(self):
        freeze = bytearray(84)
        freeze[79] = 0x21
        struct.pack_into("<HH", freeze, 62, 0, 15)
        for reply in (bytes.fromhex("522107aabb"), bytes.fromhex("5221aabb")):
            replay = Replay([(bytes.fromhex("122107"), reply)])
            session = ToyotaSession(
                replay, "ecu", {"freeze": spec(bytes.fromhex("120000"))}
            )
            self.assertEqual(
                session.freeze_no_frame_number("freeze", bytes(freeze), 7, {0x21: 2}),
                bytes.fromhex("aabb"),
            )
        replay = Replay([(bytes.fromhex("122107"), bytes.fromhex("522107aabbcc"))])
        session = ToyotaSession(
            replay, "ecu", {"freeze": spec(bytes.fromhex("120000"))}
        )
        with self.assertRaises(SessionError):
            session.freeze_no_frame_number("freeze", bytes(freeze), 7, {})
        self.assertEqual(len(replay.steps), 1)
        with self.assertRaises(ToyotaCodecError) as error:
            session.freeze_no_frame_number("freeze", bytes(freeze), 7, {0x21: 2})
        self.assertEqual(error.exception.code, SHORT_REPLY)

    def test_supported_pid_expansion_and_p4_freeze_boundaries(self):
        self.assertEqual(
            expand_supported_pid(b"\xaa\xbb", b"\x01\x00\xff"), b"\xaa\x00\xbb"
        )
        # Native accepts extra compressed bytes up to full length, then ignores them.
        self.assertEqual(expand_supported_pid(b"\xaa\xbb", b"\x01\x00"), b"\xaa\x00")
        for data, positions, code in (
            (b"", b"", 0xC0040001),
            (b"12", b"1", 0xA0040201),
            (b"1", b"11", SHORT_REPLY),
        ):
            with self.assertRaises(ToyotaCodecError) as error:
                expand_supported_pid(data, positions)
            self.assertEqual(error.exception.code, code)
        freeze = bytearray(84)
        freeze[79] = 0x21
        struct.pack_into("<HH", freeze, 62, 16, 23)
        replay = Replay([(bytes.fromhex("12070021"), bytes.fromhex("5221aabb0000"))])
        session = ToyotaSession(
            replay, "ecu", {"freeze": spec(bytes.fromhex("12000000"))}
        )
        self.assertEqual(
            session.freeze_p4("freeze", bytes(freeze), 7, bytes.fromhex("010001")),
            bytes.fromhex("aa00bb"),
        )
        with self.assertRaises(ToyotaCodecError):
            session.freeze_p4("freeze", bytes(freeze), 7, b"")

    def test_legacy_initial_values_use_getvalue_affine_without_display_selector(self):
        freeze = bytearray(84)
        freeze[79] = 0x21
        freeze[76] = 0  # Native GetValue ignores this unknown display selector.
        struct.pack_into("<HH", freeze, 62, 0, 7)
        physical = bytearray(24)
        struct.pack_into("<iii", physical, 0, 2, 1, 3)
        physical[20:22] = bytes((1, 4))  # signed; precision is ignored too.
        for p4 in (False, True):
            replay = Replay([(bytes.fromhex("2121"), bytes.fromhex("6121ff"))])
            session = ToyotaSession(
                replay, "ecu", {"read": spec(bytes.fromhex("2100"))}
            )
            value = (
                session.read_initial_p4("read", bytes(freeze), bytes(physical), b"\x01")
                if p4
                else session.read_initial_p3("read", bytes(freeze), bytes(physical))
            )
            self.assertEqual(value, 1)
        replay = Replay([(bytes.fromhex("2121"), bytes.fromhex("6121"))])
        session = ToyotaSession(replay, "ecu", {"read": spec(bytes.fromhex("2100"))})
        with self.assertRaises(ToyotaCodecError) as error:
            session.read_initial_p3("read", bytes(freeze), bytes(physical))
        self.assertEqual(error.exception.code, SHORT_REPLY)
        struct.pack_into("<iii", physical, 0, 1, 1, 0)
        replay = Replay([(bytes.fromhex("2121"), bytes.fromhex("6121ff"))])
        session = ToyotaSession(replay, "ecu", {"read": spec(bytes.fromhex("2100"))})
        self.assertEqual(
            session.read_initial_p3("read", bytes(freeze), bytes(physical)), 0xFFFFFFFF
        )

    def test_tesla_selected_support_expansion_visibility_and_fallback(self):
        row = bytearray(36)
        struct.pack_into("<II", row, 20, 0x123456, 77)
        definition = TeslaDtcDefinition(bytes(row), "native sig", "native name", "note")
        reply = bytes.fromhex("5900123456ab0001123456") + bytes(48) + b"ignored"
        self.assertEqual(len(reply[:59]), 59)
        definitions = {0x123456: definition}
        hidden = parse_tesla_dtcs(reply, definitions)
        self.assertEqual([x["expanded_code"] for x in hidden], [0xAB0001])
        self.assertEqual((hidden[0]["signature"], hidden[0]["name"]), ("AB0001", "???"))
        shown = parse_tesla_dtcs(reply, definitions, include_hidden=True)
        self.assertEqual([x["code"] for x in shown], [0x3456, 1, 0x3456])
        self.assertEqual(shown[0]["native_field_18"], 77)
        self.assertEqual(shown[0]["comment"], "note")
        with self.assertRaises(ToyotaCodecError) as error:
            parse_tesla_dtcs(bytes(58), {})
        self.assertEqual(error.exception.code, SHORT_REPLY)
        replay = Replay([(b"\x19", reply)])
        session = ToyotaSession(replay, "ecu", {"tesla": spec(b"\x19", check="raw")})
        for support in (b"", b"\xff" * 56, b"\xff" * 56 + b"\x00"):
            with self.assertRaises(ToyotaCodecError) as error:
                session.dtcs_tesla("tesla", support, definitions)
            self.assertEqual(error.exception.code, 0x90040501)
        self.assertEqual(len(replay.steps), 1)
        self.assertEqual(session.dtcs_tesla("tesla", b"\xff" * 58, definitions), hidden)
        malformed = TeslaDtcDefinition(bytes(36), "", "")
        with self.assertRaises(ToyotaCodecError):
            session.dtcs_tesla("tesla", b"\xff" * 57, {1: malformed})

    def test_no_io_until_explicit_execute(self):
        replay = Replay([(b"\x18", b"\x58\x01")])
        session = ToyotaSession(replay, "engine", {"read": spec(payload_offset=1)})
        self.assertEqual(replay.calls, [])
        self.assertEqual(session.execute("read"), b"\x01")
        json.dumps(session.report())

    def test_checks_and_missing_dependencies(self):
        replay = Replay([])
        session = ToyotaSession(replay, "ecu", {"read": spec()})
        with self.assertRaises(SessionError):
            session.sequence(["read", "missing"])
        self.assertFalse(replay.calls)
        with self.assertRaises(ValueError):
            CommandSpec(CommandFrame(b""))
        with self.assertRaises(ValueError):
            Limits(seconds=float("inf"))
        for value in (b"", b"\x7f", b"\x59"):
            with self.assertRaises(ToyotaCodecError):
                ToyotaSession(
                    Replay([(b"\x18", value)]), "ecu", {"read": spec()}
                ).execute("read")

    def test_mask_check(self):
        command = CommandSpec(CommandFrame(b"\x18", b"\xf0", b"\x50"), "both")
        self.assertEqual(command.validate(b"\x58"), b"\x58")
        with self.assertRaises(ToyotaCodecError):
            command.validate(b"\x68")
        with self.assertRaises(ValueError):
            spec(check="unknown")

    def test_kwp_receive_only_then_zero(self):
        replay = Replay(
            [
                (b"\x18", bytes.fromhex("58 01 02 03 04 05 06")),
                (b"", bytes.fromhex("58 07 08 00 00")),
            ]
        )
        session = ToyotaSession(replay, "ecu", {"dtc": spec()})
        self.assertEqual(session.dtcs("dtc"), [0x0102, 0x0304, 0x0506, 0x0708])
        self.assertEqual(replay.steps, [])

    def test_kwp_native_timeout_after_full_chunk(self):
        replay = Replay(
            [
                (b"\x18", bytes.fromhex("58 01 02 03 04 05 06")),
                (b"", NativeStatus(0x91010009)),
            ]
        )
        self.assertEqual(
            ToyotaSession(replay, "ecu", {"dtc": spec()}).dtcs("dtc"),
            [0x0102, 0x0304, 0x0506],
        )

    def test_kwp_retries_after_invalid_service(self):
        replay = Replay(
            [(b"\x18", b"\x59"), (b"\x18", bytes.fromhex("58 01 02 00 00"))]
        )
        self.assertEqual(
            ToyotaSession(replay, "ecu", {"dtc": spec()}).dtcs("dtc", retries=1),
            [0x0102],
        )

    def test_kwp_retry_after_valid_chunk_never_retransmits(self):
        replay = Replay(
            [
                (b"\x18", bytes.fromhex("58 01 02 03 04 05 06")),
                (b"", bytes.fromhex("59")),
                (b"", bytes.fromhex("58 07 08 00 00")),
            ]
        )
        session = ToyotaSession(replay, "ecu", {"dtc": spec()})
        self.assertEqual(
            session.dtcs("dtc", retries=1), [0x0102, 0x0304, 0x0506, 0x0708]
        )
        self.assertFalse(replay.steps)

    def test_kwp_masked_failure_clears_and_direct_status_bypasses(self):
        for status, flags, expected in [
            (0x91010009, 1, []),
            (0x90020321, 2, []),
            (0x90020323, 4, None),
        ]:
            session = ToyotaSession(
                Replay([(b"\x18", NativeStatus(status))]), "ecu", {"dtc": spec()}
            )
            if expected is None:
                with self.assertRaises(NativeStatus):
                    session.dtcs("dtc", mask_flags=flags)
            else:
                self.assertEqual(session.dtcs("dtc", mask_flags=flags), expected)

    def test_kwp_budget_is_not_masked(self):
        replay = Replay([(b"\x18", bytes.fromhex("58 01 02 03 04 05 06"))])
        session = ToyotaSession(
            replay, "ecu", {"dtc": spec()}, limits=Limits(exchanges=1)
        )
        with self.assertRaises(SessionError):
            session.dtcs("dtc", mask_flags=7)
        self.assertEqual(len(replay.calls), 1)

    def test_can_counted_continuation(self):
        replay = Replay(
            [
                (b"\x18", bytes.fromhex("58 03 01 02 03 04")),
                (b"", bytes.fromhex("58 03 05 06")),
            ]
        )
        session = ToyotaSession(replay, "ecu", {"dtc": spec()})
        self.assertEqual(session.dtcs_can("dtc"), [0x0102, 0x0304, 0x0506])
        self.assertFalse(replay.steps)

    def test_can_retry_after_valid_reply_never_retransmits(self):
        replay = Replay(
            [
                (b"\x18", bytes.fromhex("58 02 12 34")),
                (b"", NativeStatus(0x90020321)),
                (b"", bytes.fromhex("58 01 56 78")),
            ]
        )
        session = ToyotaSession(replay, "ecu", {"dtc": spec()})
        self.assertEqual(session.dtcs_can("dtc", retries=1), [0x1234, 0x5678])
        self.assertFalse(replay.steps)

    def test_dk_waits_for_native_timeout_after_count(self):
        replay = Replay(
            [(b"\x18", bytes.fromhex("58 01 12 34")), (b"", NativeStatus(0x91010009))]
        )
        session = ToyotaSession(replay, "ecu", {"dtc": spec()})
        self.assertEqual(session.dtcs_can("dtc", dk=True), [0x1234])
        self.assertEqual(replay.steps, [])
        replay = Replay(
            [(b"\x18", bytes.fromhex("58 02 12 34")), (b"", NativeStatus(0x91010009))]
        )
        session = ToyotaSession(replay, "ecu", {"dtc": spec()})
        with self.assertRaises(NativeStatus):
            session.dtcs_can("dtc", dk=True)

    def test_can_extended_timeout_and_status_mask(self):
        replay = Replay(
            [(b"\x18", bytes.fromhex("58 01 12 34")), (b"", NativeStatus(0x91010009))]
        )
        session = ToyotaSession(replay, "ecu", {"dtc": spec()})
        self.assertEqual(session.dtcs_can("dtc", extended=True), [0x1234])
        session = ToyotaSession(
            Replay([(b"\x18", NativeStatus(0x90020323))]), "ecu", {"dtc": spec()}
        )
        self.assertEqual(session.dtcs_can("dtc", extended=True, mask_flags=4), [])
        session = ToyotaSession(
            Replay([(b"\x18", NativeStatus(0x90020323))]), "ecu", {"dtc": spec()}
        )
        with self.assertRaises(NativeStatus):
            session.dtcs_can("dtc", mask_flags=4)

    def test_native_dtc_fallback_display_width(self):
        self.assertEqual(format_dtc(0x1234), "P1234")
        self.assertEqual(format_dtc(0xFFFF), "U3FFF")
        self.assertEqual(format_dtc(0x123456, bits=24), "P123456")
        self.assertEqual(format_dtc(0xFFFFFF, bits=24), "U3FFFFF")
        with self.assertRaises(ValueError):
            format_dtc(0x10000)

    def test_psa_native_status_and_no_status_groups(self):
        reply = bytes.fromhex("58 03 12 34 28 56 78 29 00 00 00")
        self.assertEqual(parse_psa_dtcs(reply, 1), [{"code": 0x1234, "status": 0x28}])
        self.assertEqual(len(parse_psa_dtcs(reply, 2)), 2)
        self.assertEqual(
            parse_psa_dtcs(bytes.fromhex("58 02 12 34 56 78 ff"), 1, no_status=True),
            [{"code": 0x1234}, {"code": 0x5678}],
        )
        self.assertEqual(
            parse_dk_iso_dtcs(bytes.fromhex("12 34 12 00 56")), [0x12, 0x34, 0x12]
        )

    def test_psa_audio_native_filter_and_overflow_end(self):
        reply = bytes.fromhex("58 0a 10 01 20 02 30 03")
        self.assertEqual(parse_psa_audio_dtcs(reply, 1), [0x1001])
        self.assertEqual(parse_psa_audio_dtcs(reply, 2), [0x2002])
        replay = Replay(
            [
                (b"\x18", reply),
                (b"\x19", bytes.fromhex("59 00 10 04")),
                (b"\x19", NativeStatus(0x90020321, bytes.fromhex("7f 19 12"))),
            ]
        )
        session = ToyotaSession(replay, "ecu", {"first": spec(), "next": spec(b"\x19")})
        self.assertEqual(session.dtcs_psa_audio("first", "next", 1), [0x1001, 0x1004])
        self.assertFalse(replay.steps)
        replay = Replay([(b"\x18", b"\x58\x00")])
        session = ToyotaSession(replay, "ecu", {"first": spec(), "next": spec(b"\x19")})
        self.assertEqual(session.dtcs_psa_audio("first", "next", 1), [])

    def test_psa_audio_and_add_ht_preserve_native_addtail_duplicates(self):
        self.assertEqual(
            parse_psa_audio_dtcs(bytes.fromhex("58 02 10 01 10 01"), 1),
            [0x1001, 0x1001],
        )
        self.assertEqual(
            parse_psa_add_ht_dtcs(bytes.fromhex("58 01 12 34 aa bb cc 12 34")),
            [0x1234, 0x1234],
        )
        replay = Replay(
            [
                (b"\x18", bytes.fromhex("58 0a 10 01")),
                (b"\x19", bytes.fromhex("59 00 10 01")),
                (b"\x19", NativeStatus(0x90020321, bytes.fromhex("7f 19 12"))),
            ]
        )
        session = ToyotaSession(replay, "ecu", {"first": spec(), "next": spec(b"\x19")})
        self.assertEqual(session.dtcs_psa_audio("first", "next", 1), [0x1001, 0x1001])
        self.assertFalse(replay.steps)

    def test_psa_add_ht_native_stride_and_retry(self):
        reply = bytes.fromhex("58 01 12 34 aa bb cc 00 00 dd ee ff 56 78")
        self.assertEqual(parse_psa_add_ht_dtcs(reply), [0x1234, 0x5678])
        replay = Replay([(b"\x18", NativeStatus(0x91010009)), (b"\x18", reply)])
        session = ToyotaSession(replay, "ecu", {"read": spec()})
        self.assertEqual(session.dtcs_psa_add_ht("read", retries=1), [0x1234, 0x5678])
        self.assertFalse(replay.steps)

    def test_psa_native_overflow_chain_and_second_error(self):
        replay = Replay(
            [
                (b"\x18", bytes.fromhex("58 0a 12 34 01")),
                (b"\x19", NativeStatus(0x90020323)),
            ]
        )
        session = ToyotaSession(
            replay, "ecu", {"first": spec(), "second": spec(b"\x19")}
        )
        self.assertEqual(session.dtcs_psa(["first", "second"], 1), [0x1234])
        self.assertFalse(replay.steps)
        replay = Replay([(b"\x18", bytes.fromhex("58 01 12 34 01"))])
        session = ToyotaSession(
            replay, "ecu", {"first": spec(), "second": spec(b"\x19")}
        )
        self.assertEqual(session.dtcs_psa(["first", "second"], 1), [0x1234])
        self.assertFalse(replay.steps)
        session = ToyotaSession(
            Replay([(b"\x18", NativeStatus(0x90020323))]), "ecu", {"first": spec()}
        )
        with self.assertRaises(NativeStatus):
            session.dtcs_psa(["first"], 1)

    def test_p5_status_and_duplicate_merge(self):
        rules = [StatusRule(1, 1, 1), StatusRule(2, 2, 2)]
        reply = bytes.fromhex("59 02 03 12 34 56 01 12 34 56 02 01 02 03 00")
        self.assertEqual(
            parse_p5_dtcs(reply, rules),
            [{"code": 0x123456, "status": 3, "diag_type": 3}],
        )
        self.assertEqual(diag_type(3, rules), 3)
        row = bytes(8) + b"\x01\x01"
        self.assertEqual(StatusRule.from_record(row, 1), rules[0])
        with self.assertRaises(SessionError):
            parse_p5_dtcs(reply, [])
        self.assertEqual(
            parse_p5_dtcs(reply[:-1], rules), parse_p5_dtcs(reply[:11], rules)
        )
        self.assertEqual(parse_p5_dtcs(bytes.fromhex("59 02 ff 12 34"), []), [])
        with self.assertRaises(ToyotaCodecError):
            parse_p5_dtcs(b"\x59\x02", rules)
        self.assertEqual(parse_p5_dtcs(bytes.fromhex("59 02 00"), rules), [])

    def test_scaling_and_data_request(self):
        freeze = bytearray(84)
        physical = bytearray(24)
        struct.pack_into("<HHH", freeze, 60, 7, 0, 7)
        freeze[76] = 2
        struct.pack_into("<iiiH", physical, 0, 2, 1, -4, 7)
        self.assertEqual(
            scale_signal(b"\x05", bytes(freeze), bytes(physical))["value"], 6
        )
        replay = Replay([(b"\x21\x12", b"\x61\x05")])
        session = ToyotaSession(
            replay, "ecu", {"pid": spec(b"\x21\x00", payload_offset=1)}
        )
        value = session.data_list(
            "pid", 0x12, 1, freeze=bytes(freeze), physical=bytes(physical)
        )
        assert isinstance(value, dict)
        self.assertEqual(value["value"], 6)

    def test_selected_signal_symbolic_and_unknown_display(self):
        freeze, physical = bytearray(84), bytearray(24)
        struct.pack_into("<HHH", freeze, 60, 7, 0, 7)
        struct.pack_into("<iiiH", physical, 0, 2, 1, -4, 7)
        freeze[76] = 1
        result = scale_signal(
            b"\x05",
            bytes(freeze),
            bytes(physical),
            patterns=((6, "Selected label", 0, 0),),
        )
        self.assertEqual(result["display"], "Selected label")
        self.assertIsNone(result["value"])
        unresolved = scale_signal(b"\x05", bytes(freeze), bytes(physical))
        self.assertEqual(unresolved["status"], "unresolved")
        self.assertIsNone(unresolved["value"])
        freeze[76] = 0
        self.assertEqual(
            scale_signal(b"\x05", bytes(freeze), bytes(physical))["display"],
            "-TypeErr-",
        )

    def test_native_ffd_types_flags_and_timestamp_order(self):
        self.assertEqual(
            [
                ffd_type(v)
                for v in (0, 1, 2, 3, 0x10, 0x2F, 0x30, 0x4F, 0x50, 0x6F, 0x70)
            ],
            [0, 1, 2, 0, 0x10, 0x10, 0x30, 0x30, 0x50, 0x50, 0],
        )
        self.assertEqual(
            [ffd_type(v, True) for v in (1, 14, 15, 0x10, 0x1F, 0xEF, 0xF0)],
            [0x101, 0x10E, 0, 0x210, 0x210, 0x2E0, 0],
        )
        self.assertEqual(ffd_existence_flag(1), 1)
        self.assertEqual(ffd_existence_flag(2, 1), 0x11)
        self.assertEqual(ffd_existence_flag(0x101), 0x100)
        self.assertEqual(ffd_existence_flag(0x10E), 0x200000)
        self.assertEqual(ffd_existence_flag(0x210, 7), 7)
        self.assertEqual(compare_timestamp(0xFFFFFFFF, 0, 0, 0), 1)
        self.assertEqual(compare_timestamp(1, 1, 2, 3), 2)
        self.assertEqual(compare_timestamp(1, 1, 3, 3), 3)
        samples = [
            FreezeSample(0x210, 2, 1, 0, b"a"),
            FreezeSample(1, 1, 5, 0, b"b"),
            FreezeSample(0x101, 1, 0, 0, b"c"),
            FreezeSample(0x10, 16, 2, 0, b"d"),
        ]
        self.assertEqual(
            [sample.payload for sample in order_freeze_samples(samples)],
            [b"d", b"b", b"c", b"a"],
        )
        with self.assertRaises(SessionError):
            order_freeze_samples([FreezeSample(0x999, 0, 0, 0, b"")])

    def test_native_ffd_time_indices_groups_and_propagation(self):
        samples = [
            FreezeSample(1, 1, 5, 9, b"anchor"),
            FreezeSample(0x10, 16, 3, 9, b"before"),
            FreezeSample(0x30, 48, 5, 9, b"equal"),
            FreezeSample(2, 2, 0, 0, b"separate"),
            FreezeSample(0x50, 80, 1, 0, b"later"),
        ]
        indexed = index_freeze_samples(samples)
        self.assertEqual(
            [(s.payload, s.time_index) for s in indexed],
            [
                (b"before", -1),
                (b"anchor", 0),
                (b"equal", 0),
                (b"separate", 0),
                (b"later", 1),
            ],
        )
        self.assertEqual(order_freeze_samples([samples[1]]), ())  # no anchor type1
        propagated = apply_freeze_time_indices(samples, indexed)
        self.assertEqual([s.time_index for s in propagated], [0, -1, 0, 0, 1])
        without_clocks = apply_freeze_time_indices(samples, [])
        self.assertEqual(
            [s.time_index for s in without_clocks], [0, None, None, 0, None]
        )
        duplicates = [FreezeSample(1, 1, 10, 0, b""), FreezeSample(1, 1, 20, 0, b"")]
        target = [FreezeSample(1, 1, 0, 0, b"")]
        self.assertEqual(apply_freeze_time_indices(target, duplicates)[0].time_index, 1)
        before_anchor = [
            FreezeSample(0x10, 16, 5, 0, b""),
            FreezeSample(0x10, 16, 10, 0, b""),
            FreezeSample(1, 1, 20, 0, b""),
        ]
        target = [FreezeSample(0x10, 16, 0, 0, b"")]
        self.assertEqual(
            apply_freeze_time_indices(target, before_anchor)[0].time_index, -2
        )

    def test_p5_selected_initial_value_read_helpers(self):
        active = bytearray(64)
        struct.pack_into("<HH", active, 0x28, 0, 7)
        struct.pack_into("<H", active, 0x34, 0x1234)
        monitor = bytearray(64)
        struct.pack_into("<HH", monitor, 0x2C, 4, 11)
        struct.pack_into("<H", monitor, 0x36, 0x5678)
        replay = Replay(
            [
                (bytes.fromhex("221234"), bytes.fromhex("621234ab")),
                (bytes.fromhex("225678"), bytes.fromhex("625678abcd")),
            ]
        )
        session = ToyotaSession(
            replay, "ecu", {"initial": spec(bytes.fromhex("220000"))}
        )
        self.assertEqual(session.read_active_initial_p5("initial", bytes(active)), 0xAB)
        self.assertEqual(
            session.read_monitor_initial_p5("initial", bytes(monitor)), 0xBC
        )
        short = ToyotaSession(
            Replay([(bytes.fromhex("221234"), bytes.fromhex("621234"))]),
            "ecu",
            {"initial": spec(bytes.fromhex("220000"))},
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            short.read_active_initial_p5("initial", bytes(active))
        self.assertEqual(caught.exception.code, 0xA0040202)

    def test_p5_routine_initial_probe_status_and_host_policy(self):
        for result, subaru, expected in [
            (bytes.fromhex("71031234aa"), False, True),
            (bytes.fromhex("71031234"), False, False),
            (NativeStatus(0x90020321, bytes.fromhex("7f3124")), True, True),
            (NativeStatus(0x90020321, bytes.fromhex("7f3133")), True, True),
            (NativeStatus(0x90020321, bytes.fromhex("7f3124")), False, False),
            (NativeStatus(77), True, False),
        ]:
            session = ToyotaSession(
                Replay([(bytes.fromhex("31031234"), result)]),
                "ecu",
                {"probe": spec(bytes.fromhex("31030000"))},
            )
            self.assertEqual(
                session.routine_initial_status_p5("probe", 0x1234, 1, subaru=subaru),
                expected,
            )
        flag = [False]

        def cancelled_error(ecu, request):
            flag[0] = True
            raise NativeStatus(77)

        session = ToyotaSession(
            cancelled_error,
            "ecu",
            {"probe": spec(bytes.fromhex("31030000"))},
            cancelled=lambda: flag[0],
        )
        with self.assertRaises(Cancelled):
            session.routine_initial_status_p5("probe", 0x1234, 1)
        with self.assertRaises(SessionError):
            session.routine_initial_status_p5("missing", 0x1234, 1)

    def test_p5_absolute_bcd_components_and_subaru_types(self):
        pids = {signal: signal + 0x100 for signal in range(0x3C, 0x42)}
        values = {
            pids[signal]: encoded
            for signal, encoded in zip(
                range(0x3C, 0x42), (0x38, 0x12, 0x31, 0x23, 0x59, 0x59)
            )
        }
        self.assertEqual(
            absolute_time_values(values, pids),
            dict(zip(range(0x3C, 0x42), (38, 12, 31, 23, 59, 59))),
        )
        values[pids[0x3C]] = 0x39  # native maximum is 38, no epoch guessed
        values[pids[0x3D]] = 0
        values[pids[0x3E]] = 0x1A  # invalid BCD: omitted by native helper
        self.assertEqual(
            absolute_time_values(values, pids), {0x3F: 23, 0x40: 59, 0x41: 59}
        )
        pids[0x41] = 0
        self.assertNotIn(0x41, absolute_time_values(values, pids))
        with self.assertRaises(SessionError):
            absolute_time_values({}, {})
        with self.assertRaises(ValueError):
            absolute_time_values({1: -1}, pids)
        self.assertEqual(
            [ffd_type(n, subaru=True) for n in (0, 1, 2, 0x10, 0x2F, 0x30)],
            [0, 1, 0, 0x10, 0x10, 0],
        )
        self.assertEqual(
            [ffd_type(n, True, subaru=True) for n in (0, 1, 0xFE, 0xFF)],
            [0, 0x10, 0x10, 0],
        )

    def test_native_p5_stored_freeze_data_ids(self):
        reply = bytes.fromhex(
            "59 04 12 34 56 01 10 02 01 02 aa bb 03 04 cc 12 01 03 04 dd"
        )
        result = parse_p5_freeze(reply, {0x0102: 2, 0x0304: 1})
        self.assertEqual(result["code"], 0x123456)
        self.assertEqual(result["status"], 1)
        self.assertEqual(
            result["records"],
            [
                {
                    "number": 0x10,
                    "kind": 1,
                    "items": [
                        {"did": 0x0102, "payload": "aabb"},
                        {"did": 0x0304, "payload": "cc"},
                    ],
                },
                {
                    "number": 0x12,
                    "kind": 2,
                    "items": [{"did": 0x0304, "payload": "dd"}],
                },
            ],
        )
        session = ToyotaSession(
            Replay([(bytes.fromhex("19 04 12 34 56 ff"), reply)]),
            "ecu",
            {"freeze": spec(bytes.fromhex("19 04 00 00 00 ff"))},
        )
        self.assertEqual(
            session.freeze_p5_data("freeze", 0x123456, {0x0102: 2, 0x0304: 1}), result
        )
        with self.assertRaises(SessionError):
            parse_p5_freeze(reply, {})
        with self.assertRaises(ToyotaCodecError):
            parse_p5_freeze(reply[:-1], {0x0102: 2, 0x0304: 1})
        json.dumps(result)

    def test_p5_data_id_selected_extraction_and_stored_decode(self):
        row, physical = bytearray(64), bytearray(24)
        row[0x20] = 2
        row[0x3A] = 2
        struct.pack_into("<H", row, 0x24, 0x123)
        struct.pack_into("<HHH", row, 0x2A, 7, 0, 7)
        struct.pack_into("<iiiH", physical, 0, 2, 1, -4, 7)
        samples = p5_data_id_samples(
            b"\x05", [bytes(row)], {7: bytes(physical)}, {0x123: True}
        )
        self.assertEqual(
            (samples[0]["pid"], samples[0]["raw"], samples[0]["value"]), (0x123, 5, 6)
        )
        self.assertEqual(
            p5_data_id_samples(b"\x05", [bytes(row)], {}, {0x123: False}), []
        )
        with self.assertRaises(SessionError):
            p5_data_id_samples(b"\x05", [bytes(row)], {7: bytes(physical)}, {})
        short = bytearray(row)
        struct.pack_into("<HH", short, 0x2C, 8, 15)
        self.assertEqual(p5_data_id_samples(b"\x05", [bytes(short)], {}, {}), [])
        row[0x3A] = 1
        struct.pack_into("<H", row, 0x32, 9)

        def decode(did, payload):
            self.assertEqual(did, 0x2001)
            return p5_data_id_samples(
                payload,
                [bytes(row)],
                {7: bytes(physical)},
                {0x123: True},
                patterns={9: ((6, "Label", 0, 0),)},
            )

        reply = bytes.fromhex("5904123456011001200105")
        session = ToyotaSession(
            Replay([(bytes.fromhex("1904123456ff"), reply)]),
            "ecu",
            {"freeze": spec(bytes.fromhex("1904000000ff"))},
        )
        result = session.freeze_p5_data("freeze", 0x123456, {0x2001: 1}, decode=decode)
        self.assertIn('"display": "Label"', json.dumps(result))

    def test_subaru_stored_multiple_codes_and_number_translation(self):
        reply = bytes.fromhex("5904 801234560101 200105 815566770201 2001aa")
        result = parse_subaru_stored_freeze(reply, {0x2001: 1}, request_number=255)
        records = result["records"]
        assert isinstance(records, list)
        self.assertEqual(
            [(row["code"], row["native_number"], row["status"]) for row in records],
            [(0x123456, 1, 0), (0x556677, 2, 0)],
        )
        self.assertEqual(records[1]["status_raw"], 2)
        self.assertEqual(records[0]["existence_flag"], 1)
        zero = bytes.fromhex("5904 801234560100 200105")
        self.assertEqual(
            parse_subaru_stored_freeze(zero, {0x2001: 1}, request_number=255)[
                "ignored_tail"
            ],
            "200105",
        )
        self.assertEqual(
            parse_subaru_stored_freeze(zero, {0x2001: 1}, request_number=0)[
                "ignored_tail"
            ],
            "",
        )
        with self.assertRaises(SessionError):
            parse_subaru_stored_freeze(reply, {}, request_number=255)
        with self.assertRaises(ToyotaCodecError):
            parse_subaru_stored_freeze(reply[:-1], {0x2001: 1}, request_number=255)
        replay = Replay([(b"\x19\x04", reply)])
        session = ToyotaSession(replay, "ecu", {"subaru": spec(b"\x19\x04")})
        self.assertEqual(
            session.freeze_subaru_stored("subaru", {0x2001: 1}, request_number=255),
            result,
        )
        json.dumps(result)

    def test_subaru_snapshot_ordinary_types_and_selected_request(self):
        reply = bytes.fromhex("5904123456010101200105 1001200106")
        result = parse_p5_freeze(reply, {0x2001: 1}, subaru_snapshot=True)
        records = result["records"]
        assert isinstance(records, list)
        self.assertEqual(
            [(row["number"], row["kind"], row["native_number"]) for row in records],
            [(1, 1, 0x82), (0x10, 0x10, 0x91)],
        )
        replay = Replay([(bytes.fromhex("1904123456ff"), reply)])
        session = ToyotaSession(
            replay, "ecu", {"snapshot": spec(bytes.fromhex("1904000000ff"))}
        )
        self.assertEqual(
            session.freeze_subaru_snapshot(
                "snapshot", 0x123456, {0x2001: 1}, request_number=255
            ),
            result,
        )
        with self.assertRaises(SessionError):
            parse_p5_freeze(reply, {0x2001: 1})

    def test_native_p5_zero_count_request_specific_fallback(self):
        reply = bytes.fromhex("59 04 12 34 56 01 10 00 01 02 aa 03 04 bb")
        self.assertEqual(
            parse_p5_freeze(reply, {0x0102: 1, 0x0304: 1})["ignored_tail"],
            "0102aa0304bb",
        )
        result = parse_p5_freeze(
            reply, {0x0102: 1, 0x0304: 1}, zero_count_until_end=True
        )
        self.assertEqual(
            result["records"],
            [
                {
                    "number": 0x10,
                    "kind": 1,
                    "items": [
                        {"did": 0x0102, "payload": "aa"},
                        {"did": 0x0304, "payload": "bb"},
                    ],
                }
            ],
        )

    def test_freeze_support_native_mask_extraction_and_minimum(self):
        frame = CommandFrame(bytes.fromhex("12 00 00"), bytes.fromhex("00 ff ff"))
        self.assertEqual(
            freeze_support_request(frame.request, 9), bytes.fromhex("12 00 09")
        )
        self.assertEqual(
            freeze_support_request(bytes.fromhex("12 00 aa bb"), 9),
            bytes.fromhex("12 09 aa bb"),
        )
        self.assertEqual(freeze_support_code(frame, bytes.fromhex("52 12 34")), 0x1234)
        with self.assertRaises(ToyotaCodecError):
            freeze_support_code(frame, bytes.fromhex("52 12"))
        result, added = associate_freeze(
            [DtcFreeze(0x1234), DtcFreeze(0x5678)], 0x1234, 7
        )
        self.assertTrue(added)
        result, added = associate_freeze(result, 0x1234, 3)
        self.assertFalse(added)
        self.assertEqual(result[0], DtcFreeze(0x1234, True, 3))
        self.assertFalse(result[1].supported)

    def test_freeze_history_and_timestamp_exclusions(self):
        prior = [DtcFreeze(0x1234, True, 7)]
        cases: tuple[tuple[Literal["history", "timestamp"], int], ...] = (
            ("history", 2),
            ("timestamp", 1),
        )
        for kind, diagnostic_type in cases:
            result, added = associate_freeze(
                [DtcFreeze(0x1234)],
                0x1234,
                7,
                kind=kind,
                diagnostic_type=diagnostic_type,
                other_records=prior,
            )
            self.assertFalse(added)
            self.assertFalse(result[0].supported)
            result, added = associate_freeze(
                result,
                0x1234,
                6,
                kind=kind,
                diagnostic_type=diagnostic_type,
                other_records=prior,
            )
            self.assertTrue(added)
            self.assertEqual(result[0].number, 6)

    def test_freeze_support_session_rows_and_native_failure(self):
        frame = CommandFrame(bytes.fromhex("12 00 00"), bytes.fromhex("00 ff ff"))
        replay = Replay(
            [
                (bytes.fromhex("12 00 07"), bytes.fromhex("52 12 34")),
                (bytes.fromhex("12 00 05"), NativeStatus(0x91010009)),
                (bytes.fromhex("12 00 03"), bytes.fromhex("52 12 34")),
            ]
        )
        session = ToyotaSession(replay, "ecu", {"support": CommandSpec(frame)})
        result = session.freeze_support(
            "support", [bytes((0, 0, n)) for n in (7, 5, 3)], [DtcFreeze(0x1234)]
        )
        self.assertEqual(result, (DtcFreeze(0x1234, True, 3),))
        self.assertFalse(replay.steps)

    def test_freeze_and_vin(self):
        freeze = bytearray(84)
        freeze[0x4F] = 0xAA
        replay = Replay(
            [
                (bytes.fromhex("12 aa 02"), bytes.fromhex("52 aa 02 55")),
                (bytes.fromhex("19 02 12 34 56 01"), bytes.fromhex("59 02")),
                (b"\x22", b"\x62\x00\x00\x00A\x00BC"),
            ]
        )
        session = ToyotaSession(
            replay,
            "ecu",
            {
                "p3": spec(bytes.fromhex("12 00 00")),
                "p5": spec(bytes.fromhex("19 02 00 00 00 00")),
                "vin": spec(b"\x22"),
            },
        )
        self.assertEqual(session.freeze_p3("p3", bytes(freeze), 2), b"\x55")
        self.assertEqual(session.freeze_p5("p5", 0x123456, 1), bytes.fromhex("59 02"))
        self.assertEqual(session.vin("vin"), b"ABC")

    def test_poll_health_and_cancellation(self):
        replay = Replay([(b"\x18", b"\x58"), (b"\x18", b"\x58")])
        good = ToyotaSession(replay, "ecu", {"read": spec()})
        self.assertEqual(len(good.poll(["read"], 2)), 2)
        bad = ToyotaSession(
            Replay([(b"\x18", NativeStatus(1))]), "bad", {"read": spec()}
        )
        self.assertEqual(health_check({"bad": bad}, ["read"])["bad"]["status"], "error")
        cancelled = ToyotaSession(
            Replay([]), "ecu", {"read": spec()}, cancelled=lambda: True
        )
        with self.assertRaises(Cancelled):
            health_check({"ecu": cancelled}, ["read"])

    def test_sienna_framing_receive_only_and_timeout(self):
        # Native keeps first five bytes, then removes two bytes per six.
        wire = bytes.fromhex("5904000102aabb03040506ccdd0708")
        self.assertEqual(
            normalize_sienna_dtcs(wire), bytes.fromhex("5904000102030405060708")
        )
        replay = Replay([(b"\x19", wire), (b"", b"\x59\x00")])
        session = ToyotaSession(replay, "door", {"read": spec(b"\x19")})
        self.assertEqual(
            session.dtcs_can("read", sienna=True), [1, 0x203, 0x405, 0x607]
        )
        # Sienna does not terminate on reaching count: a nonzero prior count
        # with actual DTC pairs still makes timeout fatal.
        replay = Replay(
            [(b"\x19", b"\x59\x01\x00\x01"), (b"", NativeStatus(0x91010009))]
        )
        with self.assertRaises(NativeStatus):
            ToyotaSession(replay, "door", {"read": spec(b"\x19")}).dtcs_can(
                "read", sienna=True
            )
        replay = Replay([(b"\x19", b"\x59\x01"), (b"", NativeStatus(0x91010009))])
        self.assertEqual(
            ToyotaSession(replay, "door", {"read": spec(b"\x19")}).dtcs_can(
                "read", sienna=True
            ),
            [],
        )
        with self.assertRaises(ValueError):
            session.dtcs_can("read", sienna=True, extended=True)

    def test_post_io_policy_applies_to_native_and_generic_failures(self):
        for failure in (
            NativeStatus(77),
            TimeoutError("callback timeout"),
            KeyboardInterrupt(),
        ):
            flag = [False]

            def exchange(ecu, request, flag=flag, failure=failure):
                flag[0] = True
                raise failure

            session = ToyotaSession(
                exchange, "ecu", {"read": spec()}, cancelled=lambda flag=flag: flag[0]
            )
            with self.assertRaises(Cancelled):
                session.execute("read")
        now = [0.0]

        def late_native(ecu, request):
            now[0] = 2.0
            raise NativeStatus(77)

        session = ToyotaSession(
            late_native,
            "ecu",
            {"read": spec()},
            limits=Limits(seconds=1),
            clock=lambda: now[0],
        )
        with self.assertRaises(SessionError):
            session.execute("read")
        self.assertEqual(
            session.report()["trace"],
            [
                {
                    "ecu": "ecu",
                    "request": "18",
                    "receive_only": False,
                    "native_status": 77,
                }
            ],
        )

    def test_deadline_checks_after_exchange(self):
        now = [0.0]

        def exchange(ecu, request):
            now[0] = 11.0
            return b"\x58"

        session = ToyotaSession(exchange, "ecu", {"read": spec()}, clock=lambda: now[0])
        with self.assertRaises(SessionError):
            session.execute("read")

    def test_native_vin_multi(self):
        replay = Replay(
            [
                (b"\x18", b"\x58\x00\x02"),
                (b"\x22", b"\x62\x00\x00\x00A"),
                (b"", b"\x62\x00\x00BC"),
            ]
        )
        session = ToyotaSession(
            replay, "ecu", {"count": spec(b"\x18"), "vin": spec(b"\x22")}
        )
        self.assertEqual(session.vin_multi("count", "vin"), b"ABC")
        self.assertEqual(replay.steps, [])

    def test_selected_dtc_information_and_highlighting(self):
        diagnostic, detail, signal = bytearray(28), bytearray(20), bytearray(8)
        struct.pack_into("<I", diagnostic, 12, 0x123)
        struct.pack_into("<H", detail, 12, 7)
        struct.pack_into("<H", signal, 2, 99)
        signal[4] = 2
        with self.assertRaises(SessionError):
            dtc_information(
                bytes(diagnostic), [bytes(detail)], signature="P1234", name="Synthetic"
            )
        result = dtc_information(
            bytes(diagnostic),
            [bytes(detail)],
            signature="P1234",
            name="Synthetic",
            highlighting={7: [bytes(signal)]},
        )
        self.assertEqual(result[0]["diagnostic_field_0c"], 0x123)
        self.assertEqual(result[0]["highlighting"], [{"signal_key": 99, "field_04": 2}])
        json.dumps(result)

    def test_extended_native_reply(self):
        command = spec(extended=True)
        self.assertEqual(len(command.validate(b"\x58" + bytes(300))), 301)
        with self.assertRaises(ToyotaCodecError):
            spec().validate(b"\x58" + bytes(300))

    def test_native_active_patterns(self):
        row, pattern = bytearray(92), bytearray(24)
        row[0x52], row[0x58] = 0x55, 0x20
        struct.pack_into("<H", row, 0x44, 5)
        struct.pack_into("<H", row, 0x4A, 0x6432)
        # Low-nibble first: direct value, shifted value, constant, constant+value.
        self.assertEqual(
            active_request_p3(bytes(row), bytes(pattern), 1, 3)[0],
            bytes.fromhex("6d 55 03 0c 20 23"),
        )
        self.assertEqual(
            active_request_p3(bytes(row), bytes(pattern), 7, 3)[0],
            bytes.fromhex("3d 55"),
        )
        struct.pack_into("<H", row, 0x4A, 0x0A87)
        struct.pack_into("<H", pattern, 8, 4)
        struct.pack_into("<H", pattern, 2, 9)
        pattern[20] = 1
        self.assertEqual(
            active_request_p3(bytes(row), bytes(pattern), 3, 0x1234, auxiliary=0x33),
            (bytes.fromhex("30 55 04 33 12"), 9),
        )

    def test_shared_native_active_builders_and_psa_differences(self):
        row, pattern = bytearray(92), bytearray(24)
        row[0x52] = 0x55
        struct.pack_into("<H", row, 0x4A, 2)
        for builder in (
            active_request_p3,
            active_request_p4,
            active_request_dk,
            active_request_dlc12,
        ):
            # Native support gating starts only after instruction11, not on protocol4 alone.
            self.assertEqual(
                builder(bytes(row), bytes(pattern), 4, 3, support=b"")[0],
                bytes.fromhex("30 55 03"),
            )
        self.assertEqual(
            active_request_psa(bytes(row), bytes(pattern), 1, 3)[0],
            bytes.fromhex("30 55 03"),
        )
        self.assertEqual(
            active_request_psa(
                bytes(row), bytes(pattern), 1, 3, comm_mode=bytes.fromhex("00 00 aa")
            )[0],
            bytes.fromhex("aa 55 03"),
        )
        struct.pack_into("<H", row, 0x4A, 0x2B)
        with self.assertRaises(ToyotaCodecError) as failure:
            active_request_psa(bytes(row), bytes(pattern), 4, 3, support=b"\x00")
        self.assertEqual(failure.exception.code, 0xC0050443)
        self.assertEqual(
            active_request_p3(bytes(row), bytes(pattern), 4, 3, support=b"\x00")[0],
            bytes.fromhex("30 55 06"),
        )

    def test_active_support_patterns(self):
        row, pattern = bytearray(92), bytearray(24)
        row[0x52] = 0x55
        struct.pack_into("<H", row, 0x42, 8)
        struct.pack_into("<H", row, 0x4A, 0x0C2B)
        self.assertEqual(
            active_request_p3(
                bytes(row), bytes(pattern), 4, 3, support=b"\x01\x00\x01"
            ),
            (bytes.fromhex("30 55 06 00 00"), 0),
        )
        with self.assertRaises(SessionError):
            active_request_p3(bytes(row), bytes(pattern), 4, 3)
        with self.assertRaises(ToyotaCodecError):
            active_request_p3(bytes(row), bytes(pattern), 3, 3)
        struct.pack_into("<H", row, 0x4A, 0xD)
        row[0x58] = 0xF0
        self.assertEqual(
            active_request_p3(bytes(row), bytes(pattern), 4, 3, support=b"\xa5")[0],
            bytes.fromhex("30 55 a0"),
        )

    def test_p5_active_native_packing_states_and_exchange(self):
        start, stop = active_requests_p5(
            bytes.fromhex("12 34 03 aa"), bytes.fromhex("12 34 00")
        )
        self.assertEqual(start, bytes.fromhex("2f 12 34 03 aa"))
        self.assertEqual(stop, bytes.fromhex("2f 12 34 00"))
        self.assertEqual(
            active_reply_p5(
                start, bytes.fromhex("6f 12 34"), repeat_ms=5, now_ms=0xFFFFFFFE
            ),
            {"state": 3, "next_tick": 3},
        )
        self.assertEqual(
            active_reply_p5(stop, bytes.fromhex("6f 12 34")),
            {"state": 5, "next_tick": 0},
        )
        self.assertEqual(
            active_reply_p5(stop, bytes.fromhex("6f 12 34"), has_next=True)["state"], 4
        )
        routine, release = active_requests_p5(
            bytes.fromhex("01 12 34"), bytes.fromhex("02 12 34"), routine=True
        )
        self.assertEqual(active_reply_p5(routine, b"\x71")["state"], 4)
        self.assertEqual(active_reply_p5(release, b"\x71")["state"], 5)
        replay = Replay(
            [(start, bytes.fromhex("6f 12 34")), (stop, bytes.fromhex("6f 12 34"))]
        )
        session = ToyotaSession(
            replay,
            "ecu",
            {
                "start": spec(start, check="p5_active"),
                "stop": spec(stop, check="p5_active"),
            },
        )
        session.start_active_test(ActiveTest(("start",), ("stop",)))
        session.stop_active_test()
        self.assertFalse(replay.steps)
        with self.assertRaises(ToyotaCodecError):
            active_reply_p5(start, b"\x6f")

    def test_p5_native_selected_argument_modes(self):
        record = bytearray(0x36)
        struct.pack_into("<H", record, 0x34, 0x1234)
        pattern = bytearray(24)
        struct.pack_into("<H", pattern, 2, 25)
        pattern[20] = 1
        row = bytearray(12)
        struct.pack_into("<HHH", row, 4, 1, 0, 2)
        struct.pack_into("<HH", record, 0x28, 0, 15)
        start, release, repeat = active_arguments_p5(
            bytes(record),
            [bytes(row)],
            bytes.fromhex("2f000003"),
            bytes.fromhex("2f000000"),
            0x4567,
            2,
            bytes(pattern),
        )
        self.assertEqual(
            (start.hex(), release.hex(), repeat), ("2f123403456780", "2f12340080", 25)
        )
        # Mode3 uses raw big-endian value without the output mask.
        row[10] = 3
        self.assertEqual(
            active_arguments_p5(
                bytes(record),
                [bytes(row)],
                bytes.fromhex("2f000003"),
                bytes.fromhex("2f000000"),
                0x4567,
                2,
                bytes(pattern),
            )[:2],
            (bytes.fromhex("2f1234034567"), bytes.fromhex("2f123400")),
        )
        # Mode1 places the selected bit field and repeats the complete data mask.
        row[10] = 1
        struct.pack_into("<HH", record, 0x28, 2, 4)
        self.assertEqual(
            active_arguments_p5(
                bytes(record),
                [bytes(row)],
                bytes.fromhex("2f000003"),
                bytes.fromhex("2f000000"),
                5,
                1,
                bytes(pattern),
            )[:2],
            (bytes.fromhex("2f1234032838"), bytes.fromhex("2f12340038")),
        )
        self.assertEqual(
            active_arguments_p5(
                bytes(record),
                [bytes(row)],
                bytes.fromhex("2f000003"),
                bytes.fromhex("2f000000"),
                0x25,
                1,
                bytes(pattern),
                output_mask=0x70,
            )[0],
            bytes.fromhex("2f1234032570"),
        )
        # Mode4 shifts across bytes and sets every selected output-mask bit.
        row[10] = 4
        struct.pack_into("<HH", record, 0x28, 4, 11)
        self.assertEqual(
            active_arguments_p5(
                bytes(record),
                [bytes(row)],
                bytes.fromhex("2f000003"),
                bytes.fromhex("2f000000"),
                0xAB,
                2,
                bytes(pattern),
            )[:2],
            (bytes.fromhex("2f1234030ab00ff0"), bytes.fromhex("2f1234000ff0")),
        )
        row[10] = 2
        with self.assertRaises(ToyotaCodecError):
            active_arguments_p5(
                bytes(record), [bytes(row)], b"1234", b"1234", 0, 2, bytes(pattern)
            )
        with self.assertRaises(ToyotaCodecError):
            active_arguments_p5(
                bytes(record), [bytes(row)], b"123", b"1234", 0, 2, bytes(pattern)
            )

    def test_p5_selected_routine_argument_masks(self):
        record = bytes(0x1C) + bytes.fromhex("3412")
        start, release = routine_arguments_p5(
            record,
            bytes.fromhex("31010000"),
            bytes.fromhex("31020000"),
            bytes.fromhex("100020"),
            bytes.fromhex("ff00ff"),
            0xABCD,
        )
        # Zero mask positions consume no scalar byte.
        self.assertEqual((start.hex(), release.hex()), ("31011234bb00ed", "31021234"))
        self.assertEqual(
            routine_arguments_p5(
                record,
                bytes.fromhex("31010000"),
                bytes.fromhex("31020000"),
                b"",
                bytes.fromhex("0f00f0"),
                input_bytes=bytes.fromhex("abcd"),
                button_mask=bytes.fromhex("f0000f"),
                buttons=bytes.fromhex("120034"),
            )[0],
            bytes.fromhex("310112341b00c4"),
        )
        # Native transmitted length prefers command, even if a mask is longer.
        self.assertEqual(
            routine_arguments_p5(
                record,
                bytes.fromhex("31010000"),
                bytes.fromhex("31020000"),
                b"\x01",
                bytes.fromhex("ffff"),
                0xABCD,
            )[0],
            bytes.fromhex("31011234ab"),
        )
        with self.assertRaises(ToyotaCodecError):
            routine_arguments_p5(
                record, b"1234", b"1234", b"", b"\xff\xff", input_bytes=b"\x01"
            )

    def test_p5_native_queue_repeat_dedup_and_release(self):
        queue = P5ActiveQueue()
        queue.enqueue(b"\x12\x34\x03", b"\x12\x34\x00", repeat_ms=10)
        queue.enqueue(b"\x12\x34\x03\x55", b"\x12\x34\x00", repeat_ms=10)
        self.assertEqual(len(queue.releases), 1)
        with self.assertRaises(ToyotaCodecError):
            queue.enqueue(b"\x56\x78\x03", b"\x56\x78\x00")
        self.assertEqual(len(queue.items), 2)  # host atomic preflight
        self.assertEqual(queue.next_request(0), bytes.fromhex("2f123403"))
        queue.accept(bytes.fromhex("6f1234"), 0)
        # ProcNext removes a completed first item, even if it requested repeat.
        self.assertEqual(queue.next_request(1), bytes.fromhex("2f12340355"))
        queue.accept(bytes.fromhex("6f1234"), 1)
        self.assertIsNone(queue.next_request(10))
        self.assertIsNone(queue.next_request(11))  # due -> state0, no I/O yet
        self.assertEqual(queue.next_request(11), bytes.fromhex("2f12340355"))
        queue.accept(bytes.fromhex("6f1234"), 0xFFFFFFFE)
        self.assertEqual(queue.items[0].next_tick, 8)
        # Preserve the native unsigned >= comparison at clock wrap.
        self.assertIsNone(queue.next_request(0xFFFFFFFF))
        self.assertEqual(queue.next_request(0xFFFFFFFF), bytes.fromhex("2f12340355"))
        queue.stop()
        self.assertEqual(queue.next_request(0), bytes.fromhex("2f123400"))
        queue.accept(bytes.fromhex("6f1234"), 0)
        self.assertTrue(queue.finished)
        json.dumps(queue.report())

    def test_p5_native_queue_routine_and_multiple_releases(self):
        queue = P5ActiveQueue()
        queue.enqueue(bytes.fromhex("011234"), bytes.fromhex("021234"), routine=True)
        queue.enqueue(bytes.fromhex("015678"), bytes.fromhex("025678"), routine=True)
        self.assertEqual(queue.next_request(0), bytes.fromhex("31011234"))
        with self.assertRaises(ToyotaCodecError):
            queue.accept(b"\x70", 0)
        queue.accept(b"\x71", 0)
        self.assertEqual(queue.next_request(0), bytes.fromhex("31015678"))
        queue.accept(b"\x71", 0)
        queue.stop()
        self.assertEqual(queue.next_request(0), bytes.fromhex("31021234"))
        queue.accept(b"\x71", 0)
        self.assertEqual(queue.next_request(0), bytes.fromhex("31025678"))
        queue.accept(b"\x71", 0)
        self.assertTrue(queue.finished)
        with self.assertRaises(SessionError):
            queue.enqueue(
                bytes.fromhex("011234"), bytes.fromhex("021234"), routine=True
            )

    def test_p5_session_release_preserves_observed_dual_tick(self):
        queue = P5ActiveQueue(dual=True)
        queue.enqueue(bytes.fromhex("123403"), bytes.fromhex("123400"))
        replay = Replay(
            [
                (bytes.fromhex("2f123403"), bytes.fromhex("6f1234")),
                (bytes.fromhex("2f123400"), bytes.fromhex("6f1234")),
            ]
        )
        session = ToyotaSession(replay, "ecu", {})
        session.start_p5_active(queue, 100)
        self.assertEqual(queue.last_comm_time, 100)
        session.stop_active_test(now_ms=200)
        self.assertEqual(queue.last_comm_time, 200)
        with self.assertRaises(ValueError):
            session.stop_active_test(now_ms=-1)

    def test_p5_dual_queue_records_only_valid_reply_time(self):
        for dual in (False, True):
            queue = P5ActiveQueue(dual=dual)
            queue.enqueue(bytes.fromhex("123403"), bytes.fromhex("123400"))
            queue.next_request(0)
            for reply in (b"", b"\x6f", b"\x71\x12\x34"):
                with self.assertRaises(ToyotaCodecError):
                    queue.accept(reply, 7)
                self.assertEqual(queue.last_comm_time, 0)
            queue.accept(bytes.fromhex("6f1234"), 0xFFFFFFFF)
            self.assertEqual(queue.last_comm_time, 0xFFFFFFFF if dual else 0)
            queue.stop()
            queue.next_request(0)
            queue.accept(bytes.fromhex("6f1234"), 2)
            self.assertEqual(queue.last_comm_time, 2 if dual else 0)
        # Unrecognized native control still records a valid reply, state1.
        queue = P5ActiveQueue(dual=True)
        queue.enqueue(bytes.fromhex("091234"), bytes.fromhex("021234"), routine=True)
        queue.next_request(0)
        queue.accept(b"\x71", 9)
        self.assertEqual((queue.items[0].state, queue.last_comm_time), (1, 9))
        json.dumps(queue.report())

    def test_p5_queue_session_cancel_and_failed_release_retry(self):
        queue = P5ActiveQueue()
        queue.enqueue(bytes.fromhex("123403"), bytes.fromhex("123400"), repeat_ms=10)
        replay = Replay(
            [
                (bytes.fromhex("2f123403"), bytes.fromhex("6f1234")),
                (bytes.fromhex("2f123400"), NativeStatus(77)),
                (bytes.fromhex("2f123400"), bytes.fromhex("6f1234")),
            ]
        )
        flag = [False]
        session = ToyotaSession(replay, "ecu", {}, cancelled=lambda: flag[0])
        session.start_p5_active(queue)
        flag[0] = True
        with self.assertRaises(BaseExceptionGroup) as caught:
            session.p5_active_step(1)
        self.assertIsInstance(caught.exception.exceptions[0], Cancelled)
        self.assertEqual(session.active_state, "stop_failed")
        self.assertEqual(session.stop_active_test(), [bytes.fromhex("6f1234")])
        self.assertEqual(session.active_state, "stopped")
        self.assertIsNone(session.active)
        self.assertFalse(replay.steps)

    def test_native_single_routine(self):
        self.assertEqual(
            routine_request_p5(bytes.fromhex("31 01 00 00"), 0x1234, b"\xaa"),
            bytes.fromhex("31 01 12 34 aa"),
        )
        self.assertTrue(
            routine_status_p5(bytes.fromhex("71 03 12 34 00 01"), 2, [b"\x01"])
        )
        with self.assertRaises(ToyotaCodecError):
            routine_status_p5(bytes.fromhex("71 03 12 34 00 02"), 2, [b"\x01"])
        replay = Replay(
            [
                (bytes.fromhex("31 01 12 34 aa"), bytes.fromhex("71 01 12 34")),
                (bytes.fromhex("31 03 12 34"), bytes.fromhex("71 03 12 34 01")),
                (bytes.fromhex("31 02 12 34"), bytes.fromhex("71 02 12 34")),
            ]
        )
        commands = {
            "start": spec(bytes.fromhex("31 01 00 00")),
            "status": spec(bytes.fromhex("31 03 00 00")),
            "stop": spec(bytes.fromhex("31 02 00 00")),
        }
        session = ToyotaSession(replay, "ecu", commands)
        waits = []
        self.assertEqual(
            len(
                session.single_routine(
                    "start",
                    "status",
                    "stop",
                    0x1234,
                    b"\xaa",
                    1,
                    [b"\x01"],
                    wait=waits.append,
                )
            ),
            3,
        )
        self.assertEqual(waits, [0.2, 5.0])
        self.assertEqual(session.commands, commands)
        self.assertFalse(replay.steps)

    def test_routine_native_rejection_still_releases(self):
        replay = Replay(
            [
                (
                    bytes.fromhex("31 01 12 34"),
                    NativeStatus(0x90020321, bytes.fromhex("7f 31 22")),
                ),
                (bytes.fromhex("31 02 12 34"), bytes.fromhex("71 02 12 34")),
            ]
        )
        session = ToyotaSession(
            replay,
            "ecu",
            {
                "start": spec(bytes.fromhex("31 01 00 00")),
                "status": spec(bytes.fromhex("31 03 00 00")),
                "stop": spec(bytes.fromhex("31 02 00 00")),
            },
        )
        with self.assertRaises(ToyotaCodecError) as failure:
            session.single_routine(
                "start",
                "status",
                "stop",
                0x1234,
                b"",
                1,
                [b"\x01"],
                wait=lambda seconds: None,
            )
        self.assertEqual(failure.exception.code, 0xA0040207)
        self.assertEqual(session.active_state, "stopped")
        self.assertFalse(replay.steps)

    def test_active_test_start_status_stop(self):
        replay = Replay(
            [(b"\x10", b"\x50"), (b"\x11", b"\x51\x01"), (b"\x12", b"\x52")]
        )
        session = ToyotaSession(
            replay,
            "ecu",
            {"start": spec(b"\x10"), "status": spec(b"\x11"), "stop": spec(b"\x12")},
        )
        test = ActiveTest(
            ("start",), ("stop",), ("status",), lambda replies: replies == [b"\x51\x01"]
        )
        session.start_active_test(test)
        self.assertEqual(session.active_state, "running")
        with self.assertRaises(SessionError):
            session.start_active_test(test)
        session.active_test_status()
        self.assertIsNone(session.active)
        self.assertEqual(session.active_state, "stopped")
        self.assertEqual(replay.steps, [])

    def test_completed_status_failed_stop_does_not_repeat_implicitly(self):
        replay = Replay(
            [(b"\x10", b"\x50"), (b"\x11", b"\x51"), (b"\x12", TimeoutError())]
        )
        session = ToyotaSession(
            replay,
            "ecu",
            {"start": spec(b"\x10"), "status": spec(b"\x11"), "stop": spec(b"\x12")},
        )
        session.start_active_test(
            ActiveTest(("start",), ("stop",), ("status",), lambda replies: True)
        )
        with self.assertRaises(TimeoutError):
            session.active_test_status()
        self.assertEqual(session.active_state, "stop_failed")
        self.assertEqual(len(replay.calls), 3)

    def test_active_start_failure_still_stops(self):
        replay = Replay(
            [(b"\x10", TimeoutError("lost start reply")), (b"\x12", b"\x52")]
        )
        session = ToyotaSession(
            replay, "ecu", {"start": spec(b"\x10"), "stop": spec(b"\x12")}
        )
        with self.assertRaises(TimeoutError):
            session.start_active_test(ActiveTest(("start",), ("stop",)))
        self.assertIsNone(session.active)
        self.assertEqual(replay.steps, [])

    def test_active_cancellation_stops_and_failed_stop_is_retryable(self):
        flag = [False]
        replay = Replay(
            [(b"\x10", b"\x50"), (b"\x12", TimeoutError()), (b"\x12", b"\x52")]
        )
        session = ToyotaSession(
            replay,
            "ecu",
            {"start": spec(b"\x10"), "status": spec(b"\x11"), "stop": spec(b"\x12")},
            cancelled=lambda: flag[0],
        )
        session.start_active_test(ActiveTest(("start",), ("stop",), ("status",)))
        flag[0] = True
        with self.assertRaises(BaseExceptionGroup) as failure:
            session.active_test_status()
        self.assertIsInstance(failure.exception.exceptions[0], Cancelled)
        self.assertIsInstance(failure.exception.exceptions[1], TimeoutError)
        self.assertEqual(session.active_state, "stop_failed")
        self.assertIsNotNone(session.active)
        session.stop_active_test()
        self.assertIsNone(session.active)
        self.assertEqual(replay.steps, [])


if __name__ == "__main__":
    unittest.main()
