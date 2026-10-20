"""Authored input/result contracts; no OEM DLL, vehicle or adapter execution."""

import hashlib
import json
import os
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from scripts.active_replay import ActiveReplay, create_active_examples
from scripts.active_tests import ActiveSupport, ActiveTestInitialization
from scripts.command_api import (
    DDR_EXTENSION_ARRAY_OFFSETS,
    DDR_EXTENSION_FLAG_OFFSETS,
    DDR_EXTENSION_NESTED_OFFSETS,
    SAVED_OPERATION_WORD_OFFSETS,
    SOURCE_SHA256,
    ActiveFacadeEntry,
    ActiveFacadeGroup,
    ActiveFacadeResult,
    CommandAPI,
    CommandSource,
    CommandStatus,
    DcmFacadeResult,
    DcmFlatFacadeRecord,
    DdrExtensionValues,
    EcuGroupContext,
    EcuGroupEntry,
    EcuGroupResult,
    RoBFacadeResult,
    RoBFacadeValue,
    SavedOperationFacadeFreeze,
    SavedOperationFacadeMetadata,
    SavedOperationFacadeResult,
    SavedOperationFacadeValue,
    TranslationFacadeEntry,
    TranslationFacadeResult,
    VimInformation,
    VinReply,
    VinResult,
)
from scripts.demo import _ddb, _language
from scripts.monitor_support import MonitorSupportCache
from scripts.native_communication import NativeFrameController
from scripts.profiles import VehicleCatalog, VehicleProfile
from scripts.toyota import CommandFrame, ToyotaCodecError
from scripts.toyota_analysis import DcmP5Analysis
from scripts.toyota_session import Cancelled, CommandSpec, NativeStatus, ToyotaSession


class CommandAPITests(unittest.TestCase):
    def api(self, version=18, **kwargs):
        return CommandAPI(CommandSource(version, SOURCE_SHA256[version]), **kwargs)

    def test_exact_source_guards_and_no_cross_version_fallback(self):
        for version, digest in (
            (18, SOURCE_SHA256[12]),
            (12, SOURCE_SHA256[18]),
            (2026, "a" * 64),
            (True, SOURCE_SHA256[18]),
        ):
            with self.subTest(version=version), self.assertRaises(ValueError):
                CommandSource(version, digest)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authored.dll"
            path.write_bytes(b"not an OEM image")
            with self.assertRaises(ValueError):
                CommandSource.from_file(path, version=18)
            # Only the source guard is patched; actual bytes are hashed.
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch.dict(SOURCE_SHA256, {18: digest}):
                self.assertEqual(
                    CommandSource.from_file(path, version=18), CommandSource(18, digest)
                )
        with self.assertRaises(NotImplementedError):
            self.api(12).compose_vim_support(CommandStatus(), 1)

    def test_source_guard_rejects_fifo_without_opening_a_device(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-an-image"
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, "regular file"):
                CommandSource.from_file(path, version=18)

    def test_source_identity_rejects_subclass_private_fields(self):
        from dataclasses import dataclass

        @dataclass(frozen=True)
        class ExtraSource(CommandSource):
            private_path: str = "/sensitive/log"

        with self.assertRaises(TypeError):
            CommandAPI(ExtraSource(18, SOURCE_SHA256[18]))
        for changed in (
            ExtraSource(18, SOURCE_SHA256[18]),
            CommandSource(12, SOURCE_SHA256[12]),
        ):
            api = self.api()
            api.source = changed
            with self.assertRaisesRegex(ValueError, "source context changed"):
                api.compose_vin(VinReply(CommandStatus(), 0, b""))

    def test_vin_positive_both_reconciled_versions_and_owned_result(self):
        for version in (12, 18):
            with self.subTest(version=version):
                self.assertEqual(
                    self.api(version).compose_vin(
                        VinReply(CommandStatus(), 7, b"abCD09\0ignored")
                    ),
                    VinResult(0, b"abCD09"),
                )
                self.assertEqual(
                    self.api(version).compose_vin(
                        VinReply(CommandStatus(), 4, b"ABCextra")
                    ),
                    VinResult(0, b"ABCextra"),
                )
                self.assertEqual(
                    self.api(version).compose_vin(
                        VinReply(CommandStatus(), 4, b"ABC-!\0tail")
                    ),
                    VinResult(0, b"ABC-!"),
                )
                first = self.api(version).compose_vin(
                    VinReply(CommandStatus(), 4, b"ABC")
                )
                self.api(version).compose_vin(VinReply(CommandStatus(), 4, b"XYZ"))
                self.assertEqual(first.value, b"ABC")

    def test_vin_native_invalid_success_and_short_empty(self):
        api = self.api()
        for payload in (b"A-B", b"A B", b"A_B", b"A\xffB"):
            self.assertEqual(
                api.compose_vin(VinReply(CommandStatus(), 4, payload), previous=b"OLD"),
                VinResult(0, b""),
            )
        for length in (0, 1):
            self.assertEqual(
                api.compose_vin(VinReply(CommandStatus(), length, b"ignored")),
                VinResult(0, b""),
            )

    def test_native_status_uses_detail_and_preserves_previous(self):
        result = self.api().compose_vin(
            VinReply(CommandStatus(9, 0x90020323), 65535, b""), previous=b"OLD"
        )
        self.assertEqual(result, VinResult(0x90020323, b"OLD"))
        self.assertEqual(
            self.api().compose_vin(
                VinReply(CommandStatus(9, 0), 0, b""), previous=b"OLD"
            ),
            VinResult(0, b"OLD"),
        )
        self.assertEqual(CommandStatus(0, 42).return_code, 0)

    def test_malformed_native_pointer_extent_is_host_failure(self):
        for length, payload in ((4, b"A"), (65535, b"")):
            with self.assertRaises(ValueError):
                VinReply(CommandStatus(), length, payload)
        with self.assertRaisesRegex(ValueError, "terminator"):
            self.api().compose_vin(VinReply(CommandStatus(), 4, b"A\0B"))
        for value in (-1, 65536, True):
            with self.assertRaises(ValueError):
                VinReply(CommandStatus(), value, b"")

    def test_vim_support_low_byte_and_error_retention(self):
        self.assertEqual(
            self.api().compose_vim_support(CommandStatus(), 0x1234).support, 0x34
        )
        result = self.api().compose_vim_support(CommandStatus(2, 501), 0, previous=0xA5)
        self.assertEqual((result.return_code, result.support), (501, 0xA5))
        with self.assertRaises(ValueError):
            self.api().compose_vim_support(CommandStatus(), -1)

    def test_vim_information_typed_fields_and_error_lifetime(self):
        old, new = VimInformation(1, 2, 3, 4, 5, 6), VimInformation(6, 5, 4, 3, 2, 1)
        self.assertEqual(
            self.api()
            .compose_vim_information(CommandStatus(), new, previous=old)
            .information,
            new,
        )
        result = self.api().compose_vim_information(
            CommandStatus(1, 123), new, previous=old
        )
        self.assertEqual((result.return_code, result.information), (123, old))
        self.assertEqual(
            self.api(12)
            .compose_vim_information(CommandStatus(), new, previous=old)
            .information,
            new,
        )
        self.assertEqual(
            self.api(12).compose_vim_information(
                CommandStatus(1, 123), new, previous=old
            ),
            result,
        )
        with self.assertRaises(ValueError):
            VimInformation(field0c=65536)

    def test_actual_active_list_reserved_boundaries_and_independent_group_membership(
        self,
    ):
        ids = (7999, 8000, 9999, 10000, 39999, 40000, 41999, 42000)
        rows = tuple(
            ActiveFacadeEntry(i, b"name\0discard", b"short", 0x12345678) for i in ids
        )
        groups = (
            ActiveFacadeGroup(b"group", ids + (5,)),
            ActiveFacadeGroup(b"empty", (8000,)),
        )
        result = self.api().compose_active_list(
            CommandStatus(), (None,) + rows, groups, b"description", mode=0
        )
        self.assertEqual(
            tuple(x.signal_id for x in result.entries), (7999, 10000, 39999, 42000)
        )
        self.assertEqual(result.entries[0].name, b"name")
        self.assertEqual(result.entries[0].control_value, 0x12345678)
        self.assertEqual(result.groups[0].signal_ids, (7999, 10000, 39999, 42000, 5))
        self.assertEqual(result.groups[1].signal_ids, ())
        all_ids = self.api().compose_active_list(
            CommandStatus(), rows, groups, b"description", mode=1
        )
        self.assertEqual(tuple(x.signal_id for x in all_ids.entries), ids)
        self.assertEqual(all_ids.groups[0].signal_ids, ids + (5,))
        error = self.api().compose_active_list(
            CommandStatus(1, 501), (), (), b"", mode=0, previous=result
        )
        self.assertEqual(
            error,
            ActiveFacadeResult(501, result.entries, result.groups, b"description"),
        )
        result12 = self.api(12).compose_active_list(
            CommandStatus(), rows, groups, b"description", mode=0
        )
        self.assertEqual(result12, result)

    def test_actual_translation_appends_and_preserves_attributes_duplicates_and_faults(
        self,
    ):
        previous = TranslationFacadeResult(0, (TranslationFacadeEntry(b"old", 7),))
        entries = (
            TranslationFacadeEntry(b"same\0tail", 65535),
            TranslationFacadeEntry(b"same", 1),
        )
        result = self.api().compose_translation(
            CommandStatus(), entries, previous=previous
        )
        self.assertEqual(
            result.entries,
            previous.entries
            + (
                TranslationFacadeEntry(b"same", 65535),
                TranslationFacadeEntry(b"same", 1),
            ),
        )
        self.assertEqual(
            self.api().compose_translation(CommandStatus(), (), previous=result), result
        )
        error = self.api().compose_translation(
            CommandStatus(1, 123), (), previous=result
        )
        self.assertEqual(error.return_code, 123)
        self.assertEqual(error.entries, result.entries)
        self.assertEqual(previous.entries, (TranslationFacadeEntry(b"old", 7),))
        self.assertEqual(
            self.api(12).compose_translation(
                CommandStatus(), entries, previous=previous
            ),
            result,
        )

    def test_actual_ecu_group_identifier_and_name_append_preserves_duplicates(self):
        previous = EcuGroupResult(0, (EcuGroupEntry(3, b"old"),))
        entries = (EcuGroupEntry(9, b"first\0ignored"), EcuGroupEntry(9, b"second"))
        result = self.api().compose_ecu_groups(
            CommandStatus(), entries, previous=previous
        )
        self.assertEqual(
            result.entries,
            previous.entries
            + (EcuGroupEntry(9, b"first"), EcuGroupEntry(9, b"second")),
        )
        self.assertEqual(
            self.api().compose_ecu_groups(CommandStatus(1, 123), (), previous=result),
            EcuGroupResult(123, result.entries),
        )
        self.assertEqual(
            self.api().compose_ecu_groups(CommandStatus(), (), previous=result), result
        )

    def test_actual_ddr_extension_array_append_byte_replace_and_nested_lifetime(self):
        old = DdrExtensionValues((b"old",) * 10, b"x" * 21, ((b"A",), (b"B",)))
        new = DdrExtensionValues(
            tuple(bytes([i]) for i in range(10)),
            bytes(range(21)),
            ((b"C", b""), (b"D",)),
        )
        result = self.api().compose_ddr_extension(new, previous=old)
        self.assertEqual(result.arrays, tuple(b"old" + bytes([i]) for i in range(10)))
        self.assertEqual(result.flags, bytes(range(21)))
        self.assertEqual(result.nested, ((b"A", b"C", b""), (b"B", b"D")))
        self.assertEqual(old.nested, ((b"A",), (b"B",)))
        self.assertEqual(
            DDR_EXTENSION_ARRAY_OFFSETS,
            (0x374, 0x388, 0x39C, 0x3B0, 0x44C, 0x460, 0x3D4, 0x3E8, 0x3FC, 0x410),
        )
        self.assertEqual(DDR_EXTENSION_NESTED_OFFSETS, (0x424, 0x438))
        self.assertEqual(
            DDR_EXTENSION_FLAG_OFFSETS,
            tuple(range(0x3C4, 0x3D2)) + tuple(range(0x474, 0x47B)),
        )
        with self.assertRaises(NotImplementedError):
            self.api(12).compose_ddr_extension(new)
        with self.assertRaises(TypeError):
            DdrExtensionValues((b"",) * 9, bytes(21), ((), ()))

    def test_actual_selected_group_queries_default_shared_write_and_partial_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def row(name, key, identifier, kind):
                return struct.pack("<IHHHBB", name, key, identifier, 0, 0, kind)

            rows = (
                row(1, 31, 3, 1)
                + row(2, 31, 6, 1)
                + row(3, 31, 9, 2)
                + row(4, 31, 60, 1)
                + row(4, 42, 12, 1)
            )
            (root / "Toyota.ddb").write_bytes(_ddb(1, {0: (0, b""), 5: (5, rows)}))
            (root / "M_English.ddb").write_bytes(
                _language(["First", "Second", "Default", "Other"])
            )
            catalog = VehicleCatalog(root)
            state = EcuGroupContext(31, 99)
            result = self.api().selected_ecu_groups(catalog, state)
            self.assertEqual(result.return_code, 0)
            self.assertEqual(
                [(x.identifier, x.name_id, x.name) for x in result.entries],
                [(3, 1, "First"), (6, 2, "Second")],
            )
            self.assertEqual(result.context.default_group, 9)
            self.assertEqual(state.default_group, 99)
            self.assertEqual(result.entries[0].source_row, rows[:12])
            missing_default = self.api().selected_ecu_groups(
                catalog, EcuGroupContext(42, 99)
            )
            self.assertEqual(missing_default.return_code, 0xC0040101)
            self.assertEqual([x.identifier for x in missing_default.entries], [12])
            self.assertEqual(missing_default.context.default_group, 99)
            for context, status, count in (
                (EcuGroupContext(77, 99), 0xC0040101, 0),
                (EcuGroupContext(None, 99), 0xC0040601, 0),
                (EcuGroupContext(31, None), 0xC0040601, 2),
                (EcuGroupContext(31, 99, vehicle_lookup_status=123), 123, 0),
                (EcuGroupContext(31, 99, default_lookup_status=124), 124, 2),
            ):
                actual = self.api().selected_ecu_groups(catalog, context)
                self.assertEqual(
                    (actual.return_code, len(actual.entries)), (status, count)
                )
                self.assertEqual(actual.context, context)
            for filename in ("Toyota.ddb", "M_English.ddb"):
                path = root / filename
                raw = bytearray(path.read_bytes())
                struct.pack_into("<I", raw, 28, 0x0100030C)
                path.write_bytes(raw)
            result12 = self.api(12).selected_ecu_groups(VehicleCatalog(root), state)
            self.assertEqual(result12.entries, result.entries)
            self.assertEqual(result12.context.default_group, 9)

    def test_cancellation_close_and_no_silent_success(self):
        api = self.api(cancelled=lambda: True)
        with self.assertRaises(Cancelled):
            api.compose_vin(VinReply(CommandStatus(), 4, b"ABC"))
        api = self.api()
        api.close()
        api.close()
        with self.assertRaises(ValueError):
            api.compose_vim_support(CommandStatus(), 1)
        with self.assertRaises(TypeError):
            self.api().selected_can_vin(cast(Any, object()), "count", "data")

    def session(self, steps):
        calls = []

        def exchange(ecu, request):
            calls.append((ecu, request))
            expected, reply = steps.pop(0)
            self.assertEqual(request, expected)
            if isinstance(reply, Exception):
                raise reply
            return reply

        session = ToyotaSession(
            exchange,
            "authored-ecu",
            {
                "count": CommandSpec(CommandFrame(b"\x18")),
                "data": CommandSpec(CommandFrame(b"\x22")),
            },
        )
        return session, calls

    def test_concrete_toyota_multi_receive_to_typed_consumer(self):
        steps = [
            (b"\x18", b"\x58\0\x02"),
            (b"\x22", b"\x62\0\0\0A"),
            (b"", b"\x62\0\0BC"),
        ]
        session, calls = self.session(steps)
        result = self.api().selected_can_vin(session, "count", "data")
        self.assertEqual(result, VinResult(0, b"ABC"))
        self.assertEqual([item[1] for item in calls], [b"\x18", b"\x22", b""])
        self.assertEqual(steps, [])

    def test_concrete_toyota_fault_preserved_and_cancel_before_io(self):
        session, _calls = self.session([(b"\x18", NativeStatus(0x90020323))])
        with self.assertRaises(ToyotaCodecError) as caught:
            self.api().selected_can_vin(session, "count", "data")
        self.assertEqual(caught.exception.code, 0x90020323)
        session, calls = self.session([])
        with self.assertRaises(Cancelled):
            self.api(cancelled=lambda: True).selected_can_vin(session, "count", "data")
        self.assertEqual(calls, [])

    def vin_connection(
        self,
        module,
        replies,
        *,
        version=18,
        malformed_ascii=False,
        request=b"\x22\x01",
        command=0x51,
        functions=(0x86, 0x8B, 0xEA),
        diagnostic=None,
        language=None,
        flags=1,
        category_id=None,
    ):
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import NativeCommunication
        from tests.test_native_communication import (
            DRIVER,
            J2534Fixture,
            serialized_profile,
        )

        profile = serialized_profile(
            version=version, request=request, mask=b"", check=b"", flags=flags
        )
        sections = {
            slot: (section.count, section.payload)
            for slot, section in profile.catalog.management.sections.items()
        }
        if category_id is not None:
            category = bytearray(profile.category_record)
            struct.pack_into("<H", category, 68, category_id)
            profile = replace(profile, category_record=bytes(category))
            sections[16] = (1, bytes(category))
            count, protocols = sections[13]
            protocols = bytearray(protocols)
            struct.pack_into("<H", protocols, 0, category_id)
            sections[13] = (count, bytes(protocols))
            count, initial_functions = sections[18]
            initial_functions = bytearray(initial_functions)
            for offset in range(0, len(initial_functions), 16):
                struct.pack_into("<H", initial_functions, offset, category_id)
            sections[18] = (count, bytes(initial_functions))
        row = bytearray(88)
        filename = (
            module
            if malformed_ascii
            else (module.decode("ascii") + "\0").encode("utf-16le")
        )
        row[: len(filename)] = filename
        struct.pack_into("<H", row, 80, profile.category)
        row[86] = command
        sections[19] = (1, bytes(row))
        count, function_bytes = sections[18]
        sections[18] = (
            count + len(functions),
            function_bytes
            + b"".join(
                struct.pack("<8H", profile.category, function, 1, 0, 0, 1, 0, 0)
                for function in functions
            ),
        )
        row_count, function_rows = sections[18]
        sections[18] = (
            row_count,
            b"".join(
                sorted(
                    (
                        function_rows[i : i + 16]
                        for i in range(0, len(function_rows), 16)
                    ),
                    key=lambda value: struct.unpack_from("<H", value, 2)[0],
                )
            ),
        )
        serialized = bytearray(_ddb(1, sections))
        struct.pack_into("<I", serialized, 28, profile.catalog.management.version)
        profile.catalog.management = parse_database(bytes(serialized))
        if diagnostic is not None:
            profile = replace(profile, database=diagnostic)
        if language is not None:
            profile.catalog.language = language
        backend = J2534Fixture(
            [
                J2534Result(
                    count=1,
                    messages=(NativeMessage(6, 0, 0, 0, 0, b"\0\0\x07\xe8" + reply),),
                )
                for reply in replies
            ]
            + [J2534Result(code=0x10)]
        )
        connection = NativeCommunication.from_backend(
            profile,
            backend,
            "native-vin",
            first_request=request,
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=version,
            clock=lambda: 0.0,
        )
        connection.no_init = True
        self.addCleanup(connection.disconnect)
        return connection, backend

    def test_selected_vin_native_command51_counted_route_and_actual_wire(self):
        connection, backend = self.vin_connection(
            b"GetVIN_DT.dll",
            [b"\x62\x01\x02", b"\x62\x01\0\0A", b"\x62\x01\0BC", b"\x62\x01\0IGNORED"],
        )
        self.assertEqual(self.api().get_vin(connection), VinResult(0, b"ABC"))
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 2)
        self.assertEqual(sum(op == "read_messages" for op, _ in backend.calls), 5)
        self.assertFalse(connection.closed)

    def test_selected_vin_can_first_reply_and_count_error_retains_previous(self):
        connection, backend = self.vin_connection(
            b"GetVIN_CAN_DT.dll", [b"\x62\x01\0ABC", b"\x62\x01\0IGNORED"]
        )
        self.assertEqual(self.api().get_vin(connection), VinResult(0, b"ABC"))
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 1)
        connection, _ = self.vin_connection(
            b"GetVIN_DT.dll", [b"\x62\x01\x03", b"\x62\x01\0A", b"\x62\x01\0BC"]
        )
        self.assertEqual(
            self.api().get_vin(connection, previous=b"OLD"),
            VinResult(0xA0040201, b"OLD"),
        )
        connection, backend = self.vin_connection(b"GetVIN_DT.dll", [b"\x62\x01\0"])
        self.assertEqual(
            self.api().get_vin(connection, previous=b"OLD"), VinResult(0, b"")
        )
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 1)

    def test_selected_vin_unknown_source_cancel_and_malformed_reply(self):
        connection, backend = self.vin_connection(b"UnknownVIN.dll", [])
        with self.assertRaises(NotImplementedError):
            self.api().get_vin(connection)
        self.assertEqual(backend.calls, [])
        connection, backend = self.vin_connection(b"GetVIN_DT.dll", [b"\x62\x01"])
        with self.assertRaises(Cancelled):
            self.api(cancelled=lambda: True).get_vin(connection)
        self.assertEqual(backend.calls, [])
        self.assertEqual(
            self.api().get_vin(connection, previous=b"OLD"),
            VinResult(0xA0040202, b"OLD"),
        )
        with self.assertRaises(ValueError):
            self.api(12).get_vin(connection)

    def test_selected_vin_independent12_provider_routes_on_actual_lower(self):
        for module, replies, expected in (
            (
                b"GetVIN_DT.dll",
                [b"\x62\x01\x02", b"\x62\x01\0A", b"\x62\x01\0BC"],
                b"ABC",
            ),
            (b"GetVIN_CAN_DT.dll", [b"\x62\x01\0ABC", b"\x62\x01\0IGNORED"], b"ABC"),
        ):
            with self.subTest(module=module):
                channel, backend = self.vin_connection(module, replies, version=12)
                self.assertEqual(self.api(12).get_vin(channel), VinResult(0, expected))
                self.assertFalse(channel.closed)
                self.assertTrue(any(op == "read_messages" for op, _ in backend.calls))

    def test_selected_vin_psa_distinct_prefix_zero_gate_and_short_error(self):
        for version in (12, 18):
            for reply, expected in (
                (b"\x62\x01ABC", VinResult(0, b"ABC")),
                (b"\x62\x01\0ABC", VinResult(0, b"")),
                (b"\x62\x01", VinResult(0xA0040202, b"OLD")),
            ):
                with self.subTest(version=version, reply=reply):
                    channel, backend = self.vin_connection(
                        b"GetVinPSA_DT.dll", [reply], version=version
                    )
                    self.assertEqual(
                        self.api(version).get_vin(channel, previous=b"OLD"), expected
                    )
                    self.assertEqual(
                        sum(op == "write_messages" for op, _ in backend.calls), 1
                    )
                    self.assertEqual(
                        sum(op == "read_messages" for op, _ in backend.calls), 1
                    )

    def test_selected_vin_rejects_ascii_module_and_native_scratch_overflow(self):
        channel, backend = self.vin_connection(
            b"GetVIN_DT.dll", [], malformed_ascii=True
        )
        with self.assertRaises(NotImplementedError):
            self.api().get_vin(channel)
        self.assertEqual(backend.calls, [])
        channel, _ = self.vin_connection(
            b"GetVIN_DT.dll",
            [b"\x62\x01\x02", b"\x62\x01\0" + b"A" * 128, b"\x62\x01\0" + b"B" * 128],
        )
        with self.assertRaisesRegex(ValueError, "scratch area"):
            self.api().get_vin(channel)

    def test_management_only_protocol_context_rejects_toyota_facade_before_io(self):
        from scripts.native_communication import NativeCommunication
        from scripts.profiles import ProtocolProfile
        from tests.test_native_communication import (
            DRIVER,
            J2534Fixture,
            serialized_profile,
        )

        for build in (12, 18):
            full = serialized_profile(version=build)
            profile = ProtocolProfile(full.catalog, full.category_record)
            backend = J2534Fixture([])
            connection = NativeCommunication.from_backend(
                profile,
                backend,
                "management-only",
                first_request=b"",
                device_kind=8,
                driver=DRIVER,
                bus_id=0x12,
                source_build=build,
            )
            self.addCleanup(connection.disconnect)
            before = len(backend.calls)
            with self.assertRaisesRegex(TypeError, "selected Toyota database profile"):
                self.api(build).get_vin(connection)
            self.assertEqual(len(backend.calls), before)

    def test_concrete_work_factor_provider_to_typed_consumer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            category = bytearray(76)
            category[:18] = "demo.ddb\0".encode("utf-16le")
            struct.pack_into("<H", category, 68, 42)
            module = bytearray(88)
            name = "GetAnlWkFctDcm35_DT.dll\0".encode("utf-16le")
            module[: len(name)] = name
            struct.pack_into("<H", module, 80, 42)
            module[86] = 0xD7
            settings = bytearray(16)
            struct.pack_into("<H", settings, 10, 1)
            management = {
                0: (1, struct.pack("<IH", 0, 3) + b"\x22\0\0"),
                16: (1, bytes(category)),
                17: (1, struct.pack("<4H", 2, 1, 0, 0)),
                18: (1, struct.pack("<8H", 42, 0xCA, 1, 2, 0, 1, 0, 0)),
                19: (1, bytes(module)),
                29: (1, bytes(settings)),
            }
            (root / "Toyota.ddb").write_bytes(_ddb(1, management))
            (root / "M_English.ddb").write_bytes(
                _language(["Function", "Content", "Signal"])
            )
            signal = bytearray(24)
            struct.pack_into("<I", signal, 12, 3)
            struct.pack_into("<HH", signal, 16, 0x201, 7)
            operation = struct.pack("<II4H", 1, 2, 0x201, 1, 0, 0)
            (root / "demo.ddb").write_bytes(
                _ddb(
                    2,
                    {
                        114: (1, bytes(signal)),
                        116: (1, operation),
                        117: (0, b""),
                        37: (0, b""),
                    },
                )
            )
            profile = VehicleCatalog(root).build_profile(42)
            record = b"\0\x01" + bytes(10)
            payload = record + b"\xff" * 12
            steps = [
                (b"\x22\x01\x01", b"\x62\x01\x01\x20"),
                (b"\x22\x02\0", b"\x62\x02\0\x80"),
                (b"\x22\x02\x01", b"\x62\x02\x01" + payload),
            ]

            def exchange(query):
                expected, reply = steps.pop(0)
                self.assertEqual(query.request, expected)
                return reply

            provider = DcmP5Analysis(
                profile,
                MonitorSupportCache(profile, exchange, "authored-dcm", bus_id=7),
            )
            result = self.api().selected_dcm_p5_analysis(provider)
            self.assertEqual(result.native_status, 0)
            self.assertEqual(result.source_build, 18)
            self.assertEqual(result.groups[0].received_payload, payload)
            self.assertEqual(result.groups[0].records[0].raw, record)
            self.assertEqual(result.groups[0].records[0].function_name, "Function")
            self.assertEqual(steps, [])
            composed = self.api().compose_dcm35_analysis(CommandStatus(), result)
            self.assertEqual(composed.groups[0].display_id, 7)
            self.assertEqual(composed.groups[0].records[0].function_name, "Function")
            self.assertEqual(composed.groups[0].records[0].content_name, "Content")
            self.assertEqual(composed.groups[0].records[0].time_words, (0,) * 8)
            timed = replace(
                result.groups[0].records[0],
                time_valid=True,
                time_values=(24, 12, 31, 23, 59, 58, 99),
                network_valid=True,
                network_status=("A", "B", "C", "D"),
            )
            changed = replace(
                result, groups=(replace(result.groups[0], records=(timed,)),)
            )
            timed_output = self.api().compose_dcm35_analysis(
                CommandStatus(2, 999), changed
            )
            self.assertEqual(
                timed_output.groups[0].records[0].time_words,
                (2024, 12, 0, 31, 23, 59, 58, 0),
            )
            self.assertEqual(
                timed_output.groups[0].records[0].network_names, ("A", "B", "C", "D")
            )
            fault = self.api().compose_dcm35_analysis(
                CommandStatus(1, 123), None, previous=composed
            )
            self.assertEqual(fault.return_code, 123)
            self.assertEqual(fault.groups, composed.groups)
            with self.assertRaises(ValueError):
                self.api().compose_dcm35_analysis(
                    CommandStatus(), replace(result, source_build=12)
                )

    def test_selected_analysis_d7_actual_provider_error_cancel_and_consumer(self):
        from tests.test_toyota_analysis import AnalysisTests

        fixture = AnalysisTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        provider = DcmP5Analysis(fixture.profile, fixture.cache)
        result = self.api().get_analyze_work_factor_dcm_p5(provider)
        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.groups[0].name, "Signal")
        report = self.api().analysis_report(result)
        self.assertEqual(json.loads(json.dumps(report))["result"]["return_code"], 0)
        self.assertNotIn("received_payload", json.dumps(report))
        self.assertNotIn("selected_identity", json.dumps(report))
        fixture.cache.exchange = lambda query: (_ for _ in ()).throw(
            ToyotaCodecError("native read fault", 0xC0040001)
        )
        failed = self.api().get_analyze_work_factor_dcm_p5(provider, previous=result)
        self.assertEqual(failed.return_code, 0xC0040001)
        self.assertEqual(failed.groups, result.groups)
        with self.assertRaises(Cancelled):
            self.api(cancelled=lambda: True).get_analyze_work_factor_dcm_p5(provider)
        with self.assertRaises(NotImplementedError):
            self.api(12).get_analyze_work_factor_dcm_p5(provider)

    def test_selected_rob_actual_native_wire_result_and_saved_ui_adapter(self):
        from scripts.toyota_analysis import RoBAnalysis
        from tests.test_toyota_analysis import RoBTests

        fixture = RoBTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        connection, backend = fixture.native_rob_connection()
        self.addCleanup(connection.disconnect)
        assert isinstance(connection.profile, VehicleProfile)
        provider = RoBAnalysis(connection.profile, connection.cache)
        result = self.api().get_analyze_work_factor_rob(provider)
        self.assertEqual(result.return_code, 0)
        group = result.groups[0]
        self.assertEqual(
            (group.display_id, group.data_id, group.name), (7, 0x201, "R1:Signal")
        )
        row = group.records[0]
        self.assertEqual(
            (row.operation_code, row.label, row.help, row.help_type),
            (1, "0x01:Content", "Signal", 7),
        )
        self.assertEqual(tuple(value.value for value in row.values), (1, 90, 10, 2))
        self.assertEqual(row.values[2], RoBFacadeValue(value=10, format=1))
        self.assertEqual(result.current[1].value, 100)
        self.assertEqual(len(result.time_words), 6)
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 6)
        self.assertFalse(connection.closed)
        document = json.loads(json.dumps(self.api().analysis_report(result)))
        self.assertEqual(
            document["result"]["groups"][0]["records"][0]["values"][2]["value"], 10
        )
        self.assertNotIn("physical", json.dumps(document))
        self.assertNotIn("data_ids", json.dumps(document))
        self.assertEqual(
            self.api().compose_rob_analysis(
                CommandStatus(9, 77), None, previous=result
            ),
            replace(result, return_code=77),
        )

    def test_rob_native_defaults_metadata_only_and_fault_lifetime(self):
        from scripts.toyota_analysis import RoBAnalysis
        from tests.test_toyota_analysis import RoBTests

        fixture = RoBTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        provider = RoBAnalysis(fixture.profile, fixture.cache)
        result = self.api().get_analyze_work_factor_rob(
            provider, mode=2, current_flag=0
        )
        self.assertEqual(result.current, (RoBFacadeValue(),) * 3)
        self.assertEqual(result.current[0].format, 0x4000)
        self.assertEqual(result.time_words, (0,) * 6)
        self.assertEqual(result.groups[0].records, ())
        fixture.replies[b"\x31\x01"] = ToyotaCodecError("native fault", 0xC0040001)
        failed = self.api().get_analyze_work_factor_rob(
            provider, mode=2, current_flag=0, previous=result
        )
        self.assertEqual(failed, replace(result, return_code=0xC0040001))
        fixture.replies[b"\x31\x01"] = Cancelled("stop")
        with self.assertRaises(Cancelled):
            self.api().get_analyze_work_factor_rob(provider, mode=2, current_flag=0)
        with self.assertRaises(TypeError):
            self.api().get_analyze_work_factor_rob(
                cast(Any, lambda: RoBFacadeResult(0))
            )

    def test_rob_source_fields_transformed_defaults_and_host_fault_identity(self):
        from scripts.toyota_analysis import RoBAnalysis
        from tests.test_toyota_analysis import RoBTests

        fixture = RoBTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        provider = RoBAnalysis(fixture.profile, fixture.cache)
        result = provider.run()
        row = replace(result.groups[0].records[0], happened=None)
        result = replace(result, groups=(replace(result.groups[0], records=(row,)),))
        output = self.api().compose_rob_analysis(CommandStatus(), result)
        self.assertEqual(output.groups[0].records[0].values[2], RoBFacadeValue())
        with self.assertRaises(ValueError):
            self.api().compose_rob_analysis(
                CommandStatus(), replace(result, source_build=12)
            )
        with self.assertRaises(ValueError):
            self.api().compose_rob_analysis(
                CommandStatus(), replace(result, common_sha256="0" * 64)
            )
        fault = RuntimeError("host transport failure")
        fixture.replies[b"\x31\x01"] = fault
        with self.assertRaises(RuntimeError) as raised:
            self.api().get_analyze_work_factor_rob(provider, current_flag=0)
        self.assertIs(raised.exception, fault)
        with self.assertRaises(NotImplementedError):
            self.api(12).get_analyze_work_factor_rob(provider)
        api = self.api()
        api.close()
        with self.assertRaises(ValueError):
            api.get_analyze_work_factor_rob(provider)

    def test_rob_and_dcm35_report_reject_untyped_nested_metadata(self):
        from scripts.command_api import (
            DcmP5FacadeGroup,
            DcmP5FacadeRecord,
            DcmP5FacadeResult,
            RoBFacadeGroup,
            RoBFacadeRecord,
        )

        api = self.api()
        record = DcmP5FacadeRecord(0, (0,) * 8, 1, "function", "content", 0, ("",) * 4)
        group = DcmP5FacadeGroup(1, "group", (record,))
        rob_record = RoBFacadeRecord(1, "label", (RoBFacadeValue(),) * 4, "help", 0)
        rob_group = RoBFacadeGroup(1, 2, "group", (rob_record,))
        for result in (
            DcmP5FacadeResult(0, cast(Any, ({"unexpected": "field"},))),
            DcmP5FacadeResult(
                0, (replace(group, records=cast(Any, ({"unexpected": "field"},))),)
            ),
            DcmP5FacadeResult(
                0,
                (
                    replace(
                        group,
                        records=(
                            replace(
                                record,
                                network_names=cast(
                                    Any, ("", "", "", {"unexpected": "field"})
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            DcmP5FacadeResult(
                0, (replace(group, records=(replace(record, time_words=(0,) * 7),)),)
            ),
            RoBFacadeResult(0, cast(Any, ({"unexpected": "field"},))),
            RoBFacadeResult(
                0,
                (
                    replace(
                        rob_group,
                        records=(
                            replace(
                                rob_record,
                                values=cast(Any, ({"unexpected": "field"},) * 4),
                            ),
                        ),
                    ),
                ),
            ),
            RoBFacadeResult(
                0,
                (
                    replace(
                        rob_group,
                        records=(
                            replace(
                                rob_record, help=cast(Any, {"unexpected": "field"})
                            ),
                        ),
                    ),
                ),
            ),
        ):
            with (
                self.subTest(result=type(result).__name__),
                self.assertRaises((TypeError, ValueError)),
            ):
                api.analysis_report(result)
        self.assertEqual(
            api.analysis_report(DcmP5FacadeResult(0, (group,)))["operation"],
            "GetAnalyzeWorkFactorDcmP5API",
        )
        self.assertEqual(
            api.analysis_report(RoBFacadeResult(0, (rob_group,)))["operation"],
            "GetAnalyzeWorkFactorRoBAPI",
        )

    def test_saved_image_schemas_reject_subclass_private_fields(self):
        from dataclasses import dataclass

        from scripts.command_api import ImageFacadeResult, SavedOperationFacadeMetadata
        from scripts.toyota_saved_ffd import TSS3_SOURCE_SHA256, SavedFfdSource

        @dataclass(frozen=True)
        class ExtraValue(SavedOperationFacadeValue):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraMetadata(SavedOperationFacadeMetadata):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraFreeze(SavedOperationFacadeFreeze):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraSaved(SavedOperationFacadeResult):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraImage(ImageFacadeResult):
            private_path: str = "/sensitive/log"

        with self.assertRaises(TypeError):
            SavedOperationFacadeFreeze((ExtraValue(1),))
        with self.assertRaises(TypeError):
            SavedOperationFacadeFreeze((), ExtraMetadata())
        for root in (SavedOperationFacadeResult, ImageFacadeResult):
            with self.assertRaises(TypeError):
                root(0, (ExtraFreeze(()),))
        api = self.api()
        with self.assertRaises(TypeError):
            api.saved_operation_report(
                SavedFfdSource(18, TSS3_SOURCE_SHA256), ExtraSaved(0)
            )
        with self.assertRaises(TypeError):
            api.pcs_operation_report(ExtraSaved(0))
        with self.assertRaises(TypeError):
            api.image_ffd_report(ExtraImage(0))

    def test_saved_operation_rejects_untyped_metadata_before_json_adapter(self):
        with self.assertRaisesRegex(TypeError, "typed.*metadata"):
            SavedOperationFacadeFreeze((), metadata=cast(Any, {"unexpected": "field"}))

    def test_saved_operation_native_first_value_append_error_and_source(self):
        from scripts.toyota_saved_ffd import (
            LCS_SOURCE_SHA256,
            TSS3_SOURCE_SHA256,
            SavedFfdSource,
            Tss3OperationAcquisition,
            Tss3OperationGroup,
            Tss3OperationReport,
            Tss3OperationRequest,
            Tss3SavedFreeze,
            Tss3SavedOperationResult,
        )

        for version, sha in (
            (18, TSS3_SOURCE_SHA256),
            (18, LCS_SOURCE_SHA256[18]),
            (12, LCS_SOURCE_SHA256[12]),
        ):
            with self.subTest(version=version, sha=sha):
                source = SavedFfdSource(version, sha)
                acquisition = Tss3OperationAcquisition(
                    Tss3OperationRequest(77, 12),
                    b"private-raw",
                    (Tss3OperationGroup((), (0x1234, 99)),),
                    sha,
                    "private-frame",
                )
                freeze = Tss3SavedFreeze(12, 77, acquisition)
                report = Tss3OperationReport(
                    (77,),
                    (
                        freeze,
                        replace(freeze, acquisition=replace(acquisition, groups=())),
                    ),
                    (),
                )
                acquired = Tss3SavedOperationResult(0, report, 123, "/private/log/path")
                previous = SavedOperationFacadeResult(
                    0, (SavedOperationFacadeFreeze((SavedOperationFacadeValue(9),)),)
                )
                api = self.api(version)
                output = api.compose_saved_operations(
                    source, acquired, previous=previous
                )
                self.assertEqual(
                    [row.values[0].scalar for row in output.freezes], [9, 0x1234]
                )
                self.assertEqual(output.freezes[1].values[0].text, "")
                self.assertEqual(output.freezes[1].values[0].status, 0)
                self.assertEqual(
                    dict(
                        zip(
                            SAVED_OPERATION_WORD_OFFSETS,
                            output.freezes[1].metadata.words,
                            strict=True,
                        )
                    ),
                    {0: 0, 0x1C: 1, 0x1E: 0, 0x2C: 0, 0x30: 0},
                )
                self.assertEqual(output.freezes[1].metadata.dwords, (0,) * 8)
                self.assertEqual(output.freezes[1].metadata.display_entries, ())
                self.assertEqual(
                    api.compose_saved_operations(
                        source, replace(acquired, native_status=123), previous=previous
                    ),
                    replace(previous, return_code=123),
                )
                with self.assertRaises(ValueError):
                    api.compose_saved_operations(source, replace(acquired, report=None))
                wrong = replace(
                    freeze, acquisition=replace(acquisition, source_sha256="0" * 64)
                )
                with self.assertRaises(ValueError):
                    api.compose_saved_operations(
                        source,
                        replace(acquired, report=replace(report, freezes=(wrong,))),
                    )
                self.assertNotIn("private", repr(output))
                document = json.dumps(api.saved_operation_report(source, output))
                self.assertNotIn("private", document)
                self.assertNotIn("log_path", document)
                self.assertEqual(
                    json.loads(document)["result"]["freezes"][1]["values"][0]["scalar"],
                    0x1234,
                )

    def test_image_and_pcs_untyped_previous_reject_before_io_or_log(self):
        from scripts.database_resources import DdrPacketLog

        for command, module in (
            (0xBB, b"GetImageFFD_DT.dll"),
            (0xBA, b"GetPCSOperationFFDP4_DT.dll"),
        ):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as directory,
            ):
                connection, backend = self.vin_connection(module, [], command=command)
                assert isinstance(connection.operations, NativeFrameController)
                packet_log = DdrPacketLog(Path(directory), connection.operations)
                before = len(backend.calls)
                with self.assertRaises(TypeError):
                    if command == 0xBB:
                        self.api().get_image_ffd(
                            connection, packet_log, bytes(6), previous=cast(Any, {})
                        )
                    else:
                        self.api().get_pcs_operation_ffd(
                            connection, packet_log, previous=cast(Any, {})
                        )
                self.assertEqual(len(backend.calls), before)
                self.assertFalse(packet_log.directory.exists())

    def test_pcs_native_first_scalar_reset_append_fault_and_report(self):
        from scripts.toyota_saved_ffd import (
            PCS_OPERATION_SOURCE_SHA256,
            PcsOperationPhase,
            PcsOperationSource,
            PcsSavedFreeze,
            PcsSavedOperationResult,
        )

        for build in (12, 18):
            source = PcsOperationSource(build, PCS_OPERATION_SOURCE_SHA256[build])
            phase = PcsOperationPhase(1, 0xDEADBEEF, (), ())
            acquired = PcsSavedOperationResult(
                0, (PcsSavedFreeze(7, 42, phase),), source.sha256, "privatepath"
            )
            previous = SavedOperationFacadeResult(
                0, (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),)
            )
            api = self.api(build)
            result = api.compose_pcs_operations(source, acquired, previous=previous)
            self.assertEqual(
                [row.values[0].scalar for row in result.freezes], [99, 0xDEADBEEF]
            )
            self.assertEqual(result.freezes[-1].metadata.words, (0, 1, 0, 0, 0))
            self.assertEqual(
                api.compose_pcs_operations(
                    source, replace(acquired, native_status=77), previous=previous
                ),
                replace(previous, return_code=77),
            )
            document = json.dumps(api.pcs_operation_report(result))
            self.assertNotIn("privatepath", document)
            self.assertNotIn("matched_value", document)
            self.assertEqual(json.loads(document)["operation"], "GetPCSOperationFFDApi")
            with self.assertRaises(ValueError):
                api.compose_pcs_operations(
                    source, replace(acquired, source_sha256="unreconciled")
                )

    def test_image_p5_native_retry_scalars_inner_failure_and_outer_retention(self):
        from scripts.command_api import ImageFacadeResult
        from scripts.toyota_saved_ffd import (
            IMAGE_P5_SOURCE_SHA256,
            ImageP5RecordAcquisition,
            ImageP5SavedResult,
            ImageP5Source,
        )

        source = ImageP5Source(18, IMAGE_P5_SOURCE_SHA256[18])
        record = ImageP5RecordAcquisition(
            1, 0, 8, b"raw-header", 1, 0x1234, 0, True, False, True, ()
        )
        acquired = ImageP5SavedResult(
            0,
            (record, replace(record, scalar=None), record),
            None,
            None,
            None,
            0xC0040101,
            source.sha256,
            "private-log-path",
            0,
        )
        previous = ImageFacadeResult(
            0,
            (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),),
            (7, 8, 9),
        )
        api = self.api()
        result = api.compose_image_p5(source, acquired, previous=previous)
        self.assertEqual(
            [row.values[0].scalar for row in result.freezes], [99, 0x1234, 0x1234]
        )
        self.assertEqual(result.native_fields18, (0, 0, 0))
        self.assertEqual(
            api.compose_image_p5(
                source, replace(acquired, native_status=77), previous=previous
            ),
            replace(previous, return_code=77),
        )
        with self.assertRaises(ValueError):
            api.compose_image_p5(source, replace(acquired, ddr_status=0))
        with self.assertRaises(ValueError):
            self.api(12).compose_image_p5(source, acquired)
        source12 = ImageP5Source(12, IMAGE_P5_SOURCE_SHA256[12])
        acquired12 = replace(acquired, source_sha256=source12.sha256, ddr_status=0)
        result12 = self.api(12).compose_image_p5(
            source12, acquired12, previous=previous
        )
        self.assertEqual(result12.native_fields18, (7, 8, 9))
        self.assertEqual(
            [row.values[0].scalar for row in result12.freezes], [99, 0x1234, 0x1234]
        )
        document = json.dumps(api.image_ffd_report(result))
        for private in (
            "raw-header",
            "private-log-path",
            "checksum",
            "retry",
            "ddr_report",
        ):
            self.assertNotIn(private, document)

    def test_ads_image_native_clear_first_scalar_and_presence_not_status(self):
        from scripts.command_api import ImageFacadeResult
        from scripts.database_resources import DdrP5SupportValue
        from scripts.toyota_saved_ffd import (
            ADS_IMAGE_SOURCE_SHA256,
            AdsImageRecord,
            AdsImageRecordPhase,
            AdsImageSavedResult,
            AdsImageSource,
            AdsOperationGroup,
        )

        source = AdsImageSource(18, ADS_IMAGE_SOURCE_SHA256)
        record = AdsImageRecord(
            1, 2, b"private-raw", (AdsOperationGroup((), (0x1234, 0xABCD)),), (0x501,)
        )
        phase = AdsImageRecordPhase(
            0, (record, replace(record, groups=())), (record,), (), 0
        )
        acquired = AdsImageSavedResult(
            0,
            phase,
            None,
            DdrP5SupportValue(0x170, True, 3),
            None,
            0xC0040101,
            False,
            source.sha256,
            "private-log-path",
            0,
        )
        previous = ImageFacadeResult(
            0,
            (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),),
            (7, 8, 9),
        )
        api = self.api()
        result = api.compose_ads_image(source, acquired, previous=previous)
        self.assertEqual([row.values[0].scalar for row in result.freezes], [0x1234])
        self.assertEqual(result.native_fields18, (1, 0, 3))
        self.assertEqual(
            api.compose_ads_image(
                source, replace(acquired, native_status=77), previous=previous
            ),
            ImageFacadeResult(77, (), (0, 0, 0)),
        )
        for changed in (
            replace(acquired, ddr_provided=True),
            replace(acquired, first_support=DdrP5SupportValue(0x170, False, 0)),
        ):
            self.assertEqual(
                api.compose_ads_image(source, changed).native_fields18, (0, 0, 0)
            )
        with self.assertRaises(NotImplementedError):
            self.api(12).compose_ads_image(source, acquired)
        with self.assertRaises(ValueError):
            api.compose_ads_image(source, replace(acquired, source_sha256="wrong"))
        document = json.dumps(api.ads_image_ffd_report(result))
        self.assertIn("GetADSImageFFDApi", document)
        with self.assertRaises(TypeError):
            api.ads_image_ffd_report(ImageFacadeResult(0))
        for private in (
            "private-raw",
            "private-log-path",
            "ddr_status",
            "first_support",
            "ABCD",
        ):
            self.assertNotIn(private, document)

    def test_rc_image_first_header_scalar_and_entry_clear(self):
        from scripts.command_api import ImageFacadeResult
        from scripts.database_resources import DdrP5SupportValue
        from scripts.toyota_saved_ffd import (
            RC_IMAGE_SOURCE_SHA256,
            RcImageAcquisition,
            RcImageBlock,
            RcImageGroup,
            RcImageIndexInformation,
            RcImageRecordPhase,
            RcImageSavedResult,
            RcImageSource,
        )

        source = RcImageSource(18, RC_IMAGE_SOURCE_SHA256)
        groups = (RcImageGroup(1, 0, 0, (), False), RcImageGroup(2, 0, 0, (), False))
        information = RcImageIndexInformation(groups, (), ())
        row = RcImageAcquisition(
            1,
            0,
            True,
            0,
            0,
            (
                RcImageBlock(1, 1, b"private-header", (0x1234, 0xABCD)),
                RcImageBlock(1, 2, b"private-body", (0x5678,)),
            ),
        )
        phase = RcImageRecordPhase(information, (row,), (row,), 0)
        acquired = RcImageSavedResult(
            0,
            phase,
            None,
            DdrP5SupportValue(170, True, 5),
            None,
            77,
            False,
            source.sha256,
            "private-path",
            0,
        )
        prior = ImageFacadeResult(
            0,
            (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),),
            (7, 8, 9),
        )
        api = self.api()
        result = api.compose_rc_image(source, acquired, previous=prior)
        self.assertEqual(
            [freeze.values[0].scalar for freeze in result.freezes], [0x1234]
        )
        self.assertEqual(result.native_fields18, (1, 0, 5))
        self.assertEqual(
            api.compose_rc_image(
                source, replace(acquired, ddr_provided=True)
            ).native_fields18,
            (0, 0, 0),
        )
        self.assertEqual(
            api.compose_rc_image(
                source, replace(acquired, native_status=77), previous=prior
            ),
            ImageFacadeResult(77, (), (0, 0, 0)),
        )
        document = json.dumps(api.rc_image_ffd_report(result))
        self.assertIn("GetRCImageFFDApi", document)
        for private in (
            "private-header",
            "private-body",
            "private-path",
            "ddr_status",
            "raw_reply",
        ):
            self.assertNotIn(private, document)
        with self.assertRaises(NotImplementedError):
            self.api(12).compose_rc_image(source, acquired)
        with self.assertRaises(TypeError):
            api.rc_image_ffd_report(ImageFacadeResult(0))

    def test_image_p4_facade_native_reset_append_fault_and_version_fields(self):
        from scripts.command_api import ImageFacadeResult
        from scripts.toyota_saved_ffd import (
            IMAGE_P4_SOURCE_SHA256,
            ImageP4SavedRecord,
            ImageP4SavedResult,
            ImageP4Source,
        )

        for build in (12, 18):
            source = ImageP4Source(build, IMAGE_P4_SOURCE_SHA256[build])
            acquired = ImageP4SavedResult(
                0,
                (),
                None,
                None,
                (
                    ImageP4SavedRecord(b"raw", 0x1234),
                    ImageP4SavedRecord(b"other", 0xABCD),
                ),
                source.sha256,
                "privatepath",
            )
            previous = ImageFacadeResult(
                0, (SavedOperationFacadeFreeze((SavedOperationFacadeValue(99),)),)
            )
            api = self.api(build)
            result = api.compose_image_p4(source, acquired, previous=previous)
            self.assertEqual(
                [row.values[0].scalar for row in result.freezes], [99, 0x1234, 0xABCD]
            )
            self.assertTrue(
                all(row.metadata.words == (0, 1, 0, 0, 0) for row in result.freezes)
            )
            self.assertEqual(result.native_fields18, (0, 0, 0) if build == 18 else ())
            failed = api.compose_image_p4(
                source, replace(acquired, native_status=77), previous=result
            )
            self.assertEqual(failed, replace(result, return_code=77))
            document = json.dumps(api.image_ffd_report(result))
            self.assertNotIn("raw", document)
            self.assertNotIn("privatepath", document)
            self.assertEqual(json.loads(document)["operation"], "GetImageFFDApi")
            with self.assertRaises(ValueError):
                api.compose_image_p4(
                    source, replace(acquired, source_sha256="unreconciled")
                )
            with self.assertRaises(TypeError):
                ImageFacadeResult(0, cast(Any, ({"unexpected": "field"},)))

    def test_p5_subaru26b_actual_snapshot_parser_to_public_facade(self):
        from scripts.diagnostic_db import Language, Section, parse_database
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_toyota_session import SessionTests

        signals = {
            0x1C: (1,),
            0x1D: (2,),
            0x27: (3,),
            0x28: (99,),
            **{signal: (99,) for signal in range(0x3C, 0x42)},
        }
        profile, _state = SessionTests().p5_existence_fixture(signals=signals, count=3)
        rule = bytearray(12)
        struct.pack_into("<I", rule, 0, 1)
        rule[8:10] = b"\x01\x01"
        profile.database.sections[66] = Section(66, 0, 1, False, bytes(rule))
        language = Language(
            parse_database(_language([f"label{i}" for i in range(1, 104)]))
        )
        connection, backend = self.vin_connection(
            b"GetDiagCodeP5_DT.dll",
            [
                bytes.fromhex(text)
                for text in (
                    "59020100000101",
                    "59030000010100000110",
                    "59040000010001011234050601",
                    "59040000010010011234070802",
                )
            ],
            request=bytes.fromhex("190400000001"),
            command=0xAC,
            functions=(0xCD, 0xCE, 0xCF),
            diagnostic=profile.database,
            language=language,
            category_id=0x26B,
        )
        workflow = ToyotaWorkflows.from_communication(
            connection, observations=WorkflowObservations(1, 0x12)
        )
        api = self.api()
        result = api.get_diag_code_p5(workflow, 1, 3, native_cancel_value=0)
        self.assertEqual(result.return_code, 0)
        row = result.diagnostics[0]
        self.assertEqual(row.normal_numbers, (1, 0x10))
        self.assertEqual([value.value for value in row.signals[0].values], [5, 7])
        self.assertEqual(
            [value.display for value in row.signals[0].values], ["13", "17"]
        )
        self.assertEqual(row.timestamp_flags, 1)
        self.assertEqual([block.pid for block in row.timestamps], [1, 2, 3])
        self.assertEqual(row.stored_all, 0)
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 4)
        self.assertEqual(
            api.p5_diagnostic_report(result)["operation"], "GetDiagCodeP5API"
        )
        self.assertFalse(connection.closed)

    def test_p5_subaru_stored_selected_native_113_to_public_facade(self):
        from scripts.diagnostic_db import Language, Section, parse_database
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_toyota_session import SessionTests

        profile, _state = SessionTests().p5_existence_fixture(
            function=0x113,
            frame_request=bytes.fromhex("1903ff"),
            count=3,
            signals={0x4D: (1,), 0x4E: (2,), 0x4F: (3,)},
        )
        rule = bytearray(12)
        struct.pack_into("<I", rule, 0, 1)
        rule[8:10] = b"\x01\x01"
        profile.database.sections[66] = Section(66, 0, 1, False, bytes(rule))
        language = Language(
            parse_database(_language([f"label{i}" for i in range(1, 104)]))
        )
        connection, backend = self.vin_connection(
            b"GetDiagCodeP5_DT.dll",
            [
                bytes.fromhex("59020112345601"),
                bytes.fromhex("590301123456000112340a0302"),
            ],
            request=bytes.fromhex("1903ff"),
            command=0xAC,
            functions=(0xCD, 0x113),
            diagnostic=profile.database,
            language=language,
            flags=0x20,
        )
        workflow = ToyotaWorkflows.from_communication(
            connection, observations=WorkflowObservations(1, 0x12)
        )
        api = self.api()
        result = api.get_diag_code_p5(workflow, 1, 7, native_cancel_value=0)
        self.assertEqual(result.return_code, 0)
        row = result.diagnostics[0]
        self.assertEqual((row.code, row.status), (0x123456, 1))
        self.assertEqual(row.stored_all, 1)
        # Native88fc0 copies the existing empty number list into its local stage.
        self.assertEqual(row.extended_numbers, ())
        self.assertEqual(row.existence_flags, 1)
        self.assertEqual(row.timestamp_flags, 1)
        self.assertEqual([signal.values[0].value for signal in row.signals], [10, 3, 2])
        self.assertEqual(
            [block.values[0].value for block in row.timestamps], [10, 3, 2]
        )
        writes = [
            fields["messages"][0].data
            for op, fields in backend.calls
            if op == "write_messages"
        ]
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[-1][-3:], bytes.fromhex("1903ff"))
        self.assertEqual(
            json.loads(json.dumps(api.p5_diagnostic_report(result)))["result"][
                "diagnostics"
            ][0]["stored_all"],
            1,
        )
        self.assertFalse(connection.closed)

    def test_p5_predictive_selected_native_cf_to_public_facade(self):
        from scripts.diagnostic_db import Language, Section, parse_database
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_toyota_session import SessionTests

        for build in (12, 18):
            profile, _state = SessionTests().p5_existence_fixture()
            rule = bytearray(12)
            struct.pack_into("<I", rule, 0, 2)
            rule[8:10] = b"\x02\x02"
            profile.database.sections[66] = Section(66, 0, 1, False, bytes(rule))
            diagnostic_bytes = bytearray(
                _ddb(
                    2,
                    {
                        slot: (section.count, section.payload)
                        for slot, section in profile.database.sections.items()
                    },
                )
            )
            struct.pack_into(
                "<I", diagnostic_bytes, 28, 0x0100030C if build == 12 else 0x0100032F
            )
            language_bytes = bytearray(_language([f"label{i}" for i in range(1, 103)]))
            struct.pack_into(
                "<I", language_bytes, 28, 0x0100030C if build == 12 else 0x0100032F
            )
            language = Language(parse_database(bytes(language_bytes)))
            connection, backend = self.vin_connection(
                b"GetDiagCodeP5_DT.dll",
                [
                    bytes.fromhex("59020200000102"),
                    bytes.fromhex("590400000100100112340506"),
                ],
                request=bytes.fromhex("190400000001"),
                command=0xAC,
                version=build,
                functions=(0xCD, 0xCF),
                diagnostic=parse_database(bytes(diagnostic_bytes)),
                language=language,
                flags=0x15,
            )
            workflow = ToyotaWorkflows.from_communication(
                connection,
                observations=WorkflowObservations(1, 0x12, source_version=build),
            )
            api = self.api(build)
            if build == 12:
                result = api.get_diag_code_p5_12(workflow, 2, 3, native_cancel_value=0)
                document = api.p5_diagnostic_report12(result)
            else:
                result = api.get_diag_code_p5(workflow, 2, 3, native_cancel_value=0)
                document = api.p5_diagnostic_report(result)
            self.assertEqual(result.return_code, 0)
            row = result.diagnostics[0]
            self.assertEqual(
                (row.code, row.diag_type, row.status, row.existence_flags), (1, 2, 2, 1)
            )
            self.assertEqual(row.normal_numbers, (0x10,))
            self.assertEqual([signal.values[0].value for signal in row.signals], [5, 6])
            self.assertEqual(
                [signal.values[0].index for signal in row.signals], [145, 145]
            )
            self.assertEqual((row.timestamp_flags, row.odometer_flags), (0, 0))
            writes = [
                fields["messages"][0].data
                for op, fields in backend.calls
                if op == "write_messages"
            ]
            self.assertEqual(len(writes), 2)
            self.assertEqual(writes[-1][-6:], bytes.fromhex("190400000110"))
            self.assertEqual(document["operation"], "GetDiagCodeP5API")
            self.assertFalse(connection.closed)

    def test_p5_full_normal_j2534_metadata_timestamps_odometer_absolute(self):
        from scripts.diagnostic_db import Language, Section, parse_database
        from scripts.frame_transport import J2534Result
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_toyota_session import SessionTests

        signals = {
            0x1C: (1,),
            0x1D: (2,),
            0x27: (3,),
            0x28: (4,),
            **{0x3C + i: (5 + i,) for i in range(6)},
        }
        profile, _state = SessionTests().p5_existence_fixture(signals=signals, count=10)
        rule = bytearray(12)
        struct.pack_into("<I", rule, 0, 1)
        rule[8:10] = b"\x01\x01"
        profile.database.sections[66] = Section(66, 0, 1, False, bytes(rule))
        language = Language(
            parse_database(_language([f"label{i}" for i in range(1, 111)]))
        )
        encoded = bytes((5, 6, 1, 7, 0x24, 0x10, 0x20, 0x12, 0x30, 0x40))
        connection, backend = self.vin_connection(
            b"GetDiagCodeP5_DT.dll",
            [
                bytes.fromhex("59020100000101"),
                bytes.fromhex("590300000101"),
                bytes.fromhex("590400000100010112340a") + encoded,
            ],
            request=bytes.fromhex("190400000001"),
            command=0xAC,
            functions=(0xCD, 0xCE, 0xCF),
            diagnostic=profile.database,
            language=language,
        )
        workflow = ToyotaWorkflows.from_communication(
            connection, observations=WorkflowObservations(1, 0x12)
        )
        api = self.api()
        result = api.get_diag_code_p5(workflow, 1, 3, native_cancel_value=0)
        self.assertEqual(result.return_code, 0)
        row = result.diagnostics[0]
        self.assertEqual([signal.pid for signal in row.signals], list(range(1, 11)))
        self.assertEqual(
            [signal.values[0].value for signal in row.signals], list(encoded)
        )
        self.assertEqual(
            [signal.values[0].display for signal in row.signals[:3]], ["13", "15", "5"]
        )
        self.assertEqual(
            (row.timestamp_flags, row.odometer_flags, row.absolute_flags), (1, 1, 1)
        )
        self.assertEqual([block.pid for block in row.timestamps], [1, 2, 3])
        self.assertEqual(row.odometer.pid, 4)
        self.assertEqual(
            [block.values[0].value for block in row.absolute], [24, 10, 20, 12, 30, 40]
        )
        self.assertEqual(row.signals[0].name, "label101")
        self.assertEqual(row.signals[0].unit, "label20")
        self.assertEqual(row.normal_numbers, (1,))
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 3)
        document = json.loads(json.dumps(api.p5_diagnostic_report(result)))
        self.assertEqual(
            document["result"]["diagnostics"][0]["absolute"][0]["values"][0]["value"],
            24,
        )
        self.assertFalse(connection.closed)

        # A later snapshot I/O fault is masked by the native full producer;
        # the earlier diagnostic/existence state still reaches the facade.
        partial_connection, partial_backend = self.vin_connection(
            b"GetDiagCodeP5_DT.dll",
            [bytes.fromhex("59020100000101"), bytes.fromhex("590300000101"), b"unused"],
            request=bytes.fromhex("190400000001"),
            command=0xAC,
            functions=(0xCD, 0xCE, 0xCF),
            diagnostic=profile.database,
            language=language,
        )
        partial_backend.replies[2] = J2534Result(code=9)
        partial_workflow = ToyotaWorkflows.from_communication(
            partial_connection, observations=WorkflowObservations(1, 0x12)
        )
        partial = api.get_diag_code_p5(
            partial_workflow, 1, 3, native_cancel_value=0, previous=result
        )
        self.assertEqual(partial.return_code, 0)
        self.assertEqual(len(partial.diagnostics), 2)
        self.assertEqual(partial.diagnostics[-1].existence_flags, 1)
        self.assertEqual(partial.diagnostics[-1].signals, ())
        self.assertFalse(partial_connection.closed)

    def test_p5_selected_j2534_log_attachment_and_public_json(self):
        from scripts.command_api import P5DiagnosticAttachment
        from scripts.database_resources import DdrPacketLog
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_toyota_session import SessionTests

        workflow, _operations = SessionTests().native_p5_metadata_workflow_fixture(
            18, bytes.fromhex("59020100000101")
        )
        connection, backend = self.vin_connection(
            b"GetDiagCodeP5_DT.dll",
            [bytes.fromhex("59020100000101")],
            request=bytes.fromhex("190201"),
            command=0xAC,
            functions=(0xCD,),
            diagnostic=workflow.profile.database,
            language=workflow.profile.catalog.language,
        )
        workflow = ToyotaWorkflows.from_communication(
            connection,
            observations=WorkflowObservations(1, 0x12),
        )
        with tempfile.TemporaryDirectory() as directory:
            assert isinstance(connection.operations, NativeFrameController)
            packet_log = DdrPacketLog(Path(directory), connection.operations)
            result = self.api().get_diag_code_p5(
                workflow,
                1,
                0,
                native_cancel_value=0,
                log_control=1,
                packet_log=packet_log,
                include_attachment=True,
            )
            self.assertEqual(result.return_code, 0)
            self.assertEqual([(r.code, r.status) for r in result.diagnostics], [(1, 1)])
            self.assertIsInstance(result.attachment, P5DiagnosticAttachment)
            assert result.attachment is not None
            self.assertEqual(result.attachment.native_id, 1)
            self.assertIn(b"59", result.attachment.data)
            self.assertFalse((packet_log.directory / "MarkMonRam_SSR.log").exists())
            self.assertFalse(packet_log.active)
            self.assertFalse(connection.closed)
            document = self.api().p5_diagnostic_report(result)
            self.assertNotIn("attachment", document["result"])
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 1)

    def test_p5_actual_j2534_log_start_and_write_fault_keep_attachment(self):
        from scripts.command_api import P5DiagnosticAttachment, P5DiagnosticFacadeResult
        from scripts.database_resources import DdrPacketLog
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_toyota_session import SessionTests

        for fault in ("start", "write"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                seed, _operations = SessionTests().native_p5_metadata_workflow_fixture(
                    18, bytes.fromhex("59020100000101")
                )
                connection, backend = self.vin_connection(
                    b"GetDiagCodeP5_DT.dll",
                    [bytes.fromhex("59020100000101")],
                    request=bytes.fromhex("190201"),
                    command=0xAC,
                    functions=(0xCD,),
                    diagnostic=seed.profile.database,
                    language=seed.profile.catalog.language,
                )
                workflow = ToyotaWorkflows.from_communication(
                    connection, observations=WorkflowObservations(1, 0x12)
                )
                root = Path(directory)
                if fault == "start":
                    root = root / "blocked"
                    root.write_bytes(b"not a directory")
                assert isinstance(connection.operations, NativeFrameController)
                packet_log = DdrPacketLog(
                    root,
                    connection.operations,
                    max_bytes=1 if fault == "write" else 1024,
                )
                previous = P5DiagnosticFacadeResult(
                    0, attachment=P5DiagnosticAttachment(99, b"KEEP")
                )
                result = self.api().get_diag_code_p5(
                    workflow,
                    1,
                    0,
                    native_cancel_value=0,
                    log_control=1,
                    packet_log=packet_log,
                    include_attachment=True,
                    previous=previous,
                )
                self.assertEqual(result.return_code, 0)
                self.assertEqual(len(result.diagnostics), 1)
                self.assertEqual(result.attachment, previous.attachment)
                self.assertFalse((packet_log.directory / "MarkMonRam_SSR.log").exists())
                self.assertFalse(connection.closed)
                self.assertEqual(
                    sum(op == "write_messages" for op, _ in backend.calls), 1
                )

    def test_p5_public_schemas_reject_subclass_private_fields(self):
        from dataclasses import dataclass, fields

        from scripts.command_api import (
            P5DiagnosticAttachment,
            P5DiagnosticFacadeResult,
            P5DiagnosticFacadeResult12,
            P5FacadeConversion,
            P5FacadeDiagnostic,
            P5FacadeDiagnostic12,
            P5FacadeDisplayInfo,
            P5FacadeSignal,
            P5FacadeValue,
        )
        from tests.test_freeze_p5 import state

        @dataclass(frozen=True)
        class ExtraSignal(P5FacadeSignal):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraConversion(P5FacadeConversion):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraPattern(P5FacadeDisplayInfo):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraValue(P5FacadeValue):
            private_path: str = "/sensitive/log"

        selected = state()
        selected.add_diagnostic(1, status=1, diag_type=1)
        row18 = (
            self.api().compose_p5_diagnostics(CommandStatus(), selected).diagnostics[0]
        )
        row12 = P5FacadeDiagnostic12(
            **{
                field.name: getattr(row18, field.name)
                for field in fields(P5FacadeDiagnostic12)
            }
        )
        for row in (row12, row18):
            with self.assertRaises(TypeError):
                replace(row, signals=(ExtraSignal(),))
            with self.assertRaises(TypeError):
                replace(row, timestamps=(ExtraSignal(),) * 3)
            with self.assertRaises(TypeError):
                replace(row, odometer=ExtraSignal())
        for arguments in (
            {"conversion": ExtraConversion()},
            {"values": (ExtraValue(1, "1", 0, 0),)},
        ):
            with self.assertRaises(TypeError):
                P5FacadeSignal(**cast(Any, arguments))
        with self.assertRaises(TypeError):
            P5FacadeConversion(patterns=(ExtraPattern(1, "label", 0, 0),))

        @dataclass(frozen=True)
        class ExtraRow18(P5FacadeDiagnostic):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraRow12(P5FacadeDiagnostic12):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraAttachment(P5DiagnosticAttachment):
            private_path: str = "/sensitive/log"

        for row, extended, root in (
            (row18, ExtraRow18, P5DiagnosticFacadeResult),
            (row12, ExtraRow12, P5DiagnosticFacadeResult12),
        ):
            extra = extended(
                **{field.name: getattr(row, field.name) for field in fields(row)}
            )
            with self.assertRaises(TypeError):
                root(0, cast(Any, (extra,)))
        with self.assertRaises(TypeError):
            replace(row18, absolute=(ExtraSignal(),) * 6)
        with self.assertRaises(TypeError):
            P5DiagnosticFacadeResult(0, (), ExtraAttachment())
        with self.assertRaises(TypeError):
            P5FacadeConversion(core_words=(True, False))

        @dataclass(frozen=True)
        class ExtraResult18(P5DiagnosticFacadeResult):
            private_path: str = "/sensitive/log"

        @dataclass(frozen=True)
        class ExtraResult12(P5DiagnosticFacadeResult12):
            private_path: str = "/sensitive/log"

        with self.assertRaises(TypeError):
            self.api().p5_diagnostic_report(ExtraResult18(0, (row18,)))
        with self.assertRaises(TypeError):
            self.api(12).p5_diagnostic_report12(ExtraResult12(0, (row12,)))

    def test_normal_stored_full_selected_j2534_to_p5_facade_both_builds(self):
        from scripts.diagnostic_db import Language, Section, parse_database
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_toyota_session import SessionTests

        signals = {
            signal: (99,) for signal in (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))
        }
        for build in (12, 18):
            for requested in (255, 1):
                with self.subTest(build=build, requested=requested):
                    profile, _ = SessionTests().p5_existence_fixture(signals=signals)
                    rule = bytearray(12)
                    struct.pack_into("<I", rule, 0, 1)
                    rule[8:10] = b"\x01\x01"
                    profile.database.sections[66] = Section(
                        66, 0, 1, False, bytes(rule)
                    )
                    version = 0x0100030C if build == 12 else 0x0100032F
                    diagnostic = bytearray(
                        _ddb(
                            2,
                            {
                                slot: (section.count, section.payload)
                                for slot, section in profile.database.sections.items()
                            },
                        )
                    )
                    struct.pack_into("<I", diagnostic, 28, version)
                    language = bytearray(
                        _language([f"label{i}" for i in range(1, 201)])
                    )
                    struct.pack_into("<I", language, 28, version)
                    connection, backend = self.vin_connection(
                        b"GetDiagCodeP5_DT.dll",
                        [
                            bytes.fromhex("59020100000101"),
                            bytes.fromhex("590601000001ff011234020506"),
                        ],
                        version=build,
                        request=bytes((0x19, 6, requested)),
                        command=0xAC,
                        functions=(0xCD, 0xD0),
                        diagnostic=parse_database(bytes(diagnostic)),
                        language=Language(parse_database(bytes(language))),
                    )
                    workflow = ToyotaWorkflows.from_communication(
                        connection,
                        observations=WorkflowObservations(
                            1, 0x12, source_version=build
                        ),
                    )
                    api = self.api(build)
                    if build == 12:
                        result = api.get_diag_code_p5_12(
                            workflow, 1, 4, native_cancel_value=0
                        )
                        document = api.p5_diagnostic_report12(result)
                    else:
                        result = api.get_diag_code_p5(
                            workflow, 1, 4, native_cancel_value=0
                        )
                        document = api.p5_diagnostic_report(result)
                    self.assertEqual(result.return_code, 0)
                    (row,) = result.diagnostics
                    self.assertEqual(
                        (row.code, row.diag_type, row.stored_all),
                        (1, 9, int(requested == 255)),
                    )
                    self.assertEqual(row.extended_numbers, (1,))
                    self.assertEqual(
                        json.loads(json.dumps(document))["result"]["diagnostics"][0][
                            "stored_all"
                        ],
                        int(requested == 255),
                    )
                    writes = [
                        fields["messages"][0].data
                        for op, fields in backend.calls
                        if op == "write_messages"
                    ]
                    self.assertEqual(len(writes), 2)
                    self.assertEqual(writes[-1][-3:], bytes((0x19, 6, requested)))
                    self.assertFalse(connection.closed)

    def test_original12_p5_full_selected_j2534_and_distinct_report(self):
        from scripts.command_api import P5DiagnosticFacadeResult12
        from scripts.diagnostic_db import Language, Section, parse_database
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations
        from tests.test_toyota_session import SessionTests

        profile, _ = SessionTests().p5_existence_fixture(
            signals={0x1C: (1,), 0x1D: (2,), 0x27: (3,), 0x28: (4,)}, count=4
        )
        rule = bytearray(12)
        struct.pack_into("<I", rule, 0, 1)
        rule[8:10] = b"\x01\x01"
        profile.database.sections[66] = Section(66, 0, 1, False, bytes(rule))
        encoded = bytearray(
            _ddb(
                2,
                {
                    slot: (section.count, section.payload)
                    for slot, section in profile.database.sections.items()
                },
            )
        )
        struct.pack_into("<I", encoded, 28, 0x0100030C)
        language_bytes = bytearray(_language([f"label{i}" for i in range(1, 105)]))
        struct.pack_into("<I", language_bytes, 28, 0x0100030C)
        connection, backend = self.vin_connection(
            b"GetDiagCodeP5_DT.dll",
            [
                bytes.fromhex(text)
                for text in (
                    "59020100000101",
                    "590300000101",
                    "590400000100010112340405060107",
                )
            ],
            version=12,
            request=bytes.fromhex("190400000001"),
            command=0xAC,
            functions=(0xCD, 0xCE, 0xCF),
            diagnostic=parse_database(bytes(encoded)),
            language=Language(parse_database(bytes(language_bytes))),
        )
        workflow = ToyotaWorkflows.from_communication(
            connection, observations=WorkflowObservations(1, 0x12, source_version=12)
        )
        api = self.api(12)
        result = api.get_diag_code_p5_12(workflow, 1, 3, native_cancel_value=0)
        self.assertIs(type(result), P5DiagnosticFacadeResult12)
        self.assertEqual(result.return_code, 0)
        row = result.diagnostics[0]
        self.assertEqual([signal.pid for signal in row.signals], [1, 2, 3, 4])
        self.assertEqual(
            [signal.values[0].display for signal in row.signals],
            ["13", "15", "5", "17"],
        )
        self.assertEqual([block.pid for block in row.timestamps], [1, 2, 3])
        self.assertEqual(
            (row.timestamp_flags, row.odometer_flags, row.odometer.pid), (1, 1, 4)
        )
        self.assertEqual(row.native_byte220, 3)
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 3)
        document = json.loads(json.dumps(api.p5_diagnostic_report12(result)))
        self.assertNotIn("absolute", document["result"]["diagnostics"][0])
        self.assertNotIn("attachment", document["result"])
        state = workflow.native_output["state"]
        from scripts.freeze_p5 import P5FreezeState

        assert isinstance(state, P5FreezeState)
        failed = api.compose_p5_diagnostics12(
            CommandStatus(1, 0x90020706), state, previous=result
        )
        self.assertEqual(failed, replace(result, return_code=0x90020706))
        appended = api.compose_p5_diagnostics12(CommandStatus(), state, previous=result)
        self.assertEqual(appended.diagnostics, result.diagnostics * 2)
        before = len(backend.calls)
        with self.assertRaises(Cancelled):
            self.api(12, cancelled=lambda: True).get_diag_code_p5_12(
                workflow, 1, 3, native_cancel_value=0
            )
        with self.assertRaises(ValueError):
            self.api(18).get_diag_code_p5_12(workflow, 1, 3, native_cancel_value=0)
        self.assertEqual(len(backend.calls), before)
        self.assertFalse(connection.closed)
        from scripts.frame_transport import J2534Result

        backend.replies[:] = [J2534Result(code=9)]
        native_fault = api.get_diag_code_p5_12(
            workflow, 1, 0, native_cancel_value=0, previous=result
        )
        self.assertNotEqual(native_fault.return_code, 0)
        self.assertEqual(native_fault.diagnostics, result.diagnostics)
        marker = LookupError("authored original12 transport failure")
        with (
            patch.object(backend, "invoke", side_effect=marker),
            self.assertRaises(LookupError) as raised,
        ):
            api.get_diag_code_p5_12(workflow, 1, 0, native_cancel_value=0)
        self.assertIs(raised.exception, marker)

    def test_selected_p5_actual_workflow_to_diagnostic_facade_and_report(self):
        from scripts.diagnostic_db import Section
        from tests.test_toyota_session import SessionTests

        fixture = SessionTests()
        workflow, operations = fixture.native_p5_metadata_workflow_fixture(
            18, bytes.fromhex("59020100000101")
        )
        row = bytearray(88)
        filename = "GetDiagCodeP5_DT.dll\0".encode("utf-16le")
        row[: len(filename)] = filename
        struct.pack_into("<H", row, 80, workflow.profile.category)
        row[86] = 0xAC
        workflow.profile.catalog.management.sections[19] = Section(
            19, 0, 1, False, bytes(row)
        )
        api = self.api()
        result = api.get_diag_code_p5(workflow, 1, 0, native_cancel_value=0)
        self.assertEqual(result.return_code, 0)
        self.assertEqual(
            [(r.code, r.diag_type, r.status) for r in result.diagnostics], [(1, 1, 1)]
        )
        self.assertEqual(result.diagnostics[0].name, "name1")
        self.assertEqual(result.diagnostics[0].native_byte220, 3)
        self.assertEqual(operations.receive.call_count, 1)
        document = json.loads(json.dumps(api.p5_diagnostic_report(result)))
        self.assertEqual(document["result"]["diagnostics"][0]["code"], 1)
        self.assertNotIn("attachment", document["result"])
        operations.receive.return_value.code = 0x90020323
        failed = api.get_diag_code_p5(
            workflow, 1, 0, native_cancel_value=0, previous=result
        )
        self.assertEqual(failed, replace(result, return_code=0xA004020B))
        marker = LookupError("authored host failure")
        operations.receive.side_effect = marker
        with self.assertRaises(LookupError) as raised:
            api.get_diag_code_p5(workflow, 1, 0, native_cancel_value=0)
        self.assertIs(raised.exception, marker)
        before = operations.receive.call_count
        with self.assertRaises(Cancelled):
            self.api(cancelled=lambda: True).get_diag_code_p5(
                workflow, 1, 0, native_cancel_value=0
            )
        row[:80] = b"GetDiagCodeP5_DT.dll".ljust(80, b"\0")
        workflow.profile.catalog.management.sections[19] = Section(
            19, 0, 1, False, bytes(row)
        )
        with self.assertRaises(NotImplementedError):
            api.get_diag_code_p5(workflow, 1, 0, native_cancel_value=0)
        self.assertEqual(operations.receive.call_count, before)

    def test_p5_diagnostic_composition_append_filters_flags_and_log_error(self):
        from scripts.freeze_p5 import P5FreezeSignal, P5Value
        from tests.test_freeze_p5 import state

        selected = state(pattern=True)
        diagnostic = selected.add_diagnostic(1, status=0x81, diag_type=3)
        assert diagnostic is not None
        diagnostic.metadata.update(
            signature="P000001", name="failure", division_name="system"
        )
        diagnostic.existence_flags = 1
        diagnostic.normal_numbers = [1, 0x10]
        diagnostic.extended_numbers = [0xFF]
        diagnostic.stored_all = True
        metadata = selected.signal_metadata(
            selected.profile.database.sections[62].rows(64)[0]
        )
        signal = P5FreezeSignal(metadata, [P5Value(7, -128, 1)])
        diagnostic.signals = [
            signal,
            P5FreezeSignal(replace(metadata, pid=8000), signal.values),
        ]
        diagnostic.timestamps[0] = signal
        diagnostic.timestamp_flags = 1
        diagnostic.odometer = signal
        diagnostic.odometer_flags = 1
        diagnostic.absolute[0x3C] = signal
        diagnostic.absolute_flags = 1
        api = self.api()
        first = api.compose_p5_diagnostics(CommandStatus(), selected)
        item = first.diagnostics[0]
        self.assertEqual((item.diag_type, item.status, item.code), (3, 0x81, 1))
        self.assertEqual(
            (item.signature, item.name, item.division_name),
            ("P000001", "failure", "system"),
        )
        self.assertEqual((item.native_byte24, item.native_byte220), (0, 3))
        self.assertEqual(
            (item.normal_numbers, item.extended_numbers, item.stored_all),
            ((1, 0x10), (255,), 1),
        )
        self.assertEqual(len(item.signals), 1)
        self.assertEqual(len(item.timestamps), 3)
        self.assertEqual(len(item.absolute), 6)
        self.assertEqual(item.timestamps[1].pid, 0)
        self.assertEqual(item.absolute[0].values[0].index, 128)
        self.assertEqual(
            api.compose_p5_diagnostics(CommandStatus(1, 123), None, previous=first),
            replace(first, return_code=123),
        )
        recovered = api.compose_p5_diagnostics(
            CommandStatus(1, 0x90020706), selected, previous=first
        )
        self.assertEqual(recovered.return_code, 0)
        self.assertEqual(recovered.diagnostics, first.diagnostics * 2)
        diagnostic.existence_flags = diagnostic.timestamp_flags = (
            diagnostic.odometer_flags
        ) = diagnostic.absolute_flags = 0
        gated = api.compose_p5_diagnostics(CommandStatus(), selected).diagnostics[0]
        self.assertEqual(gated.signals, ())
        self.assertTrue(
            all(
                not block.values
                for block in (*gated.timestamps, gated.odometer, *gated.absolute)
            )
        )
        document = json.loads(json.dumps(api.p5_diagnostic_report(first)))
        self.assertEqual(document["operation"], "GetDiagCodeP5API")
        self.assertEqual(document["result"]["diagnostics"][0]["code"], 1)
        with self.assertRaises(NotImplementedError):
            self.api(12).compose_p5_diagnostics(CommandStatus(), selected)

    def test_p5_signal_native_projection_main_endian_and_special_raw(self):
        from scripts.freeze_p5 import P5FreezeSignal, P5Value
        from tests.test_freeze_p5 import state

        selected = state(pattern=True)
        row = next(iter(selected.profile.database.sections[62].rows(64)))
        metadata = replace(
            selected.signal_metadata(row),
            selector=12,
            start_bit=0,
            end_bit=15,
            multiplier=1,
            divisor=1,
            offset=0,
            precision=0,
            sign_mode=0,
        )
        signal = P5FreezeSignal(metadata, [P5Value(0x1234, -1, 0x101)])
        api = self.api()
        main = api._compose_p5_signal(signal, main=True)
        special = api._compose_p5_signal(signal, main=False)
        self.assertEqual(main.values[0].value, 0x3412)
        self.assertEqual(special.values[0].value, 0x1234)
        self.assertEqual(main.values[0].display, str(0x3412))
        self.assertEqual(special.values[0].display, str(0x1234))
        self.assertEqual(main.values[0].index, 255)
        self.assertEqual(main.values[0].kind, 0x101)
        original12 = self.api(12)._compose_p5_signal(signal, main=True)
        self.assertEqual(original12.values[0].value, 0x1234)
        self.assertEqual(original12.values[0].display, "-TypeErr-")
        character = P5FreezeSignal(replace(metadata, selector=4), [P5Value(0x80, 0, 1)])
        for build in (12, 18):
            with self.assertRaisesRegex(ValueError, "observed ANSI encoding"):
                self.api(build)._compose_p5_signal(character, main=True)
        time_signal = P5FreezeSignal(
            replace(metadata, selector=19, multiplier=1, divisor=1, offset=0),
            [P5Value(125, 0, 1)],
        )
        self.assertEqual(
            self.api(12)._compose_p5_signal(time_signal, main=True).values[0].display,
            "02:05",
        )
        self.assertEqual(
            api._compose_p5_signal(time_signal, main=True).values[0].display, "2:05"
        )
        self.assertEqual(main.conversion.core_words, (1, 0))
        self.assertEqual(main.conversion.patterns[0].flag, 0)
        self.assertEqual(main.conversion.patterns[0].low, 4)
        self.assertEqual(main.conversion.patterns[0].high, 5)
        self.assertEqual(signal.values[0].value, 0x1234)
        # Native callers pass explicit zero extra words for selector29.
        float_signal = P5FreezeSignal(replace(metadata, selector=29), signal.values)
        self.assertEqual(
            api._compose_p5_signal(float_signal, main=True).values[0].display, "0"
        )
        empty = api._compose_p5_signal(None, main=False)
        self.assertEqual((empty.pid, empty.values), (0, ()))
        self.assertEqual(empty.conversion.core_words, (1, 0))

    def test_plain_ts_timestamp_projection_and_type_boundaries(self):
        from scripts.command_api import PLAIN_NORMAL_SHA256
        from scripts.toyota_analysis import (
            COMMON18_SHA256,
            PlainAnalysisResult,
            PlainFreezeData,
            PlainTimestamp,
        )

        result = PlainAnalysisResult(
            0,
            PLAIN_NORMAL_SHA256[18][0],
            COMMON18_SHA256,
            (),
            (),
            (),
            (0,) * 6,
            0,
            18,
            "language",
            1,
            current_timestamp=PlainTimestamp(
                dword00=1,
                dword04=2,
                auxiliary=(3, 4),
                dword148=5,
                freezes=(
                    PlainFreezeData(
                        pid=7,
                        name="Name",
                        short_name="Short",
                        unit="unit",
                        selector=2,
                        multiplier=2,
                        divisor=1,
                        width=8,
                        values=((3, 9),),
                    ),
                    PlainFreezeData(multiplier=1, divisor=10, values=((4, 0),)),
                    PlainFreezeData(),
                ),
            ),
        )
        api = self.api()
        facade = api.compose_plain_analysis(CommandStatus(), result)
        stamp = facade.current_timestamp
        self.assertEqual(
            (stamp.dword00, stamp.dword04, stamp.auxiliary), (1, 2, (3, 4))
        )
        self.assertEqual(stamp.scalars, (3, 4, 5))
        first, second, third = stamp.metadata
        from scripts.command_api import (
            PlainFacadeFreezeMetadata,
            SavedOperationFacadeMetadata,
        )

        assert isinstance(first, PlainFacadeFreezeMetadata)
        assert isinstance(second, PlainFacadeFreezeMetadata)
        assert isinstance(third, SavedOperationFacadeMetadata)
        self.assertEqual(first.values[0].display, "6")
        self.assertEqual(first.values[0].status, 9)
        self.assertEqual(first.short_name, "Short")
        self.assertEqual(second.values[0].display, "-TypeErr-")
        self.assertEqual(third.words, (0, 1, 0, 0, 0))
        with self.assertRaises(TypeError):
            api._compose_plain_timestamp(cast(Any, {"private_path": "secret"}))
        with self.assertRaises(TypeError):
            replace(stamp, metadata=cast(Any, ({"private": "value"},) * 3))
        document = json.loads(json.dumps(api.plain_analysis_report(facade)))
        self.assertEqual(document["result"]["current_timestamp"]["scalars"], [3, 4, 5])

    def test_plain_p3_actual_selected_native_to_full_facade(self):
        from scripts.diagnostic_db import parse_database
        from scripts.toyota_analysis import PlainAnalysis
        from tests.test_toyota_analysis import DcmTests, RoBTests, database

        for build in (12, 18):
            fixture = DcmTests()
            fixture.setUp()
            self.addCleanup(fixture.doCleanups)
            fixture.plain_context()
            if build == 12:
                for filename, kind in (
                    ("Toyota.ddb", 1),
                    ("demo.ddb", 2),
                    ("M_English.ddb", 4),
                ):
                    path = fixture.root / filename
                    parsed = parse_database(path.read_bytes())
                    path.write_bytes(
                        database(
                            kind,
                            {
                                slot: (section.count, section.payload)
                                for slot, section in parsed.sections.items()
                            },
                            version=0x0100030C,
                        )
                    )
                fixture.profile = VehicleCatalog(fixture.root).build_profile(42)
            native = RoBTests()
            native.profile = fixture.profile
            native.replies = {
                key: value
                for key, value in fixture.replies.items()
                if key.startswith((b"\x21", b"\x23\0\0"))
            }
            connection, backend = native.native_rob_connection()
            self.addCleanup(connection.disconnect)
            api = self.api(build)
            result = api.get_analyze_work_factor(
                PlainAnalysis(connection.profile, connection.cache)
            )
            self.assertEqual(result.return_code, 0)
            self.assertEqual(
                [item.value for item in result.groups[0].items], [1, 2, 0, 1, 2, 0]
            )
            self.assertEqual(
                [item.content for item in result.groups[0].items],
                ["Content", "Signal", "7"] * 2,
            )
            self.assertEqual([item.value for item in result.current], [1, 4, 0])
            self.assertEqual(result.coefficient, 2)
            self.assertEqual(result.ts_groups, ())
            self.assertEqual(result.current_timestamp.scalars, (0, 0, 0))
            self.assertTrue(
                all(
                    isinstance(metadata, SavedOperationFacadeMetadata)
                    and metadata.words == (0, 1, 0, 0, 0)
                    for metadata in result.current_timestamp.metadata
                )
            )
            document = json.loads(json.dumps(api.plain_analysis_report(result)))
            self.assertEqual(document["operation"], "GetAnalyzeWorkFactorAPI")
            self.assertNotIn("capture", json.dumps(document))
            failed = api.compose_plain_analysis(
                CommandStatus(1, 77), None, previous=result
            )
            self.assertEqual(failed, replace(result, return_code=77))
            before = len(backend.calls)
            changed = PlainAnalysis(connection.profile, connection.cache)
            changed.source_sha256 = "unreconciled"
            with self.assertRaises(ValueError):
                api.get_analyze_work_factor(changed)
            with self.assertRaises(Cancelled):
                self.api(build, cancelled=lambda: True).get_analyze_work_factor(
                    PlainAnalysis(connection.profile, connection.cache)
                )
            with self.assertRaises(ValueError):
                self.api(18 if build == 12 else 12).get_analyze_work_factor(
                    PlainAnalysis(connection.profile, connection.cache)
                )
            self.assertEqual(len(backend.calls), before)
            self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 8)
            self.assertFalse(connection.closed)

    def test_original12_dcm_selected_native_wire_to_facade_and_json(self):
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result
        from scripts.toyota_analysis import DcmAnalysis
        from tests.test_toyota_analysis import DcmTests, RoBTests, database

        fixture = DcmTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        management = {
            slot: (section.count, section.payload)
            for slot, section in fixture.profile.catalog.management.sections.items()
        }
        language = {
            slot: (section.count, section.payload)
            for slot, section in parse_database(
                (fixture.root / "M_English.ddb").read_bytes()
            ).sections.items()
        }
        rows = []
        for index in range(9):
            row = bytearray(fixture.sections[36][1])
            struct.pack_into("<I", row, 8, 3 + index * 65537)
            rows.append(bytes(row))
        fixture.sections[36] = (9, b"".join(rows))
        for name, kind, sections in (
            ("Toyota.ddb", 1, management),
            ("demo.ddb", 2, fixture.sections),
            ("M_English.ddb", 4, language),
        ):
            (fixture.root / name).write_bytes(
                database(kind, sections, version=0x0100030C)
            )
        fixture.profile = VehicleCatalog(fixture.root).build_profile(42)
        native = RoBTests()
        native.profile = fixture.profile
        native.replies = {b"stream": b"\x41\0\x61\x05" + b"\xff" * 5, **fixture.replies}
        connection, backend = native.native_rob_connection()
        self.addCleanup(connection.disconnect)
        backend.replies.insert(1, J2534Result(code=9))
        assert isinstance(connection.profile, VehicleProfile)
        api = self.api(12)
        result = api.get_analyze_work_factor_dcm(
            DcmAnalysis(connection.profile, connection.cache)
        )
        self.assertEqual(result.return_code, 0)
        self.assertEqual(
            result.flat_records[0], DcmFlatFacadeRecord(5, 6, 7, 8, (9, 10, 11, 12, 13))
        )
        self.assertEqual(
            result.flat_records[1],
            DcmFlatFacadeRecord(7, 8, 9, 10, (11, 12, 13, 14, 15)),
        )
        document = json.loads(json.dumps(api.analysis_report(result)))
        self.assertEqual(document["source_version"], 12)
        before = len(backend.calls)
        with self.assertRaises(ValueError):
            self.api(18).get_analyze_work_factor_dcm(
                DcmAnalysis(connection.profile, connection.cache)
            )
        self.assertEqual(len(backend.calls), before)
        self.assertFalse(connection.closed)

    def test_selected_dcm_fixed_metadata_wire_flat_fields_and_native_error(self):
        from scripts.toyota_analysis import DcmAnalysis
        from tests.test_toyota_analysis import DcmTests, database

        fixture = DcmTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        rows = []
        for index in range(9):
            row = bytearray(fixture.sections[36][1])
            struct.pack_into("<I", row, 8, 3 + index * 65537)
            rows.append(row)
        fixture.sections[36] = (9, b"".join(rows))
        (fixture.root / "demo.ddb").write_bytes(database(2, fixture.sections))
        fixture.profile = VehicleCatalog(fixture.root).build_profile(42)
        cache = MonitorSupportCache(
            fixture.profile,
            fixture.exchange,
            "dcm-facade",
            bus_id=7,
            stream=fixture.stream,
        )
        provider = DcmAnalysis(fixture.profile, cache)
        previous = DcmFacadeResult(0, current_words=(1, 2, 3, 4, 5), current_valid=1)
        output = self.api().get_analyze_work_factor_dcm(provider, previous=previous)
        self.assertEqual(
            output.flat_records,
            (
                DcmFlatFacadeRecord(5, 6, 7, 8, (9, 10, 11, 12, 13)),
                DcmFlatFacadeRecord(7, 8, 9, 10, (11, 12, 13, 14, 15)),
            ),
        )
        self.assertEqual(output.current_words, previous.current_words)
        self.assertEqual(output.current_valid, 1)
        document = json.loads(json.dumps(self.api().analysis_report(output)))
        self.assertEqual(document["operation"], "GetAnalyzeWorkFactorDcmAPI")
        self.assertEqual(len(document["result"]["flat_records"]), 2)
        for request in tuple(fixture.replies):
            if request.startswith(b"\x23"):
                fixture.replies[request] = ToyotaCodecError(
                    "native read fault", 0x90020323
                )
        failed = self.api().get_analyze_work_factor_dcm(provider, previous=output)
        self.assertEqual(failed, replace(output, return_code=0x90020323))

    def test_dcm_rich_append_current_word_truncation_and_validity(self):
        from scripts.toyota_analysis import DcmAnalysis, RoBValue
        from tests.test_toyota_analysis import DcmTests

        fixture = DcmTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        acquired = DcmAnalysis(fixture.profile, fixture.cache).run(2)
        # Native rich-result field composition has its own synthetic vector;
        # the variable-record provider still rejects unsupported Execute mode4.
        current = tuple(RoBValue(value=65536 + i, format=4) for i in range(5))
        acquired = replace(acquired, mode=4, current=current)
        api = self.api()
        first = api.compose_dcm_analysis(CommandStatus(), acquired, mode=2)
        second = api.compose_dcm_analysis(
            CommandStatus(), acquired, mode=2, previous=first
        )
        self.assertEqual(second.groups, first.groups * 2)
        self.assertEqual(first.current_words, (0, 1, 2, 3, 4))
        self.assertEqual(first.current_valid, 1)
        invalid = replace(
            acquired, current=(replace(current[0], format=0x4004), *current[1:])
        )
        self.assertEqual(
            api.compose_dcm_analysis(CommandStatus(), invalid, mode=2).current_valid, 0
        )
        self.assertEqual(first.groups[0].records[0].items[0].value, 5)
        self.assertEqual(
            api.compose_dcm_analysis(
                CommandStatus(2, 77), None, mode=2, previous=first
            ),
            replace(first, return_code=77),
        )
        with self.assertRaises(ValueError):
            api.compose_dcm_analysis(
                CommandStatus(), replace(acquired, source_build=12), mode=2
            )

    def test_concrete_active_replay_preserves_native_stop_chronology(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = create_active_examples()
            for name, payload in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
            replay = ActiveReplay(json.loads(files["active-p3.json"]), profile)
            support = ActiveSupport(panel=lambda *_: True, legacy=lambda *_: True)
            listed = self.api().selected_active_tests(
                replay.catalog, "p3", support=support
            )
            self.assertEqual(tuple(item.signal_id for item in listed), (1,))
            initial = self.api().selected_active_initialization(
                replay.catalog,
                "p3",
                1,
                support=support,
            )
            self.assertIsInstance(initial, ActiveTestInitialization)
            self.assertEqual(
                (initial.initial_value, initial.minimum, initial.maximum), (0, 0, 255)
            )
            with self.assertRaisesRegex(ValueError, "versions differ"):
                self.api(12).selected_active_initialization(
                    replay.catalog, "p3", 1, support=support
                )
            arguments = {
                "value": 5,
                "auxiliary": 0,
                "display_index": None,
                "input_hex": "",
                "button_index": None,
            }
            result = self.api().selected_active_run(replay, 1, arguments)
            self.assertEqual(result["state"], "stopped")
            self.assertEqual(replay.report()["state"], "stopped")
            replay.close()


if __name__ == "__main__":
    unittest.main()
