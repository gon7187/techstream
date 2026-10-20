import unittest
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

from scripts.native_modules import identify_native_module
from scripts.programming_2026_common import NativeRuntime2026
from scripts.programming_2026_consolidated import (
    MODULE,
    SOURCE_SHA256,
    Branch,
    CANEMPSWriteContext,
    CANFCWriteContext,
    CANIdentifierContext,
    ConsolidatedCAN2026,
    ConsolidatedCanDiag2026,
    ConsolidatedControllerState,
    ConsolidatedError,
    ConsolidatedReadError,
    SilDiag2026,
    SILEMPSWriteContext,
    SILIdentifierContext,
    SoftwareIdentifierContext,
    SoftwareIDRecord,
    bind_can_emps_writer,
    bind_can_fc_writer,
    bind_native_context,
    bind_sil_emps_writer,
    consolidated_archive_password,
    consolidated_block_ranges,
    consolidated_block_sizes,
    consolidated_firmware_matches,
    consolidated_location_addresses,
    consolidated_progress_percent,
    get_can_identifier,
    get_can_software_info_identifiers,
    get_ecb_rom_identifiers,
    get_identifiers,
    get_sil_identifier,
    select_branch,
    write_can_emps,
    write_can_fc,
    write_sil_emps,
)

IDENTITY = identify_native_module(SOURCE_SHA256, MODULE)


class ControllerTests(unittest.TestCase):
    def test_initialized_cpu_tables_literal_firmware_and_range_semantics(self):
        self.assertTrue(consolidated_firmware_matches("4", 0xD0, False))
        self.assertFalse(consolidated_firmware_matches("4", 0x05, True))
        self.assertTrue(consolidated_firmware_matches("11", 0x83, True))
        self.assertFalse(consolidated_firmware_matches("11", 0x03, False))
        self.assertTrue(consolidated_firmware_matches("27", 0x80, False, wide=True))
        self.assertFalse(consolidated_firmware_matches("27", 0x80, False))
        self.assertTrue(consolidated_firmware_matches("125", 0x9E, True, wide=True))
        self.assertFalse(consolidated_firmware_matches("0125", 0x9E, True, wide=True))
        self.assertFalse(consolidated_firmware_matches("missing", 0, False))
        self.assertEqual(
            consolidated_block_ranges("124", 500), ((1, 64), (129, 2048), (9217, 10240))
        )
        self.assertEqual(consolidated_block_ranges("66", 5), ((17, 22), (23, 96)))
        self.assertEqual(
            consolidated_block_ranges("19", 30),
            ((1, 8), (9, 16), (17, 24), (25, 28), (29, 30)),
        )
        self.assertEqual(consolidated_block_ranges("unknown", 16), ((1, 1), (2, 16)))
        for kwargs in (
            {"firmware": 256},
            {"shrink": 1},
            {"wide": 1},
            {"cpu_type": "4\0"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                consolidated_firmware_matches(
                    **cast(
                        dict[str, Any],
                        {"cpu_type": "4", "firmware": 0x50, "shrink": False} | kwargs,
                    )
                )

    def test_05150_password_uses_actual_global_row_and_full_dword_byte_order(self):
        from scripts.programming_2026_common import (
            NativeCallbackLookupError,
            NativeGeneralParameters2026,
        )

        for order, expected in (
            ("0", 0x04030201),
            ("1", 0x01020304),
            ("65536", 0x01020304),
            ("-65536", 0x01020304),
        ):
            raw = (
                "ParamFileKeySystemProtocolMicon,PasswordAddress,ByteOrder\r\n5CAN11,00000002,"
                + order
                + "\r\n"
            ).encode()
            parameters = NativeGeneralParameters2026.from_sources(
                {"Parameter.ini": raw}, encoded=False
            )
            self.assertEqual(
                consolidated_archive_password(
                    bytes.fromhex("aabb01020304"), parameters, "5", "11", "CAN"
                ),
                expected,
            )
            with self.assertRaises(NativeCallbackLookupError):
                consolidated_archive_password(
                    bytes.fromhex("aabb01020304"), parameters, "6", "11", "CAN"
                )
        with self.assertRaises(LookupError):
            NativeGeneralParameters2026.from_sources(
                {"TCUWCanCommonFlashWriter.dll": raw}, encoded=False
            )

    def test_old_ecb_initialized_ranges_have_separate_default(self):
        self.assertEqual(
            consolidated_block_ranges("67", 500, old_spec_ecb=True),
            ((1, 16), (17, 120)),
        )
        self.assertEqual(
            consolidated_block_ranges("missing", 128, old_spec_ecb=True),
            ((1, 10), (11, 128)),
        )
        self.assertEqual(consolidated_block_ranges("67", 128), ((1, 1), (2, 128)))

    def test_progress_uses_actual_flash_size_and_native_int64_low_word(self):
        self.assertEqual(consolidated_progress_percent(1024, 4096), 12)
        self.assertEqual(consolidated_progress_percent(1024, 0), 0)
        self.assertEqual(consolidated_progress_percent(0xFFFFFFFF, 1), 0xFFFFFFCE)
        with self.assertRaises(ValueError):
            consolidated_progress_percent(True, 4096)

    def test_native_location_id_uses_response_then_request_then_final_fields(self):
        self.assertEqual(
            consolidated_location_addresses(bytes.fromhex("123456789abcdef0")),
            (
                bytes.fromhex("00005678"),
                bytes.fromhex("00001234"),
                bytes.fromhex("0000def0"),
            ),
        )
        with self.assertRaises(ValueError):
            consolidated_location_addresses(b"short")

    def test_actual_legacy_geometry_rules_do_not_use_new_flashutils_defaults(self):
        from scripts.programming_2026_common import NativeMemoryInfo

        def memory(size, block=64):
            return NativeMemoryInfo(0x10000, 0x10000 + size - 1, block, 0)

        for cpu in ("4", "5", "6"):
            self.assertEqual(
                consolidated_block_sizes(cpu, memory(0x10000)), (0x10000, 0)
            )
            self.assertEqual(
                consolidated_block_sizes(cpu, memory(0x80000)), (0x10000, 0x70000)
            )
            self.assertEqual(
                consolidated_block_sizes(cpu, memory(0x90000)),
                (0x10000, 0x70000, 0x10000),
            )
            with self.assertRaises(ValueError):
                consolidated_block_sizes(cpu, memory(0xFFFF))
        self.assertEqual(
            consolidated_block_sizes("7", memory(0x1234, 0)), (0x4000, 0x58000)
        )
        self.assertEqual(
            consolidated_block_sizes("73", memory(0x2001)), (0x1000, 0x1000)
        )
        self.assertEqual(consolidated_block_sizes("73", memory(0xFFF)), ())
        self.assertEqual(consolidated_block_sizes("19", memory(0x3001)), (0x1000,) * 3)
        self.assertEqual(
            consolidated_block_sizes("216", memory(0x80001, 0)), (0x40000, 0x40000, 1)
        )
        self.assertEqual(
            consolidated_block_sizes("04", memory(0x28001)), (0x10000, 0x10000, 0x8001)
        )
        with self.assertRaises(ValueError):
            consolidated_block_sizes("1", memory(0x10000, 0))

    def choose(self, contact, kind, cpu="1", **flags):
        return select_branch(IDENTITY, contact, kind, (cpu,), **flags)

    def test_all_seven_primary_getter_constructors(self):
        cases = (
            ("SIL", "1", "1", "sil_cid", 0xEF60, 0xF050),
            ("CAN", "45", "1", "can_electric_id", 0x17BC0, 0x17C80),
            ("CAN", "13", "56", "can_emps_id", 0x19BA0, 0x19C60),
            ("CAN", "5", "1", "can_software_info_id", 0x1F270, 0x1F550),
            ("SIL", "13", "57", "sil_emps_id", 0x21770, 0x21870),
            ("SIL", "37", "1", "sil_occupant_id", 0x23150, 0x231D0),
            ("SIL", "63", "1", "sil_vpns_id", 0x25EE0, 0x25F30),
        )
        for contact, kind, cpu, family, constructor, worker in cases:
            with self.subTest(family=family):
                branch = self.choose(contact, kind, cpu)
                self.assertEqual(
                    (branch.family, branch.constructor_rva, branch.worker_rva),
                    (family, constructor, worker),
                )
                self.assertFalse(branch.writing)

    def test_all_ten_writer_constructors(self):
        cases = (
            ("SIL", "1", "1", False, "sil_write"),
            ("SIL", "1", "17", False, "sil_m16c_write"),
            ("SIL", "13", "58", False, "sil_emps_write"),
            ("SIL", "37", "1", False, "sil_occupant_write"),
            ("CAN", "4", "1", False, "can_chassis_write"),
            ("CAN", "4", "1", True, "can_old_ecb_write"),
            ("CAN", "45", "1", False, "can_electric_write"),
            ("CAN", "13", "56", False, "can_emps_write"),
            ("CAN", "7", "27", False, "can_epb_write"),
            ("CAN", "5", "1", False, "can_fc_write"),
        )
        for contact, kind, cpu, old, expected in cases:
            with self.subTest(expected=expected):
                branch = self.choose(contact, kind, cpu, writing=True, old_spec_ecb=old)
                self.assertEqual(branch.family, expected)
                self.assertTrue(branch.writing)

    def test_literal_comparison_priority_and_selected_cpu(self):
        for cpu in ("57", "58", "59", "60"):
            for kind in ("37", "63", "8", "30"):
                self.assertEqual(self.choose("SIL", kind, cpu).family, "sil_emps_id")
        branch = select_branch(
            IDENTITY, "SIL", "37", ("57", "17"), writing=True, cpu_index=1
        )
        self.assertEqual(branch.family, "sil_m16c_write")
        branch = select_branch(
            IDENTITY, "SIL", "37", ("1", "57"), writing=True, cpu_index=1
        )
        self.assertEqual(branch.family, "sil_occupant_write")
        self.assertTrue(self.choose("CAN", "4").requires_ecb_fallback)
        self.assertFalse(self.choose("CAN", "5").requires_ecb_fallback)
        self.assertEqual(self.choose("CAN", "45", "").family, "can_electric_id")
        self.assertEqual(self.choose("CAN", "13", "55").family, "can_software_info_id")

    def test_unsupported_routes_never_alias_an_older_family(self):
        for contact, kind, cpu, writing in (
            ("P5-CAN", "4", "1", False),
            ("P5-CAN", "4", "1", True),
            ("CAN", "17", "1", False),
            ("CAN", "7", "26", True),
            ("SIL", "11", "57", False),
            ("SIL", "11", "17", True),
            ("SIL", "8", "17", True),
            ("SIL", "30", "1", False),
            ("CAN", "05", "1", False),
            ("can", "5", "1", False),
        ):
            with self.subTest(contact=contact, kind=kind, writing=writing):
                with self.assertRaises(ConsolidatedError) as error:
                    self.choose(contact, kind, cpu, writing=writing)
                self.assertEqual(error.exception.code, 9999)

    def test_bad_types_bounds_and_source_aliases_rejected(self):
        old = replace(IDENTITY, cuw_build="18")
        for identity, contact, kind, cpus, flags in (
            (old, "CAN", "45", ("1",), {}),
            (
                replace(IDENTITY, module_name="TCUWCanM16CFlashWriter.dll"),
                "CAN",
                "45",
                ("1",),
                {},
            ),
            (IDENTITY, "CAN\0", "45", ("1",), {}),
            (IDENTITY, "CAN", "45", ["1"], {}),
            (IDENTITY, "CAN", "45", (), {}),
            (IDENTITY, "CAN", "45", ("1",), {"cpu_index": True}),
            (IDENTITY, "CAN", "45", ("1",), {"writing": 1}),
            (IDENTITY, "CAN", "45", ("1",), {"cpu_index": 1}),
        ):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                select_branch(
                    identity, contact, kind, cast(Any, cpus), **cast(Any, flags)
                )


class CANGetterTests(unittest.TestCase):
    def context(self, family="can_emps_id"):
        addresses = {
            "can_emps_id": (b"\x07\xa1", b"\x07\xa9"),
            "can_electric_id": (b"\x07\xc1", b"\x07\xc9"),
        }
        return CANIdentifierContext(IDENTITY, Branch(family, False), *addresses[family])

    def runtime(self, context, replies, fault=None):
        self.events, self.resources, self.cancelled = [], [], False
        values = iter(replies)

        def action(event, remaining):
            self.assertGreater(remaining, 0)
            self.events.append(event)
            operation = event["operation"]
            if fault:
                fault(event)
            if operation == "connect":
                self.resources.append("connection")
            elif operation == "disconnect":
                self.resources.remove("connection")
            elif operation == "start_flow_control_filter":
                self.resources.append("filter")
                return 19
            elif operation == "stop_filter":
                self.assertEqual(event["identifier"], 19)
                self.resources.remove("filter")
            elif operation == "get_timeout":
                return 1000
            elif operation == "write_messages":
                return 1
            elif operation == "read_specified_can_message":
                self.assertEqual(event["address"], b"\0\0" + context.response)
                return next(values)
            return None

        return NativeRuntime2026(action, cancelled=lambda: self.cancelled)

    def test_emps_actual_primitives_and_fixed_native_address(self):
        ctx = self.context()
        rt = self.runtime(ctx, [b"\0\0\x07\xa9\xea\x1eAUTHORED"])
        self.assertEqual(get_can_identifier(ctx, rt), "AUTHORED")
        self.assertEqual(self.resources, [])
        self.assertEqual(
            [e["data"] for e in self.events if e["operation"] == "write_messages"],
            [b"\0\0\x07\xa1\xaa\x1e"],
        )
        self.assertEqual(
            [e["milliseconds"] for e in self.events if e["operation"] == "wait"], [2000]
        )
        self.assertEqual(rt.close(), [])

    def test_native_emps_cancel_guards_skip_or_validate_retained_output(self):
        for answers, fails, writes in (
            ((True,), False, 0),
            ((False, True), False, 1),
            ((False, False, True), True, 1),
        ):
            ctx = self.context()
            rt = self.runtime(ctx, [])
            values = iter(answers)
            rt.native_cancelled = lambda values=values: next(values, True)
            if fails:
                with self.assertRaises(ConsolidatedError) as caught:
                    get_identifiers(ctx, rt)
                self.assertEqual(caught.exception.code, 3)
            else:
                self.assertEqual(get_identifiers(ctx, rt), ())
            self.assertEqual(
                len(
                    [
                        event
                        for event in self.events
                        if event["operation"] == "write_messages"
                    ]
                ),
                writes,
            )
            self.assertFalse(
                any(
                    event["operation"] == "read_specified_can_message"
                    for event in self.events
                )
            )
            self.assertEqual(self.resources, [])

    def test_native_electric_cancel_inside_exchange_still_writes_request(self):
        ctx = self.context("can_electric_id")
        rt = self.runtime(ctx, [])
        rt.native_cancelled = lambda: True
        self.assertEqual(get_identifiers(ctx, rt), ())
        self.assertEqual(
            [
                event["data"]
                for event in self.events
                if event["operation"] == "write_messages"
            ],
            [bytes.fromhex("000007c11a81")],
        )
        self.assertEqual(self.resources, [])
        self.assertEqual(rt.close(), [])

    def test_emps_pending_bound_and_native_tester_present(self):
        ctx = self.context()
        address = b"\0\0" + ctx.response
        rt = self.runtime(
            ctx, [address + b"\x7f\xaa\x78"] * 149 + [address + b"\xea\x1eAUTHORED"]
        )
        self.assertEqual(get_can_identifier(ctx, rt), "AUTHORED")
        rt = self.runtime(ctx, [address + b"\x7f\xaa\x78"] * 150)
        with self.assertRaises(ConsolidatedError):
            get_can_identifier(ctx, rt)
        self.assertEqual(
            [e["data"] for e in self.events if e["operation"] == "write_messages"][-1],
            b"\0\0\x07\xa1\x3e\x02",
        )
        self.assertEqual(self.resources, [])

    def test_electric_uses_source_diag_helper_and_five_char_identifier(self):
        ctx = self.context("can_electric_id")
        rt = self.runtime(ctx, [b"\0\0\x07\xc9\x5aID123"])
        self.assertEqual(get_can_identifier(ctx, rt), "ID123")
        self.assertEqual(
            [e["data"] for e in self.events if e["operation"] == "write_messages"],
            [b"\0\0\x07\xc1\x1a\x81"],
        )
        self.assertEqual(self.resources, [])

    def test_native_c_string_termination_is_retained(self):
        ctx = self.context()
        rt = self.runtime(ctx, [b"\0\0\x07\xa9\xea\x1eID\0THERE"])
        self.assertEqual(get_can_identifier(ctx, rt), "ID")

    def test_malformed_response_failure_and_cancellation_release_resources(self):
        ctx = self.context()
        for reply in (
            b"",
            b"\0\0\x07\xa8\xea\x1eAUTHORED",
            b"\0\0\x07\xa9\xea\x1eSHORT",
            b"\0\0\x07\xa9\xea\x1e\0UTHORED",
            b"\0\0\x07\xa9\x7f\xaa\x22",
        ):
            rt = self.runtime(ctx, [reply])
            with self.assertRaises(ValueError):
                get_can_identifier(ctx, rt)
            self.assertEqual(self.resources, [])

        def fault(event):
            if event["operation"] == "read_specified_can_message":
                raise OSError("authored unavailable transport")

        rt = self.runtime(ctx, [], fault)
        with self.assertRaises(OSError):
            get_can_identifier(ctx, rt)
        self.assertEqual(self.resources, [])

        def cancel(event):
            if event["operation"] == "write_messages":
                self.cancelled = True

        rt = self.runtime(ctx, [], cancel)
        with self.assertRaises(InterruptedError):
            get_can_identifier(ctx, rt)
        self.assertEqual(self.resources, [])

    def test_ecb_rom_two_source_selectors_and_exact_wire_bytes(self):
        ctx = SimpleNamespace(response=b"\x07\xb8")
        rt = self.runtime(
            ctx,
            [
                b"\0\0\x07\xb8\xe4\0" + bytes(5) + b"FIRSTROM",
                b"\0\0\x07\xb8\xe4\x02" + bytes(5) + b"SECONDID",
            ],
        )
        self.assertEqual(
            get_ecb_rom_identifiers(IDENTITY, rt), ("FIRSTROM", "SECONDID")
        )
        self.assertEqual(
            [e["data"] for e in self.events if e["operation"] == "write_messages"],
            [
                b"\0\0\x07\xb0\xa4\0\x08\0\0\x48\x3c",
                b"\0\0\x07\xb0\xa4\x02\x08\0\0\x48\x3c",
            ],
        )
        self.assertEqual(self.resources, [])

    def test_actual_imported_cuw_metadata_selects_fixed_can_consumers(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw

        for kind, cpu, family, response, expected in (
            ("13", "56", "can_emps_id", b"\xea\x1eAUTHORED", "AUTHORED"),
            ("45", "1", "can_electric_id", b"\x5aID123", "ID123"),
        ):
            metadata = (
                "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\n"
                f"ContactType=CAN\nKindOfECU={kind}\n[CPU01]\nCPUType={cpu}\nCPUImageName=main\n"
                "[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n"
                "01_Length=00000004\nDataFormatID=01\n"
            )
            container = parse_cuw(metadata_container(metadata, [(b"main", b"DATA")], 1))
            ctx = bind_native_context(container, IDENTITY)
            self.assertEqual(ctx.branch.family, family)
            assert isinstance(ctx, CANIdentifierContext)
            rt = self.runtime(ctx, [b"\0\0" + ctx.response + response])
            self.assertEqual(get_can_identifier(ctx, rt), expected)
            self.assertEqual(self.resources, [])

    def test_address_substitution_and_unsupported_worker_rejected_before_io(self):
        ctx = self.context()
        for change in (
            {"request": b"\x07\xe0"},
            {"response": b"\x07\xe8"},
            {"branch": Branch("sil_cid", False)},
            {"identity": replace(IDENTITY, cuw_build="18")},
        ):
            with self.assertRaises(ValueError):
                replace(ctx, **change)


class SILGetterTests(unittest.TestCase):
    def run_getter(
        self, family, kind, replies, fault=None, fast_status=0, native_cancelled=None
    ):
        from scripts.j2534_2026 import NativeMessage

        context = SILIdentifierContext(
            IDENTITY,
            Branch(family, False),
            kind,
        )
        self.events, self.connected, self.cancelled = [], False, False
        values = iter(replies)

        def action(event, remaining):
            self.assertGreater(remaining, 0)
            self.events.append(event)
            name = event["operation"]
            if fault:
                fault(event)
            if name == "connect":
                self.assertEqual(event["protocol"], 3)
                self.connected = True
            elif name == "disconnect":
                self.connected = False
            elif name == "get_timeout":
                return 1000
            elif name == "write_messages":
                self.assertEqual(event["protocol"], 3)
                return 1
            elif name in ("read_messages", "read_after_indication"):
                return next(values)
            elif name == "fast_init":
                return NativeMessage(3, b"", rx_status=fast_status)
            elif name == "five_baud_init":
                self.assertEqual(event["data"], b"\x33")
                return b""
            return None

        rt = NativeRuntime2026(
            action, cancelled=lambda: self.cancelled, native_cancelled=native_cancelled
        )
        return (
            get_identifiers(context, rt)
            if family in ("sil_vpns_id", "sil_cid")
            else get_sil_identifier(context, rt)
        )

    def test_emps_fast_init_and_full_native_wire(self):
        reply = b"\x88\xf1\x32\xdc\x0cAUTHORED\0"
        self.assertEqual(self.run_getter("sil_emps_id", "13", [reply]), "AUTHORED")
        fast = next(e for e in self.events if e["operation"] == "fast_init")
        self.assertEqual(fast["data"], SilDiag2026.packet(b"\x81\x32\xf1\x81"))
        writes = [e["data"] for e in self.events if e["operation"] == "write_messages"]
        self.assertEqual(writes, [SilDiag2026.packet(b"\x82\x32\xf1\x9c\x0c")])
        self.assertEqual(
            [e["parameters"] for e in self.events if e["operation"] == "control_io"],
            [((1, 9600),), ((0x14, 35),), ((0x15, 50),)],
        )
        self.assertFalse(self.connected)

    def test_native_sil_outer_cancel_skips_request_but_inner_cancel_appends_empty_id(
        self,
    ):
        for family, kind in (("sil_emps_id", "13"), ("sil_occupant_id", "37")):
            result = self.run_getter(family, kind, [], native_cancelled=lambda: True)
            self.assertIsNone(result)
            self.assertFalse(
                any(event["operation"] == "write_messages" for event in self.events)
            )
            self.assertFalse(self.connected)
            result = self.run_getter(
                family,
                kind,
                [],
                native_cancelled=lambda: any(
                    event["operation"] == "write_messages" for event in self.events
                ),
            )
            self.assertEqual(result, "")
            self.assertFalse(
                any(
                    event["operation"] in ("read_messages", "read_after_indication")
                    for event in self.events
                )
            )
            self.assertFalse(self.connected)

    def test_occupant_fast_init_indication_and_native_id(self):
        # Nonterminal FAST_INIT indication consumes one additional raw message.
        reply = b"\x88\xf1\x5b\x61\xdfID123\0\0"
        self.assertEqual(
            self.run_getter(
                "sil_occupant_id", "37", [b"authored init", reply], fast_status=2
            ),
            "ID123",
        )
        self.assertEqual(
            [e["data"] for e in self.events if e["operation"] == "write_messages"],
            [SilDiag2026.packet(b"\x82\x5b\xf1\x21\xdf")],
        )
        self.assertEqual(
            [e["milliseconds"] for e in self.events if e["operation"] == "wait"],
            [1000, 100, 100, 100],
        )
        self.assertFalse(self.connected)

    def test_serial_pending_receives_again_but_busy_resends(self):
        reply = b"\x88\xf1\x32\xdc\x0cAUTHORED\0"
        self.assertEqual(
            self.run_getter(
                "sil_emps_id",
                "13",
                [b"\x88\xf1\x32\x7f\x9c\x21", b"\x88\xf1\x32\x7f\x9c\x78", reply],
            ),
            "AUTHORED",
        )
        writes = [e for e in self.events if e["operation"] == "write_messages"]
        self.assertEqual(len(writes), 2)
        self.assertIn(
            5000,
            [e["milliseconds"] for e in self.events if e["operation"] == "set_timeout"],
        )
        self.assertFalse(self.connected)

    def test_serial_native_pending_and_busy_bounds_restore_and_disconnect(self):
        for code, count in ((0x78, 150), (0x21, 256)):
            with self.assertRaises(ConsolidatedError):
                self.run_getter(
                    "sil_emps_id",
                    "13",
                    [bytes((0x88, 0xF1, 0x32, 0x7F, 0x9C, code))] * count,
                )
            self.assertFalse(self.connected)
            self.assertEqual(
                [
                    e["milliseconds"]
                    for e in self.events
                    if e["operation"] == "set_timeout"
                ][-1],
                1000,
            )
        writes = [e for e in self.events if e["operation"] == "write_messages"]
        self.assertEqual(len(writes), 256)

    def test_vpns_discovery_and_selected_native_identifiers(self):
        discovery = b"\x84\xf1\xd3\x5a\x88\0\x01\x02\0"
        first = b"\x93\xf1\xd3\x5a\x88\x01" + b"AUTHORED-ID     " + b" \0"
        second = b"\x93\xf1\xd3\x5a\x88\x02" + b"NEXT\0".ljust(16, b"X") + b"\0"
        self.assertEqual(
            self.run_getter("sil_vpns_id", "63", [discovery, first, second]),
            ("AUTHORED-ID", "NEXT"),
        )
        writes = [e["data"] for e in self.events if e["operation"] == "write_messages"]
        self.assertEqual(
            writes,
            [
                SilDiag2026.packet(b"\x83\xd3\xf1\x1a\x88" + bytes((selector,)))
                for selector in (0, 1, 2)
            ],
        )
        self.assertEqual(
            [e["parameters"] for e in self.events if e["operation"] == "control_io"],
            [((1, 10400),), ((0x14, 25),), ((0x15, 50),)],
        )
        self.assertFalse(self.connected)
        for selectors in (b"", b"\x01\0\x02"):
            with self.assertRaises(ConsolidatedError):
                self.run_getter(
                    "sil_vpns_id", "63", [b"\x84\xf1\xd3\x5a\x88\0" + selectors + b"\0"]
                )
            self.assertFalse(self.connected)

    def test_imported_sil_metadata_reaches_each_implemented_consumer(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw
        from scripts.j2534_2026 import NativeMessage

        for kind, cpu, replies, expected in (
            ("13", "57", [b"\x88\xf1\x32\xdc\x0cAUTHORED\0"], ("AUTHORED",)),
            ("37", "1", [b"\x88\xf1\x5b\x61\xdfID123\0\0"], ("ID123",)),
            (
                "63",
                "1",
                [
                    b"\x84\xf1\xd3\x5a\x88\0\x01\0",
                    b"\x93\xf1\xd3\x5a\x88\x01" + b"AUTHORED".ljust(16, b" ") + b"\0",
                ],
                ("AUTHORED",),
            ),
        ):
            metadata = (
                "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\n"
                f"ContactType=SIL\nKindOfECU={kind}\n[CPU01]\nCPUType={cpu}\nCPUImageName=main\n"
                "[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000004\nDataFormatID=01\n"
            )
            ctx = bind_native_context(
                parse_cuw(metadata_container(metadata, [(b"main", b"DATA")], 1)),
                IDENTITY,
            )
            values, events = iter(replies), []

            def action(event, remaining, events=events, values=values):
                events.append(event)
                if event["operation"] in ("read_messages", "read_after_indication"):
                    return next(values)
                if event["operation"] == "get_timeout":
                    return 1000
                if event["operation"] == "fast_init":
                    return NativeMessage(3, b"")
                if event["operation"] == "write_messages":
                    return 1
                return None

            rt = NativeRuntime2026(action)
            self.assertEqual(get_identifiers(ctx, rt), expected)
            self.assertEqual(events[-1]["operation"], "disconnect")
            self.assertEqual(rt.close(), [])

    def test_sil_getter_through_actual2026_j2534_state_machine(self):
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult

        operations, replies = [], []
        handles = [0]

        def provider(operation, remaining):
            operations.append(operation)
            self.assertGreater(remaining, 0)
            name = operation["operation"]
            if name in ("passthru_open", "passthru_connect", "passthru_start_filter"):
                handles[0] += 1
                return PrimitiveResult(value=handles[0])
            if name == "passthru_ioctl" and operation["ioctl"] == 5:
                self.assertEqual(
                    operation["message"].data, SilDiag2026.packet(b"\x81\x32\xf1\x81")
                )
                return PrimitiveResult(value=NativeMessage(3, b"", rx_status=0))
            if name == "passthru_write":
                self.assertEqual(
                    operation["messages"][0].data,
                    SilDiag2026.packet(b"\x82\x32\xf1\x9c\x0c"),
                )
                replies.append(NativeMessage(3, b""))
                replies.append(NativeMessage(3, b"\x88\xf1\x32\xdc\x0cAUTHORED\0"))
                return PrimitiveResult(value=1)
            if name == "passthru_read":
                return PrimitiveResult(value=(replies.pop(0),) if replies else ())
            return PrimitiveResult()

        device = J2534Device2026(provider)
        rt = NativeRuntime2026(device.primitive)
        ctx = SILIdentifierContext(IDENTITY, Branch("sil_emps_id", False), "13")
        self.assertEqual(get_sil_identifier(ctx, rt), "AUTHORED")
        self.assertIsNone(device.channel_id)
        self.assertFalse(device.filters)
        self.assertEqual(rt.close(), [])
        device.close()
        self.assertIsNone(device.device_id)
        self.assertEqual(
            [e["operation"] for e in operations].count("passthru_close"), 1
        )

    @staticmethod
    def cid_messages(target, text):
        raw = text.encode("ascii")
        assert len(raw) == 16
        return [bytes((0x48, 0x6B, target, 0x49, 3, 4, 0))] + [
            bytes((0x48, 0x6B, target, 0x49, 4, index + 1))
            + raw[index * 4 : index * 4 + 4]
            + b"\0"
            for index in range(4)
        ]

    def test_sil_obd_cid_exact_native_four_packet_assembly(self):
        self.assertEqual(
            self.run_getter(
                "sil_cid", "0", self.cid_messages(0x10, "AUTHORED-CID-001")
            ),
            ("AUTHORED-CID-001",),
        )
        self.assertEqual(
            [e["data"] for e in self.events if e["operation"] == "write_messages"],
            [
                SilDiag2026.packet(b"\x68\x6a\xf1\x09\x03"),
                SilDiag2026.packet(b"\x68\x6a\xf1\x09\x04"),
            ],
        )
        self.assertFalse(self.connected)

    def test_vpns_empty_second_id_and_inner_cancel_preserve_partial_ids(self):
        discovery = bytes.fromhex("85f1d35a8800010200")
        first = bytes.fromhex("93f1d35a8801") + b"AUTHORED".ljust(16, b" ") + b"\0"
        second = bytes.fromhex("93f1d35a8802") + b"\0" * 16 + b"\0"
        for cancel in (False, True):
            with (
                self.subTest(cancel=cancel),
                self.assertRaises(ConsolidatedError) as error,
            ):
                self.run_getter(
                    "sil_vpns_id",
                    "63",
                    [discovery, first, second],
                    native_cancelled=lambda cancel=cancel: (
                        cancel
                        and any(
                            event["operation"] == "write_messages"
                            and event["data"][3:6] == bytes.fromhex("1a8802")
                            for event in self.events
                        )
                    ),
                )
            self.assertEqual(error.exception.code, 3)
            self.assertEqual(
                getattr(error.exception, "partial_identifiers", None), ("AUTHORED",)
            )
            self.assertFalse(self.connected)

    def test_sil_obd_native_cancel_before_init_and_after_completed_cid(self):
        self.assertEqual(
            self.run_getter("sil_cid", "0", [], native_cancelled=lambda: True), ()
        )
        self.assertFalse(
            any(event["operation"] == "five_baud_init" for event in self.events)
        )
        self.assertEqual(
            self.run_getter(
                "sil_cid",
                "0",
                self.cid_messages(0x10, "AUTHORED-CID-001"),
                native_cancelled=lambda: (
                    sum(
                        event["operation"] == "read_after_indication"
                        for event in self.events
                    )
                    >= 5
                ),
            ),
            ("AUTHORED-CID-001",),
        )
        self.assertEqual(
            sum(
                event["operation"] == "control_io" and event["ioctl"] == 8
                for event in self.events
            ),
            1,
        )
        self.assertFalse(self.connected)

    def test_sil_fast_count_cancel_still_writes0904_then_clears_rx(self):
        bad = b"\x48\x6b\x10\x49\x03\0\0"
        self.assertEqual(
            self.run_getter(
                "sil_cid",
                "0",
                [bad],
                native_cancelled=lambda: any(
                    event["operation"] == "write_messages"
                    and event["data"] == bytes.fromhex("8213f1090392")
                    for event in self.events
                ),
            ),
            (),
        )
        self.assertEqual(
            [
                event["data"]
                for event in self.events
                if event["operation"] == "write_messages"
            ],
            [
                bytes.fromhex("686af10903cf"),
                bytes.fromhex("8213f1090392"),
                bytes.fromhex("8213f1090493"),
            ],
        )
        self.assertEqual(
            sum(
                event["operation"] == "control_io" and event["ioctl"] == 8
                for event in self.events
            ),
            3,
        )
        self.assertFalse(self.connected)

    def test_sil_asm_proven_protocol_retry_and_engine_plus_ect(self):
        bad = b"\x48\x6b\x10\x49\x03\0\0"
        replies = (
            [bad, bad]
            + self.cid_messages(0x10, "AUTHORED-CID-001")
            + self.cid_messages(0x19, "AUTHORED-CID-002")
        )
        self.assertEqual(
            self.run_getter("sil_cid", "0", replies),
            ("AUTHORED-CID-001", "AUTHORED-CID-002"),
        )
        fast = [e["data"][1] for e in self.events if e["operation"] == "fast_init"]
        self.assertEqual(fast, [0x13, 0x10, 0x19])
        self.assertFalse(self.connected)

    def test_sil_secondary_ect_native_failure_keeps_primary_ids(self):
        bad = b"\x48\x6b\x10\x49\x03\0\0"
        for failures, target in ((2, 0x10), (3, 0x13)):
            replies = (
                [bad] * failures + self.cid_messages(target, "AUTHORED-CID-001") + [bad]
            )
            self.assertEqual(
                self.run_getter("sil_cid", "0", replies), ("AUTHORED-CID-001",)
            )
            self.assertFalse(self.connected)
            self.assertEqual(
                sum(event["operation"] == "fast_init" for event in self.events),
                failures + 1,
            )
        with self.assertRaises(ConsolidatedReadError) as error:
            self.run_getter("sil_cid", "0", [bad] * 4)
        self.assertEqual(error.exception.code, 3)
        self.assertEqual(error.exception.partial_identifiers, ())

    def test_serial_fault_cancel_and_wrong_header_release_connection(self):
        with self.assertRaises(ConsolidatedError):
            self.run_getter("sil_occupant_id", "37", [b"\x88\xf1\x5a\x61\xdfID123\0\0"])
        self.assertFalse(self.connected)

        def fail(event):
            if event["operation"] in ("read_messages", "read_after_indication"):
                raise OSError("authored read fault")

        with self.assertRaises(OSError):
            self.run_getter("sil_emps_id", "13", [], fault=fail)
        self.assertFalse(self.connected)

        def cancel(event):
            if event["operation"] == "write_messages":
                self.cancelled = True

        with self.assertRaises(InterruptedError):
            self.run_getter("sil_emps_id", "13", [], fault=cancel)
        self.assertFalse(self.connected)


class SoftwareInfoGetterTests(unittest.TestCase):
    def runtime(self, *, fail_discovery=False, fail_rom=False, fail_read=False):
        self.events, self.resources = [], []
        last, response = b"", b""

        def action(event, remaining):
            nonlocal last, response
            self.assertGreater(remaining, 0)
            self.events.append(event)
            name = event["operation"]
            if name == "connect":
                self.resources.append("connection")
            elif name == "disconnect":
                self.resources.remove("connection")
            elif name == "start_flow_control_filter":
                self.resources.append("filter")
                response = event["response_address"]
                return 17
            elif name == "stop_filter":
                self.resources.remove("filter")
            elif name == "get_timeout":
                return 1000
            elif name == "write_messages":
                last = event["data"][len(response) :]
                return 1
            elif name == "read_specified_can_message":
                self.assertEqual(event["address"], response)
                if fail_read:
                    raise OSError("authored raw I/O fault")
                if last[:1] == b"\xa4":
                    if fail_rom:
                        return response + b"\x7f\xa4\x22"
                    return (
                        response
                        + bytes((0xE4, last[1]))
                        + bytes(5)
                        + (b"FIRSTROM" if last[1] == 0 else b"SECONDID")
                    )
                if last == b"\x1a\x88\0":
                    return response + (
                        b"\x7f\x1a\x22" if fail_discovery else b"\x5a\x88\0\x01\x02"
                    )
                return (
                    response
                    + bytes((0x5A, 0x88, last[2]))
                    + (b"FIRST-ID" if last[2] == 1 else b"SECOND-ID").ljust(16, b" ")
                )
            return None

        return NativeRuntime2026(action)

    def test_all_six_source_table_routes_and_native_node_order(self):
        routes = {
            "4": ("000007b0",),
            "5": ("000007d1",),
            "6": ("000007d3", "00000724", "000007d2"),
            "7": ("000007502c",),
            "13": ("000007a1",),
            "51": ("00000742",),
        }
        for kind, nodes in routes.items():
            with self.subTest(kind=kind):
                rt = self.runtime()
                ctx = SoftwareIdentifierContext(IDENTITY, kind, "1")
                state = ConsolidatedControllerState()
                result = get_identifiers(ctx, rt, state)
                self.assertEqual(result, ("FIRST-ID", "SECOND-ID") * len(nodes))
                self.assertEqual(
                    state.request_id_records,
                    tuple(node[4:].upper() for node in nodes for _ in range(2)),
                )
                self.assertEqual(
                    tuple(record.identifier for record in state.software_id_records),
                    result,
                )
                self.assertEqual(
                    tuple(record.request.hex() for record in state.software_id_records),
                    tuple(node[4:] for node in nodes for _ in range(2)),
                )
                self.assertEqual(
                    tuple(record.extended for record in state.software_id_records),
                    (kind == "7",) * len(result),
                )
                requests = [
                    e["request_address"].hex()
                    for e in self.events
                    if e["operation"] == "start_flow_control_filter"
                ]
                self.assertEqual(requests, [node for node in nodes for _ in range(2)])
                self.assertEqual(self.resources, [])
                if kind == "7":
                    self.assertTrue(
                        all(
                            e["tx_flags"] == 0x80
                            for e in self.events
                            if e["operation"] == "write_messages"
                        )
                    )
                    self.assertEqual(
                        [
                            e["parameters"]
                            for e in self.events
                            if e["operation"] == "control_io"
                        ],
                        [((0x1E, 1),), ((0x1E, 0),)],
                    )

    def test_actual_ecb_fallback_sets_both_native_flags_only_after_success(self):
        state = ConsolidatedControllerState()
        ctx = SoftwareIdentifierContext(IDENTITY, "4", "1")
        rt = self.runtime(fail_discovery=True)
        self.assertEqual(get_identifiers(ctx, rt, state), ("FIRSTROM", "SECONDID"))
        self.assertTrue(state.old_spec_ecb)
        self.assertTrue(state.native_context_9e8)
        self.assertEqual(state.request_id_records, ("07B0", "07B0"))
        self.assertEqual(state.software_id_records, ())
        operations = [e["operation"] for e in self.events]
        self.assertEqual(operations.count("connect"), 2)
        self.assertLess(
            operations.index("disconnect"),
            operations.index("connect", operations.index("connect") + 1),
        )
        self.assertEqual(self.resources, [])
        state = ConsolidatedControllerState()
        rt = self.runtime(fail_discovery=True, fail_rom=True)
        with self.assertRaises(ValueError):
            get_identifiers(ctx, rt, state)
        self.assertEqual(
            state, ConsolidatedControllerState(getter_completion_callback="error")
        )
        self.assertEqual(self.resources, [])

    def test_non_ecb_native_failure_never_selects_rom_fallback(self):
        rt = self.runtime(fail_discovery=True)
        with self.assertRaises(ValueError):
            get_can_software_info_identifiers(
                SoftwareIdentifierContext(IDENTITY, "5", "1"), rt
            )
        self.assertEqual([e["operation"] for e in self.events].count("connect"), 1)
        self.assertEqual(self.resources, [])
        rt = self.runtime(fail_read=True)
        with self.assertRaises(OSError):
            get_can_software_info_identifiers(
                SoftwareIdentifierContext(IDENTITY, "4", "1"), rt
            )
        self.assertEqual([e["operation"] for e in self.events].count("connect"), 1)
        self.assertEqual(self.resources, [])

    def test_imported_cuw_selects_actual_software_id_consumer(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw

        metadata = (
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\n"
            "ContactType=CAN\nKindOfECU=5\n[CPU01]\nCPUType=1\nCPUImageName=main\n"
            "[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000004\nDataFormatID=01\n"
        )
        context = bind_native_context(
            parse_cuw(metadata_container(metadata, [(b"main", b"DATA")], 1)), IDENTITY
        )
        self.assertIsInstance(context, SoftwareIdentifierContext)
        self.assertEqual(
            get_identifiers(context, self.runtime()), ("FIRST-ID", "SECOND-ID")
        )

    def test_native_discovery_cancel_skips_each_node_without_ecb_error_fallback(self):
        for kind, filters in (("4", 1), ("6", 3)):
            rt = self.runtime()
            rt.native_cancelled = lambda: True
            state = ConsolidatedControllerState()
            self.assertEqual(
                get_identifiers(
                    SoftwareIdentifierContext(IDENTITY, kind, "1"), rt, state
                ),
                (),
            )
            self.assertEqual(
                state, ConsolidatedControllerState(getter_completion_callback="cancel")
            )
            self.assertEqual(
                sum(event["operation"] == "connect" for event in self.events), 1
            )
            self.assertEqual(
                sum(
                    event["operation"] == "start_flow_control_filter"
                    for event in self.events
                ),
                filters,
            )
            self.assertFalse(
                any(event["operation"] == "write_messages" for event in self.events)
            )
            self.assertEqual(self.resources, [])

    def test_inner_id_cancel_error_still_invokes_ecb_but_cancel_cannot_set_old_flag(
        self,
    ):
        rt = self.runtime()
        rt.native_cancelled = lambda: any(
            event["operation"] == "write_messages"
            and event["data"][4:] == b"\x1a\x88\x01"
            for event in self.events
        )
        state = ConsolidatedControllerState()
        self.assertEqual(
            get_identifiers(SoftwareIdentifierContext(IDENTITY, "4", "1"), rt, state),
            (),
        )
        self.assertEqual(
            sum(event["operation"] == "connect" for event in self.events), 2
        )
        self.assertFalse(state.old_spec_ecb)
        self.assertFalse(state.native_context_9e8)
        self.assertFalse(
            any(
                event["operation"] == "write_messages" and event["data"][4:5] == b"\xa4"
                for event in self.events
            )
        )
        self.assertEqual(self.resources, [])

    def test_ecb_final_cancel_after_filter_release_keeps_ids_without_success_flags(
        self,
    ):
        rt = self.runtime(fail_discovery=True)
        rt.native_cancelled = lambda: (
            sum(event["operation"] == "stop_filter" for event in self.events) >= 2
        )
        state = ConsolidatedControllerState()
        self.assertEqual(
            get_identifiers(SoftwareIdentifierContext(IDENTITY, "4", "1"), rt, state),
            ("FIRSTROM", "SECONDID"),
        )
        self.assertFalse(state.old_spec_ecb)
        self.assertFalse(state.native_context_9e8)
        self.assertEqual(state.request_id_records, ("07B0", "07B0"))
        self.assertEqual(self.resources, [])


class NativeExchangeCancelTests(unittest.TestCase):
    def test_can_and_sil_native_cancel_keep_pending_output_and_timeout(self):
        response = bytes.fromhex("000007c9")
        for sil in (False, True):
            events, observations = [], iter((False, True))
            pending = (
                b"\x83\xf1\x32\x7f\x9c\x78\0" if sil else response + b"\x7f\x1a\x78"
            )

            def provider(event, remaining, events=events, pending=pending):
                events.append(event)
                if event["operation"] == "get_timeout":
                    return 1000
                if event["operation"] == "write_messages":
                    return 1
                if event["operation"] in (
                    "read_messages",
                    "read_after_indication",
                    "read_specified_can_message",
                ):
                    return pending
                return None

            rt = NativeRuntime2026(
                provider,
                native_cancelled=lambda observations=observations: next(observations),
            )
            if sil:
                result = SilDiag2026(rt).exchange(
                    SilDiag2026.packet(b"\x82\x32\xf1\x9c\x0c"),
                    check_native_cancel=True,
                )
                self.assertEqual(result, pending)
            else:
                result = ConsolidatedCanDiag2026(rt).call(
                    bytes.fromhex("000007c1"),
                    response,
                    b"\x1a\x81",
                    b"\x5a",
                    minimum=6,
                    check_native_cancel=True,
                )
                self.assertEqual(result, pending[4:])
            self.assertEqual(
                [
                    event["milliseconds"]
                    for event in events
                    if event["operation"] == "set_timeout"
                ],
                [5000],
            )
            self.assertEqual(
                sum(event["operation"].startswith("read_") for event in events), 1
            )


class CANEMPSWriterTests(unittest.TestCase):
    def context(self, **changes):
        return replace(
            CANEMPSWriteContext(
                IDENTITY,
                bytes(index & 255 for index in range(0xB8C)),
                bytes((index + 17) & 255 for index in range(0x38700)),
                b"TEST",
            ),
            **changes,
        )

    def run_writer(
        self,
        context=None,
        *,
        fallback=False,
        fail=None,
        pending=False,
        cancel=False,
        stop_fault: bool | Exception = False,
        protocol=6,
        fault=None,
        error_snapshot=None,
    ):
        from scripts.programming import NativeTransportError

        ctx = context or self.context()
        self.events, self.filters, self.chunks, self.progress = (
            [],
            [],
            {1: [], 2: []},
            [],
        )
        self.cancelled, self.current_stage = False, 0
        last, selected = b"", b""
        first_stop_fault = stop_fault

        def action(event, remaining):
            nonlocal last, selected, first_stop_fault
            self.assertGreater(remaining, 0)
            self.events.append(event)
            if fault is not None:
                fault(event)
            name = event["operation"]
            if name == "get_protocol_id":
                return protocol
            if name == "get_timeout":
                return 1234
            if name == "start_flow_control_filter":
                handle = len(self.filters) + 1
                self.filters.append(handle)
                return handle
            if name == "stop_filter":
                if first_stop_fault:
                    first_stop_fault = False
                    raise (
                        stop_fault
                        if isinstance(stop_fault, Exception)
                        else OSError("authored filter release failure")
                    )
                self.filters.remove(event["identifier"])
            if name == "write_messages":
                selected, last = event["data"][:4], event["data"][4:]
                if last[:1] == b"\x31" and last[1] in (1, 2):
                    self.current_stage = last[1]
                if last[:1] == b"\x36":
                    self.chunks[self.current_stage].append(last[1:])
                    if cancel:
                        self.cancelled = True
                return 1
            if name == "read_specified_can_message":
                if fallback and selected == b"\0\0\0\x08":
                    raise NativeTransportError(9)
                address = event["address"]
                if fail is not None and last[0] == fail:
                    return address + bytes((0x7F, fail, 0x22))
                if pending and last[0] == 0x36:
                    return address + b"\x7f\x36\x78"
                if last[:1] == b"\x31":
                    reply = b"\x71" + last[1:2]
                elif last == b"\x10\x92\x02":
                    reply = b"\x50\x92"
                elif last == b"\x27\x01":
                    reply = b"\x67\x01AB"
                elif last[:2] == b"\x27\x02":
                    reply = b"\x67\x02"
                elif last[:1] == b"\x34":
                    reply = b"\x74\0\xf1"
                else:
                    reply = {0x36: b"\x76", 0x37: b"\x77", 0x11: b"\x51"}[last[0]]
                return address + reply
            return None

        self.runtime = NativeRuntime2026(action, cancelled=lambda: self.cancelled)
        return write_can_emps(
            ctx,
            self.runtime,
            progress=lambda field, value: self.progress.append((field, value)),
            error_snapshot=error_snapshot,
        )

    def test_full_fixed_geometry_transfer_checksum_and_source_progress(self):
        ctx = self.context()
        result = self.run_writer(ctx)
        self.assertTrue(result["writer_completed"])
        self.assertFalse(result["programming_completed"])
        self.assertEqual(result["physical_status"], "PHYSICAL_UNCONFIRMED")
        self.assertEqual(b"".join(self.chunks[1]), ctx.loader)
        self.assertEqual(b"".join(self.chunks[2]), ctx.image)
        writes = [e["data"] for e in self.events if e["operation"] == "write_messages"]
        self.assertEqual(writes[:3], [b"\0\0\x07\x20\xa0\x27"] * 3)
        self.assertIn(b"\0\0\0\x08\x34\xff\x80\0\0\0\x0b\x8c", writes)
        self.assertIn(b"\0\0\0\x08\x34\0\x39\0\0\x03\x87\0", writes)
        self.assertIn(b"\0\0\0\x08\x31\x03" + bytes((sum(ctx.loader) & 255,)), writes)
        self.assertEqual(
            (result["count"], result["percent"]), (len(ctx.image) * 2, 100)
        )
        self.assertEqual(
            self.progress[-2:], [("count", len(ctx.image) * 2), ("percent", 100)]
        )
        self.assertEqual(
            [e["identifier"] for e in self.events if e["operation"] == "stop_filter"],
            [1, 2],
        )
        self.assertFalse(
            any(e["operation"] in ("connect", "disconnect") for e in self.events)
        )
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 1234}
        )
        self.assertEqual(self.filters, [])
        self.assertNotIn("TEST", repr(ctx))

    def test_actual_imported_native_archives_bind_without_address_substitution_guard(
        self,
    ):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw

        ctx = self.context()

        def srecords(data, base):
            result = []
            for offset in range(0, len(data), 240):
                payload = (base + offset).to_bytes(4, "big") + data[
                    offset : offset + 240
                ]
                body = bytes((len(payload) + 1,)) + payload
                result.append(
                    b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode()
                )
            body = b"\x05" + base.to_bytes(4, "big")
            result.append(b"S7" + (body + bytes((~sum(body) & 255,))).hex().encode())
            return b"\n".join(result) + b"\n"

        metadata = (
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\n"
            "ContactType=CAN\nKindOfECU=13\n[CPU01]\nCPUType=56\nCPUImageName=main\nFlashCodeName=stub\n"
            "[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00003900\n01_Length=00038700\nDataFormatID=01\n"
        )

        def imported(main_base=0x3900):
            return parse_cuw(
                metadata_container(
                    metadata,
                    [
                        (b"main", srecords(ctx.image, main_base)),
                        (b"stub", srecords(ctx.loader, 0xFF8000)),
                    ],
                    1,
                )
            )

        bound = bind_can_emps_writer(imported(), IDENTITY, {"authorized_key": b"TEST"})
        self.assertEqual(bound, ctx)
        self.assertTrue(self.run_writer(bound)["writer_completed"])
        shifted = bind_can_emps_writer(
            imported(0x1000), IDENTITY, {"authorized_key": b"TEST"}
        )
        self.assertEqual(shifted, ctx)
        for attachments in (
            {},
            {"authorized_key": b"BAD"},
            {"authorized_key": b"TEST", "image": b"override"},
        ):
            with self.assertRaises(ValueError):
                bind_can_emps_writer(imported(), IDENTITY, attachments)
        for change in (
            {"authorized_key": b"BAD"},
            {"identity": replace(IDENTITY, cuw_build="18")},
            {"retry_after_failure": 1},
        ):
            with self.assertRaises(ValueError):
                replace(ctx, **change)

    def test_imported_can_emps_transfers_archive_extents_and_allows_zero(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw

        def records(data):
            result = []
            for offset in range(0, len(data), 128):
                payload = (0x3900 + offset).to_bytes(4, "big") + data[
                    offset : offset + 128
                ]
                body = bytes((len(payload) + 1,)) + payload
                result.append(
                    b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode()
                )
            body = b"\x05" + (0x3900).to_bytes(4, "big")
            result.append(b"S7" + (body + bytes((~sum(body) & 255,))).hex().encode())
            return b"\n".join(result) + b"\n"

        metadata = (
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\n"
            "ContactType=CAN\nKindOfECU=13\n[CPU01]\nCPUType=56\n"
            "CPUImageName=main\nFlashCodeName=stub\n"
        )
        loader, image = b"L" * 241, b"I" * 481
        container = parse_cuw(
            metadata_container(
                metadata,
                [(b"main", records(image)), (b"stub", records(loader))],
                1,
            )
        )
        context = bind_can_emps_writer(container, IDENTITY, {"authorized_key": b"TEST"})
        self.assertEqual(context.loader, loader)
        self.assertEqual(context.image, image)
        writer = CANEMPSWriterTests()
        result = writer.run_writer(context)
        self.assertTrue(result["writer_completed"])
        self.assertEqual([len(chunk) for chunk in writer.chunks[1]], [240, 1])
        self.assertEqual([len(chunk) for chunk in writer.chunks[2]], [240, 240, 1])
        self.assertIn(
            b"\x31\x03" + bytes((sum(loader) & 255,)),
            [
                e["data"][4:]
                for e in writer.events
                if e["operation"] == "write_messages"
            ],
        )
        empty = parse_cuw(
            metadata_container(
                metadata.replace("CPUImageName=main", "CPUImageName=main.vbf").replace(
                    "FlashCodeName=stub", "FlashCodeName=stub.vbf"
                ),
                [(b"main.vbf", b""), (b"stub.vbf", b"")],
                1,
            )
        )
        empty_context = bind_can_emps_writer(
            empty, IDENTITY, {"authorized_key": b"TEST"}
        )
        empty_writer = CANEMPSWriterTests()
        empty_result = empty_writer.run_writer(empty_context)
        self.assertTrue(empty_result["writer_completed"])
        self.assertEqual(empty_writer.chunks, {1: [], 2: []})
        self.assertEqual(empty_result["count"], 0)
        self.assertEqual(empty_writer.progress, [])

    def test_source_boot_target_read9_fallback(self):
        result = self.run_writer(fallback=True)
        self.assertTrue(result["writer_completed"])
        writes = [e["data"] for e in self.events if e["operation"] == "write_messages"]
        self.assertEqual(
            writes[3:5], [b"\0\0\0\x08\x10\x92\x02", b"\0\0\x07\xa0\x10\x92\x02"]
        )
        self.assertTrue(any(data.startswith(b"\0\0\x07\xa0\x36") for data in writes))

    def test_native_failure_codes_cleanup_and_no_image_replay(self):
        for operation, expected in (
            (0x10, 18),
            (0x27, 16),
            (0x34, 26),
            (0x36, 34),
            (0x37, 36),
            (0x11, 24),
        ):
            with self.subTest(operation=operation):
                result = self.run_writer(fail=operation)
                self.assertFalse(result["writer_completed"])
                self.assertEqual(result["error_code"], expected)
                self.assertFalse(result["retry_prepared"])
                self.assertEqual(self.filters, [])
                self.assertFalse(
                    any(
                        e["operation"] in ("connect", "disconnect") for e in self.events
                    )
                )
        result = self.run_writer(fail=0x36)
        self.assertEqual(sum(map(len, self.chunks[1])), 240)
        self.assertEqual(self.chunks[2], [])

    def test_explicit_retry_only_reconnects_never_replays_data(self):
        result = self.run_writer(self.context(retry_after_failure=True), fail=0x36)
        self.assertTrue(result["retry_prepared"])
        self.assertEqual(result["error_code"], 0)
        self.assertEqual(result["initial_error_code"], 34)
        self.assertEqual(result["native_error_after_disposal"], 0)
        self.assertEqual(sum(map(len, self.chunks[1])), 240)
        self.assertEqual([e["operation"] for e in self.events].count("connect"), 1)
        self.assertEqual([e["operation"] for e in self.events].count("disconnect"), 1)
        self.assertFalse(result["writer_completed"])

    def test_accepted_retry_publishes_final_internal_error_slots(self):
        callbacks = []
        result = self.run_writer(
            self.context(retry_after_failure=True),
            fail=0x36,
            error_snapshot=lambda code, driver: callbacks.append((code, driver)),
        )
        self.assertTrue(result["retry_prepared"])
        self.assertEqual((result["error_code"], result["driver_error"]), (0, 0))
        self.assertEqual(callbacks[-2:], [(34, 0), (0, 0)])

    def test_native_pending_bound_and_cancel_cleanup(self):
        result = self.run_writer(pending=True)
        self.assertEqual(result["error_code"], 34)
        self.assertEqual(sum(map(len, self.chunks[1])), 240)
        self.assertEqual(
            [e["data"] for e in self.events if e["operation"] == "write_messages"][-1],
            b"\0\0\0\x08\x3e\x02",
        )
        self.assertEqual(self.filters, [])
        with self.assertRaises(InterruptedError):
            self.run_writer(cancel=True)
        self.assertEqual(self.filters, [])
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 1234}
        )

    def test_retry_through_actual_j2534_adapter_preserves_owned_new_handles(self):
        self.adapter_retry()

    def test_cancel_after_actual_reconnect_retains_handles_for_upstream_disposal(self):
        self.adapter_retry(cancel=True)

    def adapter_retry(self, cancel=False):
        from collections import deque

        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult

        messages, active, allocated = deque(), set(), [0]
        cancelled = False
        connected = 0
        self.raw_operations = []

        def provider(operation, remaining):
            nonlocal cancelled, connected
            name = operation["operation"]
            self.raw_operations.append(operation)
            if name in ("passthru_open", "passthru_connect", "passthru_start_filter"):
                allocated[0] += 1
                value = allocated[0]
                active.add((name, value))
                if name == "passthru_connect":
                    connected += 1
                    cancelled = cancel and connected == 2
                return PrimitiveResult(value=value)
            if name == "passthru_disconnect":
                active.remove(("passthru_connect", operation["channel"]))
            elif name == "passthru_close":
                active.remove(("passthru_open", operation["device"]))
            elif name == "passthru_stop_filter":
                active.remove(("passthru_start_filter", operation["identifier"]))
            elif name == "passthru_ioctl" and operation["ioctl"] == 8:
                messages.clear()
            elif name == "passthru_write":
                message = operation["messages"][0]
                request, payload = message.data[:4], message.data[4:]
                messages.append(NativeMessage(6, request, rx_status=9))
                response_address = (int.from_bytes(request, "big") + 1).to_bytes(
                    4, "big"
                )
                if payload == b"\x10\x92\x02":
                    reply = b"\x50\x92"
                elif payload == b"\x27\x01":
                    reply = b"\x67\x01AB"
                elif payload[:2] == b"\x27\x02":
                    reply = b"\x67\x02"
                elif payload[:1] == b"\x31":
                    reply = b"\x71" + payload[1:2]
                elif payload[:1] == b"\x34":
                    reply = b"\x74\0\xf1"
                elif payload[:1] == b"\x36":
                    reply = b"\x7f\x36\x22"
                else:
                    reply = None
                if reply is not None:
                    messages.append(NativeMessage(6, response_address + reply))
                return PrimitiveResult(value=1)
            elif name == "passthru_read":
                return PrimitiveResult(value=(messages.popleft(),) if messages else ())
            return PrimitiveResult()

        device = J2534Device2026(provider)
        device.open()
        device.connect(6)
        first_channel = device.channel_id
        rt = NativeRuntime2026(device.primitive, cancelled=lambda: cancelled)
        if cancel:
            with self.assertRaises(InterruptedError):
                write_can_emps(self.context(retry_after_failure=True), rt)
        else:
            result = write_can_emps(self.context(retry_after_failure=True), rt)
            self.assertTrue(result["retry_prepared"])
            self.assertEqual(result["error_code"], 0)
            self.assertEqual(result["initial_error_code"], 34)
        self.assertNotEqual(device.channel_id, first_channel)
        self.assertIsNotNone(device.channel_id)
        self.assertFalse(device.filters)
        self.assertEqual(len(active), 2)
        self.assertEqual(rt.close(), [])
        device.disconnect()
        self.assertEqual(active, set())

    def test_cleanup_failure_is_visible_and_all_other_releases_attempted(self):
        with self.assertRaises(OSError):
            self.run_writer(stop_fault=True)
        self.assertEqual(self.filters, [1])
        self.assertEqual(self.runtime.close(), [])
        self.assertEqual(self.filters, [])
        with self.assertRaises(ValueError):
            self.run_writer(protocol=3)
        self.assertEqual(self.filters, [])
        self.assertFalse(any(e["operation"] == "write_messages" for e in self.events))


class ConsolidatedCommonTests(unittest.TestCase):
    request = bytes.fromhex("000007d1")
    response = bytes.fromhex("000007d9")

    def channel(self, replies, fault=None):
        self.events = []
        values = iter(replies)

        def provider(event, remaining):
            self.events.append(event)
            if fault is not None:
                fault(event)
            if event["operation"] == "write_messages":
                return event["count"]
            if event["operation"] == "read_specified_can_message":
                value = next(values)
                if isinstance(value, Exception):
                    raise value
                return self.response + value
            return None

        return ConsolidatedCAN2026(NativeRuntime2026(provider))

    def test_epb_extended_seed_request_native_minimum_zero_pads_fourth_seed_byte(self):
        request, response = bytes.fromhex("000007502c"), bytes.fromhex("000007582c")
        replies = iter(
            (response + bytes.fromhex("6701010203"), response + bytes.fromhex("6702"))
        )
        events = []

        def provider(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                return next(replies)
            return None

        channel = ConsolidatedCAN2026(NativeRuntime2026(provider))
        channel.epb_security_access(
            request,
            response,
            tuple(bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")),
        )
        writes = [event for event in events if event["operation"] == "write_messages"]
        self.assertEqual(
            [event["data"] for event in writes],
            [
                bytes.fromhex("000007502c270100"),
                bytes.fromhex("000007502c2702414243c0"),
            ],
        )
        self.assertTrue(all(event["tx_flags"] == 0x80 for event in writes))

    def test_epb_write_verify_singleblock_commands_and_exact_busy_codes(self):
        from scripts.programming_2026_common import NativeMemoryInfo

        ack = b"\x3c"
        channel = self.channel([ack, ack, ack, b"\x40", ack, ack, b"\0", ack])
        counts, percentages = [0], [0]
        image = b"\xa5" * 1024
        channel.write_epb_block(
            self.request,
            self.response,
            1,
            (1024,),
            NativeMemoryInfo(0x1000, 0x13FF, 1, 0),
            image,
            counts,
            percentages,
            lambda field: None,
        )
        self.assertEqual(
            [
                event["data"]
                for event in self.events
                if event["operation"] == "write_messages"
            ],
            [
                self.request + b"\x41",
                self.request + bytes.fromhex("001000ff"),
                self.request + image,
                self.request + b"\x50",
                self.request + b"\x50",
            ],
        )
        self.assertEqual((counts, percentages), ([1024], [50]))
        channel = self.channel(
            [ack]
            + [ack, ack, b"\x20", ack, ack, b"\0", ack]
            + [ack, ack, b"\0", ack] * 3
        )
        channel.verify_epb_block(
            self.request,
            self.response,
            1,
            (1024,),
            image,
            counts,
            percentages,
            lambda field: None,
        )
        self.assertEqual(self.events[0]["data"], self.request + bytes.fromhex("1500"))
        self.assertEqual((counts, percentages), ([2048], [100]))
        channel = self.channel([ack, ack, ack, b"\x10", ack])
        with self.assertRaises(ConsolidatedError) as error:
            channel.write_epb_block(
                self.request,
                self.response,
                1,
                (1024,),
                NativeMemoryInfo(0x1000, 0x13FF, 1, 0),
                image,
                [0],
                [0],
                lambda field: None,
            )
        self.assertEqual(error.exception.code, 13)

    def test_epb_memory75_exact12_and_singleblock25_status80(self):
        ack = b"\x3c"
        channel = self.channel([ack, bytes.fromhex("0010000017ff0180"), ack])
        memory = channel.get_epb_memory_info(self.request, self.response)
        self.assertEqual(
            (
                memory.start_address,
                memory.end_address,
                memory.block_size_kib,
                memory.firmware_version,
            ),
            (0x1000, 0x17FF, 1, 0x80),
        )
        self.assertFalse(channel.native_context_6c)
        self.assertEqual(self.events[0]["data"], self.request + b"\x75")
        channel = self.channel([ack, ack, b"\x80", ack, ack, b"\0", ack])
        channel.erase_epb_block(self.request, self.response, 256)
        self.assertEqual(self.events[0]["data"], self.request + bytes.fromhex("25ff"))
        self.assertEqual(
            [
                event["milliseconds"]
                for event in self.events
                if event["operation"] == "wait"
            ],
            [10, 10],
        )
        channel = self.channel([ack, ack, b"\x10", ack])
        with self.assertRaises(ConsolidatedError) as error:
            channel.erase_epb_block(self.request, self.response, 1)
        self.assertEqual(error.exception.code, 12)
        with self.assertRaises(ValueError):
            channel.erase_epb_block(self.request, self.response, 257)

    def test_disposal_native_zero_padding_and_any_driver_read_fault(self):
        from scripts.j2534_2026 import NativeJ2534Error2026, NativePassThruError2026

        for code, size in ((13, 1024), (15, 256)):
            channel = self.channel(
                [NativeJ2534Error2026(9), NativeJ2534Error2026(7), b"\xff", b"\x3c"]
            )
            channel.dispose_write_error(self.request, self.response, code)
            self.assertEqual(
                [
                    event["data"]
                    for event in self.events
                    if event["operation"] == "write_messages"
                ],
                [
                    self.request + b"\x05",
                    self.request + bytes(size),
                    self.request + b"\x05",
                ],
            )
            self.assertIn({"operation": "wait", "milliseconds": 3000}, self.events)
        channel = self.channel([NativeJ2534Error2026(9), NativePassThruError2026(7)])
        with self.assertRaises(NativePassThruError2026):
            channel.dispose_write_error(self.request, self.response, 13)
        channel = self.channel([NativeJ2534Error2026(9)])
        with self.assertRaises(ConsolidatedError) as error:
            channel.dispose_write_error(self.request, self.response, 12)
        self.assertEqual(error.exception.code, 20)
        self.assertEqual(
            sum(event["operation"] == "write_messages" for event in self.events), 1
        )

    def test_native_zero_flash_size_has_zero_progress_without_skipping_transfer(self):
        ack = b"\x3c"
        channel = self.channel([ack, ack, ack, b"\0", ack])
        counts, percentages = [0], [91]
        channel.verify_block(
            self.request,
            self.response,
            1,
            1,
            (256,),
            bytes(256),
            counts,
            percentages,
            lambda field: None,
            total_size=0,
        )
        self.assertEqual((counts, percentages), ([256], [0]))

    def test_fc_security_seed_four_rounds_and_explicit_material_bounds(self):
        events, replies = (
            [],
            iter(
                (
                    self.response + bytes.fromhex("670101020304"),
                    self.response + bytes.fromhex("6702"),
                )
            ),
        )

        def provider(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 123
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                return next(replies)
            return None

        channel = ConsolidatedCAN2026(NativeRuntime2026(provider))
        materials = tuple(
            bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")
        )
        channel.fc_security_access(self.request, self.response, materials)
        # Authored seed01020304: rounds03041122,11223344,33444142,414243c4.
        self.assertEqual(
            [
                event["data"]
                for event in events
                if event["operation"] == "write_messages"
            ],
            [
                self.request + bytes.fromhex("2701"),
                self.request + bytes.fromhex("2702414243c4"),
            ],
        )
        self.assertIn({"operation": "wait", "milliseconds": 100}, events)
        before = len(events)
        with self.assertRaises(ValueError):
            channel.fc_security_access(self.request, self.response, (b"bad",) * 4)
        self.assertEqual(len(events), before)

    def test_write_fixed1024_literal_address_and45_continuation(self):
        from scripts.programming_2026_common import NativeMemoryInfo

        ack = b"\x3c"
        image = b"\xa5" * 1024 + b"\x5a" * 1024
        for wide, start in ((False, 0x123400), (True, 0x12340000)):
            channel = self.channel(
                [ack, ack, ack, b"\0", ack, ack, ack, ack, b"\0", ack]
            )
            counts, percentages, notifications = [0], [0], []
            channel.write_block(
                self.request,
                self.response,
                1,
                2,
                (1024, 1024),
                NativeMemoryInfo(start, start + 2047, 1, 0),
                image,
                counts,
                percentages,
                lambda field, notifications=notifications: notifications.append(field),
                wait_ms=17,
                wide=wide,
            )
            self.assertEqual(
                [
                    event["data"]
                    for event in self.events
                    if event["operation"] == "write_messages"
                ],
                [
                    self.request + b"\x41",
                    self.request + start.to_bytes(4 if wide else 3, "big") + b"\xff",
                    self.request + image[:1024],
                    self.request + b"\x50",
                    self.request + b"\x45",
                    self.request + image[1024:],
                    self.request + b"\x50",
                ],
            )
            self.assertEqual((counts, percentages), ([2048], [50]))
            self.assertEqual(notifications, ["count", "percent", "count", "percent"])
            self.assertEqual(
                [
                    event["milliseconds"]
                    for event in self.events
                    if event["operation"] == "wait"
                ],
                [17, 5, 5],
            )

    def test_verify_literal_packets_progress_and_nonfinal_retained_status_eh(self):
        from scripts.programming_2026_common import NativePassThruException2026

        ack = b"\x3c"
        image = bytes(range(256)) * 2
        for error in (None, NativePassThruException2026(77, "authored", 1)):
            replies = (
                [ack, ack, ack]
                + ([b"\0", ack] if error is None else [error])
                + [ack, ack, b"\0", ack]
            )
            channel = self.channel(replies)
            counts, percentages, notifications = [0], [0], []
            channel.verify_block(
                self.request,
                self.response,
                1,
                2,
                (256, 256),
                image,
                counts,
                percentages,
                lambda field, notifications=notifications, counts=counts, percentages=percentages: (
                    notifications.append((field, counts[0], percentages[0]))
                ),
            )
            writes = [
                event["data"]
                for event in self.events
                if event["operation"] == "write_messages"
            ]
            self.assertEqual(
                writes,
                [
                    self.request + bytes.fromhex("1600000001"),
                    self.request + image[:256],
                    self.request + b"\x50",
                    self.request + image[256:],
                    self.request + b"\x50",
                ],
            )
            self.assertEqual((counts, percentages), ([512], [50]))
            self.assertEqual(
                notifications,
                [
                    ("count", 256, 0),
                    ("percent", 256, 25),
                    ("count", 512, 25),
                    ("percent", 512, 50),
                ],
            )
            self.assertEqual(
                [
                    event["milliseconds"]
                    for event in self.events
                    if event["operation"] == "wait"
                ],
                [5, 5],
            )
        channel = self.channel(
            [
                ack,
                ack,
                ack,
                b"\x10",
                ack,
                ack,
                NativePassThruException2026(77, "authored", 1),
            ]
        )
        counts, percentages = [0], [0]
        with self.assertRaises(ConsolidatedError) as error:
            channel.verify_block(
                self.request,
                self.response,
                1,
                2,
                (256, 256),
                image,
                counts,
                percentages,
                lambda field: None,
            )
        self.assertEqual(error.exception.code, 15)
        self.assertEqual(counts, [256])
        self.assertEqual(
            sum(
                event["operation"] == "write_messages" and len(event["data"]) == 260
                for event in self.events
            ),
            1,
        )

    def test_literal_check_id_one_native_batch5_and_both_byte_orders(self):
        for swapped, tail in (
            (False, ("efcd67452301", "ab89", "40302010")),
            (True, ("cdef45670123", "89ab", "10203040")),
        ):
            channel = self.channel([b"\x3c", b"authored unchecked native information"])
            channel.check_id(
                self.request,
                self.response,
                bytes.fromhex("0123456789abcdef"),
                0x10203040,
                initial_timeout=2345,
                swap_endian=swapped,
            )
            self.assertEqual(
                self.events[0],
                {
                    "operation": "write_messages",
                    "protocol": 6,
                    "messages": tuple(
                        self.request + bytes.fromhex(part)
                        for part in ("00", "00", *tail)
                    ),
                    "tx_flags": 0,
                    "count": 5,
                },
            )
            self.assertEqual(
                self.events[2], {"operation": "set_timeout", "milliseconds": 2345}
            )
            self.assertEqual(self.events[-2]["frame"], 1)
            self.assertEqual(self.events[-1]["data"], self.request + b"\x3c")

    def test_wide_blocks_fixed10ms_polling_and_blank_false(self):
        for operation, opcode, pending in (
            ("blank", 0x36, 0x10),
            ("erase", 0x26, 0x20),
            ("inverify", 0x48, 0x40),
        ):
            replies = [
                b"\x3c",
                b"\x3c",
                bytes((pending,)) + b"padding",
                b"\x3c",
                b"\x3c",
                b"\0",
                b"\x3c",
            ]
            channel = self.channel(replies)
            self.assertTrue(
                channel.block(operation, self.request, self.response, 2, 258)
            )
            self.assertEqual(
                self.events[0]["data"], self.request + bytes((opcode, 0, 1, 1, 1))
            )
            self.assertEqual(
                [
                    event["milliseconds"]
                    for event in self.events
                    if event["operation"] == "wait"
                ],
                [10, 10],
            )
        channel = self.channel([b"\x3c", b"\x3c", b"\x11", b"\x3c"])
        self.assertFalse(channel.block("blank", self.request, self.response, 1, 1))
        channel = self.channel([b"\x3c", b"\x3c", b"\x41", b"\x3c"])
        with self.assertRaises(ConsolidatedError) as caught:
            channel.block("inverify", self.request, self.response, 1, 1)
        self.assertEqual(caught.exception.code, 14)

    def test_native_driver_keeps_raw_code_and_gets_block_enum_base_error_does_not(self):
        from scripts.j2534_2026 import NativePassThruError2026
        from scripts.programming import NativeTransportError

        def fault(event):
            if event["operation"] == "write_messages":
                raise NativeTransportError(7)

        channel = self.channel([], fault)
        with self.assertRaises(NativeTransportError) as caught:
            channel.block("erase", self.request, self.response, 1, 2)
        self.assertEqual(caught.exception.code, 7)
        self.assertEqual(getattr(caught.exception, "native_error_code", None), 12)
        self.assertEqual(len(self.events), 1)

        def base_fault(event):
            if event["operation"] == "write_messages":
                raise NativePassThruError2026(7)

        channel = self.channel([], base_fault)
        with self.assertRaises(NativePassThruError2026) as base:
            channel.block("erase", self.request, self.response, 1, 2)
        self.assertEqual(base.exception.native_error_code, 7)
        self.assertEqual(base.exception.passthru_status, None)

    def test_finish_no_ack_and_explicit_ack_branches(self):
        channel = self.channel([])
        channel.finish(self.request, self.response)
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0]["data"], self.request + b"\x80")
        channel = self.channel([b"\x3c"])
        channel.finish(self.request, self.response, acknowledge=True)
        self.assertEqual(len(self.events), 2)

    def test_extended_finish_native_flag_and_memory_ack_persistent_byte(self):
        channel = self.channel([])
        channel.finish(bytes.fromhex("18daf11001"), bytes.fromhex("18da10f101"))
        self.assertEqual(self.events[0]["data"], bytes.fromhex("18daf1100180"))
        self.assertEqual(self.events[0]["tx_flags"], 0x80)
        channel = self.channel([b"\x3c", b"bad"])
        self.assertFalse(channel.native_context_6c)
        with self.assertRaises(ConsolidatedError):
            channel.get_memory_info(self.request, self.response)
        self.assertTrue(channel.native_context_6c)
        from scripts.programming import NativeTransportError

        def timeout(event):
            if event["operation"] == "read_specified_can_message":
                raise NativeTransportError(9)

        channel = self.channel([], timeout)
        with self.assertRaises(ConsolidatedError):
            channel.get_memory_info(self.request, self.response)
        self.assertFalse(channel.native_context_6c)

    def test_memory_info_native76_only_be_widths_and_no75_fallback(self):
        from scripts.programming import NativeTransportError

        for wide, encoded in (
            (False, "01000008ffff4091"),
            (True, "123400001238ffff4091"),
        ):
            channel = self.channel(
                [b"\x3c", bytes.fromhex(encoded) + b"padding"[:1], b"\x3c"]
            )
            memory = channel.get_memory_info(self.request, self.response, wide=wide)
            self.assertEqual(memory.start_address, 0x12340000 if wide else 0x10000)
            self.assertEqual(memory.end_address, 0x1238FFFF if wide else 0x8FFFF)
            self.assertEqual(
                (memory.block_size_kib, memory.firmware_version), (64, 0x91)
            )
            self.assertEqual(
                [
                    event["data"]
                    for event in self.events
                    if event["operation"] == "write_messages"
                ],
                [self.request + b"\x76"],
            )

        def fault(event):
            if event["operation"] == "read_specified_can_message":
                raise NativeTransportError(9)

        channel = self.channel([], fault)
        with self.assertRaises(ConsolidatedError) as caught:
            channel.get_memory_info(self.request, self.response)
        self.assertEqual(caught.exception.code, 10)
        self.assertEqual(len(self.events), 2)

    def test_check_id_batch_through_actual48_preserves_frames_and_indication_order(
        self,
    ):
        from collections import deque

        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult

        messages = deque()
        batches = []

        def provider(event, remaining):
            name = event["operation"]
            if name == "passthru_open":
                return PrimitiveResult(value=1)
            if name == "passthru_connect":
                return PrimitiveResult(value=2)
            if name == "passthru_ioctl" and event["ioctl"] == 8:
                messages.clear()
            if name == "passthru_write":
                batch = event["messages"]
                batches.append(tuple(message.data for message in batch))
                messages.append(NativeMessage(6, self.request, rx_status=9))
                if len(batch) == 5:
                    messages.extend(
                        (
                            NativeMessage(6, self.response + b"\x3c"),
                            NativeMessage(6, self.response, rx_status=2),
                            NativeMessage(6, self.response + b"authored"),
                        )
                    )
                return PrimitiveResult(value=len(batch))
            if name == "passthru_read":
                return PrimitiveResult(value=(messages.popleft(),) if messages else ())
            return PrimitiveResult()

        device = J2534Device2026(provider)
        device.open()
        device.connect(6)
        channel = ConsolidatedCAN2026(NativeRuntime2026(device.primitive))
        channel.check_id(
            self.request, self.response, bytes.fromhex("0123456789abcdef"), 0x10203040
        )
        self.assertEqual(
            tuple(frame.hex() for frame in batches[0]),
            (
                "000007d100",
                "000007d100",
                "000007d1efcd67452301",
                "000007d1ab89",
                "000007d140302010",
            ),
        )
        self.assertEqual(batches[1], (self.request + b"\x3c",))
        self.assertEqual(device.channel_id, 2)
        device.disconnect()


class SILEMPSWriterTests(unittest.TestCase):
    def test_actual_native_archive_binder_rejects_wrong_family_geometry_and_alias(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw

        image = b"\xa5" * (128 * 1024)
        records = []
        for offset in range(0, len(image), 128):
            raw = (
                bytes((133,)) + offset.to_bytes(4, "big") + image[offset : offset + 128]
            )
            records.append(b"S3" + (raw + bytes((~sum(raw) & 255,))).hex().encode())
        archive = b"\n".join(records) + b"\nS70500000000FA\n"
        metadata = (
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\n"
            "ContactType=SIL\nKindOfECU=13\n[CPU01]\nCPUType=59\nCPUImageName=main\n"
        )
        container = parse_cuw(metadata_container(metadata, [(b"main", archive)], 1))
        context = bind_sil_emps_writer(container, IDENTITY)
        self.assertEqual(context.image, image)
        self.assertEqual(context.flash_size, len(image))
        self.assertEqual(context.page_count, 128)
        self.assertNotIn("a5a5", repr(context))
        for kwargs in (
            {"image": image[:-1]},
            {"first_cpu_type": "56"},
            {"kind_of_ecu": "8"},
            {"retry_decisions": (1,)},
        ):
            with self.subTest(kwargs=tuple(kwargs)), self.assertRaises(ValueError):
                replace(context, **kwargs)
        with self.assertRaises(ValueError):
            bind_sil_emps_writer(container, identify_native_module("0" * 64, MODULE))

    def test_imported_sil_emps_keeps_flash_size_denominator_with_extra_backing(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw

        image = b"\xa5" * (128 * 1024 + 1024)
        records = []
        for offset in range(0, len(image), 128):
            raw = (
                bytes((133,)) + offset.to_bytes(4, "big") + image[offset : offset + 128]
            )
            records.append(b"S3" + (raw + bytes((~sum(raw) & 255,))).hex().encode())
        archive = b"\n".join(records) + b"\nS70500000000FA\n"
        metadata = (
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\n"
            "ContactType=SIL\nKindOfECU=13\n[CPU01]\nCPUType=59\nCPUImageName=main\n"
        )
        container = parse_cuw(metadata_container(metadata, [(b"main", archive)], 1))
        context = bind_sil_emps_writer(container, IDENTITY)
        self.assertEqual(context.image, image)
        self.assertEqual(context.flash_size, len(image))
        self.assertEqual(context.page_count, 128)
        writer = SILEMPSWriterTests()
        result = writer.run_writer(context=context)
        self.assertTrue(result["writer_completed"])
        self.assertEqual(result["percent"], 99)

    def run_writer(self, *, cpu="59", retry=(), replies=None, fault=None, context=None):
        from scripts.j2534_2026 import NativeMessage

        self.events, self.progress, self.pages = [], [], []
        self.cancelled = False
        values = iter(replies or ())
        last = b""
        context = context or SILEMPSWriteContext(
            IDENTITY,
            "13",
            cpu,
            b"\xa5" * ({"57": 256, "58": 240, "59": 128, "60": 192}[cpu] * 1024),
            {"57": 256, "58": 240, "59": 128, "60": 192}[cpu] * 1024,
            retry,
        )

        def provider(event, remaining):
            nonlocal last
            self.events.append(event)
            name = event["operation"]
            if fault is not None:
                fault(event)
            if name == "get_protocol_id":
                return 3
            if name == "get_timeout":
                return 1234
            if name == "get_send_timeout":
                return 5678
            if name == "fast_init":
                return NativeMessage(3, b"")
            if name == "write_messages":
                last = event["data"]
                if len(last) == 1028:
                    self.pages.append(last)
                return 1
            if name in ("read_messages", "read_after_indication"):
                explicit = next(values, None)
                if explicit is not None:
                    return explicit
                return (
                    b"\0"
                    if len(last) == 11
                    else bytes((2 if last[0] == context.page_count - 1 else 1,))
                )
            return None

        self.runtime = NativeRuntime2026(provider, cancelled=lambda: self.cancelled)
        return write_sil_emps(
            context,
            self.runtime,
            progress=lambda field, value: self.progress.append((field, value)),
        )

    def test_fixed_cpu_geometry_raw_packets_and_native_double_progress(self):
        for cpu, count in (("57", 256), ("58", 240), ("59", 128), ("60", 192)):
            with self.subTest(cpu=cpu):
                result = self.run_writer(cpu=cpu)
                self.assertTrue(result["writer_completed"])
                self.assertEqual(result["pages_written"], count)
                self.assertEqual(result["count"], count * 2048)
                self.assertEqual(result["percent"], 100)
                self.assertEqual(len(self.pages), count)
                for page, packet in enumerate(self.pages):
                    self.assertEqual(packet[:3], bytes((page, 4, 0)))
                    self.assertEqual(packet[3:-1], b"\xa5" * 1024)
                    self.assertEqual(sum(packet) & 255, 255)
                self.assertEqual(
                    self.progress[-2:], [("count", count * 2048), ("percent", 100)]
                )
                self.assertFalse(
                    any(
                        event["operation"] in ("connect", "disconnect")
                        for event in self.events
                    )
                )
                self.assertEqual(
                    self.events[-2:],
                    [
                        {"operation": "set_timeout", "milliseconds": 1234},
                        {"operation": "set_send_timeout", "milliseconds": 5678},
                    ],
                )

    def test_current_nak_three_resends_then_failure_without_reerase(self):
        result = self.run_writer(replies=[b"\0"] + [b"\x82\0"] * 4)
        self.assertEqual(result["error_code"], 13)
        self.assertEqual(result["pages_written"], 0)
        self.assertEqual(len(self.pages), 4)
        self.assertEqual(result["count"], 8192)
        self.assertEqual(self.pages, [self.pages[0]] * 4)

    def test_resends_count_native_attempted_bytes_and_percent_can_exceed100(self):
        result = self.run_writer(replies=[b"\0", b"\x82\0", b"\x82\0", b"\x01"])
        self.assertTrue(result["writer_completed"])
        self.assertEqual(result["pages_written"], 128)
        self.assertEqual(result["count"], 130 * 2048)
        self.assertEqual(result["percent"], 101)
        self.assertEqual(len(self.pages), 130)

    def test_previous_nak_read_only_discards_three_and_not_four(self):
        result = self.run_writer(replies=[b"\0", b"\x01"] + [b"\x82\0"] * 3 + [b"\x01"])
        self.assertTrue(result["writer_completed"])
        self.assertEqual(len(self.pages), 128)
        result = self.run_writer(replies=[b"\0", b"\x01"] + [b"\x82\0"] * 4)
        self.assertEqual(result["pages_written"], 1)
        self.assertEqual(result["error_code"], 13)
        self.assertEqual(len(self.pages), 2)

    def test_page_zero_previous_nak_255_never_matches_unsigned_minus_one(self):
        result = self.run_writer(replies=[b"\0", b"\x82\xff"])
        self.assertEqual(result["error_code"], 13)
        self.assertEqual(len(self.pages), 1)

    def test_only_transport9_and16_reconnect_resume_same_page(self):
        from scripts.programming import NativeTransportError

        for code in (9, 16, 7):
            failed = False

            def fault(event, code=code):
                nonlocal failed
                if (
                    event["operation"] in ("read_messages", "read_after_indication")
                    and self.pages
                    and not failed
                ):
                    failed = True
                    raise NativeTransportError(code)

            result = self.run_writer(retry=(True, False), fault=fault)
            self.assertEqual(result["reconnects"], int(code in (9, 16)))
            if code in (9, 16):
                self.assertTrue(result["writer_completed"])
                self.assertEqual(self.pages[0], self.pages[1])
                self.assertEqual(result["count"], 128 * 2048)
            else:
                self.assertFalse(result["writer_completed"])
                self.assertEqual(len(self.pages), 1)
                self.assertTrue(
                    any(
                        event == {"operation": "wait", "milliseconds": 3000}
                        for event in self.events
                    )
                )

    def test_native_base_enum9_is_not_raw_driver9_and_canonical_driver_resumes(self):
        from scripts.j2534_2026 import NativeJ2534Error2026, NativePassThruError2026
        from scripts.programming_2026_common import (
            NativeJ2534Exception2026,
            NativePassThruException2026,
        )

        for error, recoverable in (
            (NativePassThruError2026(9), False),
            (NativeJ2534Error2026(9), True),
            (NativePassThruException2026(9, "authored", 1), False),
            (NativeJ2534Exception2026(9, "authored", 1), True),
        ):
            failed = False

            def fault(event, error=error):
                nonlocal failed
                if (
                    event["operation"] == "read_after_indication"
                    and self.pages
                    and not failed
                ):
                    failed = True
                    raise error

            result = self.run_writer(retry=(True, False), fault=fault)
            self.assertEqual(result["reconnects"], int(recoverable))
            self.assertEqual(result["writer_completed"], recoverable)
            if not recoverable:
                self.assertEqual(result["error_code"], 9)
                self.assertEqual(len(self.pages), 1)
                self.assertTrue(
                    any(
                        event["operation"] == "wait" and event["milliseconds"] == 3000
                        for event in self.events
                    )
                )

    def test_erase_failure_never_programs_and_cancel_restores_timeouts(self):
        result = self.run_writer(replies=[b"\x01"], retry=(True, False))
        self.assertEqual(result["error_code"], 12)
        self.assertEqual(self.pages, [])

        def fault(event):
            if event["operation"] == "write_messages" and len(event["data"]) == 1028:
                self.cancelled = True

        with self.assertRaises(InterruptedError):
            self.run_writer(fault=fault)
        self.assertEqual(
            self.events[-1], {"operation": "set_send_timeout", "milliseconds": 5678}
        )

    def test_fast_init_failure_retry_prepares_session_without_erasing(self):
        from scripts.programming import NativeTransportError

        def fault(event):
            if event["operation"] == "fast_init":
                raise NativeTransportError(7)

        result = self.run_writer(fault=fault, retry=(True,))
        self.assertEqual(result["error_code"], 0)
        self.assertEqual(result["native_error_code"], 0)
        self.assertEqual(result["reconnects"], 1)
        self.assertFalse(result["writer_completed"])
        self.assertFalse(
            any(event["operation"] == "write_messages" for event in self.events)
        )


class CANFCWriterTests(unittest.TestCase):
    def run_writer(
        self, *, retry=(), fault=None, cpu_index=0, cpu_count=1, bound_context=None
    ):
        self.events, self.filters, self.pending = [], set(), []
        self.connected = True
        last_response = bytes.fromhex("000007d9")
        handles = [0]
        context = CANFCWriteContext(
            IDENTITY,
            "5",
            "11",
            bytes.fromhex("07d907d100000720"),
            SoftwareIDRecord(
                "AUTHORED", bytes.fromhex("07d1"), bytes.fromhex("07d9"), False
            ),
            0,
            b"\xa5" * 2048,
            2048,
            tuple(bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")),
            retry,
            cpu_index,
            cpu_count,
        )

        if bound_context is not None:
            context = bound_context
            cpu_count = context.cpu_count

        def provider(event, remaining):
            self.events.append(event)
            if fault is not None:
                fault(event)
            name = event["operation"]
            if name == "get_protocol_id":
                return 6
            if name == "get_timeout":
                return 1000
            if name == "disconnect":
                self.connected = False
                self.pending.clear()
            if name == "connect":
                self.connected = True
            if name == "start_flow_control_filter":
                handles[0] += 1
                self.filters.add(handles[0])
                return handles[0]
            if name == "stop_filter":
                self.filters.remove(event["identifier"])
            if name == "write_messages":
                if "messages" in event:
                    self.pending.extend((b"\x3c", b"information"))
                else:
                    payload = event["data"][4:]
                    if payload == b"\x27\x01":
                        self.pending.append(bytes.fromhex("670101020304"))
                    elif payload.startswith(b"\x27\x02"):
                        self.assertEqual(payload, bytes.fromhex("2702414243c4"))
                        self.pending.append(bytes.fromhex("6702"))
                    elif payload == b"\x10\x02":
                        self.pending.append(b"\x50")
                    elif payload == b"\x76":
                        self.pending.extend(
                            (b"\x3c", bytes.fromhex("0010000017ff018300"), b"\x3c")
                        )
                    elif payload == b"\x50":
                        self.pending.extend((b"\x3c", b"\0", b"\x3c"))
                    elif (
                        payload in (b"\x41", b"\x45", b"\x05")
                        or payload[:1] in (b"\x36", b"\x26", b"\x48", b"\x16")
                        or len(payload) in (256, 1024)
                    ):
                        self.pending.append(b"\x3c")
                return event["count"]
            if name == "read_specified_can_message":
                return last_response + self.pending.pop(0)
            return None

        self.runtime = NativeRuntime2026(provider)
        self.progress = []
        return write_can_fc(
            context,
            self.runtime,
            progress=lambda field, value: self.progress.append((field, value)),
            counts=[91] * cpu_count,
            percentages=[17] * cpu_count,
        )

    def test_actual_metadata_location_target_route_archive_and_flash_size_bind(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw

        image = b"\xa5" * 2048
        lines = []
        for offset in range(0, len(image), 128):
            body = (
                bytes((133,))
                + (0x1000 + offset).to_bytes(4, "big")
                + image[offset : offset + 128]
            )
            lines.append(b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode())
        body = bytes.fromhex("0500001000")
        lines.append(b"S7" + (body + bytes((~sum(body) & 255,))).hex().encode())
        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\nContactType=CAN\nKindOfECU=5\n[CPU01]\nCPUType=11\nLocationID=07d907d100000720\nNewCID=UNUSED-NEW-CID\nCPUImageName=main\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED\n01_TargetData=ffffffff\n[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000800\nDataFormatID=01\n"
        container = parse_cuw(
            metadata_container(metadata, [(b"main", b"\n".join(lines) + b"\n")], 1)
        )
        state = ConsolidatedControllerState(
            software_id_records=(
                SoftwareIDRecord(
                    "AUTHORED", bytes.fromhex("07d1"), bytes.fromhex("07d9"), False
                ),
            )
        )
        materials = tuple(
            bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")
        )
        bound = bind_can_fc_writer(
            container, IDENTITY, state, {"fc_security_materials": materials}
        )
        self.assertEqual(
            (bound.image, bound.flash_size, bound.password), (image, 2048, 0)
        )
        self.assertEqual(bound.location_id, bytes.fromhex("07d907d100000720"))
        self.assertTrue(self.run_writer(bound_context=bound)["writer_completed"])
        # FC1c380 passes null password state; no source05150 image substitution.
        with self.assertRaises(TypeError):
            cast(Any, bind_can_fc_writer)(
                container,
                IDENTITY,
                state,
                {"fc_security_materials": materials},
                password_state=True,
            )
        for attachments in ({}, {"fc_security_materials": materials, "image": image}):
            with self.assertRaises(ValueError):
                bind_can_fc_writer(container, IDENTITY, state, attachments)
        with self.assertRaises(ValueError):
            bind_can_fc_writer(
                container,
                IDENTITY,
                ConsolidatedControllerState(),
                {"fc_security_materials": materials},
            )

    def test_connected_fc_security_two_ranges_write_verify_and_location_finish(self):
        result = self.run_writer(cpu_index=1, cpu_count=3)
        self.assertTrue(result["writer_completed"])
        self.assertEqual(
            (result["counts"], result["percentages"]), ((91, 4096, 0), (17, 100, 0))
        )
        self.assertEqual((result["restarts"], result["error_code"]), (0, None))
        self.assertFalse(
            any(
                event["operation"] in ("connect", "disconnect") for event in self.events
            )
        )
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages" and "data" in event
        ]
        self.assertEqual(writes[-1], bytes.fromhex("0000072080"))
        self.assertEqual(sum(len(data) == 1028 for data in writes), 2)
        self.assertEqual(sum(len(data) == 260 for data in writes), 8)
        self.assertEqual(
            sum(data == bytes.fromhex("00000720a027") for data in writes), 3
        )
        self.assertEqual(self.filters, set())
        self.assertEqual(self.pending, [])
        self.assertEqual(self.runtime.close(), [])
        self.assertTrue(self.connected)

    def test_block_native_failure_declines_or_disposes_then_restarts(self):
        from scripts.j2534_2026 import NativePassThruError2026

        for retry in ((False,), (True,)):
            failed = False

            def fault(event):
                nonlocal failed
                if (
                    event["operation"] == "write_messages"
                    and len(event.get("data", b"")) == 1028
                    and not failed
                ):
                    failed = True
                    raise NativePassThruError2026(13)

            result = self.run_writer(retry=retry, fault=fault)
            self.assertEqual(result["writer_completed"], retry[0])
            self.assertEqual(result["restarts"], int(retry[0]))
            self.assertEqual(result["retry_decisions_consumed"], 1)
            self.assertEqual(result["count"], 4096 if retry[0] else 0)
            self.assertEqual(self.filters, set())
            self.assertEqual(self.runtime.close(), [])
            self.assertIn(("count", 0), self.progress)
            self.assertIn(("percent", 0), self.progress)
            self.assertEqual(
                sum(
                    event["operation"] == "write_messages"
                    and event.get("data", b"")[4:] == b"\x27\x01"
                    for event in self.events
                ),
                1,
            )
            self.assertEqual(
                sum(
                    event["operation"] == "write_messages" and "messages" in event
                    for event in self.events
                ),
                1,
            )

    def test_native_finish_and_filter_faults_keep_normal_callback_host_fault_stays_fatal(
        self,
    ):
        from scripts.programming_2026_common import NativeException2026

        for phase in ("finish", "prepare_stop_filter", "stop_filter"):
            failed = False

            def fault(event, phase=phase):
                nonlocal failed
                selected = (
                    event["operation"] == "write_messages"
                    and event.get("data", b"") == bytes.fromhex("0000072080")
                    if phase == "finish"
                    else event["operation"] == "stop_filter"
                    and event["identifier"]
                    == (1 if phase == "prepare_stop_filter" else 2)
                )
                if selected and not failed:
                    failed = True
                    raise NativeException2026("authored native cleanup fault")

            result = self.run_writer(retry=(True,), fault=fault)
            self.assertEqual(result["completion_callback"], "normal")
            self.assertTrue(result["writer_completed"])
            self.assertIn(phase, result["swallowed_native_faults"])
            self.assertEqual(result["retry_decisions_consumed"], 0)
            self.assertFalse(
                any(event["operation"] == "disconnect" for event in self.events)
            )
            self.assertEqual(result["counts"], (4096,))
            self.assertEqual(self.runtime.close(), [])
            self.assertEqual(self.filters, set())

    def test_prepare_native_failure_only_prepares_retry_and_host_fault_propagates(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        for native in (False, True):
            error = (
                NativeJ2534Error2026(7) if native else OSError("authored host fault")
            )

            def fault(event, error=error):
                if (
                    event["operation"] == "write_messages"
                    and event.get("data", b"")[4:] == b"\x27\x01"
                ):
                    raise error

            if native:
                result = self.run_writer(retry=(True,), fault=fault)
                self.assertTrue(result["retry_prepared"])
                self.assertFalse(result["writer_completed"])
                self.assertEqual(result["restarts"], 0)
            else:
                with self.assertRaises(OSError) as caught:
                    self.run_writer(retry=(True,), fault=fault)
                self.assertIs(caught.exception, error)
                self.assertFalse(
                    any(
                        event["operation"] in ("connect", "disconnect")
                        for event in self.events
                    )
                )
            self.assertEqual(self.filters, set())
            self.assertEqual(self.runtime.close(), [])


if __name__ == "__main__":
    unittest.main()


class CANEPBWriterTests(unittest.TestCase):
    def run_writer(self, *, fault=None, retry=(), recovery=False, context=None):
        from scripts.programming_2026_consolidated import (
            CANEPBWriteContext,
            write_can_epb,
        )

        self.events, self.filters, self.pending, self.progress = [], set(), [], []
        self.cancelled = False
        context = context or CANEPBWriteContext(
            IDENTITY,
            bytes.fromhex("07d907d100000720"),
            0,
            b"\xa5" * 1024,
            1024,
            tuple(bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")),
            recovery_timeout=recovery,
            retry_decisions=retry,
        )
        counter = 0

        def provider(event, remaining):
            nonlocal counter
            self.events.append(event)
            if fault is not None:
                fault(event)
            name = event["operation"]
            if name == "get_protocol_id":
                return 6
            if name == "get_timeout":
                return 1000
            if name == "start_flow_control_filter":
                counter += 1
                self.filters.add(counter)
                return counter
            if name == "stop_filter":
                self.filters.remove(event["identifier"])
            if name == "write_messages":
                if "messages" in event:
                    self.assertEqual(event["count"], 5)
                    self.pending.extend((b"\x3c", b"information"))
                else:
                    address_length = 5 if event["tx_flags"] == 0x80 else 4
                    payload = event["data"][address_length:]
                    if payload == bytes.fromhex("270100"):
                        self.pending.append(bytes.fromhex("6701010203"))
                    elif payload.startswith(b"\x27\x02"):
                        self.assertEqual(payload, bytes.fromhex("2702414243c0"))
                        self.pending.append(bytes.fromhex("6702"))
                    elif payload == b"\x10\x02":
                        self.pending.append(b"\x50")
                    elif payload == b"\x75":
                        self.pending.extend(
                            (b"\x3c", bytes.fromhex("0010000013ff0100"), b"\x3c")
                        )
                    elif payload == b"\x50":
                        self.pending.extend((b"\x3c", b"\0", b"\x3c"))
                    elif (
                        payload in (b"\x41", b"\x45")
                        or payload[:1] in (b"\x25", b"\x15")
                        or len(payload) in (256, 1024)
                    ):
                        self.pending.append(b"\x3c")
                return event["count"]
            if name == "read_specified_can_message":
                return event["address"] + self.pending.pop(0)
            return None

        self.runtime = NativeRuntime2026(provider, cancelled=lambda: self.cancelled)
        return write_can_epb(
            context,
            self.runtime,
            progress=lambda field, value: self.progress.append((field, value)),
        )

    def test_actual_epb_prepare_erase_page_verify_finish_order(self):
        result = self.run_writer()
        self.assertTrue(result["writer_completed"])
        self.assertEqual(result["counts"], (2048,))
        self.assertEqual(result["percentages"], (100,))
        self.assertEqual(result["retry_decisions_consumed"], 0)
        writes = [
            event for event in self.events if event["operation"] == "write_messages"
        ]
        payloads = [event.get("data", b"") for event in writes]
        self.assertEqual(payloads[0], bytes.fromhex("000007502c270100"))
        self.assertEqual(payloads.count(bytes.fromhex("00000720a027")), 3)
        erase = payloads.index(bytes.fromhex("000007d12500"))
        write = payloads.index(bytes.fromhex("000007d141"))
        verify = payloads.index(bytes.fromhex("000007d11500"))
        self.assertLess(erase, write)
        self.assertLess(write, verify)
        self.assertEqual(payloads[-1], bytes.fromhex("0000072080"))
        self.assertEqual(sum(len(value) == 260 for value in payloads), 4)
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
        )
        self.assertEqual(self.filters, set())
        self.assertEqual(self.runtime.close(), [])

    def test_actual_imported_epb_metadata_archive_and_target_consumer(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw
        from scripts.programming_2026_consolidated import bind_can_epb_writer

        image = b"\xa5" * 1024
        lines = []
        for offset in range(0, len(image), 128):
            body = (
                bytes((133,))
                + (0x1000 + offset).to_bytes(4, "big")
                + image[offset : offset + 128]
            )
            lines.append(b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode())
        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\nContactType=CAN\nKindOfECU=7\n[CPU01]\nCPUType=27\nLocationID=07d907d100000720\nNewCID=AUTHORED\nCPUImageName=main\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED\n01_TargetData=ffffffff\n[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000400\nDataFormatID=01\n"
        container = parse_cuw(
            metadata_container(metadata, [(b"main", b"\n".join(lines) + b"\n")], 1)
        )
        materials = tuple(
            bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")
        )
        bound = bind_can_epb_writer(
            container, IDENTITY, {"epb_security_materials": materials}
        )
        self.assertEqual(
            (bound.cpu_type, bound.password, bound.flash_size, bound.image),
            ("27", 0, 1024, image),
        )
        self.assertTrue(self.run_writer(context=bound)["writer_completed"])
        with self.assertRaises(ValueError):
            bind_can_epb_writer(
                container,
                IDENTITY,
                {"epb_security_materials": materials, "image": image},
            )
        with self.assertRaises(ValueError):
            bind_can_epb_writer(
                container,
                IDENTITY,
                {"epb_security_materials": materials},
                target_index=1,
            )

    def test_native_prepare_and_write_errors_only_prepare_replacement_session(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        for selected in (
            bytes.fromhex("000007502c270100"),
            bytes.fromhex("000007d12500"),
        ):

            def fault(event, selected=selected):
                if event.get("data") == selected:
                    raise NativeJ2534Error2026(7)

            result = self.run_writer(fault=fault, retry=(True,))
            self.assertFalse(result["writer_completed"])
            self.assertTrue(result["retry_prepared"])
            self.assertEqual(result["retry_decisions_consumed"], 1)
            self.assertEqual(result["counts"], (0,))
            self.assertEqual(self.filters, set())
            self.assertEqual(
                [event["operation"] for event in self.events].count("connect"), 1
            )
            self.assertEqual(self.runtime.close(), [])

    def test_finish_and_cleanup_native_all_scopes_keep_worker_success(self):
        from scripts.programming_2026_common import NativeException2026

        for selected in ("finish", "prepare_stop_filter", "stop_filter"):
            failed = False

            def fault(event, selected=selected):
                nonlocal failed
                matches = (
                    event.get("data") == bytes.fromhex("0000072080")
                    if selected == "finish"
                    else event["operation"] == "stop_filter"
                    and event["identifier"]
                    == (1 if selected == "prepare_stop_filter" else 2)
                )
                if matches and not failed:
                    failed = True
                    raise NativeException2026("authored native fault")

            result = self.run_writer(fault=fault)
            self.assertTrue(result["writer_completed"])
            self.assertEqual(result["completion_callback"], "normal")
            self.assertIn(selected, result["swallowed_native_faults"])
            self.assertEqual(self.runtime.close(), [])
            self.assertEqual(self.filters, set())

    def test_host_faults_propagate_with_filter_and_timeout_cleanup(self):
        for selected in (
            bytes.fromhex("000007502c270100"),
            bytes.fromhex("000007d12500"),
            bytes.fromhex("0000072080"),
        ):
            error = OSError("authored host fault")

            def fault(event, selected=selected, error=error):
                if event.get("data") == selected:
                    raise error

            with self.assertRaises(OSError) as caught:
                self.run_writer(fault=fault, retry=(True,))
            self.assertIs(caught.exception, error)
            self.assertEqual(self.filters, set())
            self.assertEqual(
                self.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
            )
            self.assertEqual(self.runtime.close(), [])

    def test_recovery_timeout_and_native_firmware_error(self):
        result = self.run_writer(recovery=True)
        self.assertTrue(result["writer_completed"])
        self.assertIn({"operation": "set_timeout", "milliseconds": 10000}, self.events)

        def fault(event):
            if event.get("data") == bytes.fromhex("000007d175"):
                self.pending.extend(
                    (b"\x3c", bytes.fromhex("0010000013ff0110"), b"\x3c")
                )
                event["data"] = bytes.fromhex("000007d100")

        result = self.run_writer(fault=fault)
        self.assertEqual(result["error_code"], 10)
        self.assertFalse(result["writer_completed"])

    def test_host_cancel_is_fatal_and_owned_resources_remain_releasable(self):
        cancelled = False
        error = TimeoutError("authored deadline")

        def fault(event):
            nonlocal cancelled
            if event.get("data") == bytes.fromhex("000007d12500"):
                cancelled = True
                raise error

        with self.assertRaises(TimeoutError) as caught:
            self.run_writer(fault=fault, retry=(True,))
        self.assertTrue(cancelled)
        self.assertIs(caught.exception, error)
        self.assertEqual(self.filters, set())
        self.assertEqual(self.runtime.close(), [])

    def test_native_prepare_empty_exception_propagates_without_worker_or_retry(self):
        from scripts.programming_2026_common import NativeException2026

        def fault(event):
            if event.get("data") == bytes.fromhex("000007502c270100"):
                raise NativeException2026("authored native cancellation")

        with self.assertRaises(NativeException2026):
            self.run_writer(fault=fault, retry=(True,))
        self.assertFalse(
            any(event["operation"] == "disconnect" for event in self.events)
        )
        self.assertFalse(
            any(
                event.get("data") == bytes.fromhex("000007d175")
                for event in self.events
            )
        )
        self.assertEqual(self.filters, set())

    def test_native_connect_failure_reasks_and_disconnect_failure_is_swallowed(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        attempts = 0

        def fault(event):
            nonlocal attempts
            if event.get("data") == bytes.fromhex("000007502c270100"):
                raise NativeJ2534Error2026(7)
            if event["operation"] == "disconnect":
                raise NativeJ2534Error2026(7)
            if event["operation"] == "connect":
                attempts += 1
                if attempts == 1:
                    raise NativeJ2534Error2026(7)

        result = self.run_writer(fault=fault, retry=(True, True))
        self.assertTrue(result["retry_prepared"])
        self.assertEqual(result["retry_decisions_consumed"], 2)
        self.assertFalse(result["writer_completed"])
        self.assertEqual(result["error_code"], 0)
        self.assertEqual(result["swallowed_native_faults"].count("disconnect"), 2)

    def test_actual_host_cancellation_boundary_preserves_cleanup_without_retry(self):
        def fault(event):
            if event.get("data") == bytes.fromhex("000007d12500"):
                self.cancelled = True

        with self.assertRaises(InterruptedError):
            self.run_writer(fault=fault, retry=(True,))
        self.assertEqual(self.filters, set())
        self.assertFalse(
            any(event["operation"] == "disconnect" for event in self.events)
        )
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
        )
        self.assertEqual(self.runtime.close(), [])


class ElectricFoundationTests(unittest.TestCase):
    def test_initialized_cpu117_geometry_and_literal_cpu_gate(self):
        from scripts.programming_2026_consolidated import (
            consolidated_electric_block_sizes,
        )

        sizes = consolidated_electric_block_sizes("117")
        self.assertEqual(sizes, (8192, 122880, 122880, 8192))
        self.assertEqual(sum(sizes), 262144)
        for text in ("0117", "118", "117 "):
            with self.assertRaises(ConsolidatedError) as caught:
                consolidated_electric_block_sizes(text)
            self.assertEqual(caught.exception.code, 9999)

    def test_electric_security_native_one_byte_decrement_wraps_zero(self):
        request, response = bytes.fromhex("000007c1"), bytes.fromhex("000007c9")
        for seed, expected in ((0, 255), (1, 0), (255, 254)):
            events = []
            replies = iter(
                (response + b"\x67\x01" + bytes((seed,)), response + b"\x67\x02")
            )

            def provider(event, remaining, events=events, replies=replies):
                events.append(event)
                if event["operation"] == "get_timeout":
                    return 1000
                if event["operation"] == "write_messages":
                    return 1
                if event["operation"] == "read_specified_can_message":
                    return next(replies)
                return None

            ConsolidatedCAN2026(NativeRuntime2026(provider)).electric_security_access(
                request, response
            )
            self.assertEqual(
                [
                    event["data"]
                    for event in events
                    if event["operation"] == "write_messages"
                ],
                [request + b"\x27\x01", request + b"\x27\x02" + bytes((expected,))],
            )
            self.assertIn({"operation": "wait", "milliseconds": 100}, events)

    def test_separate_check_id_matches_batched_bytes_with_four_three_ms_waits(self):
        from scripts.programming_vendor import common_check_id_frames

        request, response = bytes.fromhex("000007d1"), bytes.fromhex("000007d9")
        location = bytes.fromhex("07d907d100000720")
        events = []
        replies = iter((response + b"\x3c", response + b"information"))

        def provider(event, remaining):
            events.append(event)
            if event["operation"] == "write_messages":
                return event["count"]
            if event["operation"] == "read_specified_can_message":
                return next(replies)
            return None

        channel = ConsolidatedCAN2026(NativeRuntime2026(provider))
        channel.check_id(
            request, response, location, 0x12345678, inter_message_wait_ms=3
        )
        writes = [
            event["data"] for event in events if event["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes,
            [request + part for part in common_check_id_frames(location, 0x12345678)]
            + [request + b"\x3c"],
        )
        self.assertEqual(
            [event["milliseconds"] for event in events if event["operation"] == "wait"],
            [3] * 4,
        )
        with self.assertRaises(ValueError):
            channel.check_id(request, response, location, 0, inter_message_wait_ms=True)


class SILM16CFoundationTests(unittest.TestCase):
    def channel(self, replies):
        from scripts.programming_2026_consolidated import ConsolidatedSILM16C2026

        self.events = []
        source = iter(replies)

        def provider(event, remaining):
            self.events.append(event)
            if event["operation"] == "write_messages":
                return event["count"]
            if event["operation"] == "read_after_indication":
                item = next(source)
                if isinstance(item, Exception):
                    raise item
                return item
            return None

        return ConsolidatedSILM16C2026(NativeRuntime2026(provider))

    def test_raw_read_accumulates_discards_excess_and_bounds_empty_stream(self):
        channel = self.channel([b"", b"a", b"bcd", b"X"])
        self.assertEqual(channel.read_exact(2), b"ab")
        self.assertEqual(channel.read_exact(1), b"X")
        self.assertEqual(channel.read_exact(0), b"")
        channel = self.channel([b""] * 4096)
        with self.assertRaises(TimeoutError):
            channel.read_exact(1)

    def test_password_batch_and_bit_mask_acceptance(self):
        channel = self.channel([bytes.fromhex("000c")])
        channel.check_id(0x12345678)
        self.assertEqual(
            self.events[0],
            {
                "operation": "write_messages",
                "protocol": 3,
                "tx_flags": 0,
                "count": 2,
                "messages": (
                    bytes.fromhex("a0dfff0f07"),
                    bytes.fromhex("12345678000000"),
                ),
            },
        )
        channel = self.channel([bytes.fromhex("0008")])
        with self.assertRaises(ConsolidatedError) as caught:
            channel.check_id(0)
        self.assertEqual(caught.exception.code, 7)

    def test_erase_signed_busy_mask_and_exact_address_byte_order(self):
        channel = self.channel([bytes.fromhex("0000"), bytes.fromhex("8000")])
        channel.erase(0xFBFFF)
        self.assertEqual(
            [
                event["data"]
                for event in self.events
                if event["operation"] == "write_messages"
            ],
            [b"\xa6", bytes.fromhex("a1bf0fd0"), b"\xa4", b"\xa4"],
        )
        channel = self.channel([bytes.fromhex("9000")])
        with self.assertRaises(ConsolidatedError) as caught:
            channel.erase(0xFBFFF)
        self.assertEqual(caught.exception.code, 12)

    def test_page_write_verify_batches_progress_and_native_denominator(self):
        channel = self.channel(
            [bytes.fromhex("8000"), b"\xff", b"\x00", bytes.fromhex("8000")]
        )
        data = b"\xa5" * 256
        progress = []
        observer = lambda key, value: progress.append((key, value))
        channel.page(0xFA000, data, progress=observer)
        channel.page(0xFA000, data, verify=True, progress=observer)
        channel.page(0xFA100, data, progress=observer)
        batches = [event["messages"] for event in self.events if "messages" in event]
        self.assertEqual(
            batches,
            [
                (bytes.fromhex("a2a00f"), data),
                (bytes.fromhex("a3a00f"), data),
                (bytes.fromhex("a2a10f"), data),
            ],
        )
        self.assertEqual(
            progress,
            [
                ("count", 256),
                ("percent", 50),
                ("count", 512),
                ("percent", 100),
                ("count", 768),
                ("percent", 150),
            ],
        )

    def test_native_timeout_maps_to_operation_error_host_faults_propagate(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        for native_code in (9, 16):
            channel = self.channel([NativeJ2534Error2026(native_code)])
            with self.assertRaises(ConsolidatedError) as caught:
                channel.page(0xFA000, bytes(256))
            self.assertEqual(caught.exception.code, 13)
        for error in (OSError("authored host fault"), NativeJ2534Error2026(7)):
            channel = self.channel([error])
            with self.assertRaises(type(error)) as caught:
                channel.erase(0xFBFFF)
            self.assertIs(caught.exception, error)

    def test_programming_fast_init_exact_location_password_timing_and_drain(self):
        from scripts.j2534_2026 import NativeMessage
        from scripts.programming_2026_consolidated import ConsolidatedSILM16C2026

        events = []

        def provider(event, remaining):
            events.append(event)
            if event["operation"] == "fast_init":
                return NativeMessage(
                    protocol_id=3, rx_status=2, tx_flags=0, timestamp=0, data=b""
                )
            if event["operation"] == "read_messages":
                return b"authored drain"
            if event["operation"] == "write_messages":
                return 1
            return None

        channel = ConsolidatedSILM16C2026(NativeRuntime2026(provider))
        channel.enter_programming(bytes.fromhex("07d907d100000720"), 0x12345678)
        self.assertEqual(
            events,
            [
                {"operation": "control_io", "ioctl": 2, "parameters": ((0x14, 70),)},
                {"operation": "control_io", "ioctl": 2, "parameters": ((0x15, 80),)},
                {
                    "operation": "fast_init",
                    "data": bytes.fromhex("0000d107d90778563412"),
                    "tx_flags": 0,
                },
                {"operation": "read_messages", "count": 1},
                {
                    "operation": "write_messages",
                    "protocol": 3,
                    "tx_flags": 0,
                    "count": 1,
                    "data": b"\x3c",
                },
            ],
        )

    def test_programming_mode_maps_native_selector_and_preserves_distinct_boot_exception(
        self,
    ):
        from scripts.programming_2026_consolidated import ConsolidatedSILBootError

        for mode, expected in ((0, 0), (5, 6), (6, 0)):
            channel = self.channel([b"\x3c", b"", b"junk", b"\x3c", b"\x3c"])
            channel.select_programming_mode(mode)
            self.assertEqual(
                [
                    event["data"]
                    for event in self.events
                    if event["operation"] == "write_messages"
                ],
                [b"\x60", bytes((expected,)), b"\x05"],
            )
            self.assertIn({"operation": "wait", "milliseconds": 100}, self.events)
        for value, reason in ((255, 1), (0, 2), (127, 2)):
            channel = self.channel([bytes((value,))])
            with self.assertRaises(ConsolidatedSILBootError) as caught:
                channel.select_programming_mode(0)
            self.assertEqual(caught.exception.reason, reason)
            self.assertNotIsInstance(caught.exception, ConsolidatedError)


class SILM16CWriterTests(unittest.TestCase):
    def run_writer(self, *, fault=None, retry=(), context=None, snapshot=None):
        from scripts.j2534_2026 import NativeMessage
        from scripts.programming_2026_consolidated import (
            SILM16CWriteContext,
            write_sil_m16c,
        )

        context = context or SILM16CWriteContext(
            IDENTITY,
            "1",
            ("18", "17"),
            (bytes.fromhex("1111222200000720"), bytes.fromhex("3333444400000721")),
            (0x12345678, 0xAABBCCDD),
            b"\xa5" * 24576,
            cpu_index=1,
            retry_decisions=retry,
        )
        self.events, self.progress, self.replies = [], [], []
        self.cancelled = False
        status = b"\x80\0"

        def provider(event, remaining):
            nonlocal status
            self.events.append(event)
            if fault is not None:
                fault(event)
            name = event["operation"]
            if name == "get_protocol_id":
                return 3
            if name == "fast_init":
                return NativeMessage(3, b"", rx_status=0)
            if name == "write_messages":
                data = event.get("data")
                if "messages" in event:
                    messages = event["messages"]
                    status = b"\0\x0c" if messages[0].startswith(b"\xa0") else b"\x80\0"
                elif data in (b"\x60", b"\0", b"\x05"):
                    self.replies.append(b"\x3c")
                elif data == b"\xa4":
                    self.replies.append(status)
                elif data == b"\xa8":
                    self.replies.append(b"\0")
                elif data.startswith(b"\xa1"):
                    status = b"\x80\0"
                return event["count"]
            if name == "read_after_indication":
                return self.replies.pop(0)
            return None

        self.runtime = NativeRuntime2026(provider, cancelled=lambda: self.cancelled)
        return write_sil_m16c(
            context,
            self.runtime,
            progress=lambda key, value: self.progress.append((key, value)),
            progress_snapshot=snapshot,
        )

    def test_native_other_cpu_prepare_three_areas_96pages_write_verify(self):
        result = self.run_writer()
        self.assertTrue(result["writer_completed"])
        self.assertEqual((result["count"], result["percent"]), (49152, 9600))
        self.assertEqual(result["boot_cpu_index"], 0)
        fast = next(event for event in self.events if event["operation"] == "fast_init")
        self.assertEqual(fast["data"], bytes.fromhex("00002222111178563412"))
        batches = [event["messages"] for event in self.events if "messages" in event]
        self.assertEqual(
            batches[0], (bytes.fromhex("a0dfff0f07"), bytes.fromhex("aabbccdd000000"))
        )
        self.assertEqual(len(batches), 193)
        erases = [
            event["data"]
            for event in self.events
            if event.get("data", b"").startswith(b"\xa1")
        ]
        self.assertEqual(
            erases,
            [bytes.fromhex(value) for value in ("a1bf0fd0", "a1df0fd0", "a1ff0fd0")],
        )
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
        )
        self.assertEqual(self.progress[-2:], [("count", 49152), ("percent", 9600)])

    def test_no_other_cpu_17_or18_uses_error_path_without_programming(self):
        from scripts.programming_2026_consolidated import SILM16CWriteContext

        context = SILM16CWriteContext(
            IDENTITY, "1", ("17",), (bytes(8),), (0,), bytes(24576)
        )
        result = self.run_writer(context=context)
        self.assertFalse(result["writer_completed"])
        self.assertIsNone(result["boot_cpu_index"])
        self.assertEqual(result["error_code"], 0)
        self.assertFalse(
            any(event["operation"] == "fast_init" for event in self.events)
        )

    def test_native_write_error_resets_count_without_observer_then_reconnects_only(
        self,
    ):
        from scripts.j2534_2026 import NativeJ2534Error2026

        pages = 0

        def fault(event):
            nonlocal pages
            if event.get("messages", (b"",))[0].startswith(b"\xa2"):
                pages += 1
                if pages == 2:
                    raise NativeJ2534Error2026(7)

        result = self.run_writer(fault=fault, retry=(True,))
        self.assertFalse(result["writer_completed"])
        self.assertTrue(result["retry_prepared"])
        self.assertEqual((result["count"], result["percent"]), (0, 0))
        self.assertEqual(self.progress[-2:], [("count", 512), ("percent", 100)])
        self.assertEqual(
            [event for event in self.events if event["operation"] == "connect"],
            [{"operation": "connect", "protocol": 3}],
        )
        self.assertEqual(pages, 2)

    def test_host_fault_propagates_and_restores_timeout_without_retry(self):
        error = OSError("authored host write fault")

        def fault(event):
            if event.get("messages", (b"",))[0].startswith(b"\xa2"):
                raise error

        with self.assertRaises(OSError) as caught:
            self.run_writer(fault=fault, retry=(True,))
        self.assertIs(caught.exception, error)
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
        )
        self.assertFalse(
            any(event["operation"] == "disconnect" for event in self.events)
        )

    def test_actual_multicpu_metadata_selects_other_boot_target_and_selected_image(
        self,
    ):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw
        from scripts.programming_2026_consolidated import bind_sil_m16c_writer

        image = b"\xa5" * 24576
        lines = []
        for offset in range(0, len(image), 128):
            body = (
                bytes((133,))
                + (0xFA000 + offset).to_bytes(4, "big")
                + image[offset : offset + 128]
            )
            lines.append(b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode())
        boot_lines = []
        for offset in range(0, len(image), 128):
            body = bytes((133,)) + (0xFA000 + offset).to_bytes(4, "big") + b"\xb6" * 128
            boot_lines.append(
                b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode()
            )
        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=2\nContactType=SIL\nKindOfECU=1\n"
        for index, cpu, location in (
            (1, "18", "1111222200000720"),
            (2, "17", "3333444400000721"),
        ):
            metadata += f"[CPU{index:02d}]\nCPUType={cpu}\nLocationID={location}\nNewCID=AUTHORED\nCPUImageName={'boot' if index == 1 else 'main'}\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED\n01_TargetData=ffffffff\n"
        metadata += "[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=000FA000\n01_Length=00006000\nDataFormatID=01\n"
        metadata += "[CPUImage02]\nNumberOfAreaSettings=1\n01_StartAddress=000FA000\n01_Length=00006000\nDataFormatID=01\n"
        container = parse_cuw(
            metadata_container(
                metadata,
                [
                    (b"boot", b"\n".join(boot_lines) + b"\n"),
                    (b"main", b"\n".join(lines) + b"\n"),
                ],
                2,
            )
        )
        bound = bind_sil_m16c_writer(
            container, IDENTITY, target_indices=(0, 0), cpu_index=1
        )
        self.assertEqual(bound.cpu_types, ("18", "17"))
        self.assertEqual(bound.passwords, (0, 0))
        self.assertEqual(bound.image, image)
        self.assertTrue(self.run_writer(context=bound)["writer_completed"])
        for vector in ((0,), (0, 1), (False, 0)):
            with self.assertRaises(ValueError):
                bind_sil_m16c_writer(
                    container, IDENTITY, target_indices=vector, cpu_index=1
                )

    def test_native_timeout2000_fault_has_no_state5_reset_to1000(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        def fault(event):
            if event == {"operation": "set_timeout", "milliseconds": 2000}:
                raise NativeJ2534Error2026(7)

        result = self.run_writer(fault=fault)
        self.assertFalse(result["writer_completed"])
        self.assertEqual(result["error_phase"], "write")
        self.assertNotIn(
            {"operation": "set_timeout", "milliseconds": 1000}, self.events
        )
        self.assertEqual((result["count"], result["percent"]), (0, 0))

    def test_native_unknown_write_exception_resets_but_host_cancel_propagates(self):
        from scripts.programming_2026_common import NativeException2026

        for native in (True, False):

            def fault(event, native=native):
                if event.get("messages", (b"",))[0].startswith(b"\xa2"):
                    if native:
                        raise NativeException2026("authored native ALL")
                    self.cancelled = True

            if native:
                result = self.run_writer(fault=fault)
                self.assertFalse(result["writer_completed"])
                self.assertEqual(result["error_code"], 0)
                self.assertEqual((result["count"], result["percent"]), (0, 0))
            else:
                with self.assertRaises(InterruptedError):
                    self.run_writer(fault=fault, retry=(True,))
                self.assertFalse(
                    any(event["operation"] == "disconnect" for event in self.events)
                )
            self.assertEqual(
                self.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
            )

    def test_native_setbaud_subtype_maps_to_prepare_error5(self):
        def fault(event):
            if event.get("data") == b"\x60":
                self.replies.append(b"\xff")

        result = self.run_writer(fault=fault)
        self.assertEqual(result["error_code"], 5)
        self.assertEqual(result["error_phase"], "prepare")
        self.assertFalse(result["writer_completed"])
        self.assertFalse(
            any(event["operation"] == "set_timeout" for event in self.events)
        )


class ElectricWriterTests(unittest.TestCase):
    def run_writer(
        self, *, context=None, fault=None, retry=(), state=None, execute=None
    ):
        from scripts.programming_2026_consolidated import (
            CANElectricWriteContext,
            CANElectricWriteState,
            write_can_electric,
        )

        state = state or CANElectricWriteState()
        context = context or CANElectricWriteContext(
            IDENTITY,
            "117",
            bytes.fromhex("07d907d100000720"),
            bytes.fromhex("00000721"),
            0,
            b"\xa5" * 262144,
            262144,
            state,
            retry_decisions=retry,
        )
        self.events, self.pending, self.filters, self.progress = [], [], set(), []
        counter, check_frames = 0, 0
        self.cancelled = False

        def provider(event, remaining):
            nonlocal counter, check_frames
            self.events.append(event)
            if fault is not None:
                fault(event)
            name = event["operation"]
            if name == "get_protocol_id":
                return 6
            if name == "get_timeout":
                return 1000
            if name == "start_flow_control_filter":
                counter += 1
                self.filters.add(counter)
                return counter
            if name == "stop_filter":
                self.filters.remove(event["identifier"])
            if name == "write_messages":
                payload = event["data"][4:]
                if payload == b"\x27\x01":
                    self.pending.append(b"\x67\x01\0")
                elif payload == b"\x27\x02\xff":
                    self.pending.append(b"\x67\x02")
                elif payload == b"\x10\x02":
                    self.pending.append(b"\x50")
                elif (
                    event["data"][:4] == bytes.fromhex("000007d1") and check_frames < 5
                ):
                    check_frames += 1
                    if check_frames == 5:
                        self.pending.extend((b"\x3c", b"information"))
                elif payload == b"\x75":
                    self.pending.extend(
                        (b"\x3c", bytes.fromhex("001000040fff0170"), b"\x3c")
                    )
                elif payload == b"\x50":
                    self.pending.extend((b"\x3c", b"\0", b"\x3c"))
                elif (
                    payload in (b"\x41", b"\x45", b"\x80")
                    or payload[:1] in (b"\x25", b"\x47", b"\x15")
                    or len(payload) in (256, 1024)
                ):
                    self.pending.append(b"\x3c")
                return 1
            if name == "read_specified_can_message":
                return event["address"] + self.pending.pop(0)
            return None

        self.runtime = NativeRuntime2026(provider, cancelled=lambda: self.cancelled)
        if execute is not None:
            from scripts.programming_2026_consolidated import ConsolidatedExecuteContext

            engine, container, observer = execute
            return engine.execute(
                container,
                self.runtime,
                ConsolidatedExecuteContext(
                    writing=True,
                    retry_decisions=retry,
                    target_indices=(0,) * engine.common_definitions.num_cpu_maxnum,
                ),
                progress=observer,
            )
        return write_can_electric(
            context,
            self.runtime,
            progress=lambda key, value: self.progress.append((key, value)),
        )

    def test_cpu117_fixed_four_blocks_native_prepare_and_state_completion(self):
        result = self.run_writer()
        self.assertTrue(result["writer_completed"])
        self.assertEqual((result["counts"], result["percentages"]), ((524288,), (100,)))
        self.assertFalse(result["last_block"])
        self.assertFalse(result["block_started"])
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes.count(bytes.fromhex("00000721a027")), 3)
        self.assertEqual(writes[-1], bytes.fromhex("0000072080"))
        for opcode in (0x25, 0x47, 0x15):
            self.assertEqual(
                [data[5] for data in writes if len(data) == 6 and data[4] == opcode],
                [0, 1, 2, 3],
            )
        self.assertEqual(sum(len(data) == 1028 for data in writes), 256)
        self.assertEqual(sum(len(data) == 260 for data in writes), 1024)
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
        )
        self.assertEqual(self.filters, set())

    def test_native_last_block_failure_forces_password_byte_and_only_reconnects(self):
        from scripts.programming_2026_consolidated import ConsolidatedError

        def fault(event):
            if event.get("data") == bytes.fromhex("000007d12503"):
                raise ConsolidatedError(12, "authored")

        result = self.run_writer(fault=fault, retry=(True,))
        self.assertTrue(result["password_changed"])
        self.assertTrue(result["last_block"])
        self.assertTrue(result["block_started"])
        self.assertTrue(result["retry_prepared"])
        self.assertFalse(result["writer_completed"])
        self.assertEqual(result["counts"], (0,))
        self.assertEqual(self.progress[-2:], [("count", 0), ("percent", 0)])
        self.assertEqual(
            sum(event["operation"] == "connect" for event in self.events), 1
        )
        self.assertEqual(self.filters, set())

    def test_native_prepare_error7_toggles_password_without_started_flag(self):
        from scripts.programming_2026_consolidated import (
            CANElectricWriteState,
            ConsolidatedError,
        )

        for original in (False, True):
            state = CANElectricWriteState(password_changed=original)

            def fault(event):
                if event.get("data") == bytes.fromhex("000007c12701"):
                    raise ConsolidatedError(7, "authored")

            result = self.run_writer(fault=fault, state=state)
            self.assertEqual(result["password_changed"], not original)
            self.assertFalse(result["writer_completed"])
            self.assertFalse(
                any(
                    event.get("data") == bytes.fromhex("000007d175")
                    for event in self.events
                )
            )

    def test_host_fault_and_cancel_propagate_without_retry(self):
        for native_cancel in (False, True):
            error = OSError("authored host fault")

            def fault(event, native_cancel=native_cancel, error=error):
                if event.get("data") == bytes.fromhex("000007d12500"):
                    if native_cancel:
                        self.cancelled = True
                    else:
                        raise error

            with self.assertRaises(InterruptedError if native_cancel else OSError):
                self.run_writer(fault=fault, retry=(True,))
            self.assertFalse(
                any(event["operation"] == "disconnect" for event in self.events)
            )
            self.assertEqual(self.filters, set())
            self.assertEqual(
                self.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
            )

    def test_actual_cpu117_metadata_and_changed_password_image_branch(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw
        from scripts.programming_2026_common import NativeGeneralParameters2026
        from scripts.programming_2026_consolidated import (
            CANElectricWriteState,
            bind_can_electric_writer,
        )

        image = b"\xa5" * 262144
        lines = []
        for offset in range(0, len(image), 128):
            body = (
                bytes((133,))
                + (0x1000 + offset).to_bytes(4, "big")
                + image[offset : offset + 128]
            )
            lines.append(b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode())
        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\nContactType=CAN\nKindOfECU=45\n[CPU01]\nCPUType=117\nLocationID=07d907d100000720\nNewCID=AUTHORED\nCPUImageName=main\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED\n01_TargetData=ffffffff\n[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00040000\nDataFormatID=01\n"
        container = parse_cuw(
            metadata_container(metadata, [(b"main", b"\n".join(lines) + b"\n")], 1)
        )
        state = CANElectricWriteState()
        bound = bind_can_electric_writer(container, IDENTITY, state)
        self.assertIs(bound.state, state)
        self.assertEqual(
            (bound.image, bound.flash_size, bound.password), (image, 262144, 0)
        )
        self.assertTrue(self.run_writer(context=bound)["writer_completed"])
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": b"ParamFileKeySystemProtocolMicon,PasswordAddress,ByteOrder\r\n45CAN117,00000002,1\r\n"
            },
            encoded=False,
        )
        changed = bind_can_electric_writer(
            container,
            IDENTITY,
            CANElectricWriteState(password_changed=True),
            general_parameters=parameters,
        )
        self.assertEqual(changed.password, 0xA5A5A5A5)
        with self.assertRaises(ValueError):
            bind_can_electric_writer(container, IDENTITY, state, target_index=1)

    def test_prior_started_byte_ignores_prepare_failure_but_unknown_native_exception_propagates(
        self,
    ):
        from scripts.programming_2026_common import NativeException2026
        from scripts.programming_2026_consolidated import (
            CANElectricWriteState,
            ConsolidatedError,
        )

        for unknown in (False, True):
            error = (
                NativeException2026("authored native")
                if unknown
                else ConsolidatedError(16, "authored")
            )

            def fault(event, error=error):
                if event.get("data") == bytes.fromhex("000007c12701"):
                    raise error

            if unknown:
                with self.assertRaises(NativeException2026):
                    self.run_writer(
                        fault=fault, state=CANElectricWriteState(block_started=True)
                    )
            else:
                result = self.run_writer(
                    fault=fault, state=CANElectricWriteState(block_started=True)
                )
                self.assertTrue(result["writer_completed"])
            self.assertEqual(self.filters, set())

    def test_finish_native_failure_uses_write_error_and_preserves_last_block_byte(self):
        from scripts.programming_2026_consolidated import ConsolidatedError

        def fault(event):
            if event.get("data") == bytes.fromhex("0000072080"):
                raise ConsolidatedError(35, "authored")

        result = self.run_writer(fault=fault)
        self.assertFalse(result["writer_completed"])
        self.assertEqual(result["error_code"], 35)
        self.assertTrue(result["password_changed"])
        self.assertTrue(result["last_block"])
        self.assertEqual(result["counts"], (0,))
        self.assertEqual(self.filters, set())


class OldECBFoundationTests(unittest.TestCase):
    def test_security_literal_selector_seed_key_and_no_inter_key_delay(self):
        request, response = bytes.fromhex("000007b0"), bytes.fromhex("000007b8")
        for selector in (0, 2):
            events = []
            replies = iter(
                (response + bytes.fromhex("670101020304"), response + b"\x67\x02")
            )

            def provider(event, remaining, events=events, replies=replies):
                events.append(event)
                if event["operation"] == "get_timeout":
                    return 1000
                if event["operation"] == "write_messages":
                    return 1
                if event["operation"] == "read_specified_can_message":
                    return next(replies)
                return None

            channel = ConsolidatedCAN2026(NativeRuntime2026(provider))
            channel.old_ecb_security_access(
                request,
                response,
                selector,
                tuple(
                    bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")
                ),
            )
            self.assertEqual(
                [
                    event["data"]
                    for event in events
                    if event["operation"] == "write_messages"
                ],
                [
                    request + bytes((0x27, 1, selector)),
                    request + bytes.fromhex("2702414243c4"),
                ],
            )
            self.assertNotIn({"operation": "wait", "milliseconds": 100}, events)

    def test_old_ecb_error_disposal_literal05_ack65_ack(self):
        request, response = bytes.fromhex("000007d1"), bytes.fromhex("000007d9")
        events = []

        def provider(event, remaining):
            events.append(event)
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                return response + b"\x3c"
            return None

        ConsolidatedCAN2026(NativeRuntime2026(provider)).old_ecb_dispose_error(
            request, response
        )
        self.assertEqual(
            [
                event["data"]
                for event in events
                if event["operation"] == "write_messages"
            ],
            [request + b"\x05", request + b"\x65"],
        )
        self.assertEqual(
            [event["operation"] for event in events],
            [
                "write_messages",
                "read_specified_can_message",
                "write_messages",
                "read_specified_can_message",
            ],
        )


class OldECBWriterTests(unittest.TestCase):
    def run_writer(
        self,
        *,
        context=None,
        fault=None,
        retry=(),
        writer=None,
        separate_check=False,
        memory_override=None,
        snapshot=None,
    ):
        from scripts.programming_2026_consolidated import (
            CANOldECBWriteContext,
            CANOldECBWriteState,
            write_can_old_ecb,
        )

        context = context or CANOldECBWriteContext(
            IDENTITY,
            ("67",),
            (bytes.fromhex("07d907d100000720"),),
            (0,),
            (b"\xa5" * 122880,),
            (122880,),
            tuple(bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")),
            2,
            CANOldECBWriteState(),
            retry_decisions=retry,
        )
        self.events, self.pending, self.filters, self.progress = [], [], set(), []
        self.cancelled = False
        counter = check_frames = 0

        def provider(event, remaining):
            nonlocal counter, check_frames
            self.events.append(event)
            if fault is not None:
                fault(event)
            name = event["operation"]
            if name == "get_protocol_id":
                return 6
            if name == "get_timeout":
                return 1000
            if name == "start_flow_control_filter":
                counter += 1
                self.filters.add(counter)
                if separate_check and event["request_address"] != bytes.fromhex(
                    "000007b0"
                ):
                    check_frames = 5
                return counter
            if name == "stop_filter":
                self.filters.remove(event["identifier"])
            if name == "write_messages":
                if "messages" in event:
                    self.pending.extend((b"\x3c", b"information"))
                else:
                    payload = event["data"][4:]
                    if check_frames:
                        check_frames -= 1
                        if not check_frames:
                            self.pending.extend((b"\x3c", b"information"))
                    elif payload in (bytes.fromhex("270100"), bytes.fromhex("270102")):
                        self.pending.append(bytes.fromhex("670101020304"))
                    elif payload.startswith(b"\x27\x02"):
                        self.assertEqual(payload, bytes.fromhex("2702414243c4"))
                        self.pending.append(b"\x67\x02")
                    elif payload == b"\x10\x02":
                        self.pending.append(b"\x50")
                    elif payload == b"\x76":
                        self.pending.extend(
                            (
                                b"\x3c",
                                memory_override or bytes.fromhex("00100001efff019100"),
                                b"\x3c",
                            )
                        )
                    elif payload == b"\x50":
                        self.pending.extend((b"\x3c", b"\0", b"\x3c"))
                    elif (
                        payload in (b"\x41", b"\x45", b"\x05", b"\x65")
                        or payload[:1] in (b"\x26", b"\x48", b"\x16")
                        or len(payload) in (256, 1024)
                    ):
                        self.pending.append(b"\x3c")
                return event["count"]
            if name == "read_specified_can_message":
                return event["address"] + self.pending.pop(0)
            return None

        self.runtime = NativeRuntime2026(provider, cancelled=lambda: self.cancelled)
        return (writer or write_can_old_ecb)(
            context,
            self.runtime,
            progress=lambda key, value: self.progress.append((key, value)),
            progress_snapshot=snapshot,
        )

    def test_old_ecb_selectors_fixed_ranges_and_full_write_verify(self):
        result = self.run_writer()
        self.assertTrue(result["writer_completed"])
        self.assertEqual((result["counts"], result["percentages"]), ((245760,), (100,)))
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages" and "data" in event
        ]
        self.assertIn(bytes.fromhex("000007b0270100"), writes)
        self.assertIn(bytes.fromhex("000007b0270102"), writes)
        self.assertEqual(writes.count(bytes.fromhex("00000720a027")), 3)
        self.assertIn(bytes.fromhex("000007d1260000000f"), writes)
        self.assertIn(bytes.fromhex("000007d12600100077"), writes)
        self.assertEqual(writes[-1], bytes.fromhex("0000072080"))
        self.assertEqual(self.filters, set())

    def test_native_first_range_retry_disposes_then_repeats_check_id_and_memory(self):
        from scripts.programming_2026_consolidated import ConsolidatedError

        failed = False

        def fault(event):
            nonlocal failed
            if len(event.get("data", b"")) == 1028 and not failed:
                failed = True
                raise ConsolidatedError(13, "authored")

        result = self.run_writer(fault=fault, retry=(True,))
        self.assertTrue(result["writer_completed"])
        self.assertEqual(result["restarts"], 1)
        self.assertEqual(result["retry_decisions_consumed"], 1)
        writes = [
            event.get("data")
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertIn(bytes.fromhex("000007d105"), writes)
        self.assertIn(bytes.fromhex("000007d165"), writes)
        self.assertEqual(writes.count(bytes.fromhex("000007d176")), 2)
        self.assertEqual(sum("messages" in event for event in self.events), 2)
        self.assertEqual(self.filters, set())

    def test_later_range_error_retains_previous_range_bytes_and_password_rule(self):
        from scripts.programming_2026_consolidated import ConsolidatedError

        def fault(event):
            if event.get("data") == bytes.fromhex("000007d12600100077"):
                raise ConsolidatedError(12, "authored")

        result = self.run_writer(fault=fault)
        self.assertFalse(result["writer_completed"])
        self.assertTrue(result["password_changed"])
        self.assertEqual(result["counts"], (32768,))
        self.assertEqual(result["percentages"], (13,))
        self.assertEqual(self.progress[-2:], [("count", 32768), ("percent", 13)])

    def test_host_write_fault_propagates_and_releases_borrowed_filters(self):
        error = OSError("authored host fault")

        def fault(event):
            if len(event.get("data", b"")) == 1028:
                raise error

        with self.assertRaises(OSError) as caught:
            self.run_writer(fault=fault, retry=(True,))
        self.assertIs(caught.exception, error)
        self.assertEqual(self.filters, set())
        self.assertFalse(
            any(event["operation"] == "disconnect" for event in self.events)
        )
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
        )

    def test_actual_rom_callback_state_and_imported_archive_feed_old_writer(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw
        from scripts.programming_2026_consolidated import (
            CANOldECBWriteState,
            bind_can_old_ecb_writer,
        )

        state = ConsolidatedControllerState()
        replies = iter(
            bytes.fromhex("000007b8") + bytes((0xE4, selector)) + bytes(5) + text
            for selector, text in ((0, b"OLDROM01"), (2, b"OLDROM02"))
        )

        def getter_provider(event, remaining):
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] == "start_flow_control_filter":
                return 1
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                return next(replies)
            return None

        self.assertEqual(
            get_ecb_rom_identifiers(
                IDENTITY, NativeRuntime2026(getter_provider), state
            ),
            ("OLDROM01", "OLDROM02"),
        )
        image = b"\xa5" * 122880
        lines = []
        for offset in range(0, len(image), 128):
            body = (
                bytes((133,))
                + (0x1000 + offset).to_bytes(4, "big")
                + image[offset : offset + 128]
            )
            lines.append(b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode())
        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\nContactType=CAN\nKindOfECU=4\n[CPU01]\nCPUType=67\nLocationID=07d907d100000720\nNewCID=AUTHORED\nCPUImageName=main\nNumberOfTargets=1\n01_TargetCalibration=OLDROM01\n01_TargetData=ffffffff\n[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=0001e000\nDataFormatID=01\n"
        container = parse_cuw(
            metadata_container(metadata, [(b"main", b"\n".join(lines) + b"\n")], 1)
        )
        material = tuple(
            bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")
        )
        context = bind_can_old_ecb_writer(
            container,
            IDENTITY,
            state,
            CANOldECBWriteState(),
            {"old_ecb_security_materials": material},
            target_indices=(0,),
        )
        self.assertEqual(context.prepare_count, 2)
        self.assertEqual(context.images, (image,))
        self.assertTrue(self.run_writer(context=context)["writer_completed"])
        with self.assertRaises(ValueError):
            bind_can_old_ecb_writer(
                container,
                IDENTITY,
                ConsolidatedControllerState(),
                CANOldECBWriteState(),
                {"old_ecb_security_materials": material},
                target_indices=(0,),
            )

    def test_multiple_cpu_native65_handoff_and_final_finish_use_distinct_locations(
        self,
    ):
        from scripts.programming_2026_consolidated import (
            CANOldECBWriteContext,
            CANOldECBWriteState,
        )

        context = CANOldECBWriteContext(
            IDENTITY,
            ("67", "67"),
            (bytes.fromhex("07d907d100000720"), bytes.fromhex("07da07d200000721")),
            (0, 0),
            (b"\xa5" * 122880, b"\xb6" * 122880),
            (122880, 122880),
            tuple(bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")),
            2,
            CANOldECBWriteState(),
        )
        result = self.run_writer(context=context)
        self.assertTrue(result["writer_completed"])
        self.assertEqual(result["counts"], (245760, 245760))
        writes = [
            event.get("data")
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertIn(bytes.fromhex("000007d165"), writes)
        self.assertEqual(writes[-1], bytes.fromhex("0000072180"))
        self.assertTrue(
            any(data == bytes.fromhex("000007d2") + b"\xb6" * 1024 for data in writes)
        )
        self.assertEqual(self.filters, set())


class SILBaseFoundationTests(unittest.TestCase):
    def channel(self, replies):
        from scripts.programming_2026_consolidated import ConsolidatedSILFlash2026

        self.events = []
        source = iter(replies)

        def provider(event, remaining):
            self.events.append(event)
            if event["operation"] == "write_messages":
                return event["count"]
            if event["operation"] == "read_after_indication":
                value = next(source)
                if isinstance(value, Exception):
                    raise value
                return value
            return None

        return ConsolidatedSILFlash2026(NativeRuntime2026(provider))

    def test_status_retries_three_native_read_faults_or_bad_frames_and_waits10(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        channel = self.channel([NativeJ2534Error2026(7), b"bad", b"\x3c\x40\x3c"])
        self.assertEqual(channel.get_status(), 0x40)
        self.assertEqual(
            [
                event["data"]
                for event in self.events
                if event["operation"] == "write_messages"
            ],
            [b"\x50"] * 3,
        )
        self.assertEqual(
            [
                event["milliseconds"]
                for event in self.events
                if event["operation"] == "wait"
            ],
            [10, 10],
        )
        channel = self.channel([b"bad"] * 3)
        with self.assertRaises(ConsolidatedError) as caught:
            channel.get_status()
        self.assertEqual(caught.exception.code, 4)
        channel = self.channel([b"bad"])
        with self.assertRaises(ConsolidatedError):
            channel.get_status(False)
        self.assertEqual(len(self.events), 2)

    def test_memory75_discovery_falls_back76_and_retains_format(self):
        descriptor = bytes.fromhex("0010000013ff0181")
        channel = self.channel(
            [
                bytes(10),
                b"\x3c" + descriptor + b"X\x3c",
                b"\x3c" + descriptor + b"Y\x3c",
            ]
        )
        memory = channel.memory_info()
        self.assertEqual(
            (memory.start_address, memory.end_address, memory.firmware_version),
            (0x1000, 0x13FF, 0x81),
        )
        self.assertTrue(channel.memory_shrink)
        channel.memory_info()
        self.assertEqual(
            [
                event["data"]
                for event in self.events
                if event["operation"] == "write_messages"
            ],
            [b"\x75", b"\x76", b"\x76"],
        )

    def test_memory_initial_native_read_fault_fallback_but_host_fault_propagates(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        channel = self.channel(
            [
                NativeJ2534Error2026(7),
                b"\x3c" + bytes.fromhex("0010000013ff0181") + b"X\x3c",
            ]
        )
        channel.memory_info()
        self.assertTrue(channel.memory_shrink)
        error = OSError("authored host fault")
        channel = self.channel([error])
        with self.assertRaises(OSError) as caught:
            channel.memory_info()
        self.assertIs(caught.exception, error)

    def test_raw_blank_erase_inverify_literal_commands_and_busy_bytes(self):
        for operation, opcode, busy in (
            ("blank", 0x35, 0x10),
            ("erase", 0x25, 0x80),
            ("inverify", 0x47, 0x40),
        ):
            channel = self.channel([b"\x3c", bytes((0x3C, busy, 0x3C)), b"\x3c\0\x3c"])
            self.assertTrue(channel.block(operation, 2))
            self.assertEqual(self.events[0]["data"], bytes((opcode, 1)))
            waits = [
                event["milliseconds"]
                for event in self.events
                if event["operation"] == "wait"
            ]
            self.assertEqual(waits, [10, 10])
        channel = self.channel([b"\x3c", b"\x3c\x01\x3c"])
        self.assertFalse(channel.block("blank", 1))

    def test_literal_sil_cpu_probe_format_and_initialized_alternate_pairs(self):
        from scripts.programming_2026_consolidated import consolidated_sil_cpu_mode

        self.assertEqual(consolidated_sil_cpu_mode("4"), (True, False, "12"))
        self.assertEqual(consolidated_sil_cpu_mode("12"), (True, True, "4"))
        self.assertEqual(consolidated_sil_cpu_mode("15"), (False, True, "16"))
        self.assertEqual(consolidated_sil_cpu_mode("87"), (False, True, "88"))
        self.assertEqual(consolidated_sil_cpu_mode("011"), (False, False, None))

    def test_raw_write_first_address_packet_four_chunks_send_timeout_and_progress(self):
        from scripts.programming_2026_common import NativeMemoryInfo

        channel = self.channel([b"\x3c", b"\x3c", b"\x3c\0\x3c"])
        progress = []
        image = b"\xa5" * 1024
        channel.write_block(
            1,
            (1024,),
            NativeMemoryInfo(0x1000, 0x13FF, 1, 0),
            image,
            1024,
            progress=lambda key, value: progress.append((key, value)),
        )
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes,
            [
                b"\x41",
                bytes.fromhex("001000ff") + image[:256],
                image[:256],
                image[:256],
                image[:256],
                b"\x50",
            ],
        )
        self.assertEqual(progress[-2:], [("count", 1024), ("percent", 50)])
        self.assertEqual(
            [
                event["milliseconds"]
                for event in self.events
                if event["operation"] == "set_send_timeout"
            ],
            [10000, 1000] * 4,
        )
        self.assertEqual(
            [
                event["milliseconds"]
                for event in self.events
                if event["operation"] == "set_timeout"
            ],
            [2000, 1000],
        )

    def test_raw_verify_nonfinal_status_fault_skips_even_after_busy(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        channel = self.channel(
            [
                b"\x3c",
                b"\x3c",
                b"\x3c\x20\x3c",
                NativeJ2534Error2026(9),
                b"\x3c",
                b"\x3c\0\x3c",
            ]
        )
        channel.verify_block(1, (512,), b"\xa5" * 512, 512)
        self.assertEqual(channel.count, 512)
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes, [b"\x15\0", b"\xa5" * 256, b"\x50", b"\x50", b"\xa5" * 256, b"\x50"]
        )

    def test_raw_verify_packet_ack_false_is_ignored_but_final_status_fault_fails15(
        self,
    ):
        from scripts.j2534_2026 import NativeJ2534Error2026
        from scripts.programming_2026_legacy import NativeMappedTransportError

        channel = self.channel([b"\x3c", NativeJ2534Error2026(9), b"\x3c\0\x3c"])
        channel.verify_block(1, (256,), bytes(256), 256)
        self.assertEqual(channel.count, 256)
        channel = self.channel(
            [b"\x3c", b"\x3c", *[NativeJ2534Error2026(7) for _ in range(3)]]
        )
        with self.assertRaises(NativeMappedTransportError) as caught:
            channel.verify_block(1, (256,), bytes(256), 256)
        self.assertEqual(caught.exception.native_error_code, 15)

    def test_wide_sil_block_and_verify_literal_two_byte_range(self):
        channel = self.channel([b"\x3c", b"\x3c\0\x3c"])
        self.assertTrue(channel.block("blank", 257, last_block=258))
        self.assertEqual(self.events[0]["data"], bytes.fromhex("3601000101"))
        channel = self.channel(
            [b"\x3c", b"\x3c", b"\x3c\0\x3c", b"\x3c", b"\x3c\0\x3c"]
        )
        channel.verify_block(1, (256, 256), bytes(512), 512, last_block=2)
        self.assertEqual(self.events[0]["data"], bytes.fromhex("1600000001"))
        self.assertEqual(channel.count, 512)

    def baud_channel(self, fault=None):
        from scripts.programming_2026_consolidated import ConsolidatedSILFlash2026

        self.events, self.pending = [], []
        self.baud = None
        self.mode_calls = 0

        def provider(event, remaining):
            self.events.append(event)
            if fault is not None:
                fault(event)
            name = event["operation"]
            if name == "control_io":
                self.baud = event["parameters"][0][1]
            if name == "write_messages":
                data = event["data"]
                if data in (b"\x60", b"\0", b"\x05"):
                    if data == b"\x60":
                        self.mode_calls += 1
                    self.pending.append(b"\x3c")
                elif data == b"\x75":
                    self.pending.append(
                        b"\x3c" + bytes.fromhex("0010000013ff0110") + b"\x3c"
                    )
                elif data == bytes.fromhex("3500"):
                    self.pending.append(b"\x3c")
                elif data == b"\x50":
                    self.pending.append(b"\x3c\0\x3c")
                return 1
            if name == "read_after_indication":
                return self.pending.pop(0)
            return None

        return ConsolidatedSILFlash2026(NativeRuntime2026(provider))

    def test_native_baud_discovery_repeats100_modes100_memory100_blank(self):
        channel = self.baud_channel()
        self.assertEqual(channel.discover_baud("0"), 9600)
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes.count(b"\x60"), 100)
        self.assertEqual(writes.count(b"\x75"), 100)
        self.assertEqual(writes.count(b"\x35\0"), 100)
        self.assertEqual(writes.count(b"\x50"), 100)

    def test_native_next_baud_first_ff_retries_once_after_prior_boot_failure(self):
        second_failed = False

        def fault(event):
            nonlocal second_failed
            if event.get("data") == b"\x60" and (
                self.baud == 9600 or self.baud == 9800 and not second_failed
            ):
                self.pending.append(b"\xff")
                if self.baud == 9800:
                    second_failed = True
                event["data"] = b"\xff"

        channel = self.baud_channel(fault)
        self.assertEqual(channel.discover_baud("0"), 9800)
        baud_events = [
            event["parameters"][0][1]
            for event in self.events
            if event["operation"] == "control_io"
        ]
        self.assertEqual(baud_events, [9600, 9800])
        self.assertEqual(sum(event.get("data") == b"\xff" for event in self.events), 2)
        self.assertEqual(self.mode_calls, 100)

    def test_blank_native_failure_sends05_readone_then_next_baud_host_fault_propagates(
        self,
    ):
        for native in (True, False):
            failed = False
            error = (
                ConsolidatedError(11, "authored")
                if native
                else OSError("authored host fault")
            )

            def fault(event, native=native, error=error):
                nonlocal failed
                if event.get("data") == b"\x35\0" and not failed:
                    failed = True
                    raise error

            channel = self.baud_channel(fault)
            if native:
                self.assertEqual(channel.discover_baud("0"), 9800)
                failure_index = next(
                    index
                    for index, event in enumerate(self.events)
                    if event.get("data") == b"\x35\0"
                )
                self.assertEqual(self.events[failure_index + 1]["data"], b"\x05")
                self.assertEqual(
                    self.events[failure_index + 2]["operation"], "read_after_indication"
                )
            else:
                with self.assertRaises(OSError) as caught:
                    channel.discover_baud("0")
                self.assertIs(caught.exception, error)


class SILWriterTests(unittest.TestCase):
    def run_writer(
        self,
        *,
        cpu="0",
        shrink=False,
        fault=None,
        retry=(),
        context=None,
        image_size=None,
        memory_override=None,
        fallback=False,
        execute=None,
    ):
        from scripts.j2534_2026 import NativeMessage
        from scripts.programming_2026_consolidated import (
            SILWriteContext,
            SILWriteState,
            write_sil,
        )

        size = image_size or (2048 if shrink else 1024)
        context = context or SILWriteContext(
            IDENTITY,
            "1",
            cpu,
            bytes.fromhex("07d907d100000720"),
            0,
            b"\xa5" * size,
            size,
            SILWriteState(),
            retry_decisions=retry,
        )
        self.events, self.pending, self.progress = [], [], []
        self.cancelled = False
        self.mode_calls = 0
        transfer, packets = None, 0

        def provider(event, remaining):
            nonlocal transfer, packets
            self.events.append(event)
            if fault is not None:
                fault(event)
            name = event["operation"]
            if name == "get_protocol_id":
                return 3
            if name == "fast_init":
                return NativeMessage(3, b"", rx_status=0)
            if name == "write_messages":
                data = event["data"]
                if data in (b"\x60", b"\0", b"\x05"):
                    if data == b"\x60":
                        self.mode_calls += 1
                    self.pending.append(b"\x3c")
                elif data in (b"\x75", b"\x76"):
                    descriptor = (
                        bytes.fromhex("0010000017ff0183")
                        if shrink
                        else bytes.fromhex("0010000013ff0110")
                    )
                    descriptor = memory_override or descriptor
                    self.pending.append(
                        bytes(10)
                        if data == b"\x75" and fallback
                        else b"\x3c"
                        + descriptor
                        + (b"\0" if data == b"\x76" else b"")
                        + b"\x3c"
                    )
                elif data[:1] in (
                    b"\x35",
                    b"\x25",
                    b"\x47",
                    b"\x36",
                    b"\x26",
                    b"\x48",
                ) and len(data) in (2, 5):
                    self.pending.append(b"\x3c")
                elif data in (b"\x41", b"\x45"):
                    transfer, packets = "write", 0
                    self.pending.append(b"\x3c")
                elif data[:1] in (b"\x15", b"\x16") and len(data) in (2, 5):
                    transfer = "verify"
                    self.pending.append(b"\x3c")
                elif len(data) in (256, 260):
                    packets += 1
                    if transfer == "verify" or packets == 4:
                        self.pending.append(b"\x3c")
                elif data == b"\x50":
                    self.pending.append(b"\x3c\0\x3c")
                return 1
            if name == "read_after_indication":
                return self.pending.pop(0)
            return None

        self.runtime = NativeRuntime2026(provider, cancelled=lambda: self.cancelled)
        if execute is not None:
            from scripts.programming_2026_consolidated import ConsolidatedExecuteContext

            engine, container = execute
            return engine.execute(
                container,
                self.runtime,
                ConsolidatedExecuteContext(
                    writing=True,
                    target_indices=(0,) * engine.common_definitions.num_cpu_maxnum,
                ),
                progress=lambda key, value: self.progress.append((key, value)),
            )
        return write_sil(
            context,
            self.runtime,
            progress=lambda key, value: self.progress.append((key, value)),
        )

    def test_full_classic_sil_discovery_prepare_write_verify_and_source_callback(self):
        result = self.run_writer()
        self.assertTrue(result["writer_completed"])
        self.assertEqual(result["completion_callback"], "normal")
        self.assertEqual(
            (result["count"], result["percent"], result["baud_rate"]), (2048, 100, 9600)
        )
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes.count(b"\x60"), 101)
        self.assertEqual(writes.count(b"\x75"), 101)
        self.assertEqual(writes.count(b"\x35\0"), 101)
        self.assertIn(b"\x15\0", writes)
        self.assertIn(bytes.fromhex("001000ff") + b"\xa5" * 256, writes)
        self.assertNotIn(b"\x80", writes)

    def test_full_shrink_sil_two_ranges_uses_wide_blank_verify(self):
        result = self.run_writer(cpu="11", shrink=True)
        self.assertTrue(result["writer_completed"])
        self.assertEqual((result["count"], result["percent"]), (4096, 100))
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes.count(bytes.fromhex("3600000000")), 101)
        self.assertIn(bytes.fromhex("3600010001"), writes)
        self.assertIn(bytes.fromhex("1600000000"), writes)
        self.assertIn(bytes.fromhex("1600010001"), writes)
        self.assertEqual(writes.count(b"\x76"), 101)

    def test_native_write_failure_retains_normal_callback_resets_and_reconnects_only(
        self,
    ):
        from scripts.programming_2026_consolidated import ConsolidatedError

        def fault(event):
            if event.get("data") == b"\x41":
                raise ConsolidatedError(13, "authored")

        result = self.run_writer(fault=fault, retry=(True,))
        self.assertFalse(result["writer_completed"])
        self.assertEqual(result["completion_callback"], "normal")
        self.assertEqual(result["error_code"], 13)
        self.assertTrue(result["password_changed"])
        self.assertTrue(result["retry_prepared"])
        self.assertEqual((result["count"], result["percent"]), (0, 0))
        self.assertEqual(self.progress[-2:], [("count", 0), ("percent", 0)])
        self.assertEqual(
            sum(event["operation"] == "connect" for event in self.events), 1
        )

    def test_host_failure_and_cancel_restore_send_timeout_without_native_retry(self):
        for cancel in (False, True):
            error = OSError("authored host fault")

            def fault(event, cancel=cancel, error=error):
                if len(event.get("data", b"")) == 260:
                    if cancel:
                        self.cancelled = True
                    else:
                        raise error

            with self.assertRaises(InterruptedError if cancel else OSError):
                self.run_writer(fault=fault, retry=(True,))
            self.assertEqual(
                self.events[-1], {"operation": "set_send_timeout", "milliseconds": 1000}
            )
            self.assertFalse(
                any(event["operation"] == "disconnect" for event in self.events)
            )

    def test_probe_cpu4_becomes_cpu12_from_actual76_memory_and_fixed_map(self):
        result = self.run_writer(
            cpu="4",
            shrink=True,
            image_size=131072,
            memory_override=bytes.fromhex("00000001ffff4082"),
            fallback=True,
        )
        self.assertTrue(result["writer_completed"])
        self.assertEqual(result["effective_cpu_type"], "12")
        self.assertEqual((result["count"], result["percent"]), (262144, 100))
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes.count(b"\x75"), 1)
        self.assertEqual(writes.count(b"\x76"), 101)

    def test_actual_sil_archive_target_and_location_reach_primitive_writer(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw
        from scripts.programming_2026_consolidated import SILWriteState, bind_sil_writer

        image = b"\xa5" * 1024
        lines = []
        for offset in range(0, len(image), 128):
            body = (
                bytes((133,))
                + (0x1000 + offset).to_bytes(4, "big")
                + image[offset : offset + 128]
            )
            lines.append(b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode())
        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\nContactType=SIL\nKindOfECU=1\n[CPU01]\nCPUType=0\nLocationID=07d907d100000720\nNewCID=AUTHORED\nCPUImageName=main\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED\n01_TargetData=ffffffff\n[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000400\nDataFormatID=01\n"
        container = parse_cuw(
            metadata_container(metadata, [(b"main", b"\n".join(lines) + b"\n")], 1)
        )
        state = SILWriteState()
        context = bind_sil_writer(container, IDENTITY, state)
        self.assertIs(context.state, state)
        self.assertEqual(
            (context.cpu_type, context.image, context.password), ("0", image, 0)
        )
        self.assertTrue(self.run_writer(context=context)["writer_completed"])
        fast = next(event for event in self.events if event["operation"] == "fast_init")
        self.assertEqual(fast["data"], bytes.fromhex("0000d107d90700000000"))


class ChassisWriterTests(unittest.TestCase):
    events: list[dict]
    filters: set[int]
    progress: list[tuple]
    cancelled: bool
    run_writer = OldECBWriterTests.run_writer

    def context(self, *, cpu="67", size=122880, retry=(), recovery=False):
        from scripts.programming_2026_consolidated import (
            CANChassisWriteContext,
            CANOldECBWriteState,
        )

        return CANChassisWriteContext(
            IDENTITY,
            (cpu,),
            (bytes.fromhex("07d907d100000720"),),
            (0,),
            (b"\xa5" * size,),
            (size,),
            tuple(bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")),
            2,
            CANOldECBWriteState(),
            retry_decisions=retry,
            recovery_timeout=recovery,
        )

    def test_full_chassis_separate_checkid_native_prepare_timing_and_ranges(self):
        from scripts.programming_2026_consolidated import write_can_chassis

        result = self.run_writer(
            context=self.context(), writer=write_can_chassis, separate_check=True
        )
        self.assertTrue(result["writer_completed"])
        self.assertEqual((result["counts"], result["percentages"]), ((245760,), (100,)))
        writes = [
            event.get("data")
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes.count(bytes.fromhex("00000720a027")), 6)
        self.assertEqual(writes[-1], bytes.fromhex("0000072080"))
        self.assertIn({"operation": "set_timeout", "milliseconds": 80000}, self.events)
        self.assertEqual(sum("messages" in event for event in self.events), 0)
        self.assertEqual(self.filters, set())

    def test_cpu68_zero_prefix_sizes_make_block8_write_begin_at_image_zero(self):
        from scripts.programming_2026_consolidated import write_can_chassis

        result = self.run_writer(
            context=self.context(cpu="68", size=25600),
            writer=write_can_chassis,
            separate_check=True,
            memory_override=bytes.fromhex("0010000073ff018f00"),
        )
        self.assertTrue(result["writer_completed"])
        self.assertEqual(result["counts"], (51200,))
        writes = [
            event.get("data")
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertIn(bytes.fromhex("000007d1260007000e"), writes)
        self.assertIn(bytes.fromhex("000007d1001000ff"), writes)
        self.assertIn(bytes.fromhex("000007d1003000ff"), writes)

    def test_known_cpu30_batched_checkid_and_recovery_timeout10000(self):
        from scripts.programming_2026_consolidated import write_can_chassis

        result = self.run_writer(
            context=self.context(cpu="30", size=11264, recovery=True),
            writer=write_can_chassis,
            memory_override=bytes.fromhex("001000003bff018200"),
        )
        self.assertTrue(result["writer_completed"])
        self.assertEqual(sum("messages" in event for event in self.events), 1)
        self.assertIn({"operation": "set_timeout", "milliseconds": 10000}, self.events)

    def test_native_failure_external_progress_reset_has_no_observer_and_retry_only_reconnects(
        self,
    ):
        from scripts.programming_2026_consolidated import (
            ConsolidatedError,
            write_can_chassis,
        )

        def fault(event):
            if event.get("data") == bytes.fromhex("000007d12600100077"):
                raise ConsolidatedError(12, "authored")

        result = self.run_writer(
            context=self.context(retry=(True,)),
            writer=write_can_chassis,
            separate_check=True,
            fault=fault,
        )
        self.assertFalse(result["writer_completed"])
        self.assertTrue(result["retry_prepared"])
        self.assertTrue(result["password_changed"])
        self.assertEqual(result["counts"], (0,))
        self.assertNotEqual(self.progress[-2:], [("count", 0), ("percent", 0)])
        self.assertEqual(
            sum(event["operation"] == "connect" for event in self.events), 1
        )
        self.assertEqual(self.filters, set())

    def test_actual_cpu30_import_selects_secondary_security_and_chassis_consumer(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw
        from scripts.programming_2026_consolidated import (
            CANOldECBWriteState,
            bind_can_chassis_writer,
            write_can_chassis,
        )

        image = b"\xa5" * 11264
        lines = []
        for offset in range(0, len(image), 128):
            body = (
                bytes((133,))
                + (0x1000 + offset).to_bytes(4, "big")
                + image[offset : offset + 128]
            )
            lines.append(b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode())
        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\nContactType=CAN\nKindOfECU=4\n[CPU01]\nCPUType=30\nLocationID=07d907d100000720\nNewCID=AUTHORED\nCPUImageName=main\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED\n01_TargetData=ffffffff\n[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00002c00\nDataFormatID=01\n"
        container = parse_cuw(
            metadata_container(metadata, [(b"main", b"\n".join(lines) + b"\n")], 1)
        )
        state = ConsolidatedControllerState(request_id_records=("07B0", "07B0"))
        materials = tuple(
            bytes.fromhex(value) for value in ("1020", "3040", "5060", "7080")
        )
        bound = bind_can_chassis_writer(
            container,
            IDENTITY,
            state,
            CANOldECBWriteState(),
            {"chassis_secondary_security_materials": materials},
            target_indices=(0,),
        )
        self.assertEqual(bound.images, (image,))
        self.assertEqual(bound.passwords, (0,))
        self.assertTrue(
            self.run_writer(
                context=bound,
                writer=write_can_chassis,
                memory_override=bytes.fromhex("001000003bff018200"),
            )["writer_completed"]
        )
        with self.assertRaises(ValueError):
            bind_can_chassis_writer(
                container,
                IDENTITY,
                state,
                CANOldECBWriteState(),
                {"chassis_primary_security_materials": materials},
                target_indices=(0,),
            )
        with self.assertRaises(ValueError):
            bind_can_chassis_writer(
                container,
                IDENTITY,
                ConsolidatedControllerState(old_spec_ecb=True),
                CANOldECBWriteState(),
                {"chassis_secondary_security_materials": materials},
                target_indices=(0,),
            )

    def test_chassis_host_fault_cancel_and_finish_native_all_preservation(self):
        from scripts.programming_2026_common import NativeException2026
        from scripts.programming_2026_consolidated import write_can_chassis

        for kind in ("host", "cancel", "native_finish"):
            error = OSError("authored host fault")

            def fault(event, kind=kind, error=error):
                if kind == "native_finish" and event.get("data") == bytes.fromhex(
                    "0000072080"
                ):
                    raise NativeException2026("authored native finish ALL")
                if kind != "native_finish" and event.get("data") == bytes.fromhex(
                    "000007d1260000000f"
                ):
                    if kind == "cancel":
                        self.cancelled = True
                    else:
                        raise error

            if kind == "native_finish":
                result = self.run_writer(
                    context=self.context(),
                    writer=write_can_chassis,
                    separate_check=True,
                    fault=fault,
                )
                self.assertTrue(result["writer_completed"])
                self.assertIn("finish", result["swallowed_native_faults"])
            else:
                with self.assertRaises(
                    InterruptedError if kind == "cancel" else OSError
                ):
                    self.run_writer(
                        context=self.context(retry=(True,)),
                        writer=write_can_chassis,
                        separate_check=True,
                        fault=fault,
                    )
                self.assertFalse(
                    any(event["operation"] == "disconnect" for event in self.events)
                )
            self.assertEqual(self.filters, set())


class SILOccupantWriterTests(unittest.TestCase):
    def run_writer(self, *, vpns=False, fault=None, retry=(), context=None):
        from scripts.j2534_2026 import NativeMessage
        from scripts.programming_2026_consolidated import (
            SILOccupantWriteContext,
            SILOccupantWriteState,
            write_sil_occupant,
        )

        self.events, self.pending, self.progress = [], [], []
        self.cancelled = False
        cpu, firmware = ("72", 0xE4) if vpns else ("11", 0x83)
        size = 2048
        context = context or SILOccupantWriteContext(
            IDENTITY,
            "63" if vpns else "37",
            cpu,
            bytes.fromhex("0102030405060708"),
            0x12345678,
            b"\xa5" * size,
            size,
            SILOccupantWriteState(),
            retry_decisions=retry,
        )
        boot, transfer, packets = 0, None, 0

        def provider(event, remaining):
            nonlocal boot, transfer, packets
            self.events.append(event)
            if fault:
                fault(event)
            name = event["operation"]
            if name == "get_protocol_id":
                return 3
            if name == "get_timeout":
                return 1234
            if name == "fast_init":
                return NativeMessage(3, b"", rx_status=0)
            if name == "write_messages":
                data = event["data"]
                if len(data) > 3 and data[2] == 0xF1:
                    target = data[1]
                    if data[3:5] == b"\x27\x01":
                        self.assertEqual(
                            data,
                            bytes.fromhex("845bf127015dc2")
                            + bytes((sum(bytes.fromhex("845bf127015dc2")) & 255,)),
                        )
                        self.pending.append(
                            bytes((0x84, 0xF1, target, 0x67, 1, 0x12, 0x34, 0))
                        )
                    elif data[3:5] == b"\x27\x02":
                        self.assertEqual(data[5:7], bytes.fromhex("4f6f"))
                        self.pending.append(
                            bytes((0x83, 0xF1, target, 0x67, 2, 0xAA, 0))
                        )
                    elif data[3:5] == b"\x27\x61":
                        self.pending.append(bytes.fromhex("88f1d3676101020304050600"))
                    elif data[3:5] == b"\x27\x62":
                        self.assertEqual(data[5:11], bytes.fromhex("04070a0d1a64"))
                        self.pending.append(bytes.fromhex("83f1d367623400"))
                    elif data[3:5] == b"\x10\x02":
                        self.pending.append(bytes((0x81, 0xF1, target, 0x50, 0)))
                elif not vpns and boot < 5:
                    self.assertEqual(
                        data,
                        (
                            b"\0",
                            b"\0",
                            b"\x02\x01",
                            b"\x04\x03",
                            context.password.to_bytes(4, "little"),
                        )[boot],
                    )
                    boot += 1
                    if boot == 5:
                        self.pending.append(b"\x3c" + bytes(16))
                elif data in (b"\x60", b"\0", b"\x05", b"\x80"):
                    self.pending.append(b"\x3c")
                elif data in (b"\x75", b"\x76"):
                    descriptor = bytes.fromhex("0010000017ff01") + bytes((firmware,))
                    self.pending.append(
                        b"\x3c"
                        + descriptor
                        + (b"\0" if data == b"\x76" else b"")
                        + b"\x3c"
                    )
                elif data[:1] in (b"\x36", b"\x26", b"\x48") and len(data) == 5:
                    self.pending.append(b"\x3c")
                elif data in (b"\x41", b"\x45"):
                    transfer, packets = "write", 0
                    self.pending.append(b"\x3c")
                elif data[:1] == b"\x16" and len(data) == 5:
                    transfer = "verify"
                    self.pending.append(b"\x3c")
                elif len(data) in (256, 260):
                    packets += 1
                    if transfer == "verify" or packets == 4:
                        self.pending.append(b"\x3c")
                elif data == b"\x50":
                    self.pending.append(b"\x3c\0\x3c")
                return 1
            if name == "read_after_indication":
                return self.pending.pop(0)
            return None

        runtime = NativeRuntime2026(provider, cancelled=lambda: self.cancelled)
        return write_sil_occupant(
            context, runtime, progress=lambda k, v: self.progress.append((k, v))
        )

    def test_occupant_full_raw_boot_discovery_wide_write_verify(self):
        result = self.run_writer()
        self.assertTrue(result["writer_completed"])
        self.assertEqual((result["count"], result["percent"]), (4096, 100))
        self.assertFalse(result["block_started"])
        self.assertFalse(
            any(
                e["operation"] == "set_timeout" and e.get("milliseconds") == 5000
                for e in self.events
            )
        )

    def test_vpns_key_sequential_updates_and_full_finish_timeout_restore(self):
        from scripts.programming_2026_consolidated import consolidated_vpns_key

        self.assertEqual(
            consolidated_vpns_key(bytes.fromhex("010203040506")),
            bytes.fromhex("04070a0d1a64"),
        )
        result = self.run_writer(vpns=True)
        self.assertTrue(result["writer_completed"])
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 1234}
        )
        self.assertIn(
            {"operation": "control_io", "ioctl": 2, "parameters": ((0x15, 170),)},
            self.events,
        )
        self.assertFalse(any(e.get("data") == b"\x60" for e in self.events))

    def test_native_write_fault_resets_progress_sets_started_and_reconnects_only(self):
        from scripts.programming_2026_consolidated import ConsolidatedError

        def fault(event):
            if event.get("data") == b"\x41":
                raise ConsolidatedError(13, "authored")

        result = self.run_writer(fault=fault, retry=(True,))
        self.assertFalse(result["writer_completed"])
        self.assertTrue(result["block_started"])
        self.assertTrue(result["retry_prepared"])
        self.assertEqual(self.progress[-2:], [("count", 0), ("percent", 0)])
        self.assertEqual(sum(e.get("data") == b"\x41" for e in self.events), 1)

    def test_prelude_native_fault_propagates_outside_worker_catch(self):
        from scripts.programming_2026_consolidated import ConsolidatedError

        error = ConsolidatedError(16, "authored")

        def fault(event):
            if event.get("data", b"")[3:5] == b"\x27\x01":
                raise error

        with self.assertRaises(ConsolidatedError) as caught:
            self.run_writer(fault=fault, retry=(True,))
        self.assertIs(caught.exception, error)
        self.assertFalse(any(e["operation"] == "disconnect" for e in self.events))

    def test_host_fault_and_cancel_propagate_with_vpns_timeout_cleanup(self):
        for cancel in (False, True):
            error = OSError("authored host")

            def fault(event, cancel=cancel, error=error):
                if event.get("data") == b"\x41":
                    if cancel:
                        self.cancelled = True
                    else:
                        raise error

            with self.assertRaises(InterruptedError if cancel else OSError):
                self.run_writer(vpns=True, fault=fault, retry=(True,))
            self.assertEqual(
                self.events[-1], {"operation": "set_timeout", "milliseconds": 1234}
            )
            self.assertFalse(any(e["operation"] == "disconnect" for e in self.events))

    def test_actual_imported_metadata_target_and_archive_bind_full_occupant(self):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw
        from scripts.programming_2026_consolidated import (
            SILOccupantWriteState,
            bind_sil_occupant_writer,
        )

        image = b"\xa5" * 2048
        lines = []
        for offset in range(0, len(image), 128):
            body = (
                bytes((133,))
                + (0x1000 + offset).to_bytes(4, "big")
                + image[offset : offset + 128]
            )
            lines.append(b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode())
        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\nContactType=SIL\nKindOfECU=37\n[CPU01]\nCPUType=11\nLocationID=0102030405060708\nNewCID=AUTHORED\nCPUImageName=main\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED\n01_TargetData=ffffffff\n[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000800\nDataFormatID=01\n"
        for vpns, cpu in ((False, "11"), (True, "72")):
            selected_metadata = (
                metadata.replace("KindOfECU=37", "KindOfECU=63").replace(
                    "CPUType=11", "CPUType=72"
                )
                if vpns
                else metadata
            )
            container = parse_cuw(
                metadata_container(
                    selected_metadata, [(b"main", b"\n".join(lines) + b"\n")], 1
                )
            )
            state = SILOccupantWriteState()
            context = bind_sil_occupant_writer(container, IDENTITY, state)
            self.assertEqual(
                (context.cpu_type, context.image, context.password), (cpu, image, 0)
            )
            self.assertIs(context.state, state)
            self.assertTrue(
                self.run_writer(context=context, vpns=vpns)["writer_completed"]
            )
            if vpns:
                programming = [
                    event["data"]
                    for event in self.events
                    if event["operation"] == "fast_init" and len(event["data"]) == 10
                ]
                self.assertEqual(programming, [bytes.fromhex("00000403020100000000")])


class ConsolidatedExecuteTests(unittest.TestCase):
    @staticmethod
    def definitions(capacity=1):
        from scripts.programming_2026_common import CommonDefinitions2026

        definitions = CommonDefinitions2026()
        definitions.num_cpu_maxnum = capacity
        return definitions

    @staticmethod
    def parameters(*keys):
        from scripts.programming_2026_common import NativeGeneralParameters2026

        names = [
            "EngineTypeFlag",
            "PasswordAddress",
            "ByteOrder",
            "CalibrationType",
            "FlagToUseGetFlashSizeFunc",
            "WriteDataSize",
            "FlagToClearDTCOfENGECTWithMode04",
            "FlagToOutputAllAttachedInformation",
            "M16CTypeFlag",
            "FORESTTypeFlag",
            "FlagToChangeProtocolAtSuccessGetCID",
            "FlagToChangeWFSE",
            "CPUTypeWithModeChangeAtCPUTypeChangeFlag",
            "FlagToDoIGOFFONAtCPUTypeChange",
            "WaitTimeForIGOFFON",
            "KindOfECUNames",
            "FlagToWriteCIDAfterRepro",
            "FlagToUseCIDGetterAndFlashWriterDLL",
            "WaitTimeAfterIGOn",
            "FlagToChangeToReprogGWModeForCentralGW",
            "FlagToHoldSFormatRecords",
            "ClassNameForOEMVINReader",
            "FlagToNonVerifyProcess",
            "FlagToDisableSelectNewCalButton",
            "FlagToDisplayPSACableAttachOrRemoveScreen",
            "FlagToCancelAutomaticIGOFF",
            "FlagToReceiveRespForFinish",
            "WaitTimeAfterBatteryDisconnected",
            "WaitTimeAfterBatteryConnected",
            "BatteryVoltageUpperThreshold",
            "AlternateWaitTimeForIGOFFON",
        ]
        header = ",".join(["ParamFileKeySystemProtocolMicon", *names])
        values = ["00000000" if name == "PasswordAddress" else "0" for name in names]
        rows = [",".join([key, *values]) for key in ("P5-Unified", *keys)]
        return NativeGeneralParameters2026.from_sources(
            {"Parameter.ini": ("\r\n".join([header, *rows]) + "\r\n").encode()},
            encoded=False,
        )

    @staticmethod
    def container(kind="13", cpu="56", contact="CAN", image=None):
        from test_calibration import metadata_container

        from scripts.calibration import parse_cuw

        metadata = f"[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\nContactType={contact}\nKindOfECU={kind}\n[CPU01]\nCPUType={cpu}\nLocationID=07d907d100000720\nNewCID=AUTHORED\nCPUImageName=main\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED\n01_TargetData=ffffffff\n[CPUImage01]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000400\nDataFormatID=01\n"
        image = image or b"\xa5" * 1024
        lines = []
        if image:
            for offset in range(0, len(image), 128):
                body = (
                    bytes((133,))
                    + (0x1000 + offset).to_bytes(4, "big")
                    + image[offset : offset + 128]
                )
                lines.append(b"S3" + (body + bytes((~sum(body) & 255,))).hex().encode())
        return parse_cuw(
            metadata_container(
                metadata, [(b"main", b"\n".join(lines) + b"\n")] if image else [], 1
            )
        )

    def test_execute_getter_persistent_parameter_selection_and_actual_native_packets(
        self,
    ):
        from scripts.programming_2026_consolidated import (
            ConsolidatedExecute2026,
            ConsolidatedExecuteContext,
        )

        engine = ConsolidatedExecute2026(
            IDENTITY, self.parameters("13CAN56"), common_definitions=self.definitions(3)
        )
        events = []

        def provider(event, remaining):
            events.append(event)
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] == "start_flow_control_filter":
                return 1
            if event["operation"] == "read_specified_can_message":
                return event["address"] + (
                    b"\xea\x1eAUTHORED"
                    if event["address"] == bytes.fromhex("000007a9")
                    else b"\x5aABCDE"
                )
            return None

        first = engine.execute(
            self.container(),
            NativeRuntime2026(provider),
            ConsolidatedExecuteContext(getter_option_9c4=1),
        )
        self.assertTrue(first["execute_return"])
        self.assertEqual(first["identifiers"], ("AUTHORED",))
        self.assertEqual(engine.state.request_id_records, ("07A1",))
        second = engine.execute(
            self.container("45", "117"), NativeRuntime2026(provider)
        )
        self.assertEqual(second["identifiers"], ("ABCDE",))
        self.assertEqual(engine.parameter_keys, ("13", "56", "CAN"))
        self.assertEqual(len(engine.counts), 3)
        self.assertEqual(engine.getter_option_9c4, 0)
        self.assertEqual(sum(e["operation"] == "disconnect" for e in events), 2)

    def test_execute_full_actual_imported_sil_write_uses_primitive_worker_and_progress(
        self,
    ):
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        engine = ConsolidatedExecute2026(
            IDENTITY, self.parameters("1SIL0"), common_definitions=self.definitions(3)
        )
        container = self.container("1", "0", "SIL", b"\xa5" * 1024)
        helper = SILWriterTests(
            "test_full_classic_sil_discovery_prepare_write_verify_and_source_callback"
        )
        result = helper.run_writer(execute=(engine, container))
        self.assertTrue(result["execute_return"])
        self.assertEqual(engine.target_indices, (0, 0, 0))
        self.assertTrue(result["writer_completed"])
        self.assertEqual(
            (result["counts"], result["percentages"]), ((2048, 0, 0), (100, 0, 0))
        )
        self.assertIn(
            {
                "operation": "write_messages",
                "protocol": 3,
                "tx_flags": 0,
                "count": 1,
                "data": b"\x41",
            },
            helper.events,
        )
        self.assertEqual(helper.progress[-2:], [("count", 2048), ("percent", 100)])

    def test_execute_native_initialization_failure_sets_exact_caller_slots_then_retains_created(
        self,
    ):
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        engine = ConsolidatedExecute2026(
            IDENTITY, self.parameters(), common_definitions=self.definitions()
        )
        result = engine.execute(self.container(), NativeRuntime2026(lambda e, r: None))
        self.assertEqual(
            (
                result["execute_return"],
                result["error_code"],
                result["caller_failed_974"],
                result["caller_abort_744"],
            ),
            (False, 9999, True, True),
        )
        self.assertTrue(engine.created)
        self.assertIsNone(engine.parameter_keys)

    def test_execute_host_failure_and_cancel_propagate_without_reentrant_latch(self):
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        for error in (OSError("authored"), InterruptedError("cancel")):
            engine = ConsolidatedExecute2026(
                IDENTITY,
                self.parameters("13CAN56"),
                common_definitions=self.definitions(),
            )

            def provider(event, remaining, error=error):
                raise error

            with self.assertRaises(type(error)) as caught:
                engine.execute(self.container(), NativeRuntime2026(provider))
            self.assertIs(caught.exception, error)
            self.assertFalse(engine.active)


class EMPSCleanupScopeTests(unittest.TestCase):
    def test_can_native_filter_all_preserves_native_completion(self):
        from scripts.programming_2026_common import NativeException2026

        helper = CANEMPSWriterTests(
            "test_cleanup_failure_is_visible_and_all_other_releases_attempted"
        )
        result = helper.run_writer(
            stop_fault=NativeException2026("authored native filter ALL")
        )
        self.assertTrue(result["writer_completed"])
        self.assertEqual(result["cleanup_errors"], ("NativeException2026",))
        self.assertEqual(helper.filters, [1, 2])
        self.assertEqual(helper.runtime.close(), [])

    def test_sil_host_restore_fault_propagates_after_second_timeout_restore(self):
        helper = SILEMPSWriterTests(
            "test_fixed_cpu_geometry_raw_packets_and_native_double_progress"
        )
        error = OSError("authored host timeout restore")

        def fault(event):
            if event == {"operation": "set_timeout", "milliseconds": 1234}:
                raise error

        with self.assertRaises(OSError) as caught:
            helper.run_writer(fault=fault)
        self.assertIs(caught.exception, error)
        self.assertEqual(
            helper.events[-1], {"operation": "set_send_timeout", "milliseconds": 5678}
        )

    def test_sil_native_restore_fault_stops_native_cleanup_sequence(self):
        from scripts.programming_2026_common import NativePassThruException2026

        helper = SILEMPSWriterTests(
            "test_fixed_cpu_geometry_raw_packets_and_native_double_progress"
        )
        error = NativePassThruException2026(13, "authored", 1)

        def fault(event):
            if event == {"operation": "set_timeout", "milliseconds": 1234}:
                raise error

        with self.assertRaises(NativePassThruException2026) as caught:
            helper.run_writer(fault=fault)
        self.assertIs(caught.exception, error)
        self.assertEqual(
            helper.events[-1], {"operation": "set_timeout", "milliseconds": 1234}
        )


class ConsolidatedNativeErrorSlotTests(unittest.TestCase):
    def test_epb_native_driver_enum_and_driver_slot_remain_distinct(self):
        from scripts.programming import NativeTransportError

        helper = CANEPBWriterTests(
            "test_finish_and_cleanup_native_all_scopes_keep_worker_success"
        )

        def fault(event):
            if event.get("data") == bytes.fromhex("000007d12500"):
                raise NativeTransportError(9)

        result = helper.run_writer(fault=fault)
        self.assertFalse(result["writer_completed"])
        self.assertEqual((result["error_code"], result["driver_error"]), (12, 9))

    def test_epb_accepted_reconnect_clears_prior_native_driver_slot(self):
        from scripts.programming import NativeTransportError

        helper = CANEPBWriterTests(
            "test_finish_and_cleanup_native_all_scopes_keep_worker_success"
        )

        def fault(event):
            if event.get("data") == bytes.fromhex("000007d12500"):
                raise NativeTransportError(9)

        result = helper.run_writer(fault=fault, retry=(True,))
        self.assertTrue(result["retry_prepared"])
        self.assertEqual((result["error_code"], result["driver_error"]), (0, 0))


class SILEMPSNativeScopeTests(unittest.TestCase):
    @staticmethod
    def helper():
        return SILEMPSWriterTests(
            "test_fixed_cpu_geometry_raw_packets_and_native_double_progress"
        )

    def test_native_unscoped_timeout60000_propagates_without_worker_restoration(self):
        from scripts.programming_2026_common import NativePassThruException2026

        helper = self.helper()
        error = NativePassThruException2026(13, "authored", 1)

        def fault(event):
            if event == {"operation": "set_timeout", "milliseconds": 60000}:
                raise error

        with self.assertRaises(NativePassThruException2026) as caught:
            helper.run_writer(fault=fault, retry=(True,))
        self.assertIs(caught.exception, error)
        self.assertEqual(
            helper.events[-1], {"operation": "set_timeout", "milliseconds": 60000}
        )
        self.assertFalse(any(e["operation"] == "disconnect" for e in helper.events))

    def test_unknown_native_init_and_erase_all_retain_initialized_enum_and_restore(
        self,
    ):
        from scripts.programming_2026_common import NativeException2026

        for stage in ("init", "erase"):
            helper = self.helper()

            def fault(event, stage=stage):
                if (
                    stage == "init"
                    and event["operation"] == "fast_init"
                    or stage == "erase"
                    and event.get("data", b"")[:4] == bytes.fromhex("8732f19c")
                ):
                    raise NativeException2026("authored native ALL")

            result = helper.run_writer(fault=fault)
            self.assertFalse(result["writer_completed"])
            self.assertEqual((result["error_code"], result["driver_error"]), (0, 0))
            self.assertEqual(
                helper.events[-1],
                {"operation": "set_send_timeout", "milliseconds": 5678},
            )
            self.assertEqual(helper.pages, [])

    def test_native_initial_cpass_uses_all_retention_not_exception_enum(self):
        from scripts.programming_2026_common import NativePassThruException2026

        helper = self.helper()

        def fault(event):
            if event["operation"] == "fast_init":
                raise NativePassThruException2026(13, "authored", 1)

        result = helper.run_writer(fault=fault)
        self.assertEqual((result["error_code"], result["driver_error"]), (0, 0))

    def test_native_page_all_retains_error_and_never_replays_with_nonrecoverable_decision(
        self,
    ):
        from scripts.programming_2026_common import NativeException2026

        helper = self.helper()

        def fault(event):
            if len(event.get("data", b"")) == 1028:
                raise NativeException2026("authored page ALL")

        result = helper.run_writer(fault=fault, retry=(True, False))
        self.assertFalse(result["writer_completed"])
        self.assertEqual(result["error_code"], 0)
        self.assertEqual(result["retry_decisions_consumed"], 2)
        self.assertEqual(sum(len(e.get("data", b"")) == 1028 for e in helper.events), 1)
        self.assertIn({"operation": "wait", "milliseconds": 3000}, helper.events)

    def test_native_connect_after_initial_retry_is_outside_worker_all(self):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import NativePassThruException2026

        helper = self.helper()
        error = NativePassThruException2026(13, "authored", 1)

        def fault(event):
            if event["operation"] == "fast_init":
                raise NativeTransportError(7)
            if event["operation"] == "connect":
                raise error

        with self.assertRaises(NativePassThruException2026) as caught:
            helper.run_writer(fault=fault, retry=(True,))
        self.assertIs(caught.exception, error)
        self.assertEqual(helper.events[-1], {"operation": "connect", "protocol": 3})

    def test_native_retry_connect_cj_reasks_and_success_clears_both_slots(self):
        from scripts.programming import NativeTransportError

        helper = self.helper()
        connects = 0

        def fault(event):
            nonlocal connects
            if event["operation"] == "fast_init":
                raise NativeTransportError(7)
            if event["operation"] == "connect":
                connects += 1
                if connects == 1:
                    raise NativeTransportError(9)

        result = helper.run_writer(fault=fault, retry=(True, True))
        self.assertEqual(
            (result["reconnects"], result["retry_decisions_consumed"]), (1, 2)
        )
        self.assertEqual((result["error_code"], result["driver_error"]), (0, 0))
        self.assertEqual(
            helper.events[-1], {"operation": "set_send_timeout", "milliseconds": 5678}
        )


class CANEMPSNativeRetryScopeTests(unittest.TestCase):
    def test_native_disconnect_all_connect_cj_reasks_then_clears_slots_without_replay(
        self,
    ):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import NativeException2026

        helper = CANEMPSWriterTests(
            "test_explicit_retry_only_reconnects_never_replays_data"
        )
        connects = 0

        def fault(event):
            nonlocal connects
            if event["operation"] == "disconnect":
                raise NativeException2026("authored disconnectALL")
            if event["operation"] == "connect":
                connects += 1
                if connects == 1:
                    raise NativeTransportError(9)

        result = helper.run_writer(
            helper.context(retry_decisions=(True, True)), fail=0x36, fault=fault
        )
        self.assertTrue(result["retry_prepared"])
        self.assertEqual(result["retry_decisions_consumed"], 2)
        self.assertEqual((result["error_code"], result["driver_error"]), (0, 0))
        self.assertEqual(result["initial_error_code"], 34)
        self.assertEqual(sum(map(len, helper.chunks[1])), 240)
        self.assertEqual(helper.chunks[2], [])

    def test_connect_cpass_outside_cj_does_not_restore_worker_timeout(self):
        from scripts.programming_2026_common import NativePassThruException2026

        helper = CANEMPSWriterTests(
            "test_explicit_retry_only_reconnects_never_replays_data"
        )
        error = NativePassThruException2026(13, "authored", 1)

        def fault(event):
            if event["operation"] == "connect":
                raise error

        with self.assertRaises(NativePassThruException2026) as caught:
            helper.run_writer(
                helper.context(retry_decisions=(True,)), fail=0x36, fault=fault
            )
        self.assertIs(caught.exception, error)
        self.assertEqual(helper.events[-1], {"operation": "connect", "protocol": 6})

    def test_native_initial_control_io_is_outside_worker_catches_and_cleanup(self):
        from scripts.programming import NativeTransportError

        helper = CANEMPSWriterTests(
            "test_explicit_retry_only_reconnects_never_replays_data"
        )
        error = NativeTransportError(7)

        def fault(event):
            if event["operation"] == "control_io":
                raise error

        with self.assertRaises(NativeTransportError) as caught:
            helper.run_writer(helper.context(retry_decisions=(True,)), fault=fault)
        self.assertIs(caught.exception, error)
        self.assertEqual(
            helper.events[-1],
            {"operation": "control_io", "ioctl": 2, "parameters": ((0x23, 2),)},
        )
        self.assertEqual(helper.filters, [])


class RawSILNativeCatchTests(unittest.TestCase):
    def test_plain_cpass_status_frame_error_preserved_through_classic_and_wide_operations(
        self,
    ):
        from scripts.programming_2026_common import NativeMemoryInfo

        for wide in (False, True):
            for operation in ("blank", "erase", "inverify", "write", "verify"):
                helper = SILBaseFoundationTests(
                    "test_status_retries_three_native_read_faults_or_bad_frames_and_waits10"
                )
                replies = (
                    [b"\x3c"]
                    + ([b"\x3c"] if operation in ("write", "verify") else [])
                    + [b"bad"] * 3
                )
                channel = helper.channel(replies)
                kwargs = {"last_block": 1} if wide else {}
                with self.assertRaises(ConsolidatedError) as caught:
                    if operation == "write":
                        channel.write_block(
                            1,
                            (1024,),
                            NativeMemoryInfo(0x1000, 0x13FF, 1, 0),
                            bytes(1024),
                            1024,
                            **kwargs,
                        )
                    elif operation == "verify":
                        channel.verify_block(1, (256,), bytes(256), 256, **kwargs)
                    else:
                        channel.block(operation, 1, **kwargs)
                self.assertEqual(caught.exception.code, 4, (wide, operation))

    def test_read_cpass_retries_and_final_object_is_preserved(self):
        from scripts.programming_2026_common import NativePassThruException2026

        helper = SILBaseFoundationTests(
            "test_status_retries_three_native_read_faults_or_bad_frames_and_waits10"
        )
        error = NativePassThruException2026(4, "authored", 1)
        channel = helper.channel([error, error, b"\x3c\x40\x3c"])
        self.assertEqual(channel.get_status(), 0x40)
        self.assertEqual(sum(e.get("data") == b"\x50" for e in helper.events), 3)
        channel = helper.channel([error] * 3)
        with self.assertRaises(NativePassThruException2026) as caught:
            channel.get_status()
        self.assertIs(caught.exception, error)

    def test_write_cpass_is_outside_status_read_retry_scope(self):
        from scripts.programming_2026_common import NativePassThruException2026
        from scripts.programming_2026_consolidated import ConsolidatedSILFlash2026

        events = []
        error = NativePassThruException2026(4, "authored", 1)

        def provider(event, remaining):
            events.append(event)
            raise error

        channel = ConsolidatedSILFlash2026(NativeRuntime2026(provider))
        with self.assertRaises(NativePassThruException2026) as caught:
            channel.get_status()
        self.assertIs(caught.exception, error)
        self.assertEqual(len(events), 1)


class ConsolidatedPaddingIndicationTests(unittest.TestCase):
    def test_fast_init_rx16_uses_actual_padding_for_diagnostic_and_programming_drain(
        self,
    ):
        from scripts.j2534_2026 import NativeMessage
        from scripts.programming_2026_consolidated import (
            ConsolidatedSILFlash2026,
            SilDiag2026,
        )

        for padding in (False, True):
            for programming in (False, True):
                events = []

                def provider(event, remaining, padding=padding, events=events):
                    events.append(event)
                    if event["operation"] == "fast_init":
                        return NativeMessage(3, b"", rx_status=16)
                    if event["operation"] == "get_can_frame_padding":
                        return padding
                    if event["operation"] == "read_messages":
                        return b"authoredinit"
                    if event["operation"] == "write_messages":
                        return 1
                    return None

                runtime = NativeRuntime2026(provider)
                if programming:
                    ConsolidatedSILFlash2026(runtime).enter_programming(
                        bytes.fromhex("0102030405060708"), 0
                    )
                else:
                    SilDiag2026(runtime).fast_init(0x5B)
                self.assertEqual(
                    sum(e["operation"] == "get_can_frame_padding" for e in events), 1
                )
                self.assertEqual(
                    sum(e["operation"] == "read_messages" for e in events), int(padding)
                )
                if not programming:
                    self.assertLess(
                        next(
                            i
                            for i, e in enumerate(events)
                            if e["operation"] == "get_can_frame_padding"
                        ),
                        next(
                            i for i, e in enumerate(events) if e["operation"] == "wait"
                        ),
                    )


class ConsolidatedLiveStateTests(unittest.TestCase):
    def test_actual_electric_execute_snapshots_native_vectors_and_syncs_borrowed_flag_on_host_cleanup_fault(
        self,
    ):
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        engine = ConsolidatedExecute2026(
            IDENTITY,
            ConsolidatedExecuteTests.parameters("45CAN117"),
            common_definitions=ConsolidatedExecuteTests.definitions(3),
        )
        container = ConsolidatedExecuteTests.container(
            "45", "117", "CAN", b"\xa5" * 262144
        )
        helper = ElectricWriterTests(
            "test_cpu117_fixed_four_blocks_native_prepare_and_state_completion"
        )
        finished = False
        error = OSError("authored finalcleanup")

        def fault(event):
            nonlocal finished
            if event.get("data", b"")[4:] == b"\x80":
                finished = True
            if finished and event == {"operation": "set_timeout", "milliseconds": 1000}:
                raise error

        observed = []

        def observer(field, value):
            values = engine.counts if field == "count" else engine.percentages
            self.assertEqual(values[0], value)
            self.assertEqual(values[1:], [0, 0])
            observed.append((field, value))

        def final_native_failure(event):
            if event.get("data", b"")[4:] == b"\x25\x03":
                raise ConsolidatedError(12, "authored finalblock")

        first = helper.run_writer(
            execute=(engine, container, observer), fault=final_native_failure
        )
        self.assertFalse(first["writer_completed"])
        self.assertTrue(engine.last_range)
        self.assertTrue(engine.password_changed)
        self.assertTrue(engine.electric_state.block_started)
        observed.clear()
        with self.assertRaises(OSError) as caught:
            helper.run_writer(execute=(engine, container, observer), fault=fault)
        self.assertIs(caught.exception, error)
        self.assertFalse(engine.active)
        self.assertFalse(engine.last_range)
        self.assertEqual(engine.counts, [524288, 0, 0])
        self.assertEqual(engine.percentages, [100, 0, 0])
        self.assertEqual(observed[-2:], [("count", 524288), ("percent", 100)])

    def test_two_cpu_old_ecb_snapshots_keep_native_active_cpu_and_before_percent_order(
        self,
    ):
        from scripts.programming_2026_consolidated import (
            CANOldECBWriteContext,
            CANOldECBWriteState,
        )

        helper = OldECBWriterTests(
            "test_multiple_cpu_native65_handoff_and_final_finish_use_distinct_locations"
        )
        context = CANOldECBWriteContext(
            IDENTITY,
            ("67", "67"),
            (bytes.fromhex("07d907d100000720"), bytes.fromhex("07da07d200000721")),
            (0, 0),
            (b"\xa5" * 122880, b"\xb6" * 122880),
            (122880, 122880),
            tuple(bytes.fromhex(v) for v in ("1020", "3040", "5060", "7080")),
            2,
            CANOldECBWriteState(),
        )
        snapshots = []
        result = helper.run_writer(
            context=context,
            snapshot=lambda field, values, cpu: snapshots.append((field, values, cpu)),
        )
        self.assertTrue(result["writer_completed"])
        first_cpu1 = next(i for i, row in enumerate(snapshots) if row[2] == 1)
        self.assertEqual(snapshots[first_cpu1], ("count", (245760, 1024), 1))
        self.assertEqual(snapshots[first_cpu1 + 1], ("percent", (100, 0), 1))
        self.assertEqual(snapshots[-1], ("percent", (100, 100), 1))

    def test_base_sil_execute_projects_native_early_normal_callback_even_on_write_error(
        self,
    ):
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        engine = ConsolidatedExecute2026(
            IDENTITY,
            ConsolidatedExecuteTests.parameters("1SIL0"),
            common_definitions=ConsolidatedExecuteTests.definitions(3),
        )
        container = ConsolidatedExecuteTests.container("1", "0", "SIL", b"\xa5" * 1024)
        helper = SILWriterTests(
            "test_full_classic_sil_discovery_prepare_write_verify_and_source_callback"
        )

        def fault(event):
            if event.get("data") == b"\x41":
                raise ConsolidatedError(4, "authoredstatus")

        result = helper.run_writer(execute=(engine, container), fault=fault)
        self.assertTrue(result["execute_return"])
        self.assertTrue(result["native_callback_completed"])
        self.assertEqual(
            result["execute_return_origin"], "host_projection_of_completion_byte"
        )
        self.assertFalse(result["writer_completed"])
        self.assertEqual(result["native_error_code"], 4)
        self.assertTrue(result["caller_abort_744"])
        self.assertFalse(result["caller_old_spec_ecb_9e8"])
        self.assertEqual(result["counts"], (0, 0, 0))


class ConsolidatedCallerErrorObservationTests(unittest.TestCase):
    def test_error_ui_publishes_driver_before_retry_and_export_retains_it(self):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import NativePassThruException2026
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        for mode in ("accepted", "connect-cpass", "reask-cpass", "host-cleanup"):
            with self.subTest(mode=mode):
                engine = ConsolidatedExecute2026(
                    IDENTITY,
                    ConsolidatedExecuteTests.parameters("45CAN117"),
                    common_definitions=ConsolidatedExecuteTests.definitions(3),
                )
                container = ConsolidatedExecuteTests.container(
                    "45", "117", "CAN", b"\xa5" * 262144
                )
                helper = ElectricWriterTests(
                    "test_cpu117_fixed_four_blocks_native_prepare_and_state_completion"
                )
                connects = 0
                host_error = OSError("authored cleanup after native error UI")

                def fault(event, mode=mode, engine=engine, host_error=host_error):
                    nonlocal connects
                    if event.get("data") == bytes.fromhex("000007d12500"):
                        raise NativeTransportError(9)
                    if event["operation"] == "connect":
                        connects += 1
                        # Native c340 must already have published caller slots.
                        self.assertEqual(engine.driver_error, 9 if connects == 1 else 7)
                        if mode == "reask-cpass" and connects == 1:
                            raise NativeTransportError(7)
                        if mode in ("connect-cpass", "reask-cpass"):
                            raise NativePassThruException2026(13, "authored", 1)
                    if (
                        mode == "host-cleanup"
                        and event == {"operation": "set_timeout", "milliseconds": 1000}
                        and connects
                    ):
                        raise host_error

                arguments = {
                    "execute": (engine, container, None),
                    "fault": fault,
                    "retry": (True, True) if mode == "reask-cpass" else (True,),
                }
                if mode == "host-cleanup":
                    with self.assertRaises(OSError) as caught:
                        helper.run_writer(**arguments)
                    self.assertIs(caught.exception, host_error)
                    self.assertEqual(engine.driver_error, 9)
                    self.assertFalse(engine.active)
                    continue
                result = helper.run_writer(**arguments)
                expected_driver = (
                    0 if mode == "accepted" else 7 if mode == "reask-cpass" else 9
                )
                self.assertEqual(result["caller_driver_error_758"], expected_driver)
                if mode == "accepted":
                    self.assertTrue(result["retry_prepared"])
                    self.assertEqual(
                        (result["native_error_code"], result["driver_error"]), (0, 0)
                    )
                    self.assertEqual(result["caller_error_code_754"], 0)
                else:
                    self.assertTrue(result["caller_failed_974"])
                    self.assertEqual(result["caller_error_code_754"], 13)
                    self.assertEqual(result["driver_error"], expected_driver)


class ConsolidatedGetterWorkerBoundaryTests(unittest.TestCase):
    def test_all_seven_getters_catch_connect_native_errors_but_not_final_disconnect(
        self,
    ):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import (
            NativeException2026,
            NativePassThruException2026,
        )
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        branches = (
            ("13", "56", "CAN"),
            ("45", "117", "CAN"),
            ("5", "0", "CAN"),
            ("13", "59", "SIL"),
            ("37", "72", "SIL"),
            ("63", "72", "SIL"),
            ("1", "0", "SIL"),
        )
        for kind, cpu, contact in branches:
            for mode in ("cj", "cpass", "all", "disconnect-cpass", "host", "cancel"):
                with self.subTest(branch=(kind, cpu, contact), mode=mode):
                    engine = ConsolidatedExecute2026(
                        IDENTITY,
                        ConsolidatedExecuteTests.parameters(kind + contact + cpu),
                        common_definitions=ConsolidatedExecuteTests.definitions(),
                    )
                    engine.driver_error = 77
                    engine.state.request_id_records = ("07B0",)
                    error = (
                        NativeTransportError(9)
                        if mode in ("cj", "disconnect-cpass")
                        else NativePassThruException2026(13, "authored", 1)
                        if mode == "cpass"
                        else NativeException2026("authored ALL")
                        if mode == "all"
                        else OSError("authored connect host")
                        if mode == "host"
                        else InterruptedError("authored cancel")
                    )
                    events = []

                    def provider(
                        event, remaining, mode=mode, error=error, events=events
                    ):
                        events.append(event)
                        if event["operation"] == "connect":
                            raise error
                        if (
                            event["operation"] == "disconnect"
                            and mode == "disconnect-cpass"
                        ):
                            raise NativePassThruException2026(14, "authored cleanup", 1)

                    arguments = (
                        ConsolidatedExecuteTests.container(kind, cpu, contact),
                        NativeRuntime2026(provider),
                    )
                    if mode in ("host", "cancel"):
                        with self.assertRaises(type(error)) as caught:
                            engine.execute(*arguments)
                        self.assertIs(caught.exception, error)
                        self.assertEqual(engine.driver_error, 77)
                    else:
                        result = engine.execute(*arguments)
                        self.assertFalse(result["execute_return"])
                        outside = mode == "disconnect-cpass"
                        self.assertEqual(result["caller_failed_974"], outside)
                        self.assertEqual(result["caller_abort_744"], outside)
                        self.assertEqual(
                            result["caller_error_code_754"],
                            14
                            if outside
                            else 1
                            if mode == "cj"
                            else 13
                            if mode == "cpass"
                            else 0,
                        )
                        self.assertEqual(
                            result["caller_driver_error_758"],
                            77 if outside else 9 if mode == "cj" else 0,
                        )
                        if not outside:
                            self.assertEqual(result["identifiers"], ())
                            if contact == "CAN":
                                self.assertEqual(engine.state.request_id_records, ())
                    self.assertEqual(events[-1], {"operation": "disconnect"})
                    self.assertEqual(
                        sum(e["operation"] == "disconnect" for e in events), 1
                    )
                    self.assertFalse(engine.active)

    def test_successful_getter_clears_prior_published_error_slots(self):
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        engine = ConsolidatedExecute2026(
            IDENTITY,
            ConsolidatedExecuteTests.parameters("13CAN56"),
            common_definitions=ConsolidatedExecuteTests.definitions(),
        )
        engine.error_code, engine.driver_error = 13, 9

        def provider(event, remaining):
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] in ("start_flow_control_filter", "write_messages"):
                return 1
            if event["operation"] == "read_specified_can_message":
                return event["address"] + b"\xea\x1eAUTHORED"
            return None

        result = engine.execute(
            ConsolidatedExecuteTests.container(), NativeRuntime2026(provider)
        )
        self.assertTrue(result["execute_return"])
        self.assertEqual(
            (result["caller_error_code_754"], result["caller_driver_error_758"]), (0, 0)
        )
        self.assertEqual(engine.state.request_id_records, ("07A1",))


class ConsolidatedGetterCompletionTests(unittest.TestCase):
    def test_actual_all_seven_getter_branches_select_native_cancel_callback(self):
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        for kind, cpu, contact in (
            ("13", "56", "CAN"),
            ("45", "117", "CAN"),
            ("5", "0", "CAN"),
            ("13", "59", "SIL"),
            ("37", "72", "SIL"),
            ("63", "72", "SIL"),
            ("1", "0", "SIL"),
        ):
            with self.subTest(branch=(kind, cpu, contact)):
                engine = ConsolidatedExecute2026(
                    IDENTITY,
                    ConsolidatedExecuteTests.parameters(kind + contact + cpu),
                    common_definitions=ConsolidatedExecuteTests.definitions(),
                )
                events = []

                def provider(event, remaining, events=events):
                    events.append(event)
                    if event["operation"] == "get_timeout":
                        return 1000
                    if event["operation"] in (
                        "start_flow_control_filter",
                        "write_messages",
                    ):
                        return 1
                    return None

                runtime = NativeRuntime2026(provider, native_cancelled=lambda: True)
                result = engine.execute(
                    ConsolidatedExecuteTests.container(kind, cpu, contact), runtime
                )
                self.assertFalse(result["execute_return"])
                self.assertEqual(result["completion_callback"], "cancel")
                self.assertEqual(result["native_error_code"], 0)
                self.assertEqual(result["identifiers"], ())
                self.assertFalse(result["caller_failed_974"])
                self.assertFalse(result["caller_abort_744"])
                self.assertEqual(events[-1], {"operation": "disconnect"})
                self.assertEqual(runtime.close(), [])

    def test_native_stop_filter_fault_keeps_cid_and_disconnect_retires_failed_child(
        self,
    ):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        engine = ConsolidatedExecute2026(
            IDENTITY,
            ConsolidatedExecuteTests.parameters("13CAN56"),
            common_definitions=ConsolidatedExecuteTests.definitions(),
        )
        events = []

        def provider(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] in ("start_flow_control_filter", "write_messages"):
                return 1
            if event["operation"] == "read_specified_can_message":
                return event["address"] + b"\xea\x1eAUTHORED"
            if event["operation"] == "stop_filter":
                raise NativeTransportError(9)
            return None

        runtime = NativeRuntime2026(provider)
        result = engine.execute(ConsolidatedExecuteTests.container(), runtime)
        self.assertEqual(result["identifiers"], ("AUTHORED",))
        self.assertEqual(
            (result["caller_error_code_754"], result["caller_driver_error_758"]), (1, 9)
        )
        self.assertFalse(result["caller_failed_974"])
        self.assertEqual(engine.state.request_id_records, ())
        self.assertEqual(runtime.close(), [])
        self.assertEqual(events[-1], {"operation": "disconnect"})

    def test_partial_software_ids_keep_detailed_routes_without_unfinished_node_request_rows(
        self,
    ):
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        engine = ConsolidatedExecute2026(
            IDENTITY,
            ConsolidatedExecuteTests.parameters("5CAN0"),
            common_definitions=ConsolidatedExecuteTests.definitions(),
        )
        request = b""

        def provider(event, remaining):
            nonlocal request
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] == "start_flow_control_filter":
                return 1
            if event["operation"] == "write_messages":
                request = event["data"][4:]
                return 1
            if event["operation"] == "read_specified_can_message":
                data = (
                    b"\x5a\x88\0\x01\x02"
                    if request == b"\x1a\x88\0"
                    else b"\x5a\x88\x01FIRST-ID        "
                    if request == b"\x1a\x88\x01"
                    else b"\x5a\x88\x02"
                )
                return event["address"] + data
            return None

        result = engine.execute(
            ConsolidatedExecuteTests.container("5", "0", "CAN"),
            NativeRuntime2026(provider),
        )
        self.assertEqual(result["identifiers"], ("FIRST-ID",))
        self.assertEqual(result["native_error_code"], 3)
        self.assertEqual(engine.state.request_id_records, ())
        self.assertEqual(len(engine.state.software_id_records), 1)
        self.assertEqual(engine.state.software_id_records[0].identifier, "FIRST-ID")
        self.assertFalse(result["caller_failed_974"])


class ConsolidatedGetterAcquisitionCleanupTests(unittest.TestCase):
    def test_disconnect_retires_unreturned_filter_after_cancelled_acquire_rollback_fault(
        self,
    ):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        engine = ConsolidatedExecute2026(
            IDENTITY,
            ConsolidatedExecuteTests.parameters("13CAN56"),
            common_definitions=ConsolidatedExecuteTests.definitions(),
        )
        events = []
        cancelled = False

        def provider(event, remaining):
            nonlocal cancelled
            events.append(event)
            if event["operation"] == "start_flow_control_filter":
                cancelled = True
                return 7
            if event["operation"] == "stop_filter":
                raise NativeTransportError(9)
            return None

        runtime = NativeRuntime2026(provider, cancelled=lambda: cancelled)
        with self.assertRaises(InterruptedError):
            engine.execute(ConsolidatedExecuteTests.container(), runtime)
        self.assertEqual(
            events[-2:],
            [
                {"operation": "stop_filter", "identifier": 7},
                {"operation": "disconnect"},
            ],
        )
        self.assertEqual(runtime.owned_identifiers("stop_filter"), ())
        self.assertEqual(runtime.close(), [])
        self.assertFalse(engine.active)


class ConsolidatedSILFinalDriverSlotTests(unittest.TestCase):
    def test_four_exhausted_mode_errors_retain_original_cj_driver_in_execute(self):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_consolidated import ConsolidatedExecute2026

        engine = ConsolidatedExecute2026(
            IDENTITY,
            ConsolidatedExecuteTests.parameters("1SIL0"),
            common_definitions=ConsolidatedExecuteTests.definitions(),
        )
        attempts = []

        def provider(event, remaining):
            if event["operation"] in ("five_baud_init", "fast_init"):
                attempts.append(event)
                raise NativeTransportError(9)

        result = engine.execute(
            ConsolidatedExecuteTests.container("1", "0", "SIL"),
            NativeRuntime2026(provider),
        )
        self.assertEqual(len(attempts), 4)
        self.assertEqual(
            (result["caller_error_code_754"], result["caller_driver_error_758"]), (1, 9)
        )
        self.assertEqual(result["identifiers"], ())
        self.assertFalse(result["caller_failed_974"])


class ConsolidatedBorrowedProgressTests(unittest.TestCase):
    def test_chassis_silent_reset_mutates_borrowed_vectors_even_when_final_cleanup_raises(
        self,
    ):
        from scripts.programming_2026_consolidated import write_can_chassis

        helper = ChassisWriterTests(
            "test_full_chassis_separate_checkid_native_prepare_timing_and_ranges"
        )
        counts, percentages = [91], [72]
        error = OSError("authored cleanup after silent reset")
        failed = False

        def fault(event):
            nonlocal failed
            if event.get("data") == bytes.fromhex("000007d12600100077"):
                failed = True
                raise ConsolidatedError(12, "authored secondrange")
            if failed and event == {"operation": "set_timeout", "milliseconds": 1000}:
                raise error

        def writer(context, runtime, **observers):
            return write_can_chassis(
                context, runtime, counts=counts, percentages=percentages, **observers
            )

        with self.assertRaises(OSError) as caught:
            helper.run_writer(
                context=helper.context(),
                writer=writer,
                fault=fault,
                separate_check=True,
            )
        self.assertIs(caught.exception, error)
        self.assertEqual((counts, percentages), ([0], [0]))
        self.assertGreater(helper.progress[-2][1], 0)

    def test_m16c_silent_reset_is_visible_before_unhandled_reconnect_failure_without_ui_callbacks(
        self,
    ):
        from scripts.programming_2026_common import NativePassThruException2026

        helper = SILM16CWriterTests(
            "test_native_other_cpu_prepare_three_areas_96pages_write_verify"
        )
        snapshots = []
        pages = 0
        error = NativePassThruException2026(13, "authored connect", 1)

        def fault(event):
            nonlocal pages
            if event["operation"] == "write_messages" and "messages" in event:
                pages += 1
                if pages == 3:
                    raise ConsolidatedError(13, "authored page")
            if event["operation"] == "connect":
                self.assertEqual(snapshots, [(0, 0)])
                raise error

        with self.assertRaises(NativePassThruException2026) as caught:
            helper.run_writer(
                fault=fault,
                retry=(True,),
                snapshot=lambda count, percent: snapshots.append((count, percent)),
            )
        self.assertIs(caught.exception, error)
        self.assertGreater(helper.progress[-2][1], 0)
        self.assertNotEqual(helper.progress[-2:], [("count", 0), ("percent", 0)])
