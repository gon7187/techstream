"""Authored records exercise original executable selector/control semantics."""

import unittest
from dataclasses import replace
from typing import Any, cast
from unittest.mock import patch

from scripts.cuw_legacy_addresses import (
    AddressConfig,
    AddressDiscovery,
    AddressFactoryState,
    CAddress,
    NativeAddressFault,
    P5Address,
    discover_legacy_can_addresses,
    legacy_address_inputs,
    legacy_kind_override,
    parse_can_cids,
    parse_can_identifier,
    probe_can_cids,
    query_can_cids,
    select_fuel_cell_address,
    select_legacy_addresses,
    select_p5_addresses,
)
from tests.test_cuw_legacy_engine import imported_context


class StaticImage:
    def __init__(self, context):
        self.build = context.build
        self.table = b"".join(
            bytes(
                (
                    identifier,
                    0x12,
                    identifier,
                    0xA0,
                    0x34,
                    identifier,
                    0xB0,
                    identifier & 1,
                )
            )
            for identifier in range(65)
        )
        start = 0x586190 if self.build == 12 else 0x5D620C
        override = 0x5854C8 if self.build == 12 else 0x5D51E4
        self.p5_table = b"".join(
            bytes((identifier, 0x12, identifier, 0xA0, 0x34, identifier, 0xB0))
            for identifier in range(3)
        )
        self.memory = {
            start + offset: (0x1000 + offset).to_bytes(4, "little")
            for offset in (0, 4, 8, 12)
        }
        self.memory[override] = (0x1020).to_bytes(4, "little")
        p5_prefix = 0x58B080 if self.build == 12 else 0x5DC974
        self.memory[p5_prefix] = (0x1040).to_bytes(4, "little")
        self.memory[p5_prefix + 4] = (0x1050).to_bytes(4, "little")
        for pointer, value in (
            (0x1000, b"A"),
            (0x1004, b"B"),
            (0x1008, b"C"),
            (0x100C, b"D"),
            (0x1020, b"OVERRIDE"),
            (0x1040, b"P"),
            (0x1050, b"Q"),
        ):
            for index, char in enumerate(value + b"\0"):
                self.memory[pointer + index] = bytes((char,))

    def read(self, address, size):
        if address in (0x58B088, 0x5DC97C):
            return self.p5_table
        if address in (0x5861A0, 0x5D621C):
            return self.table
        value = self.memory[address]
        if len(value) != size:
            raise ValueError("Synthetic span mismatch")
        return value


class AddressFactoryTests(unittest.TestCase):
    def setUp(self):
        self.context = imported_context()
        self.image_patch = patch(
            "scripts.cuw_legacy_addresses.ExecutableImage", StaticImage
        )
        self.image_patch.start()
        self.addCleanup(self.image_patch.stop)

    def ids(self, kind, config=None, **kwargs):
        return tuple(
            row.identifier
            for row in select_legacy_addresses(self.context, kind, config, **kwargs)
        )

    def test_plain_native_branches_and_reverse_order_in_both_builds(self):
        expected = {
            "0": (1, 0),
            "1": (3, 18),
            "2": (0, 3),
            "3": (5,),
            "4": (9,),
            "5": (6,),
            "6": (8, 5, 7),
            "7": (31,),
            "8": (47,),
            "9": (12,),
            "10": (10, 19),
            "11": (47,),
            "12": (11,),
            "13": (15,),
            "14": (16,),
            "15": (17,),
            "16": (20, 21),
            "17": (22,),
            "18": (24,),
            "19": (27,),
            "20": (32,),
            "21": (33,),
            "22": (34,),
            "23": (36,),
            "24": (28,),
            "25": (37,),
            "27": (29,),
            "28": (30,),
            "29": (38,),
            "30": (42,),
            "31": (39,),
            "32": (40,),
            "33": (41,),
            "34": (43,),
            "35": (44,),
            "36": (45,),
            "38": (54,),
            "39": (48,),
            "40": (49,),
            "41": (50,),
            "42": (51,),
            "43": (52,),
            "44": (53,),
            "45": (55,),
            "46": (56,),
            "47": (57,),
            "48": (58,),
            "49": (59,),
            "50": (63,),
            "51": (61,),
            "52": (62,),
            "53": (64,),
            "61": (60,),
        }
        for build in (12, 18):
            self.context = replace(self.context, build=build)
            for kind, identifiers in expected.items():
                with self.subTest(build=build, kind=kind):
                    self.assertEqual(self.ids(kind), identifiers)
            for kind in ("", "26", "37", "63", "10000", "unknown", "01"):
                self.assertEqual(self.ids(kind), ())

    def test_nullable_config_and_count_are_distinct(self):
        empty = AddressConfig(())
        many = AddressConfig(("X", "Y", "Z"))
        for kind, expected in {
            "17": (23,),
            "18": (25,),
            "22": (35,),
            "25": (37, 1, 2, 0),
            "31": (39, 40),
            "32": (39, 40),
            "36": (46,),
        }.items():
            self.assertEqual(self.ids(kind, empty), expected)
        self.assertEqual(self.ids("4", many), (9, 9, 9))
        self.assertEqual(self.ids("13", many), (15, 15, 15))
        self.assertEqual(self.ids("9", many), (14, 13, 12))
        self.assertEqual(self.ids("9", AddressConfig(("X",))), (12,))
        self.assertEqual(self.ids("17", reprog_mode=True), (26,))
        self.assertEqual(self.ids("17", empty, reprog_mode=True), (26,))

    def test_private_string_predicates_and_copied_global_defaults(self):
        for build in (12, 18):
            self.context = replace(self.context, build=build)
            self.assertEqual(self.ids("0", AddressConfig(("X", "Y"))), (0,))
            self.assertEqual(self.ids("0", AddressConfig(("A", "A"))), (1, 2, 0))
            self.assertEqual(self.ids("0", AddressConfig(("A", "B", "C"))), (1, 2, 0))
            state = AddressFactoryState(b"\x06\x07")
            self.assertEqual(
                self.ids("1", AddressConfig(("D",)), factory_state=state), (4, 6)
            )
            self.assertEqual(
                self.ids("1", AddressConfig(()), factory_state=state), (6,)
            )
            for kind in ("10", "16"):
                self.assertEqual(
                    self.ids(kind, AddressConfig(()), factory_state=state), (6,)
                )
            self.assertEqual(legacy_kind_override(self.context), "OVERRIDE")

    def test_native_cid_predicates_compare_prefix_length(self):
        for build in (12, 18):
            self.context = replace(self.context, build=build)
            self.assertEqual(
                self.ids("0", AddressConfig(("A-suffix", "B-suffix"))), (1, 2, 0)
            )
            self.assertEqual(self.ids("0", AddressConfig(("XA", "XB"))), (0,))
            self.assertEqual(
                self.ids(
                    "1",
                    AddressConfig(("D-suffix",)),
                    factory_state=AddressFactoryState(b"\x06"),
                ),
                (4, 6),
            )
            self.assertEqual(
                self.ids(
                    "1",
                    AddressConfig(("XD",)),
                    factory_state=AddressFactoryState(b"\x06"),
                ),
                (6,),
            )

    def test_native_null_global_and_absent_table_id_do_not_guess(self):
        for kind in ("1", "10", "16"):
            with self.assertRaises(NativeAddressFault):
                self.ids(kind, AddressConfig(()))
        self.assertEqual(
            self.ids(
                "10", AddressConfig(()), factory_state=AddressFactoryState(b"\xff")
            ),
            (),
        )

    def test_record_fields_preserve_extra_address_bytes(self):
        record = CAddress(bytes((1, 0x12, 0x34, 0xAB, 0x56, 0x78, 0xCD, 1)))
        self.assertEqual(record.request_header, b"\0\0\x12\x34")
        self.assertEqual(record.response_header, b"\0\0\x56\x78")
        self.assertEqual(record.diagnostic_request_header, b"\0\0\x12\x34\xab")
        self.assertEqual(record.diagnostic_response_header, b"\0\0\x56\x78\xcd")
        ordinary = CAddress(record.raw[:-1] + b"\0")
        self.assertEqual(ordinary.diagnostic_request_header, ordinary.request_header)

    def test_fc_first_exact_match_and_missing_preserves_prior(self):
        prior = CAddress(bytes(8))
        state = AddressFactoryState(
            fuel_cell_rows=(("key", b"1234567"), ("key", b"7654321"))
        )
        for build in (12, 18):
            self.context = replace(self.context, build=build)
            self.assertEqual(
                select_fuel_cell_address(self.context, "key", state, prior).raw,
                b"\x411234567",
            )
            self.assertIs(
                select_fuel_cell_address(self.context, "KEY", state, prior), prior
            )

    def test_normal_manager_inputs_bind_discovered_ids_and_actual_cids(self):
        for build in (12, 18):
            context = replace(self.context, build=build)
            image = StaticImage(context)
            addresses = (CAddress(image.table[48:56]), CAddress(image.table[56:64]))
            discovery = AddressDiscovery(
                build, context.container_sha256, ("A", "B"), addresses, True, addresses
            )
            context = replace(
                context,
                observations={
                    "observed_cids": ("A", "B"),
                    "legacy_address_discovery": discovery,
                },
            )
            kind, config, mode, state = legacy_address_inputs(context)
            self.assertEqual(kind, "1")
            self.assertEqual(config.values, ("A", "B"))
            self.assertTrue(mode)
            self.assertEqual(state.default_selectors, b"\x06\x07")
            self.assertEqual(state.fuel_cell_rows, ())
            self.assertEqual(
                tuple(
                    row.identifier
                    for row in select_legacy_addresses(
                        context, kind, config, reprog_mode=mode, factory_state=state
                    )
                ),
                (6,),
            )

    def test_discovery_keeps_one_selector_per_query_with_multiple_cids(self):
        row = CAddress(StaticImage(self.context).table[:8])
        discovery = AddressDiscovery(
            18, self.context.container_sha256, ("A", "B"), (row, row), False, (row,)
        )
        context = replace(
            self.context,
            observations={
                "observed_cids": ("A", "B"),
                "legacy_address_discovery": discovery,
            },
        )
        _, config, _, state = legacy_address_inputs(context)
        self.assertEqual(config.values, ("A", "B"))
        self.assertEqual(state.default_selectors, b"\x00")
        empty_cids = replace(discovery, cids=(), addresses=())
        empty_context = replace(
            context,
            observations={"observed_cids": (), "legacy_address_discovery": empty_cids},
        )
        self.assertEqual(
            legacy_address_inputs(empty_context)[3].default_selectors, b"\x00"
        )

    def test_recovery_manager_restores_separate_cid_and_node_vectors(self):
        from scripts.programming import NativeSavedRecovery

        recovery = NativeSavedRecovery(
            self.context.container_sha256,
            0,
            0,
            False,
            False,
            False,
            {
                "cidnum": 2,
                "cid1": "A",
                "cid2": "B",
                "cidnodenum": 3,
                "cidnode1": 7,
                "cidnode2": 6,
                "cidnode3": 5,
            },
        )
        context = replace(
            self.context, recovery=recovery, observations={"observed_cids": ("A", "B")}
        )
        _, config, mode, state = legacy_address_inputs(context)
        self.assertEqual(config.values, ("A", "B"))
        self.assertFalse(mode)
        self.assertEqual(state.default_selectors, b"\x07\x06\x05")
        empty = replace(
            context,
            recovery=replace(recovery, fields={}),
            observations={"observed_cids": ()},
        )
        _, empty_config, _, empty_state = legacy_address_inputs(empty)
        self.assertEqual(empty_config.values, ())
        self.assertEqual(empty_state.default_selectors, b"")
        for fields in (
            cast(Any, []),
            {"cidnum": 2},
            {**dict(recovery.fields), "cidnode1": 256},
            {**dict(recovery.fields), "cid2": "OTHER"},
        ):
            with self.assertRaises(NativeAddressFault):
                legacy_address_inputs(
                    replace(context, recovery=replace(recovery, fields=fields))
                )

    def test_factory_inputs_reject_foreign_capture_and_unknown_normal_state(self):
        image = StaticImage(self.context)
        address = CAddress(image.table[:8])
        discovery = AddressDiscovery(
            18, self.context.container_sha256, ("A",), (address,), False
        )
        cases = (
            {"observed_cids": ("A",)},
            {"observed_cids": ["A"]},
            {
                "observed_cids": ("A",),
                "legacy_address_discovery": replace(discovery, build=12),
            },
            {
                "observed_cids": ("A",),
                "legacy_address_discovery": replace(
                    discovery, container_sha256="f" * 64
                ),
            },
            {"observed_cids": ("B",), "legacy_address_discovery": discovery},
            {
                "observed_cids": ("A",),
                "legacy_address_discovery": discovery,
                "legacy_reprog_mode": True,
            },
            {
                "observed_cids": ("A",),
                "legacy_address_discovery": replace(
                    discovery, addresses=(CAddress(b"12345678"),)
                ),
            },
        )
        for observations in cases:
            with (
                self.subTest(observations=observations),
                self.assertRaises(NativeAddressFault),
            ):
                legacy_address_inputs(replace(self.context, observations=observations))
        _, config, mode, state = legacy_address_inputs(
            replace(self.context, observations={"observed_cids": ()})
        )
        self.assertEqual(config.values, ())
        self.assertEqual(state.default_selectors, b"")
        self.assertFalse(mode)

    def test_fc_factory_rows_derive_from_captured_cid_and_headers(self):
        address = CAddress(b"\x411234567")
        discovery = AddressDiscovery(
            18, self.context.container_sha256, ("A",), (address,), False
        )
        context = replace(
            self.context,
            controller="CCanFCFlashWriter",
            observations={
                "observed_cids": ("A",),
                "legacy_address_discovery": discovery,
            },
        )
        _, _, _, state = legacy_address_inputs(context)
        self.assertEqual(state.fuel_cell_rows, (("A", b"1234567"),))
        self.assertEqual(
            select_fuel_cell_address(context, "A", state, CAddress(bytes(8))), address
        )
        with self.assertRaises(NativeAddressFault):
            legacy_address_inputs(
                replace(context, observations={"observed_cids": ("A",)})
            )

    def test_p5_uses_separate_seven_byte_table_and_native_cid_prefixes(self):
        for build in (12, 18):
            context = replace(self.context, build=build)
            for kind, config, expected in (
                ("0", None, (1, 0)),
                ("0", AddressConfig(()), (0,)),
                ("0", AddressConfig(("P-suffix", "Q-suffix")), (1, 0)),
                ("0", AddressConfig(("P", "P")), (1, 0)),
                ("0", AddressConfig(("XP", "XQ")), (0,)),
                ("1", None, (2,)),
                ("1", AddressConfig(()), (2,)),
                ("2", None, ()),
            ):
                rows = select_p5_addresses(context, kind, config)
                self.assertEqual(tuple(row.identifier for row in rows), expected)
                self.assertTrue(all(len(row.raw) == 7 for row in rows))
            row = select_p5_addresses(context, "1")[0]
            self.assertEqual(row.request_header, b"\0\0\x12\x02")
            self.assertEqual(row.response_header, b"\0\0\x34\x02")
            self.assertEqual(row.raw[3], 0xA0)
            self.assertEqual(row.raw[6], 0xB0)
            discovery = AddressDiscovery(
                build, context.container_sha256, ("A",), (row,), False, (row,)
            )
            bound = replace(
                context,
                controller="CP5CanFlashWriter",
                observations={
                    "observed_cids": ("A",),
                    "legacy_address_discovery": discovery,
                },
            )
            kind, config, mode, state = legacy_address_inputs(bound)
            self.assertEqual(state.default_selectors, b"\x02")
            self.assertFalse(mode)
            self.assertEqual(select_p5_addresses(bound, kind, config), (row,))
        with self.assertRaises(ValueError):
            P5Address(bytes(8))
        with self.assertRaises(ValueError):
            select_p5_addresses(self.context, cast(Any, True))
        image = StaticImage(self.context)
        image.p5_table = image.p5_table[:-1]
        with (
            patch("scripts.cuw_legacy_addresses.ExecutableImage", return_value=image),
            self.assertRaises(NativeAddressFault),
        ):
            select_p5_addresses(self.context, "0")

    def test_table_scan_uses_first_identifier_match_not_array_index(self):
        image = StaticImage(self.context)
        rows = [image.table[index : index + 8] for index in range(0, 520, 8)]
        rows[0], rows[28] = rows[28], rows[0]
        rows[1] = rows[0][:1] + b"FIRST!!"
        image.table = b"".join(rows)
        with patch("scripts.cuw_legacy_addresses.ExecutableImage", return_value=image):
            selected = select_legacy_addresses(self.context, "24")
        self.assertEqual(selected[0].raw, rows[0])

    def test_wrong_types_and_bounds_fail_before_static_access(self):
        for kind in (1, True, None, "x\0", "x" * 129):
            with self.assertRaises(ValueError):
                self.ids(cast(Any, kind))
        for value in (["x"], ("x\0",), ("x",) * 4097, (False,)):
            with self.assertRaises(ValueError):
                AddressConfig(cast(Any, value))
        for raw in (b"", bytes(7), bytearray(8)):
            with self.assertRaises(ValueError):
                CAddress(cast(Any, raw))
        for defaults in (bytearray(1), bytes(4097)):
            with self.assertRaises(ValueError):
                AddressFactoryState(cast(Any, defaults))

    def test_actual_source_identity_rejects_missing_and_mutated_pe(self):
        self.image_patch.stop()
        for attachments in ({}, {"legacy_executable": b"MZ"}):
            with self.assertRaises(ValueError):
                select_legacy_addresses(
                    replace(self.context, attachments=attachments), "24"
                )
        self.image_patch.start()

    def test_truncated_table_fails_closed(self):
        image = StaticImage(self.context)
        image.table = image.table[:-1]
        with (
            patch("scripts.cuw_legacy_addresses.ExecutableImage", return_value=image),
            self.assertRaises(NativeAddressFault),
        ):
            self.ids("24")


class CIDGetterTests(unittest.TestCase):
    def test_cid_count_and_ansi_preserved(self):
        first = b"A\xff B\0".ljust(16, b" ")
        second = b"\0" * 16
        self.assertEqual(
            parse_can_cids(b"anything"[:2] + b"\x02" + first + second), ("Aÿ B",)
        )
        from scripts.cuw_legacy_can import ExecutableCANError

        for payload in (b"", b"\x49\x04\x00", b"\x49\x04\x02" + first):
            with self.assertRaises(ExecutableCANError) as raised:
                parse_can_cids(payload)
            self.assertEqual(raised.exception.code, 1)

    def test_identifier_preserves_tail_and_invalid_previous(self):
        previous = b"x" * 13
        self.assertEqual(
            parse_can_identifier(b"\x5a\0\0AB", previous), b"IIAB\0" + b"x" * 8
        )
        for payload in (b"\x5a", b"\x5a\0\0", b"\x5aABC\x1f"):
            self.assertEqual(parse_can_identifier(payload, previous), previous)
        self.assertEqual(
            parse_can_identifier(b"\x5a" + b"A" * 20, previous), b"A" * 12 + b"\0"
        )

    def test_getter_query_order_skip_break_and_failure_cleanup(self):
        from scripts.cuw_legacy_can import ExecutableCANError
        from scripts.cuw_legacy_channel import ChannelState
        from scripts.cuw_legacy_engine import ExecutableIO

        context = imported_context()
        rows = tuple(
            CAddress(bytes((identifier, 1, 2, 3, 4, 5, 6, 1)))
            for identifier in (1, 0, 3, 20)
        )
        operations = []
        io = ExecutableIO(lambda event, remaining: operations.append(event))
        with (
            patch(
                "scripts.cuw_legacy_addresses.select_legacy_addresses",
                return_value=rows,
            ) as select,
            patch("scripts.cuw_legacy_engine.executable_reconnect") as reconnect,
            patch("scripts.cuw_legacy_channel.disconnect") as disconnect,
            patch(
                "scripts.cuw_legacy_channel.channel_state", return_value=ChannelState()
            ),
            patch(
                "scripts.cuw_legacy_addresses.probe_can_cids",
                side_effect=(False, True, True),
            ),
            patch(
                "scripts.cuw_legacy_addresses.query_can_cids",
                side_effect=((("A", "B"), b"x" * 13, True), ((), b"y" * 13, True)),
            ),
        ):
            output, buffers = discover_legacy_can_addresses(
                context,
                io,
                read_identifier=True,
                reprog_mode=False,
                terminated=lambda: False,
            )
            self.assertEqual(output.cids, ("A", "B"))
            self.assertEqual(output.addresses, (rows[1], rows[1]))
            self.assertEqual(output.queried_addresses, rows[1:3])
            self.assertEqual(buffers, ((b"x" * 13, True), (b"y" * 13, True)))
            self.assertEqual(
                select.call_args.args,
                (context, context.native.base_metadata["kind_of_ecu"]),
            )
            reconnect.assert_called_once_with(context, io, 6)
            disconnect.assert_called_once_with(context, io)
        with (
            patch(
                "scripts.cuw_legacy_addresses.select_legacy_addresses",
                return_value=(rows[1],),
            ),
            patch("scripts.cuw_legacy_engine.executable_reconnect"),
            patch("scripts.cuw_legacy_channel.disconnect") as disconnect,
            patch(
                "scripts.cuw_legacy_channel.channel_state", return_value=ChannelState()
            ),
            patch("scripts.cuw_legacy_addresses.probe_can_cids", return_value=False),
            self.assertRaises(ExecutableCANError),
        ):
            discover_legacy_can_addresses(
                context,
                io,
                read_identifier=False,
                reprog_mode=False,
                terminated=lambda: False,
            )
        disconnect.assert_called_once()

    def test_original12_getter_has_no_newer_identifier_slots(self):
        from scripts.cuw_legacy_channel import ChannelState
        from scripts.cuw_legacy_engine import ExecutableIO

        context = replace(imported_context(), build=12)
        row = CAddress(bytes((3, 1, 2, 3, 4, 5, 6, 1)))
        io = ExecutableIO(lambda event, remaining: None)
        with (
            patch(
                "scripts.cuw_legacy_addresses.select_legacy_addresses",
                return_value=(row,),
            ),
            patch("scripts.cuw_legacy_engine.executable_reconnect"),
            patch("scripts.cuw_legacy_channel.disconnect"),
            patch(
                "scripts.cuw_legacy_channel.channel_state", return_value=ChannelState()
            ),
            patch("scripts.cuw_legacy_addresses.probe_can_cids", return_value=True),
            patch(
                "scripts.cuw_legacy_addresses.query_can_cids",
                return_value=(("OLD",), b"\0" * 13, False),
            ) as query,
        ):
            output, identifiers = discover_legacy_can_addresses(
                context,
                io,
                read_identifier=False,
                reprog_mode=False,
                terminated=lambda: False,
            )
            self.assertEqual(output.cids, ("OLD",))
            self.assertEqual(output.queried_addresses, (row,))
            self.assertEqual(identifiers, ())
            self.assertFalse(query.call_args.kwargs["read_identifier"])
        with self.assertRaises(ValueError):
            discover_legacy_can_addresses(
                context,
                io,
                read_identifier=True,
                reprog_mode=False,
                terminated=lambda: False,
            )

    def test_concrete_query_uses_only_neutral_primitives(self):
        from scripts.cuw_legacy_can import CommonCAN
        from scripts.cuw_legacy_engine import ExecutableIO
        from scripts.j2534_2026 import NativeMessage

        request, response = b"\0\0\x12\x34", b"\0\0\x56\x78"
        frames, events, requests = [], [], []
        replies = {
            b"\x09\x00": b"\x49\x00\x30\0\0\0",
            b"\x09\x04": b"\x49\x04\x02"
            + b"CID-A".ljust(16, b"\0")
            + b"CID-B".ljust(16, b"\0"),
            b"\x1a\x89": b"\x5a\0PART-001",
        }

        def action(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "start_filter":
                self.assertEqual(event["flow_control"].data, request)
                self.assertEqual(event["pattern"].data, response)
                return 17
            if operation == "write_messages":
                payload = event["data"][4:]
                requests.append(payload)
                frames.append(NativeMessage(6, request, rx_status=9))
                frames.append(NativeMessage(6, response + replies[payload]))
                return 1
            if operation == "read_messages":
                return (frames.pop(0),)
            if operation not in ("ioctl", "wait", "stop_filter", "set_timeout"):
                raise AssertionError(operation)
            return None

        io = ExecutableIO(action)
        channel = CommonCAN(io, request, response, padding=False, read_timeout_ms=1000)
        self.assertTrue(probe_can_cids(channel))
        cids, identifier, flag = query_can_cids(
            channel,
            read_identifier=True,
            previous_identifier=b"\0" * 13,
            native_cancel=lambda: False,
            terminated=False,
        )
        self.assertEqual(cids, ("CID-A", "CID-B"))
        self.assertEqual(identifier, b"IPART-001" + b"\0" * 4)
        self.assertTrue(flag)
        self.assertEqual(requests, [b"\x09\x00", b"\x09\x04", b"\x1a\x89"])
        self.assertEqual(sum(e["operation"] == "stop_filter" for e in events), 2)
        self.assertFalse(frames)

    def test_query_probe_cancel_and_filter_ownership(self):
        from scripts.cuw_legacy_can import CommonCAN
        from scripts.cuw_legacy_engine import ExecutableIO, ExecutableJ2534Error

        operations = []

        def action(event, remaining):
            operations.append(event["operation"])
            return 8 if event["operation"] == "start_filter" else None

        io = ExecutableIO(action)
        channel = CommonCAN(
            io, b"\0\0\x12\x34", b"\0\0\x56\x78", padding=True, read_timeout_ms=1000
        )
        payload = b"\x49\x04\x01" + b"CID".ljust(16, b"\0")
        with patch(
            "scripts.cuw_legacy_body.diagnostic", return_value=payload
        ) as exchange:
            result = query_can_cids(
                channel,
                read_identifier=False,
                previous_identifier=b"\0" * 13,
                native_cancel=lambda: False,
                terminated=False,
            )
            self.assertEqual(result, (("CID",), b"\0" * 13, False))
            self.assertEqual(exchange.call_args.args[1:5], (b"\x09\x04", b"", 0, 3))
        with patch("scripts.cuw_legacy_body.diagnostic") as exchange:
            result = query_can_cids(
                channel,
                read_identifier=True,
                previous_identifier=b"x" * 13,
                native_cancel=lambda: False,
                terminated=True,
            )
            self.assertEqual(result, ((), b"x" * 13, False))
            exchange.assert_not_called()
        for status, expected in ((9, False), (16, False), (7, None)):
            with patch(
                "scripts.cuw_legacy_body.diagnostic",
                side_effect=ExecutableJ2534Error(3, status),
            ):
                if expected is None:
                    with self.assertRaises(ExecutableJ2534Error):
                        probe_can_cids(channel)
                else:
                    self.assertEqual(probe_can_cids(channel), expected)
        self.assertEqual(
            operations.count("start_filter"), operations.count("stop_filter")
        )


if __name__ == "__main__":
    unittest.main()
