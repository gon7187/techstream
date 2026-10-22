"""Authored synthetic vectors for selected native chassis state and fault paths."""

import hashlib
import struct
import unittest
from collections.abc import Callable
from dataclasses import replace

from scripts.native_memory import NativeMemoryArena
from scripts.utility_ex_ty import SHA_12_TY, SHA_PLUS_TY, TYSourceError
from scripts.utility_ex_ty_chassis import (
    CONTRACT_12,
    CONTRACT_PLUS,
    ChassisContract,
    ChassisEngine,
    run_body,
    supports,
)


class Comm:
    def __init__(self, replies=(), sessions=(), initial=0, snapshots=()):
        self.replies = list(replies)
        self.sessions = list(sessions)
        self.initial = initial
        self.events = []
        self.snapshots = list(snapshots)
        self.native_10b0 = 0
        self.target = (0x700, 12)
        self.dtcs: tuple[int, bytes] = (0, b"\x53\0")

    def initialize(self, mode=0):
        self.events.append(("initialize", mode))
        return self.initial

    def configure(self, field, value):
        self.events.append(("configure", field, value))

    def select_target(self, identifier, second=0):
        self.events.append(("select_target", identifier, second))

    def read_field(self, field):
        assert field == "native_10b0"
        self.events.append(("read_field", field))
        return self.native_10b0

    def configure_target(self, first, second=0, third=0, fourth=0, fifth=0):
        raise AssertionError("unexpected native target configuration")

    def select_protocol(self, kind):
        raise AssertionError("unexpected native protocol selection")

    def read_target(self):
        self.events.append(("read_target",))
        return self.target

    def read_dtcs(self, mode=0x80, capacity=0x1000):
        self.events.append(("read_dtcs", mode, capacity))
        return self.dtcs

    def session(self, mode, keepalive=1, **kwargs):
        self.events.append(("session", mode, keepalive))
        return self.sessions.pop(0) if self.sessions else 0

    def exchange(self, request):
        self.events.append(("exchange", request))
        return self.replies.pop(0)

    def cleanup_exchange(self, request):
        return self.exchange(request)

    def cleanup_session(self, mode, keepalive=1, **kwargs):
        return self.session(mode, keepalive, **kwargs)

    def finalize(self):
        self.events.append(("finalize",))

    def support_snapshot(self, kind):
        self.events.append(("support_snapshot", kind))
        return self.snapshots.pop(0)


class Context:
    mode = 20
    native_memory: NativeMemoryArena | None = None

    @property
    def native_memory_owner(self) -> object:
        return self

    module_bytes = b"authored synthetic chassis source identity"
    module_sha256 = hashlib.sha256(module_bytes).hexdigest()

    def __init__(self, comm):
        self.controller = comm
        self.sleeps = []
        self.tick = 0
        self.cancelled = False
        self.state = {}
        self.on_sleep: Callable[[int], None] = lambda _: None

    def comm(self, kind):
        assert kind in ("synthetic-manager", "selected")
        return self.controller

    def sleep(self, ms):
        self.sleeps.append(ms)
        self.tick = (self.tick + ms) & 0xFFFFFFFF
        self.on_sleep(ms)

    def ticks(self):
        return self.tick

    def is_cancelled(self):
        return self.cancelled


def engine():
    return ChassisEngine(
        ChassisContract(
            Context.module_sha256, "synthetic-manager", "retry", "pending", "retries"
        )
    )


class AHCComm(Comm):
    def configure_target(self, first, second=0, third=0, fourth=0, fifth=0):
        self.events.append(("configure_target", first, second, third, fourth, fifth))


class AHCContext(Context):
    def __init__(self, primary, secondary):
        super().__init__(primary)
        self.secondary = secondary

    def comm(self, kind):
        return self.secondary if kind == "native:1011c400" else super().comm(kind)


class ChassisTests(unittest.TestCase):
    def test_asus06_07_native_helpers_check_echo_without_extra_service_predicate(self):
        for original in (engine().contract, CONTRACT_12, CONTRACT_PLUS):
            contract = replace(
                original,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
                nk_manager=None,
            )
            native = ChassisEngine(contract)
            comm = Comm([(0, b"\0\x21\1")])
            ctx = Context(comm)
            self.assertEqual(native.run_body("Ex2ASUS_06_ConditionCheck", (), ctx), 0)
            self.assertNotIn(("finalize",), comm.events)
            comm = Comm([(0, b"\0\1\x11\1"), (0, b"\0\3\x11\1\2")])
            data = bytearray(8)
            struct.pack_into("<I", data, 4, 2001)
            ctx = Context(comm)
            self.assertEqual(native.run_body("Ex2ASUS_06_LiftRise", (data,), ctx), 0)
            self.assertIn(("exchange", b"\x31\1\x11\1\2\4\x8f"), comm.events)
            self.assertEqual(ctx.sleeps, [100])
            self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])
        comm = Comm([(0, b"\0\x22\1")])
        self.assertEqual(
            engine().run_body("Ex2ASUS_06_ConditionCheck", (), Context(comm)), 3
        )

    def test_plus_ars_native_dtc_filter_restore_and_center_boundaries(self):
        plus = ChassisEngine(
            replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        )
        for export, expected in (
            ("Ex2ARS_01_ReadDTCofVGRS", 1000),
            ("Ex2ARS_02_ChkVGRSDtc", -0x6FFFFFFF),
        ):
            comm = Comm()
            comm.dtcs = (0, b"\x53\1\x55\xca")
            self.assertEqual(plus.run_body(export, (), Context(comm)), expected)
            self.assertEqual(
                comm.events[-2:], [("finalize",), ("select_target", 0x700, 0)]
            )
            self.assertIn(("configure", "native_rva:142f0", 150), comm.events)
        for raw, expected in ((32768, 0), (30947, 1100), (34588, 0), (34589, 1100)):
            comm = Comm(
                [
                    (0, b"x"),
                    (0, b"\x70\5"),
                    (0, b"x"),
                    (0, b"\x61\x09" + raw.to_bytes(2, "big")),
                ]
            )
            ctx = Context(comm)
            data = bytearray(8)
            struct.pack_into("<II", data, 0, 4, 4)
            self.assertEqual(
                plus.run_body("Ex2ARS_01_ReturnActuatorCenterPos", (data,), ctx),
                expected,
            )
            self.assertEqual(ctx.sleeps, [500, 10000, 500])
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_plus_bsm_conditional_source_constants_keep_strict_angle_boundaries(self):
        plus = ChassisEngine(
            replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        )
        data = bytearray(36)
        for offset, value in ((4, 5), (12, 4), (20, 2)):
            struct.pack_into("<I", data, offset, value)
        data[28] = 0xD1
        for after, expected in (
            (499, 0),
            (500, 9001),
            (-499, 0),
            (-500, 9001),
            (100, 9001),
        ):
            comm = Comm(
                [
                    (0, b"\x61\x68\0\0\x64"),
                    (0, b"\x70\xd1"),
                    (0, b"\x61\x68\x80\0\0"),
                    (0, b"\x61\x68\0" + after.to_bytes(2, "big", signed=True)),
                    (9, b""),
                ]
            )
            self.assertEqual(
                plus.run_body("Ex2BSM_03_04_ActiveTestCon3_5", (data,), Context(comm)),
                expected,
            )
            self.assertIn(("configure", "native_rva:142f0", 150), comm.events)
            self.assertEqual(comm.events[-2:], [("exchange", b"\x30"), ("finalize",)])

    def test_plus_tpw_pointer_write_and_4wd_prevention_literal_predicates(self):
        plus = ChassisEngine(
            replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        )
        comm = Comm([(0, b"\x7b\x36")])
        ctx = Context(comm)
        ctx.native_memory = NativeMemoryArena(ctx.module_sha256, ctx)
        data = bytearray(0xC4)
        struct.pack_into("<I", data, 0x20, 2)
        struct.pack_into("<I", data, 0xC0, 5)
        data[4] = 7
        self.assertEqual(plus.run_body("Ex2TPW_03_SendMessage", (data,), ctx), 0)
        self.assertIn(("exchange", b"\x3b\x36\7\0\0\0\0"), comm.events)
        self.assertIn(("configure", "native_rva:142f0", 150), comm.events)
        for prefix in (b"\x7b\x0b", b"\0\x0b"):
            comm = Comm([(0, prefix), (0, b"\x61\xa6\x80"), (0, b"")])
            data = bytearray(4)
            struct.pack_into("<I", data, 0, 1)
            ctx = Context(comm)
            self.assertEqual(
                plus.run_body("Ex24WD_03_ChangePreventionMode", (data,), ctx),
                0 if prefix[0] == 0x7B else 3,
            )
            if prefix[0] == 0x7B:
                self.assertEqual(ctx.sleeps, [500])
            else:
                self.assertIn(("exchange", b"\x3b\x0b\0"), comm.events)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_plus_bsm_native_busy_setter_and_fault_output_mapping(self):
        plus = ChassisEngine(
            replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        )
        for export, replies, expected in (
            (
                "Ex2BSM_01_02_ChkStilInTestMode",
                [(0, b"\x50\x60"), (9, b"\x61\x69\xc0"), (0, b"x")],
                9,
            ),
            ("Ex2BSM_07_08_GetAbnormalHistory", [(9, b"\x61\x6c\xf8")], 9),
            (
                "Ex2BSM_07_08_ClearAbnormalHistory",
                [(0, b"ok"), (9, b"\x61\x6c\xf8")],
                2000,
            ),
        ):
            comm = Comm(replies)
            data = bytearray(12)
            struct.pack_into("<I", data, 0, 3)
            self.assertEqual(plus.run_body(export, (data,), Context(comm)), expected)
            self.assertEqual(data[8], 3 if export.startswith("Ex2BSM_01_") else 0xF8)
            self.assertIn(("configure", "native_rva:142f0", 256), comm.events)
            self.assertIn(("configure", "native_rva:14320", 256), comm.events)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_plus_drs_retained_reads_stop_precedence_and_legacy_role(self):
        plus = ChassisEngine(
            replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        )
        comm = Comm([(0, b"\x61\x0e\0\x12\xff\x80")])
        data = bytearray(20)
        struct.pack_into("<I", data, 0, 6)
        struct.pack_into("<I", data, 16, 5)
        self.assertEqual(
            plus.run_body("Ex2DRS_03_ReadRadarCruiseData", (data,), Context(comm)), 0
        )
        self.assertEqual(data[12:15], b"\x12\x3f\x80")
        self.assertIn(("configure", "native_rva:142f0", 150), comm.events)
        self.assertNotIn(("finalize",), comm.events)
        for export, reply, expected in (
            ("Ex2DRS_02_StopActiveTest", b"", 3),
            ("Ex2DRS_03_StopActiveTest", b"", 9),
            ("Ex2DRS_02_StopActiveTest", b"x", 9),
        ):
            comm = Comm([(9, reply)])
            self.assertEqual(plus.run_body(export, (), Context(comm)), expected)
            self.assertIn(("configure", "native_rva:142f0", 150), comm.events)
            self.assertEqual(comm.events[-1], ("finalize",))
        comm = Comm(initial=7)
        self.assertEqual(
            plus.run_body("Ex2DRS_02_SupportCheck", (bytearray(28),), Context(comm)), 7
        )
        self.assertEqual(
            comm.events, [("select_target", 0x790, 0), ("initialize", 0), ("finalize",)]
        )

    def test_plus_asus04_05_native_pending_and_literal_session_lengths(self):
        plus = ChassisEngine(
            replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        )
        data = bytearray(20)
        struct.pack_into("<I", data, 8, 4)
        struct.pack_into("<I", data, 16, 200)
        for export, replies, expected_requests in (
            ("Ex2ASUS_04_ModifyVhight", [(0, b"ok")], [b"\x30\6\x14\1"]),
            (
                "Ex2ASUS_05_ModifyVheightDownStart",
                [(0, b"x"), (0, b"ok")],
                [b"\x10\x60\0", b"\x30\6\x19\1"],
            ),
            (
                "Ex2ASUS_05_ModifyVheightStop",
                [(9, b""), (0, b"x")],
                [b"\x30\6\0\0", b"\x10\1"],
            ),
            ("Ex2ASUS_05_ReturnVheightStart", [(0, b"x")], [b"\x30"]),
        ):
            comm = Comm(replies)
            ctx = Context(comm)
            ctx.mode = 4
            args = () if export.endswith("ReturnVheightStart") else (data,)
            self.assertEqual(
                plus.run_body(export, args, ctx),
                9 if export.endswith("ModifyVheightStop") else 0,
            )
            self.assertEqual(
                [event[1] for event in comm.events if event[0] == "exchange"],
                expected_requests,
            )
            self.assertIn(("configure", "native_rva:142f0", 150), comm.events)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_supplied12_bsm_support_omits18_optional_selector3_fields(self):
        def snapshot(records):
            raw = b""
            offsets = [0x1020] * 256
            for identifier, payload in records:
                offsets[identifier] = len(raw)
                raw += bytes((identifier, len(payload))) + payload
            return 0, raw.ljust(0x1020, b"\0"), tuple(offsets)

        records = (
            (0x68, b"\xff" * 12),
            (0x7B, b"\xff" * 9),
            (0x6B, b"\x20"),
            (0x6A, b"\0" * 4 + b"\x40"),
        )
        for contract, expected in (
            (replace(CONTRACT_12, source_sha256=Context.module_sha256), 2),
            (engine().contract, 3),
        ):
            comm = Comm(snapshots=[snapshot(records), snapshot(((0xD1, b"\x80"),))])
            data = bytearray(36)
            data[28] = 0xD1
            self.assertEqual(
                ChassisEngine(contract).run_body(
                    "Ex2BSM_03_04_SupportCheck", (data,), Context(comm)
                ),
                0,
            )
            self.assertEqual(struct.unpack_from("<I", data, 32)[0], expected)
            self.assertIn(("configure", contract.legacy_setter, 150), comm.events)

    def test_supplied12_ars_4wd_psa_fault_branches_keep_source_pending_setter(self):
        native12 = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        for export, size in (
            ("Ex2ARS_02_InitCompVal", 12),
            ("Ex2ARS_03_ActiveTest", 12),
            ("Ex2ARS_01_ReturnActuatorCenterPos", 8),
            ("Ex24WD_03_ChangePreventionMode", 4),
            ("Ex2PSAABS_01_SendMessage", 0),
        ):
            comm = Comm([(9, b""), (0, b"")])
            ctx = Context(comm)
            args = (bytearray(size),) if size else ()
            self.assertEqual(native12.run_body(export, args, ctx), 9)
            self.assertIn(("configure", "native_rva:b940", 150), comm.events)
            self.assertNotIn(("configure", "native_rva:12180", 150), comm.events)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_supplied12_tpw_and_drs_use_actual_legacy_setter_and_retention(self):
        native12 = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        data = bytearray(0xC4)
        struct.pack_into("<I", data, 0x20, 2)
        struct.pack_into("<I", data, 0xC0, 5)
        data[4] = 7
        comm = Comm([(0, b"\x7b\x36")])
        ctx = Context(comm)
        ctx.native_memory = NativeMemoryArena(ctx.module_sha256, ctx)
        self.assertEqual(native12.run_body("Ex2TPW_03_SendMessage", (data,), ctx), 0)
        self.assertIn(("configure", "native_rva:b940", 150), comm.events)
        self.assertEqual(
            comm.events[-2:], [("exchange", b"\x3b\x36\7\0\0\0\0"), ("finalize",)]
        )
        data = bytearray(28)
        for offset, value in ((0, 3), (4, 4), (8, 5), (12, 6), (16, 7), (20, 2)):
            struct.pack_into("<I", data, offset, value)
        comm = Comm([(0, b"\x70\1"), (0, b"\x61\x0e\0\x12\xff\x20")])
        self.assertEqual(
            native12.run_body("Ex2DRS_02_ReadRadarCruiseData", (data,), Context(comm)),
            0,
        )
        self.assertEqual(data[24:27], b"\x12\x3f\x20")
        self.assertIn(("configure", "native_rva:b940", 150), comm.events)
        self.assertNotIn(("finalize",), comm.events)
        comm = Comm([(9, b"")])
        data = bytearray(0x1064)
        struct.pack_into("<I", data, 0x1028, 1)
        self.assertEqual(
            native12.run_body("Ex2DRS_04_SendMessage", (data,), Context(comm)), 9
        )
        self.assertIn(("configure", "native_rva:b940", 150), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_plus_emps_steering_start_preserves_host_fault_over_finalize_fault(self):
        contract = replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        primary = RuntimeError("native session callback failed")
        secondary = RuntimeError("disconnect failed")

        class FaultingComm(Comm):
            def session(self, mode, keepalive=1, **kwargs):
                self.events.append(("session", mode, keepalive))
                raise primary

            def finalize(self):
                self.events.append(("finalize",))
                raise secondary

        comm = FaultingComm()
        ctx = Context(comm)
        ctx.mode = 20
        ctx.comm = lambda kind: comm
        with self.assertRaises(RuntimeError) as raised:
            ChassisEngine(contract).run_body("Ex2EMPS_12_SteeringStart", (), ctx)
        self.assertIs(raised.exception, primary)
        self.assertEqual(
            [event for event in comm.events if event[0] == "finalize"],
            [("finalize",)],
        )

    def test_tpw03_support_inline_descriptors_reverse_masks_and_retained_outputs(self):
        raw = bytes((0x12, 3, 0x80, 0x40, 1))
        offsets = [0x1020] * 256
        offsets[0x12] = 0
        snapshot = (0, raw.ljust(0x1020, b"\0"), tuple(offsets))
        comm = Comm(snapshots=[snapshot, snapshot])
        ctx = Context(comm)
        ctx.native_memory = NativeMemoryArena(ctx.module_sha256, ctx)
        pointer = ctx.native_memory.alloc(2)
        ctx.native_memory.write(pointer, b"\x80\x40")
        data = bytearray(0xC4)
        for descriptor in [0x24 + i * 20 for i in range(7)] + [0xB0]:
            data[descriptor] = 0x12
            struct.pack_into("<II", data, descriptor + 4, pointer, 2)
        self.assertEqual(engine().run_body("Ex2TPW_03_SendMessage", (data,), ctx), 0)
        self.assertEqual(struct.unpack_from("<II", data, 0x30), (2, 3))
        self.assertEqual(
            [event for event in comm.events if event[0] == "support_snapshot"],
            [("support_snapshot", 1), ("support_snapshot", 3)],
        )
        ctx.native_memory.write(pointer, b"\x80\x80")
        comm.snapshots = [snapshot]
        struct.pack_into("<I", data, 0x30, 77)
        self.assertEqual(engine().run_body("Ex2TPW_03_SendMessage", (data,), ctx), 22)
        self.assertEqual(struct.unpack_from("<I", data, 0x30)[0], 77)

    def test_tpw03_read_native_break_mapping_and_write_length_zero_tail(self):
        data = bytearray(0xC4)
        struct.pack_into("<I", data, 0x20, 1)
        comm = Comm([(0, b"\x61\x10\x80"), (0, b"\x61\x11abcd"), (0, b"\x61\x17\x07")])
        ctx = Context(comm)
        ctx.native_memory = NativeMemoryArena(ctx.module_sha256, ctx)
        pointer = ctx.native_memory.alloc(5)
        ctx.native_memory.write(pointer, b"\xff" * 5)
        for descriptor, identifier, length in (
            (0x24, 0x10, 1),
            (0x38, 0x11, 4),
            (0x4C, 0x13, 1),
            (0x9C, 0x17, 1),
        ):
            data[descriptor] = identifier
            struct.pack_into("<IIII", data, descriptor + 4, pointer, length, 2, length)
        self.assertEqual(engine().run_body("Ex2TPW_03_SendMessage", (data,), ctx), 0)
        self.assertEqual(data[:5], b"abcd\7")
        self.assertEqual(struct.unpack_from("<I", data, 0x1C)[0], 1)
        struct.pack_into("<I", data, 0x20, 2)
        struct.pack_into("<I", data, 0xC0, 7)
        comm.replies = [(0, b"\x7b\x36")]
        self.assertEqual(engine().run_body("Ex2TPW_03_SendMessage", (data,), ctx), 0)
        self.assertEqual(comm.events[-2], ("exchange", b"\x3b\x36\7\0\0\0\0\0\0"))
        comm.replies = [(9, b"")]
        self.assertEqual(engine().run_body("Ex2TPW_03_SendMessage", (data,), ctx), 9007)

    def test_pointer_owner_fault_precedes_manager_side_effects(self):
        for export, size in (
            ("Ex2TPW_03_SendMessage", 0xC4),
            ("Ex2AWD_04_ReadValues", 45),
            ("Ex24WD_05_WriteHistoryData", 0x56),
        ):
            comm = Comm()
            ctx = Context(comm)
            ctx.native_memory = NativeMemoryArena(ctx.module_sha256, object())
            with self.assertRaisesRegex(ValueError, "source/owner"):
                engine().run_body(export, (bytearray(size),), ctx)
            self.assertEqual(comm.events, [])

    def test_awd04_history_replaces_old_allocation_and_preserves_record_bytes(self):
        support = b"\x62\1\1" + bytes(32)
        comm = Comm(
            [(0, support), (0, b"\x62\x22\1abc"), (0, b"\x62\x22\2d")] + [(7, b"")] * 25
        )
        ctx = Context(comm)
        ctx.native_memory = NativeMemoryArena(ctx.module_sha256, ctx)
        old = ctx.native_memory.alloc(3)
        data = bytearray(45)
        struct.pack_into("<II", data, 32, 3, old)
        self.assertEqual(engine().run_body("Ex2AWD_04_ReadValues", (data,), ctx), 1023)
        length, pointer = struct.unpack_from("<II", data, 32)
        self.assertEqual(length, 12)
        self.assertEqual(
            ctx.native_memory.read(pointer, length), b"\x22\1\3\0abc\x22\2\1\0d"
        )
        with self.assertRaises(ValueError):
            ctx.native_memory.read(old, 1)
        requests = [event[1] for event in comm.events if event[0] == "exchange"]
        self.assertEqual(requests[10], b"\x22\x22\x10")
        self.assertEqual(requests[-1], b"\x22\x22\x21")

    def test_awd04_values_and_missing_history_native_status_precedence(self):
        support = bytearray(b"\x62\1\1" + bytes(32))
        support[7] = 0x80
        available = bytearray(b"\x62\x20\0" + bytes(32))
        available[3] = 0x40
        for values, normal_fault, expected in (
            (True, False, 0),
            (True, True, 1001),
            (False, True, 1015),
        ):
            replies = [(0, bytes(support) if values else b"\x62\1\1" + bytes(32))]
            if values:
                replies += [
                    (0, bytes(available)),
                    (0, b"\x62\x20\2" + b"a" * 16),
                    (0, b"\x62\x20\3" + b"b" * 16),
                ]
            comm = Comm(
                replies + [(7, b"")] * 27, sessions=[0, 0, 9 if normal_fault else 0]
            )
            ctx = Context(comm)
            ctx.native_memory = NativeMemoryArena(ctx.module_sha256, ctx)
            data = bytearray(45)
            self.assertEqual(
                engine().run_body("Ex2AWD_04_ReadValues", (data,), ctx), expected
            )
            self.assertEqual(data[:32], b"a" * 16 + b"b" * 16 if values else bytes(32))
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_4wd05_bounded_history_records_ignore_wire_faults_and_reject_foreign_owner(
        self,
    ):
        comm = Comm([(7, b""), (0, b"\x6e\x20\3")])
        ctx = Context(comm)
        ctx.native_memory = NativeMemoryArena(ctx.module_sha256, ctx)
        history = b"\x20\2\2\0ab\x20\3\0\0"
        pointer = ctx.native_memory.alloc(len(history))
        ctx.native_memory.write(pointer, history)
        data = bytearray(0x56)
        struct.pack_into("<IH", data, 0x50, pointer, len(history))
        self.assertEqual(
            engine().run_body("Ex24WD_05_WriteHistoryData", (data,), ctx), 0
        )
        self.assertIn(("exchange", b"\x2e\x20\2ab"), comm.events)
        self.assertIn(("exchange", b"\x2e\x20\3"), comm.events)
        self.assertEqual(ctx.native_memory.read(pointer, len(history)), history)
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])
        comm.events.clear()
        ctx.native_memory = NativeMemoryArena(ctx.module_sha256, object())
        with self.assertRaisesRegex(ValueError, "source/owner"):
            engine().run_body("Ex24WD_05_WriteHistoryData", (data,), ctx)
        self.assertFalse(any(event[0] == "initialize" for event in comm.events))

    def test_4wd05_history_truncation_and_stale_pointer_never_cross_allocation(self):
        for freed in (False, True):
            comm = Comm()
            ctx = Context(comm)
            ctx.native_memory = NativeMemoryArena(ctx.module_sha256, ctx)
            pointer = ctx.native_memory.alloc(4)
            ctx.native_memory.write(pointer, b"\x20\2\2\0")
            if freed:
                ctx.native_memory.free(pointer)
            data = bytearray(0x56)
            struct.pack_into("<IH", data, 0x50, pointer, 6)
            with self.assertRaises(ValueError):
                engine().run_body("Ex24WD_05_WriteHistoryData", (data,), ctx)
            self.assertFalse(any(event[0] == "exchange" for event in comm.events))
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_4wd05_all_native_start_and_poll_branches_retain_or_restore(self):
        for action in range(8):
            data = bytearray(0x56)
            struct.pack_into("<I", data, 4, action)
            struct.pack_into("<I", data, 0x3C, 1)
            low = 2 if action in (0, 1) else 3 if action in (4, 5) else 5
            start = action in (0, 2, 4, 6)
            index = 5 if action == 3 else 7 if action == 7 else 4
            reply = bytes((0x71, 1 if start else 3, 0x11, low))
            if not start:
                reply += bytes(index - 4) + b"\2"
            comm = Comm([(0, reply)])
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body("Ex24WD_05_SendMessage", (data,), ctx),
                6022 if start else 0,
            )
            self.assertNotIn(("finalize",), comm.events)
            if start:
                expected = bytes((0x31, 1, 0x11, low)) + (
                    bytes((1 if action == 2 else 2,)) if action in (2, 6) else b""
                )
                self.assertIn(("exchange", expected), comm.events)
            else:
                self.assertEqual(ctx.sleeps, [200])
        data = bytearray(0x56)
        data[1] = 1
        comm = Comm(initial=7)
        self.assertEqual(
            engine().run_body("Ex24WD_05_SendMessage", (data,), Context(comm)), 7
        )
        self.assertEqual(data[1:3], b"\0\1")
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_4wd05_write_values_history_dtc_gate_and_native_readback(self):
        data = bytearray(0x56)
        data[0] = 4
        struct.pack_into("<I", data, 4, 8)
        data[8:24] = b"A" * 16
        data[28:44] = b"B" * 16
        struct.pack_into("<I", data, 0x2C, 1)
        struct.pack_into("<I", data, 0x38, 1)
        comm = Comm(
            [
                (0, b"\x6e\x20\2"),
                (0, b"\x6e\x20\3"),
                (7, b""),
                (0, b"\xeb\1"),
                (0, b"\x62\x20\2" + b"C" * 16),
                (0, b"\x62\x20\3" + b"D" * 16),
            ]
        )
        ctx = Context(comm)
        ctx.native_memory = NativeMemoryArena(ctx.module_sha256, ctx)
        pointer = ctx.native_memory.alloc(5)
        ctx.native_memory.write(pointer, b"\x12\x34\1\0x")
        struct.pack_into("<IH", data, 0x50, pointer, 5)
        self.assertEqual(engine().run_body("Ex24WD_05_SendMessage", (data,), ctx), 8008)
        self.assertEqual((data[8:24], data[28:44]), (b"C" * 16, b"D" * 16))
        self.assertIn(("exchange", b"\x2e\x12\x34x"), comm.events)
        self.assertEqual(ctx.sleeps, [1000])
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])
        struct.pack_into("<I", data, 4, 10)
        data[0] = 0
        comm = Comm([(0, b"\x6e\x20\2"), (0, b"\x6e\x20\3"), (0, b"\xeb\1\x26\x18")])
        self.assertEqual(
            engine().run_body("Ex24WD_05_SendMessage", (data,), Context(comm)), 2223
        )
        self.assertIn(("exchange", b"\x2e\x20\3" + b"\xff" * 15 + b"\xf7"), comm.events)

    def test_twelve_asus10_fixed_did_single_byte_and_rejects_extra_write_byte(self):
        selected = ChassisEngine(
            replace(
                CONTRACT_12,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
            )
        )
        data = bytearray(1)
        self.assertTrue(
            supports(SHA_12_TY, "Ex2ASUS_10_GetStatOfHeightCtrlProhibition")
        )
        comm = Comm([(0, b"\x62\x21\1\1")])
        self.assertEqual(
            selected.run_body(
                "Ex2ASUS_10_GetStatOfHeightCtrlProhibition", (data,), Context(comm)
            ),
            0,
        )
        self.assertEqual(data, b"\1")
        self.assertEqual(
            [event[1] for event in comm.events if event[0] == "exchange"],
            [b"\x22\x21\1"],
        )
        self.assertTrue(
            supports(SHA_12_TY, "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition")
        )
        comm = Comm([(0, b"\x6e\x21\1\xaa")], sessions=[0, 0, 0])
        ctx = Context(comm)
        data = bytearray((1,))
        self.assertEqual(
            selected.run_body(
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition", (data,), ctx
            ),
            3,
        )
        self.assertEqual(data, b"\1")
        self.assertIn(("exchange", b"\x2e\x21\1\0"), comm.events)
        self.assertEqual(ctx.sleeps, [])
        self.assertEqual(
            [event for event in comm.events if event[0] == "exchange"],
            [("exchange", b"\x2e\x21\1\0")],
        )
        self.assertEqual(
            [event for event in comm.events if event[0] == "session"],
            [("session", 1, 1), ("session", 3, 1), ("session", 1, 1)],
        )
        comm = Comm([(7, b"")], sessions=[0, 0, 9])
        self.assertEqual(
            selected.run_body(
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
                (data,),
                Context(comm),
            ),
            9,
        )

    def test_twelve_asus08_compressor_and_tank_have_own_no_retry_sequence(self):
        selected = ChassisEngine(
            replace(
                CONTRACT_12,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
            )
        )
        start, done = (0, b"\x71\1\x11\1"), (0, b"\x71\3\x11\1\2")
        for suffix in ("StartCompressRaisingCtrl", "StartTankPressLowCtrl"):
            export = "Ex2ASUS_08_" + suffix
            self.assertTrue(supports(SHA_12_TY, export))
            replies = [start, done, (0, b"\x62\x10\7\7\0")]
            tank = suffix == "StartTankPressLowCtrl"
            if tank:
                replies = [(0, b"\x6e\x21\1"), start, done] + replies
            comm = Comm(replies)
            ctx = Context(comm)
            ctx.state["native:100ba458"] = 1
            data = bytearray(20)
            self.assertEqual(selected.run_body(export, (data,), ctx), 0)
            self.assertEqual(data[4], 1)
            self.assertEqual(ctx.sleeps, [100, 30000, 100] if tank else [100])
            self.assertNotIn(("configure", "native_rva:129d0", 0), comm.events)
            self.assertEqual(("finalize",) in comm.events, tank)
            if tank:
                self.assertEqual(ctx.state["native:100ba458"], 0)
        comm = Comm([(0, b"\x6e\x21\1"), start, (0, b"\x71\3\x11\1\1"), (7, b"")])
        ctx = Context(comm)
        ctx.state["native:100ba458"] = 1
        base_exchange = comm.exchange

        def elapsed(request):
            if request == b"\x31\3\x11\1":
                ctx.tick += 40000
            return base_exchange(request)

        comm.exchange = elapsed
        self.assertEqual(
            selected.run_body(
                "Ex2ASUS_08_StartTankPressLowCtrl", (bytearray(20),), ctx
            ),
            1001,
        )
        self.assertEqual(ctx.sleeps, [100])
        self.assertEqual(comm.events.count(("exchange", b"\x31\1\x11\1\x0f\4\x40")), 1)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_eighteen_asus08_mode_entry_uses_native_extended_session(self):
        comm = Comm([(0, b"\x6e\x21\1")])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit", (bytearray(4),), ctx
            ),
            0,
        )
        self.assertEqual(
            [event for event in comm.events if event[0] == "session"],
            [("session", 1, 1), ("session", 3, 1)],
        )

    def test_twelve_asus08_actual_global_and_two_setter_extended_entry(self):
        selected = ChassisEngine(
            replace(
                CONTRACT_12,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
            )
        )
        self.assertTrue(
            supports(SHA_12_TY, "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit")
        )
        comm = Comm([(0, b"\x6e\x21\1")])
        ctx = Context(comm)
        data = bytearray(20)
        self.assertEqual(
            selected.run_body(
                "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit", (data,), ctx
            ),
            0,
        )
        self.assertEqual(ctx.state, {"native:100ba458": 1})
        self.assertIn(("session", 3, 1), comm.events)
        self.assertNotIn(("configure", "native_rva:129d0", 0), comm.events)
        self.assertNotIn(("finalize",), comm.events)
        self.assertTrue(supports(SHA_12_TY, "Ex2ASUS_08_ReadPressureSensor"))
        comm.replies = [(0, b"\x62\x10\7\x08\x9d")]
        comm.events.clear()
        self.assertEqual(
            selected.run_body("Ex2ASUS_08_ReadPressureSensor", (data,), ctx), 0
        )
        self.assertEqual(struct.unpack_from("<I", data, 16)[0], 1004)
        self.assertEqual(comm.events, [("exchange", b"\x22\x10\7")])
        ctx.state.clear()
        comm.events.clear()
        comm.replies = [(0, b"\x62\x10\7\0\0")]
        self.assertEqual(
            selected.run_body("Ex2ASUS_08_ReadPressureSensor", (data,), ctx), 0
        )
        self.assertEqual(struct.unpack_from("<I", data, 16)[0], 1002)
        self.assertIn(("configure", "native_rva:12980", 180000), comm.events)
        self.assertNotIn(("configure", "native_rva:129d0", 0), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_twelve_ars_legacy_target_restore_filters_clear_and_config_order(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        for group, names in (
            (1, ("ReadDTCofVGRS", "ReadDTCofARS", "ClearOffSetValue")),
            (2, ("ChkVGRSDtc", "ChkARSDtc", "ClrCompVal")),
        ):
            for name in names:
                export = f"Ex2ARS_0{group}_" + name
                self.assertTrue(supports(SHA_12_TY, export))
                clearing = name in ("ClearOffSetValue", "ClrCompVal")
                comm = Comm(
                    [(0, b"\x50"), (0, b"\xe6"), (0, b"\x54")] if clearing else []
                )
                comm.dtcs = (0, b"\x53\1\0\1")
                ctx = Context(comm)
                self.assertEqual(
                    selected.run_body(export, (bytearray(),), ctx),
                    0 if clearing else 1000 if group == 1 else -0x6FFFFFFF,
                )
                if "VGRS" in name:
                    self.assertEqual(
                        comm.events[-2:], [("finalize",), ("select_target", 0x700, 0)]
                    )
                else:
                    self.assertEqual(comm.events[-1], ("finalize",))
                configured = comm.events.index(("configure", "native_rva:b940", 150))
                initialized = comm.events.index(("initialize", 0))
                self.assertEqual(configured < initialized, group == 1)
                if clearing:
                    self.assertEqual(ctx.sleeps, [500, 500])
                    self.assertIn(("exchange", b"\x10\x40"), comm.events)
                    self.assertIn(("exchange", b"\xa6\1"), comm.events)
                    self.assertIn(("exchange", b"\x14"), comm.events)

    def test_twelve_asus05_all_native_action_payloads_read_flags_and_cancel(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        for suffix, replies in (
            ("ModifyVheightDownStart", [(0, b"\x50"), (0, b"\x70\6")]),
            ("ModifyVheightStop", [(0, b"\x70\6"), (0, b"\x50")]),
            ("ModifyVheightTimeOver", [(0, b"\x50")]),
            ("ReturnVheightStart", [(0, b"\x70")]),
            ("CheckModifiedVheight", [(0, b"\x61\x10\0")]),
            ("CheckReturnedVheight", [(0, b"\x61\x10\0")]),
            (
                "LearnKneelDownVheight",
                [(0, b"\x7b\x17"), (0, b"\x7b\7"), (0, b"\x61\x10\x10"), (0, b"\x50")],
            ),
        ):
            export = "Ex2ASUS_05_" + suffix
            self.assertTrue(supports(SHA_12_TY, export))
            data = bytearray(14)
            struct.pack_into("<III", data, 0, 2, 3, 4)
            comm = Comm(replies)
            ctx = Context(comm)
            self.assertEqual(
                selected.run_body(
                    export,
                    (data,)
                    if suffix not in ("ModifyVheightTimeOver", "ReturnVheightStart")
                    else (bytearray(),),
                    ctx,
                ),
                0,
            )
            self.assertIn(("configure", "native_rva:b940", 150), comm.events)
            if suffix == "ModifyVheightDownStart":
                self.assertIn(("exchange", b"\x30\6\x19\1"), comm.events)
            if suffix == "LearnKneelDownVheight":
                self.assertEqual(ctx.sleeps, [500, 500])
                self.assertEqual(data[12], 16)
        data = bytearray(14)
        data[13] = 1
        comm = Comm()
        self.assertEqual(
            selected.run_body(
                "Ex2ASUS_05_CheckModifiedVheight", (data,), Context(comm)
            ),
            1000,
        )
        self.assertFalse(any(event[0] == "exchange" for event in comm.events))

    def test_twelve_asus04_support_learning_return_and_timed_readback(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        first_offsets = [0x1020] * 256
        first_offsets[16] = 0
        second_offsets = [0x1020] * 256
        second_offsets[6] = 0
        for group in (4, 5):
            export = f"Ex2ASUS_0{group}_SupportCheck"
            self.assertTrue(supports(SHA_12_TY, export))
            comm = Comm(
                snapshots=[
                    (0, b"\x10\3\0\0\x30".ljust(0x1020, b"\0"), tuple(first_offsets)),
                    (0, b"\6\1\1".ljust(0x1020, b"\0"), tuple(second_offsets)),
                ]
            )
            data = bytearray(12)
            self.assertEqual(selected.run_body(export, (data,), Context(comm)), 0)
            self.assertIn(("configure", "native_rva:b940", 150), comm.events)
        data = bytearray(13)
        struct.pack_into("<II", data, 0, 2, 3)
        export = "Ex2ASUS_04_LearnKneeldownVheight"
        self.assertTrue(supports(SHA_12_TY, export))
        comm = Comm(
            [
                (0, b"\x50"),
                (0, b"\x7b\x17"),
                (0, b"\x7b\7"),
                (0, b"\x50"),
                (0, b"\x61\x10\x10"),
            ]
        )
        self.assertEqual(selected.run_body(export, (data,), Context(comm)), 0)
        self.assertEqual(data[12], 16)
        self.assertTrue(supports(SHA_12_TY, "Ex2ASUS_04_ReturnVhight"))
        comm = Comm([(0, b"\x70")])
        self.assertEqual(
            selected.run_body("Ex2ASUS_04_ReturnVhight", (bytearray(),), Context(comm)),
            0,
        )
        self.assertTrue(supports(SHA_12_TY, "Ex2ASUS_04_CheckReturnedVhight"))
        comm = Comm([(0, b"\x61\x10\x20"), (0, b"\x61\x10\0")])
        ctx = Context(comm)
        self.assertEqual(
            selected.run_body("Ex2ASUS_04_CheckReturnedVhight", (data,), ctx), 0
        )
        self.assertEqual(ctx.sleeps, [1000, 1000])

    def test_twelve_bsm_testmode_exact_side_mask_status_output_and_exit(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        data = bytearray(9)
        struct.pack_into("<II", data, 0, 3, 1)
        offsets = [0x1020] * 256
        offsets[0x69] = 0
        comm = Comm(snapshots=[(0, b"\x69\1\x30".ljust(0x1020, b"\0"), tuple(offsets))])
        self.assertTrue(supports(SHA_12_TY, "Ex2BSM_01_02_SupportCheck"))
        self.assertEqual(
            selected.run_body("Ex2BSM_01_02_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(
            comm.events[:3],
            [
                ("initialize", 0),
                ("configure", "native_rva:b940", 256),
                ("configure", "native_rva:b960", 256),
            ],
        )
        self.assertTrue(supports(SHA_12_TY, "Ex2BSM_01_02_Mov2TestMode"))
        comm = Comm([(0, b"\x50"), (0, b"\x61\x69\x30")])
        self.assertEqual(
            selected.run_body("Ex2BSM_01_02_Mov2TestMode", (data,), Context(comm)), 0
        )
        self.assertEqual(data[8], 3)
        self.assertTrue(supports(SHA_12_TY, "Ex2BSM_01_02_ChkStilInTestMode"))
        comm = Comm([(0, b"\x50\x61")])
        self.assertEqual(
            selected.run_body("Ex2BSM_01_02_ChkStilInTestMode", (data,), Context(comm)),
            -0x6FFFFFFE,
        )
        self.assertFalse(any(event == ("exchange", b"\x10\1") for event in comm.events))
        self.assertTrue(supports(SHA_12_TY, "Ex2BSM_01_02_ExitTestMode"))
        comm = Comm([(0, b"\x50")])
        self.assertEqual(
            selected.run_body("Ex2BSM_01_02_ExitTestMode", (), Context(comm)), 0
        )

    def test_twelve_bsm_history_distinct_busy_setter_and_fault_output(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        data = bytearray(12)
        struct.pack_into("<I", data, 0, 3)
        self.assertTrue(supports(SHA_12_TY, "Ex2BSM_07_08_GetAbnormalHistory"))
        comm = Comm([(7, b"\x61\x6c\xab")])
        self.assertEqual(
            selected.run_body(
                "Ex2BSM_07_08_GetAbnormalHistory", (data,), Context(comm)
            ),
            7,
        )
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 0xAB)
        self.assertEqual(
            comm.events[:3],
            [
                ("initialize", 0),
                ("configure", "native_rva:b940", 256),
                ("configure", "native_rva:b960", 256),
            ],
        )
        self.assertTrue(supports(SHA_12_TY, "Ex2BSM_07_08_ClearAbnormalHistory"))
        comm = Comm([(0, b"\x7b\x6c"), (7, b"\x61\x6c\x12")])
        self.assertEqual(
            selected.run_body(
                "Ex2BSM_07_08_ClearAbnormalHistory", (data,), Context(comm)
            ),
            2000,
        )
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 0x12)
        self.assertTrue(supports(SHA_12_TY, "Ex2BSM_07_08_SupportCheck"))
        offsets = [0x1020] * 256
        offsets[0x6C] = 0
        raw = b"\x6c\1\xf8".ljust(0x1020, b"\0")
        comm = Comm(snapshots=[(0, raw, tuple(offsets))] * 2)
        self.assertEqual(
            selected.run_body("Ex2BSM_07_08_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(struct.unpack_from("<II", data), (3, 3))

    def test_twelve_vgrs_support_filtered_dtcs_and_plain_check_init_order(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        offsets = [0x1020] * 256
        offsets[2] = 0
        data = bytearray(4)
        comm = Comm(
            snapshots=[(0, b"\2\3\xff\0\1".ljust(0x1020, b"\0"), tuple(offsets))]
        )
        comm.dtcs = (0, b"\x53\1\x55\x91")
        self.assertTrue(supports(SHA_12_TY, "Ex2VGRS_04_SupportCheck"))
        self.assertEqual(
            selected.run_body("Ex2VGRS_04_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(int.from_bytes(data, "little"), 5)
        self.assertEqual(
            comm.events[:2], [("initialize", 0), ("configure", "native_rva:b940", 150)]
        )
        self.assertTrue(supports(SHA_12_TY, "Ex2VGRS_04_CheckDTC"))
        comm.events.clear()
        self.assertEqual(
            selected.run_body("Ex2VGRS_04_CheckDTC", (bytearray(),), Context(comm)),
            10000,
        )
        self.assertEqual(
            comm.events[:2], [("configure", "native_rva:b940", 150), ("initialize", 0)]
        )

    def test_bsm_old_support_preserves_native_stale_payload_flag_on_fault(self):
        data = bytearray(26)
        struct.pack_into("<I", data, 0, 3)
        struct.pack_into("<I", data, 16, 0x11FE)
        first = bytearray(11)
        first[10] = 8
        comm = AHCComm(
            [
                (0, b"\x62\x20\0" + bytes(first)),
                (0, b"\x62\x20\x55\1"),
                (0, b"\x62\x10\0" + bytes(12)),
                (0, b"\x7e\0"),
                (0, b"\x62\2\4\x20"),
                (0, b"\x62\x10\0\x30"),
                (7, b""),
            ]
        )
        self.assertEqual(
            engine().run_body("Ex2BSM_09_10_19_20_SendMessage", (data,), Context(comm)),
            7,
        )
        self.assertEqual(data[22], 1)
        self.assertEqual(comm.events.count(("finalize",)), 2)

    def test_bsm_multi_positive_support_scans_actual_channels_and_retains_flags(self):
        def did(identifier, size, offset, value):
            payload = bytearray(size)
            payload[offset] = value
            return 0, b"\x62" + identifier.to_bytes(2, "big") + bytes(payload)

        for older, export in (
            (True, "Ex2BSM_09_10_19_20_SendMessage"),
            (False, "Ex2BSM_11_12_21_22_SendMessage"),
        ):
            data = bytearray(26)
            struct.pack_into("<I", data, 0, 3)
            struct.pack_into("<I", data, 16, 0x11FE if older else 0x1200)
            replies = [] if older else [did(0x0101, 5, 4, 128)]
            replies += [did(0x2000, 11, 10, 8), did(0x2055, 1, 0, 1)]
            if older:
                replies += [did(0x1000, 12, 11, 1)]
            replies += [
                (0, b"\x7e\0"),
                did(0x0204, 1, 0, 32),
                did(0x1000, 1, 0, 16),
                did(0x2000, 1, 0, 32),
            ]
            for _ in range(3):
                replies += [
                    (0, b"\x7e\0"),
                    did(0x0101, 5, 4, 128),
                    did(0x2000, 11, 10, 8),
                    did(0x2055, 1, 0, 1),
                ]
            comm = AHCComm(replies)
            self.assertEqual(engine().run_body(export, (data,), Context(comm)), 0)
            self.assertEqual(data[23:26] if older else data[22:25], b"\x42\x81\x82")
            self.assertEqual(data[22 if older else 21], 1)
            self.assertEqual(data[7 if older else 8], 1)
            if older:
                self.assertEqual(data[21], 1)
            self.assertEqual(comm.events.count(("finalize",)), 5)
            self.assertEqual(
                [event[2] for event in comm.events if event[0] == "configure_target"],
                [15, 66, 129, 130],
            )

    def test_bsm_multi_selected_toggle_failure_rolls_back_all_selected_ecus(self):
        for older, export in (
            (True, "Ex2BSM_09_10_19_20_SendMessage"),
            (False, "Ex2BSM_11_12_21_22_SendMessage"),
        ):
            data = bytearray(26)
            struct.pack_into("<I", data, 0, 4)
            struct.pack_into("<I", data, 16, 0x11FE if older else 0x1200)
            offset = 23 if older else 22
            data[offset : offset + 2] = b"\x41\x42"
            comm = AHCComm(
                [
                    (0, b"\x62\x20\x55\0\1"),
                    (7, b""),
                    (0, b"\x62\x20\x55\0\1"),
                    (0, b"\x6e\x20\x55"),
                    (0, b"\x62\x20\x55\0\0"),
                    (0, b"\x62\x20\x55\0\0"),
                ]
            )
            self.assertEqual(
                engine().run_body(export, (data,), Context(comm)),
                1005 if older else 2005,
            )
            self.assertEqual(
                [event[2] for event in comm.events if event[0] == "configure_target"],
                [65, 66, 65, 66],
            )
            self.assertEqual(comm.events.count(("finalize",)), 4)
            self.assertIn(("exchange", b"\x2e\x20\x55\0\0"), comm.events)
            self.assertFalse(
                any(
                    event[0] == "exchange" and event[1].startswith(b"\x31")
                    for event in comm.events
                )
            )

    def test_bsm_multi_all_native_actions_retention_and_live_cancellation(self):
        for older, export, low in (
            (True, "Ex2BSM_09_10_19_20_SendMessage", 2),
            (False, "Ex2BSM_11_12_21_22_SendMessage", 1),
        ):
            for action in range(8):
                data = bytearray(26)
                struct.pack_into("<I", data, 0, action)
                struct.pack_into("<I", data, 12, 2)
                struct.pack_into("<I", data, 16, 0x11FE if older else 0x1200)
                data[4] = 1
                data[5] = int(action == 0)
                phase = 1 if action in (0, 4) else 2
                replies = (
                    [(0, bytes((0x71, phase, 0x11, low)))]
                    if action in (0, 4, 5, 1 if older else 2)
                    else []
                )
                if action == 3:
                    replies = [(0, b"\x62\x20\0\0")] if older else [(0, b"\x62\1\1\0")]
                comm = AHCComm(replies)
                self.assertEqual(
                    engine().run_body(export, (data,), Context(comm)),
                    2206 if older and action == 0 else 0,
                    (older, action),
                )
                self.assertEqual(comm.replies, [], (older, action))
                self.assertEqual(
                    ("finalize",) in comm.events,
                    action in (3, 5, 1 if older else 2),
                    (older, action),
                )
                if action == 6:
                    self.assertEqual(data[8 if older else 9], 1)
                if action == 4:
                    self.assertIn(
                        ("exchange", bytes((0x31, 1, 0x11, low, 10, 0, 0))), comm.events
                    )
                    self.assertIn(("configure_target", 0x750, 65, 0, 0, 0), comm.events)

    def test_bsm_multi_global_and_ecu_toggle_preserves_payload_and_selected_start(self):
        data = bytearray(26)
        struct.pack_into("<I", data, 0, 4)
        struct.pack_into("<I", data, 16, 0x11FE)
        data[22:24] = b"\1\x41"
        replies = [
            (0, b"\x62\2\4\xab\0\xcd"),
            (0, b"\x6e\2\4"),
            (0, b"\x62\2\4\xab\x20\xcd"),
            (0, b"\x62\x20\x55\xaa\0"),
            (0, b"\x6e\x20\x55"),
            (0, b"\x62\x20\x55\xaa\1"),
            (0, b"\x71\1\x11\2"),
        ]
        comm = AHCComm(replies)
        self.assertEqual(
            engine().run_body("Ex2BSM_09_10_19_20_SendMessage", (data,), Context(comm)),
            0,
        )
        self.assertIn(("exchange", b"\x2e\2\4\xab\x20\xcd"), comm.events)
        self.assertIn(("exchange", b"\x2e\x20\x55\xaa\1"), comm.events)
        self.assertEqual(comm.events.count(("finalize",)), 2)
        self.assertNotEqual(comm.events[-1], ("finalize",))

    def test_bsm_multi_ordinary_and_extended_results_and_error_length(self):
        for older, export, low in (
            (True, "Ex2BSM_09_10_19_20_SendMessage", 2),
            (False, "Ex2BSM_11_12_21_22_SendMessage", 1),
        ):
            data = bytearray(26)
            struct.pack_into("<I", data, 0, 2 if older else 1)
            replies = [(0, bytes((0x71, 3, 0x11, low, 2))), (0, b"\x62\x10\x61\0\1")]
            replies += (
                [(0, b"\x62\x20\x52\0\1")]
                if older
                else [(0, b"\x62\x10\x60\0\0\x12\x34")]
            )
            comm = AHCComm(replies)
            self.assertEqual(
                engine().run_body(export, (data,), Context(comm)),
                2203 if older else 2003,
            )
            self.assertEqual(data[5], 1)
            if not older:
                self.assertEqual(data[6:8], b"\x34\x12")
            struct.pack_into("<I", data, 0, 6)
            data[5] = 0
            data[21] = int(older)
            replies = [(0, bytes((0x71, 3, 0x11, low, 2))), (0, b"\x62\x10\x61\0\1")]
            replies += (
                [(0, b"\x62\x20\x52\0\1"), (0, b"\x62\x10\x60" + bytes(8) + b"\xaa")]
                if older
                else [(0, b"\x62\x10\x60\0\0\x12\x34")]
            )
            comm = AHCComm(replies)
            self.assertEqual(engine().run_body(export, (data,), Context(comm)), 0)
            self.assertEqual(comm.events[-1], ("finalize",))
            if older:
                self.assertEqual(data[20], 0xAA)
            struct.pack_into("<I", data, 0, 0)
            comm = AHCComm([(7, b"")])
            self.assertEqual(
                engine().run_body(export, (data,), Context(comm)),
                2205 if older else 2005,
            )
            self.assertEqual(data[5], 1)

    def test_plus_abs33_and47_full_mode22_secondary_dispatch(self):
        class PlusContext(Context):
            def comm(self, kind):
                self.controller.events.append(("manager", kind))
                return self.controller

        selected = ChassisEngine(
            replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        )
        for mode in (20, 21, 22):
            for export, result in (
                ("Ex2ABS_33_ShiftNormalMode", 0),
                ("Ex2ABS_47_EndExtendedSession", 0),
                ("Ex2ABS_47_ErrorEndExtendedSession", 3),
                ("Ex2ABS_47_ExitEndExtendedSession", 1002),
            ):
                self.assertTrue(supports(SHA_PLUS_TY, export))
                comm = Comm([(7, b"")] if "ABS_33" in export else [], sessions=[9])
                ctx = PlusContext(comm)
                ctx.mode = mode
                self.assertEqual(selected.run_body(export, (bytearray(),), ctx), result)
                self.assertEqual(
                    comm.events[0],
                    ("manager", "native:1013e7d0" if mode == 22 else "native:101392d0"),
                )
                self.assertEqual(comm.events[-1], ("finalize",))
                if "ABS_33" in export:
                    self.assertIn(("exchange", b"\x31\1\x11\x0c\0"), comm.events)

    def test_ahc04_dual_init_and_start_fault_cleanup_and_poll_status_publication(self):
        data = bytearray(0x104D)
        struct.pack_into("<I", data, 0, 6)
        primary, secondary = AHCComm(), AHCComm(initial=7)
        self.assertEqual(
            engine().run_body(
                "Ex2AHC_04_SendMessage", (data,), AHCContext(primary, secondary)
            ),
            7,
        )
        self.assertEqual(secondary.events[-1], ("finalize",))
        self.assertFalse(any(e[0] == "session" for e in secondary.events))
        self.assertEqual(primary.events[-2:], [("session", 1, 1), ("finalize",)])
        primary = AHCComm([(9, b"")])
        secondary = AHCComm([(0, b"\x71\1\x11\xa2"), (0, b"\x71\2\x11\xa2")])
        self.assertEqual(
            engine().run_body(
                "Ex2AHC_04_SendMessage", (data,), AHCContext(primary, secondary)
            ),
            9,
        )
        self.assertIn(("exchange", b"\x31\2\x11\xa2"), secondary.events)
        self.assertIn(("finalize",), primary.events)
        self.assertIn(("finalize",), secondary.events)
        struct.pack_into("<I", data, 0, 4)
        primary = AHCComm([(0, b"\x71\3\x11\xa2\2"), (7, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2AHC_04_SendMessage", (data,), AHCContext(primary, AHCComm())
            ),
            0,
        )
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 2001)
        self.assertNotIn(("finalize",), primary.events)
        for action, low, expected, duration in (
            (15, 0xA8, 2002, 35000),
            (17, 0xA2, 3, 25000),
        ):
            struct.pack_into("<I", data, 0, action)
            primary = AHCComm([(0, bytes((0x71, 3, 0x11, low, 1)))])
            ctx = AHCContext(primary, AHCComm())
            base_exchange = primary.exchange

            def delayed(request, _ctx=ctx, _duration=duration, _exchange=base_exchange):
                _ctx.tick += _duration
                return _exchange(request)

            primary.exchange = delayed
            self.assertEqual(
                engine().run_body("Ex2AHC_04_SendMessage", (data,), ctx), expected
            )
            self.assertEqual(struct.unpack_from("<I", data, 8)[0], 1028)
            self.assertNotIn(("finalize",), primary.events)
        struct.pack_into("<I", data, 0, 15)
        struct.pack_into("<I", data, 4, 3)
        primary = AHCComm([(7, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2AHC_04_SendMessage", (data,), AHCContext(primary, AHCComm())
            ),
            0,
        )
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 1030)

    def test_ahc04_all_native_actions_manager_retention_and_saved_status(self):
        start = (0, b"\x71\1\x11\xa2")
        stop = (0, b"\x71\2\x11\xa2")
        done = (0, b"\x71\3\x11\xa2\2")
        for action in range(19):
            data = bytearray(0x104D)
            struct.pack_into("<I", data, 0, action)
            struct.pack_into("<I", data, 8, 55)
            struct.pack_into("<I", data, 20, 2)
            data[24:26] = b"\0\xaa"
            replies = {
                0: [(0, b"\x62\x21\1\0\xaa"), (0, b"\x6e\x21\1")],
                1: [(0, b"\x6e\x21\1")],
                2: [start],
                3: [stop],
                4: [done, start, done],
                5: [],
                6: [start],
                7: [stop],
                8: [],
                9: [done],
                10: [],
                11: [(0, b"\x71\1\x11\xa8")],
                12: [(0, b"\x71\1\x11\xa8")],
                13: [(0, b"\x71\2\x11\xa8")],
                14: [(7, b"")],
                15: [(0, b"\x71\3\x11\xa8\2")],
                16: [start],
                17: [done],
                18: [(7, b"")],
            }[action]
            secondary_replies = {
                6: [start],
                7: [stop],
                8: [stop],
                9: [done, start, done],
                18: [(9, b"")],
            }.get(action, [])
            primary, secondary = AHCComm(replies), AHCComm(secondary_replies)
            expected = (
                55 if action in (3, 5, 7, 8, 10, 13) else 1013 if action == 14 else 0
            )
            self.assertEqual(
                engine().run_body(
                    "Ex2AHC_04_SendMessage", (data,), AHCContext(primary, secondary)
                ),
                expected,
                action,
            )
            self.assertEqual(primary.replies, [], action)
            self.assertEqual(secondary.replies, [], action)
            self.assertEqual(
                ("finalize",) in primary.events,
                action in (0, 1, 3, 5, 7, 8, 10, 13),
                action,
            )
            self.assertEqual(
                ("finalize",) in secondary.events, action in (7, 8, 10), action
            )
            if action == 0:
                self.assertEqual(data[24:26], b"\1\xaa")
                self.assertIn(("exchange", b"\x2e\x21\1\1\xaa"), primary.events)
            if action in (4, 9):
                self.assertEqual(struct.unpack_from("<I", data, 8)[0], 1008)
            if action == 6:
                self.assertIn(
                    ("configure_target", 0x750, 0x36, 0, 0, 0), primary.events
                )
                self.assertIn(
                    ("configure_target", 0x750, 0x3B, 0, 0, 0), secondary.events
                )
                self.assertIn(
                    (
                        "exchange",
                        b"\x31\1\x11\xa2\3" + b"\x0c\x40\0\x64" * 3 + bytes(8),
                    ),
                    secondary.events,
                )

    def test_twelve_asus_air_success_retains_and_session_fault_maps1000(self):
        selected = ChassisEngine(
            replace(
                CONTRACT_12,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
            )
        )
        data = bytearray(8)
        struct.pack_into("<I", data, 4, 2001)
        start, done = (0, b"\x71\1\x11\1"), (0, b"\x71\3\x11\1\2")
        for group, phases in ((6, [(2, 2, 0x82)]), (7, [(3, 2, 0x88), (12, 4, 0x91)])):
            export = f"Ex2ASUS_0{group}_AirPressure"
            self.assertTrue(supports(SHA_12_TY, export))
            comm = Comm([item for _ in phases for item in (start, done)])
            self.assertEqual(selected.run_body(export, (data,), Context(comm)), 0)
            self.assertNotIn(("finalize",), comm.events)
            for phase in phases:
                self.assertIn(("exchange", b"\x31\1\x11\1" + bytes(phase)), comm.events)
            comm = Comm(sessions=[7])
            self.assertEqual(selected.run_body(export, (data,), Context(comm)), 1000)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_twelve_asus_condition_retains_manager_and_tank_threshold_restores(self):
        selected = ChassisEngine(
            replace(
                CONTRACT_12,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
            )
        )
        for group in (6, 7):
            export = f"Ex2ASUS_0{group}_ConditionCheck"
            self.assertTrue(supports(SHA_12_TY, export))
            comm = Comm([(0, b"\x6e\x21\1")])
            self.assertEqual(
                selected.run_body(export, (bytearray(),), Context(comm)), 0
            )
            self.assertNotIn(("finalize",), comm.events)
            self.assertIn(("configure", "native_rva:12960", 0), comm.events)
            self.assertIn(("configure", "native_rva:12980", 180000), comm.events)
            export = f"Ex2ASUS_0{group}_TheHeightAndTank"
            self.assertTrue(supports(SHA_12_TY, export))
            comm = Comm(
                [
                    (0, b"\x6e\x21\1"),
                    (0, b"\x71\1\x11\1"),
                    (0, b"\x71\3\x11\1\2"),
                    (0, b"\x71\1\x11\1"),
                    (0, b"\x71\3\x11\1\2"),
                    (0, b"\x62\x10\7\6\xf3"),
                ]
            )
            ctx = Context(comm)
            self.assertEqual(selected.run_body(export, (bytearray(),), ctx), 1003)
            self.assertEqual(ctx.sleeps, [100, 30000, 100])
            self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_twelve_asus_lift_exact_single_and_dual_phase_motion(self):
        selected = ChassisEngine(
            replace(
                CONTRACT_12,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
            )
        )
        data = bytearray(8)
        struct.pack_into("<I", data, 4, 2001)
        start = (0, b"\x71\1\x11\1")
        done = (0, b"\x71\3\x11\1\2")
        for group, phases in ((6, [(2, 4, 0x8F)]), (7, [(12, 2, 0x8A), (3, 4, 0xA2)])):
            export = f"Ex2ASUS_0{group}_LiftRise"
            self.assertTrue(supports(SHA_12_TY, export))
            comm = Comm([item for _ in phases for item in (start, done)])
            ctx = Context(comm)
            self.assertEqual(selected.run_body(export, (data,), ctx), 0)
            for phase in phases:
                self.assertIn(("exchange", b"\x31\1\x11\1" + bytes(phase)), comm.events)
            self.assertEqual(ctx.sleeps, [100] * len(phases))
            self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])
        comm = Comm([start, (7, b""), (9, b"")], sessions=[8])
        self.assertEqual(
            selected.run_body("Ex2ASUS_06_LiftRise", (data,), Context(comm)), 7
        )
        self.assertIn(("exchange", b"\x31\2\x11\1"), comm.events)

    def test_4wd05_support_native_four_modes_and_missing_feature_status(self):
        def frame(prefix, length, values):
            reply = bytearray(length)
            reply[: len(prefix)] = prefix
            for offset, value in values.items():
                reply[offset] = value
            return 0, bytes(reply)

        for expected, feature, history, flags, first in (
            (1, 0, 255, (0x68, 0), 0x60),
            (2, 1, 1, (0x60, 0x80), 0x60),
            (4, 1, 2, (0x40, 0x80), 0x60),
            (1001, 1, 1, (0x60, 0x80), 0x40),
        ):
            data = bytearray(b"\xff" * 80)
            replies = [
                frame(b"\x62\1\1", 35, {5: 128, 7: 128}),
                frame(b"\x62\x20\0", 35, {3: first}),
                frame(b"\x71\1\x10\1", 36, {6: 64}),
                frame(b"\x71\1\x11\0", 36, {4: flags[0], 5: flags[1]}),
                frame(b"\x62\x10\0", 35, {6: feature * 64}),
            ]
            if feature:
                replies += [(0, b"\x62\x10\x1a" + bytes((history,)))]
            comm = Comm(replies)
            status = engine().run_body("Ex24WD_05_SupportCheck", (data,), Context(comm))
            self.assertEqual(status, 1001 if expected == 1001 else 0)
            self.assertEqual(
                struct.unpack_from("<I", data, 76)[0],
                0 if expected == 1001 else expected,
            )
            self.assertEqual(data[68], history)
            self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])
        data = bytearray(80)
        comm = Comm([frame(b"\x62\1\1", 35, {})], sessions=[0, 0, 9])
        self.assertEqual(
            engine().run_body("Ex24WD_05_SupportCheck", (data,), Context(comm)), 9
        )
        self.assertEqual(struct.unpack_from("<I", data, 76)[0], 3)
        data = bytearray(b"\xff" * 80)
        comm = Comm(initial=7)
        self.assertEqual(
            engine().run_body("Ex24WD_05_SupportCheck", (data,), Context(comm)), 7
        )
        self.assertEqual(data[52:68], bytes(16))
        self.assertEqual(data[76:80], bytes(4))

    def test_twelve_drs_stop_retains_distinct_error_length_precedence(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        for group, expected in ((2, 3), (3, 7)):
            export = f"Ex2DRS_0{group}_StopActiveTest"
            self.assertTrue(supports(SHA_12_TY, export))
            comm = Comm([(7, b"")])
            self.assertEqual(
                selected.run_body(export, (bytearray(),), Context(comm)), expected
            )
            self.assertEqual(
                comm.events,
                [
                    ("configure", "native_rva:b940", 150),
                    ("exchange", b"\x30"),
                    ("finalize",),
                ],
            )

    def test_twelve_asus04_modify_uses_own_legacy_setter_and_native_direction(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        data = bytearray(20)
        struct.pack_into("<I", data, 8, 4)
        struct.pack_into("<I", data, 16, 200)
        comm = Comm([(0, b"\x70\6")])
        self.assertTrue(supports(SHA_12_TY, "Ex2ASUS_04_ModifyVhight"))
        self.assertEqual(
            selected.run_body("Ex2ASUS_04_ModifyVhight", (data,), Context(comm)), 0
        )
        self.assertIn(("exchange", b"\x30\6\x14\1"), comm.events)
        self.assertIn(("configure", "native_rva:b940", 150), comm.events)
        comm = Comm(initial=7)
        self.assertEqual(
            selected.run_body("Ex2ASUS_04_ModifyVhight", (data,), Context(comm)), 7
        )
        self.assertEqual(comm.events, [("initialize", 0), ("finalize",)])

    def test_independently_reviewed_twelve_asus08_exit(self):
        selected = ChassisEngine(
            replace(
                CONTRACT_12,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
            )
        )
        self.assertTrue(supports(SHA_12_TY, "Ex2ASUS_08_EndExtendedSession"))
        for status, expected in ((0, 0), (7, 1000)):
            comm = Comm(sessions=[status])
            self.assertEqual(
                selected.run_body(
                    "Ex2ASUS_08_EndExtendedSession", (bytearray(),), Context(comm)
                ),
                expected,
            )
            self.assertEqual(comm.events, [("session", 1, 1), ("finalize",)])

    def test_4wd08_native_stability_selected_outputs_and_stop_fault_override(self):
        def control(first=3, status=0):
            return status, b"\x6f\x28\4" + bytes((first,)) + bytes(6)

        wheels = (0, b"\x62\x10\x14\0\x67\0\x67" + bytes(4))
        speed = (0, b"\x62\x10\x20\0\1")
        data = bytearray(56)
        comm = Comm(
            [control()]
            + [item for _ in range(26) for item in (wheels, speed)]
            + [control(0)]
        )
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex24WD_08_SendMessage", (data,), ctx), 0)
        self.assertEqual(struct.unpack_from("<I", data)[0], 1)
        self.assertEqual(ctx.sleeps, [20] * 26)
        self.assertIn(("finalize",), comm.events)
        self.assertIn(("exchange", b"\x2f\x28\4\3\0\0\0\0\1\xf4\xe0"), comm.events)
        data[48:52] = (3).to_bytes(4, "little")
        data[52:56] = (2).to_bytes(4, "little")
        comm = Comm([control(), (7, b""), control(0, 9)])
        self.assertEqual(
            engine().run_body("Ex24WD_08_SendMessage", (data,), Context(comm)), 9
        )
        self.assertNotIn(("initialize", 0), comm.events)
        data[48:52] = (2).to_bytes(4, "little")
        data[44] = 1
        comm = Comm([wheels])
        ctx = Context(comm)
        ctx.on_sleep = lambda _: data.__setitem__(44, 0)
        self.assertEqual(engine().run_body("Ex24WD_08_SendMessage", (data,), ctx), 0)
        self.assertEqual(data[36:44], wheels[1][3:])
        self.assertNotIn(("finalize",), comm.events)

    def test_4wd08_speed_state_transition_restarts_stability_and_fourth_action(self):
        response = (0, b"\x6f\x28\4\3" + bytes(6))
        stop = (0, b"\x6f\x28\4\0" + bytes(6))
        wheels = (0, b"\x62\x10\x14\0\x67\0\x67" + bytes(4))
        data = bytearray(56)
        replies = [response]
        for speed in [1] * 20 + [0] * 26:
            replies += [wheels, (0, b"\x62\x10\x20\0" + bytes((speed,)))]
        comm = Comm(replies + [stop])
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex24WD_08_SendMessage", (data,), ctx), 0)
        self.assertEqual(ctx.sleeps, [20] * 46)
        self.assertEqual(data[:4], bytes(4))
        data[48:52] = (4).to_bytes(4, "little")
        comm = Comm([response, (0, b"\x62\x10\x20\0\x67"), response, response, stop])
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex24WD_08_SendMessage", (data,), ctx), 0)
        self.assertEqual(ctx.sleeps, [20, 1000, 1000, 1000])
        self.assertIn(("exchange", b"\x2f\x28\4\3" + bytes(6) + b"\x80"), comm.events)

    def test_4wd06_native_selected_init_retention_live_poll_and_control_stages(self):
        data = bytearray(33)
        data[16] = 1
        comm = Comm([(0, b"\x62\x10\x24\0\xff")])
        self.assertEqual(
            engine().run_body("Ex24WD_06_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual((data[16], data[26]), (0, 192))
        self.assertNotIn(("finalize",), comm.events)
        data[12:16] = (2).to_bytes(4, "little")
        comm = Comm([(0, b"\x62\x10\x14abcdefgh")])
        ctx = Context(comm)
        ctx.on_sleep = lambda _: data.__setitem__(32, 1)
        self.assertEqual(engine().run_body("Ex24WD_06_SendMessage", (data,), ctx), 0)
        self.assertEqual(data[18:26], b"abcdefgh")

        def response(first):
            return (0, b"\x6f\x28\1" + bytes((first,)) + bytes(8))

        data[12:16] = (3).to_bytes(4, "little")
        comm = Comm(
            [response(3)]
            + [(0, b"\x62\x10\x24\0\0")] * 26
            + [response(0), (0, b"\x62\x10\x24\0\x40")]
        )
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex24WD_06_SendMessage", (data,), ctx), 0)
        self.assertEqual(data[26], 64)
        self.assertEqual(ctx.sleeps.count(20), 26)
        data[12:16] = (5).to_bytes(4, "little")
        replies = [response(3), (0, b"\x62\x10\x20\0\x67"), response(3)]
        replies += (
            [(0, b"\x62\x10\x24\0\x80")] * 26
            + [response(3)]
            + [(0, b"\x62\x10\x24\0\x40")] * 26
            + [response(0), (0, b"\x62\x10\x24\0\xc0")]
        )
        comm = Comm(replies)
        self.assertEqual(
            engine().run_body("Ex24WD_06_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(data[26], 192)
        self.assertIn(("exchange", b"\x2f\x28\1\3" + bytes(8) + b"\x80"), comm.events)
        comm = Comm(
            [
                response(3),
                (1046, b""),
                response(0),
                response(0),
                (0, b"\x62\x10\x24\0\0"),
            ]
        )
        self.assertEqual(
            engine().run_body("Ex24WD_06_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(comm.events.count(("exchange", b"\x2f\x28\1\0\xf0")), 2)
        data[16] = 1
        comm = Comm(initial=7)
        self.assertEqual(
            engine().run_body("Ex24WD_06_SendMessage", (data,), Context(comm)), 7
        )
        self.assertNotIn(("finalize",), comm.events)

    def test_twelve_vgrs_and_emps07_independent_classic_operations(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )
        data = bytearray(b"\4\0\0\0")
        comm = Comm([(0, b"\x50"), (0, b"\x70\2")])
        self.assertEqual(
            selected.run_body("Ex2VGRS_04_StartLockRelease", (data,), Context(comm)), 0
        )
        self.assertIn(("exchange", b"\x30\2\0\1"), comm.events)
        self.assertIn(("configure", "native_rva:b940", 150), comm.events)
        for suffix, replies, requests in (
            (
                "StartNeutralCompMode",
                [(0, b"\x54"), (0, b"\x50"), (0, b"\x50")],
                [b"\x14", b"\x10\x40", b"\x10\x60"],
            ),
            (
                "ClearDTC",
                [(0, b"\x50"), (0, b"\xe6"), (0, b"\x54")],
                [b"\x10\x40", b"\xa6\1", b"\x14"],
            ),
            ("EndNeutralCompMode", [(0, b"\x50")], [b"\x10\1"]),
            ("EndLockRelease", [(7, b""), (0, b"\x70")], [b"\x30", b"\x30"]),
        ):
            comm = Comm(replies)
            self.assertEqual(
                selected.run_body("Ex2VGRS_04_" + suffix, (), Context(comm)),
                3 if suffix == "EndLockRelease" else 0,
            )
            self.assertEqual(
                [e[1] for e in comm.events if e[0] == "exchange"], requests
            )
        comm = Comm([(7, b"\x7f\x3b\x22")])
        self.assertEqual(
            selected.run_body("Ex2EMPS_07_ClearTheAssistMap", (), Context(comm)), 1002
        )
        output = bytearray(2)
        comm = Comm([(0, b"\x53\0"), (0, b"\xe9\3\x34\x12")])
        self.assertEqual(
            selected.run_body(
                "Ex2EMPS_07_ConfirmTheAssistMap", (output,), Context(comm)
            ),
            0,
        )
        self.assertEqual(output, b"\x34\x12")
        for name in (
            "Ex2VGRS_04_StartLockRelease",
            "Ex2VGRS_04_EndLockRelease",
            "Ex2VGRS_04_StartNeutralCompMode",
            "Ex2VGRS_04_EndNeutralCompMode",
            "Ex2VGRS_04_ClearDTC",
            "Ex2EMPS_07_ConfirmTheAssistMap",
            "Ex2EMPS_07_ClearTheAssistMap",
        ):
            self.assertTrue(supports(SHA_12_TY, name))

    def test_tpw08_full_feature_support_and_retained_start_live_monitor(self):
        data = bytearray(28)
        comm = Comm(
            [
                (0, b"\x62\1\1\0\0\x80\0\x80"),
                (0, b"\x62\x20\0\x40"),
                (0, b"\x71\1\x10\1\0\0\x40"),
                (0, b"\x62\x10\0" + bytes(6) + b"\x70"),
                (0, b"\x71\1\x11\0\x40\1\0\1"),
                (0, b"\x62\x20\2\5"),
                (0, b"\x62\x10\x32\xf8\0"),
                (0, b"\x62\x10\x33\x80\0"),
                (0, b"\x62\x10\x34\x80\0"),
            ]
        )
        self.assertEqual(
            engine().run_body("Ex2TPW_08_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual((data[4], data[12]), (5, 7))
        for action, low in ((1, 2), (2, 32), (3, 16)):
            data[:4] = action.to_bytes(4, "little")
            comm = Comm([(0, bytes((0x71, 1, 17, low)))])
            self.assertEqual(
                engine().run_body("Ex2TPW_08_SendMessage", (data,), Context(comm)), 0
            )
            self.assertNotIn(("finalize",), comm.events)
        data[:4] = (4).to_bytes(4, "little")
        comm = Comm([(0, b"\x62\x10\x32\xff\x42")] * 2)
        ctx = Context(comm)
        ctx.on_sleep = lambda _: (
            data.__setitem__(slice(24, 28), (1).to_bytes(4, "little"))
            if ctx.tick == 1000
            else None
        )
        self.assertEqual(engine().run_body("Ex2TPW_08_SendMessage", (data,), ctx), 0)
        self.assertEqual((data[16], data[20]), (1, 0x42))
        self.assertEqual(ctx.sleeps, [500, 500])
        data[21] = 2
        comm = Comm([(7, b"")], sessions=[9])
        self.assertEqual(
            engine().run_body("Ex2TPW_08_SendMessage", (data,), Context(comm)), 7
        )
        self.assertIn(("configure", "native_rva:1a730", 1), comm.events)
        self.assertIn(("configure", "native_rva:1a730", 0), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_tpw06_support_field_offset_and_four_five_id_write_policy(self):
        data = bytearray(40)
        comm = Comm(
            [
                (0, b"\x62\1\1\0\0\x80\0\x80"),
                (0, b"\x62\x10\0\0\4\0\0\x3e"),
                (0, b"\x62\x20\0\x60"),
            ]
        )
        self.assertEqual(
            engine().run_body("Ex2TPW_06_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(int.from_bytes(data[24:28], "little"), 1)
        data[32:36] = (1).to_bytes(4, "little")
        comm = Comm([(0, b"\x62\x10\x0e\0"), (0, b"\x62\x20\2\5")])
        self.assertEqual(
            engine().run_body("Ex2TPW_06_SendMessage", (data,), Context(comm)), 1009
        )
        self.assertEqual(data[:2], b"\0\5")
        data[32:36] = (2).to_bytes(4, "little")
        comm = Comm(
            [
                (0, bytes((0x62, 0x10, identifier)) + bytes([identifier]) * 4)
                for identifier in range(0x23, 0x28)
            ]
        )
        self.assertEqual(
            engine().run_body("Ex2TPW_06_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(data[18:22], b"\x27" * 4)
        data[32:36] = (3).to_bytes(4, "little")
        data[1] = 4
        comm = Comm([(0, b"\x6e\x20\3")], sessions=[0, 0, 9])
        self.assertEqual(
            engine().run_body("Ex2TPW_06_SendMessage", (data,), Context(comm)), 0
        )
        self.assertIn(
            ("exchange", b"\x2e\x20\3\4" + data[2:18] + bytes(4)), comm.events
        )
        self.assertEqual(comm.events[-1], ("finalize",))
        data[32:36] = (0).to_bytes(4, "little")
        comm = Comm([(7, b"")], sessions=[0, 0, 9])
        self.assertEqual(
            engine().run_body("Ex2TPW_06_SendMessage", (data,), Context(comm)), 9
        )

    def test_tpw13_full_selector_read_write_masks_and_rollback(self):
        data = bytearray(36)
        data[:4] = (1).to_bytes(4, "little")
        comm = Comm([(0, b"\x62\x20\2\5"), (0, b"\x62\x20\x11\3")])
        self.assertEqual(
            engine().run_body("Ex2TPW_13_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(data[4:6], b"\5\3")
        for changed, expected in ((False, 2000), (True, 0)):
            data[:4] = (2).to_bytes(4, "little")
            comm = Comm(
                [
                    (0, bytes((0x62, 0x10, low, 0x10, int(changed), 0, 0)))
                    for low in range(0x50, 0x54)
                ]
            )
            self.assertEqual(
                engine().run_body("Ex2TPW_13_SendMessage", (data,), Context(comm)),
                expected,
            )
        data[:4] = (3).to_bytes(4, "little")
        data[29] = 2
        comm = Comm(
            [
                (0, bytes((0x62, 0x10, low)) + bytes([low]) * 4)
                for low in range(0x55, 0x5A)
            ]
        )
        self.assertEqual(
            engine().run_body("Ex2TPW_13_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(data[6:10], b"\x55" * 4)
        self.assertEqual(data[22:26], b"\x59" * 4)
        data[:4] = (4).to_bytes(4, "little")
        data[27] = 1
        comm = Comm(
            [(0, b"\x62\x20\x33\x11\xff"), (0, b"\x6e\x20\x33"), (7, b""), (9, b"")]
        )
        self.assertEqual(
            engine().run_body("Ex2TPW_13_SendMessage", (data,), Context(comm)), 7
        )
        requests = [e[1] for e in comm.events if e[0] == "exchange"]
        self.assertEqual(requests[1], b"\x2e\x20\x33\x11\x7f")
        self.assertEqual(requests[-1], b"\x2e\x20\x33\x11\xff")
        self.assertEqual(requests[2], b"\x2e\x20\3\5" + data[6:26])
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_drs04_embedded_descriptors_read_payload_and_accumulated_write_masks(self):
        data = bytearray(0x1064)
        for base, index, mask, write_mask in (
            (0x102C, 0, 128, 64),
            (0x1048, 1, 64, 32),
        ):
            for offset, value in ((0, index), (4, mask), (12, 0), (16, write_mask)):
                data[base + offset : base + offset + 4] = value.to_bytes(4, "little")

        def snapshot(identifier, payload):
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return (
                0,
                (bytes((identifier, len(payload))) + payload).ljust(0x1020, b"\0"),
                tuple(offsets),
            )

        comm = Comm(snapshots=[snapshot(10, b"\x80\x40"), snapshot(1, b"\x60")])
        self.assertEqual(
            engine().run_body("Ex2DRS_04_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(int.from_bytes(data[:4], "little"), 2)
        self.assertEqual(int.from_bytes(data[0x1024:0x1028], "little"), 1)
        data[0x1028:0x102C] = (1).to_bytes(4, "little")
        comm = Comm([(0, b"\x61\x0a\x80\x40")])
        self.assertEqual(
            engine().run_body("Ex2DRS_04_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(data[4:6], b"\x80\x40")
        data[0x1028:0x102C] = (2).to_bytes(4, "little")
        comm = Comm([(0, b"\x7b\1")])
        self.assertEqual(
            engine().run_body("Ex2DRS_04_SendMessage", (data,), Context(comm)), 0
        )
        self.assertIn(("exchange", b"\x3b\1\x60"), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_twelve_abs17_actual_source_support_sync_and_output_layout(self):
        selected = ChassisEngine(
            replace(CONTRACT_12, source_sha256=Context.module_sha256)
        )

        def snapshot(identifier, payload):
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return (
                0,
                (bytes((identifier, len(payload))) + payload).ljust(0x1020, b"\0"),
                tuple(offsets),
            )

        data = bytearray(14)
        comm = Comm(snapshots=[snapshot(10, b"\xff" * 10), snapshot(0xF1, b"\xff")])
        self.assertEqual(
            selected.run_body("Ex2ABS_17_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(
            tuple(int.from_bytes(data[i : i + 4], "little") for i in (0, 4, 8)),
            (10, 12, 3),
        )
        self.assertIn(("configure", "native_rva:b940", 150), comm.events)
        reply = b"\x61\x0a" + bytes(8) + b"xy"
        comm = Comm([(0, reply)])
        self.assertEqual(
            selected.run_body("Ex2ABS_17_GetABSInfo", (data,), Context(comm)), 0
        )
        self.assertEqual(data[12:14], b"xy")
        comm = Comm([(0, b"\x7b\xf1"), (0, b"\x7b\xf1")])
        self.assertEqual(
            selected.run_body("Ex2ABS_17_SychronizingABSInfo", (data,), Context(comm)),
            0,
        )
        self.assertEqual(
            [e[1] for e in comm.events if e[0] == "exchange"],
            [b"\x3b\xf1\2", b"\x3b\xf1\1"],
        )
        for name in (
            "Ex2ABS_17_SupportCheck",
            "Ex2ABS_17_GetABSInfo",
            "Ex2ABS_17_SychronizingABSInfo",
            "Ex2ABS_18_SupportCheck",
            "Ex2ABS_18_SetNeutralPos",
            "Ex2ABS_21_SupportCheck",
            "Ex2ABS_21_ChangeMode",
            "Ex2ABS_21_CheckSensorStatus",
        ):
            self.assertTrue(supports(SHA_12_TY, name))
        self.assertFalse(supports(SHA_12_TY, "Ex2ARS_05_SendMessage"))

    def test_ahc03_end_preserves_actual_caller_unused_native_buffer(self):
        selected = bytearray(b"actual caller this+e8")
        before = bytes(selected)
        comm = Comm()
        self.assertEqual(
            engine().run_body(
                "Ex2AHC_03_EndExtendedSession", (selected,), Context(comm)
            ),
            1000,
        )
        self.assertEqual(selected, before)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_plus_abs18_abs21_exact_independent_layout_and_legacy_setter(self):
        selected = ChassisEngine(
            replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        )
        for name in (
            "Ex2ABS_18_SupportCheck",
            "Ex2ABS_18_SetNeutralPos",
            "Ex2ABS_21_SupportCheck",
            "Ex2ABS_21_ChangeMode",
            "Ex2ABS_21_CheckSensorStatus",
        ):
            self.assertTrue(supports(SHA_PLUS_TY, name))
        data = bytearray(24)
        data[20:24] = (1).to_bytes(4, "little")
        comm = Comm([(0, b"\x50")])
        self.assertEqual(
            selected.run_body("Ex2ABS_21_ChangeMode", (data,), Context(comm)), 0
        )
        self.assertIn(("configure", "native_rva:142f0", 150), comm.events)
        data[16:20] = (4).to_bytes(4, "little")
        comm = Comm([(1000, b"\x61\xba\x11\x22")])
        self.assertEqual(
            selected.run_body("Ex2ABS_21_CheckSensorStatus", (data,), Context(comm)),
            1000,
        )
        self.assertEqual(data[13:15], b"\x11\x22")
        comm = Comm([(0, b"\x61\6\0\0")])
        data = bytearray(20)
        data[8:12] = (4).to_bytes(4, "little")
        data[:4] = (2).to_bytes(4, "little")
        self.assertEqual(
            selected.run_body("Ex2ABS_18_SetNeutralPos", (data,), Context(comm)), 1000
        )
        self.assertIn(("configure", "native_rva:142f0", 150), comm.events)

    def test_ars05_full_selector_saved_bits_live_poll_and_native_rollback_result(self):
        data = bytearray(14)
        comm = Comm([(0, b"\x62\2\4\x45\xff"), (0, b"\x6e\2\4"), (0, b"\x6e\x20\x20")])
        self.assertEqual(
            engine().run_body("Ex2ARS_05_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(data[12:14], b"\x45\xfe")
        self.assertNotIn(("finalize",), comm.events)
        data[:4] = (1).to_bytes(4, "little")
        comm = Comm([(0, b"\x62\x10\x22\1"), (0, b"\x62\x10\x22\2")])
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2ARS_05_SendMessage", (data,), ctx), 0)
        self.assertEqual(ctx.sleeps, [200, 200])
        data[8:12] = (1).to_bytes(4, "little")
        comm = Comm([(0, b"\x62\x10\x22\1")])
        self.assertEqual(
            engine().run_body("Ex2ARS_05_SendMessage", (data,), Context(comm)), 2008
        )
        data[:4] = (2).to_bytes(4, "little")
        comm = Comm(
            [(0, b"\x62\2\4\x45\xff"), (0, b"\x6e\2\4"), (9, b"")], sessions=[7]
        )
        self.assertEqual(
            engine().run_body("Ex2ARS_05_SendMessage", (data,), Context(comm)), 0
        )
        self.assertIn(("exchange", b"\x2e\2\4\x45\xfe"), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))
        for action, expected in ((4, 99), (5, 1008)):
            data[:4] = action.to_bytes(4, "little")
            comm = Comm([(7, b"")])
            self.assertEqual(
                engine().run_body("Ex2ARS_05_SendMessage", (data,), Context(comm)),
                expected,
            )
            self.assertIn(("exchange", b"\x2e\x20\x20\xff"), comm.events)

    def test_asus08_compressor_retained_manager_and_native_completion_output(self):
        for retained in (0, 1):
            comm = Comm(
                [
                    (0, b"\x71\1\x11\1"),
                    (0, b"\x71\3\x11\1\2"),
                    (0, b"\x62\x10\7\x08\x9d"),
                ]
            )
            ctx = Context(comm)
            ctx.state["native:1012ae1c"] = retained
            data = bytearray(20)
            self.assertEqual(
                engine().run_body("Ex2ASUS_08_StartCompressRaisingCtrl", (data,), ctx),
                0,
            )
            self.assertEqual(int.from_bytes(data[4:8], "little"), 1)
            self.assertEqual(int.from_bytes(data[16:20], "little"), 1004)
            self.assertEqual(("initialize", 0) in comm.events, not retained)
            self.assertEqual(("finalize",) in comm.events, not retained)
            self.assertIn(("exchange", b"\x31\1\x11\1\x0f\2\x96"), comm.events)
        comm = Comm([(0, b"\x71\1\x11\1"), (0, b"\x71\3\x11\1\3"), (9, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_08_StartCompressRaisingCtrl", (bytearray(20),), Context(comm)
            ),
            99,
        )
        self.assertIn(("exchange", b"\x31\2\x11\1"), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_asus08_tank_pressure_branch_and_ten_bounded_timeout_cycles(self):
        data = bytearray(20)
        comm = Comm(
            [
                (0, b"\x6e\x21\1"),
                (0, b"\x71\1\x11\1"),
                (0, b"\x71\3\x11\1\2"),
                (0, b"\x71\1\x11\1"),
                (0, b"\x71\3\x11\1\2"),
                (0, b"\x62\x10\7\x07\0"),
            ]
        )
        ctx = Context(comm)
        ctx.state["native:1012ae1c"] = 1
        self.assertEqual(
            engine().run_body("Ex2ASUS_08_StartTankPressLowCtrl", (data,), ctx), 0
        )
        self.assertEqual(ctx.state["native:1012ae1c"], 0)
        self.assertNotIn(("configure", "retry", 0), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))
        replies = [(0, b"\x6e\x21\1")]
        for _ in range(10):
            replies.extend(
                [(0, b"\x71\1\x11\1")]
                + [(0, b"\x71\3\x11\1\1")] * 20
                + [(0, b"\x71\2\x11\1")]
            )
        comm = Comm(replies)
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2ASUS_08_StartTankPressLowCtrl", (data,), ctx), 1001
        )
        self.assertEqual(ctx.sleeps.count(60000), 10)
        self.assertEqual(comm.events.count(("exchange", b"\x31\2\x11\1")), 10)

    def test_abs4wd_two_targets_support_and_fault_rollback(self):
        def snapshot(identifier):
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return 0, (bytes((identifier, 1, 128))).ljust(0x1020, b"\0"), tuple(offsets)

        data = bytearray(8)
        comm = Comm(snapshots=[snapshot(0xA6), snapshot(11)] * 2)
        self.assertEqual(
            engine().run_body("Ex2ABS4WD_01_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(data, b"\1\0\0\0" * 2)
        self.assertEqual(comm.events.count(("finalize",)), 2)
        comm = Comm([(0, b"\x7b\x0b"), (0, b"\x61\xa6\x80")] * 2)
        self.assertEqual(
            engine().run_body(
                "Ex2ABS4WD_01_ChangePreventionMode", (data,), Context(comm)
            ),
            0,
        )
        self.assertNotIn(("exchange", b"\x3b\x0b\0"), comm.events)
        comm = Comm([(0, b"\x7b\x0b"), (0, b"\x61\xa6\0"), (7, b""), (8, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2ABS4WD_01_ChangePreventionMode", (data,), Context(comm)
            ),
            1000,
        )
        self.assertEqual(comm.events.count(("exchange", b"\x3b\x0b\0")), 2)
        self.assertEqual(comm.events.count(("finalize",)), 3)
        comm = Comm(initial=9)
        self.assertEqual(
            engine().run_body("Ex2ABS4WD_01_SupportCheck", (data,), Context(comm)), 9
        )
        self.assertNotIn(("finalize",), comm.events)

    def test_asus_height_tank_native_repeated_start_pressure_threshold_and_retention(
        self,
    ):
        for number in (6, 7):
            for pressure, expected in (
                (1779, 1003),
                (1780, 0),
                (2204, 0),
                (2205, 1004),
            ):
                replies = [(0, b"\x6e\x21\1")]
                replies += [(0, b"\x71\1\x11\1"), (0, b"\x71\3\x11\1\2")] * 2
                replies += [(0, b"\x62\x10\7" + pressure.to_bytes(2, "big"))]
                if expected == 1004:
                    replies += [
                        (0, b"\x71\1\x11\5"),
                        (0, b"\x71\3\x11\5\2"),
                        (0, b"\x62\x10\7\x08\x9d"),
                    ]
                comm = Comm(replies)
                ctx = Context(comm)
                self.assertEqual(
                    engine().run_body(f"Ex2ASUS_0{number}_TheHeightAndTank", (), ctx),
                    expected,
                )
                self.assertNotIn(("initialize", 0), comm.events)
                self.assertEqual(comm.events[-1], ("finalize",))
                self.assertIn(("exchange", b"\x31\1\x11\1\x0f\4\x40"), comm.events)
                self.assertIn(("exchange", b"\x31\1\x11\1\x0f\2\x40"), comm.events)
                self.assertEqual(ctx.sleeps[:3], [100, 30000, 100])
        comm = Comm([(0, b"\x6e\x21\1"), (0, b"\x71\1\x11\1"), (7, b""), (9, b"")])
        self.assertEqual(
            engine().run_body("Ex2ASUS_06_TheHeightAndTank", (), Context(comm)), 7
        )
        self.assertIn(("exchange", b"\x31\2\x11\1"), comm.events)

    def test_bsm_conditional_active_angle_change_and_strict_five_degree_limit(self):
        data = bytearray(36)
        for offset, value in ((4, 5), (12, 4), (20, 2)):
            data[offset : offset + 4] = value.to_bytes(4, "little")
        data[28] = 0xD1
        for before, after, expected in (
            (100, 200, 0),
            (100, 100, 9001),
            (100, 500, 9001),
            (100, -499, 0),
            (100, -500, 9001),
        ):
            comm = Comm(
                [
                    (0, b"\x61\x68\0" + before.to_bytes(2, "big", signed=True)),
                    (0, b"\x70\xd1"),
                    (0, b"\x61\x68\x80\0\0"),
                    (0, b"\x61\x68\0" + after.to_bytes(2, "big", signed=True)),
                    (9, b""),
                ]
            )
            self.assertEqual(
                engine().run_body(
                    "Ex2BSM_03_04_ActiveTestCon3_5", (data,), Context(comm)
                ),
                expected,
            )
            self.assertEqual(comm.events[-2:], [("exchange", b"\x30"), ("finalize",)])
        comm = Comm([(7, b"")])
        self.assertEqual(
            engine().run_body("Ex2BSM_03_04_ActiveTestCon3_5", (data,), Context(comm)),
            7,
        )
        self.assertNotIn(("exchange", b"\x30"), comm.events)

    def test_ars_calibration_selected_pressure_restore_and_dtc_policy(self):
        data = bytearray(12)
        data[:4] = (4).to_bytes(4, "little")
        data[8:12] = (3).to_bytes(4, "little")
        for second in (False, True):
            replies = [(0, b"\x50")] * (3 if second else 1)
            replies += [
                (0, b"\x61\x84\x42"),
                (0, b"\x70\2"),
                (0, b"\x50"),
                (0, b"\x61\x81\0\1"),
            ]
            comm = Comm(replies)
            ctx = Context(comm)
            name = "Ex2ARS_02_InitCompVal" if second else "Ex2ARS_03_ActiveTest"
            self.assertEqual(engine().run_body(name, (data,), ctx), 0)
            self.assertIn(("exchange", b"\x30\2\0\1\x42\5\x32\1\1"), comm.events)
            self.assertEqual(("read_dtcs", 128, 4096) in comm.events, second)
            self.assertEqual(comm.events[-1], ("finalize",))
        data[8:12] = bytes(4)
        for status, payload, expected in (
            (7, b"", -0x6FFFFFFE),
            (0, b"\x61\x81\0\2", -0x6FFFFFFF),
        ):
            comm = Comm([(0, b"\x50"), (0, b"\x70\2"), (0, b"\x50"), (status, payload)])
            self.assertEqual(
                engine().run_body("Ex2ARS_03_ActiveTest", (data,), Context(comm)),
                expected,
            )
        comm = Comm([(0, b"\x50"), (7, b""), (9, b"")])
        self.assertEqual(
            engine().run_body("Ex2ARS_03_ActiveTest", (data,), Context(comm)), 7
        )
        self.assertIn(("exchange", b"\x30"), comm.events)

    def test_abs51_two_selected_snapshots_write_verify_and_retention(self):
        data = bytearray(0x204A)
        data[6:10] = b"\2\0\3\0"
        comm = Comm([(0, b"\x62\x20\5ab")])
        self.assertEqual(
            engine().run_body("Ex2ABS_51_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(data[10:12], b"ab")
        self.assertNotIn(("finalize",), comm.events)
        data[:4] = (1).to_bytes(4, "little")
        comm = Comm([(0, b"\x62\x20\5cd"), (0, b"\x62\x20\6xyz")])
        self.assertEqual(
            engine().run_body("Ex2ABS_51_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(data[10:12], b"cd")
        self.assertEqual(data[0x102A:0x102D], b"xyz")
        data[:4] = (2).to_bytes(4, "little")
        comm = Comm([(0, b"\x6e\x20\5"), (0, b"\x62\x20\5cd")])
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2ABS_51_SendMessage", (data,), ctx), 0)
        self.assertNotIn(("initialize", 0), comm.events)
        self.assertEqual(ctx.sleeps, [1000])
        self.assertEqual(comm.events[-1], ("finalize",))
        data[:4] = (4).to_bytes(4, "little")
        comm = Comm([(0, b"\x6e\x20\5"), (0, b"\x62\x20\5ce")])
        self.assertEqual(
            engine().run_body("Ex2ABS_51_SendMessage", (data,), Context(comm)), 3
        )
        self.assertEqual(comm.events[-1], ("finalize",))
        data[:4] = (5).to_bytes(4, "little")
        comm = Comm()
        self.assertEqual(
            engine().run_body("Ex2ABS_51_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(comm.events, [("session", 1, 1), ("finalize",)])

    def test_vgrs_dtc_filtered_support_and_unfiltered_check(self):
        data = bytearray(4)
        offsets = [0x1020] * 256
        offsets[2] = 0
        comm = Comm(
            snapshots=[(0, b"\2\3\xff\0\1".ljust(0x1020, b"\0"), tuple(offsets))]
        )
        comm.dtcs = (0, b"\x53\1\x55\x91")
        self.assertEqual(
            engine().run_body("Ex2VGRS_04_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(int.from_bytes(data, "little"), 5)
        self.assertEqual(
            engine().run_body("Ex2VGRS_04_CheckDTC", (), Context(comm)), 10000
        )
        comm.dtcs = (0, b"\x53\0")
        self.assertEqual(engine().run_body("Ex2VGRS_04_CheckDTC", (), Context(comm)), 0)

    def test_ars_center_native_reply_echo_rollback_and_numeric_range(self):
        data = bytearray(b"\4\0\0\0" * 2)
        for angle, expected in ((32768, 0), (0, 1100), (65535, 1100)):
            comm = Comm(
                [
                    (0, b"\x50"),
                    (0, b"\x70\5"),
                    (0, b"\x50"),
                    (0, b"\x61\x09" + angle.to_bytes(2, "big")),
                ]
            )
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body("Ex2ARS_01_ReturnActuatorCenterPos", (data,), ctx),
                expected,
            )
            self.assertEqual(ctx.sleeps, [500, 10000, 500])
        comm = Comm([(0, b"\x50"), (0, b"\x70\6"), (9, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2ARS_01_ReturnActuatorCenterPos", (data,), Context(comm)
            ),
            3,
        )
        self.assertIn(("exchange", b"\x30"), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_bsm_target_probe_status_and_separate_saved_globals(self):
        for number, key in ((27, "native:1012ae14"), (28, "native:1012ae18")):
            data = bytearray(8)
            comm = Comm([(2, b"")])
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body(f"Ex2BSM_{number}_SendMessage", (data,), ctx), 0
            )
            self.assertEqual(ctx.state[key], 0x700)
            self.assertEqual(int.from_bytes(data[4:8], "little"), 2)
            self.assertIn(("select_target", 0x786, 0), comm.events)
            data[:4] = (1).to_bytes(4, "little")
            comm.replies = [(0, b"\x7b\x6b")]
            self.assertEqual(
                engine().run_body(f"Ex2BSM_{number}_SendMessage", (data,), ctx), 0
            )
            self.assertIn(("select_target", 0x700, 0), comm.events)
            for response in ((7, b"\x7f\x3b\x22"), (0, b"\x7b\x6a")):
                comm.replies = [response]
                self.assertEqual(
                    engine().run_body(f"Ex2BSM_{number}_SendMessage", (data,), ctx),
                    2000,
                )
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_ars_native_dtc_filter_and_target_restore_order(self):
        for second in (False, True):
            for vgrs in (False, True):
                name = (
                    ("Ex2ARS_02_" + ("ChkVGRSDtc" if vgrs else "ChkARSDtc"))
                    if second
                    else ("Ex2ARS_01_" + ("ReadDTCofVGRS" if vgrs else "ReadDTCofARS"))
                )
                for codes, expected in (
                    ((), 0),
                    ((0x55C9,) if vgrs else (0x5B01, 0x5B04), 0),
                    ((0x1234,), -0x6FFFFFFF if second else 1000),
                ):
                    comm = Comm()
                    comm.dtcs = (
                        0,
                        bytes((0x53, len(codes)))
                        + b"".join(code.to_bytes(2, "big") for code in codes),
                    )
                    self.assertEqual(
                        engine().run_body(name, (), Context(comm)), expected
                    )
                    if vgrs:
                        self.assertEqual(
                            comm.events[-2:],
                            [("finalize",), ("select_target", 0x700, 0)],
                        )
                    else:
                        self.assertEqual(comm.events[-1], ("finalize",))
                    config = comm.events.index(("configure", "native_rva:12180", 150))
                    init = comm.events.index(("initialize", 0))
                    self.assertEqual(config > init, second)
        comm = Comm(initial=8)
        self.assertEqual(
            engine().run_body("Ex2ARS_02_ChkVGRSDtc", (), Context(comm)), 8
        )
        self.assertEqual(comm.events[-1], ("select_target", 0x700, 0))

    def test_ars_clear_offset_session_write_clear_and_fault_stop(self):
        for name in ("Ex2ARS_01_ClearOffSetValue", "Ex2ARS_02_ClrCompVal"):
            comm = Comm([(0, b"\x50"), (0, b"\xe6"), (0, b"\x54")])
            ctx = Context(comm)
            self.assertEqual(engine().run_body(name, (), ctx), 0)
            self.assertEqual(ctx.sleeps, [500, 500])
            self.assertEqual(
                [e[1] for e in comm.events if e[0] == "exchange"],
                [b"\x10\x40", b"\xa6\1", b"\x14"],
            )
            comm = Comm([(7, b"")])
            self.assertEqual(engine().run_body(name, (), Context(comm)), 7)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_ars04_pending_timeout_retention_and_live_exit(self):
        data = bytearray(8)
        comm = Comm([(0, b"\x71\1\x11\5")])
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2ARS_04_SendMessage", (data,), ctx), 0)
        self.assertEqual(ctx.sleeps, [500])
        self.assertNotIn(("finalize",), comm.events)
        self.assertIn(("exchange", b"\x31\1\x11\5\1\x46\x14\x32\x32\1"), comm.events)
        data[:4] = (1).to_bytes(4, "little")
        comm = Comm([(0, b"\x71\3\x11\5\1")] * 23)
        self.assertEqual(
            engine().run_body("Ex2ARS_04_SendMessage", (data,), Context(comm)), 2000
        )
        self.assertNotIn(("finalize",), comm.events)
        data[4:8] = (1).to_bytes(4, "little")
        comm = Comm([(7, b"")])
        self.assertEqual(
            engine().run_body("Ex2ARS_04_SendMessage", (data,), Context(comm)), 0
        )
        self.assertIn(("exchange", b"\x31\2\x11\5"), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_emps13_live_poll_retention_and_native_nrc_mapping(self):
        data = bytearray(16)
        comm = Comm()
        self.assertEqual(
            engine().run_body("Ex2EMPS_13_SendMessage", (data,), Context(comm)), 0
        )
        self.assertNotIn(("finalize",), comm.events)
        data[:4] = (1).to_bytes(4, "little")
        comm = Comm(
            [(0, b"\x71\1\x10\2"), (0, b"\x71\3\x10\2\1"), (0, b"\x71\3\x10\2\2")]
        )
        self.assertEqual(
            engine().run_body("Ex2EMPS_13_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(int.from_bytes(data[12:16], "little"), 1)
        self.assertNotIn(("finalize",), comm.events)
        for action, nrc, expected in (
            (6, 0, 7),
            (7, 0x69, 7),
            (7, 0x22, 1010),
            (8, 0x69, 7),
        ):
            data[:4] = action.to_bytes(4, "little")
            comm = Comm([(7, b"\x7f\x2e\x69")])
            comm.native_10b0 = nrc
            self.assertEqual(
                engine().run_body("Ex2EMPS_13_SendMessage", (data,), Context(comm)),
                expected,
            )
            self.assertEqual(comm.events[-1], ("finalize",))
        data[:4] = (1).to_bytes(4, "little")
        data[4:12] = b"\1\0\0\0" * 2
        comm = Comm([(0, b"\x71\1\x10\2"), (9, b"")])
        self.assertEqual(
            engine().run_body("Ex2EMPS_13_SendMessage", (data,), Context(comm)), 0
        )
        self.assertIn(("exchange", b"\x31\2\x11\x10"), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_bsm_active_support_selectors_and_sparse_length_fallback(self):
        def snapshot(records):
            raw = b""
            offsets = [0x1020] * 256
            for identifier, payload in records:
                offsets[identifier] = len(raw)
                raw += bytes((identifier, len(payload))) + payload
            return 0, raw.ljust(0x1020, b"\0"), tuple(offsets)

        for older, high, condition, expected in (
            (True, False, False, 1),
            (True, True, False, 2),
            (True, True, True, 3),
            (False, False, False, 1),
            (False, True, False, 2),
        ):
            data = bytearray(36 if older else 32)
            data[28 if older else 24] = 0xD1
            payload68 = b"\xff" * (10 if condition else 8)
            payload7b = b"\xff" * (9 if high else 5)
            records = [(0x68, payload68), (0x7B, payload7b)]
            if high and older:
                records.append((0x6B, b"\x20"))
                if condition:
                    records.append((0x6A, b"\0\0\0\0\x40"))
            comm = Comm(snapshots=[snapshot(records), snapshot(((0xD1, b"\x80"),))])
            self.assertEqual(
                engine().run_body(
                    "Ex2BSM_03_04_SupportCheck"
                    if older
                    else "Ex2BSM_05_06_SupportCheck",
                    (data,),
                    Context(comm),
                ),
                0,
            )
            self.assertEqual(
                int.from_bytes(
                    data[32 if older else 28 : 36 if older else 32], "little"
                ),
                expected,
            )
            self.assertEqual(
                int.from_bytes(
                    data[12 if older else 8 : 16 if older else 12], "little"
                ),
                4,
            )
            if older and not high:
                # Native ignores missing6B count status and reuses68's count.
                self.assertEqual(data[8:12], data[4:8])
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_bsm_test_mode_native_negative_status_and_cleanup(self):
        data = bytearray(9)
        data[:4] = (3).to_bytes(4, "little")
        for export, replies, expected, value, normal in (
            ("Mov2TestMode", [(0, b"\x50"), (0, b"\x61\x69\xc0")], 0, 3, False),
            ("Mov2TestMode", [(7, b"")], -0x6FFFFFFF, 255, False),
            (
                "Mov2TestMode",
                [(0, b"\x50"), (7, b"\x7f\x21\x22"), (9, b"")],
                7,
                0,
                True,
            ),
            ("ChkStilInTestMode", [(0, b"\x50\x5f")], -0x6FFFFFFE, 255, False),
            (
                "ChkStilInTestMode",
                [(0, b"\x50\x60"), (0, b"\x61\x69\x80")],
                0,
                2,
                False,
            ),
            ("ChkStilInTestMode", [(0, b"\x50"), (0, b"\x50")], 3, 255, True),
        ):
            data[8] = 255
            comm = Comm(replies)
            self.assertEqual(
                engine().run_body("Ex2BSM_01_02_" + export, (data,), Context(comm)),
                expected,
            )
            self.assertEqual(data[8], value)
            self.assertEqual(("exchange", b"\x10\1") in comm.events, normal)
            self.assertEqual(comm.events[-1], ("finalize",))
        comm = Comm([(0, b"\x50")])
        self.assertEqual(
            engine().run_body("Ex2BSM_01_02_ExitTestMode", (), Context(comm)), 0
        )
        self.assertIn(("configure", "native_rva:121d0", 256), comm.events)

    def test_bsm_abnormal_history_error_output_and_clear_mapping(self):
        data = bytearray(12)
        data[:4] = (3).to_bytes(4, "little")
        for replies, expected, output in (
            ([(0, b"\x7b\x6c"), (0, b"\x61\x6c\xa0")], 0, 160),
            ([(7, b"")], 1000, 255),
            ([(0, b"\x7b")], 1000, 255),
            ([(0, b"\x7b\x6c"), (9, b"\x7f\x21\x22")], 2000, 34),
        ):
            data[8:12] = (255).to_bytes(4, "little")
            comm = Comm(replies)
            self.assertEqual(
                engine().run_body(
                    "Ex2BSM_07_08_ClearAbnormalHistory", (data,), Context(comm)
                ),
                expected,
            )
            self.assertEqual(int.from_bytes(data[8:12], "little"), output)
        comm = Comm([(8, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2BSM_07_08_GetAbnormalHistory", (data,), Context(comm)
            ),
            8,
        )
        self.assertEqual(data[8:12], bytes(4))

    def test_bsm_support_declared_bits_and_snapshot_order(self):
        def snapshot(identifier, payload):
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return (
                0,
                (bytes((identifier, len(payload))) + payload).ljust(0x1020, b"\0"),
                tuple(offsets),
            )

        for mode, bits in ((0, 0xC0), (1, 0x30)):
            data = bytearray(9)
            data[4:8] = mode.to_bytes(4, "little")
            comm = Comm(snapshots=[snapshot(0x69, bytes((bits, 0, 1)))])
            self.assertEqual(
                engine().run_body("Ex2BSM_01_02_SupportCheck", (data,), Context(comm)),
                0,
            )
            self.assertEqual(int.from_bytes(data[:4], "little"), 4)
        data = bytearray(12)
        comm = Comm(snapshots=[snapshot(0x6C, b"\xf8\0\1"), snapshot(0x6C, b"\xf8")])
        self.assertEqual(
            engine().run_body("Ex2BSM_07_08_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(data[:8], b"\4\0\0\0\3\0\0\0")

    def test_abs21_sparse_support_and_native_sensor_copy_status(self):
        raw = (b"\xba\x03\x81\xa0\0").ljust(0x1020, b"\0")
        offsets = [0x1020] * 256
        offsets[0xBA] = 0
        data = bytearray([255] * 26)
        comm = Comm(snapshots=[(0, raw, tuple(offsets))])
        self.assertEqual(
            engine().run_body("Ex2ABS_21_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(data[:13], bytes((1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0)))
        self.assertEqual(data[13:16], b"\xff" * 3)
        self.assertEqual(int.from_bytes(data[16:20], "little"), 4)
        for status, response, expected in (
            (0, b"\x61\xba\x11\x22", 1000),
            (1000, b"\x7f\x21\x33\x44", 1000),
            (7, b"\x7f\x21\x33", 7),
            (0, b"\x61\xbb\x11\x22", 3),
        ):
            data[13:16] = b"\xff" * 3
            comm = Comm([(status, response)])
            self.assertEqual(
                engine().run_body(
                    "Ex2ABS_21_CheckSensorStatus", (data,), Context(comm)
                ),
                expected,
            )
            self.assertEqual(
                data[13:15], response[2:] if expected == 1000 else b"\xff\xff"
            )
            self.assertEqual(comm.events[-1], ("finalize",))
        for mode, expected in ((0, b"\x10\1"), (42, b"\x10\x40")):
            data[20:24] = mode.to_bytes(4, "little")
            comm = Comm([(0, b"\x50")])
            self.assertEqual(
                engine().run_body("Ex2ABS_21_ChangeMode", (data,), Context(comm)), 0
            )
            self.assertIn(("exchange", expected), comm.events)
        data[16:20] = (20).to_bytes(4, "little")
        comm = Comm([(1000, bytes(20))])
        with self.assertRaises(ValueError):
            engine().run_body("Ex2ABS_21_CheckSensorStatus", (data,), Context(comm))
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_abs18_neutral_native_ranges_and_write_nrc_mapping(self):
        def snapshot(records):
            raw = b""
            offsets = [0x1020] * 256
            for identifier, payload in records:
                offsets[identifier] = len(raw)
                raw += bytes((identifier, len(payload))) + payload
            return 0, raw.ljust(0x1020, b"\0"), tuple(offsets)

        comm = Comm(
            snapshots=[
                snapshot(((5, b"\xff\xff"), (6, b"\0\0\xff\xff"), (0x43, b"\xff"))),
                snapshot(((12, b"\x30\0\0"),)),
            ]
        )
        selected = bytearray(20)
        self.assertEqual(
            engine().run_body("Ex2ABS_18_SupportCheck", (selected,), Context(comm)), 0
        )
        self.assertEqual(
            tuple(
                int.from_bytes(selected[i : i + 4], "little") for i in (0, 4, 8, 12, 16)
            ),
            (2, 4, 4, 3, 5),
        )
        data = bytearray(20)
        for offset, value in ((0, 2), (4, 4), (8, 4), (12, 3), (16, 3)):
            data[offset : offset + 4] = value.to_bytes(4, "little")
        for angle, first, second, speed, final, expected in (
            (0x8000, 128, 128, 7, (0, b"\x7b\x0c"), 0),
            (0x7F87, 128, 128, 7, None, 1000),
            (0x8000, 0x73, 128, 7, None, 1001),
            (0x8000, 128, 0x8D, 7, None, 1002),
            (0x8000, 128, 128, 8, None, 1003),
            (0x8078, 0x74, 0x8C, 7, (7, b"\x7f\x3b\x22"), 1004),
        ):
            replies = [(0, b"\x61\6" + angle.to_bytes(2, "big"))]
            if expected != 1000:
                replies.append((0, bytes((0x61, 5, first, second))))
            if expected not in (1000, 1001, 1002):
                replies.append((0, bytes((0x61, 0x43, speed))))
            if final is not None:
                replies.append(final)
            comm = Comm(replies)
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body("Ex2ABS_18_SetNeutralPos", (data,), ctx), expected
            )
            self.assertEqual(comm.events[-1], ("finalize",))
            if expected == 0:
                self.assertEqual(ctx.sleeps, [500, 500, 5000])

    def test_live_selected_length_mutation_is_bounded_before_allocation(self):
        data = bytearray(16)
        data[12] = 1

        class MutatingComm(Comm):
            def exchange(self, request):
                data[12:16] = b"\xff" * 4
                return super().exchange(request)

        comm = MutatingComm([(0, b"\x50")])
        with self.assertRaisesRegex(ValueError, "live native buffer"):
            engine().run_body("Ex2ASUS_13_TestStart", (data,), Context(comm))
        self.assertEqual(comm.events[-1], ("finalize",))
        self.assertEqual(sum(e[0] == "exchange" for e in comm.events), 1)

    def test_asus05_start_stop_learn_and_live_cancel(self):
        data = bytearray(14)
        data[0], data[4], data[8] = 2, 3, 5
        for suffix, replies, requests in (
            (
                "ModifyVheightDownStart",
                [b"\x50", b"\x70\6"],
                [b"\x10\x60\0", b"\x30\6\x19\1\0"],
            ),
            ("ModifyVheightStop", [b"\x70\6", b"\x50"], [b"\x30\6\0\0\0", b"\x10\1"]),
            ("ReturnVheightStart", [b"\x70"], [b"\x30"]),
            ("ModifyVheightTimeOver", [b"\x50"], [b"\x10\1"]),
        ):
            comm = Comm([(0, reply) for reply in replies])
            self.assertEqual(
                engine().run_body(
                    "Ex2ASUS_05_" + suffix,
                    (data,)
                    if suffix in ("ModifyVheightDownStart", "ModifyVheightStop")
                    else (),
                    Context(comm),
                ),
                0,
            )
            self.assertEqual(
                [e[1] for e in comm.events if e[0] == "exchange"], requests
            )
        comm = Comm(
            [(0, b"\x7b\x17"), (0, b"\x7b\7"), (0, b"\x61\x10\x10"), (0, b"\x50")]
        )
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2ASUS_05_LearnKneelDownVheight", (data,), ctx), 0
        )
        self.assertEqual(ctx.sleeps, [500, 500])
        comm = Comm()
        ctx = Context(comm)
        ctx.on_sleep = lambda _: data.__setitem__(13, 1)
        self.assertEqual(
            engine().run_body("Ex2ASUS_05_CheckModifiedVheight", (data,), ctx), 1000
        )
        self.assertFalse(any(e[0] == "exchange" for e in comm.events))
        comm = Comm([(0, b"\x61\x10\0")])
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_05_CheckReturnedVheight", (data,), Context(comm)
            ),
            0,
        )

    def test_asus04_modify_selected_hidden_bytes_and_unpublished_worker_exit(self):
        for height, suffix in ((100, b"\0\0"), (200, b"\x14\1")):
            data = bytearray(20)
            data[8], data[16] = 5, height
            comm = Comm([(0, b"ar")])
            self.assertEqual(
                engine().run_body("Ex2ASUS_04_ModifyVhight", (data,), Context(comm)), 0
            )
            self.assertIn(("exchange", b"\x30\6" + suffix + b"\0"), comm.events)
        comm = Comm()
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_04_ModifyVhight", (bytearray(20),), Context(comm)
            ),
            99,
        )
        self.assertEqual(comm.events, [])

    def test_asus04_learn_restore_sequence_and_returned_height_poll(self):
        data = bytearray(13)
        data[0], data[4] = 2, 3
        comm = Comm(
            [
                (0, b"\x50"),
                (0, b"\x7b\x17"),
                (0, b"\x7b\7"),
                (0, b"\x50"),
                (0, b"\x61\x10\x10"),
            ]
        )
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2ASUS_04_LearnKneeldownVheight", (data,), ctx), 0
        )
        self.assertEqual(ctx.sleeps, [1000])
        self.assertEqual(
            [e[1] for e in comm.events if e[0] == "exchange"],
            [b"\x10\x60\0", b"\x3b\x17", b"\x3b\7", b"\x10\1\0", b"\x21\x10"],
        )
        self.assertEqual(data[12], 16)
        comm = Comm([(0, b"\x61\x10\x20"), (0, b"\x61\x10\0")])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2ASUS_04_CheckReturnedVhight", (data,), ctx), 0
        )
        self.assertEqual(ctx.sleeps, [1000, 1000])
        comm = Comm([(8, b"\x61\x10\x10")])
        self.assertEqual(
            engine().run_body("Ex2ASUS_04_CheckReturnedVhight", (data,), Context(comm)),
            8,
        )
        self.assertEqual(data[12], 16)
        comm = Comm([(0, b"\x70")])
        self.assertEqual(
            engine().run_body("Ex2ASUS_04_ReturnVhight", (), Context(comm)), 0
        )

    def test_abs17_support_selected_read_and_two_write_modes(self):
        def snapshot(identifier, payload):
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return (
                0,
                (bytes((identifier, len(payload))) + payload).ljust(0x1020, b"\0"),
                tuple(offsets),
            )

        comm = Comm(
            snapshots=[snapshot(10, bytes([255] * 10)), snapshot(0xF1, b"\xff")]
        )
        data = bytearray(14)
        self.assertEqual(
            engine().run_body("Ex2ABS_17_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(
            tuple(int.from_bytes(data[i : i + 4], "little") for i in (0, 4, 8)),
            (10, 12, 3),
        )
        comm = Comm([(0, b"\x61\x0a" + bytes(8) + b"\xab\xcd")])
        self.assertEqual(
            engine().run_body("Ex2ABS_17_GetABSInfo", (data,), Context(comm)), 0
        )
        self.assertEqual(data[12:14], b"\xab\xcd")
        comm = Comm([(0, b"\x7b\xf1"), (0, b"\x7b\xf1")])
        self.assertEqual(
            engine().run_body("Ex2ABS_17_SychronizingABSInfo", (data,), Context(comm)),
            0,
        )
        self.assertEqual(
            [e[1] for e in comm.events if e[0] == "exchange"],
            [b"\x3b\xf1\2", b"\x3b\xf1\1"],
        )
        comm = Comm([(7, b"")])
        self.assertEqual(
            engine().run_body("Ex2ABS_17_SychronizingABSInfo", (data,), Context(comm)),
            1000,
        )
        comm = Comm(snapshots=[snapshot(10, b"\xff" * 9 + b"\0")])
        data = bytearray(b"\xaa" * 14)
        self.assertEqual(
            engine().run_body("Ex2ABS_17_SupportCheck", (data,), Context(comm)), 22
        )
        self.assertEqual(data[:8], b"\xaa" * 8)

    def test_drs02_selected_counter_and_fault_output_semantics(self):
        def snapshot(identifier, payload):
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return (
                0,
                (bytes((identifier, len(payload))) + payload).ljust(0x1020, b"\0"),
                tuple(offsets),
            )

        selected = Comm(
            snapshots=[
                snapshot(14, b"\0\xff\x3f\0\0\0\x20"),
                snapshot(1, b"\xff\xff\x1f\xff"),
            ]
        )
        layout = bytearray(28)
        self.assertEqual(
            engine().run_body("Ex2DRS_02_SupportCheck", (layout,), Context(selected)), 0
        )
        self.assertEqual(
            tuple(
                int.from_bytes(layout[i : i + 4], "little") for i in (0, 4, 8, 12, 16)
            ),
            (2, 3, 4, 5, 7),
        )
        data = bytearray(28)
        for offset, value in ((0, 3), (4, 4), (8, 5), (12, 6), (16, 7), (20, 2)):
            data[offset : offset + 4] = value.to_bytes(4, "little")
        comm = Comm([(0, b"\x70\1"), (0, b"\x61\x0e\0\x12\xff\x20")])
        self.assertEqual(
            engine().run_body("Ex2DRS_02_ReadRadarCruiseData", (data,), Context(comm)),
            0,
        )
        self.assertEqual(data[24:27], b"\x12\x3f\x20")
        self.assertEqual(int.from_bytes(data[20:24], "little"), 0)
        self.assertIn(("exchange", b"\x30\1\xff\x21\0\6\0"), comm.events)
        comm = Comm([(7, b"\x61\x0e\0\x22\xff\x20"), (8, b"")])
        self.assertEqual(
            engine().run_body("Ex2DRS_02_ReadRadarCruiseData", (data,), Context(comm)),
            7,
        )
        self.assertEqual(data[24:27], b"\x22\x3f\x20")
        self.assertEqual(comm.events[-1], ("finalize",))
        comm = Comm(
            [(0, b"\x70\1"), (0, b"\x61\x0e\0\1\2\x20"), (0, b"\x61\x0e\0\3\4\x20")]
        )
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2DRS_02_ReadModeStatus", (data,), ctx), 0)
        self.assertEqual(ctx.sleeps, [])
        self.assertNotIn(("finalize",), comm.events)

    def test_drs03_mode_success_second_read_retention_and_end_process(self):
        data = bytearray(20)
        data[0], data[4], data[16] = 6, 7, 5
        comm = Comm(
            [(0, b"\x70\1"), (0, b"\x61\x0e\0\1\2\x80"), (0, b"\x61\x0e\0\3\4\x80")]
        )
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2DRS_03_ReadModeStatus", (data,), ctx), 0)
        self.assertEqual(data[12:15], b"\3\4\x80")
        self.assertEqual(ctx.sleeps, [1000])
        self.assertNotIn(("finalize",), comm.events)
        comm = Comm(
            [
                (9, b""),
                (0, b"\x61\x0e\0\0\0\0"),
                (0, b"\x70\1"),
                (0, b"\x61\x0e\4\0\0\0"),
                (8, b""),
            ]
        )
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2DRS_03_EndProcess", (data,), ctx), 0)
        self.assertIn(("exchange", b"\x30\1\xff\x13\0\1\0"), comm.events)
        self.assertEqual(ctx.sleeps, [1000, 1000])
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_drs03_mode_restarts_at_two_seconds_then_times_out(self):
        data = bytearray(20)
        data[0], data[4], data[16] = 6, 7, 5
        start = (0, b"\x70\1")
        pending = (0, b"\x61\x0e\0\0\0\0")
        comm = Comm(
            [start, pending, pending, start, pending, pending, start, pending, (9, b"")]
        )
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2DRS_03_ReadModeStatus", (data,), ctx), 1000
        )
        self.assertEqual(ctx.sleeps, [1000] * 6)
        self.assertEqual(
            sum(e == ("exchange", b"\x30\1\xff\x13\0\0\0") for e in comm.events), 3
        )
        self.assertEqual(comm.events[-2:], [("exchange", b"\x30"), ("finalize",)])

    def test_drs03_support_target_and_selected_retained_read(self):
        def snap(identifier, payload):
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return (
                0,
                (bytes((identifier, len(payload))) + payload).ljust(0x1020, b"\0"),
                tuple(offsets),
            )

        comm = Comm(
            snapshots=[snap(14, b"\4\xff\x3f\0\0\0\x80"), snap(1, b"\xff\xff\x1f\xff")]
        )
        data = bytearray(20)
        self.assertEqual(
            engine().run_body("Ex2DRS_03_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(comm.events[0], ("select_target", 0x790, 0))
        self.assertEqual(
            tuple(int.from_bytes(data[i : i + 4], "little") for i in (0, 4, 16)),
            (6, 7, 5),
        )
        data[8] = 2
        comm = Comm([(0, b"\x70\1"), (0, b"\x61\x0e\0\x12\xff\x80")])
        self.assertEqual(
            engine().run_body("Ex2DRS_03_ReadRadarCruiseData", (data,), Context(comm)),
            0,
        )
        self.assertEqual(data[12:15], b"\x12\x3f\x80")
        self.assertEqual(int.from_bytes(data[8:12], "little"), 0)
        self.assertIn(("exchange", b"\x30\1\xff\x13\0\0\0"), comm.events)
        self.assertNotIn(("finalize",), comm.events)

    def test_abs46_two_stage_pending_and_live_exit_cleanup(self):
        replies = [
            b"\x71\1\x10\7",
            b"\x71\3\x10\7\1",
            b"\x71\3\x10\7\2",
            b"\x71\1\x10\10",
            b"\x71\3\x10\10\2",
        ]
        comm = Comm([(0, reply) for reply in replies])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2ABS_46_SendMessage", (bytearray(4),), ctx), 0
        )
        self.assertEqual(ctx.sleeps, [50, 1000, 1000, 50, 1000, 50])
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])
        data = bytearray(4)
        comm = Comm([(0, replies[0]), (0, replies[1])])
        ctx = Context(comm)
        ctx.on_sleep = lambda ms: data.__setitem__(0, 1) if ms == 1000 else None
        self.assertEqual(engine().run_body("Ex2ABS_46_SendMessage", (data,), ctx), 0)
        self.assertNotIn(("exchange", b"\x31\1\x10\10"), comm.events)
        comm = Comm([(7, b"")], sessions=[0, 9])
        self.assertEqual(
            engine().run_body("Ex2ABS_46_SendMessage", (bytearray(4),), Context(comm)),
            7,
        )

    def test_abs30_native_support_and_action_readback(self):
        replies = [
            b"\x62\1\1\0\0\x80",
            b"\x62\x10\0" + bytes(5) + b"\10",
            b"\x62\x10\x2d\0\0\10",
            b"\x71\1\x10\1\0\0\x40",
            b"\x71\1\x11\0\0\4",
        ]
        comm = Comm([(0, reply) for reply in replies])
        self.assertEqual(
            engine().run_body("Ex2ABS_30_SendMessage", (bytearray(4),), Context(comm)),
            0,
        )
        self.assertNotIn(("configure", "retries", 0), comm.events)
        comm = Comm([(0, b"\x62\1\1\0\0\0")])
        self.assertEqual(
            engine().run_body("Ex2ABS_30_SendMessage", (bytearray(4),), Context(comm)),
            22,
        )
        for bit, expected in ((8, 0), (0, 3)):
            comm = Comm(
                [(0, b"\x71\1\x11\x0e"), (0, b"\x62\x10\x2d\0\0\0" + bytes((bit,)))]
            )
            self.assertEqual(
                engine().run_body(
                    "Ex2ABS_30_SendMessage", (bytearray(b"\1\0\0\0"),), Context(comm)
                ),
                expected,
            )
            self.assertFalse(any(event[0] == "session" for event in comm.events))

    def test_emps07_dtc_gate_raw_assist_word_and_negative_status_mapping(self):
        comm = Comm([(0, b"\x53\2\x55\x81\0\0")])
        self.assertEqual(
            engine().run_body(
                "Ex2EMPS_07_ConfirmTheAssistMap", (bytearray(2),), Context(comm)
            ),
            1001,
        )
        self.assertEqual(sum(e[0] == "exchange" for e in comm.events), 1)
        comm = Comm([(0, b"\x53\1\x12\x34"), (0, b"\xe9\3\x12\x34")])
        data = bytearray(2)
        self.assertEqual(
            engine().run_body("Ex2EMPS_07_ConfirmTheAssistMap", (data,), Context(comm)),
            0,
        )
        self.assertEqual(data, b"\x12\x34")
        for reply, expected in (
            (b"\x7b\2", 0),
            (b"\x7b\3", 3),
            (b"\x7f\x3b\x22", 1002),
            (b"\x7f\x3b\x10", 1003),
        ):
            comm = Comm([(7 if reply[0] == 0x7F else 0, reply)])
            self.assertEqual(
                engine().run_body("Ex2EMPS_07_ClearTheAssistMap", (), Context(comm)),
                expected,
            )
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_drs02_03_stop_preserves_distinct_error_precedence(self):
        for model, expected in (("02", 3), ("03", 7)):
            comm = Comm([(7, b"")])
            self.assertEqual(
                engine().run_body(
                    "Ex2DRS_" + model + "_StopActiveTest", (), Context(comm)
                ),
                expected,
            )
            self.assertEqual(
                comm.events,
                [
                    ("configure", "native_rva:12180", 150),
                    ("exchange", b"\x30"),
                    ("finalize",),
                ],
            )

    def test_asus08_native_retained_mode_and_pressure_status_boundaries(self):
        comm = Comm([(0, b"\x6e\x21\1"), (0, b"\x62\x10\7\3\xe8")])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit", (bytearray(4),), ctx
            ),
            0,
        )
        self.assertEqual(ctx.state["native:1012ae1c"], 1)
        count = len(comm.events)
        data = bytearray(20)
        self.assertEqual(
            engine().run_body("Ex2ASUS_08_ReadPressureSensor", (data,), ctx), 0
        )
        self.assertEqual(comm.events[count:], [("exchange", b"\x22\x10\7")])
        self.assertEqual(struct.unpack_from("<d", data, 8)[0], 0.72)
        for raw, status in ((1779, 1002), (1780, 1003), (2204, 1003), (2205, 1004)):
            comm = Comm([(0, b"\x62\x10\7" + raw.to_bytes(2, "big"))])
            data = bytearray(20)
            self.assertEqual(
                engine().run_body(
                    "Ex2ASUS_08_ReadPressureSensor", (data,), Context(comm)
                ),
                0,
            )
            self.assertEqual(int.from_bytes(data[16:20], "little"), status)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_asus06_07_motion_actual_hidden_request_bytes_and_retention(self):
        for model, action, phases in (
            ("06", "LiftRise", (b"\2\4\x8f",)),
            ("06", "AirPressure", (b"\2\2\x82",)),
            ("07", "LiftRise", (b"\x0c\2\x8a", b"\3\4\xa2")),
            ("07", "AirPressure", (b"\3\2\x88", b"\x0c\4\x91")),
        ):
            data = bytearray(8)
            data[4:8] = (2001).to_bytes(4, "little")
            comm = Comm(
                [
                    (0, value)
                    for _ in phases
                    for value in (b"\x71\1\x11\1", b"\x71\3\x11\1\2")
                ]
            )
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body("Ex2ASUS_" + model + "_" + action, (data,), ctx), 0
            )
            self.assertEqual(
                [e[1] for e in comm.events if e[0] == "exchange" and e[1][1] == 1],
                [b"\x31\1\x11\1" + phase for phase in phases],
            )
            self.assertEqual(ctx.sleeps, [100] * len(phases))
            self.assertEqual(("finalize",) in comm.events, action == "LiftRise")
        comm = Comm([(0, b"\x71\1\x11\1"), (0, b"\x71\3\x11\1\7"), (9, b"")])
        self.assertEqual(
            engine().run_body("Ex2ASUS_06_LiftRise", (bytearray(8),), Context(comm)),
            1002,
        )
        self.assertIn(("exchange", b"\x31\2\x11\1"), comm.events)
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_asus_motion_pending_timeout_uses_native_timer_and_stop(self):
        class TimedComm(Comm):
            def exchange(self, request):
                if request == b"\x31\3\x11\1":
                    ctx.tick = (ctx.tick + 20001) & 0xFFFFFFFF
                return super().exchange(request)

        comm = TimedComm([(0, b"\x71\1\x11\1"), (0, b"\x71\3\x11\1\1"), (9, b"")])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2ASUS_06_LiftRise", (bytearray(8),), ctx), 1001
        )
        self.assertIn(("exchange", b"\x31\2\x11\1"), comm.events)

    def test_asus06_07_condition_retains_success_and_restores_only_failed_write(self):
        for model in ("06", "07"):
            for status, reply in ((0, b"\x6e\x21\1"), (7, b""), (0, b"\x6e\x21\2")):
                comm = Comm([(status, reply)])
                self.assertEqual(
                    engine().run_body(
                        "Ex2ASUS_" + model + "_ConditionCheck", (), Context(comm)
                    ),
                    status or (0 if reply == b"\x6e\x21\1" else 3),
                )
                self.assertNotIn(("configure", "retries", 0), comm.events)
                self.assertEqual(
                    ("finalize",) in comm.events, bool(status or reply != b"\x6e\x21\1")
                )
                self.assertIn(("exchange", b"\x2e\x21\1\1"), comm.events)

    def test_4wd03_support_and_selected_prevention_retention(self):
        def snapshot(identifier):
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return (
                0,
                (bytes((identifier, 2, 128, 1))).ljust(0x1020, b"\0"),
                tuple(offsets),
            )

        comm = Comm(snapshots=[snapshot(0xA6), snapshot(11)])
        data = bytearray(4)
        self.assertEqual(
            engine().run_body("Ex24WD_03_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(data, b"\2\0\0\0")
        for bit, expected in ((128, 0), (0, 1000)):
            comm = Comm(
                [(0, b"\x7b\x0b"), (0, bytes((0x61, 0xA6, bit, 0)))]
                + ([(8, b"")] if not bit else [])
            )
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body("Ex24WD_03_ChangePreventionMode", (data,), ctx),
                expected,
            )
            self.assertEqual(ctx.sleeps, [500])
            self.assertEqual(("exchange", b"\x3b\x0b\0") in comm.events, not bool(bit))
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_plus_asus13_uses_actual_changed_start_stop_payloads(self):
        selected = ChassisEngine(
            replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        )
        data = bytearray(16)
        data[12] = 3
        for suffix, request in (
            ("TestStart", b"\x30\6\xff\4\0\0"),
            ("TestStop", b"\x30\6\xff\10\0\0"),
        ):
            replies = ([(0, b"\x50")] if suffix == "TestStart" else []) + [
                (0, b"\x70\6")
            ]
            comm = Comm(replies)
            self.assertEqual(
                selected.run_body("Ex2ASUS_13_" + suffix, (data,), Context(comm)), 0
            )
            self.assertIn(("configure", "native_rva:142f0", 150), comm.events)
            self.assertIn(("exchange", request), comm.events)
            self.assertTrue(supports(SHA_PLUS_TY, "Ex2ASUS_13_" + suffix))
        comm = Comm()
        with self.assertRaises(ValueError):
            selected.run_body("Ex2ASUS_13_TestStop", (), Context(comm))
        self.assertEqual(comm.events, [])
        comm = Comm([(7, b"\x7f\x3b\x22")])
        self.assertEqual(
            selected.run_body("Ex2EMPS_07_ClearTheAssistMap", (), Context(comm)), 1002
        )
        self.assertIn(("configure", "native_rva:142f0", 150), comm.events)
        data = bytearray(14)
        data[8] = 3
        comm = Comm([(0, b"\x7b\xf1"), (0, b"\x7b\xf1")])
        self.assertEqual(
            selected.run_body("Ex2ABS_17_SychronizingABSInfo", (data,), Context(comm)),
            0,
        )
        self.assertIn(("configure", "native_rva:142f0", 150), comm.events)

    def test_ars02_optional_secondary_record_and_required_six_bytes(self):
        for optional in (False, True):
            raw = b"\x81\2\xff\xff" + (b"\x84\1\xff" if optional else b"")
            offsets = [0x1020] * 256
            offsets[0x81] = 0
            if optional:
                offsets[0x84] = 4
            first = (0, raw.ljust(0x1020, b"\0"), tuple(offsets))
            offsets = [0x1020] * 256
            offsets[2] = 0
            second = (0, b"\2\6".ljust(8, b"\xff").ljust(0x1020, b"\0"), tuple(offsets))
            comm = Comm(snapshots=[first, second])
            data = bytearray(12)
            self.assertEqual(
                engine().run_body("Ex2ARS_02_SupportCheck", (data,), Context(comm)), 0
            )
            self.assertEqual(
                tuple(int.from_bytes(data[i : i + 4], "little") for i in (0, 4, 8)),
                (4, 9, 3 if optional else 0),
            )

    def test_ars01_support_native_counts_and_fail_closed_records(self):
        def snapshot(identifier, payload):
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return (
                0,
                (bytes((identifier, len(payload))) + payload).ljust(0x1020, b"\0"),
                tuple(offsets),
            )

        comm = Comm(snapshots=[snapshot(9, b"\xff\xff\1\0"), snapshot(5, b"\xff\0\2")])
        data = bytearray(8)
        self.assertEqual(
            engine().run_body("Ex2ARS_01_A8SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(data, b"\5\0\0\0\5\0\0\0")
        self.assertEqual(
            comm.events[:2], [("configure", "native_rva:12180", 150), ("initialize", 0)]
        )
        comm = Comm(snapshots=[snapshot(9, b"\xff\x7f")])
        self.assertEqual(
            engine().run_body(
                "Ex2ARS_01_A8SupportCheck", (bytearray(8),), Context(comm)
            ),
            22,
        )
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_asus04_05_support_produces_selected_lengths_and_native_missing_status(
        self,
    ):
        offsets1 = [0x1020] * 256
        offsets1[16] = 0
        first = (0, b"\x10\3\1\0\x30".ljust(0x1020, b"\0"), tuple(offsets1))
        offsets2 = [0x1020] * 256
        offsets2[6] = 0
        second = (0, b"\6\2\1\x80".ljust(0x1020, b"\0"), tuple(offsets2))
        for suffix in ("04", "05"):
            comm = Comm(snapshots=[first, second])
            data = bytearray(12)
            self.assertEqual(
                engine().run_body(
                    "Ex2ASUS_" + suffix + "_SupportCheck", (data,), Context(comm)
                ),
                0,
            )
            self.assertEqual(data, b"\3\0\0\0\4\0\0\0\5\0\0\0")
            comm = Comm(snapshots=[(0, bytes(0x1020), tuple([0x1020] * 256))])
            self.assertEqual(
                engine().run_body(
                    "Ex2ASUS_" + suffix + "_SupportCheck",
                    (bytearray(12),),
                    Context(comm),
                ),
                22,
            )
        comm = Comm(snapshots=[(0, bytes(0x1020), tuple([0x1020] * 256))])
        self.assertEqual(
            engine().run_body(
                "Ex2ARS_01_A8SupportCheck", (bytearray(8),), Context(comm)
            ),
            22,
        )
        comm = Comm(snapshots=[(0, b"", ())])
        with self.assertRaises(ValueError):
            engine().run_body(
                "Ex2ARS_01_A8SupportCheck", (bytearray(8),), Context(comm)
            )
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_asus13_support_consumes_real_a8_record_offsets(self):
        def snapshot(identifier, payload):
            raw = bytes((identifier, len(payload))) + payload
            offsets = [0x1020] * 256
            offsets[identifier] = 0
            return 0, raw.ljust(0x1020, b"\0"), tuple(offsets)

        for first, expected in ((b"\1\0\x30", 0), (b"\1\0\x10", 3)):
            comm = Comm()
            comm.snapshots = [snapshot(16, first), snapshot(6, b"\1\0\x80")]
            data = bytearray(16)
            self.assertEqual(
                engine().run_body("Ex2ASUS_13_SupportCheck", (data,), Context(comm)),
                expected,
            )
            if not expected:
                self.assertEqual(int.from_bytes(data[8:12], "little"), 3)
                self.assertEqual(int.from_bytes(data[12:16], "little"), 2)
            self.assertEqual(comm.events[-1], ("finalize",))
        comm = Comm()
        comm.snapshots = [(7, b"", ())]
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_13_SupportCheck", (bytearray(16),), Context(comm)
            ),
            7,
        )

    def test_bsm03_active_native_selected_result_branches(self):
        for action in (0, 1, 2):
            data = bytearray(36)
            for offset, value in (
                (0, 6),
                (4, 3),
                (8, 3),
                (12, 4),
                (16, 2),
                (20, 2),
                (28, 9),
                (32, action),
            ):
                data[offset : offset + 4] = value.to_bytes(4, "little")
            replies = [(0, b"\x70\11"), (0, b"\x61\x68\x80")]
            if action:
                replies.append(
                    (0, b"\x61\x7b\x12\x34\x56\x78" if action == 1 else b"\x61\x6b\x20")
                )
            comm = Comm(replies + [(9, b"")])
            self.assertEqual(
                engine().run_body("Ex2BSM_03_04_ActiveTest", (data,), Context(comm)),
                0 if action else 9000,
            )
            if action == 1:
                self.assertEqual(data[24:28], b"\x34\x12\x78\x56")
            self.assertEqual(comm.events[-2:], [("exchange", b"\x30"), ("finalize",)])

    def test_bsm05_active_selected_poll_decode_and_timeout_cleanup(self):
        def selection():
            data = bytearray(32)
            for offset, value in (
                (0, 6),
                (4, 3),
                (8, 5),
                (12, 2),
                (16, 2),
                (24, 9),
                (28, 1),
            ):
                data[offset : offset + 4] = value.to_bytes(4, "little")
            return data

        data = selection()
        comm = Comm(
            [
                (0, b"\x70\11"),
                (0, b"\x61\x68\0"),
                (0, b"\x61\x68\x80"),
                (0, b"\x61\x7b\x12\x34\x56\x78"),
                (9, b""),
            ]
        )
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2BSM_05_06_ActiveTest", (data,), ctx), 0)
        self.assertEqual(data[20:24], b"\x34\x12\x78\x56")
        self.assertEqual(ctx.sleeps, [500])
        self.assertIn(("exchange", b"\x30\11\0\x80\0"), comm.events)
        self.assertEqual(comm.events[-2:], [("exchange", b"\x30"), ("finalize",)])
        comm = Comm([(0, b"\x70\11")] + [(0, b"\x61\x68\0")] * 12 + [(0, b"\x70")])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2BSM_05_06_ActiveTest", (selection(),), ctx), 9001
        )
        self.assertEqual(ctx.sleeps, [500] * 11)
        comm = Comm([(8, b"")])
        self.assertEqual(
            engine().run_body("Ex2BSM_05_06_ActiveTest", (selection(),), Context(comm)),
            9001,
        )
        self.assertNotIn(("exchange", b"\x30"), comm.events)
        comm = Comm([(0, b"\x70\11"), (7, b""), (8, b"")])
        self.assertEqual(
            engine().run_body("Ex2BSM_05_06_ActiveTest", (selection(),), Context(comm)),
            7,
        )
        self.assertEqual(comm.events[-2:], [("exchange", b"\x30"), ("finalize",)])

    def test_vgrs04_selected_request_lengths_and_end_cleanup(self):
        comm = Comm([(0, b"\x50"), (0, b"\x70\2")])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body(
                "Ex2VGRS_04_StartLockRelease", (bytearray(b"\5\0\0\0"),), ctx
            ),
            0,
        )
        self.assertEqual(ctx.sleeps, [500])
        self.assertIn(("exchange", b"\x30\2\0\1\0"), comm.events)
        self.assertEqual(
            comm.events[:2], [("configure", "native_rva:12180", 150), ("initialize", 0)]
        )
        comm = Comm([(0, b"\x50"), (8, b""), (9, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2VGRS_04_StartLockRelease", (bytearray(b"\3\0\0\0"),), Context(comm)
            ),
            8,
        )
        self.assertEqual(comm.events[-2:], [("exchange", b"\x30"), ("finalize",)])
        for replies, expected in (
            ([(0, b"\x70"), (0, b"\x50")], 0),
            ([(7, b""), (8, b"")], 3),
            ([(7, b"\x70"), (8, b"")], 7),
        ):
            comm = Comm(replies)
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body("Ex2VGRS_04_EndLockRelease", (), ctx), expected
            )
            self.assertEqual(ctx.sleeps, [500])
        comm = Comm([(0, b"\x54"), (0, b"\x50"), (0, b"\x50")])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2VGRS_04_StartNeutralCompMode", (), ctx), 0
        )
        self.assertEqual(ctx.sleeps, [500, 500])
        self.assertEqual(
            [e[1] for e in comm.events if e[0] == "exchange"],
            [b"\x14", b"\x10\x40", b"\x10\x60"],
        )
        comm = Comm([(0, b"\x50\1")])
        self.assertEqual(
            engine().run_body("Ex2VGRS_04_EndNeutralCompMode", (), Context(comm)), 3
        )
        comm = Comm([(0, b"\x50"), (0, b"\xe6"), (0, b"\x54")])
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2VGRS_04_ClearDTC", (), ctx), 0)
        self.assertEqual(ctx.sleeps, [500, 500])
        self.assertEqual(
            [e[1] for e in comm.events if e[0] == "exchange"],
            [b"\x10\x40", b"\xa6\1", b"\x14"],
        )

    def test_asus13_test_start_builds_selected_zero_tail_and_restores_failure(self):
        data = bytearray(16)
        data[12] = 4
        for reply, expected in ((b"\x70\6", 0), (b"\x70\7", 3), (b"", 3)):
            comm = Comm(
                [(0, b"anything"), (0, reply)] + ([(9, b"")] if expected else [])
            )
            self.assertEqual(
                engine().run_body("Ex2ASUS_13_TestStart", (data,), Context(comm)),
                expected,
            )
            self.assertIn(("exchange", b"\x30\6\x19\1\0\0\0"), comm.events)
            self.assertEqual(("exchange", b"\x10\1") in comm.events, bool(expected))
            self.assertEqual(comm.events[-1], ("finalize",))
        data[12:16] = (0x101E).to_bytes(4, "little")
        comm = Comm()
        with self.assertRaises(ValueError):
            engine().run_body("Ex2ASUS_13_TestStart", (data,), Context(comm))
        self.assertEqual(comm.events, [])

    def test_asus13_height_poll_live_flags_and_manager_retention(self):
        for suffix in ("GetHeight", "GetHeightSec50"):
            data = bytearray(12)
            data[8] = 3
            comm = Comm([(0, b"\x61\x10\0\x20"), (0, b"\x61\x10\0\0")])
            ctx = Context(comm)
            self.assertEqual(engine().run_body("Ex2ASUS_13_" + suffix, (data,), ctx), 0)
            self.assertEqual(ctx.sleeps, [1000, 1000])
            self.assertEqual(("finalize",) in comm.events, suffix.endswith("Sec50"))
            comm = Comm([(8, b"")])
            self.assertEqual(
                engine().run_body("Ex2ASUS_13_" + suffix, (data,), Context(comm)),
                8 if suffix.endswith("Sec50") else 1002,
            )
            comm = Comm()
            data[0] = 1
            self.assertEqual(
                engine().run_body("Ex2ASUS_13_" + suffix, (data,), Context(comm)),
                1003 if suffix.endswith("Sec50") else 1004,
            )
        data = bytearray(12)
        data[8] = 3
        comm = Comm([(0, b"\x61\x10\0\x20")])
        ctx = Context(comm)
        ctx.on_sleep = lambda _: data.__setitem__(4, 1)
        self.assertEqual(engine().run_body("Ex2ASUS_13_GetHeight", (data,), ctx), 1000)
        self.assertNotIn(("finalize",), comm.events)

    def test_asus13_height_offset_native_result_and_restore_precedence(self):
        for flag, expected in ((16, 0), (0, 1003)):
            data = bytearray(12)
            data[8] = 3
            comm = Comm(
                [
                    (0, b"\x7b\x17"),
                    (0, b"\x7b\7"),
                    (0, b"\x61\x10\0" + bytes((flag,))),
                    (0, b"\x50"),
                ]
            )
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body("Ex2ASUS_13_HeightOffset", (data,), ctx), expected
            )
            self.assertEqual(ctx.sleeps, [500, 500])
        comm = Comm([(8, b""), (9, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_13_HeightOffset", (bytearray(12),), Context(comm)
            ),
            8,
        )
        self.assertEqual(comm.events[-2:], [("exchange", b"\x10\1"), ("finalize",)])

    def test_asus13_native_cleanup_status_and_selected_manager(self):
        for suffix, expected in (("NormalMode", 3), ("NormalMode008", 1003)):
            for status, reply, result in (
                (0, b"anything", expected),
                (0, b"", 3),
                (7, b"", 3 if suffix == "NormalMode" else 7),
            ):
                comm = Comm([(status, reply)])
                self.assertEqual(
                    engine().run_body("Ex2ASUS_13_" + suffix, (), Context(comm)), result
                )
                self.assertEqual(comm.events, [("exchange", b"\x10\1"), ("finalize",)])
        for start, normal, expected in (
            ((0, b"\x70\6"), (0, b"\x50"), 1001),
            ((8, b""), (9, b""), 8),
            ((0, b"\x70\7"), (0, b"\x50"), 3),
            ((0, b"\x70\6"), (9, b""), 9),
        ):
            comm = Comm([start, normal])
            self.assertEqual(
                engine().run_body("Ex2ASUS_13_NormalMode005", (), Context(comm)),
                expected,
            )
            self.assertEqual(comm.events[-2:], [("exchange", b"\x10\1"), ("finalize",)])
        comm = Comm([(0, b"\x70")])
        self.assertEqual(engine().run_body("Ex2ASUS_13_TestStop", (), Context(comm)), 0)
        self.assertEqual(
            comm.events,
            [
                ("initialize", 0),
                ("configure", "native_rva:12180", 150),
                ("exchange", b"\x30"),
                ("finalize",),
            ],
        )

    def test_emps09_support_conditional_read_and_native_zero_fill(self):
        for flags, expected in (
            (b"\x20\x80", (1, 1)),
            (b"\0\0", (0, 0)),
            (b"\x20", (1, 0)),
        ):
            comm = Comm([(0, b"\x71\1\x10\1\0\0\x40"), (0, b"\x71\1\x11\0" + flags)])
            data = bytearray(b"\xaa" * 8)
            self.assertEqual(
                engine().run_body("Ex2EMPS_09_SupportCheck", (data,), Context(comm)), 0
            )
            self.assertEqual(
                tuple(int.from_bytes(data[i : i + 4], "little") for i in (0, 4)),
                expected,
            )
        comm = Comm([(0, b"\x71\1\x10\1\0\0\0")])
        data = bytearray(b"\xaa" * 8)
        self.assertEqual(
            engine().run_body("Ex2EMPS_09_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(data, bytes(8))
        self.assertEqual(sum(event[0] == "exchange" for event in comm.events), 1)
        comm = Comm([(7, b"")], sessions=[0, 0, 8])
        self.assertEqual(
            engine().run_body(
                "Ex2EMPS_09_SupportCheck", (bytearray(8),), Context(comm)
            ),
            7,
        )
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_read_retains_live_session_and_copies_bit(self):
        comm = Comm([(0, b"\x62\x11\xa6\xff\x10")])
        data = bytearray(4)
        self.assertEqual(
            engine().run_body("Ex2AHC_03_ReadModeStatus", (data,), Context(comm)), 0
        )
        self.assertEqual(data, b"\x01\0\0\0")
        self.assertNotIn(("finalize",), comm.events)
        self.assertIn(("configure", "pending", 180000), comm.events)
        self.assertEqual(
            [e for e in comm.events if e[0] == "session"],
            [("session", 1, 1), ("session", 3, 1)],
        )

    def test_short_or_wrong_echo_restores_then_closes(self):
        for reply in (
            b"\x62\x11\xa6\x10",
            b"\x62\x11\xa7\0\x10",
            b"\x63\x11\xa6\0\x10",
        ):
            with self.subTest(reply=reply):
                comm = Comm([(0, reply)])
                data = bytearray(b"\x55" * 4)
                self.assertEqual(
                    engine().run_body(
                        "Ex2AHC_03_ReadModeStatus", (data,), Context(comm)
                    ),
                    3,
                )
                self.assertEqual(data, b"\x55" * 4)
                self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_mode_switch_uses_boolean_input_then_readback(self):
        for value, byte in ((0, 255), (1, 0), (0xFFFFFFFF, 0)):
            comm = Comm([(0, b"\x71\x01\x11\xa6"), (0, b"\x62\x11\xa6\0\0")])
            ctx = Context(comm)
            data = bytearray(value.to_bytes(4, "little"))
            self.assertEqual(
                engine().run_body("Ex2AHC_03_SwitchServiceMode", (data,), ctx), 0
            )
            self.assertIn(
                ("exchange", b"\x31\x01\x11\xa6" + bytes((byte,))), comm.events
            )
            self.assertEqual(ctx.sleeps, [200])
            self.assertEqual(data, b"\0" * 4)

    def test_end_discards_restore_status(self):
        comm = Comm(sessions=[37])
        self.assertEqual(
            engine().run_body("Ex2AHC_03_EndExtendedSession", (), Context(comm)), 1000
        )
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_auto_start_retains_session_on_success(self):
        comm = Comm([(0, b"\x71\x01\x11\x0a")])
        self.assertEqual(
            engine().run_body("Ex2EMPS_12_AutoRackCentering", (), Context(comm)), 0
        )
        self.assertNotIn(("finalize",), comm.events)

    def test_plus_emps_steering_start_modes_and_fault_cleanup(self):
        contract = replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        for mode in (20, 21, 22):
            with self.subTest(mode=mode):
                comm = Comm()
                ctx = Context(comm)
                ctx.mode = mode
                managers = []
                ctx.comm = lambda kind, comm=comm, managers=managers: (
                    managers.append(kind) or comm
                )
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2EMPS_12_SteeringStart", (), ctx
                    ),
                    0,
                )
                self.assertEqual(
                    [event for event in comm.events if event[0] == "configure"],
                    [
                        ("configure", "native_rva:1e290", 0),
                        ("configure", "native_rva:1e2b0", 180000),
                        ("configure", "native_rva:1e2d0", 0),
                    ],
                )
                self.assertEqual(
                    [event for event in comm.events if event[0] == "session"],
                    [("session", 1, 1), ("session", 3, 1)],
                )
                self.assertEqual(
                    managers,
                    ["native:1013e7d0" if mode == 22 else "native:101392d0"],
                )
                self.assertNotIn(("finalize",), comm.events)

        for mode in (20, 22):
            with self.subTest(mode=mode, phase="session fault"):
                comm = Comm(sessions=[9])
                ctx = Context(comm)
                ctx.mode = mode
                ctx.comm = lambda kind, comm=comm: comm
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2EMPS_12_SteeringStart", (), ctx
                    ),
                    9,
                )
                self.assertEqual(
                    [event for event in comm.events if event[0] == "session"],
                    [("session", 1, 1)],
                )
                self.assertEqual(comm.events[-1], ("finalize",))

        comm = Comm(initial=8)
        ctx = Context(comm)
        ctx.mode = 22
        ctx.comm = lambda kind: comm
        self.assertEqual(
            ChassisEngine(contract).run_body("Ex2EMPS_12_SteeringStart", (), ctx), 8
        )
        self.assertFalse(
            any(event[0] in ("configure", "session") for event in comm.events)
        )
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_plus_emps_auto_rack_modern_and_nk_vectors(self):
        contract = replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        for mode in (20, 21):
            with self.subTest(mode=mode):
                comm = Comm([(0, b"\x00\x01\x11\x0a")])
                ctx = Context(comm)
                ctx.mode = mode
                managers = []
                ctx.comm = lambda kind, comm=comm, managers=managers: (
                    managers.append(kind) or comm
                )
                unused = bytearray(b"caller")
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2EMPS_12_AutoRackCentering", (unused,), ctx
                    ),
                    0,
                )
                self.assertEqual(unused, b"caller")
                self.assertIn(("exchange", b"\x31\x01\x11\x0a"), comm.events)
                self.assertEqual(managers, ["native:101392d0"])
                self.assertNotIn(("finalize",), comm.events)

        data = bytearray(0x1038)
        comm = Comm(
            [
                (0, b"\x62\x20\x13\xaa\xbb\xcc"),
                (0, b"\x00\x20\x13"),
                (0, b"\x00\x01\x11\x0a\x00"),
            ]
        )
        ctx = Context(comm)
        ctx.mode = 22
        managers = []
        ctx.comm = lambda kind, comm=comm, managers=managers: (
            managers.append(kind) or comm
        )
        self.assertEqual(
            ChassisEngine(contract).run_body(
                "Ex2EMPS_12_AutoRackCentering", (data,), ctx
            ),
            0,
        )
        self.assertEqual(
            [event[1] for event in comm.events if event[0] == "exchange"],
            [b"\x22\x20\x13", b"\x2e\x20\x13\x01\x90\xcc", b"\x31\x01\x11\x0a"],
        )
        self.assertEqual(data[0x13:0x19], b"\x62\x20\x13\xaa\xbb\xcc")
        self.assertEqual(int.from_bytes(data[0x1034:0x1038], "little"), 6)
        self.assertEqual(managers, ["native:1013e7d0"])
        self.assertNotIn(("finalize",), comm.events)

    def test_plus_emps_auto_rack_nk_fault_and_minimum_lengths(self):
        contract = replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        for replies, expected, expected_requests in (
            (
                [(0, b"\x62\x20\x13\xaa\xbb\xcc"), (9, b"")],
                9,
                2,
            ),
            (
                [
                    (0, b"\x62\x20\x13\xaa\xbb\xcc"),
                    (0, b"\x6e\x20\x13"),
                    (0, b"\x71\x01\x11\x0a"),
                ],
                3,
                3,
            ),
        ):
            with self.subTest(expected=expected):
                data = bytearray(0x1038)
                comm = Comm(replies, sessions=[0, 0, 31] if expected == 9 else [])
                ctx = Context(comm)
                ctx.mode = 22
                ctx.comm = lambda kind, comm=comm: comm
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2EMPS_12_AutoRackCentering", (data,), ctx
                    ),
                    expected,
                )
                self.assertEqual(
                    len([event for event in comm.events if event[0] == "exchange"]),
                    expected_requests,
                )
                self.assertIn(("session", 1, 1), comm.events)
                self.assertEqual(comm.events[-1], ("finalize",))
                if expected == 9:
                    self.assertEqual(
                        [event for event in comm.events if event[0] == "session"],
                        [("session", 1, 1), ("session", 3, 1), ("session", 1, 1)],
                    )
                    self.assertEqual(data[0x13:0x19], b"\x62\x20\x13\xaa\xbb\xcc")
                    self.assertEqual(int.from_bytes(data[0x1034:0x1038], "little"), 6)

        for mode, args in ((22, (bytearray(0x1037),)), (22, ())):
            with self.subTest(mode=mode, args=len(args)):
                comm = Comm()
                ctx = Context(comm)
                ctx.mode = mode
                ctx.comm = lambda kind, comm=comm: comm
                with self.assertRaises(ValueError):
                    ChassisEngine(contract).run_body(
                        "Ex2EMPS_12_AutoRackCentering", args, ctx
                    )
                self.assertEqual(comm.events, [])

    def test_plus_emps_steering_angle_live_loop_echo_and_cleanup(self):
        contract = replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        for mode in (20, 22):
            with self.subTest(mode=mode, phase="live reply"):
                data = bytearray(19)

                class LiveComm(Comm):
                    def __init__(self, replies, live_data):
                        super().__init__(replies)
                        self.live_data = live_data

                    def exchange(self, request):
                        result = super().exchange(request)
                        self.live_data[8:12] = (1).to_bytes(4, "little")
                        return result

                comm = LiveComm([(0, b"\x00\x11\x2e\x12\x34")], data)
                ctx = Context(comm)
                ctx.mode = mode
                managers = []
                ctx.comm = lambda kind, comm=comm, managers=managers: (
                    managers.append(kind) or comm
                )
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2EMPS_12_SteeringAngleCheck", (data,), ctx
                    ),
                    0,
                )
                self.assertEqual(data[17:19], b"\x12\x34")
                self.assertEqual(int.from_bytes(data[12:16], "little"), 1)
                self.assertEqual(
                    managers,
                    ["native:1013e7d0" if mode == 22 else "native:101392d0"],
                )
                self.assertNotIn(("initialize", 0), comm.events)
                self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

            with self.subTest(mode=mode, phase="initial exit"):
                data = bytearray(19)
                data[8:12] = (1).to_bytes(4, "little")
                comm = Comm(sessions=[9])
                ctx = Context(comm)
                ctx.mode = mode
                ctx.comm = lambda kind, comm=comm: comm
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2EMPS_12_SteeringAngleCheck", (data,), ctx
                    ),
                    0,
                )
                self.assertFalse(any(event[0] == "exchange" for event in comm.events))
                self.assertEqual(comm.events[-1], ("finalize",))

            with self.subTest(mode=mode, phase="exchange fault"):
                data = bytearray(19)
                comm = Comm([(9, b"\x62\x11\x2e\x12\x34")])
                ctx = Context(comm)
                ctx.mode = mode
                ctx.comm = lambda kind, comm=comm: comm
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2EMPS_12_SteeringAngleCheck", (data,), ctx
                    ),
                    9,
                )
                self.assertEqual(data[12:19], bytes(7))
                self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_plus_emps_host_faults_release_retained_normal_and_preserve_exception(self):
        contract = replace(CONTRACT_PLUS, source_sha256=Context.module_sha256)
        primary = RuntimeError("primary SDK failure")
        cleanup_failure = RuntimeError("secondary cleanup failure")

        class FaultComm(Comm):
            def __init__(self, fail_cleanup):
                super().__init__()
                self.fail_cleanup = fail_cleanup

            def exchange(self, request):
                self.events.append(("exchange", request))
                raise primary

            def cleanup_session(self, mode, keepalive=1, **kwargs):
                self.events.append(("cleanup_session", mode, keepalive))
                if self.fail_cleanup:
                    raise cleanup_failure
                return self.session(mode, keepalive, **kwargs)

        for export, args in (
            ("Ex2EMPS_12_AutoRackCentering", ()),
            ("Ex2EMPS_12_SteeringAngleCheck", (bytearray(19),)),
        ):
            for fail_cleanup in (False, True):
                with self.subTest(export=export, fail_cleanup=fail_cleanup):
                    comm = FaultComm(fail_cleanup)
                    ctx = Context(comm)
                    ctx.mode = 20
                    ctx.comm = lambda kind, comm=comm: comm
                    with self.assertRaises(RuntimeError) as raised:
                        ChassisEngine(contract).run_body(export, args, ctx)
                    self.assertIs(raised.exception, primary)
                    self.assertEqual(comm.events.count(("cleanup_session", 1, 1)), 1)
                    self.assertEqual(comm.events.count(("finalize",)), 1)
                    if fail_cleanup:
                        self.assertEqual(
                            comm.events[-2:],
                            [
                                ("cleanup_session", 1, 1),
                                ("finalize",),
                            ],
                        )
                    else:
                        self.assertEqual(
                            comm.events[-3:],
                            [
                                ("cleanup_session", 1, 1),
                                ("session", 1, 1),
                                ("finalize",),
                            ],
                        )

        class CleanupComm(Comm):
            def cleanup_session(self, mode, keepalive=1, **kwargs):
                self.events.append(("cleanup_session", mode, keepalive))
                return self.session(mode, keepalive, **kwargs)

        comm = CleanupComm()
        ctx = Context(comm)
        ctx.mode = 20
        ctx.cancelled = True
        ctx.comm = lambda kind, comm=comm: comm
        self.assertEqual(
            ChassisEngine(contract).run_body(
                "Ex2EMPS_12_SteeringAngleCheck", (bytearray(19),), ctx
            ),
            1000,
        )
        self.assertEqual(
            comm.events[-3:],
            [("cleanup_session", 1, 1), ("session", 1, 1), ("finalize",)],
        )

    def test_poll_pending_then_complete(self):
        comm = Comm([(0, b"\x71\x03\x11\x0a\1"), (0, b"\x71\x03\x11\x0a\2")])
        ctx = Context(comm)
        data = bytearray(20)
        self.assertEqual(
            engine().run_body("Ex2EMPS_12_ReadRoutineStatus", (data,), ctx), 0
        )
        self.assertEqual(data[16], 2)
        self.assertEqual(ctx.sleeps, [500, 500])
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_poll_cancel_unknown_and_driver_fault_preserve_primary_error(self):
        for flag, replies, expected in (
            (1, [(9, b"")], 1000),
            (0, [(0, b"\x71\x03\x11\x0a\3"), (9, b"")], 1001),
            (0, [(27, b""), (9, b"")], 27),
        ):
            comm = Comm(replies, sessions=[91])
            data = bytearray(20)
            data[0] = flag
            self.assertEqual(
                engine().run_body(
                    "Ex2EMPS_12_ReadRoutineStatus", (data,), Context(comm)
                ),
                expected,
            )
            self.assertIn(("exchange", b"\x31\x02\x11\x0a"), comm.events)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_angle_buffer_publication_and_live_stop(self):
        comm = Comm([(0, b"\x62\x11\x2e\x34\x12")])
        data = bytearray(19)

        class LiveComm(Comm):
            def exchange(self, request):
                result = super().exchange(request)
                data[8] = 1
                return result

        comm = LiveComm(comm.replies)
        self.assertEqual(
            engine().run_body("Ex2EMPS_12_SteeringAngleCheck", (data,), Context(comm)),
            0,
        )
        self.assertEqual(data[17:19], b"\x34\x12")
        self.assertEqual(data[12:16], b"\1\0\0\0")

    def test_abs47_dealer_mode_bit_and_fault_mapping(self):
        for reply, expected in (
            (b"\x62\x10\x2d" + bytes(9) + b"\x08", 0),
            (b"\x62\x10\x2d" + bytes(10), 1001),
        ):
            comm = Comm([(0, b"\x71\x01\x11\x0c"), (0, reply)])
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body("Ex2ABS_47_ShiftToDealerMode", (), ctx), expected
            )
            self.assertEqual(ctx.sleeps, [4000])
            self.assertEqual(("finalize",) in comm.events, bool(expected))

    def test_abs47_calibration_updates_seven_strided_bits(self):
        data = bytearray(85)

        class LiveComm(Comm):
            def exchange(self, request):
                result = super().exchange(request)
                data[0] = 1
                return result

        comm = LiveComm([(0, b"\x62\x10\xb4\0\xaa")])
        self.assertEqual(
            engine().run_body(
                "Ex2ABS_47_CheckCalibrationStatus", (data,), Context(comm)
            ),
            1000,
        )
        self.assertEqual([data[i * 12] for i in range(1, 8)], [1, 0, 1, 0, 1, 0, 1])
        self.assertNotIn(("finalize",), comm.events)

    def test_motor_failure_sends_stop_and_maps_1000(self):
        comm = Comm([(7, b""), (8, b"")], sessions=[0, 0, 9])
        self.assertEqual(
            engine().run_body("Ex2ABS_41_DriveMotor", (), Context(comm)), 1000
        )
        self.assertIn(("exchange", b"\x2f\x28\x02\0\0\0\0\x08"), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_motor_success_and_stop_restore_status(self):
        comm = Comm([(0, b"\x6f\x28\x02\x03")])
        self.assertEqual(
            engine().run_body("Ex2ABS_41_DriveMotor", (), Context(comm)), 0
        )
        self.assertNotIn(("finalize",), comm.events)
        comm = Comm([(0, b"\x6f\x28\x02\0")], sessions=[25])
        self.assertEqual(
            engine().run_body("Ex2ABS_41_StopMotor", (), Context(comm)), 25
        )

    def test_abs49_refresh_and_explicit_exit(self):
        comm = Comm([(0, b"\x71\x01\x11\x66")])
        self.assertEqual(
            engine().run_body("Ex2ABS_49_StartSLM2Refresh", (), Context(comm)), 0
        )
        self.assertNotIn(("finalize",), comm.events)
        for suffix, expected in (("Exit", 1001), ("Error", 1004)):
            comm = Comm([(9, b"")], sessions=[8])
            self.assertEqual(
                engine().run_body(
                    "Ex2ABS_49_PatternDriveExecutingFlag" + suffix, (), Context(comm)
                ),
                expected,
            )
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_abs49_flag_poll_and_source_native_retention(self):
        for flag, expected in ((0, 1000), (4, 1003)):
            comm = Comm()
            data = bytearray(8)
            data[flag] = 1
            self.assertEqual(
                engine().run_body(
                    "Ex2ABS_49_PatternDriveExecutingFlag", (data,), Context(comm)
                ),
                expected,
            )
            self.assertEqual(comm.events, [])
        comm = Comm(
            [
                (0, b"\x62\x10\x2d" + bytes(13) + b"\x40"),
                (0, b"\x62\x10\x2d" + bytes(14)),
            ]
        )
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body(
                "Ex2ABS_49_PatternDriveExecutingFlag", (bytearray(8),), ctx
            ),
            0,
        )
        self.assertEqual(ctx.sleeps, [1000, 1000])
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_abs48_start_stop_and_failure_cleanup(self):
        for suffix, rid in (
            ("StartECBProhibitionControl", 0x35),
            ("StartRearAirBleedingDrive", 0x69),
        ):
            comm = Comm([(0, bytes((0x71, 1, 0x11, rid)))])
            self.assertEqual(
                engine().run_body("Ex2ABS_48_" + suffix, (), Context(comm)), 0
            )
            self.assertNotIn(("finalize",), comm.events)
            comm = Comm([(7, b""), (9, b"")])
            ctx = Context(comm)
            self.assertEqual(engine().run_body("Ex2ABS_48_" + suffix, (), ctx), 7)
            self.assertIn(("exchange", bytes((0x31, 2, 0x11, rid))), comm.events)
            self.assertEqual(ctx.sleeps, [3000] if rid == 0x69 else [])
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_abs47_support_native_chain_and_sparse_ui_flags(self):
        def frame(prefix, length, fields):
            value = bytearray(prefix + bytes(length - len(prefix)))
            for offset, bits in fields:
                value[offset] = bits
            return bytes(value)

        replies = [
            frame(b"\x62\1\1", 35, ((5, 128),)),
            frame(b"\x62\x10\0", 35, ((8, 8), (25, 16))),
            frame(b"\x62\x10\x2d", 12, ((11, 8),)),
            b"\x62\x10\xb4\xa2\0",
            frame(b"\x71\1\x10\1", 36, ((6, 64),)),
            frame(b"\x71\1\x11\0", 36, ((5, 16),)),
        ]
        data = bytearray(b"\xcc" * 80)
        comm = Comm([(0, value) for value in replies])
        self.assertEqual(
            engine().run_body("Ex2ABS_47_DIDRIDSupportCheck", (data,), Context(comm)), 0
        )
        for index, expected in enumerate((1, 0, 1, 0, 0, 0, 1)):
            self.assertEqual(
                int.from_bytes(data[4 + 12 * index : 8 + 12 * index], "little"),
                expected,
            )
        self.assertEqual(data[:4], b"\xcc" * 4)
        self.assertEqual(data[8:16], b"\xcc" * 8)
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])
        for stage in range(6):
            for status, reply, expected in (
                (17, b"", 17),
                (0, b"", 3),
                (0, bytes(len(replies[stage])), 3),
            ):
                comm = Comm(
                    [(0, value) for value in replies[:stage]] + [(status, reply)]
                )
                self.assertEqual(
                    engine().run_body(
                        "Ex2ABS_47_DIDRIDSupportCheck", (bytearray(80),), Context(comm)
                    ),
                    expected,
                )
                self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])
        comm = Comm([(0, value) for value in replies], sessions=[0, 0, 29])
        self.assertEqual(
            engine().run_body(
                "Ex2ABS_47_DIDRIDSupportCheck", (bytearray(80),), Context(comm)
            ),
            29,
        )

    def test_abs48_fixed_exit_statuses_and_wait_retention(self):
        for suffix, expected in (
            ("StopTheRoutineControl", 0),
            ("StopTheRoutine", 0),
            ("StopTheRoutineTimeOver", 3),
        ):
            comm = Comm([(9, b"")], sessions=[8])
            self.assertEqual(
                engine().run_body("Ex2ABS_48_" + suffix, (), Context(comm)), expected
            )
            self.assertEqual(comm.events[-1], ("finalize",))
        comm = Comm()
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2ABS_48_RetrunWait", (), ctx), 1001)
        self.assertEqual(ctx.sleeps, [20000])
        self.assertEqual(comm.events, [])

    def test_abs31_support_selection_and_final_routine_status(self):
        for selected in (False, True):
            for observed in (False, True):
                replies = (
                    b"\x62\1\1\0\0\x80",
                    b"\x62\x10\0" + bytes(8) + b"\x0c",
                    b"\x62\x10\x46" + bytes((2 if selected else 0,)),
                    b"\x71\1\x10\1\0\0\x40",
                    b"\x71\1\x11\0\0" + bytes((8 if observed else 0,)) + b"\x08",
                )
                comm = Comm([(0, reply) for reply in replies])
                data = bytearray(b"\xaa" * 8)
                expected = 0 if selected == observed else 3
                self.assertEqual(
                    engine().run_body("Ex2ABS_31_SupportCheck", (data,), Context(comm)),
                    expected,
                )
                self.assertEqual(
                    int.from_bytes(data[4:8], "little"),
                    int(not selected and not observed),
                )
                self.assertEqual(comm.events[-1], ("finalize",))

    def test_abs31_routine_readback_and_single_native_retry(self):
        for action, expected_byte in ((1, 0), (2, 2)):
            for observed in (0, 2):
                comm = Comm(
                    [
                        (0, b"\x71\1\x11\x0d"),
                        (0, b"\x62\x10\x46\0" + bytes((observed,))),
                    ]
                )
                ctx = Context(comm)
                self.assertEqual(
                    engine().run_body(
                        "Ex2ABS_31_RoutineStart",
                        (bytearray(action.to_bytes(4, "little")),),
                        ctx,
                    ),
                    0 if observed == expected_byte else 3,
                )
                self.assertEqual(ctx.sleeps, [3000])
        comm = Comm(
            [
                (0, b"\x71\1\x11\x15"),
                (0, b"\x62\x10\x45\1\0"),
                (0, b"\x71\1\x11\x15"),
                (0, b"\x62\x10\x45\0\0"),
            ],
            sessions=[0, 0, 9],
        )
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2ABS_31_RoutineStart", (bytearray(b"\3\0\0\0"),), ctx),
            0,
        )
        self.assertEqual(ctx.sleeps, [4000, 5000, 4000])
        for replies in ([(5, b"")], [(0, b"\x71\1\x11\x15"), (6, b"")]):
            comm = Comm(replies)
            self.assertEqual(
                engine().run_body(
                    "Ex2ABS_31_RoutineStart", (bytearray(b"\3\0\0\0"),), Context(comm)
                ),
                3,
            )
            self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_abs48_wait_never_acquires_manager_and_propagates_interruption(self):
        class InterruptedWait(RuntimeError):
            pass

        ctx = Context(Comm())

        def no_manager(kind):
            self.fail("native wait must not acquire a communication manager")

        def interrupted(ms):
            self.assertEqual(ms, 20000)
            raise InterruptedWait

        ctx.comm = no_manager
        self.assertEqual(engine().run_body("Ex2ABS_48_RetrunWait", (), ctx), 1001)
        ctx.sleep = interrupted
        with self.assertRaises(InterruptedWait):
            engine().run_body("Ex2ABS_48_RetrunWait", (), ctx)
        with self.assertRaises(ValueError):
            engine().run_body("Ex2ABS_48_RetrunWait", (bytearray(4),), ctx)

    def test_abs48_confirm_bit_and_vacuum_payload_mutation(self):
        for value, expected in ((128, 0), (0, 3)):
            comm = Comm([(0, b"\x62\x20\x02" + bytes((value,)))])
            self.assertEqual(
                engine().run_body("Ex2ABS_48_ConfirmBitInformation", (), Context(comm)),
                expected,
            )
        comm = Comm(
            [
                (0, b"\x62\x20\x02\x55\x11\x22\x33"),
                (0, b"\x6e\x20\x02"),
                (0, b"\x62\x20\x02\x55\x80"),
            ]
        )
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2ABS_48_VacuumFillingIncomplete", (), ctx), 0
        )
        self.assertIn(("exchange", b"\x2e\x20\x02\x55\x80\x22\x33"), comm.events)
        self.assertEqual(ctx.sleeps, [1000])

    def test_abs52_selected_readback_and_mismatch(self):
        payload = bytes(range(16))
        for writing, second, expected in (
            (False, payload, 0),
            (True, payload, 0),
            (True, bytes(16), 3),
        ):
            replies = ([(0, b"\x6e\x20\x07")] if writing else []) + [
                (0, b"\x62\x10\xb9" + payload),
                (0, b"\x62\x20\x07" + second),
            ]
            comm = Comm(replies)
            ctx = Context(comm)
            data = bytearray(52)
            data[36:52] = payload
            export = (
                "Ex2ABS_52_"
                + ("Write" if writing else "Read")
                + "BrakePadResidualThickness"
            )
            self.assertEqual(engine().run_body(export, (data,), ctx), expected)
            self.assertEqual(data[4:20], payload)
            self.assertEqual(data[20:36], second)
            self.assertEqual(ctx.sleeps, [1000] if writing else [])
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_plus_abs52_exports_and_echo_only_read(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        self.assertTrue(
            supports(SHA_PLUS_TY, "Ex2ABS_52_ReadBrakePadResidualThickness")
        )
        self.assertTrue(
            supports(SHA_PLUS_TY, "Ex2ABS_52_WriteBrakePadResidualThickness")
        )
        payload = bytes(range(32))
        comm = Comm(
            [
                (0, b"\x00\x10\xb9" + payload[:16]),
                (0, b"\x00\x20\x07" + payload[16:]),
            ]
        )
        data = bytearray([0xAA] * 52)
        result = ChassisEngine(contract).run_body(
            "Ex2ABS_52_ReadBrakePadResidualThickness", (data,), Context(comm)
        )
        self.assertEqual(result, 0)
        self.assertEqual(data[0:4], b"\xaa" * 4)
        self.assertEqual(data[4:36], payload)

    def test_plus_abs52_partial_read_and_numeric_status_precedence(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        first = bytes(range(16))
        comm = Comm([(0, b"\x00\x10\xb9" + first), (77, b"")], sessions=[0, 0, 99])
        data = bytearray([0xAA] * 52)
        self.assertEqual(
            ChassisEngine(contract).run_body(
                "Ex2ABS_52_ReadBrakePadResidualThickness", (data,), Context(comm)
            ),
            77,
        )
        self.assertEqual(data[4:20], first)
        self.assertEqual(data[20:36], b"\xaa" * 16)
        self.assertEqual(data[0:4], b"\xaa" * 4)
        self.assertEqual(
            [event[1] for event in comm.events if event[0] == "exchange"],
            [b"\x22\x10\xb9", b"\x22\x20\x07"],
        )

    def test_plus_abs52_read_rejects_short_or_wrong_echo_without_publish(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        for reply in (b"\x00\x10\xb9" + bytes(15), b"\x00\x10\xba" + bytes(16)):
            with self.subTest(reply_length=len(reply), echo=reply[1:3]):
                comm = Comm([(0, reply)])
                data = bytearray([0xAA] * 36)
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2ABS_52_ReadBrakePadResidualThickness",
                        (data,),
                        Context(comm),
                    ),
                    3,
                )
                self.assertEqual(data, b"\xaa" * 36)

    def test_plus_abs52_write_accepts_extra_echo_bytes_and_compares_live_ui(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        payload = bytes(range(16))
        comm = Comm(
            [
                (0, b"\x00\x20\x07\xaa\xbb"),
                (0, b"\x00\x10\xb9" + payload),
                (0, b"\x00\x20\x07" + payload),
            ],
            sessions=[0, 0, 99],
        )
        ctx = Context(comm)
        data = bytearray(52)
        data[36:52] = payload
        ctx.on_sleep = lambda ms: data.__setitem__(slice(36, 52), b"Z" * 16)
        self.assertEqual(
            ChassisEngine(contract).run_body(
                "Ex2ABS_52_WriteBrakePadResidualThickness", (data,), ctx
            ),
            3,
        )
        self.assertEqual(
            [event[1] for event in comm.events if event[0] == "exchange"],
            [b"\x2e\x20\x07" + payload, b"\x22\x10\xb9", b"\x22\x20\x07"],
        )
        self.assertEqual(ctx.sleeps, [1000])
        self.assertEqual(data[4:20], payload)
        self.assertEqual(data[20:36], payload)

    def test_plus_abs52_write_primitive_failure_skips_sleep_and_readback(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        comm = Comm([(77, b"")], sessions=[0, 0, 99])
        ctx = Context(comm)
        data = bytearray(52)
        self.assertEqual(
            ChassisEngine(contract).run_body(
                "Ex2ABS_52_WriteBrakePadResidualThickness", (data,), ctx
            ),
            77,
        )
        self.assertEqual(ctx.sleeps, [])
        self.assertEqual(
            [event[1] for event in comm.events if event[0] == "exchange"],
            [b"\x2e\x20\x07" + bytes(16)],
        )

    def test_plus_abs52_initialization_exception_preserves_primary_without_normal(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        primary = RuntimeError("activation failed")
        secondary = RuntimeError("disconnect failed")

        class FaultingComm(Comm):
            def session(self, mode, keepalive=1, **kwargs):
                self.events.append(("session", mode, keepalive))
                raise primary

            def finalize(self):
                self.events.append(("finalize",))
                raise secondary

        comm = FaultingComm()
        ctx = Context(comm)
        with self.assertRaises(RuntimeError) as raised:
            ChassisEngine(contract).run_body(
                "Ex2ABS_52_ReadBrakePadResidualThickness", (bytearray(36),), ctx
            )
        self.assertIs(raised.exception, primary)
        self.assertEqual(
            [event for event in comm.events if event[0] == "session"],
            [("session", 1, 1)],
        )
        self.assertEqual(
            [event for event in comm.events if event[0] == "finalize"],
            [("finalize",)],
        )

    def test_plus_abs52_host_fault_stages_cleanup_and_preserve_identity(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        payload = bytes(range(16))
        for stage in ("write", "sleep", "firstread", "secondread"):
            with self.subTest(stage=stage):
                primary = RuntimeError(stage)
                secondary = RuntimeError("cleanup failed")

                class FaultingComm(Comm):
                    def exchange(self, request, *, fault_stage=stage, error=primary):
                        self.events.append(("exchange", request))
                        if fault_stage == "write" and request.startswith(b"\x2e"):
                            raise error
                        if fault_stage == "firstread" and request == b"\x22\x10\xb9":
                            raise error
                        if fault_stage == "secondread" and request == b"\x22\x20\x07":
                            raise error
                        if request.startswith(b"\x2e"):
                            return 0, b"\x00\x20\x07"
                        if request == b"\x22\x10\xb9":
                            return 0, b"\x00\x10\xb9" + payload
                        return 0, b"\x00\x20\x07" + payload

                    def cleanup_session(
                        self, mode, keepalive=1, *, error=secondary, **kwargs
                    ):
                        self.events.append(("cleanup_session", mode, keepalive))
                        raise error

                    def finalize(self, *, error=secondary):
                        self.events.append(("finalize",))
                        raise error

                comm = FaultingComm()
                ctx = Context(comm)
                if stage == "sleep":
                    ctx.on_sleep = lambda ms, error=primary: (_ for _ in ()).throw(
                        error
                    )
                data = bytearray(52)
                data[36:52] = payload
                with self.assertRaises(RuntimeError) as raised:
                    ChassisEngine(contract).run_body(
                        "Ex2ABS_52_WriteBrakePadResidualThickness", (data,), ctx
                    )
                self.assertIs(raised.exception, primary)
                self.assertEqual(
                    [event for event in comm.events if event[0] == "cleanup_session"],
                    [("cleanup_session", 1, 1)],
                )
                self.assertEqual(
                    [event for event in comm.events if event[0] == "finalize"],
                    [("finalize",)],
                )

    def test_plus_abs52_activation_numeric_fault_skips_normal_cleanup(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        for initialize, sessions, expected in ((7, [], 7), (0, [0, 8], 8)):
            with self.subTest(initialize=initialize, sessions=sessions):
                comm = Comm(initial=initialize, sessions=sessions)
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2ABS_52_ReadBrakePadResidualThickness",
                        (bytearray(36),),
                        Context(comm),
                    ),
                    expected,
                )
                self.assertFalse(
                    any(event[0] in ("cleanup_session",) for event in comm.events)
                )
                self.assertNotIn(("session", 1, 1), comm.events[-2:])

    def test_ekdss_start_selected_argument_exact_length_and_stop(self):
        for reply, expected in ((b"\x71\x01\x11\1", 0), (b"\x71\x01\x11\1\0", 3)):
            data = bytearray(6)
            data[5] = 7
            comm = Comm([(0, reply)])
            self.assertEqual(
                engine().run_body("Ex2EKDSS_01_SendMessage", (data,), Context(comm)),
                expected,
            )
            self.assertIn(("exchange", b"\x31\x01\x11\1\7\0\0"), comm.events)
            self.assertEqual(("finalize",) in comm.events, bool(expected))
        data[0] = 1
        comm = Comm([(17, b"")], sessions=[19])
        self.assertEqual(
            engine().run_body("Ex2EKDSS_01_SendMessage", (data,), Context(comm)), 17
        )
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_ekdss_second_routine_maps_error_and_restores(self):
        comm = Comm([(31, b"")], sessions=[0, 17])
        self.assertEqual(
            engine().run_body("Ex2EKDSS_02_SendMessage", (), Context(comm)), 1000
        )
        self.assertIn(("exchange", b"\x31\x01\x11\x02\0"), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_emps09_live_selection_and_error_mapping(self):
        comm = Comm(
            [
                (0, b"\x71\x01\x11\x09"),
                (0, b"\x71\x01\x10\x02"),
                (0, b"\x71\x01\x11\x03"),
            ]
        )
        ctx = Context(comm)
        data = bytearray(b"\1\0\0\0" * 2)
        self.assertEqual(
            engine().run_body("Ex2EMPS_09_ModeTransition", (data,), ctx), 0
        )
        self.assertEqual(ctx.sleeps, [5000])
        self.assertEqual(len([e for e in comm.events if e[0] == "exchange"]), 3)
        comm = Comm([(7, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2EMPS_09_ModeTransition", (bytearray(8),), Context(comm)
            ),
            1007,
        )
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_native_restoration_status_disposition_differs_by_export(self):
        for name, expected in (
            ("Ex2ASUS_08_EndExtendedSession", 1000),
            ("Ex2ABS_47_EndExtendedSession", 0),
        ):
            comm = Comm(sessions=[31])
            self.assertEqual(engine().run_body(name, (), Context(comm)), expected)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_abs33_sensor_pair_mapping_and_retained_status(self):
        comm = Comm([(0, b"\x62\x10\x30\x80\x40\x21\x10")])
        data = bytearray(22)
        self.assertEqual(
            engine().run_body("Ex2ABS_33_CheckSensorStatus", (data,), Context(comm)),
            1000,
        )
        self.assertEqual(data[:4], b"\1\0\0\1")
        self.assertEqual(data[16:22], b"\1\0\0\1\1\0")
        self.assertNotIn(("finalize",), comm.events)
        comm = Comm([(7, b""), (8, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2ABS_33_CheckSensorStatus", (bytearray(22),), Context(comm)
            ),
            3,
        )
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_abs33_support_selected_chain_and_bit_failure(self):
        replies = [
            (0, b"\x62\1\1\0\0\x80"),
            (0, b"\x62\x10\0" + bytes(5) + b"\x09"),
            (0, b"\x62\x10\x2d" + bytes(8) + b"\x08"),
            (0, b"\x62\x10\x30\x80\0\0\0"),
            (0, b"\x71\1\x10\1\0\0\x40"),
            (0, b"\x71\1\x11\0\0\x10"),
        ]
        comm = Comm(replies)
        self.assertEqual(
            engine().run_body(
                "Ex2ABS_33_SupportCheck", (bytearray(22),), Context(comm)
            ),
            0,
        )
        self.assertEqual(len([e for e in comm.events if e[0] == "exchange"]), 6)
        comm = Comm([(0, b"\x62\1\1\0\0\0")])
        self.assertEqual(
            engine().run_body(
                "Ex2ABS_33_SupportCheck", (bytearray(22),), Context(comm)
            ),
            3,
        )

    def test_emps11_start_and_pending_complete(self):
        comm = Comm([(0, b"\x71\1\x11\x0b")])
        self.assertEqual(
            engine().run_body("Ex2EMPS_11_SendMessage", (bytearray(8),), Context(comm)),
            0,
        )
        self.assertNotIn(("finalize",), comm.events)
        comm = Comm([(0, b"\x71\3\x11\x0b\1"), (0, b"\x71\3\x11\x0b\2")])
        data = bytearray(8)
        data[0] = 1
        self.assertEqual(
            engine().run_body("Ex2EMPS_11_SendMessage", (data,), Context(comm)), 0
        )
        self.assertEqual(comm.events[-1], ("finalize",))
        comm = Comm([(0, b"\x71\3\x11\x0b\3"), (7, b"")])
        self.assertEqual(
            engine().run_body("Ex2EMPS_11_SendMessage", (data,), Context(comm)), 2000
        )

    def test_epb04_and_abs44_share_exact_native_worker(self):
        for export in ("Ex2EPB_04_SendMessage", "Ex2ABS_44_SendMessage"):
            comm = Comm([(0, b"\x71\1\x11\x1e")])
            ctx = Context(comm)
            self.assertEqual(engine().run_body(export, (), ctx), 0)
            self.assertEqual(ctx.sleeps, [500])
            self.assertIn(("exchange", b"\x31\1\x11\x1e"), comm.events)
            self.assertEqual(comm.events[-1], ("finalize",))

    def test_steering_start_is_real_session_initialization(self):
        comm = Comm()
        self.assertEqual(
            engine().run_body("Ex2EMPS_12_SteeringStart", (), Context(comm)), 0
        )
        self.assertEqual(
            [e for e in comm.events if e[0] == "session"],
            [("session", 1, 1), ("session", 3, 1)],
        )
        self.assertNotIn(("finalize",), comm.events)

    def test_tpw07_support_and_actual_saved_read_reply(self):
        comm = Comm(
            [
                (0, b"\x62\1\1" + bytes(4) + b"\x80"),
                (0, b"\x62\x20\0\x80\0\0\0\x08"),
                (0, b"\x62\x20\x25\x80\x55"),
            ]
        )
        data = bytearray(0x204C)
        self.assertEqual(
            engine().run_body("Ex2TPW_07_SupportCheck", (data,), Context(comm)), 0
        )
        self.assertEqual(data[0x102C:0x1031], b"\x62\x20\x25\x80\x55")
        self.assertEqual(int.from_bytes(data[8:12], "little"), 5)
        comm = Comm([(0, b"\x62\x20\1\x03\x55")])
        self.assertEqual(
            engine().run_body(
                "Ex2TPW_07_ReadSystemOperationMode", (data,), Context(comm)
            ),
            0,
        )
        self.assertEqual(data[:4], bytes(4))
        self.assertEqual(data[12:17], b"\x62\x20\1\x03\x55")
        self.assertEqual(int.from_bytes(data[4:8], "little"), 5)

    def test_tpw07_write_mutates_only_native_fields_in_native_order(self):
        for action in (0, 1):
            data = bytearray(0x204C)
            data[:4] = action.to_bytes(4, "little")
            data[4:8] = (5).to_bytes(4, "little")
            data[8:12] = (5).to_bytes(4, "little")
            data[12:17] = b"\x62\x20\1\xff\x55"
            data[0x102C:0x1031] = b"\x62\x20\x25\x44\xff"
            replies = (
                [(0, b"\x6e\x20\1"), (0, b"\x6e\x20\x25")]
                if action == 0
                else [(0, b"\x6e\x20\x25"), (0, b"\x6e\x20\1")]
            )
            comm = Comm(replies)
            self.assertEqual(
                engine().run_body(
                    "Ex2TPW_07_WriteSystemOperationMode", (data,), Context(comm)
                ),
                0,
            )
            requests = [e[1] for e in comm.events if e[0] == "exchange"]
            self.assertEqual(
                requests,
                [b"\x2e\x20\1\xfc\x55", b"\x2e\x20\x25\x44\x7f"]
                if action == 0
                else [b"\x2e\x20\x25\x44\xff", b"\x2e\x20\1\xff\x55"],
            )
            self.assertEqual(comm.events[-1], ("finalize",))
        comm = Comm()
        with self.assertRaises(ValueError):
            engine().run_body(
                "Ex2TPW_07_WriteSystemOperationMode",
                (bytearray(0x204C),),
                Context(comm),
            )
        self.assertEqual(comm.events, [])

    def test_epb05_support_faults_and_dealer_readback(self):
        replies = [
            (0, b"\x62\1\1\0\0\x80"),
            (0, b"\x62\x10\0" + bytes(5) + b"\x08"),
            (0, b"\x62\x10\x2d" + bytes(8) + b"\x08"),
            (0, b"\x71\1\x10\1\0\0\x40"),
            (0, b"\x71\1\x11\0\0\x10"),
        ]
        comm = Comm(replies)
        self.assertEqual(
            engine().run_body("Ex2EPB_05_SendMessage", (bytearray(4),), Context(comm)),
            0,
        )
        comm = Comm([(0, b"\x71\1\x11\x0c"), (0, b"\x62\x10\x2d" + bytes(9) + b"\x08")])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2EPB_05_SendMessage", (bytearray(b"\1\0\0\0"),), ctx),
            0,
        )
        self.assertEqual(ctx.sleeps, [4000])
        comm = Comm([(7, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2EPB_05_SendMessage", (bytearray(b"\1\0\0\0"),), Context(comm)
            ),
            2001,
        )
        comm = Comm()
        self.assertEqual(
            engine().run_body(
                "Ex2EPB_05_SendMessage", (bytearray(b"\2\0\0\0"),), Context(comm)
            ),
            0,
        )
        self.assertFalse(any(e[0] == "session" for e in comm.events))

    def test_asus10_support_selects_native_did_and_status(self):
        self.assertTrue(
            supports(SHA_PLUS_TY, "Ex2ASUS_10_GetStatOfHeightCtrlProhibition")
        )
        self.assertTrue(
            supports(
                SHA_PLUS_TY,
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
            )
        )
        for mask, did in ((128, 1), (0x10, 4)):
            comm = Comm(
                [
                    (0, b"\x00\1\1" + bytes(4) + b"\x40" + bytes(27)),
                    (0, b"\x00\x21\0" + bytes((mask,)) + bytes(31)),
                    (0, bytes((0x00, 0x21, did, 1))),
                ]
            )
            data = bytearray(2)
            self.assertEqual(
                engine().run_body(
                    "Ex2ASUS_10_GetStatOfHeightCtrlProhibition", (data,), Context(comm)
                ),
                0,
            )
            self.assertEqual(data, bytes((1, did)))
            self.assertFalse(any(e[0] == "session" for e in comm.events))

    def test_asus10_change_readback_and_restore_precedence(self):
        comm = Comm([(0, b"\x00\x21\4"), (0, b"\x00\x21\4\0")])
        data = bytearray((1, 4))
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition", (data,), ctx
            ),
            0,
        )
        self.assertEqual(data, bytes((0, 4)))
        self.assertEqual(ctx.sleeps, [100])
        self.assertIn(("exchange", b"\x2e\x21\4\0"), comm.events)
        comm = Comm([(0, b"\x00\x21\x04\xaa")], sessions=[0, 0, 0])
        data = bytearray((1, 4))
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
                (data,),
                ctx,
            ),
            3,
        )
        self.assertEqual(data, bytes((1, 4)))
        self.assertEqual(ctx.sleeps, [])
        self.assertEqual(
            [event for event in comm.events if event[0] == "exchange"],
            [("exchange", b"\x2e\x21\4\0")],
        )
        self.assertEqual(
            [event for event in comm.events if event[0] == "session"],
            [("session", 1, 1), ("session", 3, 1), ("session", 1, 1)],
        )
        comm = Comm([(0, b"\x6e\x21\4\0")], sessions=[0, 0, 31])
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
                (bytearray((1, 4)),),
                Context(comm),
            ),
            31,
        )

    def test_asus10_invalid_request_and_normal_status_precedence(self):
        for contract in (
            replace(
                CONTRACT_12,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
            ),
            replace(
                CONTRACT_PLUS,
                source_sha256=Context.module_sha256,
                manager="synthetic-manager",
            ),
        ):
            with self.subTest(discovery=contract.asus10_discover):
                comm = Comm(sessions=[0, 0, 0])
                data = (
                    bytearray((2, 1)) if contract.asus10_discover else bytearray((2,))
                )
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
                        (data,),
                        Context(comm),
                    ),
                    3,
                )
                self.assertFalse(any(event[0] == "exchange" for event in comm.events))
                comm = Comm([(7, b"")], sessions=[0, 0, 9])
                data = (
                    bytearray((0, 1)) if contract.asus10_discover else bytearray((0,))
                )
                self.assertEqual(
                    ChassisEngine(contract).run_body(
                        "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
                        (data,),
                        Context(comm),
                    ),
                    9,
                )

    def test_asus10_host_fault_releases_normal_and_preserves_primary(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        primary = RuntimeError("read failed")
        secondary = RuntimeError("disconnect failed")

        class FaultingComm(Comm):
            def exchange(self, request):
                self.events.append(("exchange", request))
                if request.startswith(b"\x22\x21"):
                    raise primary
                return 0, b"\x00\x21\x04"

            def finalize(self):
                self.events.append(("finalize",))
                raise secondary

        comm = FaultingComm()
        ctx = Context(comm)
        with self.assertRaises(RuntimeError) as raised:
            ChassisEngine(contract).run_body(
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
                (bytearray((1, 4)),),
                ctx,
            )
        self.assertIs(raised.exception, primary)
        self.assertEqual(
            [event for event in comm.events if event[0] == "session"],
            [("session", 1, 1), ("session", 3, 1), ("session", 1, 1)],
        )
        self.assertEqual(
            [event for event in comm.events if event[0] == "finalize"],
            [("finalize",)],
        )

    def test_asus10_get_host_fault_preserves_primary_without_normal_release(self):
        contract = replace(
            CONTRACT_PLUS,
            source_sha256=Context.module_sha256,
            manager="synthetic-manager",
        )
        primary = RuntimeError("discovery read failed")
        secondary = RuntimeError("disconnect failed")

        class FaultingComm(Comm):
            def exchange(self, request):
                self.events.append(("exchange", request))
                raise primary

            def finalize(self):
                self.events.append(("finalize",))
                raise secondary

        comm = FaultingComm()
        with self.assertRaises(RuntimeError) as raised:
            ChassisEngine(contract).run_body(
                "Ex2ASUS_10_GetStatOfHeightCtrlProhibition",
                (bytearray(2),),
                Context(comm),
            )
        self.assertIs(raised.exception, primary)
        self.assertEqual([event for event in comm.events if event[0] == "session"], [])
        self.assertEqual(
            [event for event in comm.events if event[0] == "finalize"],
            [("finalize",)],
        )

    def test_asus10_native_bad_echo_still_publishes_valid_data_byte(self):
        comm = Comm([(0, b"\x00\x21\4"), (0, b"\x00\x21\5\1")])
        data = bytearray((0, 4))
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
                (data,),
                Context(comm),
            ),
            3,
        )
        self.assertEqual(data[0], 1)
        comm = Comm([(0, b"\x00\x21\4"), (0, b"\x00\x21\4\3")])
        self.assertEqual(
            engine().run_body(
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
                (bytearray((0, 4)),),
                Context(comm),
            ),
            1001,
        )

    def test_abs29_preserves_own_failure_and_restore_policy(self):
        comm = Comm([(31, b"")], sessions=[0, 0, 47])
        self.assertEqual(
            engine().run_body("Ex2ABS_29_SupportCheck", (), Context(comm)), 3
        )
        comm = Comm([(31, b"")])
        self.assertEqual(
            engine().run_body("Ex2ABS_29_ShiftDealerMode", (), Context(comm)), 1006
        )
        comm = Comm([(0, b"\x71\1\x11\x0c"), (0, b"\x62\x10\x2d" + bytes(9) + b"\x08")])
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2ABS_29_ShiftDealerMode", (), ctx), 0)
        self.assertEqual(ctx.sleeps, [4000])

    def test_abs29_checks_echo_without_requiring_positive_sid(self):
        support = [
            b"\0\1\1\0\0\x80",
            b"\0\x10\0\0\0\0\0\0\x08",
            b"\0\x10\x2d" + bytes(8) + b"\x08",
            b"\0\1\x10\1\0\0\x40",
            b"\0\1\x11\0\0\x10",
        ]
        comm = Comm([(0, reply) for reply in support], sessions=[0, 0, 47])
        self.assertEqual(
            engine().run_body("Ex2ABS_29_SupportCheck", (), Context(comm)), 47
        )

        comm = Comm([(0, b"\0\1\x11\x0c"), (0, b"\0\x10\x2d" + bytes(9) + b"\x08")])
        self.assertEqual(
            engine().run_body("Ex2ABS_29_ShiftDealerMode", (), Context(comm)), 0
        )

    def test_abs29_host_fault_restores_normal_and_preserves_primary(self):
        primary = RuntimeError("ABS29 exchange failed")
        cleanup_fault = RuntimeError("normal cleanup failed")
        finalize_fault = RuntimeError("finalize failed")

        class FaultingComm(Comm):
            def exchange(self, request):
                self.events.append(("exchange", request))
                raise primary

            def cleanup_session(self, mode, keepalive=1, **kwargs):
                self.events.append(("cleanup_session", mode, keepalive))
                raise cleanup_fault

            def finalize(self):
                self.events.append(("finalize",))
                raise finalize_fault

        comm = FaultingComm()
        with self.assertRaises(RuntimeError) as raised:
            engine().run_body("Ex2ABS_29_SupportCheck", (), Context(comm))

        self.assertIs(raised.exception, primary)
        self.assertEqual(
            [event for event in comm.events if event[0] == "cleanup_session"],
            [("cleanup_session", 1, 1)],
        )
        self.assertEqual(comm.events.count(("finalize",)), 1)

    def test_4wd07_support_consumes_exact_native_bitmaps(self):
        first = bytearray(b"\x71\1\x10\1" + bytes(32))
        first[6] = 0x40
        second = bytearray(b"\x71\1\x11\0" + bytes(32))
        second[4] = 8
        third = bytearray(b"\x62\1\1" + bytes(32))
        third[7] = 0x20
        fourth = bytearray(b"\x62\x22\0" + bytes(32))
        fourth[3] = 0x15
        fourth[5] = 0x19
        fourth[6] = 0xE0
        comm = Comm([(0, bytes(reply)) for reply in (first, second, third, fourth)])
        data = bytearray(80)
        self.assertEqual(
            engine().run_body("Ex24WD_07_SupportCheck", (data,), Context(comm)), 0
        )
        words = [
            int.from_bytes(data[offset : offset + 4], "little")
            for offset in range(32, 80, 4)
        ]
        self.assertEqual(words, [1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1])
        comm = Comm([(0, bytes(first) + b"\0")])
        self.assertEqual(
            engine().run_body(
                "Ex24WD_07_SupportCheck", (bytearray(80),), Context(comm)
            ),
            3,
        )

    def test_4wd07_selected_clear_start_and_complete(self):
        data = bytearray(80)
        data[:4] = (2001).to_bytes(4, "little")
        data[32] = 1
        comm = Comm([(0, b"\x71\1\x11\5")])
        self.assertEqual(
            engine().run_body("Ex24WD_07_BackupMemoryClear1st", (data,), Context(comm)),
            1000,
        )
        self.assertIn(("exchange", b"\x31\1\x11\5\4"), comm.events)
        self.assertNotIn(("finalize",), comm.events)
        reply = bytearray(b"\x71\3\x11\5" + bytes(30))
        reply[11] = 2
        comm = Comm([(0, bytes(reply))])
        self.assertEqual(
            engine().run_body("Ex24WD_07_BackupMemoryClear2nd", (data,), Context(comm)),
            0,
        )
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_4wd07_multiple_selected_clear_stages_and_cancel(self):
        data = bytearray(80)
        data[:4] = (2003).to_bytes(4, "little")
        data[36] = 1
        data[56] = data[60] = 1
        first = bytearray(b"\x71\3\x11\x09" + bytes(44))
        first[45] = 2
        second = bytearray(first)
        second[47] = 2
        comm = Comm([(0, bytes(first)), (0, b"\x71\1\x11\x09"), (0, bytes(second))])
        self.assertEqual(
            engine().run_body("Ex24WD_07_BackupMemoryClear2nd", (data,), Context(comm)),
            0,
        )
        self.assertIn(("exchange", b"\x31\1\x11\x09\x15"), comm.events)
        pending = bytearray(first)
        pending[45] = 1
        data[28] = 1
        comm = Comm([(0, bytes(pending))])
        self.assertEqual(
            engine().run_body("Ex24WD_07_BackupMemoryClear2nd", (data,), Context(comm)),
            1001,
        )

    def test_4wd07_suppresses_one_source_selector_and_requires_metadata(self):
        data = bytearray(80)
        data[:4] = (2003).to_bytes(4, "little")
        data[32] = data[56] = data[60] = 1
        self.assertEqual(engine()._4wd_selector(data, 1), 0x14)
        self.assertEqual(engine()._4wd_selector(data, 2), 0)
        with self.assertRaises(ValueError):
            engine().run_body(
                "Ex24WD_07_BackupMemoryClear1st", (bytearray(80),), Context(Comm())
            )

    def test_bsm13_native_payload_output_and_length(self):
        comm = Comm([(0, b"\x62\x20\x50\xaa\xbb\xcc")])
        data = bytearray(b"\xff" * 0x1024)
        self.assertEqual(
            engine().run_body("Ex2BSM_13_14_23_24_SendMessage", (data,), Context(comm)),
            0,
        )
        self.assertEqual(data[:4], b"\xaa\xbb\xcc\0")
        self.assertEqual(int.from_bytes(data[0x1020:0x1024], "little"), 3)
        comm = Comm([(7, b"")])
        self.assertEqual(
            engine().run_body("Ex2BSM_13_14_23_24_SendMessage", (data,), Context(comm)),
            2000,
        )
        self.assertEqual(data[:0x1024], bytes(0x1024))

    def test_bsm15_actual_read_write_compare_and_flag_payload(self):
        data = bytearray(0x102C)
        data[:4] = b"\x20\x50\xaa\xbb"
        data[0x1024:0x1028] = (2).to_bytes(4, "little")
        comm = Comm(
            [
                (0, b"\x62\x20\x50\x11\x22"),
                (0, b"\x6e\x20\x50"),
                (0, b"\x62\x20\x50\xaa\xbb"),
                (0, b"\x62\x20\x52\x44\x80\x66"),
                (0, b"\x6e\x20\x52"),
                (0, b"\x62\x20\x52\x44\x81\x66"),
            ]
        )
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2BSM_15_16_25_26_SendMessage", (data,), ctx), 0
        )
        self.assertIn(("exchange", b"\x2e\x20\x50\xaa\xbb"), comm.events)
        self.assertIn(("exchange", b"\x2e\x20\x52\x44\x81\x66"), comm.events)
        self.assertEqual(ctx.sleeps, [100, 100])

    def test_bsm15_skip_flag_family_and_readback_mismatch(self):
        data = bytearray(0x102C)
        data[:4] = b"\x20\x50\xaa\xbb"
        data[0x1024:0x1028] = (2).to_bytes(4, "little")
        data[0x1028:0x102C] = (0x12DB).to_bytes(4, "little")
        for readback, expected in ((b"\xaa\xbb", 0), (b"\xaa\xcc", 2001)):
            comm = Comm(
                [
                    (0, b"\x62\x20\x50\x11\x22"),
                    (0, b"\x6e\x20\x50"),
                    (0, b"\x62\x20\x50" + readback),
                ]
            )
            self.assertEqual(
                engine().run_body(
                    "Ex2BSM_15_16_25_26_SendMessage", (data,), Context(comm)
                ),
                expected,
            )
            self.assertEqual(len([e for e in comm.events if e[0] == "exchange"]), 3)

    def test_awd_overwrite_is_native_status_without_io(self):
        comm = Comm()
        self.assertEqual(
            engine().run_body("Ex2AWD_04_Overwrite", (), Context(comm)), 1024
        )
        self.assertEqual(comm.events, [])

    def test_abs32_support_missing_bit_is_native_99(self):
        comm = Comm([(0, b"\x62\1\1\0\0\0")])
        self.assertEqual(
            engine().run_body("Ex2ABS_32_SupportCheck", (), Context(comm)), 99
        )
        replies = [
            (0, b"\x62\1\1\0\0\x80"),
            (0, b"\x62\x10\0" + bytes(8) + b"\x08"),
            (0, b"\x71\1\x10\1\0\0\x40"),
            (0, b"\x71\1\x11\0\0\0\x08"),
        ]
        comm = Comm(replies)
        self.assertEqual(
            engine().run_body("Ex2ABS_32_SupportCheck", (), Context(comm)), 0
        )

    def test_abs32_release_delay_both_bytes_and_session_failure_mapping(self):
        for values, expected in ((b"\5\5", 0), (b"\5\4", 1003)):
            comm = Comm([(0, b"\x71\1\x11\x15"), (0, b"\x62\x10\x45" + values)])
            ctx = Context(comm)
            self.assertEqual(
                engine().run_body("Ex2ABS_32_EPBFullReleaseAndCheck", (), ctx), expected
            )
            self.assertEqual(ctx.sleeps, [10000])
            self.assertEqual(comm.events[-1], ("finalize",))
        comm = Comm(sessions=[37])
        self.assertEqual(
            engine().run_body("Ex2ABS_32_EPBFullReleaseAndCheck", (), Context(comm)),
            1001,
        )
        comm = Comm(initial=37)
        self.assertEqual(
            engine().run_body("Ex2ABS_32_EPBFullReleaseAndCheck", (), Context(comm)), 37
        )

    def test_abs41_three_support_predicates_and_exact_lengths(self):
        first = bytearray(b"\x62\1\1" + bytes(32))
        first[8] = 128
        second = bytearray(b"\x62\x28\0" + bytes(32))
        second[3] = 0x40
        comm = Comm(
            [(0, bytes(first)), (0, bytes(second)), (0, b"\x62\x28\2\xaa\0\x38")]
        )
        self.assertEqual(
            engine().run_body("Ex2ABS_41_DIDSupportCheck", (), Context(comm)), 0
        )
        comm = Comm(
            [(0, bytes(first)), (0, bytes(second)), (0, b"\x62\x28\2\xaa\0\x18")]
        )
        self.assertEqual(
            engine().run_body("Ex2ABS_41_DIDSupportCheck", (), Context(comm)), 99
        )
        comm = Comm([(0, bytes(first) + b"\0")])
        self.assertEqual(
            engine().run_body("Ex2ABS_41_DIDSupportCheck", (), Context(comm)), 3
        )

    def test_abs41_solenoid_two_timed_phases_across_tick_wrap(self):
        for selection, inlet, outlet in (
            (1, 2, 16),
            (2, 8, 32),
            (3, 32, 32),
            (4, 128, 16),
        ):
            comm = Comm(
                [(0, b"\x6f\x28\2\3")] * 5
                + [(0, b"\x6f\x28\2\0")]
                + [(0, b"\x6f\x28\2\3")] * 4
                + [(0, b"\x6f\x28\2\0")]
            )
            ctx = Context(comm)
            ctx.tick = 0xFFFFFFF0
            self.assertEqual(
                engine().run_body(
                    "Ex2ABS_41_DriveSolenoid",
                    (bytearray(selection.to_bytes(4, "little")),),
                    ctx,
                ),
                0,
            )
            requests = [e[1] for e in comm.events if e[0] == "exchange"]
            self.assertEqual(len(requests), 11)
            self.assertEqual(
                requests[0],
                b"\x2f\x28\2\3\0"
                + inlet.to_bytes(4, "little")
                + inlet.to_bytes(2, "little")
                + b"\0",
            )
            self.assertEqual(requests[-1], b"\x2f\x28\2\0\0\0\0" + bytes((outlet,)))
            self.assertEqual(ctx.sleeps, [1000] * 9)

    def test_abs41_solenoid_fault_stops_before_restore_and_close(self):
        comm = Comm([(37, b""), (17, b"")])
        self.assertEqual(
            engine().run_body(
                "Ex2ABS_41_DriveSolenoid", (bytearray(b"\1\0\0\0"),), Context(comm)
            ),
            1000,
        )
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])
        self.assertEqual(len([e for e in comm.events if e[0] == "exchange"]), 2)

    def test_psaabs01_actual_pending_complete_and_negative_mapping(self):
        comm = Comm([(0, b"\x71\xbe\1"), (0, b"\x71\xbe\1"), (0, b"\x71\xbe\2")])
        ctx = Context(comm)
        self.assertEqual(engine().run_body("Ex2PSAABS_01_SendMessage", (), ctx), 0)
        self.assertEqual(ctx.sleeps, [1000, 1000, 1000])
        self.assertIn(("configure", "native_rva:12180", 150), comm.events)
        comm = Comm([(7, b"\x7f\x31\x22")])
        self.assertEqual(
            engine().run_body("Ex2PSAABS_01_SendMessage", (), Context(comm)), 9006
        )

    def test_psaabs02_two_actual_routine_passes(self):
        comm = Comm(
            [
                (0, b"\x71\xb4\1"),
                (0, b"\x71\xb4\2"),
                (0, b"\x71\xb4\1"),
                (0, b"\x71\xb4\2"),
            ]
        )
        self.assertEqual(
            engine().run_body("Ex2PSAABS_02_SendMessage", (), Context(comm)), 0
        )
        requests = [e[1] for e in comm.events if e[0] == "exchange"]
        self.assertEqual(
            requests, [b"\x31\xb4\0\0", b"\x31\xb4\1", b"\x31\xb4\0\xff", b"\x31\xb4\1"]
        )

    def test_psaabs03_start_selected_three_bytes_and_native_retention(self):
        data = bytearray(16)
        data[8:11] = b"\x11\x22\x33"
        for result, expected in ((0, 9101), (1, 9100), (2, 9102)):
            comm = Comm([(0, bytes((0x70, 0xD1, result)))])
            self.assertEqual(
                engine().run_body(
                    "Ex2PSAABS_03_StartActiveTest", (data,), Context(comm)
                ),
                expected,
            )
            self.assertIn(("exchange", b"\x30\xd1\x11\x22\x33"), comm.events)
            self.assertEqual(("finalize",) in comm.events, result != 1)
        comm = Comm(initial=37)
        self.assertEqual(
            engine().run_body("Ex2PSAABS_03_StartActiveTest", (data,), Context(comm)),
            37,
        )
        self.assertNotIn(("finalize",), comm.events)

    def test_psaabs03_exact_timeout_and_indeterminate_stop_policy(self):
        data = bytearray(16)
        data[12:16] = (1000).to_bytes(4, "little")
        comm = Comm([(0, b"\x70\xd1\1"), (0, b"\x70\xd1\1"), (7, b"")])
        ctx = Context(comm)
        self.assertEqual(
            engine().run_body("Ex2PSAABS_03_ConfirmStatus", (data,), ctx), 9013
        )
        self.assertEqual(ctx.sleeps, [1000, 1000, 1000])
        self.assertIn(("exchange", b"\x30\xd1\x11"), comm.events)
        comm = Comm([(0, b"\x70\xd1\3"), (7, b"")])
        self.assertEqual(
            engine().run_body("Ex2PSAABS_03_ConfirmStatus", (data,), Context(comm)),
            9102,
        )
        comm = Comm([(7, b"\x7f\x30\x22")])
        self.assertEqual(
            engine().run_body("Ex2PSAABS_03_ConfirmStatus", (data,), Context(comm)),
            9014,
        )

    def test_plus_constant_body_is_independently_supported_without_other_aliases(self):
        self.assertTrue(supports(SHA_PLUS_TY, "Ex2AWD_04_Overwrite"))
        for name in (
            "Ex2AHC_03_ReadModeStatus",
            "Ex2AHC_03_SwitchServiceMode",
            "Ex2AHC_03_EndExtendedSession",
            "Ex2ABS_48_RetrunWait",
            "Ex2ASUS_08_EndExtendedSession",
            "Ex2ABS_41_DriveMotor",
            "Ex2ABS_41_StopMotor",
            "Ex2ABS_44_SendMessage",
            "Ex2EPB_04_SendMessage",
        ):
            self.assertTrue(supports(SHA_PLUS_TY, name))
        for name in (
            "Ex2EMPS_12_AutoRackCentering",
            "Ex2EMPS_12_SteeringStart",
            "Ex2EMPS_12_SteeringAngleCheck",
        ):
            self.assertTrue(supports(SHA_PLUS_TY, name))
        self.assertFalse(supports(SHA_PLUS_TY, "Ex2EMPS_12_ReadRoutineStatus"))
        ctx = Context(Comm())
        ctx.module_sha256 = SHA_PLUS_TY
        with self.assertRaises(TYSourceError):
            run_body("Ex2AWD_04_Overwrite", (), ctx)
        self.assertEqual(ctx.controller.events, [])

    def test_identity_and_argument_faults_do_not_open_comm(self):
        comm = Comm()
        ctx = Context(comm)
        with self.assertRaises(TYSourceError):
            run_body("Ex2AHC_03_ReadModeStatus", (bytearray(4),), ctx)
        with self.assertRaises(ValueError):
            engine().run_body("Ex2AHC_03_ReadModeStatus", (bytearray(3),), ctx)
        ctx.module_bytes = b"tampered"
        with self.assertRaises(TYSourceError):
            engine().run_body("Ex2AHC_03_EndExtendedSession", (), ctx)
        self.assertEqual(comm.events, [])


if __name__ == "__main__":
    unittest.main()
