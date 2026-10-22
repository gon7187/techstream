import unittest

from scripts.programming import (
    Checkpoint,
    NativeEthernetChannel,
    NativeProgrammingChannel,
    NativeTransportError,
    Programmer,
    ProgramPlan,
    ReproStdLogicalBlock,
    ReproStdPrepareContext,
    ReproStdSegment,
    SimulatorBackend,
    UnifiedArea,
    UnifiedPrepareContext,
    UnifiedProgram,
    decode_native_data,
    ethernet_block_size,
    ethernet_request,
    ethernet_write,
    inspect_recovery_info,
    native_data_request,
    reprostd_block_size,
    reprostd_download_request,
    reprostd_fingerprint_requests,
    reprostd_prepare,
    reprostd_prepare_actions,
    reprostd_routine_request,
    reprostd_security,
    reprostd_transfer,
    reprostd_write,
    unified_download_request,
    unified_fingerprint_requests,
    unified_prepare,
    unified_prepare_actions,
    unified_routine_request,
    unified_write,
)


def plan():
    return ProgramPlan(
        "synthetic-ECU", "old", "new", (b"authored one", b"authored two")
    )


def checkpoint(report):
    return Checkpoint(**report["checkpoint"])


class FaultBackend(SimulatorBackend):
    def __init__(self, fault_index, after=False):
        super().__init__("synthetic-ECU", "old")
        self.fault_index = fault_index
        self.after = after
        self.faulted = False

    def execute(self, phase, index, plan, timeout):
        fault = len(self.journal) == self.fault_index and not self.faulted
        if fault and not self.after:
            self.faulted = True
            raise ConnectionError("synthetic disconnect before operation")
        super().execute(phase, index, plan, timeout)
        if fault:
            self.faulted = True
            raise ConnectionError("synthetic disconnect after operation")


class ProgrammingTests(unittest.TestCase):
    def test_complete_explicit_simulator(self):
        backend = SimulatorBackend("synthetic-ECU", "old")
        report = Programmer(backend).run(plan())
        self.assertEqual(report["state"], "completed")
        self.assertEqual(backend.current_id, "new")
        self.assertEqual(backend.image, dict(enumerate(plan().blocks)))
        self.assertEqual(report["physical_status"], "PHYSICAL_UNCONFIRMED")
        self.assertEqual(
            Programmer(backend).run(plan(), checkpoint=checkpoint(report))["state"],
            "completed",
        )

    def test_failure_before_and_after_every_operation(self):
        for index in range(len(plan().operations)):
            for after in (False, True):
                with self.subTest(index=index, after=after):
                    backend = FaultBackend(index, after)
                    programmer = Programmer(backend)
                    report = programmer.run(plan())
                    self.assertEqual(
                        report["state"], "failed" if index < 2 else "recovery_required"
                    )
                    if index >= 2:
                        resumed = programmer.run(plan(), checkpoint=checkpoint(report))
                        self.assertEqual(resumed["state"], "completed", resumed)
                        self.assertEqual(backend.journal, list(plan().operations))

    def test_cancellation_before_every_phase(self):
        for index in range(len(plan().operations)):
            backend = SimulatorBackend("synthetic-ECU", "old")
            programmer = Programmer(backend)
            report = programmer.run(
                plan(),
                cancelled=lambda backend=backend, index=index: (
                    len(backend.journal) == index
                ),
            )
            self.assertEqual(len(backend.journal), index)
            self.assertEqual(
                report["state"], "cancelled" if index < 3 else "recovery_required"
            )
            if index:
                self.assertEqual(
                    programmer.run(plan(), checkpoint=checkpoint(report))["state"],
                    "completed",
                )

    def test_mismatch_never_erases(self):
        for ecu, cid in (("other", "old"), ("synthetic-ECU", "other")):
            backend = SimulatorBackend(ecu, cid)
            backend.image[0] = b"existing"
            result = Programmer(backend).run(plan())
            self.assertEqual(result["state"], "failed")
            self.assertEqual(backend.image, {0: b"existing"})
            self.assertEqual(backend.journal, [])

    def test_recovery_cannot_trust_forged_or_new_backend(self):
        backend = FaultBackend(3, True)
        report = Programmer(backend).run(plan())
        saved = checkpoint(report)
        fresh = SimulatorBackend("synthetic-ECU", "old")
        self.assertEqual(
            Programmer(fresh).run(plan(), checkpoint=saved)["state"],
            "recovery_required",
        )
        backend.image[0] = b"corrupt"
        self.assertEqual(
            Programmer(backend).run(plan(), checkpoint=saved)["state"],
            "recovery_required",
        )
        self.assertEqual(len(backend.journal), 4)
        for value in (
            Checkpoint("0" * 64, 3, True),
            Checkpoint(plan().digest, -1, True),
            Checkpoint(plan().digest, True, True),
        ):
            with self.assertRaises(ValueError):
                Programmer(backend).run(plan(), checkpoint=value)

    def test_deadline_every_phase(self):
        for index in range(len(plan().operations)):
            now = [0.0]
            fault_position = index

            class LateBackend(SimulatorBackend):
                def execute(self, phase, index, plan, timeout):
                    super().execute(phase, index, plan, timeout)
                    if len(self.journal) == fault_position + 1:  # noqa: B023 - synchronous per iteration
                        now[0] = 2  # noqa: B023 - synchronous per iteration

            backend = LateBackend("synthetic-ECU", "old")
            result = Programmer(backend, clock=lambda now=now: now[0]).run(
                plan(), timeout=1
            )
            self.assertEqual(
                result["state"], "failed" if index < 2 else "recovery_required"
            )
            self.assertEqual(len(backend.journal), index + 1)

    def test_cancelled_recovery_preserves_original_checkpoint(self):
        backend = FaultBackend(3, True)
        result = Programmer(backend).run(plan())
        stopped = Programmer(backend).run(
            plan(), checkpoint=checkpoint(result), cancelled=lambda: True
        )
        self.assertEqual(stopped["checkpoint"], result["checkpoint"])
        self.assertEqual(len(backend.journal), 4)

    def test_interruption_leaves_recovery_checkpoint(self):
        class Interrupted(SimulatorBackend):
            def execute(self, phase, index, plan, timeout):
                if phase == "transfer":
                    raise KeyboardInterrupt("synthetic interruption")
                super().execute(phase, index, plan, timeout)

        report = Programmer(Interrupted("synthetic-ECU", "old")).run(plan())
        self.assertEqual(report["state"], "recovery_required")
        self.assertTrue(report["checkpoint"]["uncertain"])
        self.assertEqual(report["checkpoint"]["next_operation"], 3)

    def test_native_plaintext_recovery_inspection(self):
        raw = b"[RecoveryInfo]\nCIDNum=1\nCID1=synthetic-old\nWriting=1\nWriteCpuIndex=0\nWritingEndBlock=1\nSavedCalibrationFilePath=C:\\fake.cuw\n"
        report = inspect_recovery_info(raw)
        encoded = bytes(
            (nibble + 8) << 2 for byte in raw for nibble in (byte >> 4, byte & 15)
        )
        self.assertEqual(inspect_recovery_info(encoded)["fields"], report["fields"])
        self.assertTrue(inspect_recovery_info(encoded)["encoded"])
        self.assertEqual(report["fields"]["cid1"], "synthetic-old")
        self.assertFalse(report["resume_authorized"])
        self.assertFalse(report["integrity_validated"])
        for bad in (
            b"",
            b"[RecoveryInfo]\nCIDNum=1",
            b"[RecoveryInfo]\nWriting=2",
            b"[RecoveryInfo]\nWritingEndBlock=3",
            b"[RecoveryInfo]\nPassThruErrorCode=256",
            b"[RecoveryInfo]\nReproCheckResult=256",
            b"[RecoveryInfo]\nCIDNum=-1",
            b"[RecoveryInfo]\nCIDNum=4097",
            b"[RecoveryInfo]\nWriting=1\nWriting=0",
            b"[Wrong]\nWriting=1",
        ):
            with self.assertRaises(ValueError):
                inspect_recovery_info(bad)

    def test_native_reprostd_fragment_bytes_and_rollover(self):
        requests = []

        def exchange(ecu, request):
            self.assertEqual(ecu, "fake")
            requests.append(request)
            if request[0] == 0x34:
                return bytes.fromhex("741003")
            if request[0] == 0x36:
                return bytes((0x76, request[1]))
            return b"\x77"

        result = reprostd_transfer(exchange, "fake", 0x1000, b"A" * 260)
        self.assertEqual(result["state"], "fragment_completed")
        self.assertFalse(result["programming_completed"])
        self.assertEqual(requests[0], bytes.fromhex("3401440000100000000104"))
        self.assertEqual(requests[255], b"\x36\xffA")
        self.assertEqual(requests[256], b"\x36\x00A")
        self.assertEqual(requests[-1], b"\x37")
        self.assertEqual(reprostd_block_size(bytes.fromhex("7440ffffffff")), 4093)
        for selector in (1, 0x21, 0x11):
            self.assertEqual(reprostd_download_request(16, 1, selector)[1], selector)

    def test_native_reprostd_fragment_faults_and_cancellation(self):
        for failed in range(4):
            calls = []

            def exchange(ecu, request, failed=failed, calls=calls):
                calls.append(request)
                if len(calls) == failed + 1:
                    raise ConnectionError("synthetic lost acknowledgement")
                return (
                    bytes.fromhex("741003")
                    if request[0] == 0x34
                    else bytes((0x76, request[1]))
                    if request[0] == 0x36
                    else b"\x77"
                )

            result = reprostd_transfer(exchange, "fake", 0, b"AB")
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(len(calls), failed + 1)
            self.assertFalse(result["automatic_retry"])
        calls = []
        result = reprostd_transfer(
            lambda ecu, request: calls.append(request) or b"",
            "fake",
            0,
            b"A",
            cancelled=lambda: True,
        )
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(calls, [])
        for raw in (
            b"",
            bytes.fromhex("7f3478"),
            bytes.fromhex("7400"),
            bytes.fromhex("741102"),
            bytes.fromhex("741002"),
            bytes.fromhex("742003"),
        ):
            with self.assertRaises(ValueError):
                reprostd_block_size(raw)
        with self.assertRaises(ValueError):
            reprostd_download_request(0xFFFFFFFF, 2)

    def test_native_response_pending_receives_without_resending(self):
        sent = []
        pending_responses = []

        def exchange(ecu, request):
            sent.append(request)
            positive = (
                bytes.fromhex("741003")
                if request[0] == 0x34
                else bytes((0x76, request[1]))
                if request[0] == 0x36
                else b"\x77"
            )
            pending_responses.append(positive)
            return bytes((0x7F, request[0], 0x78))

        result = reprostd_transfer(
            exchange, "fake", 0, b"A", receive=lambda ecu: pending_responses.pop(0)
        )
        self.assertEqual(result["state"], "fragment_completed")
        self.assertEqual(len(sent), 3)
        result = reprostd_transfer(
            lambda ecu, request: b"\x7f\x34\x78",
            "fake",
            0,
            b"A",
            receive=lambda ecu: b"\x7f\x34\x78",
        )
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["error"], "TimeoutError")

    def test_native_reprostd_routine_fragments(self):
        erase, ack = reprostd_routine_request("erase", 16, 2)
        self.assertEqual(erase, bytes.fromhex("3101ff00440000001000000002"))
        self.assertEqual(ack, bytes.fromhex("7101ff00"))
        for operation, suffix in (
            ("routine_check", b"\x10\xf5"),
            ("verify", b"\x10\xf6"),
        ):
            for size in (16, 256):
                signature = b"S" * size
                request, ack = reprostd_routine_request(
                    operation, 16, 2, signature=signature
                )
                self.assertEqual(request[:5], b"\x31\x01" + suffix + b"\x44")
                self.assertEqual(request[13:18], bytes.fromhex("00ffffffff"))
                self.assertEqual(request[18:20], size.to_bytes(2, "big"))
                self.assertEqual(request[20:], signature)
                self.assertEqual(ack, b"\x71\x01" + suffix)
                request, _ = reprostd_routine_request(
                    operation, 16, 2, checksum=b"ABCD", signature=signature
                )
                self.assertEqual(request[13:18], b"\x04ABCD")
        for kwargs in (
            {},
            {"signature": b"x"},
            {"signature": b"S" * 16, "checksum": b"x"},
        ):
            with self.assertRaises(ValueError):
                reprostd_routine_request("verify", 0, 1, **kwargs)
        with self.assertRaises(ValueError):
            reprostd_routine_request("erase", 0, 1, signature=b"S" * 16)

    def test_native_preblock_fingerprint_fragments(self):
        timestamp = (2026, 10, 2, 20, 14, 20, 0, 123)
        for slot in range(1, 17):
            packets = reprostd_fingerprint_requests(
                slot, b"C" * 16, b"T" * 32, timestamp
            )
            self.assertEqual(
                tuple(len(request) for request, _ in packets), (19, 67, 19)
            )
            self.assertEqual(
                packets[0][0][1:3],
                (0x0202 if slot == 1 else 0x023F + slot).to_bytes(2, "big"),
            )
            self.assertEqual(packets[1][0][3:], b"T" * 32 + bytes(32))
            self.assertEqual(packets[2][0][3:5], b"\x07\xea")
            self.assertEqual(packets[2][0][-2:], b"\x00\x7b")
            for request, ack in packets:
                self.assertEqual(ack, b"\x6e" + request[1:3])
        for slot in (0, 17, True):
            with self.assertRaises(ValueError):
                reprostd_fingerprint_requests(slot, b"C" * 16, b"T" * 32, timestamp)
        with self.assertRaises(ValueError):
            reprostd_fingerprint_requests(1, b"C" * 15, b"T" * 32, timestamp)

    def test_cancelled_recovery_keeps_uncertain_erase(self):
        backend = FaultBackend(2, True)
        report = Programmer(backend).run(plan())
        self.assertEqual(report["checkpoint"]["next_operation"], 2)
        stopped = Programmer(backend).run(
            plan(), checkpoint=checkpoint(report), cancelled=lambda: True
        )
        self.assertEqual(stopped["state"], "recovery_required")
        self.assertEqual(stopped["checkpoint"], report["checkpoint"])

    def test_native_block_length_all_nibble_widths(self):
        for width in range(1, 16):
            self.assertEqual(
                reprostd_block_size(
                    bytes((0x74, width << 4)) + bytes(width - 1) + b"\x03"
                ),
                1,
            )
            self.assertEqual(
                reprostd_block_size(bytes((0x74, width << 4)) + bytes([255]) * width),
                min((1 << (width * 8)) - 1, 4095) - 2,
            )

    def test_native_positive_response_prefixes_allow_parameters(self):
        def exchange(ecu, request):
            if request[0] == 0x34:
                return bytes.fromhex("74100300")
            if request[0] == 0x36:
                return bytes((0x76, request[1], 0))
            return b"\x77\x00"

        self.assertEqual(
            reprostd_transfer(exchange, "fake", 0, b"AB")["state"], "fragment_completed"
        )
        for bad in (b"\x76\x00", b"\x75\x01"):

            def wrong(ecu, request, bad=bad):
                return bytes.fromhex("741003") if request[0] == 0x34 else bad

            self.assertEqual(
                reprostd_transfer(wrong, "fake", 0, b"AB")["state"], "recovery_required"
            )

    def test_native_recovery_indexed_vehicle_flags(self):
        raw = b"[RecoveryInfo]\nVehicleInfoForUpdateAvailableFlagNum=1\nVehicleInfoForUpdateAvailableFlag1=1"
        self.assertEqual(
            inspect_recovery_info(raw)["fields"]["vehicleinfoforupdateavailableflag1"],
            1,
        )
        for suffix in (b"", b"\nVehicleInfoForUpdateAvailableFlag1=2"):
            with self.assertRaises(ValueError):
                inspect_recovery_info(
                    raw.split(b"\nVehicleInfoForUpdateAvailableFlag1")[0] + suffix
                )

    def test_native_security_injected_provider_and_failures(self):
        requests = []
        seed = b"S" * 16

        def exchange(ecu, request):
            requests.append(request)
            return b"\x67\x01" + seed if request == b"\x27\x01" else b"\x67\x02"

        result = reprostd_security(
            exchange,
            "fake",
            lambda ecu, supplied_seed: b"K" * 16 if supplied_seed == seed else b"",
        )
        self.assertEqual(result["state"], "security_fragment_completed")
        self.assertEqual(requests, [b"\x27\x01", b"\x27\x02" + b"K" * 16])
        self.assertNotIn("KKKK", str(result))
        requests.clear()
        with self.assertRaises(ValueError):
            reprostd_security(exchange, "fake", None)
        self.assertEqual(requests, [])
        for provider in (lambda ecu, seed: b"short", lambda ecu, seed: None):
            result = reprostd_security(exchange, "fake", provider)  # pyright: ignore[reportArgumentType]
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(result["phase"], "key_provider")
        result = reprostd_security(
            lambda ecu, request: b"\x67\x01short", "fake", lambda ecu, seed: b"K" * 16
        )
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["phase"], "seed")

    def test_invalid_plans_and_deadlines(self):
        for args in (
            ("", "old", "new", (b"x",)),
            ("ecu", "old", "old", (b"x",)),
            ("ecu", "old", "new", ()),
            ("ecu", "old", "new", (b"",)),
            ("ecu", "old", "new", [b"x"]),
        ):
            with self.assertRaises(ValueError):
                ProgramPlan(*args)  # pyright: ignore[reportArgumentType]
        for value in (0, -1, float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                Programmer(SimulatorBackend("synthetic-ECU", "old")).run(
                    plan(), timeout=value
                )


class NativePreparationTests(unittest.TestCase):
    @staticmethod
    def exchange(ecu, request):
        if request == b"\x10\x02":
            return b"\x50\x02" + bytes(4)
        if request == b"\x27\x01":
            return b"\x67\x01" + b"S" * 16
        if request == b"\x27\x02" + b"K" * 16:
            return b"\x67\x02"
        raise AssertionError(request.hex())

    def test_prepare_native_branches_and_packets(self):
        for delay in (0, 1, 2000, 2001, 4000):
            for kind in (0, 1, 2):
                context = ReproStdPrepareContext(
                    25,
                    delay,
                    kind,
                    (b"\x07\x50\x5f",) * 2 if kind else (),
                    b"\x07\x60",
                    50,
                    True,
                )
                actions = reprostd_prepare_actions(context)
                self.assertEqual(actions[0]["operation"], "set_previous_send_time")
                self.assertEqual(actions[2]["data_hex"], "000007771083")
                self.assertEqual(actions[4]["data_hex"], "0000077ffe1083")
                self.assertEqual(actions[-1]["operation"], "security")
                controls = [
                    a["data_hex"]
                    for a in actions
                    if a["operation"] == "raw_write" and "288" in a["data_hex"]
                ]
                self.assertEqual(
                    controls,
                    [
                        "00000777288101",
                        "0000077ffe288101",
                        "00000777288301",
                        "0000077ffe288301",
                    ],
                )
                modes = [
                    a["mode"]
                    for a in actions
                    if a["operation"] == "p5_central_gateway_routine"
                ]
                self.assertEqual(modes, [0, 1, 0, 1, 2, 3, 2, 3] if kind == 1 else [])
                seen = []
                report = reprostd_prepare(
                    lambda a, budget, seen=seen: seen.append(a),
                    self.exchange,
                    "fake",
                    context,
                    lambda ecu, seed: b"K" * 16,
                )
                self.assertEqual(report["state"], "preparation_completed")
                self.assertEqual(len(seen), len(actions))
                self.assertEqual(
                    seen[-2:],
                    [
                        {"operation": "set_ecu_block_size", "size": 0},
                        {"operation": "stop_flow_control_filter"},
                    ],
                )
                self.assertFalse(report["programming_completed"])

    def test_prepare_fault_at_every_platform_action(self):
        context = ReproStdPrepareContext(0, 0, 1, (b"\x07\x50\x5f",))
        actions = reprostd_prepare_actions(context)
        for fault in range(len(actions)):
            if actions[fault]["operation"] in ("programming_session", "security"):
                continue
            seen = []

            external_fault = sum(
                a["operation"] not in ("programming_session", "security")
                for a in actions[:fault]
            )

            def action(entry, budget, seen=seen, external_fault=external_fault):
                seen.append(entry)
                if len(seen) == external_fault + 1:
                    raise ConnectionError("injected platform interruption")

            report = reprostd_prepare(
                action, self.exchange, "fake", context, lambda ecu, seed: b"K" * 16
            )
            self.assertEqual(report["state"], "recovery_required")
            self.assertFalse(report["automatic_retry"])
            self.assertFalse(report["resume_authorized"])
            self.assertEqual(report["operation_index"], fault)
        seen = []
        with self.assertRaises(ValueError):
            reprostd_prepare(
                lambda a, budget: seen.append(a), self.exchange, "fake", context, None
            )
        self.assertEqual(seen, [])
        report = reprostd_prepare(
            lambda a, budget: None,
            self.exchange,
            "fake",
            context,
            lambda ecu, seed: b"K" * 16,
            cancelled=lambda: True,
        )
        self.assertEqual(report["state"], "cancelled")
        for request in (b"\x10\x02", b"\x27\x01", b"\x27\x02" + b"K" * 16):

            def exchange(ecu, data, request=request):
                if data == request:
                    raise KeyboardInterrupt("lost acknowledgement")
                return self.exchange(ecu, data)

            report = reprostd_prepare(
                lambda a, budget: None,
                exchange,
                "fake",
                context,
                lambda ecu, seed: b"K" * 16,
            )
            self.assertEqual(report["state"], "recovery_required")
        report = reprostd_prepare(
            lambda a, budget: None,
            lambda ecu, request: b"\x50\x02",
            "fake",
            context,
            lambda ecu, seed: b"K" * 16,
        )
        self.assertEqual(report["operation"], "programming_session")
        self.assertEqual(report["state"], "recovery_required")

    def test_prepare_resolved_input_boundary(self):
        for args in (
            (-1, 0),
            (0, 120001),
            (0, 0, 3),
            (0, 0, 1, (b"short",)),
        ):
            with self.assertRaises(ValueError):
                ReproStdPrepareContext(*args)  # pyright: ignore[reportArgumentType]


class NativeWriterTests(unittest.TestCase):
    @staticmethod
    def block(method="whole", image=True, package=True, ecu_index=0):
        segment = ReproStdSegment(0x1000, b"authored", b"S" * 16)
        return ReproStdLogicalBlock(
            method,
            1,
            b"C" * 16,
            b"T" * 32,
            (2026, 10, 2, 20, 12, 0, 0, 0),
            segment if image else None,
            segment if package else None,
            ecu_index,
        )

    @staticmethod
    def exchange(ecu, request):
        if request[0] == 0x2E:
            return b"\x6e" + request[1:3]
        if request[0] == 0x31:
            return b"\x71" + request[1:4]
        if request[0] == 0x34:
            return b"\x74\x10\x06"
        if request[0] == 0x36:
            return b"\x76" + request[1:2]
        if request == b"\x37":
            return b"\x77"
        if request == b"\x11\x01":
            return b"\x51\x01"
        raise AssertionError(request.hex())

    def test_writer_methods_native_order(self):
        for method, selector in (("whole", 1), ("delta", 0x21), ("compressed", 0x11)):
            requests, actions = [], []

            def exchange(ecu, request, requests=requests):
                requests.append(request)
                return self.exchange(ecu, request)

            result = reprostd_write(
                lambda a, budget, actions=actions: actions.append(a),
                exchange,
                "fake",
                (self.block(method),),
            )
            self.assertEqual(result["state"], "writer_completed")
            self.assertFalse(result["programming_completed"])
            downloads = [r for r in requests if r[0] == 0x34]
            self.assertEqual([r[1] for r in downloads], [1, selector])
            routines = [r[2:4] for r in requests if r[0] == 0x31]
            self.assertEqual(
                routines,
                [b"\x10\xf5"]
                + ([] if method == "delta" else [b"\xff\x00"])
                + [b"\x10\xf6"],
            )
            self.assertEqual(requests[-1], b"\x11\x01")
            self.assertEqual(actions[-3]["data_hex"], "000007771081")
            self.assertEqual(actions[-2]["data_hex"], "0000077ffe1081")
        requests = []
        result = reprostd_write(
            lambda a, budget: None,
            lambda ecu, request: (
                requests.append(request) or self.exchange(ecu, request)
            ),
            "fake",
            (self.block("delta", False, False),),
        )
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual([r[0] for r in requests], [0x2E, 0x2E, 0x2E, 0x11])

    def test_writer_fault_each_exchange_and_platform_action(self):
        blocks = (self.block(ecu_index=0), self.block(ecu_index=1))
        baseline = []

        def platform(entry, budget):
            baseline.append(("action", entry))

        def exchange(ecu, request):
            baseline.append(("exchange", request))
            return self.exchange(ecu, request)

        self.assertEqual(
            reprostd_write(platform, exchange, "fake", blocks)["state"],
            "writer_completed",
        )
        for fault in range(len(baseline)):
            seen = []

            def record(kind, value, fault=fault, seen=seen):
                seen.append((kind, value))
                if len(seen) == fault + 1:
                    raise ConnectionError("injected lost acknowledgement")

            def platform(entry, budget):
                record("action", entry)

            def exchange(ecu, request):
                record("exchange", request)
                return self.exchange(ecu, request)

            result = reprostd_write(platform, exchange, "fake", blocks)
            self.assertEqual(result["state"], "recovery_required")
            if len(seen) == fault + 2:
                self.assertEqual(
                    seen[-1], ("action", {"operation": "restore_send_timeout"})
                )
            else:
                self.assertEqual(len(seen), fault + 1)
            self.assertFalse(result["resume_authorized"])
        result = reprostd_write(
            lambda a, budget: None,
            self.exchange,
            "fake",
            blocks,
            cancelled=lambda: True,
        )
        self.assertEqual(result["state"], "cancelled")

    def test_writer_pending_receive_shares_aggregate_budget(self):
        current = [b""]

        def exchange(ecu, request):
            if request[0] == 0x36:
                current[0] = b"\x76" + request[1:2] + bytes(4093)
                return b"\x7f\x36\x78\x00"
            return self.exchange(ecu, request)

        segment = ReproStdSegment(0x1000, b"X", b"S" * 16)
        block = self.block(package=False)
        block = ReproStdLogicalBlock(
            block.method,
            block.slot,
            block.nonce,
            block.tester_info,
            block.system_time,
            segment,
        )
        result = reprostd_write(
            lambda a, budget: None,
            exchange,
            "fake",
            (block,) * 300,
            receive=lambda ecu: current[0],
        )
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["error"], "ValueError")
        self.assertLess(result["logical_block"], 300)
        self.assertFalse(result["automatic_retry"])

    def test_writer_rejects_input_before_platform(self):
        for blocks in ((), [], (None,)):
            with self.assertRaises(ValueError):
                reprostd_write(
                    lambda a, budget: self.fail("unexpected action"),
                    self.exchange,
                    "fake",
                    blocks,  # pyright: ignore[reportArgumentType]
                )
        for method, image in (
            ("whole", False),
            ("compressed", False),
            ("guessed", True),
        ):
            with self.assertRaises(ValueError):
                self.block(method, image)


class NativeUnifiedBuilderTests(unittest.TestCase):
    def test_supplied_fingerprint_and_uint40_routines(self):
        records = unified_fingerprint_requests(
            bytes.fromhex("0100000000"), b"K" * 16, b"N" * 16
        )
        self.assertEqual(
            [r[0][:3] for r in records],
            [b"\x2e\x02\x03", b"\x2e\x02\x01", b"\x2e\x02\x02"],
        )
        self.assertEqual([len(r[0]) for r in records], [8, 19, 19])
        for operation, identifier in (
            ("stub_check", "10f0"),
            ("erase", "ff00"),
            ("routine_check", "10f1"),
            ("verify", "10f2"),
        ):
            request, response = unified_routine_request(
                operation, 0x01FFFFFFFE, 3, 0x10
            )
            self.assertEqual(
                request, bytes.fromhex("3101" + identifier + "45020000000100000010")
            )
            self.assertEqual(response, bytes.fromhex("7101" + identifier))
        for offset in (-1, True, 0x10000000000):
            with self.assertRaises(ValueError):
                unified_routine_request("erase", offset, 0, 1)
        with self.assertRaises(ValueError):
            unified_routine_request("erase", 0xFFFFFFFFFF, 1, 1)
        with self.assertRaises(ValueError):
            unified_fingerprint_requests(b"short6", b"K" * 16, b"N" * 16)


class NativeUnifiedWriterTests(unittest.TestCase):
    @staticmethod
    def program(last=True):
        return UnifiedProgram(
            bytes.fromhex("0100000000"),
            b"K" * 16,
            b"N" * 16,
            8,
            (UnifiedArea(0x100, b"stub"),),
            (UnifiedArea(0x200, b"routine"),),
            (UnifiedArea(0x1000, b"authored firmware"),),
            ((0x1000, 16),),
            last,
            100,
        )

    @staticmethod
    def exchange(ecu, request):
        return NativeWriterTests.exchange(ecu, request)

    def test_unified_download_and_full_sequence(self):
        self.assertEqual(
            unified_download_request(0x1FFFFFFFE, 3, 16, encrypted=True, memory_type=1),
            bytes.fromhex("34014601020000000100000010"),
        )
        for last in (False, True):
            requests, actions = [], []

            def exchange(ecu, request, requests=requests):
                requests.append(request)
                return self.exchange(ecu, request)

            result = unified_write(
                lambda a, budget, actions=actions: actions.append(a),
                exchange,
                "fake",
                self.program(last),
            )
            self.assertEqual(result["state"], "writer_completed")
            self.assertFalse(result["programming_completed"])
            self.assertEqual([r[3] for r in requests if r[0] == 0x34], [1, 1, 0])
            self.assertTrue(
                all(r[1:3] == b"\x01\x46" for r in requests if r[0] == 0x34)
            )
            self.assertEqual(
                [r[2:4] for r in requests if r[0] == 0x31],
                [b"\x10\xf0", b"\xff\x00", b"\x10\xf1", b"\x10\xf2"],
            )
            self.assertEqual(any(r == b"\x11\x01" for r in requests), last)
            self.assertEqual(
                sum(a["operation"] == "wait" for a in actions), 2 if last else 0
            )
            self.assertNotIn("KKKK", str(result))

    def test_unified_fault_every_action_and_exchange(self):
        baseline = []

        def action(entry, budget):
            baseline.append(("action", entry))

        def exchange(ecu, request):
            baseline.append(("exchange", request))
            return self.exchange(ecu, request)

        self.assertEqual(
            unified_write(action, exchange, "fake", self.program())["state"],
            "writer_completed",
        )
        for fault in range(len(baseline)):
            seen = []

            def record(kind, value, seen=seen, fault=fault):
                seen.append((kind, value))
                if len(seen) == fault + 1:
                    raise KeyboardInterrupt("injected interruption")

            def action(entry, budget):
                record("action", entry)

            def exchange(ecu, request):
                record("exchange", request)
                return self.exchange(ecu, request)

            result = unified_write(action, exchange, "fake", self.program())
            self.assertEqual(result["state"], "recovery_required")
            if len(seen) == fault + 2:
                self.assertEqual(
                    seen[-1], ("action", {"operation": "restore_send_timeout"})
                )
            else:
                self.assertEqual(len(seen), fault + 1)
            self.assertFalse(result["resume_authorized"])
        result = unified_write(
            lambda a, budget: self.fail("unexpected action"),
            self.exchange,
            "fake",
            self.program(),
            cancelled=lambda: True,
        )
        self.assertEqual(result["state"], "cancelled")
        for wakeup in (-1, 1, 51, 120050):
            p = self.program()
            with self.assertRaises(ValueError):
                UnifiedProgram(
                    p.offset_address,
                    p.calibration_key,
                    p.nonce,
                    p.security_property,
                    p.stub,
                    p.routine,
                    p.image,
                    p.erase,
                    p.last_cpu_in_node,
                    wakeup,
                )


class NativeEachAreaTests(unittest.TestCase):
    def test_area_sequence_and_all_fault_positions(self):
        program = UnifiedProgram(
            bytes(5),
            b"K" * 16,
            b"N" * 16,
            0,
            (UnifiedArea(0x100, b"stub1"), UnifiedArea(0x200, b"stub2")),
            (),
            (UnifiedArea(0x1000, b"image1"), UnifiedArea(0x2000, b"image2")),
            ((0x1000, 6), (0x2000, 6)),
            True,
            0,
        )
        baseline = []

        def action(entry, budget):
            baseline.append(("action", entry))

        def exchange(ecu, request):
            baseline.append(("exchange", request))
            return NativeWriterTests.exchange(ecu, request)

        result = unified_write(action, exchange, "fake", program, each_area=True)
        self.assertEqual(result["state"], "writer_completed")
        requests = [r for kind, r in baseline if kind == "exchange"]
        self.assertEqual(sum(r[0] == 0x2E for r in requests), 6)
        self.assertEqual(
            [r[2:4] for r in requests if r[0] == 0x31],
            [b"\x10\xf0", b"\xff\x00", b"\x10\xf2"] * 2,
        )
        for fault in range(len(baseline)):
            seen = []

            def record(kind, value, seen=seen, fault=fault):
                seen.append((kind, value))
                if len(seen) == fault + 1:
                    raise ConnectionError("lost response")

            def action(entry, budget):
                record("action", entry)

            def exchange(ecu, request):
                record("exchange", request)
                return NativeWriterTests.exchange(ecu, request)

            result = unified_write(action, exchange, "fake", program, each_area=True)
            self.assertEqual(result["state"], "recovery_required")
            if len(seen) == fault + 2:
                self.assertEqual(
                    seen[-1], ("action", {"operation": "restore_send_timeout"})
                )
            else:
                self.assertEqual(len(seen), fault + 1)
        bad = UnifiedProgram(
            program.offset_address,
            program.calibration_key,
            program.nonce,
            program.security_property,
            program.stub[:1],
            program.routine,
            program.image,
            program.erase,
            True,
            0,
        )
        with self.assertRaises(ValueError):
            unified_write(
                lambda a, budget: self.fail("unexpected action"),
                NativeWriterTests.exchange,
                "fake",
                bad,
                each_area=True,
            )


class NativeChannelBoundaryTests(unittest.TestCase):
    def test_bad_packets_fail_before_exchange(self):
        calls = []
        channel = NativeProgrammingChannel(
            lambda ecu, request: calls.append(request) or b"\x77", "fake"
        )
        for request, expected in (
            (b"", b"\x77"),
            (b"X" * 4096, b"\x77"),
            (b"\x37", b""),
            (b"\x37", b"X" * 4096),
        ):
            with self.assertRaises(ValueError):
                channel.call(request, expected)
        self.assertEqual(calls, [])
        channel = NativeProgrammingChannel(lambda ecu, request: b"", "fake")
        with self.assertRaises(ValueError):
            channel.call(b"\x37", None)


class NativeUnifiedPreparationTests(unittest.TestCase):
    @staticmethod
    def exchange(ecu, request):
        if request == b"\x22\xf1\x81":
            return b"\x62\xf1\x81X"
        if request == b"\x27\x01" + b"A" * 16:
            return b"\x67\x01" + b"S" * 16
        return NativePreparationTests.exchange(ecu, request)

    def test_unified_prepare_flags_and_branches(self):
        for delay in (0, 2000, 2001):
            for kind in (0, 1, 2):
                context = UnifiedPrepareContext(
                    20,
                    delay,
                    b"A" * 16,
                    kind,
                    (b"\x07\x50\x5f",) if kind else (),
                    b"\x07\x50\xe9",
                    True,
                    True,
                )
                actions = unified_prepare_actions(context)
                self.assertEqual(
                    [
                        a["enable"]
                        for a in actions
                        if a["operation"] == "cancel_automatic_ig_off"
                    ],
                    [True],
                )
                controls = [
                    a["data_hex"]
                    for a in actions
                    if a["operation"] == "raw_write" and "288" in a["data_hex"]
                ]
                self.assertEqual(controls, ["00000777288101", "0000077ffe288101"])
                self.assertNotIn("41414141", str(actions))
                result = unified_prepare(
                    lambda a, budget: None,
                    self.exchange,
                    "fake",
                    context,
                    lambda ecu, seed: b"K" * 16,
                )
                self.assertEqual(result["state"], "preparation_completed")
                self.assertNotIn("AAAA", str(result))

    def test_optional_software_id_catches_native_failures_only(self):
        context = UnifiedPrepareContext(0, 0, b"A" * 16, native_flag_724=True)
        for response, expected in (
            (b"\x61", "preparation_completed"),
            (b"", "recovery_required"),
            (bytes(4096), "recovery_required"),
        ):

            def exchange(ecu, request, response=response):
                if request == b"\x22\xf1\x81":
                    return response
                return self.exchange(ecu, request)

            result = unified_prepare(
                lambda *args: None, exchange, "fake", context, lambda *args: b"K" * 16
            )
            self.assertEqual(result["state"], expected)

        def invalid_provider(ecu, request):
            if request == b"\x22\xf1\x81":
                raise ValueError("invalid captured provider")
            return self.exchange(ecu, request)

        result = unified_prepare(
            lambda *args: None,
            invalid_provider,
            "fake",
            context,
            lambda *args: b"K" * 16,
        )
        self.assertEqual(result["state"], "recovery_required")

    def test_software_id_failure_requires_explicit_native_flag(self):
        for flag in (False, True):
            context = UnifiedPrepareContext(0, 0, b"A" * 16, native_flag_724=flag)

            def exchange(ecu, request):
                if request == b"\x22\xf1\x81":
                    from scripts.programming import NativeTransportError

                    raise NativeTransportError(9)
                return self.exchange(ecu, request)

            result = unified_prepare(
                lambda a, budget: None,
                exchange,
                "fake",
                context,
                lambda ecu, seed: b"K" * 16,
            )
            self.assertEqual(
                result["state"],
                "preparation_completed" if flag else "recovery_required",
            )
        context = UnifiedPrepareContext(0, 0, b"A" * 16, native_flag_724=True)

        def timeout_exchange(ecu, request):
            raise TimeoutError("synthetic timeout")

        result = unified_prepare(
            lambda a, budget: None,
            timeout_exchange,
            "fake",
            context,
            lambda ecu, seed: b"K" * 16,
        )
        self.assertEqual(result["state"], "recovery_required")

    def test_fault_every_unified_prepare_platform_action(self):
        context = UnifiedPrepareContext(0, 0, b"A" * 16)
        actions = unified_prepare_actions(context)
        external = [
            (i, a)
            for i, a in enumerate(actions)
            if a["operation"]
            not in ("read_software_id", "programming_session", "security")
        ]
        for fault, (expected_index, _) in enumerate(external):
            seen = []

            def action(entry, budget, seen=seen, fault=fault):
                seen.append(entry)
                if len(seen) == fault + 1:
                    raise ConnectionError("injected action failure")

            result = unified_prepare(
                action, self.exchange, "fake", context, lambda ecu, seed: b"K" * 16
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(result["operation_index"], expected_index)
            self.assertFalse(result["resume_authorized"])
        with self.assertRaises(ValueError):
            unified_prepare(
                lambda a, budget: self.fail("unexpected action"),
                self.exchange,
                "fake",
                context,
                None,
            )


class RecoveryNativeTypesTests(unittest.TestCase):
    def test_native_vin_and_byte_node_types(self):
        result = inspect_recovery_info(
            b"[RecoveryInfo]\nVIN=SYNTHETIC000000001\nCIDNodeNum=1\nCIDNode1=255"
        )
        self.assertEqual(result["fields"]["vin"], "SYNTHETIC000000001")
        self.assertEqual(result["fields"]["cidnode1"], 255)
        for value in ("node", "-1", "256"):
            with self.assertRaises(ValueError):
                inspect_recovery_info(
                    ("[RecoveryInfo]\nCIDNodeNum=1\nCIDNode1=" + value).encode()
                )


class NativeSharedDataTests(unittest.TestCase):
    def test_native_fields_and_filtering(self):
        self.assertEqual(native_data_request("assembly_p4")["request_hex"], "1a89")
        self.assertEqual(native_data_request("assembly_p4")["utility_policy"], "old")
        for name, prefix in (
            ("assembly_p4", b"\x5a"),
            ("assembly_p5", b"\x62\x01\x05"),
        ):
            self.assertEqual(
                decode_native_data(name, prefix + b"\0\0ABC\0tail"), "IIABC"
            )
            self.assertEqual(decode_native_data(name, prefix + bytes(12)), "")
            self.assertEqual(decode_native_data(name, prefix + b"bad\x80"), "")
        self.assertEqual(
            decode_native_data("serial", b"\x62\xf1\x8c" + b"A" * 300), "A" * 256
        )
        self.assertEqual(
            decode_native_data("cbest", b"\x62\x02\x10" + bytes(range(60))),
            bytes(range(50)).hex().upper(),
        )
        response = (
            b"\x62\x01\x28\x00"
            + b"\x07"
            + b"SYNTHETIC123"
            + b"\x08"
            + b"\0" * 12
            + b"tail"
        )
        self.assertEqual(
            decode_native_data("slave_cid", response),
            [{"node": 7, "cid": "SYNTHETIC123"}],
        )
        for name in ("slave_cid", "assembly_p4", "assembly_p5", "serial", "cbest"):
            for response in (b"", b"wrong", b"X" * 4096):
                with self.assertRaises(ValueError):
                    decode_native_data(name, response)


class NativeEthernetTests(unittest.TestCase):
    def test_frame_filter_pending_and_native_length_widths(self):
        self.assertEqual(
            ethernet_request(b"\x01\x03", b"\x27\x01"),
            bytes.fromhex("02fd8001000000060e8001032701"),
        )
        replies = iter(
            [
                bytes.fromhex("99990e8077"),
                bytes.fromhex("01030e807f3778"),
                bytes.fromhex("01030e8077"),
            ]
        )
        requests = []
        channel = NativeEthernetChannel(
            lambda ecu, data: requests.append(data) or next(replies),
            "fake",
            b"\x01\x03",
            receive=lambda ecu: next(replies),
        )
        self.assertEqual(channel.call(b"\x37", b"\x77"), b"\x77")
        self.assertEqual(len(requests), 1)
        self.assertEqual(channel.raw_messages, 3)
        self.assertEqual(ethernet_block_size(bytes.fromhex("74201014")), 4114)
        self.assertEqual(ethernet_block_size(bytes.fromhex("74500300000000")), 1)
        for response in (
            b"",
            bytes.fromhex("740003"),
            bytes.fromhex("743010"),
            bytes.fromhex("741002"),
        ):
            with self.assertRaises(ValueError):
                ethernet_block_size(response)

    def test_native_ethernet_writer_and_precise_retry_policy(self):
        target = b"\x01\x03"
        segment = ReproStdSegment(0x1000, b"X" * 5000, b"S" * 16)
        template = NativeWriterTests.block(package=False)
        block = ReproStdLogicalBlock(
            template.method,
            template.slot,
            template.nonce,
            template.tester_info,
            template.system_time,
            segment,
        )
        requests = []
        failures = [2]

        def exchange(ecu, frame):
            self.assertEqual(frame[:4], bytes.fromhex("02fd8001"))
            self.assertEqual(int.from_bytes(frame[4:8], "big"), len(frame) - 8)
            self.assertEqual(frame[8:12], b"\x0e\x80" + target)
            request = frame[12:]
            requests.append(request)
            if request[0] == 0x36 and failures[0]:
                failures[0] -= 1
                raise NativeTransportError(9)
            response = (
                b"\x74\x20\x10\x14"
                if request[0] == 0x34
                else NativeWriterTests.exchange(ecu, request)
            )
            return target + b"\x0e\x80" + response

        actions = []
        result = ethernet_write(
            lambda a, budget: actions.append(a),
            exchange,
            "fake",
            target,
            (block,),
            wakeup_ms=100,
        )
        self.assertEqual(result["state"], "writer_completed")
        transfers = [r for r in requests if r[0] == 0x36]
        self.assertEqual([len(r) for r in transfers], [4116, 4116, 4116, 888])
        self.assertEqual(transfers[0], transfers[1])
        self.assertEqual(transfers[1], transfers[2])
        self.assertEqual(sum(a["operation"] == "wait" for a in actions), 2)
        for error in (NativeTransportError(7), TimeoutError("synthetic timeout")):
            attempts = []

            def failed_exchange(ecu, frame, error=error, attempts=attempts):
                if frame[12] == 0x36:
                    attempts.append(frame)
                    raise error
                return (
                    target + b"\x0e\x80" + NativeWriterTests.exchange(ecu, frame[12:])
                )

            result = ethernet_write(
                lambda a, budget: None, failed_exchange, "fake", target, (block,)
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(len(attempts), 1)

    def test_ethernet_all_failure_positions_and_early_rejection(self):
        target = b"\x01\x00"
        block = NativeWriterTests.block()
        baseline = []

        def action(entry, budget):
            baseline.append(("action", entry))

        def exchange(ecu, frame):
            baseline.append(("exchange", frame))
            return target + b"\x0e\x80" + NativeWriterTests.exchange(ecu, frame[12:])

        self.assertEqual(
            ethernet_write(action, exchange, "fake", target, (block,))["state"],
            "writer_completed",
        )
        for fault in range(len(baseline)):
            seen = []

            def record(kind, value, seen=seen, fault=fault):
                seen.append((kind, value))
                if len(seen) == fault + 1:
                    raise ConnectionError("interrupted Ethernet phase")

            def action(entry, budget):
                record("action", entry)

            def exchange(ecu, frame):
                record("exchange", frame)
                return (
                    target + b"\x0e\x80" + NativeWriterTests.exchange(ecu, frame[12:])
                )

            result = ethernet_write(action, exchange, "fake", target, (block,))
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(
                [a[1]["operation"] for a in seen[fault + 1 :]],
                ["stop_periodic", "finish_diag_comm"],
            )
        with self.assertRaises(ValueError):
            ethernet_write(
                lambda a, budget: self.fail("unexpected action"),
                exchange,
                "fake",
                target,
                (NativeWriterTests.block("delta"),),
            )


class NativeCallbackBoundaryTests(unittest.TestCase):
    def test_cancel_and_deadline_take_precedence_at_callback_boundary(self):
        for pending in (False, True):
            for fail in (False, True):
                for cancelled in (False, True):
                    state = {"cancelled": False, "now": 0.0}

                    def callback(*args, state=state, cancelled=cancelled, fail=fail):
                        state["cancelled"] = cancelled
                        state["now"] = 0.0 if cancelled else 31.0
                        if fail:
                            raise ConnectionError("callback failed after boundary")
                        return b"\x50"

                    channel = NativeProgrammingChannel(
                        (lambda *args: b"\x7f\x10\x78") if pending else callback,
                        "authored",
                        cancelled=lambda state=state: state["cancelled"],
                        clock=lambda state=state: state["now"],
                        receive=callback,
                    )
                    with self.assertRaises(
                        InterruptedError if cancelled else TimeoutError
                    ):
                        channel.call(b"\x10", b"\x50")
                    self.assertEqual(channel.history, [])


class NativeResponseBudgetTests(unittest.TestCase):
    def test_explicit_large_response_budget_can_retain_only_hashes(self):
        payload = b"\x62" + bytes(4094)
        channel = NativeProgrammingChannel(
            lambda *args: payload,
            "authored",
            response_budget=2 * 1024 * 1024,
            retain_payload_history=False,
        )
        for _ in range(300):
            self.assertEqual(channel.call(b"\x22", b"\x62"), payload)
        self.assertEqual(channel.response_bytes, 300 * 4095)
        self.assertEqual(len(channel.history), 300)
        self.assertNotIn("response_hex", channel.history[-1])
        self.assertEqual(channel.history[-1]["response_length"], 4095)
        for budget in (0, -1, True, 128 * 1024 * 1024 + 1):
            with self.assertRaises(ValueError):
                NativeProgrammingChannel(
                    lambda *args: payload, "authored", response_budget=budget
                )


class NativePendingElapsedTests(unittest.TestCase):
    def test_native_second_quantization_and_expiry_write_excludes_host_abort(self):
        from scripts.programming import NativePendingTimeout

        now = [0.9]
        writes = []

        def receive(ecu):
            now[0] = 1.0
            return bytes.fromhex("7f3178")

        channel = NativeProgrammingChannel(
            lambda *args: bytes.fromhex("7f3178"),
            "authored",
            timeout=10,
            clock=lambda: now[0],
            receive=receive,
            pending_response_timeout_seconds=1,
            pending_timeout_write=lambda ecu, payload: writes.append(payload),
        )
        with self.assertRaises(NativePendingTimeout) as caught:
            channel.call(b"\x31", b"\x71")
        self.assertEqual(caught.exception.request, b"\x31")
        self.assertEqual(caught.exception.response, bytes.fromhex("7f3178"))
        self.assertEqual(writes, [b"\x3e"])
        for aborted in ("cancel", "deadline"):
            now[0] = 0.9
            writes.clear()
            stopped = [False]

            def interrupted_receive(ecu, aborted=aborted, stopped=stopped):
                now[0] = 20 if aborted == "deadline" else 1
                stopped[0] = aborted == "cancel"
                return bytes.fromhex("7f3178")

            channel = NativeProgrammingChannel(
                lambda *args: bytes.fromhex("7f3178"),
                "authored",
                timeout=10,
                clock=lambda: now[0],
                cancelled=lambda stopped=stopped: stopped[0],
                receive=interrupted_receive,
                pending_response_timeout_seconds=1,
                pending_timeout_write=lambda ecu, payload: writes.append(payload),
            )
            with self.assertRaises((TimeoutError, InterruptedError)):
                channel.call(b"\x31", b"\x71")
            self.assertEqual(writes, [])

    def test_native_timer_starts_on_first_pending_and_counts_elapsed(self):
        now = [0.0]
        receives = []

        def exchange(*args):
            now[0] = 20.0
            return b"\x7f\x31\x78"

        def receive(*args):
            receives.append(now[0])
            now[0] += 10
            return b"\x7f\x31\x78"

        channel = NativeProgrammingChannel(
            exchange,
            "authored",
            timeout=100,
            clock=lambda: now[0],
            receive=receive,
            pending_response_timeout_seconds=30,
        )
        with self.assertRaises(TimeoutError):
            channel.call(b"\x31", b"\x71")
        self.assertEqual(receives, [20, 30, 40])
        for value in (-1, True, float("nan"), float("inf"), 2**32):
            with self.assertRaises(ValueError):
                NativeProgrammingChannel(
                    exchange, "authored", pending_response_timeout_seconds=value
                )


class NativeMetadataContextTests(unittest.TestCase):
    def test_imported_cuw_builds_writer_blocks_without_geometry_defaults(self):
        from scripts.calibration import parse_cuw
        from scripts.programming import native_reprostd_blocks
        from tests.test_calibration import logical_container

        clock = (2026, 10, 2, 20, 12, 0, 0, 0)
        for spec in ("03", "04"):
            blocks = native_reprostd_blocks(
                parse_cuw(logical_container(spec=spec)),
                1,
                ("authored-old",),
                bytes(32),
                clock,
            )
            self.assertEqual(blocks[0].nonce, bytes(range(16)))
            image = blocks[0].image
            assert image is not None
            self.assertEqual(image.address, 0x1000)
            self.assertEqual(image.data, b"data")
            self.assertEqual(len(image.signature), 16 if spec == "03" else 256)
            with self.assertRaises(ValueError):
                native_reprostd_blocks(
                    parse_cuw(logical_container()),
                    1,
                    ("wrong-current",),
                    bytes(32),
                    clock,
                )
        for code, kinds in (
            ("01", ("ReproData", "EraseAndReproRoutine")),
            ("07", ("DeltaReproData", "DeltaEraseAndReproRoutine")),
            ("09", ("CompressionReproData", "CompressionEraseAndReproRoutine")),
        ):
            blocks = native_reprostd_blocks(
                parse_cuw(logical_container(code, kinds=kinds)),
                1,
                ("authored-old",),
                bytes(32),
                clock,
            )
            self.assertIsNotNone(blocks[0].routine_package)


class EthernetPreparationTests(unittest.TestCase):
    def test_native_order_gateway_and_fault_every_callback(self):
        from scripts.programming import ethernet_prepare

        baseline = []

        def action(entry, budget):
            baseline.append(("action", entry["operation"]))

        def exchange(ecu, frame):
            payload = frame[12:]
            baseline.append(("exchange", payload[:2]))
            if payload == b"\x27\x21":
                response = b"\x67\x21" + bytes(16)
            elif payload.startswith(b"\x27\x22"):
                self.assertEqual(len(payload), 258)
                response = b"\x67\x22"
            elif payload.startswith(b"\x31"):
                response = b"\x71" + payload[1:] + (b"\x01" if payload[1] == 3 else b"")
            else:
                response = NativePreparationTests.exchange(ecu, payload)
            return frame[10:12] + b"\x0e\x80" + response

        kwargs = {
            "gateway_target": b"\x01\x03",
            "gateway_key_provider": lambda *args: bytes(256),
        }
        result = ethernet_prepare(
            action, exchange, "authored", b"\x01\x00", lambda *args: b"K" * 16, **kwargs
        )
        self.assertEqual(result["state"], "preparation_completed")
        self.assertIn(("exchange", b"\x27\x21"), baseline)
        self.assertEqual(baseline[-1], ("exchange", b"\x27\x02"))
        steps = tuple(baseline)
        for fault in range(len(steps)):
            calls = []

            def mark(kind, fault=fault, calls=calls):
                calls.append(kind)
                if len(calls) == fault + 1:
                    raise ConnectionError("authored phase interruption")

            def failed_action(entry, budget):
                mark("action")

            def failed_exchange(ecu, frame):
                mark("exchange")
                return exchange(ecu, frame)

            result = ethernet_prepare(
                failed_action,
                failed_exchange,
                "authored",
                b"\x01\x00",
                lambda *args: b"K" * 16,
                **kwargs,
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(len(calls), fault + 1)
        with self.assertRaises(ValueError):
            ethernet_prepare(
                lambda *args: self.fail("unexpected callback"),
                exchange,
                "authored",
                b"\x01\x00",
                lambda *args: b"K" * 16,
                gateway_target=b"\x01\x03",
            )


class NativeErrorPrivacyTests(unittest.TestCase):
    def test_provider_exception_does_not_publish_authorization_material(self):
        secret = "authored-private-provider-material"

        def provider(*args):
            raise ValueError(secret)

        result = reprostd_security(
            NativePreparationTests.exchange, "authored", provider
        )
        self.assertEqual(result["error"], "ValueError")
        self.assertNotIn(secret, str(result))


class NativePre206ContextTests(unittest.TestCase):
    def test_srecord_package_context_runs_actual_native_writer_fragments(self):
        from scripts.calibration import parse_cuw
        from scripts.programming import native_reprostd_blocks
        from tests.test_calibration import NativeMaterializationTests, logical_container

        blocks = native_reprostd_blocks(
            parse_cuw(
                logical_container(
                    "01",
                    kinds=("ReproData", "EraseAndReproRoutine"),
                    version=107,
                    payloads={"ReproData": NativeMaterializationTests.payload()},
                )
            ),
            1,
            ("authored-old",),
            bytes(32),
            (2026, 10, 2, 20, 12, 0, 0, 0),
        )
        result = reprostd_write(
            lambda *args: None, NativeWriterTests.exchange, "authored", blocks
        )
        self.assertEqual(result["state"], "writer_completed")


class NativePrepareCleanupTests(unittest.TestCase):
    def test_uncertain_bs_enable_restores_and_releases_filter(self):
        for unified in (False, True):
            events = []
            cancelled = [False]

            def action(entry, budget, events=events, cancelled=cancelled):
                self.assertGreater(budget, 0)
                events.append(entry)
                if entry == {"operation": "set_ecu_block_size", "size": 1}:
                    cancelled[0] = True
                    raise ConnectionError("applied then interrupted")

            context = (
                UnifiedPrepareContext(0, 0, b"A" * 16, extended_addressing=True)
                if unified
                else ReproStdPrepareContext(0, 0, extended_addressing=True)
            )
            from functools import partial

            runner = (
                partial(unified_prepare, context=context)
                if isinstance(context, UnifiedPrepareContext)
                else partial(reprostd_prepare, context=context)
            )
            result = runner(
                action,
                NativeUnifiedPreparationTests.exchange
                if unified
                else NativePreparationTests.exchange,
                "authored",
                key_provider=lambda *args: b"K" * 16,
                cancelled=lambda cancelled=cancelled: cancelled[0],
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(
                events[-2:],
                [
                    {"operation": "set_ecu_block_size", "size": 0},
                    {"operation": "stop_flow_control_filter"},
                ],
            )

    def test_imported_node_timings_and_ids_build_prepare_context(self):
        from dataclasses import replace

        from scripts.calibration import parse_cuw
        from scripts.programming import (
            native_ethernet_prepare_inputs,
            native_reprostd_prepare_context,
        )
        from tests.test_calibration import logical_container

        container = parse_cuw(logical_container())
        extra = b"\nWakeUpTimeAfterReset=2\nEmissionsRelatedSystem=3\nNumberOfGateway=1\n01_GatewayDiagID=07505F\n01_GatewayLogicalAddress=0103\nLogicalAddress=0100\nChargeLocalBusEcuReprogrammingFlow=01\nChargeLocalBusPowerOnControllingEcuDiagID=0760\nChargeLocalBusEcuStartTimeAfterPowerOn=4\n"
        data = container.attached.data.replace(
            b"NumberOfLogicalBlock=1", b"NumberOfLogicalBlock=1" + extra
        )
        container = replace(container, attached=replace(container.attached, data=data))
        context = native_reprostd_prepare_context(
            container, 1, gateway_kind=1, extended_addressing=False
        )
        self.assertEqual(
            (
                context.wakeup_ms,
                context.emissions_delay_ms,
                context.charge_bus_start_ms,
            ),
            (100, 30, 200),
        )
        self.assertEqual(context.gateway_ids, (bytes.fromhex("07505f"),))
        self.assertEqual(context.charge_bus_id, bytes.fromhex("0760"))
        self.assertEqual(
            native_ethernet_prepare_inputs(container, 1),
            {
                "target": bytes.fromhex("0100"),
                "gateway_target": bytes.fromhex("0103"),
                "wakeup_ms": 100,
            },
        )


class NativeUnifiedImportTests(unittest.TestCase):
    def test_pre101_vehicle_fields_are_not_unified_node_zero(self):
        from scripts.programming import (
            native_unified_prepare_context,
            native_unified_program,
        )

        container = NativeExecuteTests.container(modern=True)
        with self.assertRaisesRegex(ValueError, "populated native node"):
            native_unified_prepare_context(
                container,
                0,
                gateway_kind=0,
                extended_addressing=False,
                native_flag_724=False,
            )
        with self.assertRaisesRegex(ValueError, "populated native node"):
            native_unified_program(
                container, 0, ("authored",), extended_addressing=False
            )

    def test_source_headers_materialize_areas_and_mismatch_is_rejected(self):
        from scripts.calibration import parse_cuw
        from scripts.programming import native_unified_program
        from tests.test_calibration import (
            NativeMaterializationTests,
            metadata_container,
        )

        metadata = """[Format]
Version=101
[Vehicle]
NumberOfNode=1
ContactType=P5-Unified
[Node01]
NumberOfCalibration=1
RequiredSpecReproVer=02
WakeUpTimeAfterReset=2
[CPU11]
NumberOfTargets=1
01_TargetCalibration=AUTHORED-OLD
OffsetAddress=0000000000
SeedKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Nonce=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
SecurityProperty2=08
[CPUImage11]
NumberOfAreaSettings=1
01_StartAddress=00001000
01_Length=00000004
[WriteRoutine11]
NumberOfAreaSettings=1
01_StartAddress=00001002
01_Length=00000002
[EraseRoutine11]
NumberOfAreaSettings=1
01_StartAddress=00001000
01_Length=00000002
"""
        container = parse_cuw(
            metadata_container(
                metadata,
                ((b"authored.srec", NativeMaterializationTests.payload(1)),),
                1,
            )
        )
        program = native_unified_program(
            container, 0, ("AUTHORED-OLD",), extended_addressing=False
        )
        self.assertEqual(program.image[0].data, b"data")
        self.assertEqual(program.stub[0].data, b"da")
        self.assertEqual(program.routine[0].data, b"ta")
        self.assertEqual(program.erase, ((0x1000, 4),))
        self.assertTrue(program.last_cpu_in_node)
        self.assertEqual(program.wakeup_ms, 100)
        from dataclasses import replace
        from unittest.mock import patch

        oversized = replace(
            container,
            attached=replace(
                container.attached,
                data=container.attached.data.replace(
                    b"01_Length=00000004", b"01_Length=04000000", 1
                ),
            ),
        )
        with (
            patch(
                "scripts.programming.materialize_native_srecord_area",
                side_effect=AssertionError("allocation attempted"),
            ),
            self.assertRaisesRegex(ValueError, "before allocation"),
        ):
            native_unified_program(
                oversized, 0, ("AUTHORED-OLD",), extended_addressing=False
            )
        with self.assertRaisesRegex(ValueError, "does not match"):
            native_unified_program(container, 0, ("OTHER",), extended_addressing=False)


class NativeUnified12Tests(unittest.TestCase):
    def test_old_download_width_and_full_writer(self):
        from scripts.programming import unified12_block_size

        self.assertEqual(unified12_block_size(bytes.fromhex("74200003")), 1)
        self.assertEqual(unified12_block_size(bytes.fromhex("7420ffff")), 4093)
        for response in (bytes.fromhex("741003"), bytes.fromhex("74200002")):
            with self.assertRaises(ValueError):
                unified12_block_size(response)

        def exchange(ecu, request):
            if request[0] == 0x34:
                return bytes.fromhex("74200008")
            return NativeWriterTests.exchange(ecu, request)

        result = unified_write(
            lambda *args: None,
            exchange,
            "authored",
            NativeUnifiedWriterTests.program(),
            native_build=12,
        )
        self.assertEqual(result["state"], "writer_completed")
        self.assertIn("CUW12", result["provenance"])

    def test_old_build_rejects_absent_each_area_module_before_io(self):
        events = []
        with self.assertRaisesRegex(ValueError, "EachArea"):
            unified_write(
                lambda *args: events.append(args),
                lambda *args: (events.append(args), b"")[1],
                "authored",
                NativeUnifiedWriterTests.program(),
                native_build=12,
                each_area=True,
            )
        self.assertEqual(events, [])

    def test_native_pending_expiry_write_and_optional_read_differ_from_host_deadline(
        self,
    ):
        for allow in (False, True):
            now = [0.9]
            actions = []
            context = UnifiedPrepareContext(0, 0, b"A" * 16, native_flag_724=allow)

            def exchange(ecu, payload):
                if payload == bytes.fromhex("22f181"):
                    return bytes.fromhex("7f2278")
                return NativeUnifiedPreparationTests.exchange(ecu, payload)

            def receive(ecu, now=now):
                now[0] = 181.0
                return bytes.fromhex("7f2278")

            result = unified_prepare(
                lambda entry, budget, actions=actions: actions.append(entry),
                exchange,
                "authored",
                context,
                lambda *args: b"K" * 16,
                native_build=12,
                timeout=300,
                clock=lambda now=now: now[0],
                receive=receive,
            )
            self.assertEqual(
                result["state"],
                "preparation_completed" if allow else "recovery_required",
            )
            self.assertEqual(
                sum(
                    entry == {"operation": "write_diagnostic", "payload_hex": "3e"}
                    for entry in actions
                ),
                1,
            )

    def test_old_prepare_order_and_each_boundary_failure(self):
        context = UnifiedPrepareContext(
            0,
            3000,
            b"A" * 16,
            gateway_kind=1,
            gateway_ids=(bytes.fromhex("07505f"),),
            native_flag_724=False,
        )
        actions = unified_prepare_actions(context, native_build=12)
        operations = [entry["operation"] for entry in actions]
        self.assertNotIn("cancel_automatic_ig_off", operations)
        self.assertNotIn("authorize_p5_central_gateway", operations)
        self.assertEqual(
            operations[2:4], ["authorize_central_gateway", "start_flow_control_filter"]
        )
        baseline = []

        def action(entry, budget):
            baseline.append(("action", entry))

        def exchange(ecu, request):
            baseline.append(("exchange", request))
            return NativeUnifiedPreparationTests.exchange(ecu, request)

        result = unified_prepare(
            action,
            exchange,
            "authored",
            context,
            lambda *args: b"K" * 16,
            native_build=12,
        )
        self.assertEqual(result["state"], "preparation_completed")
        for fault in range(len(baseline) - 1):
            seen = [0]

            def fail(*args, seen=seen, fault=fault):
                seen[0] += 1
                if seen[0] == fault + 1:
                    raise ConnectionError("authored fault")

            def action_failed(entry, budget):
                fail()

            def exchange_failed(ecu, request):
                fail()
                return NativeUnifiedPreparationTests.exchange(ecu, request)

            result = unified_prepare(
                action_failed,
                exchange_failed,
                "authored",
                context,
                lambda *args: b"K" * 16,
                native_build=12,
            )
            self.assertEqual(result["state"], "recovery_required")


class NativeRecoveryTests(unittest.TestCase):
    def test_phase_field_is_native_byte_not_uint32(self):
        from scripts.programming import NativeRecoveryState

        self.assertEqual(NativeRecoveryState(False, 255).phase_738, 255)
        with self.assertRaises(ValueError):
            NativeRecoveryState(False, 256)

    def run_recovery(
        self,
        *,
        fault=None,
        retry=True,
        confirm=True,
        cancelled=lambda: False,
        clock=lambda: 0,
        native_build=18,
        reconnect_error=False,
        decline=False,
    ):
        from scripts.programming import (
            NativeRecoveryState,
            NativeRecoveryTransportError,
            native_recovery,
        )

        events = []

        def record(kind, value):
            events.append((kind, value))
            if fault == len(events) - 1:
                raise ConnectionError("private provider details")

        def action(entry, budget):
            self.assertGreater(budget, 0)
            record("action", entry)
            if entry["operation"] == "connect" and reconnect_error:
                raise NativeRecoveryTransportError(9, 123)
            if entry["operation"] == "get_opened_device":
                return True
            if entry["operation"] == "native_recovery_callback":
                if entry["slot"] == 3:
                    return {"active_610": not decline}
                if entry["slot"] in (25, 28, 14):
                    return True
            return None

        parameters = {
            "IGOffRetriableFlag": "1",
            "PrepareRetryFlag": "1",
            "ReceiveTimeoutBeforePrepareRetry": "250",
            "ConfirmAfterEndOfFlashingFlag": str(int(confirm)),
        }

        def prepare(budget):
            record("prepare", None)
            return retry

        def resolve(budget):
            record("resolve", None)
            return ("authored-address",)

        def finished(addresses, budget):
            record("finish", addresses)
            return True

        result = native_recovery(
            action,
            NativeRecoveryState(
                True,
                2,
                flag_728=True,
                flag_72c=True,
                flag_730=True,
                error_608=9,
                error_60c=16,
            ),
            lambda name: parameters.get(name, ""),
            prepare,
            resolve,
            finished,
            ethernet=False,
            native_build=native_build,
            cancelled=cancelled,
            clock=clock,
        )
        return result, events

    def test_native_prepare_retry_and_confirm_clear_only_proven_fields(self):
        result, events = self.run_recovery()
        self.assertEqual(result["state"], "recovery_completed")
        state = result["native_state"]
        self.assertFalse(state["active_610"])
        self.assertFalse(state["flag_728"])
        self.assertFalse(state["flag_72c"])
        self.assertTrue(state["flag_724"])
        self.assertEqual((state["error_608"], state["error_60c"]), (0, 0))
        self.assertEqual(result["prepare_retries"], 1)
        self.assertEqual(
            [kind for kind, value in events if kind != "action"],
            ["prepare", "resolve", "finish"],
        )
        result, events = self.run_recovery(confirm=False)
        self.assertEqual(result["state"], "recovery_required")
        self.assertTrue(result["native_state"]["active_610"])

    def test_declined_reconnect_never_claims_recovery_and_typed_native_error_continues(
        self,
    ):
        result, events = self.run_recovery(decline=True)
        self.assertEqual(result["state"], "recovery_required")
        self.assertTrue(result["native_state"]["flag_5f8"])
        self.assertEqual(result["prepare_retries"], 0)
        for build in (12, 18):
            result, events = self.run_recovery(native_build=build, reconnect_error=True)
            self.assertEqual(result["state"], "recovery_completed")
            self.assertIn(f"CUW{build}", result["provenance"])
            self.assertGreaterEqual(
                sum(
                    kind == "action" and value.get("slot") == 5
                    for kind, value in events
                ),
                2,
            )

    def test_fault_every_native_recovery_boundary_is_private_and_uncertain(self):
        baseline, events = self.run_recovery()
        self.assertEqual(baseline["state"], "recovery_completed")
        for fault in range(len(events)):
            result, _ = self.run_recovery(fault=fault)
            self.assertEqual(result["state"], "recovery_required")
            self.assertNotIn("private provider", str(result))
        result, events = self.run_recovery(cancelled=lambda: True)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(events, [])


class NativeExecuteTests(unittest.TestCase):
    @staticmethod
    def container(modern=False):
        from scripts.calibration import parse_cuw
        from tests.test_calibration import metadata_container

        metadata = (
            "[Format]\nVersion=4\n[Vehicle]\nNumberOfCalibration=2\nContactType="
            + ("P5-Unified" if modern else "CAN")
            + "\nKindOfECU=0\n[CPU01]\nCPUType=0\n[CPU02]\nCPUType=1\n"
        )
        return parse_cuw(
            metadata_container(metadata, ((b"a.vbf", b"one"), (b"b.vbf", b"two")), 2)
        )

    def test_actual_same_invocation_prepare_gateway_write_and_cpu_loop(self):
        from scripts.programming import NativeExecuteStep, native_execute

        events = []

        def run(stage, step, budget):
            events.append((stage, step.cpu_index))
            if stage == "prepare":
                return NativeExecuteStep(True, 3, step.cpu_index)
            if stage == "gateway":
                return NativeExecuteStep(True, 2, step.cpu_index)
            return NativeExecuteStep(True, 2, step.cpu_index + 1)

        result = native_execute(
            lambda *args: None,
            self.container(),
            NativeExecuteStep(False, 1, 0),
            run,
            lambda index, key: (
                "1" if key == "CpuLoopBetweenPrepareAndWriteFlag" else "0"
            ),
        )
        self.assertEqual(result["state"], "phase_completed")
        self.assertEqual(
            events,
            [
                (stage, cpu)
                for cpu in (0, 1)
                for stage in ("prepare", "gateway", "write")
            ],
        )
        self.assertEqual(result["cpu_index"], 2)

    def test_modern_dispatch_does_not_add_legacy_cpu_loop(self):
        from scripts.programming import NativeExecuteStep, native_execute

        stages = []

        def run(stage, step, budget):
            stages.append(stage)
            return NativeExecuteStep(True, 2, step.cpu_index)

        result = native_execute(
            lambda *args: None,
            self.container(True),
            NativeExecuteStep(True, 1, 0),
            run,
            lambda *args: "1",
        )
        self.assertEqual(stages, ["prepare", "write"])
        self.assertEqual(result["state"], "phase_completed")
        result = native_execute(
            lambda *args: None,
            self.container(True),
            NativeExecuteStep(True, 3, 0),
            run,
            lambda *args: "1",
        )
        self.assertEqual(result["state"], "recovery_required")

    def test_fault_every_driver_and_phase_boundary_stays_uncertain(self):
        from scripts.programming import NativeExecuteStep, native_execute

        for fault in range(4):
            count = [0]

            def mark(count=count, fault=fault):
                count[0] += 1
                if count[0] == fault + 1:
                    raise ConnectionError("private provider state")

            def action(entry, budget):
                mark()

            def run(stage, step, budget):
                mark()
                return NativeExecuteStep(True, 2, 0)

            result = native_execute(
                action,
                self.container(True),
                NativeExecuteStep(False, 1, 0),
                run,
                lambda *args: "0",
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertNotIn("private provider", str(result))


class NativeModernPhaseTests(unittest.TestCase):
    def test_shared_phase_pointer_survives_recovery_success_and_exception(self):
        from dataclasses import asdict

        from scripts.programming import (
            NativeExecuteStep,
            NativeRecoveryState,
            native_modern_phase,
        )

        changed = asdict(NativeRecoveryState(False, 1))
        original = NativeRecoveryState(True, 2)

        def unexpected(*args):
            raise ConnectionError("private recovery payload")

        for status, recover in (
            ("recovery_required", lambda *args: {"native_state": changed}),
            ("writer_completed", unexpected),
            ("recovery_required", unexpected),
        ):
            result = native_modern_phase(
                NativeExecuteTests.container(True),
                NativeExecuteStep(False, 2, 0),
                original,
                lambda *args, status=status: {"state": status, "native_state": changed},
                recover,
            )
            self.assertEqual(result["native_step"].phase, 1)
            self.assertEqual(result["native_state"]["phase_738"], 1)
            self.assertNotIn("private recovery payload", str(result))
        result = native_modern_phase(
            NativeExecuteTests.container(True),
            NativeExecuteStep(False, 2, 0),
            original,
            lambda *args: {"state": "recovery_required"},
            lambda *args: {"native_state": changed},
        )
        followup = native_modern_phase(
            NativeExecuteTests.container(True),
            result["native_step"],
            NativeRecoveryState(**result["native_state"]),
            lambda *args: {"state": "preparation_completed"},
            lambda *args: {},
        )
        self.assertEqual(followup["native_step"].phase, 2)
        result = native_modern_phase(
            NativeExecuteTests.container(True),
            NativeExecuteStep(False, 2, 0),
            original,
            lambda *args: {"state": "recovery_required"},
            lambda *args: {"native_state": asdict(NativeRecoveryState(False, 255))},
        )
        self.assertEqual(result["error"], "ValueError")
        self.assertEqual(
            result["native_step"].phase, result["native_state"]["phase_738"]
        )

    def test_prepare_produces_phase_two_and_writer_advances_actual_node_cpu_range(self):
        from scripts.programming import (
            NativeExecuteStep,
            NativeRecoveryState,
            native_modern_phase,
        )

        calls = []

        def export(stage, cpu, budget):
            calls.append((stage, cpu))
            return {
                "state": "preparation_completed"
                if stage == "prepare"
                else "writer_completed"
            }

        state = NativeRecoveryState(
            True, 1, flag_724=True, flag_728=True, flag_72c=True
        )
        result = native_modern_phase(
            NativeExecuteTests.container(True),
            NativeExecuteStep(False, 1, 0),
            state,
            export,
            lambda *args: {},
        )
        self.assertEqual(result["native_step"], NativeExecuteStep(True, 2, 0))
        state = NativeRecoveryState(**result["native_state"])
        result = native_modern_phase(
            NativeExecuteTests.container(True),
            result["native_step"],
            state,
            export,
            lambda *args: {},
        )
        self.assertEqual(calls, [("prepare", 0), ("write", 0), ("write", 1)])
        self.assertEqual(result["native_step"], NativeExecuteStep(True, 2, 2))
        self.assertFalse(result["native_state"]["flag_728"])

    def test_logical_export_does_not_advance_context_cpu_pointer(self):
        from scripts.calibration import parse_cuw
        from scripts.programming import (
            NativeExecuteStep,
            NativeRecoveryState,
            native_modern_phase,
        )
        from tests.test_calibration import logical_container

        result = native_modern_phase(
            parse_cuw(logical_container()),
            NativeExecuteStep(False, 2, 0),
            NativeRecoveryState(True, 2),
            lambda *args: {"state": "writer_completed"},
            lambda *args: {},
        )
        self.assertEqual(result["native_step"], NativeExecuteStep(True, 2, 0))
        self.assertEqual(result["exports_called"], [("write", 0)])

    def test_failure_uses_recovery_pointer_state_and_never_retries_writer(self):
        from dataclasses import asdict

        from scripts.programming import (
            NativeExecuteStep,
            NativeRecoveryState,
            native_modern_phase,
        )

        calls = []
        state = NativeRecoveryState(True, 2)

        def export(*args):
            calls.append("write")
            return {"state": "recovery_required", "native_state": asdict(state)}

        def recover(previous, budget):
            calls.append("recovery")
            return {
                "state": "recovery_completed",
                "native_state": asdict(NativeRecoveryState(False, 2)),
            }

        result = native_modern_phase(
            NativeExecuteTests.container(True),
            NativeExecuteStep(False, 2, 0),
            state,
            export,
            recover,
        )
        self.assertEqual(calls, ["write", "recovery"])
        self.assertTrue(result["native_step"].succeeded)
        self.assertEqual(result["native_step"].cpu_index, 0)
        result = native_modern_phase(
            NativeExecuteTests.container(True),
            NativeExecuteStep(False, 2, 0),
            state,
            export,
            lambda *args: {"state": "recovery_completed"},
        )
        self.assertFalse(result["native_step"].succeeded)


class NativeFactoryPolicyTests(unittest.TestCase):
    def test_reprostd_nested_transfers_keep_actual_p5_driver_policy(self):
        from scripts.programming_vendor import VendorP5Channel

        changes = []
        created = []
        first = [True]

        def factory(*args, **kwargs):
            channel = VendorP5Channel(
                *args,
                **kwargs,
                get_timeout=lambda: 3000,
                set_timeout=changes.append,
                minimum_response_timeout_ms=5530,
            )
            created.append(channel)
            return channel

        def exchange(ecu, request):
            if request[0] == 0x34 and first[0]:
                first[0] = False
                return bytes.fromhex("7f3478")
            return NativeWriterTests.exchange(ecu, request)

        result = reprostd_write(
            lambda *args: None,
            exchange,
            "authored",
            (NativeWriterTests.block(),),
            receive=lambda *args: bytes.fromhex("741003"),
            channel_factory=factory,
        )
        self.assertEqual(result["state"], "writer_completed")
        self.assertGreater(len(created), 1)
        self.assertIn(1000, changes)
        self.assertEqual(changes[-1], 3000)

    def test_imported_logical_pending_minutes_bind_to_prepare_and_writer(self):
        from dataclasses import replace

        from scripts.calibration import parse_cuw
        from scripts.programming import (
            native_reprostd_blocks,
            native_reprostd_prepare_context,
        )
        from tests.test_calibration import logical_container

        container = parse_cuw(logical_container())
        container = replace(
            container,
            attached=replace(
                container.attached,
                data=container.attached.data.replace(
                    b"NewCID=authored-new", b"NewCID=authored-new\nP4ServerMaxTime=02"
                ),
            ),
        )
        blocks = native_reprostd_blocks(
            container, 1, ("authored-old",), bytes(32), (2026, 10, 2, 20, 12, 0, 0, 0)
        )
        self.assertEqual(blocks[0].pending_timeout_seconds, 120)
        self.assertEqual(
            native_reprostd_prepare_context(
                container, 1, gateway_kind=0, extended_addressing=False
            ).pending_timeout_seconds,
            120,
        )


class NativeLegacyPhaseTests(unittest.TestCase):
    def test_fault_and_interruption_at_every_export_phase(self):
        from scripts.programming import (
            NativeExecuteStep,
            NativeRecoveryState,
            native_legacy_phase,
        )

        for phase in (1, 2, 3):
            for failure in (ConnectionError, InterruptedError, TimeoutError):
                calls = []

                def export(stage, index, budget, failure=failure, calls=calls):
                    calls.append(stage)
                    raise failure("private provider payload")

                result = native_legacy_phase(
                    NativeExecuteTests.container(),
                    NativeExecuteStep(True, phase, 0),
                    NativeRecoveryState(True, phase),
                    export,
                    lambda *args: self.fail("unexpected recovery after host failure"),
                    lambda *args: "",
                    lambda *args: 0,
                )
                self.assertEqual(len(calls), 1)
                self.assertEqual(result["state"], "recovery_required")
                self.assertEqual(result["error"], failure.__name__)
                self.assertNotIn("private provider payload", str(result))
            cancelled = [False]

            def late_export(*args, cancelled=cancelled):
                cancelled[0] = True
                return {
                    "state": "writer_completed",
                    "gateway_result_valid": True,
                    "gateway_result": True,
                }

            result = native_legacy_phase(
                NativeExecuteTests.container(),
                NativeExecuteStep(True, phase, 0),
                NativeRecoveryState(True, phase),
                late_export,
                lambda *args: self.fail("late recovery"),
                lambda *args: "",
                lambda *args: self.fail("late callback18"),
                cancelled=lambda cancelled=cancelled: cancelled[0],
            )
            self.assertEqual(result["error"], "InterruptedError")
            self.assertEqual(len(result["exports_called"]), 1)

    def test_wrong_imported_contact_rejected_before_any_provider(self):
        from scripts.programming import (
            NativeExecuteStep,
            NativeRecoveryState,
            native_legacy_phase,
            native_modern_phase,
        )

        def forbidden(*args):
            self.fail("mismatched contact invoked a provider")

        step, state = NativeExecuteStep(True, 1, 0), NativeRecoveryState(False, 1)
        with self.assertRaises(ValueError):
            native_legacy_phase(
                NativeExecuteTests.container(modern=True),
                step,
                state,
                forbidden,
                forbidden,
                forbidden,
                forbidden,
            )
        with self.assertRaises(ValueError):
            native_modern_phase(
                NativeExecuteTests.container(), step, state, forbidden, forbidden
            )

    def run_phase(
        self,
        phase=2,
        *,
        succeeded=True,
        parameter=lambda i, k: "",
        enum=0,
        export=None,
        recovered=None,
    ):
        from dataclasses import asdict

        from scripts.programming import (
            NativeExecuteStep,
            NativeRecoveryState,
            native_legacy_phase,
        )

        state = NativeRecoveryState(active_610=True, phase_738=phase, flag_728=True)
        calls = []

        def run(stage, index, budget):
            calls.append((stage, index))
            return export(stage, index) if export else {"state": "writer_completed"}

        def recover(current, budget):
            return {"native_state": asdict(recovered or current)}

        result = native_legacy_phase(
            NativeExecuteTests.container(),
            NativeExecuteStep(succeeded, phase, 0),
            state,
            run,
            recover,
            parameter,
            lambda budget: enum,
            clock=lambda: 0,
        )
        return result, calls

    def test_writer_own_bound_and_success_pointer_fields(self):
        result, calls = self.run_phase()
        self.assertEqual(calls, [("write", 0), ("write", 1)])
        self.assertEqual(result["native_step"].cpu_index, 2)
        for key in ("active_610", "flag_724", "flag_728", "flag_72c"):
            self.assertFalse(result["native_state"][key])
        result, calls = self.run_phase(
            parameter=lambda i, k: (
                "1" if k == "CpuLoopBetweenPrepareAndWriteFlag" else ""
            )
        )
        self.assertEqual(calls, [("write", 0)])
        self.assertEqual(result["native_step"].cpu_index, 1)

    def test_prepare_callback_enum_changes_phase_even_on_false(self):
        for enum, expected in ((0, 3), (2, 1), (9, 3)):
            result, calls = self.run_phase(
                1, enum=enum, export=lambda *args: {"state": "preparation_failed"}
            )
            self.assertEqual(calls, [("prepare", 0)])
            self.assertEqual(result["native_step"].phase, expected)
            self.assertFalse(result["native_step"].succeeded)

    def test_gateway_seventh_out_flag_controls_adopting_bool(self):
        for valid, returned, success in (
            (False, False, True),
            (False, True, True),
            (True, False, False),
            (True, True, True),
        ):
            result, calls = self.run_phase(
                3,
                export=lambda *args, valid=valid, returned=returned: {
                    "gateway_result_valid": valid,
                    "gateway_result": returned,
                },
            )
            self.assertEqual(result["native_step"].succeeded, success)
            self.assertEqual(result["native_step"].phase, 2 if success else 3)
            self.assertEqual(calls, [("gateway", 0)])
        result, calls = self.run_phase(3, succeeded=False)
        self.assertEqual(calls, [])
        self.assertFalse(result["native_step"].succeeded)

    def test_recovery_completion_and_native_retry_stop(self):
        from scripts.programming import NativeRecoveryState

        for active, failed, success in (
            (False, False, True),
            (False, True, False),
            (True, False, False),
        ):
            result, calls = self.run_phase(
                export=lambda *args: {"state": "recovery_required"},
                recovered=NativeRecoveryState(
                    active_610=active, phase_738=2, flag_5f8=failed
                ),
                parameter=lambda i, k: "1" if k == "IGOffRetriableFlag" else "",
            )
            self.assertEqual(calls, [("write", 0)])
            self.assertEqual(result["native_step"].succeeded, success)
        attempts = [0]

        def run(stage, index):
            attempts[0] += 1
            return {
                "state": "recovery_required" if attempts[0] == 1 else "writer_completed"
            }

        result, calls = self.run_phase(export=run)
        self.assertEqual(calls, [("write", 0), ("write", 0), ("write", 1)])
        self.assertTrue(result["native_step"].succeeded)

    def test_next_cpu_flag_and_malformed_gateway_fail_closed(self):
        result, calls = self.run_phase(
            parameter=lambda i, k: "1" if k == "FlagToDoIGOFFONAtCPUTypeChange" else ""
        )
        self.assertEqual(calls, [("write", 0)])
        result, _ = self.run_phase(
            3, export=lambda *args: {"state": "preparation_completed"}
        )
        self.assertEqual(result["error"], "ValueError")
        self.assertFalse(result["native_step"].succeeded)

    def test_native_prefix_error_keeps_host_validation_distinct(self):
        from typing import cast

        from scripts.programming import (
            NativeProgrammingChannel,
            NativeUnexpectedResponse,
        )

        channel = NativeProgrammingChannel(lambda *args: b"wrong", "authored")
        with self.assertRaises(NativeUnexpectedResponse) as caught:
            channel.call(b"\x10\x02", b"\x50")
        self.assertEqual(caught.exception.response, b"wrong")
        self.assertNotIn("wrong", str(caught.exception))
        for response in (b"", bytes(4096), None):
            with self.assertRaises(ValueError) as caught:
                NativeProgrammingChannel(
                    lambda *args, response=response: cast(bytes, response), "authored"
                ).call(b"\x10\x02", b"\x50")
            self.assertNotIsInstance(caught.exception, NativeUnexpectedResponse)


class NativeSavedRecoveryTests(unittest.TestCase):
    @staticmethod
    def recovery():
        return b"[RecoveryInfo]\nSavedCalibrationFilePath=C:\\authored.cuw\nSelectedJ2534Device=authored-device\nWriteCpuIndex=1\nWriting=1\nWritingEndBlock=0\nUseNewSoftwarePassword=1\n"

    def test_source_device_cpu_binding_and_boolean_end_flag(self):
        from scripts.programming import bind_native_saved_recovery

        container = NativeExecuteTests.container()
        result = bind_native_saved_recovery(
            self.recovery(),
            container,
            supplied_source_path=r"C:\authored.cuw",
            enumerated_devices=("other", "authored-device", "authored-device"),
        )
        self.assertEqual(result.calibration_sha256, container.digest)
        self.assertEqual(result.selected_device_index, 1)
        self.assertEqual(result.write_cpu_index, 1)
        self.assertTrue(result.writing)
        self.assertFalse(result.writing_end_block)
        self.assertTrue(result.use_new_software_password)
        with self.assertRaises(TypeError):
            result.fields["writing"] = 0  # pyright: ignore[reportIndexIssue]

    def test_mismatch_missing_and_malformed_never_import(self):
        from scripts.programming import bind_native_saved_recovery

        container = NativeExecuteTests.container()
        cases = (
            (self.recovery(), "different", ("authored-device",)),
            (self.recovery(), r"C:\authored.cuw", ("other",)),
            (
                self.recovery().replace(b"WriteCpuIndex=1", b"WriteCpuIndex=2"),
                r"C:\authored.cuw",
                ("authored-device",),
            ),
            (
                self.recovery().replace(b"WritingEndBlock=0", b"WritingEndBlock=7"),
                r"C:\authored.cuw",
                ("authored-device",),
            ),
            (
                self.recovery().replace(b"Writing=1", b"Unknown=1"),
                r"C:\authored.cuw",
                ("authored-device",),
            ),
        )
        for data, path, devices in cases:
            with self.assertRaises(ValueError):
                bind_native_saved_recovery(
                    data,
                    container,
                    supplied_source_path=path,
                    enumerated_devices=devices,
                )


class NativeCIDCallerTests(unittest.TestCase):
    def test_actual_bool_is_independent_of_ids_and_does_not_advance_phase(self):
        from scripts.programming import (
            NativeCIDExportResult,
            NativeExecuteStep,
            NativeRecoveryState,
            native_cid_phase,
        )

        for ids, value in (((), True), (("authored",), False), (("authored",), True)):
            result = native_cid_phase(
                NativeExecuteStep(False, 0, 2),
                NativeRecoveryState(False, 0),
                lambda budget, ids=ids, value=value: NativeCIDExportResult(ids, value),
                current_software_ids=(),
                current_get_cid_failed_734=True,
            )
            self.assertEqual(result["native_step"], NativeExecuteStep(value, 0, 2))
            self.assertEqual(result["software_ids"], ids)
            self.assertEqual(result["cid_count_4e8"], len(ids))
            self.assertTrue(result["get_cid_failed_734"])

    def test_native_catch_and_host_abort_remain_distinct(self):
        from scripts.programming import (
            NativeCIDExportResult,
            NativeExecuteStep,
            NativeRecoveryState,
            native_cid_phase,
        )

        for native in (False, True):

            def fail(budget, native=native):
                error = ValueError("private failed CID")
                if native:
                    error.__dict__["native_cuw_code"] = 81
                raise error

            result = native_cid_phase(
                NativeExecuteStep(True, 0, 0),
                NativeRecoveryState(False, 0),
                fail,
                current_software_ids=("previous",),
                current_get_cid_failed_734=False,
            )
            self.assertEqual(result["get_cid_failed_734"], native)
            self.assertEqual(result["native_state"]["error_608"], 81 if native else 0)
            self.assertEqual(result["native_state"]["flag_5f8"], native)
            self.assertNotIn("private failed CID", str(result))
        aborted = [False]

        def late(budget):
            aborted[0] = True
            return NativeCIDExportResult(("authored",), True)

        result = native_cid_phase(
            NativeExecuteStep(True, 0, 0),
            NativeRecoveryState(False, 0),
            late,
            current_software_ids=("previous",),
            current_get_cid_failed_734=False,
            cancelled=lambda: aborted[0],
        )
        self.assertEqual(result["error"], "InterruptedError")
        self.assertEqual(result["software_ids"], ("previous",))
        self.assertFalse(result["native_step"].succeeded)

    def test_original_fixed_context_buffer_is_bounded_before_copy(self):
        from scripts.programming import NativeCIDExportResult

        for ids in (("x",) * 33, ("x" * 32,), ("x\x00",), ("☃",)):
            with self.assertRaises(ValueError):
                NativeCIDExportResult(ids, True)


class NativeOrderedGatewayJudgeTests(unittest.TestCase):
    def test_both_actual_ordered_probes_select_tail_from_native_enum(self):
        from scripts.programming import (
            ReproStdPrepareContext,
            UnifiedPrepareContext,
            reprostd_prepare,
            unified_prepare,
        )

        for unified in (False, True):
            for kind in (1, 2):
                events = []

                def action(entry, budget, kind=kind, events=events):
                    events.append(entry)
                    if entry["operation"] == "judge_reprogramming_gateway":
                        self.assertEqual(set(entry), {"operation"})
                        return kind

                if unified:
                    result = unified_prepare(
                        action,
                        NativeUnifiedPreparationTests.exchange,
                        "authored",
                        UnifiedPrepareContext(
                            25, 0, b"A" * 16, gateway_ids=(bytes.fromhex("07505f"),)
                        ),
                        lambda *args: b"K" * 16,
                    )
                else:
                    result = reprostd_prepare(
                        action,
                        NativePreparationTests.exchange,
                        "authored",
                        ReproStdPrepareContext(
                            25,
                            0,
                            gateway_ids=(bytes.fromhex("07505f"),),
                            gateway_modes=("02",),
                        ),
                        lambda *args: b"K" * 16,
                    )
                self.assertEqual(result["state"], "preparation_completed")
                self.assertEqual(result["gateway_kind"], kind)
                self.assertEqual(
                    [entry["operation"] for entry in events[:3]],
                    ["set_previous_send_time", "wait", "judge_reprogramming_gateway"],
                )
                self.assertEqual(events[1]["milliseconds"], 25)
                self.assertEqual(
                    sum(
                        entry["operation"] == "judge_reprogramming_gateway"
                        for entry in events
                    ),
                    1,
                )
                self.assertEqual(
                    any(
                        entry["operation"] == "authorize_central_gateway"
                        for entry in events
                    ),
                    kind == 2,
                )
                self.assertEqual(
                    any(
                        entry["operation"] == "authorize_p5_central_gateway"
                        for entry in events
                    ),
                    kind == 1,
                )

    def test_no_build12_probe_no_later_gateway_probe_and_mode_guard(self):
        from scripts.programming import (
            ReproStdPrepareContext,
            UnifiedPrepareContext,
            reprostd_prepare_actions,
            unified_prepare_actions,
        )

        fixed = bytes.fromhex("07505f")
        self.assertNotIn(
            "judge_reprogramming_gateway",
            [
                a["operation"]
                for a in unified_prepare_actions(
                    UnifiedPrepareContext(0, 0, b"A" * 16, gateway_ids=(fixed,)),
                    native_build=12,
                )
            ],
        )
        for ids, modes in (
            ((bytes.fromhex("0760"), fixed), ("01", "01")),
            ((fixed,), ("00",)),
            ((fixed,), ()),
        ):
            self.assertNotIn(
                "judge_reprogramming_gateway",
                [
                    a["operation"]
                    for a in reprostd_prepare_actions(
                        ReproStdPrepareContext(
                            0, 0, gateway_ids=ids, gateway_modes=modes
                        )
                    )
                ],
            )

    def test_native_probe_error_metadata_survives_without_private_buffers(self):
        from scripts.programming import UnifiedPrepareContext, unified_prepare
        from scripts.programming_vendor import VendorOperationError

        error = VendorOperationError(79, "private provider message")
        observed = {
            "native_error_domain": "CJ2534Exception",
            "native_error_code": 99,
            "response": "private",
        }
        cleanup_details = [
            {
                "native_error_domain": "CPassThruException",
                "native_error_code": 80,
                "message": "private",
            }
        ]

        error.__dict__.update(
            observed_native_error=observed, cleanup_error_details=cleanup_details
        )

        def action(entry, budget):
            if entry["operation"] == "judge_reprogramming_gateway":
                raise error

        result = unified_prepare(
            action,
            NativeUnifiedPreparationTests.exchange,
            "authored",
            UnifiedPrepareContext(
                0, 0, b"A" * 16, gateway_ids=(bytes.fromhex("07505f"),)
            ),
            lambda *args: b"K" * 16,
        )
        self.assertEqual(result["native_error_code"], 79)
        self.assertEqual(result["observed_native_error"]["native_error_code"], 99)
        self.assertEqual(result["cleanup_error_details"][0]["native_error_code"], 80)
        self.assertNotIn("private", repr(result))

    def test_cancel_boundary_preserves_nested_observed_native_code(self):
        from scripts.programming import UnifiedPrepareContext, unified_prepare

        cancelled = [False]

        def action(entry, budget):
            if entry["operation"] == "judge_reprogramming_gateway":
                cancelled[0] = True
                observed = InterruptedError("authored cancellation")
                observed.__dict__["observed_native_error"] = {
                    "native_error_domain": "CJ2534Exception",
                    "native_error_code": 99,
                }
                raise observed

        result = unified_prepare(
            action,
            NativeUnifiedPreparationTests.exchange,
            "authored",
            UnifiedPrepareContext(
                0, 0, b"A" * 16, gateway_ids=(bytes.fromhex("07505f"),)
            ),
            lambda *args: b"K" * 16,
            cancelled=lambda: cancelled[0],
        )
        self.assertEqual(result["observed_native_error"]["native_error_code"], 99)
        self.assertNotIn("native_error_code", result)

    def test_unified_raw_gateway_id_case_matches_native_strcmp(self):
        from scripts.programming import UnifiedPrepareContext, unified_prepare_actions

        for text, matches in (("07505F", True), ("07505f", False)):
            actions = unified_prepare_actions(
                UnifiedPrepareContext(
                    0,
                    0,
                    b"A" * 16,
                    gateway_ids=(bytes.fromhex(text),),
                    gateway_id_texts=(text,),
                )
            )
            self.assertEqual(
                any(a["operation"] == "judge_reprogramming_gateway" for a in actions),
                matches,
            )
            actions = unified_prepare_actions(
                UnifiedPrepareContext(
                    0,
                    0,
                    b"A" * 16,
                    gateway_kind=2,
                    gateway_ids=(bytes.fromhex(text),),
                    gateway_id_texts=(text,),
                )
            )
            self.assertEqual(
                any(a["operation"] == "authorize_central_gateway" for a in actions),
                matches,
            )
            for native_build in (12, 18):
                actions = unified_prepare_actions(
                    UnifiedPrepareContext(
                        0,
                        0,
                        b"A" * 16,
                        gateway_kind=2,
                        gateway_ids=(bytes.fromhex(text),),
                        gateway_id_texts=(text,),
                    ),
                    native_build=native_build,
                )
                for operation in (
                    "authorize_central_gateway",
                    "change_central_gateway_mode",
                ):
                    self.assertEqual(
                        any(a["operation"] == operation for a in actions), matches
                    )

    def test_probe_failure_or_invalid_result_never_reaches_broadcast(self):
        from scripts.programming import UnifiedPrepareContext, unified_prepare

        for value in (None, True, 0, 3, "1"):
            events = []

            def action(entry, budget, value=value, events=events):
                events.append(entry["operation"])
                return (
                    value
                    if entry["operation"] == "judge_reprogramming_gateway"
                    else None
                )

            result = unified_prepare(
                action,
                NativeUnifiedPreparationTests.exchange,
                "authored",
                UnifiedPrepareContext(
                    0, 0, b"A" * 16, gateway_ids=(bytes.fromhex("07505f"),)
                ),
                lambda *args: b"K" * 16,
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(result["operation"], "judge_reprogramming_gateway")
            self.assertNotIn("raw_write", events)


if __name__ == "__main__":
    unittest.main()
