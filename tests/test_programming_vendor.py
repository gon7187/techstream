"""Authored vector/replay checks; no vendor DLL, USB or vehicle execution."""

import unittest

from scripts.programming import NativeProgrammingChannel
from scripts.programming_vendor import (
    SBRFile,
    VendorCAN,
    VendorDiagnosticChannel,
    VendorSegment,
    common_auth_frames,
    common_block_request,
    common_check_id_frames,
    common_memory_info,
    hino_download_request,
    hino_write,
    mmc_download_request,
    mmc_write,
    psa_download_request,
    psa_identification_request,
    psa_prepare,
    psa_write,
    sbr_write,
)


class VendorTests(unittest.TestCase):
    def channel(self, responses, cls=NativeProgrammingChannel, **kwargs):
        replies = iter(responses)
        writes = []

        def exchange(ecu, request):
            self.assertEqual(ecu, "ecu")
            writes.append(request)
            return next(replies)

        return cls(exchange, "ecu", **kwargs), writes

    def test_p5_native_timeout_controls_and_pending_receive(self):
        from scripts.programming_vendor import VendorP5Channel

        timeouts, requests = [], []
        channel = VendorP5Channel(
            lambda ecu, packet: requests.append(packet) or b"\x7f\x22\x78",
            "ecu",
            receive=lambda ecu: b"\x62\x01",
            get_timeout=lambda: 100,
            set_timeout=timeouts.append,
            minimum_response_timeout_ms=5530,
            pending_response_timeout_seconds=180,
        )
        self.assertEqual(channel.call(b"\x22\x01", b"\x62"), b"\x62\x01")
        self.assertEqual(timeouts, [1000, 100])
        self.assertEqual(requests, [b"\x22\x01"])
        from scripts.programming_vendor import NativeTransportError

        reads = iter([NativeTransportError(9, "pending") for _ in range(4)] + [b"\x62"])

        def pending(ecu):
            value = next(reads)
            if isinstance(value, Exception):
                raise value
            return value

        timeouts.clear()
        channel.receive = pending
        self.assertEqual(channel.call(b"\x22", b"\x62"), b"\x62")
        self.assertEqual(timeouts, [1000, 1530, 100])
        cancelled = [False]
        channel = VendorP5Channel(
            lambda ecu, packet: b"\x62",
            "ecu",
            get_timeout=lambda: 100,
            set_timeout=lambda value: cancelled.__setitem__(0, value == 100),
            minimum_response_timeout_ms=5000,
            cancelled=lambda: cancelled[0],
        )
        with self.assertRaises(InterruptedError):
            channel.call(b"\x22", b"\x62")

    def test_common_status_retries_only_native_ack_failure(self):
        from scripts.programming_vendor import NativeTransportError

        replies = iter([NativeTransportError(9, "ACK"), b"\x3c", b"\0", b"\x3c"])
        writes = []

        def read(remaining):
            response = next(replies)
            if isinstance(response, Exception):
                raise response
            return response

        stream = VendorCAN(lambda packet, remaining: writes.append(packet) or 1, read)
        self.assertEqual(stream.status(), 0)
        self.assertEqual(writes, [b"\x50", b"\x50"])
        stream, writes = self.raw([b"\x3c", b"\0\xaa\xbb", b"\x3c"])
        self.assertEqual(stream.status(), 0)
        self.assertEqual(writes, [b"\x50"])
        for phase in ("write", "data"):
            writes = []
            replies = iter([b"\x3c", NativeTransportError(9, "data")])

            def write(packet, remaining, phase=phase, writes=writes):
                writes.append(packet)
                if phase == "write":
                    raise NativeTransportError(9, "uncertain write")
                return 1

            stream = VendorCAN(write, read)
            with self.assertRaises(NativeTransportError):
                stream.status()
            self.assertEqual(writes, [b"\x50"])

    def test_nonfinal_verify_status_ack_failure_does_not_replay_data(self):
        from scripts.programming_vendor import NativeTransportError

        responses = iter(
            [
                b"\x3c",
                b"\x3c",
                NativeTransportError(9, "status ACK"),
                b"\x3c",
                b"\x3c",
                b"\0",
                b"\x3c",
            ]
        )
        writes = []

        def read(remaining):
            value = next(responses)
            if isinstance(value, Exception):
                raise value
            return value

        stream = VendorCAN(lambda packet, remaining: writes.append(packet) or 1, read)
        stream.common_verify(1, 1, b"A" * 256 + b"B" * 256)
        self.assertEqual(writes[1:], [b"A" * 256, b"\x50", b"B" * 256, b"\x50"])

    def test_powertrain_32bh_and_ordinary_timeout_order(self):
        from scripts.programming_vendor import PowerTrainProfile, powertrain_write

        for bh32 in (False, True):
            events = []

            class Stream(VendorCAN):
                def memory_info(self, *, wide=False, events=events):
                    events.append("memory")
                    return {
                        "address": 0x1000,
                        "end_address": 0x13FF,
                        "block_size_kib": 1,
                        "firmware_descriptor": 1,
                        "extended": True,
                    }

                def common_block(self, *args, **kwargs):
                    return True

                def common_write(self, *args, **kwargs):
                    pass

                def common_verify(self, *args, **kwargs):
                    pass

                def finish(self, *args, **kwargs):
                    pass

            stream = Stream(lambda packet, remaining: 1, lambda remaining: b"\x3c")
            profiles = (
                PowerTrainProfile(
                    2 if bh32 else 1,
                    "0,1,1",
                    shrink=not bh32,
                    timing=(("flash_timeout_ms", 100),),
                ),
                PowerTrainProfile(
                    1, "0,1,1", shrink=True, timing=(("flash_timeout_ms", 200),)
                ),
            )
            result = powertrain_write(
                stream,
                bytes(8),
                0,
                bytes(1024),
                profiles,
                skip_check_id=True,
                bh32=bh32,
                set_timeout=lambda value, remaining, events=events: events.append(
                    value
                ),
            )
            self.assertEqual(result["state"], "writer_completed", result)
            self.assertEqual(events, ["memory", 200] if bh32 else [100, "memory"])

    def test_vendor_profile_and_mmc_optional_native_negative(self):
        from scripts.programming_vendor import vendor_get_cid, vendor_module_profile

        channel, writes = self.channel([b"\x62\xf1\x11" + b"H" * 24, b"\x7f\x22\x31"])
        result = vendor_get_cid(channel, "MMC")
        self.assertEqual(result["state"], "read_completed", result)
        self.assertEqual(result["identifiers"], ())
        self.assertEqual(writes, [b"\x22\xf1\x11", b"\x22\xf1\x88"])
        profile = vendor_module_profile("TCUWCanSBRPrepareWriter.dll", 18)
        self.assertEqual(profile["minimum_response_timeout_ms"], 5000)
        self.assertEqual(profile["gateway_request_id"], 0x763)
        self.assertEqual(profile["master_catalog_address_offsets"], (7, 10))
        self.assertEqual(
            vendor_module_profile("TCUWCanMMCCIDGetter.dll", 12)["address_scope"],
            "first",
        )
        self.assertFalse(
            vendor_module_profile("TCUWCanSoftwareInfoIDGetter.dll", 18)[
                "manage_filter"
            ]
        )

    def test_powertrain_and_solar_native_range_and_retry_split(self):
        from scripts.programming_vendor import (
            PowerTrainProfile,
            VendorInitialCommandError,
            VendorOperationError,
            powertrain_write,
        )

        class Stream(VendorCAN):
            def __init__(self, extended, length):
                super().__init__(lambda packet, budget: 1, lambda budget: b"\x3c")
                self.events, self.initial_attempts = [], 0
                self.extended, self.length = extended, length

            def memory_info(self, *, wide=False):
                return {
                    "address": 0x1000,
                    "end_address": 0x1000 + self.length - 1,
                    "block_size_kib": 1,
                    "firmware_descriptor": 1 if self.extended else 0x10,
                    "extended": self.extended,
                }

            def check_id(self, *args, **kwargs):
                self.initial_attempts += 1
                if self.initial_attempts < 3:
                    raise VendorInitialCommandError("initial ACK")
                return b"ID"

            def common_block(self, operation, first, last, **kwargs):
                self.events.append((operation, first, last))
                return True

            def common_write(self, address, data, **kwargs):
                self.events.append(("write", address, len(data)))

            def common_verify(self, first, last, data, **kwargs):
                self.events.append(("verify", first, last))

            def finish(self, **kwargs):
                self.events.append(("finish",))

            def change_cpu(self):
                self.events.append(("change_cpu",))

        stream = Stream(False, 2048)
        result = powertrain_write(
            stream,
            bytes(8),
            None,
            bytes(2048),
            (PowerTrainProfile(1, "0,1,2", non_verify=True),),
            skip_check_id=True,
            s0_header=b"ignored native S0",
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertIn(("blank", 1, 2), stream.events)
        self.assertIn(("verify", 1, 2), stream.events)
        stream = Stream(False, 1024)
        result = powertrain_write(
            stream,
            bytes(8),
            None,
            bytes(1024),
            (PowerTrainProfile(1, "1,1,1"),),
            skip_check_id=True,
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertIn(("blank", 2, 2), stream.events)
        self.assertIn(("write", 0x1000, 1024), stream.events)
        for igoff in (False, True):
            stream = Stream(False, 1024)
            result = powertrain_write(
                stream,
                bytes(8),
                None,
                bytes(1024),
                (PowerTrainProfile(1, "0,1,1"),),
                skip_check_id=True,
                next_cpu=True,
                next_cpu_igoff=lambda igoff=igoff: igoff,
                completion_callback=lambda slot, budget, stream=stream: (
                    stream.events.append(("callback", slot))
                ),
                clear_native_flags=lambda names, budget, stream=stream: (
                    stream.events.append(("clear", names))
                ),
            )
            self.assertEqual(
                result["state"],
                "writer_completed" if igoff else "cpu_completed",
                result,
            )
            self.assertEqual(("change_cpu",) in stream.events, not igoff)
            self.assertEqual(("finish",) in stream.events, igoff)
            self.assertEqual(
                stream.events[-1],
                ("clear", ("flag_728",) if igoff else ("flag_728", "flag_72c")),
            )

        class FailedChange(Stream):
            def change_cpu(self):
                self.attempted = True
                raise VendorOperationError(19, "negative change CPU ACK")

        stream = FailedChange(False, 1024)
        result = powertrain_write(
            stream,
            bytes(8),
            None,
            bytes(1024),
            (PowerTrainProfile(1, "0,1,1"),),
            skip_check_id=True,
            next_cpu=True,
            next_cpu_igoff=lambda: False,
            completion_callback=lambda slot, budget: stream.events.append(
                ("callback", slot)
            ),
            clear_native_flags=lambda names, budget: stream.events.append(
                ("clear", names)
            ),
        )
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertEqual(result["native_error_code"], 19)
        self.assertEqual(
            stream.events[-2:], [("callback", 1), ("clear", ("flag_728", "flag_72c"))]
        )
        stream = Stream(True, 2048)
        result = powertrain_write(
            stream,
            bytes(8),
            123,
            bytes(2048),
            (PowerTrainProfile(1, "0,1,2", shrink=True),),
            solar=True,
            initial_command_attempts=11,
            solar_next_igoff=lambda: False,
            completion_callback=lambda slot, budget: stream.events.append(
                ("callback", slot)
            ),
            clear_native_flags=lambda names, budget: stream.events.append(
                ("clear", names)
            ),
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertEqual(stream.initial_attempts, 3)
        self.assertEqual(
            stream.events[-3:],
            [
                ("callback", 1),
                ("clear", ("flag_72c", "flag_614", "flag_610")),
                ("callback", 7),
            ],
        )
        self.assertTrue(result["completion_callbacks_invoked"])
        self.assertIn(("erase", 1, 1), stream.events)
        self.assertIn(("erase", 2, 2), stream.events)

    def test_native_vendor_password_selection_and_solar_lifecycle(self):
        from dataclasses import replace

        from scripts.programming_legacy import bind_native_cpu_context
        from scripts.programming_vendor import (
            vendor_module_profile,
            vendor_password_input,
        )
        from tests.test_programming_legacy import authored_legacy_input

        container, selection, _, _ = authored_legacy_input(
            "TCUWP4CanBodyFlashWriter.dll",
            "write",
            payload=bytes.fromhex("01020304") + bytes(1020),
            parameters={"PasswordAddress": "0", "ByteOrder": "65536"},
        )
        context = bind_native_cpu_context(
            container, 1, ("DEMO-OLD",), selection, stage="write"
        )
        parameters = {"IGOffRetriableFlag": "1"}
        get = lambda key: parameters.get(key, "")
        self.assertEqual(
            vendor_password_input(
                context, ("DEMO-OLD",), get, family="PowerTrain", use_new=False
            ),
            0x12345678,
        )
        self.assertEqual(
            vendor_password_input(
                context, ("DEMO-OLD",), get, family="PowerTrain", use_new=True
            ),
            0x04030201,
        )
        self.assertEqual(
            vendor_password_input(
                context, ("DEMO-OLD",), get, family="Solar", use_new=True
            ),
            0x11223344,
        )
        parameters["ExternalMemoryFlag"] = "1"
        self.assertEqual(
            vendor_password_input(
                context, ("DEMO-OLD",), get, family="Solar", use_new=True
            ),
            0x12345678,
        )
        parameters["IGOffRetriableFlag"] = "0"
        context = replace(
            context,
            selected=replace(
                context.selected, values={**context.selected.values, "cputype": "OTHER"}
            ),
        )
        self.assertIsNone(
            vendor_password_input(
                context, (), get, family="PowerTrain", use_new=True, recovery=True
            )
        )
        parameters.update(
            ReceiveTimeoutBeforeFlashWrite="333", WaitTimeAfterReprogrammingMode="444"
        )
        profile = vendor_module_profile(
            "TCUWCanPowerTrainFlashWriterForSolar.dll", 18, parameter=get
        )
        self.assertTrue(profile["restore_timeout"])
        self.assertEqual(profile["fixed_receive_timeout_ms"], 333)
        self.assertEqual(profile["wait_before_timeout_ms"], 444)

    def test_solar_cpu0_byte_order_and_timeout_stage_order(self):
        from scripts.calibration import parse_cuw
        from scripts.programming_vendor import (
            VendorControls,
            vendor_stage,
            vendor_write_inputs,
        )
        from tests.test_calibration import metadata_container

        metadata = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=2\n[CPU01]\nCPUImageName=first.vbf\nCPUType=BASE\nLocationID=0000000000000000\n[CPU02]\nCPUImageName=second.vbf\nCPUType=CHILD\nLocationID=0000000000000001\n"
        container = parse_cuw(
            metadata_container(
                metadata, [(b"first", bytes(1024)), (b"second", bytes(1024))], 2
            )
        )
        current = {"CPUIDNo": "01", "BlockSizeInfo": "0,1,1", "BigEndianFlag": "1"}
        selected = []

        def resolve(cpu_type):
            selected.append(cpu_type)
            return lambda key: "0" if key == "BigEndianFlag" else ""

        inputs = vendor_write_inputs(
            container,
            1,
            "Solar",
            lambda key: current.get(key, ""),
            observed={"password": 1},
            resolve_parameter=resolve,
        )
        self.assertFalse(inputs["swap_endian"])
        self.assertEqual(selected, ["BASE"])
        events = []
        controls = VendorControls(
            lambda: events.append("get") or 25,
            lambda value: events.append(("set", value)),
            lambda: events.append("filter") or 1,
            lambda handle: events.append("stop"),
            lambda protocol: None,
            lambda: None,
            lambda enabled: None,
        )
        channel, _ = self.channel([])
        result = vendor_stage(
            channel,
            controls,
            lambda: events.append("action") or {"state": "writer_completed"},
            receive_timeout_ms=123,
            before_timeout=lambda: events.append("wait"),
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertEqual(
            events,
            ["wait", "get", ("set", 123), "filter", "action", "stop", ("set", 25)],
        )

    def test_common_native_operation_error_domains(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            VendorOperationError,
        )

        operations = (
            (11, lambda stream: stream.common_block("blank", 1, 1)),
            (12, lambda stream: stream.common_block("erase", 1, 1)),
            (13, lambda stream: stream.common_write(0x1000, bytes(1024))),
            (14, lambda stream: stream.common_block("inverify", 1, 1)),
            (15, lambda stream: stream.common_verify(1, 1, bytes(256))),
            (19, lambda stream: stream.change_cpu()),
            (35, lambda stream: stream.finish()),
            (71, lambda stream: stream.auth(bytes(16))),
            (72, lambda stream: stream.auth(bytes(16), key=True)),
            (72, lambda stream: stream.auth_combined(bytes(16), bytes(16))),
            (73, lambda stream: stream.detect_falsify()),
        )

        def failed_ack(budget):
            raise NativeTransportError(9, "typed native ACK timeout")

        def failed_write(packet, budget):
            raise NativeTransportError(9, "uncertain write")

        for code, operation in operations:
            stream = VendorCAN(lambda packet, budget: 1, failed_ack)
            with self.assertRaises(VendorOperationError) as caught:
                operation(stream)
            self.assertEqual(caught.exception.code, code)
            stream = VendorCAN(failed_write, failed_ack)
            with self.assertRaises(NativeTransportError):
                operation(stream)
        stream, _ = self.raw([b"\x3c", b"short"])
        with self.assertRaises(VendorOperationError) as caught:
            stream.memory_info()
        self.assertEqual(caught.exception.code, 10)
        stream, _ = self.raw([b"\x3c", b"\x3c", b"\x01", b"\x3c"])
        with self.assertRaises(VendorOperationError) as caught:
            stream.detect_falsify()
        self.assertEqual(caught.exception.code, 73)

    def test_native_utility_error_code_vectors_preserve_driver_domain(self):
        from scripts.programming import NativeTransportError as DriverError
        from scripts.programming_vendor import (
            VendorOperationError,
            native_utility_call,
            vendor_utility_error_code,
        )

        vectors = [
            ("Common", "prepare", "1002", 18),
            ("Common", "prepare", "1060", 49),
            ("MMC", "write", "3400", 26),
            ("MMC", "write", "3601", 34),
            ("MMC", "write", "37", 28),
            ("MMC", "write", "31010301", 70),
            ("MMC", "write", "31010304", 68),
            ("MMC", "write", "3101ff00", 69),
            ("SBR", "write", "3101ff00", 90),
            ("SBR", "write", "3101ff01", 89),
            ("HINO", "write", "310110ff", 89),
            ("HINO", "write", "310110fe", 89),
            ("HINO", "write", "310110fd", 90),
            ("HINO", "write", "310110fc", 90),
            ("HINO-DSS", "write", "31a2", 89),
            ("HINO-DSS", "write", "31a0", 90),
            ("HINO-VCS", "write", "3105", 89),
            ("HINO-VCS", "write", "3101", 90),
            ("HINO-VCS", "write", "11", 24),
            ("HINO-DSS", "prepare", "1085", 41),
            ("PSA", "prepare", "81", 57),
            ("MMC", "prepare", "2741", 16),
            ("MMC", "prepare", "2742", 17),
            ("SBR", "prepare", "22f100", 97),
            ("SBR", "prepare", "22101c", 98),
            ("SBR", "prepare", "31010200", 81),
            ("SBR", "prepare", "31010201", 49),
            ("SBR", "prepare", "2733", 16),
            ("SBR", "prepare", "2734", 17),
            ("DH", "get_cid", "1a81", 3),
        ]
        for family, stage, request_hex, code in vectors:
            request = bytes.fromhex(request_hex)
            self.assertEqual(vendor_utility_error_code(family, stage, request), code)
            for response in (bytes((0x7F, request[0], 0x22)), b"unexpected"):
                channel, _ = self.channel([response])
                with self.assertRaises(VendorOperationError) as caught:
                    native_utility_call(channel, request, b"expected", code)
                self.assertEqual(
                    (caught.exception.code, caught.exception.response), (code, response)
                )

        def failed(ecu, request):
            raise DriverError(9)

        channel = NativeProgrammingChannel(failed, "ecu")
        with self.assertRaises(DriverError):
            native_utility_call(channel, b"\x22", b"\x62", 3)
        with self.assertRaises(ValueError):
            vendor_utility_error_code("MMC", "write", b"\x31\x01\x99")

    def test_vendor_first_failure_reports_actual_native_utility_code(self):
        from scripts.programming_vendor import dh_get_cid, vendor_get_cid

        channel, _ = self.channel([b"\x7f\x31\x22"], cls=VendorDiagnosticChannel)
        result = psa_write(
            channel,
            1,
            (VendorSegment(0x1000, b"x"),),
            bytes(22),
            wait=lambda *args: None,
        )
        self.assertEqual(result["native_error_code"], 61, result)
        channel, _ = self.channel([b"\x7f\x81\x22"], cls=VendorDiagnosticChannel)
        result = psa_prepare(
            channel, lambda seed: bytes(4), periodic=lambda *args: None
        )
        self.assertEqual(result["native_error_code"], 57, result)
        channel, _ = self.channel([b"\x7f\x1a\x22"], cls=VendorDiagnosticChannel)
        result = dh_get_cid(channel, b"PREFIX")
        self.assertEqual(result["native_error_code"], 3, result)
        channel, _ = self.channel(
            [b"\x7f\x09\x22", b"\x49\x04\x01" + b"ID".ljust(16, b"\0")],
            cls=VendorDiagnosticChannel,
        )
        result = vendor_get_cid(channel, "Common")
        self.assertEqual(result["state"], "read_completed", result)
        channel, _ = self.channel(
            [b"\xc1\xd0\x8f", b"\x67\x81" + bytes(4)], cls=VendorDiagnosticChannel
        )
        result = psa_prepare(channel, lambda seed: False, periodic=lambda *args: None)
        self.assertEqual(result["native_error_code"], 17, result)

    def test_hino_standard_native_nrc31_erase_fallback(self):
        replies = [
            b"\x74\x10\x04",
            b"\x76\x01",
            b"\x77",
            b"\x71\x01\x10\xff\0",
            b"\x7f\x31\x31",
            b"\x74\x10\x04",
            b"\x76\x01",
            b"\x77",
            b"\x71\x01\x10\xfe\0",
            b"\x7f\x31\x31",
            b"\x51\x01",
        ]
        channel, writes = self.channel(replies)
        result = hino_write(
            channel,
            "HINO",
            VendorSegment(0x1000, b"L"),
            VendorSegment(0x2000, b"I"),
            raw_write=lambda *args: 1,
            wait=lambda *args: None,
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertEqual(writes[-1], b"\x11\x01")

    def test_recovered_record_layouts_and_prepare_retry(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            mmc_segments,
            powertrain_prepare_retry,
            psa_records,
        )

        self.assertEqual(
            mmc_segments(bytes.fromhex("0000123400000002") + b"xyAB"),
            (VendorSegment(0x1234, b"xy", b"AB"),),
        )
        with self.assertRaises(ValueError):
            mmc_segments(bytes.fromhex("0000123400000003") + b"xyAB")
        records = ((0, 0, b"HEADER\x19"), (1, 0, bytes(13)), (2, 0x1234, b"xy"))
        self.assertEqual(
            psa_records(records), (0x19, bytes(13), (VendorSegment(0x1234, b"xy"),))
        )
        events = []
        replies = iter((NativeTransportError(9, "timeout"), b"\xff", b"\x3c"))

        def read(timeout):
            value = next(replies)
            if isinstance(value, Exception):
                raise value
            return value

        stream = VendorCAN(lambda payload, timeout: events.append(payload) or 1, read)
        result = powertrain_prepare_retry(stream, 13)
        self.assertEqual(result["state"], "prepare_retry_completed", result)
        self.assertEqual(events, [b"\x05", bytes(1024), b"\x05"])

    def test_sbr_prepare_retry_short_native_branch(self):
        from scripts.programming_vendor import sbr_prepare

        channel, writes = self.channel([])
        gateway, gateway_writes = self.channel(
            [
                b"\x67\x33" + bytes(16),
                b"\x67\x34",
                b"\x71\x01\x02\0",
                b"\x71\x01\x02\x01",
            ]
        )
        raw, waits, filters = [], [], []
        from scripts.programming_vendor import VendorControls

        controls = VendorControls(
            lambda: 100,
            lambda timeout: None,
            lambda: filters.append("start") or len(filters),
            lambda handle: filters.append("stop"),
            lambda protocol: None,
            lambda: None,
            lambda enabled: None,
        )
        result = sbr_prepare(
            channel,
            gateway,
            lambda ident, seed: b"key",
            lambda seed: bytes(256),
            raw_write=lambda ident, payload, timeout: raw.append((ident, payload)) or 1,
            wait=lambda ms, timeout: waits.append(ms),
            periodic=lambda *args: None,
            retry=True,
            send_all_on_prepare_retry=False,
            wait_after_function=True,
            gateway_controls=controls,
        )
        self.assertEqual(result["state"], "prepare_completed", result)
        self.assertEqual(writes, [])
        self.assertEqual(
            [payload for ident, payload in raw],
            [b"\x10\x63"] * 3 + [b"\x10\x03", b"\x3e\x80"],
        )
        self.assertEqual(gateway_writes[-1], b"\x31\x01\x02\x01")
        self.assertEqual(waits, [100, 100, 100, 100, 60, 220, 60])
        self.assertEqual(filters, ["start", "stop"] * 3)

    def test_controls_and_mask_post_error_precedence(self):
        from scripts.programming_vendor import (
            VendorControls,
            common_diagnostic_mask,
            vendor_stage,
        )

        for cancel in (True, False):
            changed = [False]
            channel = NativeProgrammingChannel(
                lambda *args: b"",
                "ecu",
                timeout=1,
                clock=lambda changed=changed, cancel=cancel: (
                    2.0 if changed[0] and not cancel else 0.0
                ),
                cancelled=lambda changed=changed, cancel=cancel: changed[0] and cancel,
            )

            def connect(protocol, changed=changed):
                changed[0] = True
                raise OSError("connect failure")

            controls = VendorControls(
                lambda: 10,
                lambda value: None,
                lambda: 1,
                lambda token: None,
                connect,
                lambda: None,
                lambda value: None,
            )
            result = vendor_stage(
                channel, controls, lambda: {"state": "read_completed"}, reading=True
            )
            self.assertEqual(result["state"], "cancelled" if cancel else "failed")
            self.assertEqual(result["observed_error"], "connect failure")
            self.assertIn("cancelled" if cancel else "deadline", result["error"])
        cancelled = [False]
        waits = []

        def wait(ms, timeout):
            waits.append(ms)
            cancelled[0] = len(waits) == 3

        with self.assertRaises(InterruptedError):
            common_diagnostic_mask(
                lambda *args: 1, wait, wait_ms=1, cancelled=lambda: cancelled[0]
            )

    def test_old_pending_timeout_reset_and_busy_counter(self):
        sent, configured = [], []
        responses = iter((b"\x7f\x10\x21", b"\x7f\x10\x78", b"\x50"))
        received = iter((b"\x7f\x10\x21",))
        channel = VendorDiagnosticChannel(
            lambda ecu, request: sent.append(request) or next(responses),
            "ecu",
            receive=lambda ecu: next(received),
            busy_limit=1,
            get_timeout=lambda: 100,
            set_timeout=configured.append,
            pending_timeout_ms=7000,
        )
        self.assertEqual(channel.call(b"\x10", b"\x50"), b"\x50")
        self.assertEqual(sent, [b"\x10"] * 3)
        self.assertIn(7000, configured)
        self.assertEqual(configured[-1], 100)

    def test_common_finish_probe_and_memory_fallback(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            VendorControls,
            common_is_finished,
        )

        events = []
        stream = VendorCAN(
            lambda payload, timeout: events.append(payload) or 1,
            lambda timeout: b"arbitrary native response",
        )
        controls = VendorControls(
            lambda: 0,
            lambda value: None,
            lambda: 7,
            lambda token: events.append(token),
            lambda protocol: None,
            lambda: None,
            lambda value: None,
        )
        result = common_is_finished(stream, controls)
        self.assertTrue(result["finished"], result)
        self.assertFalse(result["programming_completed"])
        self.assertEqual(events, [b"\x3e", 7])
        for code in (9, 16, 5):
            replies = iter(
                (
                    NativeTransportError(code, "read failure"),
                    b"\x3c",
                    bytes.fromhex("000000000fff0110"),
                    b"\x3c",
                )
            )
            writes = []

            def read(timeout, replies=replies):
                value = next(replies)
                if isinstance(value, Exception):
                    raise value
                return value

            stream = VendorCAN(
                lambda payload, timeout, writes=writes: writes.append(payload) or 1,
                read,
            )
            if code in (9, 16):
                self.assertFalse(stream.memory_info()["extended"])
                self.assertEqual(writes, [b"\x76", b"\x75"])
            else:
                with self.assertRaises(NativeTransportError):
                    stream.memory_info()
                self.assertEqual(writes, [b"\x76"])

    def test_raw_callback_deadline_and_cancel_precedence(self):
        for reading in (False, True):
            now = [0.0]

            def fail(*args, now=now):
                now[0] = 2.0
                raise OSError("native error")

            channel = VendorCAN(fail, fail, timeout=1, clock=lambda now=now: now[0])
            with self.assertRaises(TimeoutError):
                channel.read() if reading else channel.write(b"x")
        cancelled = [False]

        def cancel(*args):
            cancelled[0] = True
            raise OSError("native error")

        channel = VendorCAN(cancel, cancel, cancelled=lambda: cancelled[0])
        with self.assertRaises(InterruptedError):
            channel.write(b"x")
        self.assertTrue(channel.attempted)

    def test_old_negative_none_is_error(self):
        from scripts.programming_vendor import NativeDiagnosticError

        channel, writes = self.channel([b"\x7f\x09\x22"], cls=VendorDiagnosticChannel)
        with self.assertRaises(NativeDiagnosticError):
            channel.call(b"\x09\0", None)
        self.assertEqual(len(writes), 1)

    def test_common_combined_auth_and_verify2(self):
        stream, writes = self.raw([b"\x3c"], wait=lambda ms, timeout: None)
        stream.auth_combined(bytes(range(16)), bytes(range(16)), wait_ms=1)
        self.assertEqual(len(writes), 6)
        self.assertEqual(writes[2][0], 0x39)
        self.assertEqual(writes[3][0], 0x3A)
        stream, writes = self.raw([b"\x3c", b"\x3c", b"\x3c", b"\0", b"\x3c"])
        stream.common_verify2(1, 2, b"x" * 128)
        self.assertEqual(writes[0], bytes.fromhex("1800000001"))
        self.assertEqual(len(writes[1]), 128)

    def test_native_short_seed_and_ascii_cid_codes(self):
        from scripts.programming_vendor import mmc_prepare, vendor_get_cid

        channel, _ = self.channel([b"\x49\x04\x01short"], cls=VendorDiagnosticChannel)
        result = vendor_get_cid(channel, "SBR", support_get_cid=True)
        self.assertEqual(result["native_error_code"], 3)
        now = [0.0]
        channel, _ = self.channel(
            [b"\x50\x02\0\x01\0\x01", b"\x67\x41x"], clock=lambda: now[0]
        )

        def send_start(packet, remaining):
            now[0] += 1.0
            return 1

        result = mmc_prepare(
            channel,
            key_provider=lambda seed: bytes(8),
            periodic=lambda *args: None,
            configure=lambda *args: None,
            preparation_state=lambda: 3,
            send_start=send_start,
        )
        self.assertEqual(result["native_error_code"], 16)

    def test_lifecycle_keeps_primary_and_cleanup_native_domains(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            VendorControls,
            vendor_stage,
        )

        def fail(*args):
            raise NativeTransportError(99, "uncertain lifecycle")

        channel, _ = self.channel([])
        controls = VendorControls(
            lambda: 100,
            lambda value: None,
            fail,
            lambda token: None,
            lambda value: None,
            lambda: None,
            lambda value: None,
        )
        result = vendor_stage(
            channel, controls, lambda: {"state": "read_completed"}, reading=True
        )
        self.assertEqual(result["native_error_code"], 99)
        controls = VendorControls(
            lambda: 100,
            lambda value: None,
            lambda: 7,
            fail,
            lambda value: None,
            lambda: None,
            lambda value: None,
        )
        result = vendor_stage(
            channel,
            controls,
            lambda: {"state": "failed", "native_error_code": 3},
            reading=True,
        )
        self.assertEqual(result["native_error_code"], 3)
        self.assertEqual(result["cleanup_error_details"][0]["native_error_code"], 99)

    def test_software_info_primary_and_filter_bs_cleanup_are_retained(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            software_info_get_cid,
        )

        def cleanup(*args):
            raise NativeTransportError(99, "cleanup uncertain")

        channel, _ = self.channel([b"\x7f\x1a\x22"], cls=VendorDiagnosticChannel)
        result = software_info_get_cid(
            channel, start_filter=lambda: 7, stop_filter=cleanup
        )
        self.assertEqual(result["native_error_code"], 3)
        self.assertEqual(result["cleanup_error_details"][0]["native_error_code"], 99)

    def test_lifecycle_keyboard_interrupt_is_cancellation_with_cleanup(self):
        from scripts.programming_vendor import VendorControls, vendor_stage

        events = []

        def interrupt():
            raise KeyboardInterrupt()

        channel, _ = self.channel([])
        controls = VendorControls(
            lambda: 100,
            lambda value: events.append(value),
            interrupt,
            lambda token: None,
            lambda value: None,
            lambda: events.append("disconnect"),
            lambda value: None,
        )
        result = vendor_stage(
            channel, controls, lambda: {"state": "read_completed"}, reading=True
        )
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(events, [100, "disconnect"])

    def test_sbr_ascii_does_not_read_unused_rom_width(self):
        from scripts.programming_vendor import vendor_get_cid, vendor_module_profile

        def parameter(name):
            if name == "SoftwareInfoROMIDByteNum":
                raise AssertionError("Unused ASCII width must not be read")
            return "1" if name == "FlagToSupportGetCID" else ""

        profile = vendor_module_profile(
            "TCUWCanSBRSoftwareIDGetter.dll", 18, parameter=parameter
        )
        self.assertNotIn("rom_id_bytes", profile["settings"])
        self.assertEqual(profile["fixed_address_width"], 2)
        channel, writes = self.channel([b"\x49\x04\x01" + b"A" * 16])
        result = vendor_get_cid(channel, "SBR", rom_id_bytes=0)
        self.assertEqual(result["state"], "read_completed")
        self.assertEqual(writes, [b"\x09\x04"])

    def test_separate_transmit_and_response_extensions(self):
        from scripts.programming_vendor import (
            dh_get_cid,
            software_info_get_cid,
            vendor_get_cid,
        )

        channel, writes = self.channel(
            [b"\xbb\x5aABCDE"],
            cls=VendorDiagnosticChannel,
            address_extension=0xAA,
            response_address_extension=0xBB,
        )
        result = dh_get_cid(
            channel, b"PREFIX", address_extension=0xAA, response_address_extension=0xBB
        )
        self.assertEqual(result["identifiers"], (b"PREFIXABCDE",))
        self.assertEqual(writes, [b"\xaa\x1a\x81"])
        channel, writes = self.channel(
            [b"\xbbprobe", b"\xbb\x49\x04\x01" + b"CID".ljust(16, b"\0")],
            cls=VendorDiagnosticChannel,
            address_extension=0xAA,
            response_address_extension=0xBB,
        )
        result = vendor_get_cid(
            channel, "Common", address_extension=0xAA, response_address_extension=0xBB
        )
        self.assertEqual(result["identifiers"], (b"CID",))
        self.assertEqual(writes, [b"\xaa\x09\0", b"\xaa\x09\x04"])
        channel, writes = self.channel(
            [b"\xbb\x5a\x88\0\x01", b"\xbb\x5a\x88\x01" + b"ID".ljust(16, b" ")],
            cls=VendorDiagnosticChannel,
            address_extension=0xAA,
            response_address_extension=0xBB,
        )
        result = software_info_get_cid(
            channel,
            start_filter=lambda: 7,
            stop_filter=lambda token: None,
            set_bs=lambda *args: None,
            address_extension=0xAA,
            response_address_extension=0xBB,
        )
        self.assertEqual(result["identifiers"], (b"ID",))
        self.assertEqual(writes, [b"\xaa\x1a\x88\0", b"\xaa\x1a\x88\x01"])
        channel, writes = self.channel(
            [b"\xbb\x7f\x22\x78"],
            cls=VendorDiagnosticChannel,
            receive=lambda ecu: b"\xbb\x62",
            address_extension=0xAA,
            response_address_extension=0xBB,
        )
        self.assertEqual(channel.call(b"\xaa\x22", b"\xbb\x62"), b"\xbb\x62")
        self.assertEqual(writes, [b"\xaa\x22"])
        cleanup = []
        channel, _ = self.channel(
            [b"\xbb\x7f\x22\x78"],
            cls=VendorDiagnosticChannel,
            address_extension=0xAA,
            response_address_extension=0xBB,
            pending_limit=0,
            send_cleanup=lambda ecu, packet: cleanup.append(packet) or 1,
        )
        with self.assertRaises(TimeoutError):
            channel.call(b"\xaa\x22", b"\xbb\x62")
        self.assertEqual(cleanup, [b"\xaa\x3e"])

    def test_cj2534_error_aliases_use_the_same_native_catches(self):
        from scripts.programming import NativeTransportError as SharedTransportError
        from scripts.programming_vendor import (
            NativeTransportError,
            VendorOperationError,
            common_judge_gateway,
        )

        for driver in (
            lambda code: NativeTransportError(code, "driver"),
            SharedTransportError,
        ):
            for code in (9, 16, 99):

                def exchange(ecu, packet, driver=driver, code=code):
                    raise driver(code)

                old = VendorDiagnosticChannel(exchange, "ecu", address_extension=0x5F)
                p5, writes = self.channel([b"\x5f\x7e\0"])
                if code in (9, 16):
                    self.assertEqual(
                        common_judge_gateway(old, p5, expiry_write=lambda *args: None),
                        1,
                    )
                    self.assertEqual(writes, [b"\x5f\x3e\0"])
                else:
                    with self.assertRaises(OSError):
                        common_judge_gateway(old, p5, expiry_write=lambda *args: None)
                    self.assertEqual(writes, [])
        writes = []

        def read(remaining):
            raise SharedTransportError(9)

        stream = VendorCAN(lambda packet, remaining: writes.append(packet) or 1, read)
        with self.assertRaises(VendorOperationError) as caught:
            stream.common_block("blank", 1, 1)
        self.assertEqual(caught.exception.code, 11)
        self.assertEqual(len(writes), 1)

    def test_optional_assembly_uses_native92_and_preserves_cids(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            software_info_get_cid,
            vendor_get_cid,
            vendor_utility_error_code,
        )

        for family in ("Common", "SoftwareInfo"):
            self.assertEqual(
                vendor_utility_error_code(family, "get_cid", b"\x1a\x89"), 92
            )
            initial = (
                [b"probe", b"\x49\x04\x01" + b"CID".ljust(16, b"\0")]
                if family == "Common"
                else [b"\x5a\x88\0\x01", b"\x5a\x88\x01" + b"CID".ljust(16, b" ")]
            )
            for failure in (
                b"\x7f\x1a\x22",
                b"\x5b",
                NativeTransportError(99, "assembly uncertain"),
            ):
                replies = iter(initial + [failure])

                def exchange(ecu, packet, replies=replies):
                    reply = next(replies)
                    if isinstance(reply, BaseException):
                        raise reply
                    return reply

                channel = VendorDiagnosticChannel(exchange, "ecu")
                result = (
                    vendor_get_cid(channel, family, query_kind=0)
                    if family == "Common"
                    else software_info_get_cid(
                        channel,
                        start_filter=lambda: 7,
                        stop_filter=lambda token: None,
                        query_kind=0,
                    )
                )
                self.assertEqual(result["identifiers"], (b"CID",))
                self.assertFalse(result["assembly_valid"])
                if isinstance(failure, BaseException):
                    self.assertEqual(result["state"], "failed")
                    self.assertEqual(result["native_error_code"], 99)
                else:
                    self.assertEqual(result["state"], "read_completed")
                    self.assertEqual(result["assembly_error"]["native_error_code"], 92)

    def test_gateway_native_pending_expiry_policy_and_restore(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            VendorOperationError,
            VendorP5Channel,
            common_judge_gateway,
        )

        def no_reply(ecu, packet):
            raise NativeTransportError(9, "no reply")

        clock, requests, writes, timeouts = [0.0], [], [], []

        def receive(ecu):
            clock[0] = 180.0
            return b"\x5f\x7f\x3e\x78"

        p5 = VendorP5Channel(
            lambda ecu, packet: requests.append(packet) or b"\x5f\x7f\x3e\x78",
            "ecu",
            timeout=200,
            clock=lambda: clock[0],
            receive=receive,
            get_timeout=lambda: 100,
            set_timeout=timeouts.append,
            minimum_response_timeout_ms=5000,
            pending_response_timeout_seconds=30,
        )
        with self.assertRaises(VendorOperationError) as caught:
            common_judge_gateway(
                VendorDiagnosticChannel(no_reply, "ecu", address_extension=0x5F),
                p5,
                expiry_write=lambda ecu, packet: writes.append(packet),
            )
        self.assertEqual(caught.exception.code, 79)
        self.assertEqual(caught.exception.response, b"\x7f\x3e\x78")
        self.assertEqual(requests, [b"\x5f\x3e\0"])
        self.assertEqual(writes, [b"\x5f\x3e"])
        self.assertEqual(timeouts, [1000, 100])
        self.assertEqual(p5.minimum_response_timeout_ms, 5000)
        self.assertEqual(p5.pending_response_timeout_seconds, 30)
        self.assertIsNone(p5.pending_timeout_write)
        old, _ = self.channel(
            [b"\x5f\x7f\x3e\x78"],
            cls=VendorDiagnosticChannel,
            address_extension=0x5F,
            receive=lambda ecu: b"\x5f\x7f\x3e\x78",
            send_cleanup=lambda *args: 1,
        )
        fallback, attempted = self.channel([])
        with self.assertRaises(VendorOperationError) as caught:
            common_judge_gateway(old, fallback, expiry_write=lambda *args: None)
        self.assertEqual(caught.exception.code, 80)
        self.assertEqual(attempted, [])

    def test_software_info_native_probe_error_mapping(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            software_info_get_cid,
        )

        for code in (9, 16, 99):
            events = []

            def exchange(ecu, request, code=code):
                raise NativeTransportError(code, "probe failure")

            result = software_info_get_cid(
                VendorDiagnosticChannel(exchange, "ecu"),
                start_filter=lambda: 7,
                stop_filter=lambda token, events=events: events.append(token),
            )
            self.assertEqual(result["state"], "failed")
            self.assertEqual(result["native_error_code"], 3 if code in (9, 16) else 99)
            self.assertEqual(events, [7])

    def test_gateway_fallback_and_bus_type(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            common_bus_type,
            common_judge_gateway,
        )

        def no_reply(ecu, payload):
            raise NativeTransportError(9, "no reply")

        old = VendorDiagnosticChannel(no_reply, "ecu", address_extension=0x5F)
        p5, writes = self.channel([b"\x5f\x7e\0"])
        self.assertEqual(
            common_judge_gateway(old, p5, expiry_write=lambda ecu, packet: None), 1
        )
        self.assertEqual(writes, [b"\x5f\x3e\0"])
        old, writes = self.channel(
            [b"\x5f\x7e"], cls=VendorDiagnosticChannel, address_extension=0x5F
        )
        p5, _unused = self.channel([])
        self.assertEqual(
            common_judge_gateway(old, p5, expiry_write=lambda ecu, packet: None), 2
        )
        self.assertEqual(common_bus_type(bytes((0, 1, 2)), 1), 1)
        self.assertEqual(common_bus_type(bytes((0, 1, 2)), 2), 2)
        with self.assertRaises(ValueError):
            common_bus_type(b"x", 2)

    def test_hino_dss_unsupported_loader_and_vcs_retry(self):
        from scripts.programming_vendor import hino_prepare

        segment = VendorSegment(0x100, b"xy")
        channel, writes = self.channel(
            [
                b"\x7f\x34\x11",
                b"\x71\xa0\0",
                b"\x74",
                b"\x76",
                b"\x77",
                b"\x71\xa3\0",
                b"\x51",
            ],
            cls=VendorDiagnosticChannel,
        )
        result = hino_write(
            channel,
            "HINO-DSS",
            segment,
            segment,
            raw_write=lambda *args: 1,
            wait=lambda *args: None,
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertEqual(writes[1], b"\x31\xa0")
        channel, writes = self.channel(
            [b"\x7f\x10\x22", b"\x50", b"\x67\x01" + bytes(12), b"\x67\x02"],
            cls=VendorDiagnosticChannel,
        )
        waits = []
        result = hino_prepare(
            channel,
            "HINO-VCS",
            lambda seed: bytes(12),
            raw_write=lambda *args: 1,
            wait=lambda ms, timeout: waits.append(ms),
            configure=lambda *args: None,
        )
        self.assertEqual(result["state"], "prepare_completed", result)
        self.assertEqual(writes[:2], [b"\x10\x02", b"\x10\x02"])
        self.assertEqual(waits, [1000, 1000])

    def test_mmc_prepare_native_burst(self):
        from scripts.programming_vendor import mmc_prepare

        now = [0.0]
        channel, writes = self.channel(
            [b"\x50\x02\0\x64\0\x32", b"\x67\x41" + bytes(8), b"\x67\x42"],
            clock=lambda: now[0],
        )
        starts = []

        def send(payload, remaining):
            starts.append(payload)
            now[0] += 0.6
            return 1

        periodic = []
        result = mmc_prepare(
            channel,
            lambda seed: b"K" * 8,
            preparation_state=lambda: 3,
            send_start=send,
            periodic=lambda *args: periodic.append(args),
            configure=lambda *args: None,
        )
        self.assertEqual(result["state"], "prepare_completed", result)
        self.assertEqual(len(starts), 4)
        self.assertEqual(writes[-1], b"\x27\x42" + b"K" * 8)
        self.assertEqual(periodic[0][:5], (True, 0x7DF, b"\x3e\x80", 2000, 100))

    def test_sbr_prepare_actual_zero_seed(self):
        from scripts.programming_vendor import sbr_prepare

        channel, writes = self.channel(
            [b"\x62\xf1\0ABC", b"\x67\x01" + bytes(4), b"\x50\x02"]
        )
        gateway, _unused = self.channel([])

        def no_key(*args):
            self.fail("Zero actual seed should not request a key")

        result = sbr_prepare(
            channel,
            gateway,
            no_key,
            no_key,
            raw_write=lambda *args: 1,
            wait=lambda *args: None,
            periodic=lambda *args: None,
            cpu_index=1,
            retry=True,
            prepare_retry=False,
            error_kind=0,
        )
        self.assertEqual(result["state"], "prepare_completed", result)
        self.assertEqual(writes, [b"\x22\xf1\0", b"\x27\x01", b"\x10\x02"])

    def test_lifecycle_cleanup_faults_remain_visible(self):
        from scripts.programming_vendor import VendorControls, vendor_stage

        events = []
        channel, writes = self.channel([b"\x50"])

        def cleanup(token):
            events.append(("stop", token))
            raise OSError("stop failed")

        controls = VendorControls(
            lambda: 99,
            lambda value: events.append(("timeout", value)),
            lambda: 7,
            cleanup,
            lambda protocol: events.append(("connect", protocol)),
            lambda: events.append(("disconnect",)),
            lambda padding: events.append(("padding", padding)),
        )

        def action():
            channel.call(b"\x10\x02", b"\x50")
            return {"state": "read_completed"}

        result = vendor_stage(
            channel,
            controls,
            action,
            reading=True,
            receive_timeout_ms=100,
            padding=False,
        )
        self.assertEqual(result["state"], "failed")
        self.assertIn("stop_filter:stop failed", result["cleanup_errors"])
        self.assertEqual(events[-2:], [("timeout", 99), ("disconnect",)])
        self.assertEqual(writes, [b"\x10\x02"])

    def test_vendor_getters(self):
        from scripts.programming_vendor import (
            common_cid_response,
            sbr_identifiers,
            vendor_get_cid,
        )

        self.assertEqual(
            common_cid_response(b"\x49\x04\x01" + b"ID".ljust(16, b"\0")), (b"ID",)
        )
        with self.assertRaises(ValueError):
            common_cid_response(b"\x49\x04\x02" + bytes(16))
        self.assertEqual(
            sbr_identifiers(b"\x12\x34", ascii_records=False), ("0000001234",)
        )
        vectors = (
            (
                "MMC",
                [
                    b"\x62\xf1\x11" + b"HARD".ljust(24, b"\0"),
                    b"\x62\xf1\x88" + b"CID".ljust(24, b"\0"),
                ],
            ),
            ("HINO", [b"\x7e\0", b"\x62\xf1\x88" + b"CID".ljust(12, b"\0")]),
            ("HINO-DSS", [b"\x7e", b"\x5a\x88\x01" + b"CID".ljust(16, b"\0")]),
            ("HINO-VCS", [b"\x7e", b"\x7e", b"\x5a\x03" + b"CID".ljust(13, b"\0")]),
            ("SBR", [b"\x49\x04\x01" + b"CID".ljust(16, b"\0")]),
            ("Common", [b"\x49\0\0", b"\x49\x04\x01" + b"CID".ljust(16, b"\0")]),
        )
        for family, replies in vectors:
            with self.subTest(family=family):
                channel, writes = self.channel(replies)
                result = vendor_get_cid(channel, family)
                self.assertEqual(result["state"], "read_completed")
                self.assertEqual(result["identifiers"], (b"CID",))
                self.assertTrue(writes)

    def test_mmc_getter_propagates_host_failures_on_both_calls_and_builds(self):
        from unittest.mock import patch

        from scripts.programming_vendor import vendor_get_cid

        host_errors = (
            OSError("host I/O"),
            TimeoutError("host deadline"),
            InterruptedError("host cancellation"),
            KeyboardInterrupt(),
        )
        primary = b"\x62\xf1\x11" + b"H".ljust(24, b"\0")
        for build in (12, 18):
            for call_index in (0, 1):
                for error in host_errors:
                    with self.subTest(
                        build=build, call_index=call_index, error=type(error).__name__
                    ):
                        channel, _ = self.channel([])
                        responses = iter((primary,))

                        calls = [0]

                        def p5_call(
                            *args,
                            call_index=call_index,
                            error=error,
                            responses=responses,
                            calls=calls,
                        ):
                            if calls[0] == call_index:
                                calls[0] += 1
                                raise error
                            calls[0] += 1
                            return next(responses)

                        with (
                            patch(
                                "scripts.programming_vendor._p5_call",
                                side_effect=p5_call,
                            ),
                            self.assertRaises(type(error)) as raised,
                        ):
                            vendor_get_cid(channel, "MMC", native_build=build)
                        self.assertIs(raised.exception, error)

    def test_mmc_getter_native_second_read_failure_retains_primary_identifier(self):
        from unittest.mock import patch

        from scripts.programming_vendor import NativeTransportError, vendor_get_cid

        primary = b"\x62\xf1\x11" + b"HARDWARE".ljust(24, b"\0")
        native_error = NativeTransportError(9, "native receive timeout")
        channel, _ = self.channel([])
        with patch(
            "scripts.programming_vendor._p5_call", side_effect=(primary, native_error)
        ):
            result = vendor_get_cid(channel, "MMC")
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["identifier_f111"], b"HARDWARE")
        self.assertEqual(result["native_error_domain"], "CJ2534Exception")
        self.assertEqual(result["native_error_code"], 9)

    def test_psa_getter_and_metadata(self):
        from scripts.programming_vendor import (
            PSAQuery,
            psa_get_cid,
            psa_identification_field,
        )

        hardware = b"\x61\x80" + bytes.fromhex("1234567890") + bytes(17)
        software = b"\x61\xfe" + bytes(range(24))
        channel, writes = self.channel(
            [b"\xc1\xd0\x8f", hardware, software, b"\xc2"], cls=VendorDiagnosticChannel
        )
        result = psa_get_cid(
            channel, PSAQuery(0x80, 3, 5), PSAQuery(0xFE, 24, 3, suffix=1)
        )
        self.assertEqual(result["state"], "read_completed")
        self.assertEqual(result["hardware_identifier"], b"1234567890")
        self.assertEqual(writes[1:3], [b"\x21\x80", b"\x21\xfe"])
        merged = psa_identification_field(
            bytes(range(13)), software, day=20, month=10, year=2026
        )
        self.assertEqual(len(merged), 22)
        self.assertEqual(merged[11:14], bytes((20, 10, 26)))
        self.assertEqual(merged[15:18], bytes.fromhex("266666"))

    def test_hino_prepare_provider(self):
        from scripts.programming_vendor import hino_prepare

        channel, writes = self.channel(
            [b"\x50\x02\0\x64\0\x32", b"\x67\x01" + bytes(range(12)), b"\x67\x02"]
        )
        raw, configured = [], []
        result = hino_prepare(
            channel,
            "HINO",
            lambda seed: b"K" * 12,
            raw_write=lambda ident, payload, timeout: raw.append(payload) or 1,
            wait=lambda ms, timeout: None,
            configure=lambda *args: configured.append(args),
        )
        self.assertEqual(result["state"], "prepare_completed")
        self.assertEqual(writes[-1], b"\x27\x02" + b"K" * 12)
        self.assertEqual(len(raw), 4)
        self.assertEqual(configured[0][:2], ("transport_timeout_ms", 100))
        self.assertEqual(configured[1][:2], ("pending_timeout_ms", 500))

    def test_powertrain_complete_cpu(self):
        from scripts.programming_vendor import PowerTrainProfile, powertrain_write

        done = [b"\x3c", b"\0", b"\x3c"]
        replies = [b"\x3c", bytes.fromhex("0010000013ff010100"), b"\x3c"]
        replies += [b"\x3c"] + done  # blank
        replies += [b"\x3c", b"\x3c"] + done  # 41,address(no ACK),data ACK
        replies += [b"\x3c"] + done  # inverify
        replies += [b"\x3c"] + ([b"\x3c"] + done) * 4  # verify256
        replies += [b"\x3c"]  # finish
        stream, writes = self.raw(replies)
        result = powertrain_write(
            stream,
            bytes(8),
            0,
            b"x" * 1024,
            (PowerTrainProfile(1, "0,1,1", shrink=True),),
            skip_check_id=True,
        )
        self.assertEqual(result["state"], "writer_completed", result)
        self.assertEqual(result["transferred"], 1024)
        self.assertEqual(writes[-1], b"\x80")

    def test_powertrain_versioned_finish_and_progress_cleanup(self):
        from scripts.programming_vendor import PowerTrainProfile, powertrain_write

        done = [b"\x3c", b"\0", b"\x3c"]
        base = [b"\x3c", bytes.fromhex("0010000013ff010100"), b"\x3c"]
        base += [b"\x3c"] + done
        base += [b"\x3c", b"\x3c"] + done
        base += [b"\x3c"] + done
        base += [b"\x3c"] + ([b"\x3c"] + done) * 4
        for build in (12, 18):
            progress = []
            stream, writes = self.raw(base + ([b"\x3c"] if build == 18 else []))
            result = powertrain_write(
                stream,
                bytes(8),
                0,
                b"x" * 1024,
                (PowerTrainProfile(1, "0,1,1", shrink=True),),
                skip_check_id=True,
                native_build=build,
                progress=lambda count, percent, progress=progress: progress.append(
                    (count, percent)
                ),
            )
            self.assertEqual(result["state"], "writer_completed", result)
            self.assertEqual(progress[-1], (2048, 100))
            self.assertEqual(writes[-1], b"\x80")
            progress.clear()

            def write(payload, timeout):
                raise OSError("partial write")

            stream = VendorCAN(write, lambda timeout: b"\x3c")
            result = powertrain_write(
                stream,
                bytes(8),
                0,
                b"x" * 1024,
                (PowerTrainProfile(1, "0,1,1", shrink=True),),
                skip_check_id=True,
                native_build=build,
                progress=lambda count, percent, progress=progress: progress.append(
                    (count, percent)
                ),
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(progress, [(0, 0), (0, 0)] if build == 18 else [])

    def test_sbr_pending_override_restored_and_key_widths(self):
        from scripts.programming_vendor import sbr_prepare

        channel, writes = self.channel(
            [b"\x74\x20\0\x0a", b"\x76\x01", b"\x77"],
            pending_response_timeout_seconds=180,
        )

        def periodic(enable, *args):
            if enable:
                raise OSError("periodic start uncertain")

        result = sbr_write(
            channel,
            (SBRFile(VendorSegment(0, b"xy"), erase=False),),
            raw_write=lambda *args: 1,
            wait=lambda *args: None,
            periodic=periodic,
            sumcheck_timeout_seconds=7,
        )
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertEqual(channel.pending_response_timeout_seconds, 180)
        for aes in (False, True):
            channel, writes = self.channel(
                [b"\x62\xf1\0ABC", b"\x67\x01" + b"S" * (16 if aes else 4)]
            )
            gateway, _ = self.channel([])
            result = sbr_prepare(
                channel,
                gateway,
                lambda ident, seed: b"K",
                lambda seed: bytes(256),
                raw_write=lambda *args: 1,
                wait=lambda *args: None,
                periodic=lambda *args: None,
                cpu_index=1,
                aes=aes,
            )
            self.assertEqual(result["state"], "recovery_required", result)
            self.assertFalse(any(request.startswith(b"\x27\x02") for request in writes))

    def test_vendor_exchange_fault_cancel_deadline_matrix(self):
        segment = VendorSegment(0x100, b"xy")
        scenarios = (
            (
                VendorDiagnosticChannel,
                [
                    b"\x71\x81\x01",
                    b"\x71\x81\x02",
                    b"\x74\x02",
                    b"\x71\x82\x01",
                    b"\x71\x82\x02",
                    b"\x74\x02",
                    b"\xc2",
                ],
                lambda channel: psa_write(
                    channel, 1, (segment,), bytes(22), wait=lambda *args: None
                ),
            ),
            (
                NativeProgrammingChannel,
                [
                    b"\x74\x20\0\x04",
                    b"\x76\x01",
                    b"\x77AB",
                    b"\x71\x01\x03\x01\x10",
                    b"\x71\x01\xff\0\x10",
                    b"\x74\x20\0\x04",
                    b"\x76\x01",
                    b"\x77AB",
                    b"\x71\x01\x03\x04\x10\x02",
                ],
                lambda channel: mmc_write(
                    channel,
                    (VendorSegment(0x100, b"xy", b"AB"),),
                    (VendorSegment(0x100, b"xy", b"AB"),),
                    loader_selector=1,
                    image_selector=2,
                    loader_routine=bytes(4),
                    erase_areas=((0x100, 2),),
                ),
            ),
            (
                NativeProgrammingChannel,
                [
                    b"\x71\x01\xff\0",
                    b"\x74\x20\0\x0a",
                    b"\x76\x01",
                    b"\x77",
                    b"\x71\x01\xff\x01\x01",
                ],
                lambda channel: sbr_write(
                    channel,
                    (SBRFile(segment),),
                    raw_write=lambda *args: 1,
                    wait=lambda *args: None,
                    periodic=lambda *args: None,
                ),
            ),
            (
                NativeProgrammingChannel,
                [
                    b"\x74\x20\0\x04",
                    b"\x76\x01",
                    b"\x77",
                    b"\x71\x01\x10\xff\0",
                    b"\x71\x01\x10\xfd\0",
                    b"\x74\x20\0\x04",
                    b"\x76\x01",
                    b"\x77",
                    b"\x71\x01\x10\xfe\0",
                    b"\x71\x01\x10\xfc\0",
                    b"\x51\x01",
                ],
                lambda channel: hino_write(
                    channel,
                    "HINO",
                    segment,
                    segment,
                    raw_write=lambda *args: 1,
                    wait=lambda *args: None,
                ),
            ),
        )
        for channel_type, replies, run in scenarios:
            for fault in ("write", "cancel", "deadline"):
                for target in range(len(replies)):
                    writes = []
                    boundary = [False]

                    def exchange(
                        ecu,
                        request,
                        target=target,
                        fault=fault,
                        replies=replies,
                        writes=writes,
                        boundary=boundary,
                    ):
                        index = len(writes)
                        writes.append(request)
                        if index == target:
                            if fault == "write":
                                raise OSError("uncertain write")
                            boundary[0] = True
                        return replies[index]

                    channel = channel_type(
                        exchange,
                        "ecu",
                        timeout=1,
                        cancelled=lambda boundary=boundary, fault=fault: (
                            boundary[0] and fault == "cancel"
                        ),
                        clock=lambda boundary=boundary, fault=fault: (
                            2.0 if boundary[0] and fault == "deadline" else 0.0
                        ),
                    )
                    result = run(channel)
                    self.assertEqual(
                        result["state"], "recovery_required", (fault, target, result)
                    )
                    self.assertEqual(len(writes), target + 1)
                    self.assertFalse(result["programming_completed"])

    def test_final_restore_and_solar_version_boundaries(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            PowerTrainProfile,
            powertrain_prepare_retry,
            powertrain_write,
        )

        changed = [False]
        restores = []

        def restore(value):
            restores.append(value)
            if len(restores) == 2:
                changed[0] = True

        channel = VendorDiagnosticChannel(
            lambda *args: b"\x62",
            "ecu",
            get_timeout=lambda: 100,
            set_timeout=restore,
            cancelled=lambda: changed[0],
        )
        with self.assertRaises(InterruptedError):
            channel.call(b"\x22", b"\x62")
        for build in (12, 18):
            progress = []

            def fail(*args):
                raise OSError("partial write")

            result = powertrain_write(
                VendorCAN(fail, lambda timeout: b""),
                bytes(8),
                0,
                bytes(1024),
                (PowerTrainProfile(1, "0,1,1"),),
                solar=True,
                native_build=build,
                progress=lambda count, percent, progress=progress: progress.append(
                    (count, percent)
                ),
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(progress, [(0, 0), (0, 0)])
        writes = []

        def missing(timeout):
            raise NativeTransportError(9, "missing response")

        result = powertrain_prepare_retry(
            VendorCAN(lambda payload, timeout: writes.append(payload) or 1, missing), 13
        )
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(writes, [b"\x05", bytes(1024)] * 3)

    def test_dh_and_software_info_codecs_and_versioned_flow(self):
        from scripts.programming_vendor import (
            dh_get_cid,
            dh_identifier,
            software_info_get_cid,
            software_info_identifier,
            software_info_selectors,
        )

        self.assertEqual(dh_identifier(b"\x5aABCDE", b"PRE"), b"PREABCDE")
        self.assertEqual(dh_identifier(b"\x5aZABCDE", b"PRE"), b"PREABCDE")
        self.assertEqual(
            dh_identifier(b"\x10\x5aAB\0DE", b"PRE", address_extension=0x10), b"PREAB"
        )
        self.assertEqual(software_info_selectors(b"\x5a\x88\0\x01\x02"), (1, 2))
        with self.assertRaises(ValueError):
            software_info_selectors(b"\x5a\x88\0\x01\0")
        self.assertEqual(
            software_info_identifier(b"\x5a\x88\x01" + b"ID".ljust(16, b" "), 1), b"ID"
        )
        self.assertEqual(
            software_info_identifier(b"\x5a\x88\x01" + b"ID  \0".ljust(16, b" "), 1),
            b"ID  ",
        )
        self.assertEqual(
            software_info_identifier(
                b"\x5a\x88\x01" + bytes(16).replace(b"\0", b" "), 1
            ),
            b" ",
        )
        self.assertEqual(
            software_info_identifier(
                b"\x5a\x88\x01" + b"ABCD            ", 1, byte_count=3
            ),
            b"ABC",
        )
        channel, writes = self.channel([b"\x5aABCDE"], cls=VendorDiagnosticChannel)
        self.assertEqual(dh_get_cid(channel, b"PRE")["identifiers"], (b"PREABCDE",))
        self.assertEqual(writes, [b"\x1a\x81"])
        for build in (12, 18):
            replies = [b"\x5a\x88\0\x01", b"\x5a\x88\x01" + b"SOFT".ljust(16, b" ")]
            if build == 18:
                replies.append(b"\x5aASSEMBLY0000")
            channel, writes = self.channel(replies, cls=VendorDiagnosticChannel)
            events = []
            result = software_info_get_cid(
                channel,
                start_filter=lambda events=events: events.append("start") or 7,
                stop_filter=lambda token, events=events: events.append(("stop", token)),
                set_bs=lambda enabled, remaining, events=events: events.append(
                    ("BS", enabled)
                ),
                kind_of_ecu="38",
                query_kind=0,
                native_build=build,
            )
            self.assertEqual(result["state"], "read_completed", result)
            self.assertEqual(result["identifiers"], (b"SOFT",))
            self.assertEqual(
                events,
                [
                    ("BS", True),
                    "start",
                    ("stop", 7),
                    "start",
                    ("stop", 7),
                    ("BS", False),
                ],
            )
            self.assertEqual(
                writes,
                [b"\x1a\x88\0", b"\x1a\x88\x01"]
                + ([b"\x1a\x89"] if build == 18 else []),
            )

    def test_software_info_fault_boundaries_and_cleanup(self):
        from scripts.programming_vendor import software_info_get_cid

        replies = [b"\x5a\x88\0\x01", b"\x5a\x88\x01" + b"ID".ljust(16, b" ")]
        for fault in ("io", "cancel", "deadline"):
            for target in range(2):
                changed = [False]
                writes = []
                events = []

                def exchange(
                    ecu,
                    request,
                    writes=writes,
                    changed=changed,
                    target=target,
                    fault=fault,
                ):
                    index = len(writes)
                    writes.append(request)
                    if index == target:
                        changed[0] = True
                        if fault == "io":
                            raise OSError("failed read")
                    return replies[index]

                channel = VendorDiagnosticChannel(
                    exchange,
                    "ecu",
                    timeout=1,
                    clock=lambda changed=changed, fault=fault: (
                        2.0 if changed[0] and fault == "deadline" else 0.0
                    ),
                    cancelled=lambda changed=changed, fault=fault: (
                        changed[0] and fault == "cancel"
                    ),
                )
                result = software_info_get_cid(
                    channel,
                    start_filter=lambda: 7,
                    stop_filter=lambda token, events=events: events.append(
                        ("stop", token)
                    ),
                    set_bs=lambda enabled, remaining, events=events: events.append(
                        ("BS", enabled)
                    ),
                    kind_of_ecu="38",
                )
                self.assertNotEqual(result["state"], "read_completed", result)
                self.assertEqual(events[-1], ("BS", False))
                self.assertEqual(
                    sum(event == ("stop", 7) for event in events), target + 1
                )
                self.assertEqual(len(writes), target + 1)

    def test_check_id_native_error_domain_is_ack_only(self):
        from scripts.programming_vendor import (
            NativeTransportError,
            VendorInitialCommandError,
        )

        for code in (9, 16, 7):

            def read(timeout, code=code):
                raise NativeTransportError(code, "native read")

            stream = VendorCAN(lambda *args: 1, read)
            expected = (
                VendorInitialCommandError if code in (9, 16) else NativeTransportError
            )
            with self.assertRaises(expected) as caught:
                stream.check_id(bytes(8), 0)
            self.assertEqual(caught.exception.code, 7 if code in (9, 16) else code)

        def partial(*args):
            raise NativeTransportError(9, "uncertain write")

        with self.assertRaises(NativeTransportError):
            VendorCAN(partial, lambda timeout: b"\x3c").check_id(bytes(8), 0)

    def test_extended_diagnostic_pending_and_getters(self):
        from scripts.programming_vendor import dh_get_cid, software_info_get_cid

        channel, writes = self.channel(
            [b"\x10\x7f\x1a\x78"],
            cls=VendorDiagnosticChannel,
            address_extension=0x10,
            receive=lambda ecu: b"\x10\x5aABCDE",
        )
        self.assertEqual(
            dh_get_cid(channel, b"P", address_extension=0x10)["identifiers"],
            (b"PABCDE",),
        )
        self.assertEqual(writes, [b"\x10\x1a\x81"])
        events = []
        channel, writes = self.channel(
            [b"\x10\x5a\x88\0\x02", b"\x10\x5a\x88\x02" + b"ID".ljust(16, b" ")],
            cls=VendorDiagnosticChannel,
            address_extension=0x10,
        )
        result = software_info_get_cid(
            channel,
            address_extension=0x10,
            start_filter=lambda: 7,
            stop_filter=lambda token: None,
            set_bs=lambda enabled, remaining: events.append(enabled),
            request_id=bytes.fromhex("07e010"),
        )
        self.assertEqual(result["state"], "read_completed", result)
        self.assertEqual(
            result["communication_addresses"],
            ({"flag": 0, "request_id_hex": "07E010"},),
        )
        self.assertEqual(events, [True, False])

    def test_last_cleanup_and_wait_callback_boundary(self):
        from scripts.programming_vendor import VendorControls, vendor_stage

        cancelled = [False]

        def cancel(*args):
            cancelled[0] = True

        channel = VendorCAN(
            lambda *args: 1, lambda timeout: b"\x3c", cancelled=lambda: cancelled[0]
        )
        controls = VendorControls(
            lambda: 0,
            lambda value: None,
            lambda: 7,
            cancel,
            lambda protocol: None,
            lambda: None,
            lambda value: None,
        )
        result = vendor_stage(
            channel,
            controls,
            lambda: {"state": "probe_completed"},
            restore_timeout=False,
        )
        self.assertEqual(result["state"], "cancelled", result)
        cancelled[0] = False

        def fail_wait(*args):
            cancelled[0] = True
            raise OSError("wait provider failed")

        channel = VendorCAN(
            lambda *args: 1,
            lambda timeout: b"\x3c",
            cancelled=lambda: cancelled[0],
            wait=fail_wait,
        )
        with self.assertRaises(InterruptedError):
            channel.wait(1)

    def test_software_info_all_control_failures_cleanup(self):
        from scripts.programming_vendor import software_info_get_cid

        for target in range(6):
            calls = []

            def control(name, *args, target=target, calls=calls):
                index = len(calls)
                calls.append(name)
                if index == target:
                    raise OSError("control failure")
                return 7

            channel, _writes = self.channel(
                [b"\x5a\x88\0\x01", b"\x5a\x88\x01" + b"ID".ljust(16, b" ")],
                cls=VendorDiagnosticChannel,
            )
            result = software_info_get_cid(
                channel,
                start_filter=lambda control=control: control("start"),
                stop_filter=lambda token, control=control: control("stop") and None,
                set_bs=lambda enabled, remaining, control=control: (
                    control("BS1" if enabled else "BS0") and None
                ),
                kind_of_ecu="38",
            )
            self.assertEqual(result["state"], "failed", (target, result))
            self.assertEqual(calls[-1], "BS0")

    def test_imported_cpu_vendor_inputs_use_native_metadata(self):
        from scripts.calibration import parse_cuw
        from scripts.programming_vendor import (
            psa_records_from_image,
            vendor_write_inputs,
        )
        from tests.test_calibration import metadata_container, srecord

        base = "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=1\n[CPU01]\nCPUImageName=main.vbf\nFlashCodeName=stub.vbf\nLocationID=0001020304050607\n"

        def imported(metadata, main, loader=b"code"):
            return parse_cuw(
                metadata_container(metadata, [(b"main", main), (b"stub", loader)], 1)
            )

        encoded = bytes.fromhex("0000100000000002") + b"xyAB"
        metadata = (
            base
            + "[CPUImage01]\nDataFormatID=02\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000002\n[FlashCode01]\nDataFormatID=01\nNumberOfAreaSettings=1\n01_StartAddress=00002000\n01_Length=00000002\n"
        )
        args = vendor_write_inputs(
            imported(metadata, encoded, encoded), 0, "MMC", lambda name: ""
        )
        self.assertEqual(args["image"], (VendorSegment(0x1000, b"xy", b"AB"),))
        self.assertEqual(args["loader_routine"], bytes.fromhex("00002000"))
        self.assertEqual(args["erase_areas"], ((0x1000, 2),))
        params = {
            "SBLStartAddressSize": "00002000\n00000100",
            "DATAStartAddressSize": "00001000\n00000200",
            "CPUIDNo": "01",
            "BlockSizeInfo": "0,1,1",
            "SendDataByteForWriteBlockType": "2",
        }
        for family in ("HINO", "HINO-DSS", "HINO-VCS"):
            args = vendor_write_inputs(
                imported(base, b"DATA"), 0, family, lambda name: params.get(name, "")
            )
            self.assertEqual(
                (
                    args["loader"].address,
                    args["loader_size"],
                    args["image"].data,
                    args["image_size"],
                ),
                (0x2000, 256, b"DATA", 512),
            )
        args = vendor_write_inputs(
            imported(base, bytes(1024)),
            0,
            "PowerTrain",
            lambda name: params.get(name, ""),
            observed={"password": 7, "finish_ack_flags": (False,)},
        )
        self.assertEqual(args["location_id"], bytes(range(8)))
        self.assertEqual(args["profiles"][0].send_type, 2)
        params["AlternateCPUType"] = "alternate"
        params["32BHFlag"] = "1"
        alternate = dict(
            params,
            CPUIDNo="02",
            AlternateCPUType="",
            ReceiveTimeoutBeforeFlashWrite="1234",
        )
        args = vendor_write_inputs(
            imported(base, bytes(1024)),
            0,
            "PowerTrain",
            lambda name: params.get(name, ""),
            observed={"password": 7, "recovery": True},
            native_build=12,
            resolve_parameter=lambda cpu_type: lambda key: alternate.get(key, ""),
        )
        self.assertEqual([p.cpu_id for p in args["profiles"]], [1])
        alternate_profile = args["resolve_profile"](1)
        self.assertEqual(alternate_profile.cpu_id, 2)
        self.assertEqual(dict(alternate_profile.timing)["flash_timeout_ms"], 1234)
        self.assertTrue(args["bh32"])
        self.assertTrue(args["skip_check_id"])
        psa = b"\n".join(
            (
                srecord(0, 0, b"HEADER\x03"),
                srecord(1, 0, bytes(range(13))),
                srecord(2, 0x123400, b"xy"),
                srecord(8, 0),
            )
        )
        self.assertEqual(psa_records_from_image(psa)[0], 3)
        args = vendor_write_inputs(
            imported(base, psa),
            0,
            "PSA",
            lambda name: "",
            observed={"software_response": b"\x61" + bytes(25), "date": (20, 10, 2026)},
        )
        self.assertEqual(args["records"], (VendorSegment(0x123400, b"xy"),))
        self.assertEqual(len(args["identification"]), 22)
        filemeta = "[Format]\nVersion=9\n[Vehicle]\nNumberOfCalibration=1\n[CPU01]\nNumberOfFiles=1\n[File1001]\nFileName=authored.bin\nDataFormat=00\nDownloadAddress=00001000\nDownloadMemsize=00000004\nALFID=44\nEraseBlock=1\n"
        args = vendor_write_inputs(
            parse_cuw(metadata_container(filemeta, [(b"file", b"data")], 1, 2)),
            0,
            "SBR",
            lambda name: "",
        )
        self.assertEqual(
            args["files"], (SBRFile(VendorSegment(0x1000, b"data"), logical_size=4),)
        )

    def test_common_getter_build12_omits_new_auxiliary_read(self):
        from scripts.programming_vendor import vendor_get_cid

        for build in (12, 18):
            replies = [b"probe", b"\x49\x04\x01" + b"CID".ljust(16, b"\0")] + (
                [b"\x5aASSEMBLY0000"] if build == 18 else []
            )
            channel, writes = self.channel(replies, cls=VendorDiagnosticChannel)
            result = vendor_get_cid(channel, "Common", query_kind=0, native_build=build)
            self.assertEqual(result["state"], "read_completed", result)
            self.assertEqual(
                writes,
                [b"\x09\0", b"\x09\x04"] + ([b"\x1a\x89"] if build == 18 else []),
            )

    def test_native_psa_parameter_binding_and_hino_declared_size(self):
        from scripts.programming_vendor import psa_getter_inputs, vendor_prepare_inputs

        params = {
            "PSASID21ParamListForHardwareID": "80,3,5,1",
            "PSASID21ParamListForSoftwareID": "FE,24,3,1,1",
            "FlagToUseDiagnosticSessionProcessForPSA": "1",
        }
        args = psa_getter_inputs(lambda name: params.get(name, ""))
        self.assertEqual(
            (
                args["hardware"].parameter,
                args["hardware"].offset,
                args["software"].suffix,
            ),
            (0x80, 3, 1),
        )
        self.assertTrue(args["diagnostic_session"])
        self.assertTrue(
            vendor_prepare_inputs("HINO", lambda name: "", kind_of_ecu="106")["dcu"]
        )
        self.assertFalse(
            vendor_prepare_inputs("SBR", lambda name: "", retry=True)[
                "send_all_on_prepare_retry"
            ]
        )
        request = hino_download_request(
            "HINO", VendorSegment(0x1000, b"xy"), size=0x2000
        )
        self.assertEqual(request[-4:], bytes.fromhex("00002000"))
        self.assertEqual(
            hino_download_request(
                "HINO-DSS", VendorSegment(0x1000, b"xy"), size=0x2000
            ),
            bytes.fromhex("34001000000000"),
        )

    def test_common_block_vectors(self):
        self.assertEqual(common_block_request("erase", 1, 1), b"\x25\0")
        self.assertEqual(
            common_block_request("blank", 2, 258, wide=True), b"\x36\0\x01\x01\x01"
        )
        self.assertEqual(common_block_request("verify", 256, 256), b"\x15\xff")
        for first, last in ((0, 1), (2, 1), (1, 2), (257, 257)):
            with self.assertRaises(ValueError):
                common_block_request("erase", first, last)

    def test_supplied_auth_and_id(self):
        nonce = bytes(range(16))
        self.assertEqual(common_auth_frames(nonce)[2], b"\x39\x0c\x0d\x0e\x0f")
        self.assertEqual(
            common_auth_frames(nonce, key=True)[0], b"\x3a\0\x01\x02\x03\x04\x05"
        )
        frames = common_check_id_frames(bytes(range(8)), 0x11223344)
        self.assertEqual(
            frames,
            (b"\0", b"\0", b"\x07\x06\x03\x02\x01\0", b"\x05\x04", b"\x44\x33\x22\x11"),
        )
        swapped = common_check_id_frames(bytes(range(8)), 0x11223344, swap_endian=True)
        self.assertEqual(swapped[-1], b"\x11\x22\x33\x44")
        with self.assertRaises(ValueError):
            common_auth_frames(b"short")

    def test_memory_descriptor(self):
        info = common_memory_info(bytes.fromhex("123456001000aabb"))
        self.assertEqual(
            info,
            {
                "address": 0x123456,
                "end_address": 4096,
                "block_size_kib": 0xAA,
                "firmware_descriptor": 0xBB,
            },
        )
        self.assertEqual(
            common_memory_info(bytes.fromhex("1234567800100000aabb"))["address"],
            0x12345678,
        )
        with self.assertRaises(ValueError):
            common_memory_info(b"short")

    def raw(self, replies, **kwargs):
        responses = iter(replies)
        writes = []

        def write(payload, timeout):
            self.assertGreater(timeout, 0)
            writes.append(payload)
            return 1

        return VendorCAN(write, lambda timeout: next(responses), **kwargs), writes

    def test_common_erase_status_busy(self):
        stream, writes = self.raw(
            [b"noise", b"\x3c", b"\x3c", b"\x20", b"\x3c", b"\x3c", b"\0", b"\x3c"]
        )
        self.assertTrue(stream.common_block("erase", 2, 2))
        self.assertEqual(writes, [b"\x25\x01", b"\x50", b"\x50"])

    def test_common_write_and_verify(self):
        stream, writes = self.raw([b"\x3c", b"\x3c", b"\x3c", b"\0", b"\x3c"])
        stream.common_write(0x123400, b"x" * 128, send_type=2)
        self.assertEqual(writes[:2], [b"\x41", bytes.fromhex("1234001f")])
        self.assertEqual(writes[2], b"x" * 128)
        self.assertEqual(stream.transferred, 128)
        with self.assertRaises(ValueError):
            stream.common_write(0, b"x", send_type=2)

    def test_common_partial_write_and_cancel(self):
        stream = VendorCAN(lambda payload, timeout: 0, lambda timeout: b"\x3c")
        with self.assertRaises(OSError):
            stream.command(b"\x25\0")
        self.assertTrue(stream.attempted)
        stream = VendorCAN(
            lambda payload, timeout: 1, lambda timeout: b"\x3c", cancelled=lambda: True
        )
        with self.assertRaises(InterruptedError):
            stream.command(b"\x25\0")
        self.assertFalse(stream.attempted)

    def test_old_nrc21_resend_and78_receive_only(self):
        cleanup = []
        channel, writes = self.channel(
            [b"\x7f\x31\x21", b"\x7f\x31\x78"],
            cls=VendorDiagnosticChannel,
            receive=lambda ecu: b"\x71\x01",
            send_cleanup=lambda ecu, payload: cleanup.append(payload) or 1,
        )
        self.assertEqual(channel.call(b"\x31\x01", b"\x71"), b"\x71\x01")
        self.assertEqual(writes, [b"\x31\x01", b"\x31\x01"])
        self.assertEqual(cleanup, [])

    def test_old_pending_cleanup_and_busy_ceiling(self):
        cleanup = []
        channel, writes = self.channel(
            [b"\x7f\x31\x78"],
            cls=VendorDiagnosticChannel,
            pending_limit=0,
            send_cleanup=lambda ecu, payload: cleanup.append(payload) or 1,
        )
        with self.assertRaises(TimeoutError):
            channel.call(b"\x31\x01", b"\x71")
        self.assertEqual(cleanup, [b"\x3e"])
        channel, writes = self.channel(
            [b"\x7f\x31\x21"] * 3, cls=VendorDiagnosticChannel, busy_limit=2
        )
        with self.assertRaises(TimeoutError):
            channel.call(b"\x31\x01", b"\x71")
        self.assertEqual(len(writes), 3)

    def test_psa_packets(self):
        packet = psa_download_request(4, 0x123456, b"xy")
        self.assertEqual(packet[:8], bytes.fromhex("3404123456027879"))
        self.assertEqual(len(packet), 10)
        packet = psa_identification_request(bytes(range(22)))
        self.assertEqual(len(packet), 56)
        self.assertEqual(packet[:10], bytes.fromhex("34830000003000010000"))
        with self.assertRaises(ValueError):
            psa_download_request(0, 1 << 24, b"x")

    def test_psa_writer_and_failure(self):
        replies = [
            b"\x71\x81\x01",
            b"\x71\x81\0",
            b"\x71\x81\x02",
            b"\x74\x02",
            b"\x71\x82\x01",
            b"\x71\x82\x02",
            b"\x74\x02",
            b"\xc2",
        ]
        channel, writes = self.channel(replies, cls=VendorDiagnosticChannel)
        result = psa_write(
            channel,
            3,
            (VendorSegment(0x1200, b"abc"),),
            bytes(22),
            wait=lambda ms, timeout: None,
        )
        self.assertEqual(result["state"], "writer_completed")
        self.assertFalse(result["programming_completed"])
        self.assertEqual(writes[0], bytes.fromhex("318103f05a"))
        self.assertEqual(writes[-1], b"\x82")
        channel, writes = self.channel([b"\x7f\x31\x22"], cls=VendorDiagnosticChannel)
        result = psa_write(
            channel,
            3,
            (VendorSegment(0x1200, b"abc"),),
            bytes(22),
            wait=lambda ms, timeout: None,
        )
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(len(writes), 1)

    def test_psa_prepare_authorized_only(self):
        channel, writes = self.channel(
            [b"\xc1\xd0\x8f", b"\x67\x81abcd", b"\x67\x82"], cls=VendorDiagnosticChannel
        )
        self.assertEqual(
            psa_prepare(channel, lambda seed: b"KEY!", periodic=lambda *args: None)[
                "state"
            ],
            "prepare_completed",
        )
        self.assertEqual(writes[-1], b"\x27\x82KEY!")
        channel, writes = self.channel(
            [b"\xc1\xd0\x8f", b"\x67\x81abcd"], cls=VendorDiagnosticChannel
        )
        self.assertEqual(
            psa_prepare(channel, lambda seed: b"", periodic=lambda *args: None)[
                "state"
            ],
            "recovery_required",
        )
        self.assertEqual(len(writes), 2)

    def test_mmc_flow(self):
        replies = [
            b"\x74\x20\0\x04",
            b"\x76\x01",
            b"\x77AB",
            b"\x71\x01\x03\x01\x10",
            b"\x71\x01\xff\0\x10",
            b"\x74\x20\0\x04",
            b"\x76\x01",
            b"\x77CD",
            b"\x71\x01\x03\x04\x10\x02",
        ]
        channel, writes = self.channel(replies)
        loader, image = (
            VendorSegment(0x100, b"xy", b"AB"),
            VendorSegment(0x200, b"ab", b"CD"),
        )
        result = mmc_write(
            channel,
            (loader,),
            (image,),
            loader_selector=1,
            image_selector=2,
            loader_routine=b"abcd",
            erase_areas=((0x200, 2),),
        )
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(writes[0], mmc_download_request(loader, 1))
        self.assertEqual(writes[1], b"\x36\x01xy")
        self.assertEqual(writes[-1], b"\x31\x01\x03\x04")

    def test_hino_modes(self):
        segment = VendorSegment(0x1234, b"xy")
        self.assertEqual(
            hino_download_request("HINO-DSS", segment), bytes.fromhex("34001234000000")
        )
        self.assertEqual(hino_download_request("HINO-VCS", segment)[:2], b"\x34\x01")
        replies = [
            b"\x74\x20\0\x04",
            b"\x76\x01",
            b"\x77",
            b"\x71\x01\x10\xff\0",
            b"\x71\x01\x10\xfd\0",
            b"\x74\x20\0\x04",
            b"\x76\x01",
            b"\x77",
            b"\x71\x01\x10\xfe\0",
            b"\x71\x01\x10\xfc\0",
            b"\x51\x01",
        ]
        channel, writes = self.channel(replies)
        raw = []
        result = hino_write(
            channel,
            "HINO",
            segment,
            segment,
            raw_write=lambda ident, payload, timeout: raw.append((ident, payload)) or 1,
            wait=lambda ms, timeout: None,
        )
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(
            [payload for ident, payload in raw],
            [b"\xa0\x28\x01", b"\x28\x80\x01", b"\xa0\x85\x01", b"\x85\x81"],
        )
        self.assertEqual(writes[-1], b"\x11\x01")

    def test_sbr_addressed_transfer(self):
        replies = [
            b"\x71\x01\xff\0",
            b"\x74\x20\0\x0a",
            b"\x76\x01",
            b"\x77",
            b"\x71\x01\xff\x01\x01",
        ]
        channel, writes = self.channel(replies)
        raw, periodic = [], []
        result = sbr_write(
            channel,
            (SBRFile(VendorSegment(0x100, b"abcd")),),
            raw_write=lambda ident, payload, timeout: raw.append((ident, payload)) or 1,
            wait=lambda ms, timeout: None,
            periodic=lambda *args: periodic.append(args),
        )
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(writes[2], bytes.fromhex("360100000100") + b"abcd")
        self.assertEqual(len(raw), 5)
        self.assertEqual([p[0] for p in periodic], [True, False, True, False])

    def test_deadline_and_truncated_fail_closed(self):
        now = [0.0]
        channel = NativeProgrammingChannel(
            lambda ecu, payload: b"\x74\x20", "ecu", clock=lambda: now[0]
        )
        segment = VendorSegment(0, b"x", b"AB")
        result = mmc_write(
            channel,
            (segment,),
            (segment,),
            loader_selector=1,
            image_selector=2,
            loader_routine=bytes(4),
            erase_areas=((0, 1),),
        )
        self.assertEqual(result["state"], "recovery_required")
        channel = NativeProgrammingChannel(
            lambda ecu, payload: b"", "ecu", cancelled=lambda: True
        )
        result = psa_prepare(
            channel, lambda seed: bytes(4), periodic=lambda *args: None
        )
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(result["history"], [])


if __name__ == "__main__":
    unittest.main()
