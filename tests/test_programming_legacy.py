import unittest
from dataclasses import replace
from typing import cast

from scripts.programming import NativeProgrammingChannel
from scripts.programming_legacy import (
    BlockInfo,
    LegacyCPU,
    LegacyPrepareContext,
    LegacyTarget,
    LegacyTransportError,
    bind_legacy_context,
    bind_legacy_finish_probe,
    bind_native_cpu_context,
    block_ranges,
    block_sizes,
    complete_block_info,
    cxpi_erase,
    decode_legacy_cids,
    legacy_blocks,
    legacy_bus_type,
    legacy_get_cids,
    legacy_is_finished,
    legacy_module_profile,
    legacy_prepare,
    legacy_security,
    legacy_write,
    materialize_legacy_image,
    native_cpu_passwords,
    parse_block_info,
    vforest_groups,
    vforest_transfer,
)
from scripts.programming_vendor import NativeTransportError as VendorTransportError
from scripts.programming_vendor import (
    VendorCAN,
    VendorDiagnosticChannel,
    VendorOperationError,
)


class RawReplay:
    def __init__(self, fault=None):
        self.writes = []
        self.responses = []
        self.address = False
        self.fault = fault
        self.check_id_count = 0
        self.waits = []
        self.timeouts = []
        self.timeout = 321
        self.actions = []

    def write(self, payload, remaining):
        self.writes.append(payload)
        if self.fault is not None and self.fault(payload, self.writes):
            raise OSError("authored uncertain transport failure")
        if self.check_id_count < 5:
            self.check_id_count += 1
            if self.check_id_count == 5:
                self.responses.extend((b"\x3c", b"\0"))
        elif payload == b"\x3c":
            pass
        elif payload == b"\x76":
            self.responses.extend(
                (b"\x3c", bytes.fromhex("0000000003ff010100"), b"\x3c")
            )
        elif payload == b"\x50":
            self.responses.extend((b"\x3c", b"\0", b"\x3c"))
        elif self.address:
            self.address = False
        elif payload == b"\x41":
            self.address = True
            self.responses.append(b"\x3c")
        elif payload[0] in (0x37, 0x38, 0x3A, 0x3B) and len(payload) == 7:
            pass
        else:
            self.responses.append(b"\x3c")
        return 1

    def read(self, remaining):
        if not self.responses:
            raise AssertionError("unexpected native read")
        return self.responses.pop(0)

    def set_timeout(self, value, remaining):
        self.timeouts.append(value)
        self.timeout = value

    def lifecycle(self, operation, parameters, remaining):
        self.actions.append((operation, parameters))
        if operation == "get_timeout":
            return self.timeout
        if operation == "get_send_timeout":
            return 654
        if operation == "start_filter":
            return 42
        if operation == "set_timeout":
            self.set_timeout(parameters["milliseconds"], remaining)
        return None

    def channel(self, **kwargs):
        return VendorCAN(
            self.write,
            self.read,
            wait=lambda ms, remaining: self.waits.append(ms),
            **kwargs,
        )


def authored_legacy_input(
    module,
    stage,
    *,
    payload=None,
    metadata_extra="",
    vehicle_extra="",
    parameters=None,
    observations=None,
    build=18,
):
    from scripts.calibration import parse_cuw
    from scripts.calibration_catalog import CalibrationCatalog, parse_parameter_table
    from scripts.demo_calibration import table
    from scripts.native_modules import _BUILDS, identify_native_module
    from tests.test_calibration import metadata_container

    metadata = (
        "[Format]\nVersion=6\n[Vehicle]\nNumberOfCalibration=1\nKindOfECU=1\nContactType=CAN\n"
        + vehicle_extra
        + "[CPU01]\nCPUType=1\nCPUImageName=authored.vbf\nLocationID=0108010000000720\n"
        "NumberOfTargets=1\n01_TargetCalibration=DEMO-OLD\n01_TargetData=12345678\n"
        "NewPassword=11223344\nNonce="
        + bytes(16).hex()
        + "\nSeedKey="
        + bytes(16).hex()
        + "\n"
        + metadata_extra
    )
    container = parse_cuw(
        metadata_container(
            metadata, [(b"cpu", bytes(1024) if payload is None else payload)], 1
        )
    )
    suffix = {
        "get_cid": "GetCID",
        "prepare": "PrepareWrite",
        "write": "FlashWrite",
        "gateway": "ChangeToReprogGatewayMode",
    }[stage]
    data = {
        "ParamFileKeySystemProtocolMicon": "1CAN1",
        "DLLFileNameFor" + suffix: module,
        "BlockSizeInfo": "0:1x1",
        "CPUIDNo": "1",
        "ShrinkFlag": "1",
        "BigEndianFlag": "0",
        "SecurityAccessPassword": "aabb\nccdd",
    }
    if stage == "write":
        data["GetCANIDFunctionNameFor" + suffix] = "GetCanIDsFromLocationIDForWrite"
    else:
        selector = (
            "GetCanIDsFromParamForReprogGateway"
            if stage == "gateway"
            else "GetCanIDsFromParamForGetCID"
            if stage == "get_cid"
            else "GetCanIDsFromParamForPrepareWrite"
        )
        data["GetCANIDFunctionNameFor" + suffix] = selector
        data[
            {
                "get_cid": "CanIDForGetCID",
                "prepare": "CanIDForPrepareWrite",
                "gateway": "CanIDForReprogGateway",
            }[stage]
        ] = "0100/0108"
    if stage == "write" and "ForCXPI" in module:
        data["GetCANIDFunctionNameForPrepareWrite"] = (
            "GetCanIDsFromParamForPrepareWrite"
        )
        data["CanIDForPrepareWrite"] = "010001/010801"
    data.update(parameters or {})
    catalog = CalibrationCatalog(
        [
            parse_parameter_table(
                "1CAN1.ini", table(tuple(data), [tuple(data.values())]), encoded=False
            )
        ]
    )
    digest = next(
        digest
        for digest, (builds, name) in _BUILDS.items()
        if name == module and str(build) in builds
    )
    identity = identify_native_module(digest, module)
    observations = dict(observations or {})
    if stage == "gateway":
        observations["stage"] = "gateway"
    return container, catalog.select("1CAN1"), identity, observations


class LegacyTests(unittest.TestCase):
    def test_imported_cuw_contexts_execute_all_51_native_module_builds(self):
        from scripts.programming_legacy import _PREPARERS, _WRITERS

        modules = [
            *((name, "write") for name in _WRITERS),
            *((name, "prepare") for name in _PREPARERS),
            *(
                (name, "get_cid")
                for name in (
                    "TCUWP5CanCIDGetter.dll",
                    "TCUWP5CanCIDGetterWithSetBS.dll",
                    "TCUWP4P5CanCIDGetter.dll",
                )
            ),
        ]
        self.assertEqual(len(modules), 26)
        executed = 0
        for module, stage in modules:
            for build in (12, 18):
                if (
                    build == 12
                    and module == "TCUWP5CanSecurityPowerTrainPrepareWriter.dll"
                ):
                    continue
                params = {}
                if stage == "prepare":
                    if "CentralGW" in module:
                        params["GetCANIDFunctionNameForPrepareWrite"] = ""
                    elif "PowerTrain" in module or "ChassisShrink" in module:
                        params["CanIDForPrepareWrite"] = "0100/0108\n0200/0208"
                if stage == "get_cid" and "P4P5" in module:
                    params["CanIDForGetCID"] = "0100/0108\n0200/0208"
                image = (
                    b"ZV\0\x03\xfb" + bytes(1019)
                    if "VFOREST" in module
                    else bytes(1024)
                )
                container, selection, identity, observations = authored_legacy_input(
                    module, stage, payload=image, parameters=params, build=build
                )
                inputs = bind_legacy_context(
                    container,
                    1,
                    ("DEMO-OLD",),
                    selection,
                    identity,
                    {"ecu_auth_key": bytes(16)},
                    observations,
                )
                with self.subTest(module=module, build=build):
                    if stage == "write":
                        assert inputs.cpu is not None
                        replay = RawReplay()
                        channel = replay.channel()
                        result = legacy_write(
                            module,
                            channel,
                            inputs.cpu,
                            finish_channel=channel,
                            set_bs=lambda value: None,
                            tester_present=lambda: None,
                            native_build=inputs.native_build,
                            lifecycle=replay.lifecycle,
                        )
                        self.assertEqual(result["state"], "complete", result)
                        self.assertEqual(
                            [op for op, p in replay.actions].count("start_filter"), 1
                        )
                        self.assertEqual(
                            [op for op, p in replay.actions].count("stop_filter"), 1
                        )
                    else:
                        width = (
                            16
                            if "Security" in module
                            else 2
                            if "Airbag" in module or "Sonar" in module
                            else 6
                            if "BodyMicon" in module or "CanBody" in module
                            else 4
                        )

                        def exchange(ecu, payload, width=width):
                            if payload[:2] == b"\x09\0":
                                return bytes.fromhex("490030000000")
                            if payload[:2] == b"\x09\x04":
                                return bytes.fromhex("490401") + b"DEMO-OLD" + bytes(8)
                            if payload[:2] == b"\x1a\x89":
                                return b"\x5a" + bytes(12)
                            if payload[0] == 0x22:
                                return (
                                    bytes.fromhex("62f18101") + b"DEMO-OLD" + bytes(8)
                                )
                            if payload[0] == 0x10:
                                return b"\x50" + payload[1:2] + bytes(4)
                            if payload[0] == 0x31:
                                return b"\x71" + payload[1:]
                            return (
                                b"\x67"
                                + payload[1:2]
                                + (bytes(width) if payload[1] & 1 else b"")
                                + (b"\x34" if payload[1] in (3, 4, 0x62) else b"")
                            )

                        targets = inputs.bind_targets(
                            lambda address, policy: (
                                VendorDiagnosticChannel
                                if policy == "p4"
                                else NativeProgrammingChannel
                            )(exchange, "authored")
                        )
                        replay = RawReplay()
                        if stage == "get_cid":
                            result = legacy_get_cids(
                                module,
                                targets,
                                set_bs=lambda value: None,
                                native_build=inputs.native_build,
                                parameters=inputs.parameters,
                                lifecycle=replay.lifecycle,
                            )
                            self.assertEqual(
                                result["cids"],
                                ["DEMO-OLD"] * (2 if "P4P5" in module else 1),
                            )
                            self.assertEqual(
                                replay.actions[0], ("connect", {"protocol": 6})
                            )
                            self.assertEqual(replay.actions[-1], ("disconnect", {}))
                        else:
                            assert inputs.prepare is not None
                            result = legacy_prepare(
                                module,
                                targets,
                                inputs.prepare,
                                lambda name, seed: bytes(len(seed)),
                                raw_write=lambda a, p, r: 1,
                                wait=lambda ms, r: None,
                                set_bs=lambda value: None,
                                confirm_gateway=lambda: True,
                                native_build=inputs.native_build,
                                lifecycle=replay.lifecycle,
                            )
                        self.assertEqual(result["state"], "complete", result)
                executed += 1
        self.assertEqual(executed, 51)

    def test_sonar_lifecycle_order_restores_both_native_timeouts(self):
        container, selection, identity, _observations = authored_legacy_input(
            "TCUWP4CanClearanceSonarFlashWriter.dll",
            "write",
            parameters={"SendTimeoutBeforePrepareWrite": "99"},
        )
        inputs = bind_legacy_context(container, 1, ("DEMO-OLD",), selection, identity)
        assert inputs.cpu is not None
        replay = RawReplay()
        channel = replay.channel()
        result = legacy_write(
            inputs.module,
            channel,
            inputs.cpu,
            finish_channel=channel,
            lifecycle=replay.lifecycle,
        )
        self.assertEqual(result["state"], "complete")
        self.assertEqual(
            replay.actions,
            [
                ("get_timeout", {}),
                ("set_timeout", {"milliseconds": 0}),
                ("get_send_timeout", {}),
                ("set_send_timeout", {"milliseconds": 99}),
                ("start_filter", {"target_index": 0}),
                ("stop_filter", {"filter_id": 42}),
                ("set_timeout", {"milliseconds": 321}),
                ("set_send_timeout", {"milliseconds": 654}),
            ],
        )

    def test_imported_cuw_to_context_to_native_writer_without_manual_geometry(self):
        module = "TCUWP4CanBodyFlashWriter.dll"
        container, selection, identity, observations = authored_legacy_input(
            module, "write"
        )
        inputs = bind_legacy_context(
            container, 1, ("DEMO-OLD",), selection, identity, observations=observations
        )
        assert inputs.cpu is not None
        self.assertEqual(inputs.cpu.password, 0x12345678)
        self.assertIsNone(inputs.cpu.alternate_password)
        self.assertEqual(inputs.cpu.location_id, bytes.fromhex("0108010000000720"))
        self.assertEqual(inputs.target_metadata[0].request, bytes.fromhex("0100"))
        self.assertEqual(inputs.target_metadata[1].request, bytes.fromhex("0720"))
        self.assertEqual(inputs.cpu.flash_size, 1024)
        replay = RawReplay()
        channel = replay.channel()
        result = legacy_write(
            inputs.module,
            channel,
            inputs.cpu,
            finish_channel=channel,
            get_timeout=lambda: 321,
            set_timeout=replay.set_timeout,
            native_build=inputs.native_build,
        )
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["transferred_bytes"], 1024)
        self.assertNotIn("12345678", repr(inputs))
        self.assertNotIn("11223344", repr(inputs.report()))
        with self.assertRaises(ValueError):
            bind_legacy_context(container, 1, ("WRONG-CID",), selection, identity)
        with self.assertRaises(ValueError):
            bind_legacy_context(
                container,
                1,
                ("DEMO-OLD",),
                selection,
                identity,
                observations={"geometry": 1024},
            )

    def test_imported_writer_cleanup_failure_retains_uncertainty_and_restores_timeout(
        self,
    ):
        container, selection, identity, _ = authored_legacy_input(
            "TCUWP4CanBodyFlashWriter.dll", "write"
        )
        inputs = bind_legacy_context(container, 1, ("DEMO-OLD",), selection, identity)
        assert inputs.cpu is not None
        replay = RawReplay()

        def lifecycle(operation, parameters, remaining):
            result = replay.lifecycle(operation, parameters, remaining)
            if operation == "stop_filter":
                raise OSError("authored uncertain filter removal")
            return result

        channel = replay.channel()
        result = legacy_write(
            inputs.module,
            channel,
            inputs.cpu,
            finish_channel=channel,
            lifecycle=lifecycle,
        )
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["lifecycle_cleanup_error_type"], "OSError")
        self.assertEqual(replay.timeout, 321)
        self.assertEqual(result["transferred_bytes"], 1024)

    def test_imported_alternate_cpu_row_is_lazy_and_only_vforest_uses_it(self):
        for module in (
            "TCUWP4CanBodyFlashWriter.dll",
            "TCUWP4CanVFORESTFlashWriter.dll",
        ):
            payload = (
                b"ZV\0\x03\xfb" + bytes(1019) if "VFOREST" in module else bytes(1024)
            )
            container, selection, identity, _ = authored_legacy_input(
                module,
                "write",
                payload=payload,
                parameters={"AlternateCPUType": "missing"},
            )
            inputs = bind_legacy_context(
                container, 1, ("DEMO-OLD",), selection, identity
            )
            assert inputs.cpu is not None
            self.assertEqual(
                callable(inputs.cpu.alternate_parameters), "VFOREST" in module
            )
            replay = RawReplay()
            channel = replay.channel()
            self.assertEqual(
                legacy_write(
                    module,
                    channel,
                    inputs.cpu,
                    finish_channel=channel,
                    lifecycle=replay.lifecycle,
                )["state"],
                "complete",
            )
            if "VFOREST" in module:
                mismatch = replace(
                    inputs.cpu, parameters={**inputs.cpu.parameters, "CPUIDNo": "2"}
                )
                replay = RawReplay()
                channel = replay.channel()
                result = legacy_write(
                    module,
                    channel,
                    mismatch,
                    finish_channel=channel,
                    lifecycle=replay.lifecycle,
                )
                self.assertEqual(result["state"], "failed")
                self.assertEqual(result["error_type"], "LookupError")
                self.assertFalse(
                    any(payload[:1] == b"\x42" for payload in replay.writes)
                )

    def test_p5_prepare_native_pending_cleanup_uses_same_scoped_policy(self):
        now, writes, requests = [0.9], [], []

        def receive(ecu):
            now[0] = 180.0
            return bytes.fromhex("7f1078")

        channel = NativeProgrammingChannel(
            lambda ecu, request: requests.append(request) or bytes.fromhex("7f1078"),
            "authored",
            timeout=300,
            clock=lambda: now[0],
            receive=receive,
            pending_timeout_write=lambda ecu, request: writes.append(request),
        )
        result = legacy_prepare(
            "TCUWP5CanPowerTrainPrepareWriter.dll",
            [LegacyTarget(bytes.fromhex("abcd"), channel)],
            LegacyPrepareContext(b"\0", "1", {}),
            lambda module, seed: seed,
            wait=lambda milliseconds, remaining: None,
            raw_write=lambda address, payload, remaining: 1,
        )
        self.assertEqual(requests, [bytes.fromhex("1002")])
        self.assertEqual(writes, [b"\x3e"])
        self.assertEqual(result["error_type"], "NativePendingTimeout")
        self.assertEqual(result["native_error_code"], 41)
        self.assertEqual(result["state"], "recovery_required")
        self.assertIsNone(channel.pending_response_timeout_seconds)

    def test_native_finish_address_cpu_selection_and_width_matrix(self):
        from scripts.calibration import parse_cuw
        from scripts.programming_legacy import _WRITERS
        from tests.test_calibration import metadata_container

        cpu0_kinds = {
            "airbag",
            "security_airbag",
            "sonar",
            "dss",
            "chassis",
            "security_chassis",
        }
        for module, kind in _WRITERS.items():
            for first_720 in (False, True):
                _, selection, identity, _ = authored_legacy_input(module, "write")
                payload = (
                    b"ZV\0\x03\xfb" + bytes(1019) if kind == "vforest" else bytes(1024)
                )
                metadata = "[Format]\nVersion=6\n[Vehicle]\nNumberOfCalibration=2\nKindOfECU=1\nContactType=CAN\n"
                for index, last in (
                    (1, "0720" if first_720 else "0740"),
                    (2, "0740" if first_720 else "0720"),
                ):
                    metadata += (
                        f"[CPU0{index}]\nCPUType=1\nCPUImageName=image.vbf\nLocationID=01080{index}000000{last}\n"
                        "NumberOfTargets=1\n01_TargetCalibration=DEMO-OLD\n01_TargetData=12345678\n"
                        f"Nonce={bytes(16).hex()}\nSeedKey={bytes(16).hex()}\n"
                    )
                container = parse_cuw(
                    metadata_container(
                        metadata, [(b"one", payload), (b"two", payload)], 2
                    )
                )
                inputs = bind_legacy_context(
                    container,
                    1,
                    ("DEMO-OLD",),
                    selection,
                    identity,
                    observations={"cpu_index": 1},
                )
                use_720 = first_720 if kind in cpu0_kinds else not first_720
                expected = bytes.fromhex("0720" if use_720 else "0740fe")
                if kind in ("chassis", "security_chassis", "vforest"):
                    expected = expected[:2]
                elif kind == "cxpi":
                    expected = expected.ljust(3, b"\0")
                self.assertEqual(
                    inputs.target_metadata[0].request, bytes.fromhex("0200")
                )
                self.assertEqual(inputs.target_metadata[1].request, expected, module)
                self.assertEqual(inputs.target_metadata[1].extended, len(expected) == 3)

    def test_writer_interrupts_and_late_host_limits_preserve_cleanup(self):
        for mode in ("data", "cleanup", "cancel", "deadline"):
            container, selection, identity, _ = authored_legacy_input(
                "TCUWP4CanClearanceSonarFlashWriter.dll",
                "write",
                parameters={"SendTimeoutBeforePrepareWrite": "99"},
            )
            inputs = bind_legacy_context(
                container, 1, ("DEMO-OLD",), selection, identity
            )
            assert inputs.cpu is not None
            replay, now, cancelled = RawReplay(), [0.0], [False]
            original = replay.write

            def write(payload, remaining, original=original, mode=mode):
                if mode == "data" and len(payload) > 256:
                    raise KeyboardInterrupt("authored interrupted data")
                return original(payload, remaining)

            replay.write = write

            def lifecycle(
                operation,
                values,
                remaining,
                replay=replay,
                mode=mode,
                now=now,
                cancelled=cancelled,
            ):
                result = replay.lifecycle(operation, values, remaining)
                if operation == "stop_filter":
                    if mode == "cleanup":
                        raise KeyboardInterrupt("authored interrupted cleanup")
                    if mode == "cancel":
                        cancelled[0] = True
                    if mode == "deadline":
                        now[0] = 400
                return result

            channel = replay.channel(
                timeout=300,
                clock=lambda now=now: now[0],
                cancelled=lambda cancelled=cancelled: cancelled[0],
            )
            result = legacy_write(
                inputs.module,
                channel,
                inputs.cpu,
                finish_channel=channel,
                lifecycle=lifecycle,
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(replay.timeout, 321)
            self.assertIn(("set_send_timeout", {"milliseconds": 654}), replay.actions)
            if mode == "data":
                self.assertEqual(result["error_type"], "KeyboardInterrupt")

    def test_cid_preserves_primary_failure_and_checks_final_cleanup_boundary(self):
        for mode in ("primary", "cancel", "deadline"):
            now, cancelled, actions = [0.0], [False], []
            primary = TimeoutError("authored original timeout")

            def exchange(ecu, payload, mode=mode, primary=primary):
                if mode == "primary":
                    raise primary
                return bytes.fromhex("62f18101") + b"CID" + bytes(13)

            channel = NativeProgrammingChannel(
                exchange,
                "authored",
                clock=lambda now=now: now[0],
                cancelled=lambda cancelled=cancelled: cancelled[0],
            )

            def lifecycle(
                operation,
                values,
                remaining,
                mode=mode,
                now=now,
                cancelled=cancelled,
                actions=actions,
            ):
                actions.append(operation)
                if operation == "stop_filter" and mode == "primary":
                    raise OSError("authored cleanup failure")
                if operation == "disconnect":
                    if mode == "cancel":
                        cancelled[0] = True
                    if mode == "deadline":
                        now[0] = 100
                return 42 if operation == "start_filter" else None

            with self.assertRaises(
                InterruptedError if mode == "cancel" else TimeoutError
            ) as caught:
                legacy_get_cids(
                    "TCUWP5CanCIDGetter.dll",
                    [LegacyTarget(bytes.fromhex("abcd"), channel)],
                    parameters={},
                    lifecycle=lifecycle,
                )
            self.assertEqual(actions[-1], "disconnect")
            if mode == "primary":
                self.assertIs(caught.exception, primary)
                self.assertEqual(
                    primary.__dict__["legacy_cleanup_errors"][0]["operation"],
                    "stop_filter",
                )

    def test_prepare_skips_unused_archive_materialization_and_bus_type_requires_it_only_when_read(
        self,
    ):
        from scripts.calibration import parse_cuw
        from tests.test_calibration import metadata_container

        for module in (
            "TCUWP4CanCentralGWPrepareWriter.dll",
            "TCUWP5CanPowerTrainPrepareWriter.dll",
            "TCUWP5CanCIDGetter.dll",
        ):
            stage = "get_cid" if "CIDGetter" in module else "prepare"
            container, selection, identity, _ = authored_legacy_input(
                module,
                stage,
                parameters={"GetCANIDFunctionNameForPrepareWrite": ""}
                if "CentralGW" in module
                else {},
            )
            metadata = container.attached.data.decode("ascii").replace(
                "authored.vbf", "unused.bin"
            )
            container = parse_cuw(
                metadata_container(metadata, [(b"cpu", b"not an image")], 1)
            )
            inputs = bind_legacy_context(container, 1, (), selection, identity)
            if inputs.prepare is not None:
                self.assertIsNone(inputs.prepare.cpu_image)
            if "CentralGW" in module:
                assert inputs.prepare is not None
                result = legacy_prepare(
                    module, [], inputs.prepare, None, confirm_gateway=lambda: True
                )
                self.assertEqual(result["state"], "complete")
        self.assertEqual(legacy_bus_type(None, {}), 2)
        with self.assertRaises(ValueError):
            legacy_bus_type(None, {"CANCommunicationSpeedAddress": "0"})

    def test_imported_cid_timeout_allowance_is_lazy_and_typed(self):
        for code in (9, 16, 1):

            def exchange(ecu, request, code=code):
                raise LegacyTransportError(code)

            target = LegacyTarget(
                bytes.fromhex("abcd"), NativeProgrammingChannel(exchange, "authored")
            )
            if code in (9, 16):
                result = legacy_get_cids(
                    "TCUWP5CanCIDGetter.dll",
                    [target],
                    parameters={"RequestCANIDAllowingTimeout": "ABCD"},
                )
                self.assertEqual(result["skipped_timeout_targets"], ["abcd"])
            else:
                with self.assertRaises(LegacyTransportError):
                    legacy_get_cids(
                        "TCUWP5CanCIDGetter.dll",
                        [target],
                        parameters={"RequestCANIDAllowingTimeout": "invalid"},
                    )
        target = LegacyTarget(
            bytes.fromhex("abcd"),
            NativeProgrammingChannel(
                lambda ecu, request: bytes.fromhex("62f18101") + b"CID" + bytes(13),
                "authored",
            ),
        )
        self.assertEqual(
            legacy_get_cids(
                "TCUWP5CanCIDGetter.dll",
                [target],
                parameters={"RequestCANIDAllowingTimeout": "invalid"},
            )["cids"],
            ["CID"],
        )

    def test_prepare_callback_host_limit_wins_and_retains_original_error_type(self):
        cancelled = [False]

        def confirm():
            cancelled[0] = True
            raise OSError("authored provider failure")

        result = legacy_prepare(
            "TCUWP4CanCentralGWPrepareWriter.dll",
            [],
            LegacyPrepareContext(None, "1", {}),
            None,
            confirm_gateway=confirm,
            cancelled=lambda: cancelled[0],
        )
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(result["error_type"], "InterruptedError")
        self.assertEqual(result["error_chain"], ["InterruptedError", "OSError"])

    def test_cancelled_filter_acquisition_retains_id_for_cleanup_before_bus(self):
        for stage in ("write", "get_cid"):
            cancelled, operations, requests = [False], [], []
            replay = RawReplay()

            def lifecycle(
                operation,
                parameters,
                remaining,
                replay=replay,
                cancelled=cancelled,
                operations=operations,
            ):
                operations.append((operation, parameters))
                result = replay.lifecycle(operation, parameters, remaining)
                if operation == "start_filter":
                    cancelled[0] = True
                return result

            if stage == "get_cid":
                channel = NativeProgrammingChannel(
                    lambda ecu, request, requests=requests: (
                        requests.append(request) or b""
                    ),
                    "authored",
                    cancelled=lambda cancelled=cancelled: cancelled[0],
                )
                with self.assertRaises(InterruptedError):
                    legacy_get_cids(
                        "TCUWP5CanCIDGetter.dll",
                        [LegacyTarget(bytes.fromhex("abcd"), channel)],
                        parameters={},
                        lifecycle=lifecycle,
                    )
                self.assertEqual(requests, [])
                self.assertEqual(operations[-1], ("disconnect", {}))
            else:
                container, selection, identity, _ = authored_legacy_input(
                    "TCUWP4CanBodyFlashWriter.dll", "write"
                )
                inputs = bind_legacy_context(
                    container, 1, ("DEMO-OLD",), selection, identity
                )
                assert inputs.cpu is not None
                raw = replay.channel(cancelled=lambda cancelled=cancelled: cancelled[0])
                result = legacy_write(
                    inputs.module,
                    raw,
                    inputs.cpu,
                    finish_channel=raw,
                    lifecycle=lifecycle,
                )
                self.assertEqual(result["state"], "recovery_required")
                self.assertEqual(replay.writes, [])
                self.assertEqual(replay.timeout, 321)
            self.assertIn(("stop_filter", {"filter_id": 42}), operations)

    def test_all_six_imported_finish_probe_builds_use_cpu0_and_filter_lifecycle(self):
        from scripts.calibration import parse_cuw
        from tests.test_calibration import metadata_container

        modules = (
            "TCUWP4CanAirbagFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
        )
        for module in modules:
            for build in (12, 18):
                container, selection, identity, _ = authored_legacy_input(
                    module,
                    "write",
                    build=build,
                    parameters={"BlockSizeInfo": "unused-invalid-layout"},
                )
                metadata = (
                    container.attached.data.decode("ascii")
                    .replace("NumberOfCalibration=1", "NumberOfCalibration=2")
                    .replace("authored.vbf", "unused.bin")
                )
                metadata += "[CPU02]\nCPUType=1\nCPUImageName=second.bin\nLocationID=0208030000000740\nNumberOfTargets=1\n01_TargetCalibration=other\n"
                container = parse_cuw(
                    metadata_container(
                        metadata, [(b"one", b"unused"), (b"two", b"unused")], 2
                    )
                )
                address = bind_legacy_finish_probe(container, 1, selection, identity)
                self.assertEqual(address.request, bytes.fromhex("0100"))
                self.assertEqual(address.response, bytes.fromhex("0108"))
                events = []

                def lifecycle(operation, values, remaining, events=events):
                    events.append((operation, values))
                    return 42 if operation == "start_filter" else None

                channel = VendorCAN(
                    lambda payload, remaining, events=events: (
                        events.append(("write", payload)) or 1
                    ),
                    lambda remaining, events=events: (
                        events.append(("read", None)) or b"native-probe-payload"
                    ),
                )
                self.assertTrue(
                    legacy_is_finished(module, channel, lifecycle=lifecycle)
                )
                self.assertEqual(
                    events,
                    [
                        ("start_filter", {"target_index": 0}),
                        ("write", b"\x3e"),
                        ("read", None),
                        ("stop_filter", {"filter_id": 42}),
                    ],
                )

    def test_finish_probe_native_failure_and_host_cleanup_boundaries(self):
        module = "TCUWP4CanAirbagFlashWriter.dll"
        for mode in ("transport", "cancel_start", "cancel_stop", "deadline", "cleanup"):
            events, now, cancelled = [], [0.0], [False]

            def write(payload, remaining, events=events, mode=mode):
                events.append("write")
                if mode == "transport":
                    raise OSError("authored native transport failure")
                return 1

            def lifecycle(
                operation,
                values,
                remaining,
                mode=mode,
                events=events,
                now=now,
                cancelled=cancelled,
            ):
                events.append(operation)
                if mode == "cancel_start" and operation == "start_filter":
                    cancelled[0] = True
                if mode == "cancel_stop" and operation == "stop_filter":
                    cancelled[0] = True
                if mode == "deadline" and operation == "stop_filter":
                    now[0] = 100
                if mode == "cleanup" and operation == "stop_filter":
                    raise KeyboardInterrupt("authored interrupted filter cleanup")
                return 42 if operation == "start_filter" else None

            channel = VendorCAN(
                write,
                lambda remaining: b"reply",
                clock=lambda now=now: now[0],
                cancelled=lambda cancelled=cancelled: cancelled[0],
            )
            if mode == "transport":
                self.assertFalse(
                    legacy_is_finished(module, channel, lifecycle=lifecycle)
                )
            else:
                with self.assertRaises(
                    TimeoutError
                    if mode == "deadline"
                    else KeyboardInterrupt
                    if mode == "cleanup"
                    else InterruptedError
                ):
                    legacy_is_finished(module, channel, lifecycle=lifecycle)
            self.assertEqual(events[-1], "stop_filter")
            if mode == "cancel_start":
                self.assertNotIn("write", events)

    def test_cxpi_tester_present_primitive_uses_first_current_prepare_address(self):
        for value, prefix in (
            ("010001/010801\n020002/020802", "0000010001"),
            ("0100/0108", "0000010000"),
        ):
            container, selection, identity, _ = authored_legacy_input(
                "TCUWP4CanBodyFlashWriterForCXPI.dll",
                "write",
                parameters={"CanIDForPrepareWrite": value},
            )
            inputs = bind_legacy_context(
                container, 1, ("DEMO-OLD",), selection, identity
            )
            self.assertEqual(
                dict(inputs.tester_present_request or {}),
                {
                    "operation": "write_messages",
                    "protocol": 6,
                    "tx_flags": 128,
                    "data_hex": prefix + "3e02",
                    "count": 1,
                },
            )

    def test_native_negative_status_codes_preserve_host_error_distinction(self):
        expected = {
            "cpu": 10,
            "erase": 12,
            "write": 13,
            "inverify": 14,
            "verify": 15,
            "falsify": 73,
        }
        for phase, code in expected.items():
            module = (
                "TCUWP4CanSecurityAirbagFlashWriter.dll"
                if phase == "falsify"
                else "TCUWP4CanBodyFlashWriter.dll"
            )
            container, selection, identity, _ = authored_legacy_input(
                module, "write", parameters={"CPUIDNo": "2"} if phase == "cpu" else {}
            )
            inputs = bind_legacy_context(
                container, 1, ("DEMO-OLD",), selection, identity
            )
            assert inputs.cpu is not None
            replay, current = RawReplay(), [None]
            original = replay.write

            def write(
                payload,
                remaining,
                replay=replay,
                current=current,
                original=original,
                phase=phase,
            ):
                if len(payload) in (2, 5):
                    current[0] = {
                        0x25: "erase",
                        0x26: "erase",
                        0x47: "inverify",
                        0x48: "inverify",
                        0x15: "verify",
                        0x16: "verify",
                    }.get(payload[0], current[0])
                elif payload == b"\x41":
                    current[0] = "write"
                elif payload == b"\x47":
                    current[0] = "falsify"
                count = original(payload, remaining)
                if payload == b"\x50" and current[0] == phase:
                    replay.responses[-2] = b"\x01"
                return count

            replay.write = write
            channel = replay.channel()
            result = legacy_write(
                module,
                channel,
                inputs.cpu,
                finish_channel=channel,
                lifecycle=replay.lifecycle,
            )
            self.assertEqual(result["native_error_code"], code, phase)
            self.assertEqual(result["error_type"], "VendorOperationError")
            self.assertEqual(
                result["state"], "failed" if phase == "cpu" else "recovery_required"
            )
        for verify, code in ((False, 29), (True, 30)):
            responses = iter((b"\x3c", b"\x3c", b"\x3c", b"\x01", b"\x3c"))
            channel = VendorCAN(
                lambda payload, remaining: 1,
                lambda remaining, responses=responses: next(responses),
            )
            with self.assertRaises(VendorOperationError) as caught:
                vforest_transfer(channel, b"ZV\0\x03\xfb" + bytes(1019), verify=verify)
            self.assertEqual(caught.exception.code, code)
            original_error = VendorTransportError(55, "authored native driver failure")

            def write_failure(payload, remaining, error=original_error):
                raise error

            channel = VendorCAN(write_failure, lambda remaining: b"\x3c")
            with self.assertRaises(VendorTransportError) as caught_driver:
                vforest_transfer(channel, b"ZV\0\x03\xfb" + bytes(1019), verify=verify)
            self.assertIs(caught_driver.exception, original_error)
            self.assertEqual(caught_driver.exception.code, code)

    def test_body_gateway_external_memory_skips_unused_image_and_authorization(self):
        from scripts.calibration import parse_cuw
        from tests.test_calibration import metadata_container

        container, selection, identity, observations = authored_legacy_input(
            "TCUWP4CanBodyPrepareWriter.dll",
            "gateway",
            parameters={
                "ExternalMemoryFlag": "1",
                "CANCommunicationSpeedAddress": "0",
                "WaitTimeAfterSeedData": "unused",
            },
        )
        metadata = container.attached.data.decode("ascii").replace(
            "authored.vbf", "unused.bin"
        )
        container = parse_cuw(
            metadata_container(metadata, [(b"cpu", b"not an image")], 1)
        )
        inputs = bind_legacy_context(
            container, 1, (), selection, identity, observations=observations
        )
        assert inputs.prepare is not None
        self.assertIsNone(inputs.prepare.cpu_image)
        result = legacy_prepare(
            inputs.module, [], inputs.prepare, None, gateway_only=True
        )
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["events"], ["native_gateway_bus_skip"])
        self.assertFalse(result["gateway_result_valid"])
        self.assertTrue(result["gateway_result"])

    def test_diagnostic_native_caller_codes_preserve_nrc_classes_and_gateway_validity(
        self,
    ):
        cases = (
            ("airbag", b"\x27\x03", 16),
            ("airbag", b"\x27\x04", 17),
            ("airbag", b"\x10\x02", 18),
            ("body", b"\x10\x60", 49),
            ("power5", b"\x31", 25),
        )
        for kind, failing, native_code, positive in [
            (k, f, c, p) for k, f, c in cases for p in (False, True)
        ]:
            module = {
                "airbag": "TCUWP4CanAirbagPrepareWriter.dll",
                "body": "TCUWP4CanBodyPrepareWriter.dll",
                "power5": "TCUWP5CanPowerTrainPrepareWriter.dll",
            }[kind]

            def exchange(ecu, request, failing=failing, kind=kind, positive=positive):
                if request.startswith(failing):
                    return b"\x62\0" if positive else bytes((0x7F, request[0], 0x31))
                if request[:2] == b"\x27\x03":
                    return b"\x67\x03\0\0\x34"
                if request[:2] == b"\x27\x04":
                    return b"\x67\x04\x34"
                if request[:2] == b"\x27\x61":
                    return b"\x67\x61" + bytes(6)
                if request[:2] == b"\x27\x62":
                    return b"\x67\x62\x34"
                if request[:2] == b"\x27\x01":
                    return b"\x67\x01" + bytes(4)
                if request[:2] == b"\x27\x02":
                    return b"\x67\x02"
                return b"\x50\x02" + (bytes(4) if kind == "power5" else b"")

            channel = (
                NativeProgrammingChannel(exchange, "authored")
                if kind == "power5"
                else VendorDiagnosticChannel(exchange, "authored")
            )
            context = LegacyPrepareContext(
                b"\x01",
                "1",
                {"CANCommunicationSpeedAddress": "0"},
                security_access_password=b"ab",
            )
            result = legacy_prepare(
                module,
                [LegacyTarget(b"\x01\0", channel)],
                context,
                lambda module, seed: bytes(len(seed)),
                raw_write=lambda address, payload, remaining: 1,
                wait=lambda milliseconds, remaining: None,
                gateway_only=kind == "body",
                set_bs=lambda value: None,
            )
            self.assertEqual(
                result["native_error_code"], native_code, (kind, failing, result)
            )
            self.assertEqual(
                result["error_type"],
                "NativeUnexpectedResponse"
                if positive
                else "NativeNegativeResponse"
                if kind == "power5"
                else "NativeDiagnosticError",
            )
            if kind == "body":
                self.assertTrue(result["gateway_result_valid"])
                self.assertFalse(result["gateway_result"])

    def test_optional_native_positive_failures_are_caught_but_host_empty_is_not(self):
        for mode in ("prefix", "short", "host"):

            def exchange(ecu, request, mode=mode):
                if request == bytes.fromhex("22f181"):
                    return bytes.fromhex("62f18101") + b"CID" + bytes(13)
                if mode == "host":
                    return b""
                if mode == "short" and request == bytes.fromhex("220128"):
                    return bytes.fromhex("620128")
                return bytes.fromhex("6200")

            targets = [
                LegacyTarget(
                    b"\xab\xcd", NativeProgrammingChannel(exchange, "authored")
                )
            ]
            if mode == "host":
                with self.assertRaises(ValueError):
                    legacy_get_cids("TCUWP5CanCIDGetter.dll", targets, query_kind=2)
            else:
                result = legacy_get_cids(
                    "TCUWP5CanCIDGetter.dll", targets, query_kind=2
                )
                self.assertEqual(result["cids"], ["CID"])
                self.assertEqual(
                    [error["native_error_code"] for error in result["optional_errors"]],
                    [3, 92, 94, 3],
                )
                self.assertTrue(
                    all(
                        error["error_type"] == "NativeUnexpectedResponse"
                        for error in result["optional_errors"]
                    )
                )

    def test_old_native_utility_cap_keeps_caller_code_separate_from_host_timeout(self):
        cleanup = []
        channel = VendorDiagnosticChannel(
            lambda ecu, request: bytes.fromhex("7f2778"),
            "authored",
            pending_limit=0,
            send_cleanup=lambda ecu, request: cleanup.append(request) or 1,
        )
        result = legacy_prepare(
            "TCUWP4CanAirbagPrepareWriter.dll",
            [LegacyTarget(b"\x01\0", channel)],
            LegacyPrepareContext(None, "1", {}, security_access_password=b"ab"),
            lambda module, seed: seed,
            raw_write=lambda address, payload, remaining: 1,
        )
        self.assertEqual(result["error_type"], "VendorUtilityTimeout")
        self.assertEqual(result["native_error_code"], 16)
        self.assertEqual(cleanup, [b"\x3e"])

    def test_imported_global_authorization_is_private_and_conflicts_fail(self):
        ecu, service = bytes(range(16)), bytes(range(16, 32))
        container, selection, identity, _ = authored_legacy_input(
            "TCUWP5CanSecurityPowerTrainPrepareWriter.dll",
            "prepare",
            vehicle_extra=f"ECUAuthKey={ecu.hex()}\nServiceAuthKey={service.hex()}\n",
        )
        inputs = bind_legacy_context(container, 1, (), selection, identity)
        self.assertEqual(inputs.security_material["ecu_auth_key"], ecu)
        self.assertEqual(inputs.security_material["service_auth_key"], service)
        for secret in (ecu.hex(), service.hex()):
            self.assertNotIn(secret, repr(inputs))
            self.assertNotIn(secret, repr(inputs.report()))
        with self.assertRaises(ValueError):
            bind_legacy_context(
                container,
                1,
                (),
                selection,
                identity,
                attachments={"ecu_auth_key": bytes(16)},
            )
        self.assertEqual(
            bind_legacy_context(
                container, 1, (), selection, identity, attachments={"ecu_auth_key": ecu}
            ).report(),
            inputs.report(),
        )

    def test_original_executable_location_strings_do_not_invoke_dll_address_rules(self):
        from unittest.mock import patch

        from scripts.calibration import parse_cuw
        from tests.test_calibration import metadata_container

        container, selection, _, _ = authored_legacy_input(
            "TCUWP4CanBodyFlashWriter.dll", "write"
        )
        for location in ("98", "216", "native text", "0108010000000720"):
            metadata = container.attached.data.replace(
                b"LocationID=0108010000000720", f"LocationID={location}".encode()
            )
            imported = parse_cuw(
                metadata_container(metadata.decode(), [(b"cpu", bytes(1024))], 1)
            )
            for build in (12, 18):
                with self.subTest(location=location, build=build):
                    with patch.object(
                        type(selection),
                        "addresses",
                        side_effect=AssertionError(
                            "Original executable must use its own address producer"
                        ),
                    ):
                        context = bind_native_cpu_context(
                            imported,
                            1,
                            (),
                            selection,
                            stage="write",
                            original_executable_build=build,
                        )
                    self.assertEqual(context.selected.values["locationid"], location)
                    self.assertEqual(context.target_metadata, ())
                    self.assertEqual(
                        context.location_id,
                        bytes.fromhex(location) if len(location) == 16 else None,
                    )
                    self.assertEqual(context.parameters, context.base_parameters)
            if len(location) != 16:
                with self.assertRaisesRegex(ValueError, "eight hexadecimal bytes"):
                    bind_native_cpu_context(imported, 1, (), selection, stage="write")
        for build in (True, 0, 2026, "18"):
            with (
                self.subTest(invalid_build=build),
                self.assertRaises((TypeError, ValueError)),
            ):
                bind_native_cpu_context(
                    container,
                    1,
                    (),
                    selection,
                    stage="write",
                    original_executable_build=cast(int, build),
                )

    def test_imported_password_sources_resolve_only_native_used_fields(self):
        container, selection, _, _ = authored_legacy_input(
            "TCUWP4CanBodyFlashWriter.dll",
            "write",
            payload=bytes.fromhex("01020304") + bytes(1020),
            parameters={"PasswordAddress": "0", "ByteOrder": "65536"},
        )
        context = bind_native_cpu_context(
            container, 1, ("DEMO-OLD",), selection, stage="write"
        )
        self.assertEqual(
            native_cpu_passwords(context, ("DEMO-OLD",)), (0x12345678, 0x11223344)
        )
        self.assertEqual(
            native_cpu_passwords(
                context,
                ("DEMO-OLD",),
                require_new=True,
                use_metadata_new_password=False,
            ),
            (0x12345678, 0x04030201),
        )
        big = replace(context, parameters={"PasswordAddress": "0", "ByteOrder": "2"})
        self.assertEqual(
            native_cpu_passwords(
                big, ("DEMO-OLD",), require_new=True, use_metadata_new_password=False
            )[1],
            0x01020304,
        )
        unused = replace(
            context,
            parameters={"PasswordAddress": "invalid"},
            selected=replace(
                context.selected,
                values={**context.selected.values, "newpassword": "invalid"},
            ),
        )
        self.assertEqual(
            native_cpu_passwords(unused, ("DEMO-OLD",), resolve_new=False),
            (0x12345678, None),
        )
        current = replace(unused, metadata_version=8)
        self.assertEqual(
            native_cpu_passwords(current, ("DEMO-OLD",), resolve_new=False), (0, None)
        )
        with self.assertRaises(ValueError):
            native_cpu_passwords(unused, ("DEMO-OLD",), require_new=True)

    def test_imported_prepare_password_from_catalog_and_channel_binding(self):
        module = "TCUWP4CanAirbagPrepareWriter.dll"
        container, selection, identity, observations = authored_legacy_input(
            module, "prepare"
        )
        inputs = bind_legacy_context(
            container, 1, (), selection, identity, observations=observations
        )
        self.assertIsNone(inputs.cpu)
        assert inputs.prepare is not None
        self.assertEqual(inputs.prepare.security_access_password, bytes.fromhex("aabb"))
        calls = []

        def exchange(ecu, payload):
            calls.append(payload)
            if payload[:2] == bytes.fromhex("2703"):
                return bytes.fromhex("6703000034")
            if payload[:2] == bytes.fromhex("2704"):
                return bytes.fromhex("670434")
            return bytes.fromhex("5002")

        targets = inputs.bind_targets(
            lambda address, policy: VendorDiagnosticChannel(exchange, "authored")
        )
        result = legacy_prepare(
            module,
            targets,
            inputs.prepare,
            lambda name, seed: bytes(2),
            raw_write=lambda a, p, r: 1,
        )
        self.assertEqual(result["state"], "complete")
        self.assertEqual(calls[0], bytes.fromhex("2703aabb"))
        with self.assertRaises(ValueError):
            inputs.bind_targets(
                lambda address, policy: NativeProgrammingChannel(
                    exchange, "wrong-policy"
                )
            )

    def test_ordinary_srecord_materialization_keeps_first_s1_gap_ff_and_s0(self):
        from tests.test_calibration import srecord

        raw = b"\n".join(
            (
                srecord(0, 0, b"header"),
                srecord(1, 0x1000, b"AB"),
                srecord(1, 0x1004, b"CD"),
                srecord(9, 0x1000),
            )
        )
        image = materialize_legacy_image(raw)
        self.assertEqual(image.data, b"AB\xff\xffCD")
        self.assertEqual(image.s0_header, b"header")
        self.assertEqual(image.base_address, 0x1000)
        self.assertEqual(image.flash_size, 4)
        mixed = b"\n".join(
            (srecord(1, 0x1000, b"ABCD"), srecord(2, 0x1002, b"xy"), srecord(8, 0x1000))
        )
        overlap = materialize_legacy_image(mixed)
        self.assertEqual(overlap.data, b"ABxy")
        self.assertEqual(overlap.flash_size, 6)

        with self.assertRaises(ValueError):
            materialize_legacy_image(bytes(8), filename="unknown.bin")
        self.assertEqual(
            materialize_legacy_image(bytes(8), filename="explicit.VBF").data, bytes(8)
        )

    def test_ordinary_srecords_sort_unsigned_addresses_before_overlapping_copies(self):
        from tests.test_calibration import srecord

        for address in (0x1000, 0x80001000):
            with self.subTest(address=address):
                raw = b"\n".join(
                    (
                        srecord(3, address + 2, b"XY"),
                        srecord(3, address, b"abcd"),
                        srecord(7, address),
                    )
                )
                image = materialize_legacy_image(raw)
                self.assertEqual(image.data, b"abXY")
                self.assertEqual((image.base_address, image.flash_size), (address, 6))

    def test_ordinary_srecord_span_ends_at_last_sorted_record(self):
        from tests.test_calibration import srecord

        raw = b"\n".join(
            (
                srecord(1, 0x1000, b"abcdef"),
                srecord(1, 0x1002, b"XY"),
                srecord(9, 0x1000),
            )
        )
        with self.assertRaisesRegex(ValueError, "record exceeds"):
            materialize_legacy_image(raw)

    def test_all_thirteen_native_preparation_entrypoints(self):
        modules = (
            "TCUWP4CanAirbagPrepareWriter.dll",
            "TCUWP4CanBodyPrepareWriter.dll",
            "TCUWP4CanCentralGWPrepareWriter.dll",
            "TCUWP4CanChassisShrinkPrepareWriter.dll",
            "TCUWP4CanClearanceSonarPrepareWriter.dll",
            "TCUWP4CanPowerTrainPrepareWriter.dll",
            "TCUWP4CanSecurityAirbagPrepareWriter.dll",
            "TCUWP4CanSecurityChassisShrinkPrepareWriter.dll",
            "TCUWP4P5CanPowerTrainPrepareWriter.dll",
            "TCUWP5CanPowerTrainPrepareWriter.dll",
            "TCUWP5CanPowerTrainPrepareWriterForBodyMicon.dll",
            "TCUWP5CanPowerTrainPrepareWriterForSolar.dll",
            "TCUWP5CanSecurityPowerTrainPrepareWriter.dll",
        )
        for module, build in (
            (module, build) for module in modules for build in (12, 18)
        ):
            if build == 12 and module == "TCUWP5CanSecurityPowerTrainPrepareWriter.dll":
                continue
            with self.subTest(module=module, build=build):
                calls, raw, waits, bs = [], [], [], []
                width = (
                    16
                    if "Security" in module
                    else 2
                    if any(part in module for part in ("Airbag", "Sonar"))
                    else 6
                    if "BodyMicon" in module or "CanBody" in module
                    else 4
                )

                def exchange(ecu, payload, calls=calls, width=width):
                    calls.append((ecu, payload))
                    if payload[0] == 0x10:
                        return b"\x50" + payload[1:2] + bytes(4)
                    if payload[0] == 0x31:
                        return b"\x71" + payload[1:]
                    if payload[1] & 1:
                        return (
                            b"\x67"
                            + payload[1:2]
                            + bytes(range(width))
                            + (b"\x34" if payload[1] == 3 else b"")
                        )
                    return (
                        b"\x67"
                        + payload[1:2]
                        + (b"\x34" if payload[1] in (4, 0x62) else b"")
                    )

                old = module.startswith("TCUWP4") and "P4P5" not in module
                count = (
                    0
                    if "CentralGW" in module
                    else 2
                    if any(part in module for part in ("PowerTrain", "ChassisShrink"))
                    else 1
                )
                targets = []
                for index in range(count):
                    cls = (
                        VendorDiagnosticChannel
                        if old or ("P4P5" in module and index == 1)
                        else NativeProgrammingChannel
                    )
                    targets.append(
                        LegacyTarget(
                            index.to_bytes(
                                3 if module == "TCUWP4CanBodyPrepareWriter.dll" else 2,
                                "big",
                            ),
                            cls(exchange, str(index)),
                        )
                    )
                context = LegacyPrepareContext(
                    b"\x01",
                    "13",
                    {
                        "CANCommunicationSpeedAddress": "0",
                        "WaitTimeAfterSeedData": "5",
                        "WaitTimeAfterSeedKey": "7",
                        "WaitTimeAfterDiagnosticMask": "11",
                    },
                    cpu_count=2,
                    address_extended=True,
                    security_access_password=b"\xaa\xbb",
                    ecu_auth_key=b"\xcc" * 16,
                )
                result = legacy_prepare(
                    module,
                    targets,
                    context,
                    lambda name, seed: seed[::-1],
                    raw_write=lambda identifier, payload, remaining, raw=raw: (
                        raw.append((identifier, payload)) or 1
                    ),
                    wait=lambda milliseconds, remaining, waits=waits: waits.append(
                        milliseconds
                    ),
                    set_bs=bs.append,
                    confirm_gateway=lambda: True,
                    native_build=build,
                )
                self.assertEqual(result["state"], "complete", result)
                self.assertTrue(all(entry == (0x720, b"\xa0\x27") for entry in raw))
                if "CentralGW" not in module:
                    self.assertGreaterEqual(len(raw), 3)
                if "ChassisShrink" in module:
                    seeds = [
                        payload for ecu, payload in calls if payload[:2] == b"\x27\x01"
                    ]
                    self.assertEqual([payload[2] for payload in seeds], [1, 0])
                if "AirbagPrepare" in module and "Security" in module:
                    self.assertEqual(
                        len([p for ecu, p in calls if p[:2] == b"\x27\x03"]), 2
                    )
                if bs:
                    self.assertEqual(bs, [1, 0])
                self.assertNotIn("cccccccc", repr(result))

    def test_native_prepare_gateway_and_bus_selection(self):
        self.assertEqual(legacy_bus_type(b"\0\x01\x05", {}), 2)
        for offset, expected in (("0", 0), ("1", 1), ("2", 2)):
            self.assertEqual(
                legacy_bus_type(
                    b"\0\x01\x05", {"CANCommunicationSpeedAddress": offset}
                ),
                expected,
            )
        with self.assertRaises(ValueError):
            legacy_bus_type(b"\0", {"CANCommunicationSpeedAddress": "1"})
        calls = []

        def exchange(ecu, payload):
            calls.append(payload)
            if payload == b"\x27\x61":
                return b"\x67\x61" + bytes(6)
            if payload[:2] == b"\x27\x62":
                return b"\x67\x62\x34"
            return b"\x50\x60"

        targets = [
            LegacyTarget(b"\x01\0", VendorDiagnosticChannel(exchange, "authored"))
        ]
        context = LegacyPrepareContext(
            b"\x01", "0", {"CANCommunicationSpeedAddress": "0"}
        )
        for build in (12, 18):
            result = legacy_prepare(
                "TCUWP4CanBodyPrepareWriter.dll",
                targets,
                context,
                lambda name, seed: seed,
                gateway_only=True,
                native_build=build,
            )
            self.assertEqual(result["state"], "complete")
            self.assertEqual(calls[-1], b"\x10\x60")
        calls.clear()
        context = LegacyPrepareContext(
            b"\0", "0", {"CANCommunicationSpeedAddress": "0"}
        )
        result = legacy_prepare(
            "TCUWP4CanBodyPrepareWriter.dll",
            targets,
            context,
            lambda name, seed: seed,
            gateway_only=True,
        )
        self.assertEqual(result["events"], ["native_gateway_bus_skip"])
        self.assertEqual(calls, [])

    def test_prepare_native_soft_negative_and_cancel_boundaries(self):
        for module, soft_sid in (
            ("TCUWP5CanPowerTrainPrepareWriter.dll", 0x27),
            ("TCUWP5CanPowerTrainPrepareWriterForSolar.dll", 0x10),
        ):
            for sid in (0x27, 0x10):
                targets = [
                    LegacyTarget(
                        b"\x01\0",
                        NativeProgrammingChannel(
                            lambda ecu, payload, sid=sid: bytes((0x7F, sid, 0x12)),
                            "authored",
                        ),
                    )
                ]
                context = LegacyPrepareContext(
                    b"\0", "0", native_flag_728_nonempty=True
                )
                result = legacy_prepare(
                    module,
                    targets,
                    context,
                    lambda name, seed: seed,
                    raw_write=lambda *args: 1,
                    wait=lambda *args: None,
                )
                self.assertEqual(
                    result["state"],
                    "complete" if sid == soft_sid else "recovery_required",
                )
        calls = []
        channel = VendorDiagnosticChannel(
            lambda ecu, payload: calls.append(payload) or b"\x67\x61" + bytes(6),
            "authored",
        )
        targets = [LegacyTarget(b"\x01\0", channel)]
        context = LegacyPrepareContext(b"\0", "0")
        result = legacy_prepare(
            "TCUWP4CanBodyPrepareWriter.dll",
            targets,
            context,
            lambda name, seed: seed,
            raw_write=lambda *args: 1,
            cancelled=lambda: True,
        )
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(calls, [])

    def test_all_ten_native_writer_entrypoints(self):
        modules = (
            "TCUWP4CanAirbagFlashWriter.dll",
            "TCUWP4CanBodyFlashWriter.dll",
            "TCUWP5CanBodyFlashWriter.dll",
            "TCUWP4CanBodyFlashWriterForCXPI.dll",
            "TCUWP4CanChassisShrinkFlashWriter.dll",
            "TCUWP4CanClearanceSonarFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
            "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
            "TCUWP4CanVFORESTFlashWriter.dll",
        )
        for module, build in (
            (module, build) for module in modules for build in (12, 18)
        ):
            if build == 12 and module == "TCUWP5CanSecurityPowerTrainPrepareWriter.dll":
                continue
            with self.subTest(module=module, build=build):
                replay = RawReplay()
                channel = replay.channel()
                image = (
                    b"ZV\0\x03\xfb" + bytes(1019)
                    if "VFOREST" in module
                    else bytes(1024)
                )
                cpu = LegacyCPU(
                    image,
                    bytes(8),
                    0x12345678,
                    {"BlockSizeInfo": "0:1x1", "CPUIDNo": "1", "ShrinkFlag": "1"},
                    nonce=bytes(16),
                    authorized_key=bytes(16),
                    id_big_endian=False,
                )
                result = legacy_write(
                    module,
                    channel,
                    cpu,
                    finish_channel=channel,
                    set_timeout=replay.set_timeout,
                    get_timeout=lambda replay=replay: replay.timeout,
                    tester_present=lambda: None,
                    set_bs=lambda value: None,
                    native_build=build,
                )
                self.assertEqual(result["state"], "complete", result)
                self.assertEqual(result["transferred_bytes"], len(image))
                self.assertIn(b"\x80", replay.writes)
                if "CXPI" in module:
                    self.assertIn(b"\x18\0\0\0\0", replay.writes)
                    self.assertEqual(replay.waits, [2000] * 4)
                elif "VFOREST" in module:
                    self.assertIn(b"\x42\0\0\0\0\xff", replay.writes)
                    self.assertIn(b"\x17\0\0\0\0\xff", replay.writes)
                    self.assertNotIn(b"\x26\0\0\0\0", replay.writes)
                else:
                    self.assertIn(b"\x26\0\0\0\0", replay.writes)
                    self.assertIn(b"\x16\0\0\0\0", replay.writes)

    def test_cxpi_uncertain_bs_enable_is_reset_before_transport_setup(self):
        changes = []

        def set_bs(value):
            changes.append(value)
            if value:
                raise ConnectionError("authored applied then raised")

        replay = RawReplay()
        channel = replay.channel()
        result = legacy_write(
            "TCUWP4CanBodyFlashWriterForCXPI.dll",
            channel,
            LegacyCPU(
                bytes(1024),
                bytes(8),
                1,
                {"BlockSizeInfo": "0:1x1", "CPUIDNo": "1", "ShrinkFlag": "1"},
                id_big_endian=False,
            ),
            finish_channel=channel,
            get_timeout=lambda: 321,
            set_timeout=replay.set_timeout,
            set_bs=set_bs,
            tester_present=lambda: None,
        )
        self.assertEqual(result["state"], "failed")
        self.assertEqual(changes, [1, 0])
        self.assertEqual(replay.writes, [])
        self.assertEqual(replay.timeouts, [])

    def test_initial_retry_password_toggle_and_error_domains(self):
        class InitialFault(RawReplay):
            def __init__(self, code, response_phase=False):
                super().__init__()
                self.code, self.response_phase, self.reads = code, response_phase, 0

            def read(self, remaining):
                self.reads += 1
                if self.reads == (2 if self.response_phase else 1):
                    self.responses.clear()
                    self.check_id_count = 0
                    raise VendorTransportError(
                        self.code, "authored native transport failure"
                    )
                return super().read(remaining)

        for module, code, response_phase, success in (
            ("TCUWP4CanAirbagFlashWriter.dll", 9, False, True),
            ("TCUWP4CanAirbagFlashWriter.dll", 7, False, False),
            ("TCUWP4CanAirbagFlashWriter.dll", 9, True, False),
            ("TCUWP4CanBodyFlashWriter.dll", 9, True, True),
        ):
            replay = InitialFault(code, response_phase)
            channel = replay.channel()
            result = legacy_write(
                module,
                channel,
                LegacyCPU(
                    bytes(1024),
                    bytes(8),
                    0x11223344,
                    {
                        "BlockSizeInfo": "0:1x1",
                        "CPUIDNo": "1",
                        "ShrinkFlag": "1",
                        "WaitTimeAfterInitialCommandError": "17",
                    },
                    id_big_endian=False,
                    native_retry_flag_728=True,
                    alternate_password=0x55667788,
                ),
                finish_channel=channel,
                get_timeout=lambda: 321,
                set_timeout=replay.set_timeout,
            )
            self.assertEqual(
                result["state"], "complete" if success else "failed", result
            )
            self.assertEqual(result["initial_command_attempts"], 2 if success else 1)
            if success:
                self.assertEqual(replay.writes[4], bytes.fromhex("44332211"))
                self.assertEqual(
                    replay.writes[9],
                    bytes.fromhex("88776655")
                    if "Airbag" in module
                    else bytes.fromhex("44332211"),
                )
                self.assertEqual(replay.waits, [17] if "Airbag" in module else [])

    def test_initial_retry_ceiling_and_native_password_cleanup(self):
        class NeverAck(RawReplay):
            def read(self, remaining):
                self.responses.clear()
                self.check_id_count = 0
                raise VendorTransportError(9, "authored native timeout")

        replay = NeverAck()
        channel = replay.channel()
        result = legacy_write(
            "TCUWP4CanAirbagFlashWriter.dll",
            channel,
            LegacyCPU(
                bytes(1024),
                bytes(8),
                1,
                {"BlockSizeInfo": "0:1x1", "CPUIDNo": "1", "ShrinkFlag": "1"},
                native_retry_flag_728=True,
                alternate_password=2,
            ),
            finish_channel=channel,
            get_timeout=lambda: 321,
            set_timeout=replay.set_timeout,
        )
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["initial_command_attempts"], 11)
        self.assertEqual(len(replay.writes), 55)
        self.assertTrue(result["next_password_is_new"])
        self.assertEqual(result["native_error_code"], 7)
        self.assertEqual(replay.timeouts, [0, 321])

    def test_deadline_after_native_wait_restores_transport_before_io(self):
        now = [0.0]
        replay = RawReplay()
        channel = VendorCAN(
            replay.write,
            replay.read,
            timeout=1,
            clock=lambda: now[0],
            wait=lambda ms, r: now.__setitem__(0, 2.0),
        )
        result = legacy_write(
            "TCUWP4CanChassisShrinkFlashWriter.dll",
            channel,
            LegacyCPU(
                bytes(1024),
                bytes(8),
                1,
                {
                    "BlockSizeInfo": "0:1x1",
                    "CPUIDNo": "1",
                    "ShrinkFlag": "1",
                    "WaitTimeAfterReprogrammingMode": "2000",
                },
            ),
            finish_channel=channel,
            get_timeout=lambda: 321,
            set_timeout=replay.set_timeout,
        )
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["timeout_cleanup_error_type"], "TimeoutError")
        self.assertEqual(result["error_type"], "TimeoutError")
        self.assertEqual(replay.writes, [])
        self.assertEqual(replay.timeouts, [0, 321])

    def test_multi_cpu_change_and_exact_static_identity(self):
        replay = RawReplay()
        channel = replay.channel()
        result = legacy_write(
            "TCUWP4CanDSS1FlashWriter.dll",
            channel,
            LegacyCPU(
                bytes(1024),
                bytes(8),
                1,
                {"BlockSizeInfo": "0:1x1", "CPUIDNo": "1", "ShrinkFlag": "1"},
                cpu_count=2,
            ),
            finish_channel=channel,
            get_timeout=lambda: 321,
            set_timeout=replay.set_timeout,
        )
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["transitions"], ["next_cpu"])
        self.assertIn(b"\x65", replay.writes)
        self.assertNotIn(b"\x80", replay.writes)
        digest = "71782a813c5fb8b5f165a6539dbbccdba0b74a0ab3107f973dcd20c23ca85454"
        profile = legacy_module_profile("TCUWP4CanBodyFlashWriter.dll", digest)
        self.assertEqual(profile["native_build"], 12)
        self.assertEqual(profile["callable_exports"], ["StartFlashWrite"])
        with self.assertRaises(ValueError):
            legacy_module_profile("TCUWP5CanBodyFlashWriter.dll", digest)

    def test_native_flag740_is_independent_of_retry_password72c(self):
        for flag in (False, True):
            replay = RawReplay()
            channel = replay.channel()
            result = legacy_write(
                "TCUWP4CanChassisShrinkFlashWriter.dll",
                channel,
                LegacyCPU(
                    bytes(1024),
                    bytes(8),
                    1,
                    {"BlockSizeInfo": "0:1x1", "CPUIDNo": "1", "ShrinkFlag": "1"},
                    native_flag_740=flag,
                    native_retry_flag_72c=True,
                ),
                finish_channel=channel,
                get_timeout=lambda: 321,
                set_timeout=replay.set_timeout,
            )
            self.assertEqual(result["state"], "complete")
            self.assertEqual(replay.timeouts, [0, 10000, 321] if flag else [0, 321])

    def test_sonar_finish_ack_is_build_specific(self):
        counts = []
        for build in (12, 18):
            replay = RawReplay()
            channel = replay.channel()
            result = legacy_write(
                "TCUWP4CanClearanceSonarFlashWriter.dll",
                channel,
                LegacyCPU(
                    bytes(1024),
                    bytes(8),
                    1,
                    {"BlockSizeInfo": "0:1x1", "CPUIDNo": "1", "ShrinkFlag": "1"},
                ),
                finish_channel=channel,
                native_build=build,
                get_timeout=lambda: 321,
                set_timeout=replay.set_timeout,
            )
            self.assertEqual(result["state"], "complete")
            counts.append(channel.received)
            self.assertEqual(replay.responses, [b"\x3c"] if build == 12 else [])
        self.assertEqual(counts[1], counts[0] + 1)

    def test_native_writer_uncertainty_and_no_automatic_resume(self):
        module = "TCUWP4CanBodyFlashWriter.dll"
        cpu = LegacyCPU(
            bytes(1024),
            bytes(8),
            1,
            {"BlockSizeInfo": "0:1x1", "CPUIDNo": "1", "ShrinkFlag": "1"},
            id_big_endian=False,
        )
        replay = RawReplay(lambda payload, writes: payload.startswith(b"\x26"))
        channel = replay.channel()
        result = legacy_write(
            module,
            channel,
            cpu,
            finish_channel=channel,
            set_timeout=replay.set_timeout,
            get_timeout=lambda replay=replay: replay.timeout,
        )
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["checkpoint"]["phase"], "erase")
        self.assertTrue(result["checkpoint"]["uncertain"])
        count = len(replay.writes)
        resumed = legacy_write(
            module,
            channel,
            cpu,
            finish_channel=channel,
            checkpoint=result["checkpoint"],
        )
        self.assertEqual(resumed["state"], "recovery_required")
        self.assertEqual(len(replay.writes), count)
        self.assertFalse(resumed["resumed"])

    def test_legacy_cid_native_pending_expiry_writes_only_cleanup(self):
        for mode in ("native", "host", "cancel", "missing"):
            now, writes, requests = [0.9], [], []

            def exchange(ecu, request, requests=requests):
                requests.append(request)
                return bytes.fromhex("7f2278")

            def receive(ecu, now=now):
                now[0] = 180.0
                return bytes.fromhex("7f2278")

            channel = NativeProgrammingChannel(
                exchange,
                "authored",
                timeout=100 if mode == "host" else 300,
                clock=lambda now=now: now[0],
                receive=receive,
                cancelled=lambda mode=mode, now=now: mode == "cancel" and now[0] > 1,
                pending_timeout_write=None
                if mode == "missing"
                else lambda ecu, request, writes=writes: writes.append(request),
            )
            with self.assertRaises(
                InterruptedError
                if mode == "cancel"
                else ValueError
                if mode == "missing"
                else TimeoutError
            ):
                legacy_get_cids(
                    "TCUWP5CanCIDGetter.dll",
                    [LegacyTarget(bytes.fromhex("abcd"), channel)],
                )
            self.assertEqual(writes, [b"\x3e"] if mode == "native" else [])
            self.assertEqual(requests, [bytes.fromhex("22f181")])
            self.assertIsNone(channel.pending_response_timeout_seconds)

    def test_optional_native_pending_expiry_retains_cid_but_host_timeout_stops(self):
        for host_timeout in (False, True):
            now, writes, requests = [0.0], [], []

            def exchange(ecu, request, requests=requests):
                requests.append(request)
                if request == bytes.fromhex("22f181"):
                    return bytes.fromhex("62f18101") + b"CID" + bytes(13)
                return bytes.fromhex("7f2278")

            def receive(ecu, now=now):
                now[0] += 180
                return bytes.fromhex("7f2278")

            channel = NativeProgrammingChannel(
                exchange,
                "authored",
                timeout=100 if host_timeout else 2000,
                clock=lambda now=now: now[0],
                receive=receive,
                pending_timeout_write=lambda ecu, request, writes=writes: writes.append(
                    request
                ),
            )
            if host_timeout:
                with self.assertRaises(TimeoutError):
                    legacy_get_cids(
                        "TCUWP5CanCIDGetter.dll",
                        [LegacyTarget(bytes.fromhex("abcd"), channel)],
                        query_kind=2,
                    )
                self.assertEqual(writes, [])
                self.assertEqual(len(requests), 2)
            else:
                result = legacy_get_cids(
                    "TCUWP5CanCIDGetter.dll",
                    [LegacyTarget(bytes.fromhex("abcd"), channel)],
                    query_kind=2,
                )
                self.assertEqual(result["cids"], ["CID"])
                self.assertEqual(writes, [b"\x3e"] * 4)
                self.assertEqual(
                    [item["error_type"] for item in result["optional_errors"]],
                    ["NativePendingTimeout"] * 4,
                )
                self.assertEqual(len(requests), 5)

    def test_build18_cid_address_metadata_has_global_native_32_entry_cap(self):
        response = bytes.fromhex("62f18114") + (b"CID" + bytes(13)) * 20
        targets = [
            LegacyTarget(
                bytes.fromhex(address),
                NativeProgrammingChannel(lambda ecu, request: response, address),
            )
            for address in ("abcd", "ef01")
        ]
        result = legacy_get_cids("TCUWP5CanCIDGetter.dll", targets)
        self.assertEqual(len(result["cids"]), 40)
        self.assertEqual(
            result["address_metadata"],
            [{"flag": 0, "request_id": "ABCD"}] * 20
            + [{"flag": 0, "request_id": "EF01"}] * 12,
        )
        self.assertEqual(len(result["cid_addresses"]), 32)

    def test_all_native_cid_entrypoints_execute_real_requests(self):
        modules = (
            "TCUWP4P5CanCIDGetter.dll",
            "TCUWP5CanCIDGetter.dll",
            "TCUWP5CanCIDGetterWithSetBS.dll",
        )
        for module, build in (
            (module, build) for module in modules for build in (12, 18)
        ):
            calls, bs = [], []

            def exchange(ecu, payload, calls=calls):
                calls.append((ecu, payload))
                if payload == b"\x09\0":
                    return b"\x49\0\x30\0\0\0"
                if payload == b"\x09\x04":
                    return b"\x49\x04\x01" + b"P4" + bytes(14)
                if payload == b"\x1a\x89":
                    return b"\x5a" + b"ASSEMBLY" + bytes(4)
                return b"\x62\xf1\x81\x01" + b"P5" + bytes(14)

            targets = [
                LegacyTarget(b"\xab\xcd", NativeProgrammingChannel(exchange, "p5"))
            ]
            if "P4P5" in module:
                targets.append(
                    LegacyTarget(b"\x02\0", VendorDiagnosticChannel(exchange, "p4"))
                )
            result = legacy_get_cids(
                module, targets, set_bs=bs.append, native_build=build
            )
            self.assertEqual(
                result["cids"], ["P5", "P4"] if len(targets) == 2 else ["P5"]
            )
            self.assertEqual(bs, [1, 0] if "WithSetBS" in module else [])
            self.assertEqual(
                result["address_metadata"],
                [
                    {"flag": 0, "request_id": target.request.hex().upper()}
                    for target in targets
                ]
                if build == 18
                else [],
            )
            self.assertEqual(
                result["cid_address_association"], "host-observed-target-association"
            )
            self.assertEqual(calls[0], ("p5", b"\x22\xf1\x81"))
            if len(targets) == 2:
                self.assertEqual(calls[1:3], [("p4", b"\x09\0"), ("p4", b"\x09\x04")])

    def test_native_cid_timeout_exception_is_exactly_scoped(self):
        for status in (9, 16, 1):

            def exchange(ecu, payload, status=status):
                raise LegacyTransportError(status)

            targets = [
                LegacyTarget(b"\x01\0", NativeProgrammingChannel(exchange, "authored"))
            ]
            if status in (9, 16):
                result = legacy_get_cids(
                    "TCUWP5CanCIDGetter.dll",
                    targets,
                    allowing_timeout_request=b"\x01\0",
                )
                self.assertEqual(result["skipped_timeout_targets"], ["0100"])
            else:
                with self.assertRaises(LegacyTransportError):
                    legacy_get_cids(
                        "TCUWP5CanCIDGetter.dll",
                        targets,
                        allowing_timeout_request=b"\x01\0",
                    )
            with self.assertRaises(LegacyTransportError):
                legacy_get_cids("TCUWP5CanCIDGetter.dll", targets)

    def test_bs_cleanup_even_when_enable_applies_then_raises(self):
        changes = []

        def set_bs(value):
            changes.append(value)
            if value:
                raise ConnectionError("authored applied then failed")

        target = LegacyTarget(
            b"\x01\0", NativeProgrammingChannel(lambda e, p: b"", "x")
        )
        with self.assertRaises(ConnectionError):
            legacy_get_cids("TCUWP5CanCIDGetterWithSetBS.dll", [target], set_bs=set_bs)
        self.assertEqual(changes, [1, 0])
        changes.clear()
        result = legacy_prepare(
            "TCUWP4CanAirbagPrepareWriter.dll",
            [LegacyTarget(b"\x01\0", VendorDiagnosticChannel(lambda e, p: b"", "x"))],
            LegacyPrepareContext(
                b"\x01",
                "1",
                {"CANCommunicationSpeedAddress": "0"},
                security_access_password=bytes(2),
            ),
            lambda name, seed: bytes(len(seed)),
            raw_write=lambda a, p, r: 1,
            set_bs=set_bs,
        )
        self.assertEqual(changes, [1, 0])
        self.assertEqual(result["state"], "failed")

    def test_optional_p5_data_failures_retain_cids_and_build12_omits_queries(self):
        for build in (12, 18):
            calls = []

            def exchange(ecu, payload, calls=calls):
                calls.append(payload)
                if payload == b"\x22\xf1\x81":
                    return b"\x62\xf1\x81\x01" + b"CID" + bytes(13)
                return b"\x7f" + payload[:1] + b"\x31"

            result = legacy_get_cids(
                "TCUWP5CanCIDGetter.dll",
                [LegacyTarget(b"\x01\0", NativeProgrammingChannel(exchange, "x"))],
                query_kind=2,
                native_build=build,
            )
            self.assertEqual(result["cids"], ["CID"])
            self.assertEqual(len(result["optional_errors"]), 4 if build == 18 else 0)
            self.assertEqual(len(calls), 5 if build == 18 else 1)
            self.assertEqual(result["skipped_timeout_targets"], [])

    def test_timeout_snapshot_restore_including_uncertain_setup(self):
        cpu = LegacyCPU(
            bytes(1024),
            bytes(8),
            1,
            {"BlockSizeInfo": "0:1x1", "CPUIDNo": "1", "ShrinkFlag": "1"},
            id_big_endian=False,
        )
        replay = RawReplay()
        channel = replay.channel()
        changes = []

        def configure(value, remaining):
            changes.append(value)
            if value == 0:
                raise ConnectionError("applied")

        result = legacy_write(
            "TCUWP4CanBodyFlashWriter.dll",
            channel,
            cpu,
            finish_channel=channel,
            get_timeout=lambda: 777,
            set_timeout=configure,
        )
        self.assertEqual(changes, [0, 777])
        self.assertEqual(replay.writes, [])
        self.assertEqual(result["state"], "failed")
        replay = RawReplay()
        channel = replay.channel()
        result = legacy_write(
            "TCUWP4CanBodyFlashWriter.dll",
            channel,
            cpu,
            finish_channel=channel,
            get_timeout=lambda: 321,
            set_timeout=replay.set_timeout,
        )
        self.assertEqual(result["state"], "complete")
        self.assertEqual(replay.timeouts, [0, 321])

    def test_pre_ack_progress_and_build_specific_vforest_failure_reset(self):
        for build in (12, 18):
            image = b"ZV\0\x03\xfb" + bytes(1019)
            replay = RawReplay()
            events = []
            fail = [False]

            def progress(kind, value, events=events, fail=fail):
                events.append((kind, value))
                if kind == "count" and value:
                    fail[0] = True

            channel = replay.channel(cancelled=lambda fail=fail: fail[0])
            result = legacy_write(
                "TCUWP4CanVFORESTFlashWriter.dll",
                channel,
                LegacyCPU(image, bytes(8), 1, {"CPUIDNo": "1", "ShrinkFlag": "1"}),
                finish_channel=channel,
                native_build=build,
                progress=progress,
            )
            self.assertEqual(result["state"], "recovery_required")
            self.assertEqual(result["transferred_bytes"], 0)
            self.assertEqual(events[:1], [("count", 1024)])
            self.assertEqual(
                events[1:], [("count", 0), ("percent", 0)] if build == 18 else []
            )
            self.assertEqual(result["progress_count"], 0)

    def test_nonverify_writes_full_image_and_keeps_inverify(self):
        replay = RawReplay()
        channel = replay.channel()
        result = legacy_write(
            "TCUWP4CanBodyFlashWriter.dll",
            channel,
            LegacyCPU(
                bytes(1024),
                bytes(8),
                1,
                {
                    "BlockSizeInfo": "0:1x1",
                    "CPUIDNo": "1",
                    "ShrinkFlag": "1",
                    "FlagToNonVerifyProcess": "1",
                },
                id_big_endian=False,
            ),
            finish_channel=channel,
            get_timeout=lambda: 321,
            set_timeout=replay.set_timeout,
        )
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["progress_count"], 1024)
        self.assertEqual(result["progress_percent"], 100)
        self.assertIn(b"\x48\0\0\0\0", replay.writes)
        self.assertNotIn(b"\x16\0\0\0\0", replay.writes)

    def test_all_native_finish_probes_and_static_identity_rejection(self):
        for module in (
            "TCUWP4CanAirbagFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
        ):
            writes = []
            channel = VendorCAN(
                lambda p, r, writes=writes: writes.append(p) or 1,
                lambda r: b"arbitrary",
            )
            self.assertTrue(legacy_is_finished(module, channel))
            self.assertEqual(writes, [b"\x3e"])
        with self.assertRaises(ValueError):
            legacy_module_profile("TCUWP4CanBodyFlashWriter.dll", "0" * 64)
        with self.assertRaises(InterruptedError):
            legacy_is_finished(
                "TCUWP4CanAirbagFlashWriter.dll",
                VendorCAN(lambda p, r: 1, lambda r: b"x", cancelled=lambda: True),
            )

    def test_native_block_layout_and_s0_bounds(self):
        info = parse_block_info("0:1x2,4:2x1")
        self.assertEqual(info, (BlockInfo(0, 1, 2), BlockInfo(4, 2, 1)))
        self.assertEqual(block_sizes(info), (1024, 1024, 2048, 2048, 2048))
        self.assertEqual(block_ranges(info, grouped=True), ((1, 2), (5, 5)))
        completed = complete_block_info(parse_block_info("0:0x0"), 0x1000, 0x1FFF, 1)
        self.assertEqual(completed, (BlockInfo(0, 1, 4),))
        s0 = b"x" + bytes.fromhex("aa55aa550000000100010002")
        self.assertEqual(block_ranges(completed, s0_header=s0), ((2, 2), (3, 3)))
        image = bytes(range(256)) * 16
        plan = legacy_blocks(image, block_sizes(completed), ((1, 2), (3, 4)), 0x1000)
        self.assertEqual(
            [
                (block.first, block.last, block.address, len(block.data))
                for block in plan
            ],
            [(1, 2, 0x1000, 2048), (3, 4, 0x1800, 2048)],
        )
        for damaged in (s0[:-1], bytes.fromhex("aa55aa55")):
            with self.assertRaises(ValueError):
                block_ranges(completed, s0_header=damaged)
        for damaged in ("", "0:1", "0:-1x2", "1:1x2,0:1x1"):
            with self.assertRaises(ValueError):
                block_sizes(parse_block_info(damaged))
        with self.assertRaises(ValueError):
            legacy_blocks(bytes(1024), (1024, 1024), ((1, 2),), 0)
        with self.assertRaises(ValueError):
            legacy_blocks(bytes(2048), (1024, 1024), ((1, 1), (1, 2)), 0)

    def test_native_cid_framing_and_string_semantics(self):
        rows = b"CAL-A\0" + bytes(10) + bytes(16) + b"\xff" * 16
        for p5, prefix in ((True, b"\x62\xf1\x81\x03"), (False, b"\x49\x04\x03")):
            raw = prefix + rows
            self.assertEqual(decode_legacy_cids(raw, p5=p5), ("CAL-A", "ÿ" * 16))
            for damaged in (
                raw[:-1],
                raw + b"x",
                prefix[:-1] + b"\x02" + rows,
                prefix[:-1] + b"\0",
            ):
                with self.assertRaises(ValueError):
                    decode_legacy_cids(damaged, p5=p5)

    def test_vforest_native_grouped_transfer_and_bounds(self):
        first = b"ZV\x00\x04\x00" + bytes(1024)
        second = b"ZV\x01\x00\x01" + b"XY" + b"z"
        image = first + second
        self.assertEqual(vforest_groups(image), (first, second))
        for damaged in (b"", b"ZV\0\0", b"BAD\0\0", image[:-1]):
            with self.assertRaises(ValueError):
                vforest_groups(damaged)
        for verify in (False, True):
            writes = []
            responses = iter((b"\x3c",) + (b"\x3c", b"\x3c", b"\0", b"\x3c") * 3)
            channel = VendorCAN(
                lambda payload, remaining, writes=writes: writes.append(payload) or 1,
                lambda remaining, responses=responses: next(responses),
            )
            vforest_transfer(channel, image, verify=verify)
            self.assertEqual(
                writes,
                [
                    bytes((0x17 if verify else 0x42, 0, 0, 0, 1, 255)),
                    first[:1024],
                    b"\x50",
                    first[1024:],
                    b"\x50",
                    second,
                    b"\x50",
                ],
            )
            self.assertEqual(channel.transferred, 0 if verify else len(image))

    def test_native_security_widths_and_magic(self):
        for request, seed, suffix in (
            (b"\x27\x03\xaa\xbb", b"\x01\x02", b"\x34"),
            (b"\x27\x61", bytes(range(6)), b""),
            (b"\x27\x01\x02", bytes(range(4)), b""),
            (b"\x27\x03" + bytes(16), bytes(range(16)), b"\x34"),
        ):
            calls, waits = [], []

            def exchange(
                ecu, payload, calls=calls, request=request, seed=seed, suffix=suffix
            ):
                calls.append(payload)
                if len(calls) == 1:
                    return bytes((0x67, request[1])) + seed + suffix
                return bytes((0x67, request[1] + 1)) + b"\x34"

            channel = NativeProgrammingChannel(exchange, "authored")
            legacy_security(
                channel,
                request,
                len(seed),
                lambda value: value[::-1],
                seed_suffix=suffix,
                key_suffix=b"\x34",
                wait_ms=5,
                wait=waits.append,
            )
            self.assertEqual(
                calls, [request, bytes((0x27, request[1] + 1)) + seed[::-1]]
            )
            self.assertEqual(waits, [5])

    def test_security_malformed_and_cancel_do_not_send_key(self):
        calls = []
        channel = NativeProgrammingChannel(
            lambda ecu, data: calls.append(data) or b"\x67\x03\x01\x02\x35", "authored"
        )
        with self.assertRaises(ValueError):
            legacy_security(
                channel, b"\x27\x03\xaa\xbb", 2, lambda seed: seed, seed_suffix=b"\x34"
            )
        self.assertEqual(len(calls), 1)
        for key in (b"", bytearray(2), b"123"):
            channel = NativeProgrammingChannel(
                lambda ecu, data: b"\x67\x03\x01\x02\x34", "authored"
            )
            with self.assertRaises(ValueError):
                legacy_security(
                    channel,
                    b"\x27\x03\xaa\xbb",
                    2,
                    lambda seed, key=key: cast(bytes, key),
                )
        channel = NativeProgrammingChannel(
            lambda ecu, data: b"\x67\x61" + bytes(6), "authored", cancelled=lambda: True
        )
        with self.assertRaises(InterruptedError):
            legacy_security(channel, b"\x27\x61", 6, lambda seed: seed)

    def test_cxpi_native_erase_order_and_status(self):
        events = []
        responses = iter(
            (b"\x3c", b"\x3c", b"\x20", b"\x3c", b"\x3c", b"\x00", b"\x3c")
        )
        channel = VendorCAN(
            lambda payload, remaining: events.append(("write", payload)) or 1,
            lambda remaining: next(responses),
            wait=lambda ms, remaining: events.append(("wait", ms)),
        )
        cxpi_erase(
            channel,
            1,
            258,
            lambda: events.append(("tester", b"\x3e\x02")),
            wait_before_status_ms=7,
        )
        self.assertEqual(
            events[:8],
            [
                ("write", b"\x26\x00\x00\x01\x01"),
                ("wait", 2000),
                ("tester", b"\x3e\x02"),
                ("wait", 2000),
                ("tester", b"\x3e\x02"),
                ("wait", 2000),
                ("tester", b"\x3e\x02"),
                ("wait", 2000),
            ],
        )
        self.assertEqual(
            events[8:],
            [("wait", 7), ("write", b"\x50"), ("wait", 7), ("write", b"\x50")],
        )


if __name__ == "__main__":
    unittest.main()
