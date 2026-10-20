import itertools
import unittest
from dataclasses import replace
from unittest.mock import Mock, patch

from scripts.calibration import CalibrationRecord, NativeCPU, parse_cuw
from scripts.calibration_catalog import CalibrationCatalog, parse_parameter_table
from scripts.cuw_legacy_can import CommonCAN, ExecutableCANError
from scripts.cuw_legacy_channel import ChannelState, channel_state
from scripts.cuw_legacy_engine import (
    ExecutableContext,
    ExecutableForeignNativeError,
    ExecutableJ2534Error,
    ExecutableState,
    bind_context,
    select_executable_controller,
)
from scripts.cuw_legacy_vendor import (
    DCMController,
    DCMWire,
    EMPSController,
    EMPSWire,
    LegacyVendorResponseError,
    bind_emps_regions,
    bind_techvim_finalize,
    emps_accept_rxstatus,
    emps_download_request,
    emps_header_pairs,
    emps_percent,
    emps_routine_request,
    emps_transfer_request,
    emps_validate_response,
    prepare_emps,
    select_emps_session,
    techvim_needs_finalize,
)
from scripts.demo_calibration import table
from scripts.j2534_2026 import NativeMessage
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import NativeRuntime2026
from scripts.programming_legacy import (
    NativeCPUContext,
    bind_native_cpu_context,
    materialize_legacy_image,
)
from tests.test_calibration import metadata_container


def authored_emps_context(
    source: bytes = b"",
    build: int = 18,
    *,
    shared_bind: bool = False,
    cpu_index: int = 0,
    cpu_count: int = 1,
    kind: str = "13",
    cpu_type: str = "56",
    channel: ChannelState | None = None,
    main_srec: bytes | None = None,
    include_loader: bool = True,
    parameters: dict[str, str] | None = None,
) -> ExecutableContext:
    metadata = (
        "[Format]\nVersion=6\n[Vehicle]\nNumberOfCalibration=1\n"
        "KindOfECU=13\nContactType=CAN\n[CPU01]\nCPUType=56\n"
        "CPUImageName=main.srec\nFlashCodeName=loader.srec\n"
    )
    srec = main_srec if main_srec is not None else b"S1051000414267\nS9031000EC\n"
    records = [(b"main", srec), (b"loader", srec)]
    if cpu_count == 2:
        metadata = metadata.replace("NumberOfCalibration=1", "NumberOfCalibration=2")
        metadata += (
            "[CPU02]\nCPUType=56\nCPUImageName=main2.srec\nFlashCodeName=loader2.srec\n"
        )
        records = [
            (b"main", srec),
            (b"main2", b"S1051000434463\nS9031000EC\n"),
            (b"loader", srec),
            (b"loader2", b"S105100045465F\nS9031000EC\n"),
        ]
    if not include_loader:
        metadata = metadata.replace("FlashCodeName=loader.srec\n", "").replace(
            "FlashCodeName=loader2.srec\n", ""
        )
        records = [row for row in records if not row[0].startswith(b"loader")]
    metadata = metadata.replace("KindOfECU=13", f"KindOfECU={kind}").replace(
        "CPUType=56", f"CPUType={cpu_type}"
    )
    cuw = parse_cuw(metadata_container(metadata, records, cpu_count))
    catalog = CalibrationCatalog(
        [
            parse_parameter_table(
                f"{kind}CAN{cpu_type}.ini",
                table(
                    ("ParamFileKeySystemProtocolMicon", *(parameters or {})),
                    [(f"{kind}CAN{cpu_type}", *(parameters or {}).values())],
                ),
                encoded=False,
            ),
        ]
    )
    selected = catalog.select_metadata(kind, cpu_type, "CAN", stage="write")
    if shared_bind:
        return bind_context(
            cuw,
            1,
            (),
            selected,
            build=build,
            cpu_index=cpu_index,
            attachments={"legacy_executable": source},
            observations={
                "legacy_channel_state": channel
                or ChannelState(
                    protocol=6, read_timeout=1000, send_timeout=1000, padding=True
                ),
                "protocol_id": 6,
                "observed_cids": (),
                "channel_padding": True,
            },
        )
    contexts = tuple(
        bind_native_cpu_context(cuw, 1, (), selected, stage="write", cpu_index=index)
        for index in range(cpu_count)
    )
    native = contexts[cpu_index]
    metadata = native.base_metadata
    controller = select_executable_controller(
        metadata["contact_type"],
        metadata["kind_of_ecu"],
        metadata["cpu_type"],
        native.selected.values["cputype"],
    )
    return ExecutableContext(
        build,
        controller,
        native,
        contexts,
        cuw.digest,
        state=ExecutableState(write_cpu_index=cpu_index),
        attachments={"legacy_executable": source},
        observations={
            "protocol_id": 6,
            "legacy_channel_state": channel
            or ChannelState(protocol=6, read_timeout=1000, send_timeout=1000),
        },
        constructor_read_timeout=1000,
    )


class ExecutableVendorPrimitiveTests(unittest.TestCase):
    def test_emps_session_and_common_helpers_share_authoritative_channel_ram(self):
        state = ChannelState(
            protocol=6, read_timeout=937, send_timeout=2468, padding=True
        )
        context = authored_emps_context(channel=state)
        trace, pending = [], []

        def action(op, _remaining):
            trace.append(op)
            if op["operation"].startswith("get_"):
                raise AssertionError(
                    "Bound native state must not query a second snapshot"
                )
            if op["operation"] == "write_messages":
                self.assertEqual((op["timeout_ms"], op["tx_flags"]), (2468, 0x40))
                pending.extend(
                    (
                        NativeMessage(6, b"0000", rx_status=2),
                        NativeMessage(6, b"1111\x50\x92"),
                    )
                )
                return 1
            if op["operation"] == "read_messages":
                return (pending.pop(0),)
            return None

        io = NativeRuntime2026(action)
        common = CommonCAN.from_io(io, b"0000", b"1111", state=state)
        common.set_timeout(5151)
        with patch(
            "scripts.cuw_legacy_vendor.emps_header_pairs",
            return_value=((b"0000", b"1111"),),
        ):
            wire = select_emps_session(
                context, io, channel_flag_67=False, read_timeout_ms=123
            )
        self.assertIs(wire.channel.state, state)
        self.assertEqual(
            [op["timeout_ms"] for op in trace if op["operation"] == "read_messages"][
                -1
            ],
            5151,
        )
        self.assertEqual(
            (common.timeout_ms, wire.read_timeout_ms, state.read_timeout),
            (1000, 1000, 1000),
        )
        common.set_timeout(2222)
        self.assertEqual(wire.read_timeout_ms, 2222)
        state.padding = False
        self.assertFalse(wire.channel_flag_67)

    def test_dcm_scalar_percentage_retains_native_low_dword(self):
        image = authored_emps_context().native.image
        assert image is not None
        controller = DCMController.__new__(DCMController)
        values = []
        controller.io = NativeRuntime2026(
            lambda op, _remaining: values.append((op["field"], op["value"]))
        )
        controller.main = replace(image, flash_size=1)
        controller.countdown_b8 = 15000
        controller.written_a4 = 0x07FFFFFE
        controller.transferred(1)
        self.assertEqual(
            values, [("writing_bytes", 0x08000000), ("writing_percent", 0x90000000)]
        )

    def test_dcm_region_uses_offset_chunks_acknowledged_progress_wrap_and_checksum(
        self,
    ):
        for length in (0, 1, 60, 61, 1024, 15361):
            operations, pending, payloads, progress = [], [], [], []
            data = b"prefix" + bytes(index & 255 for index in range(length)) + b"tail"

            def action(
                op,
                _remaining,
                operations=operations,
                pending=pending,
                payloads=payloads,
            ):
                operations.append(op)
                if op["operation"] == "write_messages":
                    body = op["data"][5:]
                    payloads.append(body)
                    pending.append(NativeMessage(6, b"0000", rx_status=2))
                    reply = {0x34: b"\x74\x30\0\0\0", 0x36: b"\x76\xee", 0x37: b"\x77"}[
                        body[0]
                    ]
                    pending.append(NativeMessage(6, b"1111y" + reply))
                    return 1
                if op["operation"] == "read_messages":
                    return (pending.pop(0),)
                return None

            context = replace(
                authored_emps_context(), controller="CCanDCMPRLFlashWriter"
            )
            with patch(
                "scripts.cuw_legacy_vendor.legacy_executable_bytes", return_value=b""
            ):
                wire = DCMWire(
                    context,
                    CommonCAN(
                        NativeRuntime2026(action),
                        b"0000x",
                        b"1111y",
                        padding=False,
                        read_timeout_ms=1000,
                    ),
                )
                wire.write_region(data, 6, length, transferred=progress.append)
            self.assertEqual(
                payloads[0], b"\x34\0\x33\0\0\x06" + length.to_bytes(3, "big")
            )
            self.assertEqual(
                b"".join(body[2:] for body in payloads[1:-1]), data[6 : 6 + length]
            )
            self.assertEqual(
                [body[1] for body in payloads[1:-1]],
                [(index + 1) & 255 for index in range((length + 59) // 60)],
            )
            self.assertEqual(progress, [len(body) - 2 for body in payloads[1:-1]])
            self.assertEqual(
                payloads[-1],
                b"\x37" + (sum(data[6 : 6 + length]) & 65535).to_bytes(2, "big"),
            )
            self.assertFalse(pending)
            before = len(operations)
            with self.assertRaises(ValueError):
                wire.write_region(data, 6, len(data), transferred=progress.append)
            self.assertEqual(len(operations), before)

    def test_dcm_execute_imported_multicpu_block_vector_and_phase_failures(self):
        from scripts.cuw_legacy_addresses import (
            AddressConfig,
            AddressFactoryState,
            CAddress,
        )

        for fault in (
            None,
            "security",
            "transfer",
            "cancel",
            "foreign",
            "host",
            "over100",
            "late_timeout",
        ):
            context = replace(
                authored_emps_context(
                    cpu_count=2,
                    cpu_index=1,
                    kind="8",
                    cpu_type="65",
                    channel=ChannelState(
                        protocol=6, read_timeout=937, send_timeout=937
                    ),
                ),
                cpu_types=("65", "65"),
            )
            if fault == "over100":
                assert context.native.image is not None
                native = replace(
                    context.native, image=replace(context.native.image, flash_size=1)
                )
                context = replace(
                    context, native=native, cpus=(context.cpus[0], native)
                )
            trace, pending, payloads = [], [], []

            def action(
                op,
                _remaining,
                trace=trace,
                pending=pending,
                payloads=payloads,
                fault=fault,
            ):
                trace.append(op)
                name = op["operation"]
                if name == "get_channel_padding":
                    return False
                if name in ("get_timeout", "get_send_timeout"):
                    return 937
                if name == "start_filter":
                    return 42
                if name == "write_messages":
                    body = op["data"][5:]
                    payloads.append(body)
                    if fault == "foreign" and body[:1] == b"\x36":
                        raise ExecutableForeignNativeError("explicit native identity")
                    if fault == "host" and body[:1] == b"\x36":
                        raise ValueError("explicit host validation")
                    if (fault == "security" and body == b"\x27\x01") or (
                        fault == "transfer" and body[:1] == b"\x36"
                    ):
                        raise NativeTransportError(9)
                    if fault == "cancel" and body[:1] == b"\x36":
                        raise InterruptedError("host abort")
                    pending.append(NativeMessage(6, b"\0\0\x07\xe0", rx_status=2))
                    reply = {
                        0x27: b"\x67\x01\0" if body[1] == 1 else b"\x67\x02",
                        0x31: b"\x71" + body[1:],
                        0x34: b"\x74\x30\0\0\0",
                        0x36: b"\x76\0",
                        0x37: b"\x77",
                        0x11: b"\x51\x01",
                    }[body[0]]
                    pending.append(NativeMessage(6, b"\0\0\x07\xe8y" + reply))
                    return 1
                if name == "read_messages":
                    return (pending.pop(0),)
                if name == "controller_callback" and op["callback"] == "read_flag_88":
                    return False
                return None

            with (
                patch(
                    "scripts.cuw_legacy_addresses.legacy_address_inputs",
                    return_value=("8", AddressConfig(()), False, AddressFactoryState()),
                ),
                patch(
                    "scripts.cuw_legacy_addresses.select_legacy_addresses",
                    return_value=(CAddress(b"\x2f\x07\xe0x\x07\xe8y\x01"),),
                ),
                patch("scripts.cuw_legacy_vendor._vendor_resource", side_effect=("8",)),
                patch("scripts.cuw_legacy_vendor.ExecutableImage") as image,
                patch(
                    "scripts.cuw_legacy_vendor.legacy_executable_bytes",
                    return_value=b"",
                ),
            ):
                image.return_value.read.side_effect = lambda address, width: bytes(
                    width
                )
                controller = DCMController(context, NativeRuntime2026(action))
                if fault == "late_timeout":
                    channel_state(context).read_timeout = 2746
                if fault == "host":
                    with self.assertRaisesRegex(ValueError, "explicit host validation"):
                        controller.run()
                    self.assertFalse(
                        any(op.get("callback") == "completion" for op in trace)
                    )
                    continue
                if fault == "cancel":
                    with self.assertRaises(InterruptedError):
                        controller.run()
                    self.assertFalse(
                        any(op.get("callback") == "completion" for op in trace)
                    )
                    self.assertEqual(trace[-1]["operation"], "stop_filter")
                    self.assertEqual(trace[-1]["filter_id"], 42)
                    continue
                result = controller.run()
            self.assertEqual(
                result["native_success"], fault in (None, "over100", "late_timeout")
            )
            self.assertEqual(
                result["native_value_80"], 9 if fault in ("security", "transfer") else 0
            )
            self.assertEqual(
                [
                    op["milliseconds"]
                    for op in trace
                    if op["operation"] == "set_timeout"
                ][-1],
                2746 if fault == "late_timeout" else 937,
            )
            if fault in (None, "over100", "late_timeout"):
                self.assertIn(b"\x36\x01CD", payloads)
                self.assertEqual(
                    [
                        op["value"]
                        for op in trace
                        if op.get("field") == "writing_percent"
                    ],
                    [200 if fault == "over100" else 100],
                )
                self.assertEqual(
                    [
                        op["value"]
                        for op in trace
                        if op.get("field") == "waiting_milliseconds"
                    ],
                    [0, 15000] + list(range(14500, -1, -500)),
                )
            if fault == "security":
                self.assertFalse(any(body[0] == 0x34 for body in payloads))
                self.assertEqual(result["native_value_78"], 16)
            if fault == "transfer":
                self.assertEqual(result["native_value_78"], 27)
                self.assertFalse(
                    any(op.get("field") == "writing_bytes" for op in trace)
                )

    def test_dcm_typed_faults_keep_caller_category_and_driver_dword(self):
        cases = (
            (lambda wire: wire.security(), 16),
            (lambda wire: wire.reset(), 24),
            (lambda wire: wire.routine(0x0200, 1), 25),
            (lambda wire: wire.download(0, 1024), 26),
            (lambda wire: wire.transfer(b"x", 0), 27),
            (lambda wire: wire.exit(1), 28),
        )
        for (invoke, category), point in itertools.product(
            cases, ("write_messages", "read_messages")
        ):
            operations = []

            def action(operation, _remaining, point=point, operations=operations):
                operations.append(operation)
                if operation["operation"] == point:
                    raise NativeTransportError(0xDEADBEEF)
                return 1 if operation["operation"] == "write_messages" else None

            context = replace(
                authored_emps_context(), controller="CCanDCMPRLFlashWriter"
            )
            with patch(
                "scripts.cuw_legacy_vendor.legacy_executable_bytes", return_value=b""
            ):
                wire = DCMWire(
                    context,
                    CommonCAN(
                        NativeRuntime2026(action),
                        b"0000x",
                        b"1111y",
                        padding=False,
                        read_timeout_ms=1000,
                    ),
                )
                with self.assertRaises(ExecutableJ2534Error) as caught:
                    invoke(wire)
            self.assertEqual(
                (
                    caught.exception.native_code,
                    caught.exception.driver_status,
                    caught.exception.code,
                ),
                (category, 0xDEADBEEF, 0xDEADBEEF),
            )
            self.assertEqual(
                sum(op["operation"] == "write_messages" for op in operations), 1
            )

    def test_dcm_native_helpers_use_extended_headers_and_source_seed_operands(self):
        for build in (12, 18):
            operations, pending, payloads = [], [], []

            def action(
                operation,
                _remaining,
                operations=operations,
                pending=pending,
                payloads=payloads,
            ):
                operations.append(operation)
                if operation["operation"] == "write_messages":
                    frame = operation["data"]
                    body = frame[5:]
                    payloads.append(body)
                    pending.append(NativeMessage(6, frame[:4], rx_status=2))
                    if body == b"\x27\x01":
                        reply = b"\x67\x01\x12"
                    elif body[0] == 0x27:
                        reply = b"\x67\x02"
                    elif body[0] == 0x11:
                        reply = b"\x51\x01"
                    elif body[0] == 0x31:
                        reply = b"\x71" + body[1:]
                    elif body[0] == 0x34:
                        reply = b"\x74\x30\0\0\0"
                    elif body[0] == 0x36:
                        reply = b"\x76\xee"
                    else:
                        reply = b"\x77"
                    pending.append(NativeMessage(6, b"1111y" + reply))
                    return 1
                if operation["operation"] == "read_messages":
                    return (pending.pop(0),)
                return None

            context = replace(
                authored_emps_context(build=build), controller="CCanDCMPRLFlashWriter"
            )
            with (
                patch(
                    "scripts.cuw_legacy_vendor.legacy_executable_bytes",
                    return_value=b"",
                ),
                patch("scripts.cuw_legacy_vendor.ExecutableImage") as image,
            ):
                image.return_value.read.side_effect = (b"\x01", b"\x02")
                wire = DCMWire(
                    context,
                    CommonCAN(
                        NativeRuntime2026(action),
                        b"0000x",
                        b"1111y",
                        padding=False,
                        read_timeout_ms=1000,
                    ),
                )
                wire.security()
                wire.reset()
                wire.routine(0x0201, 1)
                wire.routine(0x0201, 2)
                wire.download(0x12345678, 0x01020304)
                wire.transfer(b"ab", 255)
                wire.exit(0xFFFF)
            self.assertEqual(
                payloads,
                [
                    b"\x27\x01",
                    b"\x27\x02\x01\x14",
                    b"\x11\x01",
                    b"\x31\x01\x02\x01",
                    b"\x31\x02\x02\x01\x01",
                    b"\x34\0\x33\x34\x56\x78\x02\x03\x04",
                    b"\x36\0ab",
                    b"\x37\xff\xff",
                ],
            )
            self.assertEqual(
                [op["milliseconds"] for op in operations if op["operation"] == "wait"],
                [100] * 16,
            )
            self.assertTrue(
                all(
                    op["tx_flags"] == 0x80
                    for op in operations
                    if op["operation"] == "write_messages"
                )
            )

    def test_multicpu_emps_uses_unindexed_first_work_record(self):
        context = authored_emps_context(cpu_index=1, cpu_count=2)
        self.assertEqual(context.native.selected.index, 1)
        self.assertEqual(len(context.native.cpus), 2)
        with patch(
            "scripts.cuw_legacy_vendor.legacy_executable_bytes", return_value=b""
        ):
            self.assertEqual(bind_emps_regions(context), (b"AB", b"AB"))

    def test_progress_uses_native_extended_precision_before_truncation(self):
        self.assertEqual(int(13920 / 48000 * 100), 28)
        self.assertEqual(emps_percent(13920, 48000), 29)
        for position, total, expected in (
            (0, 1, 0),
            (1, 1, 100),
            (240, 720, 33),
            (480, 720, 66),
            (240, 1000, 24),
        ):
            self.assertEqual(emps_percent(position, total), expected)
        for position, total in ((0, 0), (2, 1), (-1, 1), (True, 1)):
            with self.assertRaises(ValueError):
                emps_percent(position, total)

    def test_error_prompt_reconnect_retry_publishes_updated_native_fields(self):
        callbacks = []
        controller = object.__new__(EMPSController)
        controller.context = authored_emps_context()
        controller.flag_68 = False
        controller.status_70 = 1
        controller.value_78, controller.value_80 = 16, 7
        answers = iter((True, False))

        def action(operation, _remaining):
            callbacks.append(operation)
            return next(answers) if operation["callback"] == "read_flag_88" else None

        controller.io = NativeRuntime2026(action)
        with (
            patch.object(controller, "status", return_value=3),
            patch(
                "scripts.cuw_legacy_vendor.executable_reconnect",
                side_effect=ExecutableJ2534Error(-128, 99),
            ) as reconnect,
        ):
            controller.error_handler()
        reconnect.assert_called_once_with(controller.context, controller.io, 6)
        self.assertTrue(controller.flag_68)
        self.assertEqual(
            [op["callback"] for op in callbacks],
            [
                "value_70",
                "values_78_80",
                "flag_88",
                "error_handler",
                "read_flag_88",
                "value_70",
                "values_78_80",
                "flag_88",
                "error_handler",
                "read_flag_88",
            ],
        )
        self.assertEqual(
            [
                (op["value_78"], op["value_80"])
                for op in callbacks
                if op["callback"] == "values_78_80"
            ],
            [(16, 7), (0xFFFFFF80, 99)],
        )

    def test_execute_native_phases_callbacks_and_separate_host_cleanup(self):
        for build, fault in itertools.product(
            (12, 18),
            (
                "success",
                "config",
                "filter2",
                "seed",
                "main",
                "reset",
                "stop1",
                "cancel",
                "cancel_restore_fault",
                "host_cancelled",
                "shape",
                "native_cpass_read",
            ),
        ):
            operations, pending = [], []
            state = {
                "filters": 0,
                "stage": 0,
                "stopped": False,
                "seed": False,
                "cancelled": False,
            }

            def action(
                operation,
                _remaining,
                operations=operations,
                pending=pending,
                state=state,
                fault=fault,
            ):
                operations.append(operation)
                name = operation["operation"]
                if name == "get_channel_padding":
                    return False
                if name in ("get_timeout", "get_send_timeout"):
                    return 2468
                if (
                    name == "set_timeout"
                    and operation["milliseconds"] == 2468
                    and fault == "cancel_restore_fault"
                ):
                    raise RuntimeError("authored restore fault")
                if name == "ioctl" and operation["ioctl_id"] == 2 and fault == "config":
                    raise NativeTransportError(7)
                if name == "start_filter":
                    state["filters"] += 1
                    if fault == "filter2" and state["filters"] == 2:
                        raise NativeTransportError(7)
                    return state["filters"]
                if name == "stop_filter" and fault == "stop1" and not state["stopped"]:
                    state["stopped"] = True
                    raise NativeTransportError(7)
                if name == "controller_callback":
                    return False if operation["callback"] == "read_flag_88" else None
                if name == "write_messages":
                    data = operation["data"]
                    body = data[4:]
                    state["seed"] = body == b"\x27\x01"
                    if fault == "host_cancelled" and state["seed"]:
                        state["cancelled"] = True
                    if body[:1] == b"\x31":
                        state["stage"] = body[1]
                    target = (
                        (fault == "seed" and body == b"\x27\x01")
                        or (fault == "main" and body[0] == 0x36 and state["stage"] == 2)
                        or (fault == "reset" and body[0] == 0x11)
                    )
                    if target:
                        raise NativeTransportError(7)
                    if (
                        fault in ("cancel", "cancel_restore_fault")
                        and body == b"\x27\x01"
                    ):
                        raise InterruptedError("authored cancellation")
                    pending.append(NativeMessage(6, data[:4], rx_status=2))
                    if body == b"xy":
                        return 1
                    reply = (
                        b"\x50\x92"
                        if body[0] == 0x10
                        else b"\x67\x01\0\0"
                        if body == b"\x27\x01"
                        else b"\x67\x02"
                        if body[0] == 0x27
                        else bytes((0x71, body[1]))
                        if body[0] == 0x31
                        else b"\x74\0\xf1"
                        if body[0] == 0x34
                        else bytes((body[0] + 0x40,))
                    )
                    if fault == "shape" and body == b"\x27\x01":
                        reply = b"\x67\x01"
                    pending.append(NativeMessage(6, b"1111" + reply))
                    return 1
                if name == "read_messages":
                    if (
                        fault == "native_cpass_read"
                        and state["seed"]
                        and pending[0].rx_status == 0
                    ):
                        raise ExecutableCANError(9)
                    return (pending.pop(0),)
                return None

            base = {12: 0x52EDDD, 18: 0x577BED}[build]
            status_base = {12: 0x59A7F0, 18: 0x5F1A48}[build]
            memory = {
                base + i * 4 + 3: bytes((value,)) for i, value in enumerate(b"ABCDxy")
            }
            memory.update(
                {status_base + i * 4: i.to_bytes(4, "little") for i in range(4)}
            )
            with (
                patch(
                    "scripts.cuw_legacy_vendor.legacy_executable_bytes",
                    return_value=b"",
                ),
                patch(
                    "scripts.cuw_legacy_vendor.emps_header_pairs",
                    return_value=((b"0000", b"1111"), (b"2222", b"3333")),
                ),
                patch("scripts.cuw_legacy_vendor.ExecutableImage") as image,
            ):
                image.return_value.read.side_effect = (
                    lambda address, size, memory=memory: memory.get(address, b"x")
                )
                controller = EMPSController(
                    authored_emps_context(
                        build=build,
                        channel=ChannelState(
                            protocol=6, read_timeout=2468, send_timeout=2468
                        ),
                    ),
                    NativeRuntime2026(
                        action, cancelled=lambda state=state: bool(state["cancelled"])
                    ),
                )
                if fault in (
                    "config",
                    "cancel",
                    "cancel_restore_fault",
                    "host_cancelled",
                ):
                    with self.assertRaises(
                        ExecutableJ2534Error if fault == "config" else InterruptedError
                    ) as caught:
                        controller.run()
                    if fault in ("cancel", "cancel_restore_fault", "host_cancelled"):
                        self.assertEqual(
                            [
                                op["milliseconds"]
                                for op in operations
                                if op["operation"] == "set_timeout"
                            ][-1],
                            2468,
                        )
                    if fault == "cancel_restore_fault":
                        self.assertIn(
                            "Host abort timeout restoration failed: RuntimeError",
                            caught.exception.__notes__,
                        )
                    self.assertFalse(
                        any(op.get("callback") == "completion" for op in operations)
                    )
                else:
                    result = controller.run()
                    self.assertEqual(
                        [
                            op["milliseconds"]
                            for op in operations
                            if op["operation"] == "set_timeout"
                        ][-1],
                        1000,
                    )
                    self.assertEqual(
                        result["native_success"], fault in ("success", "stop1")
                    )
                    self.assertEqual(result["host_cleanup_errors"], [])
                    categories = {
                        "success": 0,
                        "stop1": 0,
                        "filter2": 1,
                        "seed": 16,
                        "main": 34,
                        "reset": 24,
                        "shape": 16,
                        "native_cpass_read": 9,
                    }
                    self.assertEqual(
                        (result["native_value_78"], result["native_value_80"]),
                        (
                            categories[fault],
                            0
                            if fault
                            in ("success", "stop1", "shape", "native_cpass_read")
                            else 7,
                        ),
                    )
                    self.assertEqual(
                        result["native_flag_68"], fault not in ("success", "stop1")
                    )
                    self.assertEqual(
                        [
                            op["outcome"]
                            for op in operations
                            if op.get("callback") == "completion"
                        ],
                        ["success" if result["native_success"] else "failure"],
                    )
                if fault == "stop1":
                    self.assertEqual(
                        [
                            op["filter_id"]
                            for op in operations
                            if op["operation"] == "stop_filter"
                        ],
                        [1, 2, 1],
                    )
                if fault in ("filter2", "seed", "shape", "native_cpass_read"):
                    self.assertFalse(
                        any(
                            op["operation"] == "write_messages"
                            and op["data"][4:6] == b"\x31\x02"
                            for op in operations
                        )
                    )

    def test_setup_orders_config_two_filters_and_three_native_startup_frames(self):
        pairs = ((b"0000", b"1111"), (b"2222", b"3333"))
        frame = b"ABCDxy"
        for build in (12, 18):
            operations, handles = [], []

            def action(operation, _remaining, operations=operations, handles=handles):
                operations.append(operation)
                name = operation["operation"]
                if name == "get_channel_padding":
                    return True
                if name in ("get_timeout", "get_send_timeout"):
                    return 4321
                if name == "start_filter":
                    handles.append(len(handles) + 10)
                    return handles[-1]
                if name == "write_messages":
                    return 1
                if name == "read_messages":
                    return (NativeMessage(protocol_id=6, data=frame[:4], rx_status=2),)
                return None

            base = {12: 0x52EDDD, 18: 0x577BED}[build]
            operands = {
                base + index * 4 + 3: bytes((value,))
                for index, value in enumerate(frame)
            }
            with (
                patch(
                    "scripts.cuw_legacy_vendor.emps_header_pairs", return_value=pairs
                ),
                patch("scripts.cuw_legacy_vendor.ExecutableImage") as image,
            ):
                image.return_value.read.side_effect = (
                    lambda address, size, operands=operands: operands[address]
                )
                io = NativeRuntime2026(action)
                self.assertEqual(
                    prepare_emps(
                        authored_emps_context(
                            build=build,
                            channel=ChannelState(
                                protocol=6,
                                read_timeout=4321,
                                send_timeout=4321,
                                padding=True,
                            ),
                        ),
                        io,
                    ),
                    (10, 11),
                )
                native = operations
                self.assertEqual(
                    [op["operation"] for op in native],
                    ["ioctl", "start_filter", "start_filter"]
                    + ["ioctl", "write_messages", "read_messages", "wait"] * 3,
                )
                self.assertEqual(
                    native[0]["input"], {"num_params": 1, "config": ((0x23, 2),)}
                )
                self.assertEqual(
                    [
                        op["pattern"].data
                        for op in native
                        if op["operation"] == "start_filter"
                    ],
                    [b"1111", b"3333"],
                )
                for op in native:
                    if op["operation"] == "write_messages":
                        self.assertEqual(
                            (op["data"], op["tx_flags"], op["timeout_ms"]),
                            (frame, 0x40, 4321),
                        )
                    if op["operation"] == "wait":
                        self.assertEqual(op["milliseconds"], 100)
                self.assertEqual(io.close(), [])
                self.assertEqual(
                    [
                        op["filter_id"]
                        for op in operations
                        if op["operation"] == "stop_filter"
                    ],
                    [11, 10],
                )

    def test_session_probe_retries_only_read_timeouts_and_bad_positive_shapes(self):
        pairs = ((b"0000", b"1111"), (b"2222", b"3333"))
        for fault, status, expected in (
            ("shape", 0, "second"),
            ("read", 9, "second"),
            ("read", 16, "second"),
            ("read", 7, "driver"),
            ("write", 9, "driver"),
            ("all_shapes", 0, "response"),
        ):
            writes, pending = [], []

            def action(
                operation,
                _remaining,
                writes=writes,
                pending=pending,
                fault=fault,
                status=status,
            ):
                if operation["operation"] in ("ioctl", "set_timeout"):
                    return None
                if operation["operation"] == "write_messages":
                    writes.append(operation["data"])
                    if fault == "write" and len(writes) == 1:
                        raise NativeTransportError(status)
                    pending.append(operation["data"])
                    return 1
                if pending:
                    return (NativeMessage(6, pending.pop(), rx_status=2),)
                if fault == "read" and len(writes) == 1:
                    raise NativeTransportError(status)
                header = b"1111" if len(writes) == 1 else b"3333"
                payload = (
                    b"bad" if len(writes) == 1 or fault == "all_shapes" else b"\x50\x92"
                )
                return (NativeMessage(6, header + payload),)

            with patch(
                "scripts.cuw_legacy_vendor.emps_header_pairs", return_value=pairs
            ):
                runtime = NativeRuntime2026(action)
                if expected == "second":
                    wire = select_emps_session(
                        authored_emps_context(),
                        runtime,
                        channel_flag_67=False,
                        read_timeout_ms=1000,
                    )
                    self.assertEqual(wire.request, b"2222")
                    self.assertEqual(writes, [b"0000\x10\x92\x02", b"2222\x10\x92\x02"])
                elif expected == "driver":
                    with self.assertRaises(ExecutableJ2534Error) as caught:
                        select_emps_session(
                            authored_emps_context(),
                            runtime,
                            channel_flag_67=False,
                            read_timeout_ms=1000,
                        )
                    self.assertEqual(caught.exception.native_code, 0x12)
                    self.assertEqual(caught.exception.driver_status, status)
                    self.assertEqual(len(writes), 1)
                else:
                    with self.assertRaises(LegacyVendorResponseError) as failed:
                        select_emps_session(
                            authored_emps_context(),
                            runtime,
                            channel_flag_67=False,
                            read_timeout_ms=1000,
                        )
                    self.assertEqual(failed.exception.code, 0x12)
                    self.assertEqual(len(writes), 2)

    def test_source_header_initializer_operands_are_decoded_as_big_endian_headers(self):
        for build in (12, 18):
            context = authored_emps_context(build=build)
            with patch("scripts.cuw_legacy_vendor.ExecutableImage") as image:
                image.return_value.read.side_effect = (
                    b"\x01",
                    b"\x02",
                    b"\x55\x44\x33\0",
                    b"\x66\x44\x33\0",
                )
                self.assertEqual(
                    emps_header_pairs(context),
                    (
                        (b"\0\0\0\x01", b"\0\0\0\x02"),
                        (b"\0\x33\x44\x55", b"\0\x33\x44\x66"),
                    ),
                )
                image.assert_called_once_with(context)
                self.assertEqual(
                    [call.args[1] for call in image.return_value.read.call_args_list],
                    [1, 1, 4, 4],
                )

    def test_native_transport_faults_retain_driver_status_and_helper_category(self):
        cases = (
            (0, b"\x31\x01", 0x25),
            (1, b"\x31\x02", 0x26),
            (0, b"\x34", 0x1A),
            (0, b"\x36", 0x22),
            (0, b"\x37", 0x24),
            (0, b"\x31\x03", 0x27),
            (None, b"\x27\x01", 0x10),
            (None, b"\x27\x02", 0x11),
            (2, b"\x11\x01", 0x18),
        )
        for (selector, target, category), point in itertools.product(
            cases, ("write", "read")
        ):
            writes, pending = [], []

            def action(
                operation,
                _remaining,
                writes=writes,
                pending=pending,
                target=target,
                point=point,
            ):
                if operation["operation"] in ("ioctl", "notification", "set_timeout"):
                    return None
                if operation["operation"] == "write_messages":
                    payload = operation["data"][4:]
                    writes.append(payload)
                    if point == "write" and payload.startswith(target):
                        raise NativeTransportError(0xDEADBEEF)
                    pending.append(operation["data"])
                    return 1
                if point == "read" and writes[-1].startswith(target):
                    raise NativeTransportError(0xDEADBEEF)
                if pending:
                    return (NativeMessage(6, pending.pop(), rx_status=2),)
                request = writes[-1]
                reply = (
                    (b"\x67\x01\0\0" if request[1] == 1 else b"\x67\x02")
                    if request[0] == 0x27
                    else bytes((0x71, request[1]))
                    if request[0] == 0x31
                    else b"\x74\0\xf1"
                    if request[0] == 0x34
                    else bytes((request[0] + 0x40,))
                )
                return (NativeMessage(6, b"1111" + reply),)

            wire = EMPSWire(
                NativeRuntime2026(action),
                b"0000",
                b"1111",
                channel_flag_67=False,
                read_timeout_ms=1000,
            )
            with self.assertRaises(ExecutableJ2534Error) as caught:
                if selector == 2:
                    wire.reset()
                elif selector is None:
                    with patch("scripts.cuw_legacy_vendor.ExecutableImage") as source:
                        source.return_value.read.return_value = b"x"
                        wire.security(authored_emps_context())
                else:
                    wire.write_region(b"a", selector)
            self.assertEqual(caught.exception.native_code, category)
            self.assertEqual(caught.exception.driver_status, 0xDEADBEEF)
            self.assertEqual(caught.exception.code, 0xDEADBEEF)
            self.assertTrue(writes[-1].startswith(target))

    def test_authored_cuw_import_reaches_shared_context_and_region_binding(self):
        context = authored_emps_context()
        self.assertEqual(context.native.selected.values["cputype"], "56")
        self.assertEqual(context.native.base_metadata["kind_of_ecu"], "13")
        with patch("scripts.cuw_legacy_vendor.legacy_executable_bytes"):
            self.assertEqual(bind_emps_regions(context), (b"AB", b"AB"))

    def test_bound_regions_keep_native_sum_prefix_and_vbf_loader_branch(self):
        loader = b"S1051000414267\nS9031000EC\n"
        sparse = b"S1051000414267\nS105100443445F\nS9031000EC\n"
        overlap = b"S1051000414267\nS1051000434463\nS9031000EC\n"
        for main_data, filename, code, expected in (
            (sparse, "image.srec", loader, (b"AB", b"AB\xff\xff")),
            (b"raw", "image.vbf", loader, (loader, b"raw")),
            (overlap, "image.srec", loader, None),
            (sparse, "image.srec", b"raw", None),
        ):
            main = materialize_legacy_image(main_data, filename=filename)
            cpu = NativeCPU(
                0,
                1,
                "CPU0",
                {"flashcodename": "loader.vbf"},
                {},
                {},
                None,
                CalibrationRecord(0, b"", code, 0),
                (),
                (),
                (),
                (),
                {},
            )
            native = NativeCPUContext(
                cpu, (cpu,), 101, {}, {}, {}, main, main, None, ()
            )
            context = ExecutableContext(
                18,
                "CCanEMPS_V850E_PS2FlashWriter",
                native,
                (native,),
                "0" * 64,
            )
            # Source admission itself is tested with actual PE separately.
            with patch("scripts.cuw_legacy_vendor.legacy_executable_bytes") as admit:
                if expected is None:
                    with self.assertRaises(ValueError):
                        bind_emps_regions(context)
                else:
                    self.assertEqual(bind_emps_regions(context), expected)
                admit.assert_called_once_with(context)

    def test_write_preserves_channel_padding_and_clear_rx_tx_chronology(self):
        for padding in (False, True):
            operations = []

            def action(operation, _remaining, operations=operations):
                operations.append(operation)
                if operation["operation"] in ("ioctl", "notification", "set_timeout"):
                    return None
                if operation["operation"] == "write_messages":
                    return 1
                return (NativeMessage(6, b"0000\x37", rx_status=2),)

            wire = EMPSWire(
                NativeRuntime2026(action),
                b"0000",
                b"1111",
                channel_flag_67=padding,
                read_timeout_ms=1500,
            )
            wire.write(b"\x37")
            self.assertEqual(
                [op["operation"] for op in operations],
                ["ioctl", "write_messages", "read_messages"],
            )
            self.assertEqual(operations[0]["ioctl_id"], 8)
            self.assertIsNone(operations[0]["input"])
            self.assertIsNone(operations[0]["output"])
            self.assertEqual(operations[1]["tx_flags"], 0x40 if padding else 0)
            self.assertEqual(operations[2]["timeout_ms"], 1500)

    def test_security_uses_admitted_source_bytes_and_checks_seed_width(self):
        for build, (seed, success) in itertools.product(
            (12, 18), ((b"\x67\x01\0\0", True), (b"\x67\x01\0", False))
        ):
            context = authored_emps_context(build=build)
            writes, pending = [], []

            def action(
                operation, _remaining, writes=writes, pending=pending, seed=seed
            ):
                if operation["operation"] in ("ioctl", "notification", "set_timeout"):
                    return None
                if operation["operation"] == "write_messages":
                    writes.append(operation["data"][4:])
                    pending.append(operation["data"])
                    return 1
                if pending:
                    return (NativeMessage(6, pending.pop(), rx_status=2),)
                reply = seed if len(writes) == 1 else b"\x67\x02"
                return (NativeMessage(6, b"1111" + reply),)

            wire = EMPSWire(
                NativeRuntime2026(action),
                b"0000",
                b"1111",
                channel_flag_67=False,
                read_timeout_ms=1000,
            )
            with patch("scripts.cuw_legacy_vendor.ExecutableImage") as source:
                source.return_value.read.return_value = b"x"
                if success:
                    wire.security(context)
                    self.assertEqual(writes, [b"\x27\x01", b"\x27\x02xxxx"])
                else:
                    with self.assertRaises(LegacyVendorResponseError) as caught:
                        wire.security(context)
                    self.assertEqual(caught.exception.code, 0x10)
                    self.assertEqual(writes, [b"\x27\x01"])
                source.assert_called_once_with(context)
                self.assertEqual(source.return_value.read.call_count, 4)

    def test_region_real_primitive_chronology_and_chunk_boundaries(self):
        for size in (0, 1, 239, 240, 241, 480, 481):
            for selector in (0, 1):
                writes = []
                tx_pending = []
                notifications = []

                def action(
                    operation,
                    _remaining,
                    writes=writes,
                    tx_pending=tx_pending,
                    notifications=notifications,
                ):
                    if operation["operation"] == "notification":
                        notifications.append((operation["field"], operation["value"]))
                        return None
                    if operation["operation"] in (
                        "ioctl",
                        "notification",
                        "set_timeout",
                    ):
                        return None
                    if operation["operation"] == "write_messages":
                        writes.append(operation["data"][4:])
                        tx_pending.append(operation["data"])
                        return 1
                    if tx_pending:
                        return (NativeMessage(6, tx_pending.pop(), rx_status=2),)
                    request = writes[-1]
                    if request[0] == 0x31:
                        reply = bytes((0x71, request[1]))
                    elif request[0] == 0x34:
                        reply = b"\x74\0\xf1"
                    else:
                        reply = bytes((request[0] + 0x40,))
                    return (NativeMessage(6, b"1111" + reply),)

                wire = EMPSWire(
                    NativeRuntime2026(action),
                    b"0000",
                    b"1111",
                    channel_flag_67=False,
                    read_timeout_ms=1000,
                )
                image = bytes(index % 256 for index in range(size))
                self.assertEqual(wire.write_region(image, selector), size)
                self.assertEqual(writes[0], bytes((0x31, selector + 1)))
                self.assertEqual(writes[1], emps_download_request(selector))
                self.assertEqual(writes[-2], b"\x37")
                self.assertEqual(writes[-1], emps_routine_request(3, image))
                self.assertEqual(b"".join(frame[1:] for frame in writes[2:-2]), image)
                self.assertEqual(len(writes[2:-2]), (size + 239) // 240)
                self.assertEqual(wire.written_9c, size if selector else 0)
                self.assertEqual(wire.percent_a4, 100 if selector and size else 0)
                expected_progress = []
                if selector:
                    for offset in range(0, size, 240):
                        position = min(offset + 240, size)
                        expected_progress.extend(
                            (
                                ("writing_bytes", position * 2),
                                ("writing_percent", int(position / size * 100)),
                            )
                        )
                self.assertEqual(notifications, expected_progress)

    def test_real_runtime_filters_rxstatus_and_pending_timeout(self):
        response = bytes.fromhex("00000728")
        frames = iter(
            [
                NativeMessage(6, response + b"\x76", rx_status=2),
                NativeMessage(6, bytes.fromhex("00000729") + b"\x76"),
                NativeMessage(6, response + b"\x7f\x36\x78"),
                NativeMessage(6, response + b"\x76"),
            ]
        )
        operations = []

        def action(operation, _remaining):
            operations.append(operation)
            if operation["operation"] == "set_timeout":
                return None
            return (next(frames),)

        wire = EMPSWire(
            NativeRuntime2026(action),
            bytes.fromhex("00000720"),
            response,
            channel_flag_67=False,
            read_timeout_ms=1234,
        )
        self.assertEqual(wire.read(0x36, 0x22), b"\x76")
        self.assertEqual(
            [
                op["timeout_ms"]
                for op in operations
                if op["operation"] == "read_messages"
            ],
            [1234, 1234, 1234, 5000],
        )
        self.assertEqual(wire.read_timeout_ms, 1000)
        self.assertEqual(
            [
                op["milliseconds"]
                for op in operations
                if op["operation"] == "set_timeout"
            ],
            [5000, 1000],
        )

    def test_pending_exhaustion_native_tester_present_and_error(self):
        response = bytes.fromhex("00000728")
        operations = []
        tx_pending = []

        def action(operation, _remaining):
            operations.append(operation)
            if operation["operation"] in ("ioctl", "notification", "set_timeout"):
                return None
            if operation["operation"] == "write_messages":
                tx_pending.append(operation["data"])
                return 1
            if tx_pending:
                return (NativeMessage(6, tx_pending.pop(), rx_status=2),)
            return (NativeMessage(6, response + b"\x7f\x34\x78"),)

        wire = EMPSWire(
            NativeRuntime2026(action),
            bytes.fromhex("00000720"),
            response,
            channel_flag_67=False,
            read_timeout_ms=1000,
        )
        with self.assertRaises(LegacyVendorResponseError) as caught:
            wire.read(0x34, 0x1A)
        self.assertEqual(caught.exception.code, 0x1A)
        self.assertEqual(len(operations), 302)
        self.assertEqual(operations[-2]["data"], bytes.fromhex("000007203e02"))
        self.assertEqual(operations[-1]["operation"], "read_messages")
        self.assertEqual(wire.read_timeout_ms, 5000)

    def test_no_byte_only_reply_or_boolean_write_success(self):
        for result in ((b"0000\x76",), True):
            wire = EMPSWire(
                NativeRuntime2026(
                    lambda op, _remaining, result=result: (
                        None if op["operation"] == "ioctl" else result
                    )
                ),
                b"0000",
                b"1111",
                channel_flag_67=False,
                read_timeout_ms=1000,
            )
            with self.assertRaises(ValueError):
                if result is True:
                    wire.write(b"\x37")
                else:
                    wire.read(0x36, 0x22)

    def test_rxstatus_filter_preserves_native_channel_flag(self):
        for status in range(32):
            for flag in (False, True):
                expected = status == 0 or (status == 16 and not flag)
                self.assertEqual(emps_accept_rxstatus(status, flag), expected)
                self.assertEqual(
                    emps_accept_rxstatus(status | 0xFFFF0000, flag), expected
                )
        with self.assertRaises(ValueError):
            emps_accept_rxstatus(-1, False)
        with self.assertRaises(TypeError):
            emps_accept_rxstatus(0, 0)  # pyright: ignore[reportArgumentType]

    def test_native_fixed_download_fields(self):
        self.assertEqual(emps_download_request(0).hex(), "34ff800000000b8c")
        self.assertEqual(emps_download_request(1).hex(), "3400390000038700")
        for value in (-1, 2, True):
            with self.assertRaises(ValueError):
                emps_download_request(value)

    def test_checksum_wrap_and_no_sequence_counter(self):
        self.assertEqual(emps_routine_request(1, b"ignored"), b"\x31\x01")
        self.assertEqual(emps_routine_request(2), b"\x31\x02")
        self.assertEqual(emps_routine_request(3, bytes((255, 128, 1))), b"\x31\x03\x80")
        self.assertEqual(emps_transfer_request(b"abc"), b"\x36abc")
        self.assertEqual(len(emps_transfer_request(bytes(240))), 241)
        for data in (b"", bytes(241)):
            with self.assertRaises(ValueError):
                emps_transfer_request(data)

    def test_native_response_lengths_codes_and_trailing_bytes(self):
        cases = [
            ("routine", 1, b"\x71\x01", 0x25),
            ("routine", 2, b"\x71\x02", 0x26),
            ("routine", 3, b"\x71\x03", 0x27),
            ("download", 1, b"\x74\0\xf1", 0x1A),
            ("transfer", 1, b"\x76", 0x22),
            ("exit", 1, b"\x77", 0x24),
            ("reset", 1, b"\x51", 0x18),
        ]
        for operation, stage, good, code in cases:
            with self.subTest(operation=operation, stage=stage):
                emps_validate_response(operation, good, stage=stage)
                emps_validate_response(operation, good + b"extra", stage=stage)
                for bad in (good[:-1], b"\x7f\x31\x78", b"\xff" + good[1:]):
                    with self.assertRaises(LegacyVendorResponseError) as caught:
                        emps_validate_response(operation, bad, stage=stage)
                    self.assertEqual(caught.exception.code, code)
                    self.assertEqual(caught.exception.response, bad)

    def test_techvim_source_predicate_truth_table(self):
        for a, b, first, second, last in itertools.product((False, True), repeat=5):
            # Literal branch translation of 4a301e/4a30b2/4a30e0.
            if a and not first and not second:
                expected = True
            elif b or first or second:
                expected = last
            else:
                expected = False
            self.assertEqual(
                techvim_needs_finalize(a, b, first, second, 2, 1 if last else 0),
                expected,
            )

    def test_techvim_binds_source_strings_and_imported_base_metadata(self):
        for build, slots in (
            (12, (0x585544, 0x585548, 0x585474, 0x585478)),
            (18, (0x5D5260, 0x5D5264, 0x5D5190, 0x5D5194)),
        ):
            context = replace(
                authored_emps_context(build=build), controller="CTechVimFlashWriter"
            )
            for family in (b"CAN", b"other"):
                memory = {}
                for index, (slot, value) in enumerate(
                    zip(slots, (family, b"SIL", b"5", b"6"), strict=True)
                ):
                    address = 0x600000 + index * 256
                    memory[slot] = address.to_bytes(4, "little")
                    memory.update(
                        {
                            address + offset: bytes((byte,))
                            for offset, byte in enumerate(value + b"\0")
                        }
                    )
                with patch("scripts.cuw_legacy_vendor.ExecutableImage") as image:
                    image.return_value.read.side_effect = (
                        lambda address, size, memory=memory: memory[address]
                    )
                    self.assertEqual(bind_techvim_finalize(context), family == b"CAN")

    def test_dh_source_selects_native_round_operands_and_rejects_ambiguity(self):
        from scripts.cuw_legacy_vendor import DHSource

        for build in (12, 18):
            context = replace(
                authored_emps_context(build=build, kind="17", cpu_type="65"),
                controller="CCanDHFlashWriter",
                cpu_types=("65",),
            )
            start, end, target, table, pending = (
                (0x53F528, 0x53FDC6, 0x40E310, 0x5CBD68, 0x5C5008)
                if build == 12
                else (0x58A870, 0x58B10E, 0x419BDC, 0x6281E4, 0x621484)
            )
            code = bytearray(b"\x90" * (end - start))
            for index in range(95):
                offset = index * 20 + 10
                code[offset - 5 : offset] = b"\x68" + (index + 256).to_bytes(
                    4, "little"
                )
                code[offset : offset + 5] = b"\xe8" + (
                    target - start - offset - 5
                ).to_bytes(4, "little", signed=True)
            arrays = (0x700000, 0x700026, 0x70004C, 0x700072, 0x700098)
            row_arrays = (
                arrays[0],
                arrays[2],
                arrays[1],
                arrays[3],
                arrays[0],
                arrays[4],
                arrays[0],
            )
            memory = {start: bytes(code), pending: (50).to_bytes(4, "little")}
            for row in range(7):
                memory[table + row * 12 + 4] = (0x4000 + row).to_bytes(4, "little")
                memory[table + row * 12 + 8] = row_arrays[row].to_bytes(4, "little")
            with (
                patch("scripts.cuw_legacy_vendor.ExecutableImage") as image,
                patch(
                    "scripts.cuw_legacy_vendor._vendor_resource",
                    side_effect=lambda context, slot12, slot18: str(
                        (
                            0x5D504C,
                            0x5D50C8,
                            0x5D5014,
                            0x5D50D8,
                            0x5D50DC,
                            0x5D50E0,
                        ).index(slot18)
                    ),
                ),
            ):
                image.return_value.read.side_effect = (
                    lambda address, size, memory=memory: memory[address][:size]
                )
                source = DHSource(context)
                self.assertEqual(source.index, 6)
                self.assertEqual(source.flash_address, b"\0\0\x40\x06")
                self.assertEqual(
                    source.rounds,
                    tuple(value.to_bytes(2, "big") for value in range(256, 275)),
                )
                self.assertEqual(source.pending, 50)
                memory[start] = bytes(code).replace(
                    b"\x68\x00\x01\x00\x00", b"\x90" * 5, 1
                )
                with self.assertRaisesRegex(ValueError, "operand must be unique"):
                    DHSource(context)

    def test_dh_execute_concrete_primitives_security_eh_and_abort(self):
        from scripts.cuw_legacy_addresses import (
            AddressConfig,
            AddressFactoryState,
            CAddress,
        )
        from scripts.cuw_legacy_vendor import DHController, DHSource

        for fault in (
            None,
            "seed_retry",
            "seed_exhaust",
            "mask",
            "session",
            "cpass",
            "foreign",
            "host",
            "cancel",
            "transfer",
            "sparse",
        ):
            context = replace(
                authored_emps_context(
                    kind="17",
                    cpu_type="65",
                    main_srec=b"S1051000414267\nS105100443445F\nS9031000EC\n"
                    if fault == "sparse"
                    else None,
                ),
                controller="CCanDHFlashWriter",
                constructor_send_timeout=927,
            )
            source = DHSource.__new__(DHSource)
            source.context = context
            source.special = source.short_seed = False
            source.cpu_type = "65"
            source.pending = 50
            source.rounds = (b"\x01\x02",) * 19
            source.flash_address = b"\0\0\x40\0"
            frame = b"\0\0\x07\xe0\xa0\x27"
            memory = {
                0x58A4D4 + index * 4 + 3: bytes((value,))
                for index, value in enumerate(frame)
            }
            for index in range(4):
                memory[0x5F1A48 + index * 4] = (100 + index).to_bytes(4, "little")
            source.image = Mock()
            source.image.read.side_effect = lambda address, size, memory=memory: memory[
                address
            ][:size]
            trace, pending = [], []
            seeds = 0

            def action(op, remaining, trace=trace, pending=pending, fault=fault):
                nonlocal seeds
                trace.append(op)
                name = op["operation"]
                if name.startswith("get_"):
                    self.fail("Shared channel state must not query provider getters")
                if name == "start_filter":
                    return 42
                if name == "write_messages":
                    body = op["data"][4:]
                    if (fault == "mask" and body == b"\xa0\x27") or (
                        fault == "session" and body == b"\x10\x85"
                    ):
                        raise NativeTransportError(9)
                    if body == b"\x27\x01":
                        seeds += 1
                        if (
                            fault == "seed_retry" and seeds == 1
                        ) or fault == "seed_exhaust":
                            raise NativeTransportError(9)
                        if fault == "cpass":
                            raise ExecutableCANError(9)
                        if fault == "foreign":
                            raise ExecutableForeignNativeError("foreign identity")
                        if fault == "host":
                            raise ValueError("host validation")
                    if body[:1] == b"\x36":
                        if fault == "cancel":
                            raise InterruptedError("host cancellation")
                        if fault == "transfer":
                            raise NativeTransportError(7)
                    pending.append(NativeMessage(6, op["data"][:4], rx_status=2))
                    if body == b"\xa0\x27":
                        return 1
                    replies = {
                        0x10: b"\x50\x85",
                        0x27: b"\x67\x01\x01\x02\x03\x04\0"
                        if body[1:2] == b"\x01"
                        else b"\x67\x02\x34",
                        0x34: b"\x74\x20\0\x61",
                        0x36: b"\x76",
                        0x37: b"\x77",
                        0x31: b"\x71\x01\xf0\x11\x20\0\x61"
                        if body[4:5] == b"\0"
                        else b"\x71\x01\xf0\x11\0",
                        0x11: b"\x51",
                    }
                    pending.append(NativeMessage(6, b"\0\0\x07\xe8" + replies[body[0]]))
                    return 1
                if name == "read_messages":
                    return (pending.pop(0),)
                if name == "controller_callback" and op["callback"] == "read_flag_88":
                    return False
                return None

            with (
                patch("scripts.cuw_legacy_vendor.DHSource", return_value=source),
                patch("scripts.cuw_legacy_vendor._vendor_resource", return_value="17"),
                patch(
                    "scripts.cuw_legacy_addresses.legacy_address_inputs",
                    return_value=(
                        "17",
                        AddressConfig(()),
                        False,
                        AddressFactoryState(),
                    ),
                ),
                patch(
                    "scripts.cuw_legacy_addresses.select_legacy_addresses",
                    return_value=(CAddress(b"\0\x07\xe0\0\x07\xe8\0\0"),),
                ),
            ):
                controller = DHController(context, NativeRuntime2026(action))
                state = channel_state(context)
                state.read_timeout, state.send_timeout = 137, 813
                if fault in ("foreign", "host", "cancel"):
                    error = {
                        "foreign": ExecutableForeignNativeError,
                        "host": ValueError,
                        "cancel": InterruptedError,
                    }[fault]
                    with self.assertRaises(error):
                        controller.run()
                    self.assertFalse(
                        any(op.get("callback") == "completion" for op in trace)
                    )
                    if fault == "cancel":
                        self.assertEqual(
                            (state.read_timeout, state.send_timeout), (137, 813)
                        )
                    continue
                result = controller.run()
            self.assertEqual(
                result["native_success"], fault in (None, "seed_retry", "sparse")
            )
            self.assertEqual((state.read_timeout, state.send_timeout), (1000, 927))
            self.assertEqual(
                seeds,
                2
                if fault == "seed_retry"
                else 31
                if fault == "seed_exhaust"
                else 0
                if fault in ("mask", "session")
                else 1,
            )
            if fault is None:
                self.assertFalse(pending)
                self.assertEqual(
                    [
                        op["value"]
                        for op in trace
                        if op.get("field") == "writing_percent"
                    ],
                    [0, 50, 100],
                )
                self.assertEqual(
                    [op["value"] for op in trace if op.get("field") == "writing_bytes"],
                    [0, 2, 4],
                )
            if fault == "sparse":
                assert context.native.first_image is not None
                bodies = [
                    op["data"][4:]
                    for op in trace
                    if op["operation"] == "write_messages"
                ]
                self.assertEqual(
                    (
                        len(context.native.first_image.data),
                        context.native.first_image.flash_size,
                    ),
                    (6, 4),
                )
                self.assertEqual(
                    [
                        int.from_bytes(body[-4:], "big")
                        for body in bodies
                        if body[:1] == b"\x34" or body[:5] == b"\x31\x01\xf0\x11\0"
                    ],
                    [6, 6],
                )
                self.assertEqual(
                    [len(body) - 1 for body in bodies if body[:1] == b"\x36"], [6, 4, 4]
                )
            if fault == "cpass":
                self.assertEqual(
                    (result["native_value_78"], result["native_value_80"]), (9, 0)
                )
            if fault == "transfer":
                self.assertEqual(
                    (result["native_value_78"], result["native_value_80"]), (34, 7)
                )

    def test_dh_negotiated_block_size_retains_unsigned_subtraction(self):
        from scripts.cuw_legacy_vendor import DHController, DHWire

        self.assertEqual(DHWire.block_size(b"\0\0"), 0xFFFFFFFF)
        self.assertEqual(DHWire.block_size(b"\0\x61"), 96)
        with self.assertRaisesRegex(ValueError, "divide by zero"):
            DHWire.block_size(b"\0\x01")
        controller = DHController.__new__(DHController)
        with self.assertRaisesRegex(ValueError, "Bounded native DH"):
            controller.region(bytes(4124), 0xFFFFFFFF, 1)

    def test_fhi_round_output_swap_and_group_retry_pending(self):
        from scripts.cuw_legacy_vendor import FHISource, FHIWire

        source = FHISource.__new__(FHISource)
        source.rounds = (b"\x01\x02",) * 16
        source.substitution = bytes(32)
        self.assertEqual(source.key(b"ABCD"), b"CDAB")
        with self.assertRaisesRegex(ValueError, "four-byte seed"):
            source.key(b"ABC")
        state = ChannelState(
            protocol=6, read_timeout=1000, send_timeout=927, padding=True
        )
        tx = (b"\0\0\x07\xe0", b"\0\0\x07\xe1")
        rx = (b"\0\0\x07\xe8", b"\0\0\x07\xe9")
        trace, queue = [], []
        writes = 0

        def action(op, remaining):
            nonlocal writes
            trace.append(op)
            if op["operation"] == "write_messages":
                writes += 1
                self.assertEqual(
                    op["messages"], tuple(header + b"\x85\x02" for header in tx)
                )
                queue.append(NativeMessage(6, tx[0], rx_status=2))
                if writes == 1:
                    queue.extend(
                        (
                            NativeMessage(6, rx[1] + b"\x7f\x85\x22"),
                            NativeMessage(6, rx[0] + b"\xc5\x02"),
                        )
                    )
                else:
                    queue.extend(
                        (
                            NativeMessage(6, rx[0] + b"\x7f\x85\x78"),
                            NativeMessage(6, rx[1] + b"\xc5\x02"),
                            NativeMessage(6, rx[0] + b"\xc5\x02"),
                        )
                    )
                return 2
            if op["operation"] == "read_messages":
                count = op["count"]
                frames = tuple(queue[:count])
                del queue[:count]
                return frames
            return None

        channel = CommonCAN.from_io(
            NativeRuntime2026(action), tx[0], rx[0], state=state
        )
        wire = FHIWire(source, channel, tx, rx)
        self.assertEqual(
            wire.exchange(b"\x85\x02", b"\xc5\x02", 2, 42, retry_wait=20),
            (b"\xc5\x02", b"\xc5\x02"),
        )
        with self.assertRaisesRegex(ValueError, "header groups"):
            FHIWire(source, channel, (), rx)
        operations = len(trace)
        with self.assertRaisesRegex(ValueError, "diagnostic fields"):
            wire.exchange(b"\x85\x02", b"\xc5\x02", 1, 42)
        self.assertEqual(len(trace), operations)
        self.assertEqual(writes, 2)
        self.assertFalse(queue)
        self.assertEqual(state.read_timeout, 1000)
        self.assertIn({"operation": "wait", "milliseconds": 20}, trace)
        self.assertIn({"operation": "set_timeout", "milliseconds": 5000}, trace)

    def test_fhi_execute_uses_configured_probes_and_unconfigured_programming(self):
        from scripts.cuw_legacy_addresses import (
            AddressConfig,
            AddressFactoryState,
            CAddress,
        )
        from scripts.cuw_legacy_vendor import FHIController, FHISource

        for case in (
            "success",
            "already",
            "seed",
            "transfer",
            "foreign",
            "host",
            "cancel",
            "sparse",
        ):
            context = replace(
                authored_emps_context(
                    kind="32",
                    cpu_type="65",
                    parameters={"WaitTimeAfterIGOn": " 42ms"},
                    main_srec=b"S1051000414267\nS105100443445F\nS9031000EC\n"
                    if case == "sparse"
                    else None,
                ),
                cpu_types=("65",),
            )
            source = FHISource.__new__(FHISource)
            source.context = context
            source.kind31 = False
            source.width, source.address, source.encoded_address = (
                3,
                0x3000,
                b"\0\x30\0",
            )
            source.wait_parameter = "WaitTimeAfterIGOn"
            source.routines = (b"\x62\0", b"\x63\0", b"\x02\x01", b"\x02\x02")
            source.rounds, source.substitution = (b"\x01\x02",) * 16, bytes(32)
            source.filters = tuple(
                (value.to_bytes(4, "big"), (value + 8).to_bytes(4, "big"))
                for value in (0x7E0, 0x7E1, 0x7B0)
            )
            source.broadcast = b"\0\0\x07\xdf"
            source.image = Mock()
            source.image.read.side_effect = lambda address, size: (
                ((address - 0x5F1A48) // 4) + 100
            ).to_bytes(4, "little")[:size]
            configured = (
                CAddress(b"\x27\x07\xe0\0\x07\xe8\0\0"),
                CAddress(b"\x28\x07\xe1\0\x07\xe9\0\0"),
            )
            trace, queue, bodies = [], [], []
            injected = False
            foreign = ExecutableForeignNativeError("native identity")
            host = ValueError("host identity")
            cancel = InterruptedError("abort identity")
            main = context.native.first_image
            assert main is not None

            def action(
                op,
                remaining,
                case=case,
                context=context,
                trace=trace,
                queue=queue,
                bodies=bodies,
                main=main,
                foreign=foreign,
                host=host,
                cancel=cancel,
            ):
                nonlocal injected
                trace.append(op)
                if op["operation"] == "start_filter":
                    return len(
                        [row for row in trace if row["operation"] == "start_filter"]
                    )
                if (
                    op["operation"] == "controller_callback"
                    and op["callback"] == "read_flag_88"
                ):
                    return False
                if op["operation"] == "write_messages":
                    frames = op.get("messages", (op.get("data"),))
                    body = frames[0][4:]
                    bodies.append((frames[0][:4], body))
                    if body[0] == 0x28:
                        self.assertEqual(channel_state(context).read_timeout, 500)
                    if case == "already" and body[0] == 9 and not injected:
                        injected = True
                        raise NativeTransportError(9)
                    if (case == "seed" and body[:2] == b"\x27\x61") or (
                        case == "transfer" and body[:1] == b"\xb6"
                    ):
                        raise NativeTransportError(7)
                    if body[:2] == b"\x27\x61":
                        if case == "foreign":
                            raise foreign
                        if case == "host":
                            raise host
                    if case == "cancel" and body[:1] == b"\xb6":
                        raise cancel
                    queue.append(NativeMessage(6, frames[0][:4], rx_status=2))
                    if body[0] == 0xB7:
                        reply = b"\xf7" + main.data[: main.flash_size]
                    else:
                        reply = {
                            9: b"\x49\0",
                            0x10: b"\x50" + body[1:2],
                            0x27: b"\x67\x61ABCD"
                            if body[1:2] == b"\x61"
                            else b"\x67\x62",
                            0x85: b"\xc5\x02",
                            0x28: b"\x68\x03",
                            0x34: b"\x74\x20\0\x61",
                            0x35: b"\x75\x20\0\x61",
                            0x31: b"\x71\x01" + body[2:4],
                            0xB6: b"\xf6",
                            0x37: b"\x77",
                        }[body[0]]
                    for frame in frames:
                        identifier = int.from_bytes(frame[:4], "big")
                        receivers = (
                            (0x7E8, 0x7E9) if identifier == 0x7DF else (identifier + 8,)
                        )
                        for receiver in receivers:
                            queue.append(
                                NativeMessage(6, receiver.to_bytes(4, "big") + reply)
                            )
                    return len(frames)
                if op["operation"] == "read_messages":
                    count = op["count"]
                    frames = tuple(queue[:count])
                    del queue[:count]
                    return frames
                return None

            with (
                patch("scripts.cuw_legacy_vendor.FHISource", return_value=source),
                patch(
                    "scripts.cuw_legacy_addresses.legacy_address_inputs",
                    return_value=(
                        "32",
                        AddressConfig(()),
                        False,
                        AddressFactoryState(),
                    ),
                ),
                patch(
                    "scripts.cuw_legacy_addresses.select_legacy_addresses",
                    side_effect=lambda context, kind, config, configured=configured, **values: (
                        configured if config is not None else configured[1:]
                    ),
                ),
            ):
                controller = FHIController(context, NativeRuntime2026(action))
                channel_state(context).read_timeout = 333
                if case in ("foreign", "host", "cancel"):
                    error = {"foreign": foreign, "host": host, "cancel": cancel}[case]
                    with self.assertRaises(type(error)) as caught:
                        controller.run()
                    self.assertIs(caught.exception, error)
                    self.assertFalse(
                        any(op.get("callback") == "completion" for op in trace)
                    )
                    if case == "cancel":
                        self.assertEqual(channel_state(context).read_timeout, 333)
                    continue
                result = controller.run()
            self.assertEqual(trace[0], {"operation": "wait", "milliseconds": 42})
            self.assertEqual(
                result["native_success"], case in ("success", "already", "sparse")
            )
            self.assertEqual(channel_state(context).read_timeout, 2000)
            self.assertTrue(
                all(
                    header == b"\0\0\x07\xe1"
                    for header, body in bodies
                    if body[0] in (0x27, 0x34, 0x35, 0xB6, 0xB7)
                )
            )
            if case == "success":
                self.assertFalse(queue)
                self.assertEqual(
                    [
                        op["value"]
                        for op in trace
                        if op.get("field") == "writing_percent"
                    ],
                    [50, 100],
                )
            if case == "already":
                self.assertFalse(any(body[0] == 0x27 for header, body in bodies))
            if case == "seed":
                self.assertEqual(
                    (result["native_value_78"], result["native_value_80"]), (16, 7)
                )
            if case == "transfer":
                self.assertEqual(
                    (result["native_value_78"], result["native_value_80"]), (34, 7)
                )
            if case == "sparse":
                self.assertEqual(
                    [
                        int.from_bytes(body[-3:], "big")
                        for header, body in bodies
                        if body[0] in (0x34, 0x35)
                    ],
                    [6, 6],
                )
                self.assertEqual(
                    [len(body) - 4 for header, body in bodies if body[0] == 0xB6], [4]
                )

    def test_fhi_source_kind32_selects_second_sixteen_round_array(self):
        from scripts.cuw_legacy_vendor import FHISource

        for build in (12, 18):
            context = authored_emps_context(build=build, kind="32", cpu_type="65")
            start, end, target, base, sub, static = (
                (0x5335A0, 0x533968, 0x40E310, 0x5C06A0, 0x5C2830, 0x5BFB04)
                if build == 12
                else (0x57CBF4, 0x57CFBC, 0x419BDC, 0x61CAB8, 0x61EC48, 0x61BF14)
            )
            code = bytearray(b"\x90" * (end - start))
            for index in range(36):
                offset = index * 20 + 10
                code[offset - 5 : offset] = b"\x68" + (index + 40).to_bytes(4, "little")
                code[offset : offset + 5] = b"\xe8" + (
                    target - start - offset - 5
                ).to_bytes(4, "little", signed=True)
            memory = {
                start: bytes(code),
                base + 4: (0x3000).to_bytes(4, "little"),
                sub: bytes(index & 15 for index in range(32)),
            }
            for index, value in enumerate(
                (0x7E0, 0x7E1, 0x7B0, 0x7E8, 0x7E9, 0x7B8, 0x7B0, 0x7DF)
            ):
                memory[static + 16 + index * 2] = value.to_bytes(2, "little")
            with (
                patch("scripts.cuw_legacy_vendor.ExecutableImage") as image,
                patch(
                    "scripts.cuw_legacy_vendor._vendor_resource",
                    side_effect=lambda context, slot12, slot18: (
                        "31" if slot18 == 0x5D51F4 else "WaitTimeAfterIGOn"
                    ),
                ),
            ):
                image.return_value.read.side_effect = (
                    lambda address, size, memory=memory: memory[address][:size]
                )
                source = FHISource(context)
                self.assertEqual(source.width, 3)
                self.assertEqual(source.encoded_address, b"\0\x30\0")
                self.assertEqual(
                    source.rounds,
                    tuple(value.to_bytes(2, "big") for value in range(60, 76)),
                )
                code[10] = 0x90
                memory[start] = bytes(code)
                with self.assertRaisesRegex(
                    ValueError, "four routine plus two sixteen-round"
                ):
                    FHISource(context)


if __name__ == "__main__":
    unittest.main()
