import csv
import dataclasses
import io
import struct
import unittest
import zlib
from pathlib import Path

from scripts.calibration_2026 import (
    encode_metadata_string_2026,
    native2026_metadata,
    native2026_with_cpu_type,
    parse_cuw_2026,
)
from scripts.calibration_catalog import CalibrationCatalog, ParameterTable
from scripts.j2534_2026 import (
    J2534Device2026,
    NativeJ2534Error2026,
    NativeMessage,
    NativePassThruError2026,
    PrimitiveResult,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CommonResponseError,
    NativeException2026,
    NativeJ2534Exception2026,
    NativePassThruException2026,
    NativeRuntime2026,
    bind_native_parameter2026,
)
from scripts.programming_2026_sil import (
    SILChannel,
    SILCIDState2026,
    SILProgress2026,
    SILRawProgramming,
    SILTransferState2026,
    _dcmprl_blocks,
    _sil_bootstrap,
    _sil_parameters,
    _sil_raw_memory,
    bind_context,
    ecu_kind,
    execute_context,
    execute_context_report,
    native_sil_image_password,
    physical_address,
    sil_cid,
    sil_dcmprl_prepare,
    sil_dcmprl_version,
    sil_dcmprl_write,
    sil_dh_software_id,
    sil_hino_cid,
    sil_hino_prepare,
    sil_hino_write,
    sil_j2534_action,
    sil_message,
    sil_prepare,
    sil_write,
)


class Primitive:
    def __init__(self, reads=()):
        self.reads = iter(reads)
        self.events = []
        self.fail: str | None = None

    def __call__(self, event, remaining):
        self.events.append(event)
        if self.fail == event["operation"]:
            raise OSError("authored primitive fault")
        operation = event["operation"]
        if operation == "write_messages":
            return 1
        if operation == "get_timeout":
            return 125
        if operation == "read_messages":
            value = next(self.reads)
            if isinstance(value, Exception):
                raise value
            return value
        if operation == "ioctl" and event["ioctl"] == 4:
            return b"\x55\x08\x08"
        if operation == "ioctl" and event["ioctl"] == 5:
            return {"data": b"\x83\xf1\x10\xc1\xe9\x8f", "rx_status": 0}
        return None


class WireScript:
    def __init__(self, pairs, fault=None):
        self.pairs = list(pairs)
        self.reads = []
        self.events = []
        self.timeout = 125
        self.fault = fault

    def __call__(self, event, remaining):
        self.events.append(event)
        if len(self.events) - 1 == self.fault:
            raise OSError("authored primitive fault")
        operation = event["operation"]
        if operation == "write_messages":
            expected, response = self.pairs.pop(0)
            if event["data"] != expected:
                raise AssertionError((event["data"].hex(), expected.hex()))
            if response is not None:
                self.reads.append(response)
            return 1
        if operation == "read_messages":
            value = self.reads.pop(0)
            if isinstance(value, Exception):
                raise value
            return value
        if operation == "get_timeout":
            return self.timeout
        if operation == "set_timeout":
            self.timeout = event["milliseconds"]
        if operation == "connect":
            return 42
        if operation == "ioctl" and event["ioctl"] == 5:
            return {"data": b"", "rx_status": 0}
        return None


class ActualJ2534Provider:
    def __init__(self, pairs=()):
        self.pairs = list(pairs)
        self.reads = []
        self.events = []
        self.cancel_connect: list[bool] | None = None

    def __call__(self, event, remaining):
        self.events.append(event)
        name = event["operation"]
        if name in ("passthru_open", "passthru_connect", "passthru_start_filter"):
            if name == "passthru_connect" and self.cancel_connect is not None:
                self.cancel_connect[0] = True
            return PrimitiveResult(value=len(self.events))
        if name == "passthru_ioctl" and event["ioctl"] == 5:
            return PrimitiveResult(value=NativeMessage(3, b"", rx_status=0))
        if name == "passthru_ioctl" and event["ioctl"] == 4:
            return PrimitiveResult(value=b"\x55\x08\x08")
        if name == "passthru_write":
            expected, response = self.pairs.pop(0)
            if event["messages"][0].data != expected:
                raise AssertionError((event["messages"][0].data, expected))
            if response is not None:
                self.reads.extend(
                    (NativeMessage(3, b"", rx_status=0), NativeMessage(3, response))
                )
            return PrimitiveResult(value=1)
        if name == "passthru_read":
            return PrimitiveResult(value=(self.reads.pop(0),) if self.reads else ())
        return PrimitiveResult()


def authored_frame(prefix):
    value = bytes.fromhex(prefix)
    return value + bytes((sum(value) & 255,))


def authored_container(
    *,
    target="AUTHORED-OLD",
    target_data="12345678",
    location="01020304AABBCCDD",
    version=7,
    flash=False,
    image=b"\x11\x22\x33\x44",
    image_name="authored.vbf",
):
    target_data = encode_metadata_string_2026(target_data)
    text = (
        f"[Format]\nVersion={version}\n[Vehicle]\nNumberOfCalibration=1\n"
        f"ContactType=SIL\nKindOfECU=8\n[CPU01]\nCPUImageName={image_name}\n"
        f"CPUType=31\nLocationID={location}\nNumberOfTargets=1\n"
        f"01_TargetCalibration={target}\n01_TargetData={target_data}\n"
    )
    if flash:
        text += "FlashCodeName=authored-sbl.vbf\n"
    text = text.encode()

    def record(name, data):
        return (
            struct.pack(">H", len(name))
            + name
            + struct.pack(">II", len(data), zlib.crc32(data))
            + data
        )

    body = record(b"attach.att", text) + b"\x01" + record(image_name.encode(), image)
    if flash:
        body += record(b"authored-sbl.vbf", b"SBL")
    raw = (
        b"\0CALIBRATION\0"
        + b"\x68"
        + bytes(4)
        + struct.pack(">I", 22 + len(body))
        + body
    )
    return parse_cuw_2026(raw[:14] + struct.pack(">I", zlib.crc32(raw[18:])) + raw[18:])


def authored_selection(**parameters):
    return CalibrationCatalog(
        [
            ParameterTable(
                "authored.csv",
                "0" * 64,
                ("ParamFileKeySystemProtocolMicon", *parameters),
                (("DEMO", *parameters.values()),),
            )
        ]
    ).select("DEMO")


def authored_native_binding(
    container, module, selection=None, metadata_state=None, general_source=None
):
    table = (selection or authored_selection()).catalog.tables[0]
    headers = (
        *table.headers,
        "DLLFileNameForGetCID",
        "DLLFileNameForPrepareWrite",
        "DLLFileNameForFlashWrite",
    )
    key = "8SIL" + (
        metadata_state.cpu.values["cputype"] if metadata_state is not None else "31"
    )
    row = (key, *table.rows[0][1:], module, module, module)
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(headers)
    writer.writerow(row)
    stage = (
        "prepare"
        if "PrepareWriter" in module
        else "write"
        if "FlashWriter" in module
        else "get_cid"
    )
    sources = {key + ".ini": stream.getvalue().encode()}
    if general_source is not None:
        sources["Parameter.ini"] = general_source
    return bind_native_parameter2026(
        container,
        sources,
        stage,
        encoded=False,
        metadata_state=metadata_state,
    )


def assert_fault_and_cancel_boundaries(test, pairs, runner, indices=None):
    baseline = WireScript(pairs)
    normal = []
    previous_cleanup = [0]

    def baseline_action(event, remaining):
        normal.append(baseline_channel.cleanup_calls == previous_cleanup[0])
        previous_cleanup[0] = baseline_channel.cleanup_calls
        return baseline(event, remaining)

    baseline_channel = SILChannel(baseline_action)
    runner(baseline_channel)
    boundaries = range(len(baseline.events)) if indices is None else tuple(indices)
    for index in boundaries:
        with test.subTest(fault=index):
            provider = WireScript(pairs, fault=index)
            with test.assertRaises(OSError):
                runner(SILChannel(provider))
    for index in boundaries:
        if not normal[index]:
            continue
        provider = WireScript(pairs)
        cancelled = [False]

        def action(
            event, remaining, provider=provider, index=index, cancelled=cancelled
        ):
            result = provider(event, remaining)
            if len(provider.events) - 1 == index:
                cancelled[0] = True
            return result

        with test.subTest(cancel=index), test.assertRaises(InterruptedError):
            runner(
                SILChannel(action, cancelled=lambda cancelled=cancelled: cancelled[0])
            )


class SILTests(unittest.TestCase):
    def test_cleanup_tracks_only_local_failure_including_catch_continuations(self):
        cleanup = NativePassThruException2026(44, "authored cleanup fault", 1)
        timeouts = []

        def action(event, remaining):
            operation = event["operation"]
            if operation == "get_timeout":
                return 500
            if operation == "write_messages":
                return 1
            if operation == "read_messages":
                return bytes.fromhex("83f0195a0300")
            if operation == "set_timeout":
                timeouts.append(True)
                if len(timeouts) == 2:
                    raise cleanup
            return None

        outer = OSError("unrelated enclosing handler")
        try:
            raise outer
        except OSError:
            with self.assertRaises(NativePassThruException2026) as caught:
                SILChannel(action).exchange(authored_frame("8219f01a81"), minimum=6)
        self.assertIs(caught.exception, cleanup)
        self.assertFalse(hasattr(outer, "__notes__"))
        host = OSError("authored progress callback failure")

        def native_failure(event, remaining):
            operation = event["operation"]
            if operation == "get_timeout":
                return 125
            if operation == "set_timeout":
                if event["milliseconds"] == 125:
                    raise cleanup
                return None
            if operation == "write_messages":
                raise NativePassThruException2026(7, "authored process fault", 1)
            return None

        def observer(name, value):
            raise host

        identity = identify_native_module(
            "cf77caf4e127b9c2fb2e0075f594348cfa131d9254cd163c8f2ef184f68d0f54",
            "TCUWSilDCMPRLFlashWriter.dll",
        )
        with self.assertRaises(OSError) as caught:
            sil_dcmprl_write(
                SILChannel(native_failure),
                identity,
                "31",
                "8",
                b"A",
                0,
                progress=SILProgress2026(1, observer=observer),
            )
        self.assertIs(caught.exception, host)
        self.assertEqual(
            host.__notes__, ["SIL cleanup failed: NativePassThruException2026"]
        )

    def test_native_all_security_seed_reads_use_zeroed_backing_array(self):
        provider = WireScript(
            [
                (
                    authored_frame("82c7f12701"),
                    NativeException2026("authored native read fault"),
                ),
                (authored_frame("84c7f127023b13"), bytes.fromhex("82f1c76702")),
            ]
        )
        identity = identify_native_module(
            "24dbe4b27bdcc3075e15a5166608b667471f100b5244fd23547e2d7850e97247",
            "TCUWSilDCMPRLPrepareWriter.dll",
        )
        sil_dcmprl_prepare(
            SILChannel(provider), identity, "31", "8", reset_requested=False
        )
        self.assertEqual(provider.pairs, [])
        provider = WireScript(
            [
                (authored_frame("8119f03e"), bytes.fromhex("81f0197e")),
                (authored_frame("8319f0108502"), bytes.fromhex("82f0195085")),
                (
                    authored_frame("8219f02701"),
                    NativeException2026("authored native read fault"),
                ),
                (authored_frame("8e19f02702" + "ff" * 12), bytes.fromhex("82f0196702")),
                (authored_frame("8319f0108502"), bytes.fromhex("82f0195085")),
                (authored_frame("8719f0830312fe02fe01"), bytes.fromhex("82f019c303")),
            ]
        )
        identity = identify_native_module(
            "831bbbe0cc53bf334f6ccc20581623ab048e6c3bf9bf66898cf14753e0f3e8c4",
            "TCUWSilHINOPrepareWriterForAMT.dll",
        )
        sil_hino_prepare(SILChannel(provider), identity)
        self.assertEqual(provider.pairs, [])
        self.assertEqual(provider.timeout, 125)

    def test_cleanup_preserves_host_identity_but_native_cleanup_takes_precedence(self):
        for primary in (
            OSError("authored host failure"),
            InterruptedError("authored abort"),
            NativePassThruException2026(7, "authored native fault", 1),
        ):
            with self.subTest(primary=type(primary).__name__):
                cleanup = NativePassThruException2026(44, "authored cleanup fault", 1)

                def action(event, remaining, primary=primary, cleanup=cleanup):
                    operation = event["operation"]
                    if operation == "get_timeout":
                        return 500
                    if operation == "write_messages":
                        return 1
                    if operation == "read_messages":
                        raise primary
                    if operation == "set_timeout":
                        raise cleanup
                    return None

                expected = (
                    cleanup if isinstance(primary, NativeException2026) else primary
                )
                with self.assertRaises(type(expected)) as caught:
                    SILChannel(action).exchange(
                        authored_frame("8219f01a81"), minimum=16
                    )
                self.assertIs(caught.exception, expected)
                if expected is primary:
                    self.assertEqual(
                        primary.__notes__,
                        ["SIL cleanup failed: NativePassThruException2026"],
                    )

    def test_getter_export_catches_process_but_not_native_setup_or_disconnect(self):
        modules = (
            (
                "TCUWSilCIDGetter.dll",
                "fada26732fbe56b7402ed353ca4a580a827fe617ee6c0ed798461a7e34d3c80c",
            ),
            (
                "TCUWSilDCMPRLVersionGetter.dll",
                "1b85297cced5fd156cfb6e164c2a098a0e0b933553558cee78a67ad1c26c4744",
            ),
            (
                "TCUWSilDHSoftwareIDGetter.dll",
                "94f65b4c4d9fe720c47f8cb6d369c76cdf28b26d9c10e129cfaf6569f998485f",
            ),
            (
                "TCUWSilHINOCIDGetterForAMT.dll",
                "a355eb5723b6ff1fef851d0459137c73c841527462cafdc6724315ec7dba285b",
            ),
        )
        for name, digest in modules:
            container = authored_container()
            selection = authored_native_binding(
                container,
                name,
                authored_selection(
                    ECUTargetAddressForSIL="10", ReceiveTimeoutBeforeGetCID="500"
                ),
            )
            attachments = (
                {"id_conversion_records": b"\x34\x12" + b"MATCH".ljust(12, b"\0")}
                if "DHSoftware" in name
                else {}
            )
            context = bind_context(
                container,
                1,
                (),
                selection,
                identify_native_module(digest, name),
                attachments,
                {},
            )
            for boundary in ("set_timeout", "connect", "ioctl", "disconnect"):
                with self.subTest(module=name, boundary=boundary):
                    primary = NativePassThruException2026(
                        7, "authored process fault", 1
                    )
                    cleanup = NativePassThruException2026(
                        44, "authored cleanup fault", 1
                    )

                    def action(
                        event,
                        remaining,
                        boundary=boundary,
                        primary=primary,
                        cleanup=cleanup,
                    ):
                        operation = event["operation"]
                        if operation == boundary:
                            raise cleanup if boundary == "disconnect" else primary
                        if operation == "ioctl":
                            raise primary
                        if operation == "connect":
                            return 1
                        return None

                    caught = boundary in ("connect", "ioctl") or (
                        boundary == "set_timeout" and "VersionGetter" in name
                    )
                    if caught:
                        result = execute_context_report(context, SILChannel(action))
                        self.assertIs(result.native_success, False)
                        self.assertIs(result.native_error, primary)
                    else:
                        with self.assertRaises(NativePassThruException2026) as result:
                            execute_context_report(context, SILChannel(action))
                        self.assertIs(
                            result.exception,
                            cleanup if boundary == "disconnect" else primary,
                        )

    def test_native_callback_failure_keeps_host_cancel_and_deadline_precedence(self):
        cancelled = [False]
        failure = OSError("authored callback fault")

        def callback():
            cancelled[0] = True
            raise failure

        with self.assertRaises(InterruptedError):
            SILChannel(
                Primitive(), cancelled=lambda: cancelled[0], native_cancelled=callback
            ).native_cancel_requested()
        now = [0.0]

        def late_callback():
            now[0] = 2.0
            raise failure

        with self.assertRaises(TimeoutError):
            SILChannel(
                Primitive(),
                clock=lambda: now[0],
                timeout=1,
                native_cancelled=late_callback,
            ).native_cancel_requested()

        def ordinary_failure():
            raise failure

        with self.assertRaises(OSError) as result:
            SILChannel(
                Primitive(), native_cancelled=ordinary_failure
            ).native_cancel_requested()
        self.assertIs(result.exception, failure)

        def native_failure():
            raise NativePassThruError2026(2)

        with self.assertRaises(NativePassThruException2026) as result:
            SILChannel(
                Primitive(), native_cancelled=native_failure
            ).native_cancel_requested()
        self.assertNotIsInstance(result.exception, NativeJ2534Exception2026)
        self.assertEqual(result.exception.error, 2)

    def test_canonical_export_bool_is_independent_of_prepare_reset_result(self):
        container = authored_container()
        module = "TCUWSilDCMPRLPrepareWriter.dll"
        identity = identify_native_module(
            "24dbe4b27bdcc3075e15a5166608b667471f100b5244fd23547e2d7850e97247", module
        )
        context = bind_context(
            container,
            1,
            (),
            authored_native_binding(container, module),
            identity,
            {},
            {"reset_requested": False, "prepare_status": 0},
        )
        provider = WireScript(
            [
                (authored_frame("82c7f12701"), bytes.fromhex("84f1c767010010")),
                (authored_frame("84c7f127024b23"), bytes.fromhex("82f1c76702")),
            ]
        )
        result = execute_context_report(context, SILChannel(provider))
        self.assertIs(result.native_return, True)
        self.assertIsNone(result.native_success)
        self.assertIs(result.result, False)
        self.assertIsNone(result.native_error)

        def native_fault(event, remaining):
            if event["operation"] == "get_timeout":
                return 125
            if event["operation"] == "set_timeout":
                return None
            raise NativeTransportError(7)

        result = execute_context_report(context, SILChannel(native_fault))
        self.assertIs(result.native_return, False)
        self.assertIsInstance(result.native_error, NativeJ2534Exception2026)

        def native_all_fault(event, remaining):
            if event["operation"] == "get_timeout":
                return 125
            if event["operation"] == "set_timeout":
                return None
            raise NativeException2026("authored native CException")

        result = execute_context_report(context, SILChannel(native_all_fault))
        self.assertIs(result.native_return, False)
        self.assertIs(type(result.native_error), NativeException2026)
        self.assertEqual(result.error_code, 9999)

        def setup_fault(event, remaining):
            if event["operation"] == "get_timeout":
                return 125
            raise NativeTransportError(7)

        transfer = SILTransferState2026(status=0)
        with self.assertRaises(NativeJ2534Exception2026):
            execute_context_report(context, SILChannel(setup_fault), transfer=transfer)
        self.assertEqual(transfer.status, 0)
        reused_error = NativeJ2534Exception2026(7, "authored reused driver error", 1)

        def cleanup_fault(event, remaining):
            if event["operation"] == "get_timeout":
                return 125
            if event["operation"] == "set_timeout" and event["milliseconds"] == 10000:
                return None
            raise reused_error

        with self.assertRaises(NativeJ2534Exception2026) as result:
            execute_context_report(context, SILChannel(cleanup_fault))
        self.assertIs(result.exception, reused_error)
        calls, cancelled = [], [False]

        def cancelled_setup(event, remaining):
            calls.append(event)
            if event["operation"] == "get_timeout":
                return 125
            if event["operation"] == "set_timeout" and event["milliseconds"] == 10000:
                cancelled[0] = True
            return None

        with self.assertRaises(InterruptedError):
            execute_context_report(
                context, SILChannel(cancelled_setup, cancelled=lambda: cancelled[0])
            )
        self.assertEqual(
            calls,
            [
                {"operation": "get_timeout"},
                {"operation": "set_timeout", "milliseconds": 10000},
                {"operation": "set_timeout", "milliseconds": 125},
            ],
        )

        def host_fault(event, remaining):
            raise OSError("authored host failure")

        with self.assertRaises(OSError):
            execute_context_report(context, SILChannel(host_fault))

    def test_native_progress_cleanup_failure_is_outside_export_false_catch(self):
        container = authored_container()
        module = "TCUWSilDCMPRLFlashWriter.dll"
        identity = identify_native_module(
            "cf77caf4e127b9c2fb2e0075f594348cfa131d9254cd163c8f2ef184f68d0f54", module
        )
        context = bind_context(
            container,
            1,
            (),
            authored_native_binding(
                container, module, authored_selection(WaitTimeAfterEndOfFlashing="0")
            ),
            identity,
            {},
            {},
        )
        failure = NativeException2026("authored body and cleanup native fault")
        primitive = Primitive()

        def action(event, remaining):
            if event["operation"] == "write_messages":
                raise failure
            return primitive(event, remaining)

        def observer(name, value):
            raise failure

        progress = SILProgress2026(4, count=5, percent=50, observer=observer)
        transfer = SILTransferState2026()
        with self.assertRaises(NativeException2026) as result:
            execute_context_report(
                context, SILChannel(action), progress=progress, transfer=transfer
            )
        self.assertIs(result.exception, failure)
        self.assertEqual(
            (transfer.error, transfer.status, progress.count, progress.percent),
            (9999, 2, 0, 50),
        )

    def test_canonical_getter_pointer_return_and_out_bool_are_separate(self):
        container = authored_container()
        module = "TCUWSilDHSoftwareIDGetter.dll"
        identity = identify_native_module(
            "94f65b4c4d9fe720c47f8cb6d369c76cdf28b26d9c10e129cfaf6569f998485f", module
        )
        records = bytes.fromhex("3412") + b"AUTHORED".ljust(12, b"\0")
        context = bind_context(
            container,
            1,
            (),
            authored_native_binding(
                container, module, authored_selection(ECUTargetAddressForSIL="10")
            ),
            identity,
            {"id_conversion_records": records},
            {},
        )
        provider = WireScript(
            [(authored_frame("8110f01a"), bytes.fromhex("83f0105a1234aa"))]
        )
        result = execute_context_report(context, SILChannel(provider))
        self.assertIsNone(result.native_return)
        self.assertIs(result.native_success, True)
        self.assertEqual(result.result, ("AUTHORED",))
        self.assertNotIn("AUTHORED", repr(result))
        result = execute_context_report(
            context, SILChannel(WireScript([]), native_cancelled=lambda: True)
        )
        self.assertIsNone(result.native_return)
        self.assertIs(result.native_success, False)
        self.assertIsInstance(result.native_error, CommonResponseError)
        self.assertEqual(result.result, ())
        polls = iter((False, False, True))
        provider = WireScript(
            [(authored_frame("8110f01a"), bytes.fromhex("83f0105a1234aa"))]
        )
        state = SILCIDState2026()
        result = execute_context_report(
            context,
            SILChannel(provider, native_cancelled=lambda: next(polls)),
            cid_state=state,
        )
        self.assertIs(result.native_success, False)
        self.assertEqual(result.result, ("AUTHORED",))
        self.assertEqual(state.identifiers, ["AUTHORED"])

    def test_actual48_read_indication_fault_and_empty_count_then_payload(self):
        for indication in (PrimitiveResult(status=7), PrimitiveResult(value=())):
            provider = ActualJ2534Provider()
            reads = [indication, PrimitiveResult(value=(NativeMessage(3, b"DATA"),))]

            def primitive(event, remaining, provider=provider, reads=reads):
                if event["operation"] == "passthru_read":
                    provider.events.append(event)
                    return reads.pop(0)
                return provider(event, remaining)

            device = J2534Device2026(
                primitive, clock=lambda: 0, background_workers=False
            )
            channel = SILChannel(sil_j2534_action(device), clock=lambda: 0)
            channel.acquire("connect", "disconnect", protocol=3)
            self.assertEqual(channel.call("read_messages", count=1), b"DATA")
            self.assertEqual(reads, [])
            self.assertEqual(
                sum(e["operation"] == "passthru_read" for e in provider.events), 2
            )
            channel.close()

    def test_generic_engine_mutation_rejects_untyped_capability_before_io(self):
        identity = identify_native_module(
            "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97",
            "TCUWSilFlashWriter.dll",
        )
        primitive = Primitive()
        with self.assertRaises(ValueError):
            sil_write(
                SILChannel(primitive),
                identity,
                bytes(1024),
                bytes(4),
                0,
                authored_selection(BlockSizeInfo="0:1x1"),
                "0",
                "SIL",
                transfer=SILTransferState2026(engine=object()),
            )
        self.assertEqual(primitive.events, [])

    def test_native_alternate_cpu_mutates_actual_engine_before_missing_row_failure(
        self,
    ):
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import NativeGeneralParameters2026
        from tests.test_calibration_2026 import cpu_text, cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        general = b"ParamFileKeySystemProtocolMicon,M16CTypeFlag,FORESTTypeFlag\r\n8SIL31,0,0\r\n8SIL32,0,0\r\n"
        engine = CUWEngine2026(
            image.read_bytes(),
            general_parameters=NativeGeneralParameters2026.from_sources(
                {"Parameter.ini": general}, encoded=False
            ),
        )
        engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
        text = (
            cpu_text(version=7)
            .replace("P5-Unified", "SIL")
            .replace("KindOfECU=149", "KindOfECU=8")
            .replace("CPUType=311", "CPUType=31")
        )
        metadata = engine.load_cuw(cuw(text, payloads=(bytes(1024),)))
        selection = authored_native_binding(
            metadata.source_container,
            "TCUWSilFlashWriter.dll",
            authored_selection(
                BlockSizeInfo="0:1x1",
                ShrinkFlag="0",
                **{"32BHFlag": "1", "AlternateCPUType": "32"},
            ),
            metadata_state=metadata,
            general_source=general,
        )
        handshake = [(b"\x60", b"\x3c"), (b"\x00", b"\x3c"), (b"\x05", b"\x3c")]
        memory = (b"\x76", bytes.fromhex("3c0000000003ff0110993c"))
        blank = [(b"\x36\x00\x00\x00\x00", b"\x3c"), (b"\x50", b"\x3c\x00\x3c")]
        provider = WireScript(
            [(b"\x3c", None)]
            + handshake * 100
            + [(b"\x75", bytes(10)), memory]
            + [memory] * 99
            + blank * 100
            + handshake
            + [memory]
        )
        identity = identify_native_module(
            "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97",
            "TCUWSilFlashWriter.dll",
        )
        transfer = SILTransferState2026(engine=engine)
        with self.assertRaises(CommonResponseError) as result:
            sil_write(
                SILChannel(provider),
                identity,
                bytes(1024),
                bytes(4),
                0,
                selection,
                "8",
                "SIL",
                transfer=transfer,
            )
        self.assertEqual(result.exception.code, 10)
        self.assertEqual(engine.native_metadata.cpu.values["cputype"], "32")
        self.assertEqual(transfer.cpu_type_override, "32")
        self.assertEqual(provider.pairs, [])

    def test_actual48_read_host_failure_propagates_and_wrap_drain_reads_once(self):
        for operation, fail in (("read_messages", True), ("wrap_read_messages", False)):
            provider = ActualJ2534Provider()

            def primitive(event, remaining, provider=provider, fail=fail):
                if event["operation"] == "passthru_read":
                    provider.events.append(event)
                    if fail:
                        raise OSError("authored host failure")
                    return PrimitiveResult(value=(NativeMessage(3, b"DRAIN"),))
                return provider(event, remaining)

            device = J2534Device2026(
                primitive, clock=lambda: 0, background_workers=False
            )
            channel = SILChannel(sil_j2534_action(device), clock=lambda: 0)
            channel.acquire("connect", "disconnect", protocol=3)
            if fail:
                with self.assertRaises(OSError):
                    channel.call(operation, count=1)
            else:
                self.assertEqual(channel.call(operation, count=1), b"DRAIN")
            self.assertEqual(
                sum(e["operation"] == "passthru_read" for e in provider.events), 1
            )
            channel.close()

    def test_actual48_device_complete_dh_wire_and_connection_rollback(self):
        provider = ActualJ2534Provider(
            [(authored_frame("8110f01a"), bytes.fromhex("83f0105a1234aa"))]
        )
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        identity = identify_native_module(
            "94f65b4c4d9fe720c47f8cb6d369c76cdf28b26d9c10e129cfaf6569f998485f",
            "TCUWSilDHSoftwareIDGetter.dll",
        )
        table = bytes.fromhex("3412") + b"AUTHORED".ljust(12, b"\0")
        channel = SILChannel(sil_j2534_action(device), clock=lambda: 0)
        self.assertEqual(
            sil_dh_software_id(channel, identity, 16, table, 500), ("AUTHORED",)
        )
        self.assertIsNone(device.channel_id)
        self.assertIsNone(device.device_id)
        self.assertEqual(provider.pairs, [])
        self.assertTrue(
            any(
                e["operation"] == "passthru_ioctl"
                and e["ioctl"] == 2
                and e.get("parameters") == ((1, 10400),)
                for e in provider.events
            )
        )
        cancelled = [False]
        provider = ActualJ2534Provider()
        provider.cancel_connect = cancelled
        device = J2534Device2026(
            provider,
            clock=lambda: 0,
            cancelled=lambda: cancelled[0],
            background_workers=False,
        )
        with self.assertRaises(InterruptedError):
            SILChannel(sil_j2534_action(device), clock=lambda: 0).acquire(
                "connect", "disconnect", protocol=3
            )
        self.assertIsNone(device.channel_id)
        self.assertIsNone(device.device_id)
        self.assertIn(
            "passthru_disconnect", [event["operation"] for event in provider.events]
        )

    def test_actual48_preconnected_caller_channel_survives_rejected_acquisition(self):
        provider = ActualJ2534Provider()
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(3)
        before = (device.device_id, device.channel_id, tuple(device.filters))
        count = len(provider.events)
        with self.assertRaises(ValueError):
            SILChannel(sil_j2534_action(device), clock=lambda: 0).acquire(
                "connect", "disconnect", protocol=3
            )
        self.assertEqual(
            (device.device_id, device.channel_id, tuple(device.filters)), before
        )
        self.assertEqual(len(provider.events), count)
        device.disconnect()

    def test_actual48_caller_open_device_survives_rejected_getter_acquisition(self):
        provider = ActualJ2534Provider()
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        identifier = device.device_id
        count = len(provider.events)
        with self.assertRaises(ValueError):
            SILChannel(sil_j2534_action(device), clock=lambda: 0).acquire(
                "connect", "disconnect", protocol=3
            )
        self.assertEqual(device.device_id, identifier)
        self.assertTrue(device.opened)
        self.assertEqual(len(provider.events), count)
        device.close()

    def test_native_dh_cancel_polls_twice_skips_request_and_keeps_host_cleanup(self):
        provider = ActualJ2534Provider()
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        polls = []

        def cancelled():
            polls.append(True)
            return True

        channel = SILChannel(
            sil_j2534_action(device), clock=lambda: 0, native_cancelled=cancelled
        )
        identity = identify_native_module(
            "94f65b4c4d9fe720c47f8cb6d369c76cdf28b26d9c10e129cfaf6569f998485f",
            "TCUWSilDHSoftwareIDGetter.dll",
        )
        with self.assertRaises(CommonResponseError) as result:
            sil_dh_software_id(
                channel,
                identity,
                16,
                bytes.fromhex("3412") + b"AUTHORED".ljust(12, b"\0"),
                500,
            )
        self.assertEqual(result.exception.code, 3)
        self.assertEqual(polls, [True, True])
        self.assertFalse(
            any(event["operation"] == "passthru_write" for event in provider.events)
        )
        self.assertIsNone(device.channel_id)

    def test_native_version_cancel_returns_empty_ids_and_actual_prl_contact_update(
        self,
    ):
        provider = WireScript([])
        polls = []

        def cancelled():
            polls.append(True)
            return True

        identity = identify_native_module(
            "1b85297cced5fd156cfb6e164c2a098a0e0b933553558cee78a67ad1c26c4744",
            "TCUWSilDCMPRLVersionGetter.dll",
        )
        self.assertEqual(
            sil_dcmprl_version(
                SILChannel(provider, native_cancelled=cancelled), identity, "8", 500
            ),
            ((), "SIL"),
        )
        self.assertEqual(polls, [True])
        self.assertEqual(
            sum(
                event == {"operation": "wait", "milliseconds": 500}
                for event in provider.events
            ),
            1,
        )

    def test_native_utils_cancel_returns_zero_output_but_host_abort_remains_error(self):
        request = bytes.fromhex("8310f1220102a9")
        for method in ("receive", "exchange"):
            provider = WireScript([(request, None)] if method == "exchange" else [])
            polls = []

            def cancelled(polls=polls):
                polls.append(True)
                return True

            result = getattr(SILChannel(provider, native_cancelled=cancelled), method)(
                request,
                minimum=100,
                payload_prefix=b"impossible",
                check_native_cancel=True,
            )
            self.assertEqual(result, b"")
            self.assertEqual(polls, [True])
            self.assertFalse(
                any(event["operation"] == "read_messages" for event in provider.events)
            )
            self.assertEqual(provider.timeout, 125)
        provider = Primitive()
        with self.assertRaises(InterruptedError):
            SILChannel(
                provider, cancelled=lambda: True, native_cancelled=lambda: True
            ).receive(request, minimum=6, check_native_cancel=True)
        self.assertEqual(provider.events, [])

    def test_native_utils_cancel_preserves_last_pending_or_busy_output(self):
        request = bytes.fromhex("8310f1220102a9")
        for nrc in (0x78, 0x21):
            response = bytes((0x83, 0xF1, 0x10, 0x7F, 0x22, nrc))
            pairs = [(request, response)] + ([(request, None)] if nrc == 0x21 else [])
            provider = WireScript(pairs)
            replies = iter((False, True))
            result = SILChannel(
                provider, native_cancelled=lambda replies=replies: next(replies)
            ).exchange(
                request,
                minimum=100,
                check_native_cancel=True,
                pending_limit=3,
                busy_limit=3,
            )
            self.assertEqual(result, response)
            self.assertEqual(provider.pairs, [])
            self.assertEqual(provider.timeout, 125)
        provider = WireScript([])
        self.assertEqual(
            SILChannel(provider, native_cancelled=lambda: True).receive(
                request,
                minimum=100,
                check_native_cancel=True,
                initial_response=b"previous",
            ),
            b"previous",
        )

    def test_native_hino_cancel_skips_tester_and_cid_then_halts_before_error(self):
        provider = WireScript([(authored_frame("8119f082"), bytes.fromhex("81f019c2"))])
        polls = []

        def cancelled():
            polls.append(True)
            return True

        identity = identify_native_module(
            "a355eb5723b6ff1fef851d0459137c73c841527462cafdc6724315ec7dba285b",
            "TCUWSilHINOCIDGetterForAMT.dll",
        )
        with self.assertRaises(CommonResponseError) as result:
            sil_hino_cid(SILChannel(provider, native_cancelled=cancelled), identity)
        self.assertEqual(result.exception.code, 3)
        self.assertEqual(polls, [True, True, True, True])
        self.assertEqual(provider.pairs, [])

    def test_bound_native_runtime_cpu_type_override_supplies_operational_metadata(self):
        container = authored_container()
        changed = native2026_with_cpu_type(native2026_metadata(container), 0, "32")
        module = "TCUWSilDCMPRLFlashWriter.dll"
        identity = identify_native_module(
            "cf77caf4e127b9c2fb2e0075f594348cfa131d9254cd163c8f2ef184f68d0f54", module
        )
        selected = authored_native_binding(container, module, metadata_state=changed)
        context = bind_context(container, 1, (), selected, identity, {}, {})
        self.assertEqual(context.arguments[0], "32")
        self.assertEqual(context.calibration_sha256, container.digest)

    def test_logical_cpu_prepare_uses_actual_synthesized_cpu_values(self):
        from tests.test_calibration_2026 import cuw, logical_text

        container = parse_cuw_2026(
            cuw(
                logical_text().replace(
                    "ContactType=P5-Unified", "KindOfECU=8\nContactType=SIL"
                )
            )
        )
        module = "TCUWSilDCMPRLPrepareWriter.dll"
        identity = identify_native_module(
            "24dbe4b27bdcc3075e15a5166608b667471f100b5244fd23547e2d7850e97247", module
        )
        source = f"ParamFileKeySystemProtocolMicon,DLLFileNameForPrepareWrite\r\n8SIL,{module}\r\n".encode()
        selected = bind_native_parameter2026(
            container, {"8SIL.ini": source}, "prepare", encoded=False
        )
        context = bind_context(
            container, 1, (), selected, identity, {}, {"reset_requested": False}
        )
        self.assertEqual(context.arguments, ("", "8"))
        provider = WireScript(
            [
                (authored_frame("82c7f12701"), bytes.fromhex("84f1c767010010")),
                (authored_frame("84c7f127024b23"), bytes.fromhex("82f1c76702")),
            ]
        )
        result = execute_context_report(context, SILChannel(provider))
        self.assertIs(result.native_return, True)
        self.assertEqual(provider.pairs, [])

    def test_context_replacement_cannot_change_actual_native_wire_arguments(self):
        container = authored_container()
        module = "TCUWSilDHSoftwareIDGetter.dll"
        identity = identify_native_module(
            "94f65b4c4d9fe720c47f8cb6d369c76cdf28b26d9c10e129cfaf6569f998485f", module
        )
        selection = authored_native_binding(
            container, module, authored_selection(ECUTargetAddressForSIL="10")
        )
        records = bytes.fromhex("3412") + b"AUTHORED".ljust(12, b"\0")
        context = bind_context(
            container,
            1,
            (),
            selection,
            identity,
            {"id_conversion_records": records},
            {},
        )
        provider = Primitive()
        for replaced in (
            dataclasses.replace(context, arguments=(0x19, records, 500)),
            dataclasses.replace(context, calibration_sha256="0" * 64),
            dataclasses.replace(context),
        ):
            with self.assertRaisesRegex(ValueError, "binder-issued"):
                execute_context(replaced, NativeRuntime2026(provider))
        self.assertEqual(provider.events, [])

    def test_exported_getter_clears_previous_vector_but_retains_current_partial(self):
        container = authored_container()
        module = "TCUWSilDHSoftwareIDGetter.dll"
        identity = identify_native_module(
            "94f65b4c4d9fe720c47f8cb6d369c76cdf28b26d9c10e129cfaf6569f998485f", module
        )
        records = bytes.fromhex("3412") + b"AUTHORED".ljust(12, b"\0")
        context = bind_context(
            container,
            1,
            (),
            authored_native_binding(
                container, module, authored_selection(ECUTargetAddressForSIL="10")
            ),
            identity,
            {"id_conversion_records": records},
            {},
        )
        state = SILCIDState2026(identifiers=["STALE"])
        polls = iter((False, False, True))
        provider = WireScript(
            [(authored_frame("8110f01a"), bytes.fromhex("83f0105a1234aa"))]
        )
        with self.assertRaises(CommonResponseError):
            execute_context(
                context,
                SILChannel(provider, native_cancelled=lambda: next(polls)),
                cid_state=state,
            )
        self.assertEqual(state.identifiers, ["AUTHORED"])
        with self.assertRaises(CommonResponseError):
            execute_context(
                context,
                SILChannel(WireScript([]), native_cancelled=lambda: True),
                cid_state=state,
            )
        self.assertEqual(state.identifiers, [])

    def test_selected_srecord_preserve_flag_has_no_fabricated_contiguous_image(self):
        container = authored_container(
            image_name="authored.srec", image=b"S1070000112233444E\nS9030000FC\n"
        )
        module = "TCUWSilFlashWriter.dll"
        identity = identify_native_module(
            "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97", module
        )
        for preserve in ("0", "1"):
            selection = authored_native_binding(
                container, module, authored_selection(FlagToHoldSFormatRecords=preserve)
            )
            if preserve == "1":
                with self.assertRaisesRegex(ValueError, "materialized"):
                    bind_context(
                        container,
                        1,
                        ("AUTHORED-OLD",),
                        selection,
                        identity,
                        {},
                        {"use_new_password": False},
                    )
            else:
                bound = bind_context(
                    container,
                    1,
                    ("AUTHORED-OLD",),
                    selection,
                    identity,
                    {},
                    {"use_new_password": False},
                )
                self.assertEqual(bound.arguments[0], bytes.fromhex("11223344"))
                self.assertEqual(bound.keywords["flash_size"], 4)

    def test_progress_cancel_after_count_prevents_percent_and_next_wire(self):
        provider = WireScript([(b"A" * 256, None)])
        cancelled = [False]
        events = []

        def observer(name, value):
            events.append((name, value, provider.events[-1]))
            cancelled[0] = True

        progress = SILProgress2026(1024, observer=observer)
        channel = SILChannel(provider, cancelled=lambda: cancelled[0])
        with self.assertRaises(InterruptedError):
            SILRawProgramming(channel, progress)._data_packet(b"A" * 256)
        self.assertEqual((progress.count, progress.percent), (256, 0))
        self.assertEqual(
            events,
            [("count", 256, {"operation": "set_send_timeout", "milliseconds": 1000})],
        )
        self.assertEqual(provider.pairs, [])

    def test_receive_native_pending_exhaustion_always_sends_compact_stop(self):
        provider = WireScript([(bytes.fromhex("8110f18204"), None)])
        provider.reads.append(bytes.fromhex("83f1107f22789d"))
        with self.assertRaises(CommonResponseError):
            SILChannel(provider).receive(bytes.fromhex("8310f1220102a9"), minimum=6)
        self.assertEqual(provider.pairs, [])
        self.assertEqual(provider.timeout, 125)

    def test_bound_actual_stage_wrong_row_module_and_container_rejected(self):
        container = authored_container()
        module = "TCUWSilFlashWriter.dll"
        identity = identify_native_module(
            "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97", module
        )
        valid = authored_native_binding(container, module)
        for wrong in (
            dataclasses.replace(valid, key="unrelated"),
            dataclasses.replace(valid, operation="prepare"),
            authored_native_binding(authored_container(target="another"), module),
            authored_native_binding(container, "TCUWSilPrepareWriter.dll"),
            authored_native_binding(container, "TCUWSilDCMPRLFlashWriter.dll"),
        ):
            with (
                self.subTest(key=wrong.key, stage=wrong.operation),
                self.assertRaises(ValueError),
            ):
                bind_context(
                    container,
                    1,
                    ("AUTHORED-OLD",),
                    wrong,
                    identity,
                    {},
                    {"use_new_password": False},
                )

    def test_actual_metadata_binder_old_new_password_and_no_geometry_overrides(self):
        identity = identify_native_module(
            "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97",
            "TCUWSilFlashWriter.dll",
        )
        container = authored_container()
        selection = authored_native_binding(
            container,
            identity.module_name,
            authored_selection(PasswordAddress="00", ByteOrder="1"),
        )
        context = bind_context(
            container,
            1,
            ("AUTHORED-OLD",),
            selection,
            identity,
            {},
            {"use_new_password": False},
        )
        self.assertEqual(
            context.arguments[:3],
            (bytes.fromhex("11223344"), bytes.fromhex("01020304"), 0x12345678),
        )
        self.assertNotIn("12345678", repr(context))
        self.assertEqual(context.report()["calibration_sha256"], container.digest)
        new = bind_context(
            container, 1, (), selection, identity, {}, {"use_new_password": True}
        )
        self.assertEqual(new.arguments[2], 0x11223344)
        for observations in (
            {},
            {"use_new_password": 1},
            {"use_new_password": False, "target_index": 0},
        ):
            with self.subTest(observations=observations), self.assertRaises(ValueError):
                bind_context(
                    container,
                    1,
                    ("AUTHORED-OLD",),
                    selection,
                    identity,
                    {},
                    observations,
                )
        with self.assertRaises(ValueError):
            bind_context(
                container,
                1,
                ("unrelated",),
                selection,
                identity,
                {},
                {"use_new_password": False},
            )
        with self.assertRaises(ValueError):
            bind_context(
                container,
                1,
                (),
                selection,
                identity,
                {"password": b"override"},
                {"use_new_password": True},
            )

    def test_all_canonical_modules_bind_actual_metadata_and_archive_order(self):
        identities = {
            "TCUWSilCIDGetter.dll": "fada26732fbe56b7402ed353ca4a580a827fe617ee6c0ed798461a7e34d3c80c",
            "TCUWSilDCMPRLFlashWriter.dll": "cf77caf4e127b9c2fb2e0075f594348cfa131d9254cd163c8f2ef184f68d0f54",
            "TCUWSilDCMPRLPrepareWriter.dll": "24dbe4b27bdcc3075e15a5166608b667471f100b5244fd23547e2d7850e97247",
            "TCUWSilDCMPRLVersionGetter.dll": "1b85297cced5fd156cfb6e164c2a098a0e0b933553558cee78a67ad1c26c4744",
            "TCUWSilDHSoftwareIDGetter.dll": "94f65b4c4d9fe720c47f8cb6d369c76cdf28b26d9c10e129cfaf6569f998485f",
            "TCUWSilFlashWriter.dll": "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97",
            "TCUWSilHINOCIDGetterForAMT.dll": "a355eb5723b6ff1fef851d0459137c73c841527462cafdc6724315ec7dba285b",
            "TCUWSilHINOFlashWriterForAMT.dll": "e573f4d0bea6318763ca9923a960d30556270450bd4e9266dfd8465e4735c586",
            "TCUWSilHINOPrepareWriterForAMT.dll": "831bbbe0cc53bf334f6ccc20581623ab048e6c3bf9bf66898cf14753e0f3e8c4",
            "TCUWSilPrepareWriter.dll": "14bc941c496e273fcf2c195609ff5cb5b4fe0bc84a5b65d54c486e7d75dfd1c0",
        }
        selection = authored_selection(
            PasswordAddress="00",
            ByteOrder="0",
            ECUTargetAddressForSIL="19",
            SBLStartAddressSize="001000\n000003",
            DATAStartAddressSize="002000\n000004",
        )
        records = bytes.fromhex("3412") + b"AUTHORED".ljust(12, b"\0")
        for module, digest in identities.items():
            observations = {}
            if module == "TCUWSilFlashWriter.dll":
                observations["use_new_password"] = False
            elif module == "TCUWSilDCMPRLPrepareWriter.dll":
                observations["reset_requested"] = False
            with self.subTest(module=module):
                container = authored_container(flash=True)
                context = bind_context(
                    container,
                    1,
                    ("AUTHORED-OLD",),
                    authored_native_binding(container, module, selection),
                    identify_native_module(digest, module),
                    {"id_conversion_records": records},
                    observations,
                )
                self.assertEqual(context.identity.module_name, module)
                if module == "TCUWSilHINOFlashWriterForAMT.dll":
                    self.assertEqual(
                        context.arguments[:2], (b"SBL", bytes.fromhex("11223344"))
                    )
        identity = identify_native_module(
            identities["TCUWSilFlashWriter.dll"], "TCUWSilFlashWriter.dll"
        )
        container8 = authored_container(version=8)
        zero = bind_context(
            container8,
            1,
            ("AUTHORED-OLD",),
            authored_native_binding(container8, identity.module_name, selection),
            identity,
            {},
            {"use_new_password": False},
        )
        self.assertEqual(zero.arguments[2], 0)

    def test_native_32bh_memory_fallback_and_pic_literal_discontiguous_bounds(self):
        provider = WireScript(
            [
                (b"\x75", bytes(10)),
                (b"\x76", bytes.fromhex("3c0000000003ff0110993c")),
            ]
        )
        memory, shrink = _sil_raw_memory(
            SILRawProgramming(SILChannel(provider)), False, True
        )
        self.assertTrue(shrink)
        assert memory is not None
        self.assertEqual(
            (
                memory.start_address,
                memory.end_address,
                memory.block_size_kib,
                memory.firmware_version,
            ),
            (0, 1023, 1, 16),
        )
        self.assertEqual(provider.pairs, [])
        with self.assertRaises(CommonResponseError):
            _sil_raw_memory(
                SILRawProgramming(SILChannel(WireScript([(b"\x76", bytes(11))]))),
                True,
                False,
            )
        blocks = _dcmprl_blocks("34", bytes(0x4300))
        self.assertEqual(
            blocks,
            (
                (0, 0x400000, 1024),
                (1024, 0x400400, 1024),
                (2048, 0x400800, 1024),
                (3072, 0x400C00, 1024),
                (0x400E, 0x40400E, 4),
                (0x4200, 0x404200, 256),
            ),
        )
        with self.assertRaises(ValueError):
            _dcmprl_blocks("34", bytes(0x42FF))

    def test_native_bootstrap_blank_cpass_cleanup_then_next_baud(self):
        descriptor = bytes.fromhex("3c0000000003ff01103c")
        handshake = [(b"\x60", b"\x3c"), (b"\x00", b"\x3c"), (b"\x05", b"\x3c")]
        pairs = handshake * 100 + [(b"\x75", descriptor)] * 100
        pairs += [(b"\x35\x00", NativeTransportError(17)), (b"\x05", b"\x3c")]
        pairs += handshake * 100 + [(b"\x75", descriptor)] * 100
        pairs += [(b"\x35\x00", b"\x3c"), (b"\x50", b"\x3c\x00\x3c")] * 100
        provider = WireScript(pairs)
        result = _sil_bootstrap(
            SILRawProgramming(SILChannel(provider)),
            {
                "BlockSizeInfo": "0:1x1",
                "CPUIDNo": "1",
                "ShrinkFlag": "0",
                "32BHFlag": "0",
                "AlternateCPUType": "",
            },
            False,
            False,
        )
        self.assertFalse(result)
        self.assertEqual(provider.pairs, [])
        self.assertEqual(
            [
                event["config"]
                for event in provider.events
                if event["operation"] == "ioctl"
            ],
            [((1, 9600),), ((1, 9800),)],
        )

    def test_native_32bh_detection_runs_once_then_keeps_known_shrink_command(self):
        good = bytes.fromhex("3c0000000003ff0110993c")
        provider = WireScript(
            [(b"\x75", bytes(10)), (b"\x76", good), (b"\x76", good), (b"\x76", good)]
        )
        raw = SILRawProgramming(SILChannel(provider))
        memory, shrink = _sil_raw_memory(raw, False, True)
        self.assertTrue(shrink)
        self.assertIsNotNone(memory)
        ignored, shrink = _sil_raw_memory(raw, False, True, parse_descriptor=False)
        self.assertIsNone(ignored)
        self.assertTrue(shrink)
        memory, shrink = _sil_raw_memory(raw, False, True)
        self.assertIsNotNone(memory)
        self.assertEqual(provider.pairs, [])

    def test_protocol_transport_remap_retains_driver_and_restores_timeout(self):
        for method in ("receive", "exchange"):
            provider = Primitive()

            def action(event, remaining, provider=provider):
                if event["operation"] == "read_messages":
                    raise NativeTransportError(17)
                return provider(event, remaining)

            with (
                self.subTest(method=method),
                self.assertRaises(NativeJ2534Exception2026) as result,
            ):
                getattr(SILChannel(action), method)(
                    bytes.fromhex("8310f1220102a9"), minimum=6, error_code=0x1B
                )
            self.assertEqual(
                (result.exception.error, result.exception.j2534_error), (0x1B, 17)
            )
            self.assertEqual(
                provider.events[-1], {"operation": "set_timeout", "milliseconds": 125}
            )

    def test_native_dcm_prepare_failure_sets_status_and_reset_flag_in_cleanup(self):
        identity = identify_native_module(
            "24dbe4b27bdcc3075e15a5166608b667471f100b5244fd23547e2d7850e97247",
            "TCUWSilDCMPRLPrepareWriter.dll",
        )
        for failure, expected in (
            (NativeTransportError(17), 1),
            (CommonResponseError(10), 10),
            (NativeException2026("authored native ALL"), 9999),
            (RuntimeError("authored host failure"), 0),
        ):
            provider = Primitive()

            def action(event, remaining, failure=failure, provider=provider):
                if event["operation"] == "ioctl":
                    raise failure
                return provider(event, remaining)

            transfer = SILTransferState2026(j2534_error=77)
            with (
                self.subTest(failure=type(failure).__name__),
                self.assertRaises(
                    NativeJ2534Exception2026
                    if isinstance(failure, NativeTransportError)
                    else type(failure)
                ),
            ):
                sil_dcmprl_prepare(
                    SILChannel(action),
                    identity,
                    "31",
                    "8",
                    reset_requested=False,
                    transfer=transfer,
                )
            self.assertEqual(
                (transfer.status, transfer.error, transfer.reset_requested),
                (1 if expected else 0, expected, bool(expected)),
            )
            self.assertEqual(transfer.j2534_error, 17 if expected == 1 else 77)
            self.assertEqual(
                provider.events[-1], {"operation": "set_timeout", "milliseconds": 125}
            )

    def test_host_prepare_failure_does_not_infer_reset_from_existing_status(self):
        identity = identify_native_module(
            "24dbe4b27bdcc3075e15a5166608b667471f100b5244fd23547e2d7850e97247",
            "TCUWSilDCMPRLPrepareWriter.dll",
        )
        provider = Primitive()
        failure = OSError("authored host failure")

        def action(event, remaining):
            if event["operation"] == "ioctl":
                raise failure
            return provider(event, remaining)

        transfer = SILTransferState2026(status=1)
        with self.assertRaises(OSError) as result:
            sil_dcmprl_prepare(
                SILChannel(action),
                identity,
                "31",
                "8",
                reset_requested=False,
                prepare_status=1,
                transfer=transfer,
            )
        self.assertIs(result.exception, failure)
        self.assertEqual(
            (transfer.status, transfer.reset_requested, transfer.error), (1, False, 0)
        )
        self.assertEqual(
            provider.events[-1], {"operation": "set_timeout", "milliseconds": 125}
        )

    def test_host_dcm_flash_failure_preserves_assigned_state_without_native_outcome(
        self,
    ):
        identity = identify_native_module(
            "cf77caf4e127b9c2fb2e0075f594348cfa131d9254cd163c8f2ef184f68d0f54",
            "TCUWSilDCMPRLFlashWriter.dll",
        )
        provider = Primitive()

        def action(event, remaining):
            if event["operation"] == "write_messages":
                raise RuntimeError("authored host failure")
            return provider(event, remaining)

        transfer = SILTransferState2026(j2534_error=77)
        with self.assertRaises(RuntimeError):
            sil_dcmprl_write(
                SILChannel(action), identity, "31", "8", b"A", 500, transfer=transfer
            )
        self.assertEqual(
            (
                transfer.status,
                transfer.error,
                transfer.j2534_error,
                transfer.writing,
                transfer.wait_end_ms,
            ),
            (0, 0, 77, True, 500),
        )
        self.assertEqual(
            provider.events[-1], {"operation": "set_timeout", "milliseconds": 125}
        )

    def test_native_startup_driver_error_sets_transfer_slots_and_clears_password_flag(
        self,
    ):
        identity = identify_native_module(
            "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97",
            "TCUWSilFlashWriter.dll",
        )
        calls, events = [], []

        def fail(event, remaining):
            calls.append(event)
            raise NativeTransportError(17)

        state = SILTransferState2026(use_new_password=True)
        progress = SILProgress2026(
            1024, observer=lambda name, value: events.append((name, value))
        )
        with self.assertRaises(NativeJ2534Exception2026):
            sil_write(
                SILChannel(fail),
                identity,
                bytes(1024),
                bytes(4),
                0,
                authored_selection(BlockSizeInfo="0:1x1"),
                "0",
                "SIL",
                use_new_password=True,
                transfer=state,
                progress=progress,
            )
        self.assertEqual(
            (state.error, state.j2534_error, state.use_new_password, state.writing),
            (1, 17, False, False),
        )
        self.assertEqual(
            calls, [{"operation": "ioctl", "ioctl": 2, "config": ((1, 9600),)}]
        )
        self.assertEqual(events, [])
        self.assertEqual(state.status, 1)

    def test_native_generic_catch_continuation_sets_status_only_for_native_errors(self):
        identity = identify_native_module(
            "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97",
            "TCUWSilFlashWriter.dll",
        )
        for failure, expected in (
            (NativePassThruError2026(2), 1),
            (CommonResponseError(10), 1),
            (NativeException2026("authored native CException"), 1),
            (OSError("authored host failure"), 77),
        ):

            def fail(event, remaining, failure=failure):
                raise failure

            state = SILTransferState2026(status=77, j2534_error=91)
            with self.assertRaises(
                NativePassThruException2026
                if isinstance(failure, NativePassThruError2026)
                else type(failure)
            ):
                sil_write(
                    SILChannel(fail),
                    identity,
                    bytes(1024),
                    bytes(4),
                    0,
                    authored_selection(BlockSizeInfo="0:1x1"),
                    "0",
                    "SIL",
                    transfer=state,
                )
            self.assertEqual(state.status, expected)
            self.assertEqual(state.j2534_error, 91)

    def test_native_cid_final_failure_preserves_partial_shared_vector(self):
        frames = (
            [b"\x48\x6b\x10\x49\x03\x08"]
            + [
                b"\x48\x6b\x10\x49\x04\x01" + part
                for part in (b"ABCD", b"EFGH", b"IJKL", b"MN12")
            ]
            + [NativeTransportError(17)]
        )
        primitive = Primitive(frames)

        def action(event, remaining):
            if event["operation"] == "connect":
                primitive.events.append(event)
                return 42
            if event["operation"] == "ioctl" and event["ioctl"] == 5:
                raise NativeTransportError(17)
            return primitive(event, remaining)

        identity = identify_native_module(
            "fada26732fbe56b7402ed353ca4a580a827fe617ee6c0ed798461a7e34d3c80c",
            "TCUWSilCIDGetter.dll",
        )
        state = SILCIDState2026()
        with self.assertRaises(NativeJ2534Exception2026) as result:
            sil_cid(SILChannel(action), identity, "0", 500, state=state)
        self.assertEqual(state.identifiers, ["ABCDEFGHIJKLMN12"])
        self.assertIs(result.exception.__dict__["sil_cid_state"], state)
        self.assertNotIn("ABCDEFGHIJKLMN12", repr(state))
        self.assertEqual(
            primitive.events[-1], {"operation": "disconnect", "identifier": 42}
        )

    def test_native_generic_retry_password_cleanup_uses_error_and_last_block(self):
        identity = identify_native_module(
            "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97",
            "TCUWSilFlashWriter.dll",
        )
        for failure, last, expected in (
            (CommonResponseError(7), False, True),
            (CommonResponseError(10), False, False),
            (CommonResponseError(10), True, True),
            (NativeException2026("authored native ALL"), False, True),
            (OSError("authored host fault"), True, True),
            (InterruptedError("authored host abort"), False, True),
        ):

            def fail(event, remaining, failure=failure):
                raise failure

            state = SILTransferState2026(
                last_block=last, error=7, use_new_password=True
            )
            with self.assertRaises(type(failure)):
                sil_write(
                    SILChannel(fail),
                    identity,
                    bytes(1024),
                    bytes(4),
                    0,
                    authored_selection(BlockSizeInfo="0:1x1"),
                    "0",
                    "SIL",
                    use_new_password=True,
                    transfer=state,
                )
            self.assertEqual(state.use_new_password, expected)

    def test_actual48_plain_pass_error_keeps_enum_without_driver(self):
        for acquisition in (False, True):

            def fail(event, remaining):
                raise NativePassThruError2026(2)

            channel = SILChannel(fail)
            with self.subTest(acquisition=acquisition):
                with self.assertRaises(NativePassThruException2026) as result:
                    if acquisition:
                        channel.acquire("connect", "disconnect", protocol=3)
                    else:
                        channel.call("ioctl", ioctl=2, config=((1, 9600),))
                self.assertNotIsInstance(result.exception, NativeJ2534Exception2026)
                self.assertEqual(result.exception.error, 2)
                self.assertIsNone(result.exception.passthru_status)

        def driver_fault(event, remaining):
            raise NativeJ2534Error2026(7)

        with self.assertRaises(NativeJ2534Exception2026) as result:
            SILChannel(driver_fault).call("read_messages", count=1)
        self.assertEqual((result.exception.error, result.exception.j2534_error), (1, 7))

    def test_native_generic_transport_enum_remaps_preserve_driver_and_source(self):
        for operation, expected in (
            ("initialize", 7),
            ("blank", 11),
            ("erase", 12),
            ("inverify", 14),
            ("write", 13),
            ("verify", 15),
        ):

            def fail(event, remaining):
                raise NativeTransportError(17)

            raw = SILRawProgramming(SILChannel(fail))
            with (
                self.subTest(operation=operation),
                self.assertRaises(NativeJ2534Exception2026) as result,
            ):
                if operation == "initialize":
                    raw.initialize(bytes(4), 0)
                elif operation == "write":
                    raw.write_group(bytes(1024), 0)
                elif operation == "verify":
                    raw.verify_group(bytes(256), 1, 1, wide=False)
                else:
                    raw.block_command(operation, 1, 1, wide=False)
            self.assertEqual(
                (result.exception.error, result.exception.j2534_error), (expected, 17)
            )
        original = NativeJ2534Exception2026(18, "authored-origin", 123)

        def typed_fail(event, remaining):
            raise original

        with self.assertRaises(NativeJ2534Exception2026) as result:
            SILRawProgramming(SILChannel(typed_fail)).write_group(bytes(1024), 0)
        self.assertIs(result.exception, original)
        self.assertEqual(
            (original.error, original.source, original.line),
            (13, "authored-origin", 123),
        )

    def test_native_verify_nonfinal_common_error_is_suppressed_before_next_packet(self):
        data = bytes(512)
        provider = WireScript(
            [
                (bytes.fromhex("1500"), b"\x3c"),
                (bytes(256), b"\x3c"),
                (b"\x50", bytes(3)),
                (bytes(256), b"\x3c"),
                (b"\x50", b"\x3c\x00\x3c"),
            ]
        )
        SILRawProgramming(SILChannel(provider)).verify_group(data, 1, 1, wide=False)
        self.assertEqual(provider.pairs, [])

    def test_native_verify_nonfinal_failure_retains_previous_pending_status(self):
        provider = WireScript(
            [
                (bytes.fromhex("1500"), b"\x3c"),
                (bytes(256), b"\x3c"),
                (b"\x50", b"\x3c\x20\x3c"),
                (b"\x50", CommonResponseError(4)),
            ]
        )
        with self.assertRaises(CommonResponseError) as result:
            SILRawProgramming(SILChannel(provider)).verify_group(
                bytes(512), 1, 1, wide=False
            )
        self.assertEqual(result.exception.code, 15)
        self.assertEqual(provider.pairs, [])

    def test_native_first_memory_read_fault_falls_back_but_write_and_host_fault_do_not(
        self,
    ):
        good = bytes.fromhex("3c0000000003ff0110993c")
        for native in (
            NativeTransportError(7),
            CommonResponseError(4),
            NativeException2026("authored native ALL"),
        ):
            provider = WireScript([(b"\x75", native), (b"\x76", good)])
            _, shrink = _sil_raw_memory(
                SILRawProgramming(SILChannel(provider)), False, True
            )
            self.assertTrue(shrink)
            self.assertEqual(provider.pairs, [])
        provider = WireScript([(b"\x75", OSError("authored host fault"))])
        with self.assertRaises(OSError):
            _sil_raw_memory(SILRawProgramming(SILChannel(provider)), False, True)
        self.assertEqual(
            [e["data"] for e in provider.events if e["operation"] == "write_messages"],
            [b"\x75"],
        )
        events = []

        def write_failure(event, remaining):
            events.append(event)
            raise NativeTransportError(7)

        with self.assertRaises(NativeJ2534Exception2026):
            _sil_raw_memory(SILRawProgramming(SILChannel(write_failure)), False, True)
        self.assertEqual([e["data"] for e in events], [b"\x75"])

    def test_raw_serial_status_retry_and_native_ack_error_classes(self):
        for code in (9, 16, 17):

            def failed(event, remaining, code=code):
                raise NativeTransportError(code)

            raw = SILRawProgramming(SILChannel(failed))
            if code in (9, 16):
                self.assertFalse(raw.ack())
            else:
                with self.assertRaises(NativeJ2534Exception2026) as result:
                    raw.ack()
                self.assertEqual(
                    (result.exception.error, result.exception.j2534_error), (1, code)
                )
        provider = WireScript([(b"\x50", b"bad"), (b"\x50", b"\x3c\x20\x3c")])
        self.assertEqual(SILRawProgramming(SILChannel(provider)).status(), 0x20)
        self.assertIn({"operation": "wait", "milliseconds": 10}, provider.events)
        provider = WireScript([(b"\x50", b"bad")])
        with self.assertRaises(CommonResponseError) as result:
            SILRawProgramming(SILChannel(provider)).status(retry=False)
        self.assertEqual(result.exception.code, 4)
        # The native exact-count reader discards surplus bytes in the same frame.
        self.assertEqual(
            SILRawProgramming(SILChannel(Primitive([b"ABCD"]))).read_exact(2), b"AB"
        )

    def test_raw_init_nonzero_password_literal_little_endian(self):
        provider = WireScript([(b"\x3c", None)])
        SILRawProgramming(SILChannel(provider)).initialize(
            bytes.fromhex("01020304"), 0x11223344
        )
        self.assertEqual(
            next(
                event["input"]
                for event in provider.events
                if event["operation"] == "ioctl" and event["ioctl"] == 5
            ),
            bytes.fromhex("00000403020144332211"),
        )

    def test_native_parameter_prefix_defaults_and_password_address_or_fold(self):
        image = bytes.fromhex("11223344")
        for order, expected in (
            ("1 trailing", 0x11223344),
            ("not-a-number", 0x44332211),
            ("2147483648", 0x11223344),
            ("-65536", 0x44332211),
        ):
            self.assertEqual(
                native_sil_image_password(
                    image, authored_selection(PasswordAddress="00", ByteOrder=order)
                ),
                expected,
            )
        self.assertEqual(
            native_sil_image_password(
                b"X" + image, authored_selection(PasswordAddress="0100000000")
            ),
            0x44332211,
        )
        self.assertEqual(
            native_sil_image_password(image, authored_selection(PasswordAddress=" 0")),
            0x44332211,
        )
        values = _sil_parameters(
            authored_selection(ShrinkFlag="2 trailing", **{"32BHFlag": "bad"})
        )
        self.assertEqual((values["ShrinkFlag"], values["32BHFlag"]), ("1", "0"))
        container = authored_container()
        identity = identify_native_module(
            "fada26732fbe56b7402ed353ca4a580a827fe617ee6c0ed798461a7e34d3c80c",
            "TCUWSilCIDGetter.dll",
        )
        selected = authored_native_binding(
            container,
            identity.module_name,
            authored_selection(ReceiveTimeoutBeforeGetCID=" +123 trailing"),
        )
        self.assertEqual(
            bind_context(container, 1, (), selected, identity, {}, {}).arguments,
            ("8", 123),
        )

    def test_image_password_native_low_word_byte_order_and_bounds(self):
        image = bytes.fromhex("11223344")
        for text, expected in (
            ("0", 0x44332211),
            ("65536", 0x44332211),
            ("1", 0x11223344),
            ("-1", 0x11223344),
        ):
            self.assertEqual(
                native_sil_image_password(
                    image, authored_selection(PasswordAddress="00", ByteOrder=text)
                ),
                expected,
            )
        for address, order in (
            ("1", "0"),
            ("-1", "0"),
            ("0", "2147483648"),
            ("0", "invalid"),
        ):
            with self.assertRaises(ValueError):
                native_sil_image_password(
                    image, authored_selection(PasswordAddress=address, ByteOrder=order)
                )

    def test_bound_dcmprl_execute_preserves_runtime_budget_and_cleanup(self):
        identity = identify_native_module(
            "24dbe4b27bdcc3075e15a5166608b667471f100b5244fd23547e2d7850e97247",
            "TCUWSilDCMPRLPrepareWriter.dll",
        )
        container = authored_container()
        context = bind_context(
            container,
            1,
            (),
            authored_native_binding(container, identity.module_name),
            identity,
            {},
            {"reset_requested": False},
        )
        provider = WireScript(
            [
                (authored_frame("82c7f12701"), bytes.fromhex("84f1c767010010")),
                (authored_frame("84c7f127024b23"), bytes.fromhex("82f1c76702")),
            ]
        )
        runtime = NativeRuntime2026(provider, clock=lambda: 0)
        runtime.calls = 65535
        with self.assertRaises(ValueError):
            execute_context(context, runtime)
        self.assertEqual(runtime.calls, 65537)
        self.assertEqual(runtime.cleanup_calls, 1)
        self.assertEqual(
            provider.events,
            [
                {"operation": "get_timeout"},
                {"operation": "set_timeout", "milliseconds": 125},
            ],
        )
        self.assertEqual(runtime.deadline, 30)

    def test_full_cid_obd2_state_machine_and_disconnect(self):
        fragments = [b"ABCD", b"EFGH", b"IJKL", b"MN12"]
        action = Primitive(
            [b"\x48\x6b\x10\x49\x03\x04"]
            + [b"\x48\x6b\x10\x49\x04\x01" + fragment for fragment in fragments]
        )
        original = action.__call__

        def provider(event, remaining):
            if event["operation"] in ("connect", "write_messages"):
                action.events.append(event)
                return 42 if event["operation"] == "connect" else 1
            return original(event, remaining)

        identity = identify_native_module(
            "fada26732fbe56b7402ed353ca4a580a827fe617ee6c0ed798461a7e34d3c80c",
            "TCUWSilCIDGetter.dll",
        )
        self.assertEqual(
            sil_cid(SILChannel(provider), identity, "0", 500), ("ABCDEFGHIJKLMN12",)
        )
        writes = [
            event["data"]
            for event in action.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes, [bytes.fromhex("686af10903cf"), bytes.fromhex("686af10904d0")]
        )
        self.assertEqual(
            action.events[-1], {"operation": "disconnect", "identifier": 42}
        )

    def test_cid_native_obd_failure_falls_back_to_fast_init(self):
        action = Primitive(
            [bytes.fromhex("83f113490304")]
            + [
                bytes.fromhex("87f113490401") + part
                for part in (b"ABCD", b"EFGH", b"IJKL", b"MN12")
            ]
        )

        def provider(event, remaining):
            if event["operation"] == "ioctl" and event["ioctl"] == 4:
                action.events.append(event)
                raise NativeTransportError(17)
            if event["operation"] in ("connect", "write_messages"):
                action.events.append(event)
                return 42 if event["operation"] == "connect" else 1
            return action(event, remaining)

        identity = identify_native_module(
            "fada26732fbe56b7402ed353ca4a580a827fe617ee6c0ed798461a7e34d3c80c",
            "TCUWSilCIDGetter.dll",
        )
        self.assertEqual(
            sil_cid(SILChannel(provider), identity, "0", 500), ("ABCDEFGHIJKLMN12",)
        )
        self.assertEqual(
            [
                event["data"]
                for event in action.events
                if event["operation"] == "write_messages"
            ],
            [authored_frame("8213f10903"), authored_frame("8213f10904")],
        )
        self.assertIn(
            {"operation": "ioctl", "ioctl": 2, "config": ((1, 9600),)}, action.events
        )

    def test_generic_sil_flash_literal_bootstrap_and_programming(self):
        image = b"\xaa" * 1024
        descriptor = bytes.fromhex("0000000003ff0110")
        handshake = [(b"\x60", b"\x3c"), (b"\x00", b"\x3c"), (b"\x05", b"\x3c")]
        blank = [(b"\x35\x00", b"\x3c"), (b"\x50", b"\x3c\x00\x3c")]
        memory = [(b"\x75", b"\x3c" + descriptor + b"\x3c")]
        pairs = [(b"\x3c", None)] + (
            handshake * 100 + memory * 100 + blank * 100 + handshake + memory + blank
        )
        pairs += [
            (b"\x41", b"\x3c"),
            (b"\x00\x00\x00\xff" + image[:256], b""),
            (image[256:512], b""),
            (image[512:768], b""),
            (image[768:], b"\x3c"),
            (b"\x50", b"\x3c\x00\x3c"),
            (b"\x47\x00", b"\x3c"),
            (b"\x50", b"\x3c\x00\x3c"),
            (b"\x15\x00", b"\x3c"),
        ]
        for offset in range(0, 1024, 256):
            pairs += [
                (image[offset : offset + 256], b"\x3c"),
                (b"\x50", b"\x3c\x00\x3c"),
            ]
        selection = CalibrationCatalog(
            [
                ParameterTable(
                    "authored.csv",
                    "0" * 64,
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "BlockSizeInfo",
                        "CPUIDNo",
                        "ShrinkFlag",
                        "32BHFlag",
                    ),
                    (("DEMO", "0:1x1", "1", "0", "0"),),
                )
            ]
        ).select("DEMO")
        identity = identify_native_module(
            "547a52a3ebd1ff8a27fab1fe5696202222dc985777bfc38653421de7fdf43f97",
            "TCUWSilFlashWriter.dll",
        )
        provider = WireScript(pairs)
        events = []
        state_events = []
        transfer = SILTransferState2026(
            observer=lambda name, value: state_events.append((name, value))
        )
        progress = SILProgress2026(
            len(image), observer=lambda name, value: events.append((name, value))
        )
        native_polls = []
        result = sil_write(
            SILChannel(
                provider, native_cancelled=lambda: native_polls.append(True) or True
            ),
            identity,
            image,
            bytes.fromhex("01020304"),
            0,
            selection,
            "0",
            "SIL",
            progress=progress,
            transfer=transfer,
        )
        self.assertEqual(
            events,
            [("count", 0), ("percent", 0)]
            + [
                (name, value)
                for index in range(1, 9)
                for name, value in (
                    ("count", index * 256),
                    ("percent", int(index * 256 / 2048 * 100)),
                )
            ],
        )
        self.assertEqual(
            state_events, [("writing", True), ("last_block", True), ("writing", False)]
        )
        self.assertFalse(transfer.use_new_password)
        self.assertEqual((result["count"], result["percent"]), (2048, 100))
        self.assertEqual(result["bytes_written"], 1024)
        self.assertEqual(result["bytes_verified"], 1024)
        self.assertEqual(native_polls, [])
        self.assertEqual(provider.pairs, [])
        self.assertEqual(sum(e.get("data") == b"\x60" for e in provider.events), 101)
        init = next(
            e for e in provider.events if e["operation"] == "ioctl" and e["ioctl"] == 5
        )
        self.assertEqual(init["input"], bytes.fromhex("00000403020100000000"))
        failed = WireScript(pairs)
        failure_events = []
        failure_state = SILTransferState2026()
        failure_progress = SILProgress2026(
            1024,
            observer=lambda name, value: failure_events.append(
                (name, value, failure_state.status)
            ),
        )

        def fail_second_packet(event, remaining):
            if (
                event["operation"] == "write_messages"
                and event["data"] == image[256:512]
            ):
                raise NativeTransportError(17)
            return failed(event, remaining)

        with self.assertRaises(NativeJ2534Exception2026):
            sil_write(
                SILChannel(fail_second_packet),
                identity,
                image,
                bytes.fromhex("01020304"),
                0,
                selection,
                "0",
                "SIL",
                progress=failure_progress,
                transfer=failure_state,
            )
        self.assertEqual(
            failure_events,
            [
                ("count", 0, 0),
                ("percent", 0, 0),
                ("count", 256, 0),
                ("percent", 12, 0),
                ("count", 0, 0),
                ("percent", 0, 0),
            ],
        )
        self.assertEqual(
            (
                failure_state.status,
                failure_state.error,
                failure_state.j2534_error,
                failure_state.use_new_password,
            ),
            (2, 13, 17, True),
        )
        stages = {}
        for index, event in enumerate(provider.events):
            key = (event["operation"], event.get("data", b"")[:1], event.get("ioctl"))
            stages.setdefault(key, index)
        assert_fault_and_cancel_boundaries(
            self,
            pairs,
            lambda channel: sil_write(
                channel,
                identity,
                image,
                bytes.fromhex("01020304"),
                0,
                selection,
                "0",
                "SIL",
            ),
            indices=stages.values(),
        )

    def test_hino_prepare_actual_wire_and_complement_seed(self):
        pairs = [
            (authored_frame("8119f03e"), bytes.fromhex("81f0197e")),
            (authored_frame("8319f0108502"), bytes.fromhex("82f0195085")),
            (
                authored_frame("8219f02701"),
                bytes.fromhex("8ef0196701") + bytes(range(12)),
            ),
            (
                authored_frame("8e19f02702fffefdfcfbfaf9f8f7f6f5f4"),
                bytes.fromhex("82f0196702"),
            ),
            (authored_frame("8319f0108502"), bytes.fromhex("82f0195085")),
            (authored_frame("8719f0830312fe02fe01"), bytes.fromhex("82f019c303")),
        ]
        identity = identify_native_module(
            "831bbbe0cc53bf334f6ccc20581623ab048e6c3bf9bf66898cf14753e0f3e8c4",
            "TCUWSilHINOPrepareWriterForAMT.dll",
        )
        provider = WireScript(pairs)
        sil_hino_prepare(SILChannel(provider), identity)
        self.assertEqual(provider.pairs, [])
        self.assertEqual(provider.timeout, 125)
        assert_fault_and_cancel_boundaries(
            self, pairs, lambda channel: sil_hino_prepare(channel, identity)
        )

    def test_hino_cid_actual_extract_and_halt(self):
        pairs = [
            (authored_frame("8119f03e"), bytes.fromhex("81f0197e")),
            (
                authored_frame("8219f01a81"),
                bytes.fromhex("8df0195a03") + b"AUTHORED123",
            ),
            (authored_frame("8119f082"), bytes.fromhex("81f019c2")),
        ]
        identity = identify_native_module(
            "a355eb5723b6ff1fef851d0459137c73c841527462cafdc6724315ec7dba285b",
            "TCUWSilHINOCIDGetterForAMT.dll",
        )
        provider = WireScript(pairs)
        self.assertEqual(sil_hino_cid(SILChannel(provider), identity), ("AUTHORED123",))
        self.assertEqual(
            provider.events[-1], {"operation": "disconnect", "identifier": 42}
        )
        assert_fault_and_cancel_boundaries(
            self, pairs, lambda channel: sil_hino_cid(channel, identity)
        )

    def test_hino_sbl_then_data_and_explicit_addresses(self):
        selection = CalibrationCatalog(
            [
                ParameterTable(
                    "authored.csv",
                    "0" * 64,
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "SBLStartAddressSize",
                        "DATAStartAddressSize",
                    ),
                    (("DEMO", "001000\n000001", "002000\n000001"),),
                )
            ]
        ).select("DEMO")
        pairs = [
            (authored_frame("8119f034"), bytes.fromhex("82f0197484")),
            (authored_frame("8019f0053600100041"), bytes.fromhex("80f0190176")),
            (authored_frame("8119f037"), bytes.fromhex("81f01977")),
            (authored_frame("8219f03102"), bytes.fromhex("81f01971")),
            (authored_frame("8219f03101"), bytes.fromhex("81f01971")),
            (authored_frame("8119f034"), bytes.fromhex("82f0197484")),
            (authored_frame("8019f0053600200042"), bytes.fromhex("80f0190176")),
            (authored_frame("8119f037"), bytes.fromhex("81f01977")),
            (authored_frame("8219f03102"), bytes.fromhex("81f01971")),
            (authored_frame("8119f082"), bytes.fromhex("81f019c2")),
        ]
        identity = identify_native_module(
            "e573f4d0bea6318763ca9923a960d30556270450bd4e9266dfd8465e4735c586",
            "TCUWSilHINOFlashWriterForAMT.dll",
        )
        provider = WireScript(pairs)
        events = []
        state_events = []
        transfer = SILTransferState2026(
            observer=lambda name, value: state_events.append(
                (name, value, len(provider.pairs))
            )
        )
        progress = SILProgress2026(
            1, observer=lambda name, value: events.append((name, value))
        )
        self.assertEqual(
            sil_hino_write(
                SILChannel(provider),
                identity,
                b"A",
                b"B",
                selection,
                progress=progress,
                transfer=transfer,
            ),
            2,
        )
        self.assertEqual(state_events, [("writing", True, 5), ("writing", False, 0)])
        self.assertEqual(events, [("count", 1), ("percent", 100)])
        self.assertEqual(provider.pairs, [])
        self.assertEqual(provider.timeout, 125)
        for fail_download, status in ((1, 1), (2, 2)):
            failed_native = WireScript(pairs)
            download_count = [0]
            progress_events = []

            def native_failure(
                event,
                remaining,
                fail_download=fail_download,
                download_count=download_count,
                failed_native=failed_native,
            ):
                if event["operation"] == "write_messages" and event[
                    "data"
                ] == authored_frame("8119f034"):
                    download_count[0] += 1
                    if download_count[0] == fail_download:
                        raise NativeTransportError(17)
                return failed_native(event, remaining)

            failure_state = SILTransferState2026()
            failure_progress = SILProgress2026(
                1,
                count=5,
                percent=50,
                observer=lambda name, value, progress_events=progress_events: (
                    progress_events.append((name, value))
                ),
            )
            with self.assertRaises(NativeJ2534Exception2026):
                sil_hino_write(
                    SILChannel(native_failure),
                    identity,
                    b"A",
                    b"B",
                    selection,
                    progress=failure_progress,
                    transfer=failure_state,
                )
            self.assertEqual(
                (failure_state.status, failure_state.writing),
                (status, fail_download == 2),
            )
            self.assertEqual((failure_progress.count, failure_progress.percent), (0, 0))
            self.assertEqual(progress_events, [("count", 0), ("percent", 0)])
        failed = WireScript(pairs)
        downloads = [0]

        def fail_main(event, remaining):
            if event["operation"] == "write_messages" and event[
                "data"
            ] == authored_frame("8119f034"):
                downloads[0] += 1
                if downloads[0] == 2:
                    raise RuntimeError("authored main transfer failure")
            return failed(event, remaining)

        transfer = SILTransferState2026(j2534_error=77)
        with self.assertRaises(RuntimeError):
            sil_hino_write(
                SILChannel(fail_main),
                identity,
                b"A",
                b"B",
                selection,
                transfer=transfer,
            )
        self.assertEqual(
            (transfer.error, transfer.j2534_error, transfer.writing), (0, 77, True)
        )
        self.assertEqual(failed.timeout, 125)
        assert_fault_and_cancel_boundaries(
            self,
            pairs,
            lambda channel: sil_hino_write(channel, identity, b"A", b"B", selection),
        )

    def test_dcmprl_prepare_actual_seed_key_and_timeout(self):
        provider = WireScript(
            [
                (authored_frame("82c7f12701"), bytes.fromhex("84f1c767010010")),
                (authored_frame("84c7f127024b23"), bytes.fromhex("82f1c76702")),
            ]
        )
        identity = identify_native_module(
            "24dbe4b27bdcc3075e15a5166608b667471f100b5244fd23547e2d7850e97247",
            "TCUWSilDCMPRLPrepareWriter.dll",
        )
        self.assertTrue(
            sil_dcmprl_prepare(
                SILChannel(provider),
                identity,
                "31",
                "8",
                reset_requested=False,
                prepare_status=1,
            )
        )
        self.assertEqual(provider.timeout, 125)
        self.assertEqual(provider.pairs, [])
        self.assertIn(
            {"operation": "ioctl", "ioctl": 2, "config": ((12, 0),)}, provider.events
        )
        assert_fault_and_cancel_boundaries(
            self,
            [
                (authored_frame("82c7f12701"), bytes.fromhex("84f1c767010010")),
                (authored_frame("84c7f127024b23"), bytes.fromhex("82f1c76702")),
            ],
            lambda channel: sil_dcmprl_prepare(
                channel, identity, "31", "8", reset_requested=False
            ),
        )

    def test_dcmprl_version_literal_request_and_contact(self):
        provider = WireScript(
            [(authored_frame("82c7f12127"), bytes.fromhex("87f1c76127") + b"ABCDE")]
        )
        identity = identify_native_module(
            "1b85297cced5fd156cfb6e164c2a098a0e0b933553558cee78a67ad1c26c4744",
            "TCUWSilDCMPRLVersionGetter.dll",
        )
        self.assertEqual(
            sil_dcmprl_version(SILChannel(provider), identity, "8", 500),
            (("ABCDE",), "SIL"),
        )
        self.assertEqual(
            sum(
                e == {"operation": "wait", "milliseconds": 500} for e in provider.events
            ),
            14,
        )
        self.assertEqual(
            provider.events[-1], {"operation": "disconnect", "identifier": 42}
        )
        assert_fault_and_cancel_boundaries(
            self,
            [(authored_frame("82c7f12127"), bytes.fromhex("87f1c76127") + b"ABCDE")],
            lambda channel: sil_dcmprl_version(channel, identity, "8", 500),
        )

    def test_dh_software_id_uses_actual_conversion_records(self):
        provider = WireScript(
            [(authored_frame("8110f01a"), bytes.fromhex("83f0105a1234aa"))]
        )
        identity = identify_native_module(
            "94f65b4c4d9fe720c47f8cb6d369c76cdf28b26d9c10e129cfaf6569f998485f",
            "TCUWSilDHSoftwareIDGetter.dll",
        )
        table = bytes.fromhex("3412") + b"AUTHORED".ljust(12, b"\0")
        self.assertEqual(
            sil_dh_software_id(SILChannel(provider), identity, 16, table, 500),
            ("AUTHORED",),
        )
        self.assertEqual(
            provider.events[-1], {"operation": "disconnect", "identifier": 42}
        )
        assert_fault_and_cancel_boundaries(
            self,
            [(authored_frame("8110f01a"), bytes.fromhex("83f0105a1234aa"))],
            lambda channel: sil_dh_software_id(channel, identity, 16, table, 500),
        )

    def test_dcmprl_flash_full_wire_and_fault_every_stage(self):
        pairs = [
            (authored_frame("84c7f131010201"), bytes.fromhex("84f1c771010201")),
            (
                authored_frame("89c7f1340033000000000002"),
                bytes.fromhex("85f1c77430000000"),
            ),
            (authored_frame("84c7f136011122"), bytes.fromhex("82f1c77600")),
            (authored_frame("83c7f1370033"), bytes.fromhex("81f1c777")),
            (authored_frame("85c7f13102020101"), bytes.fromhex("85f1c77102020101")),
            (authored_frame("82c7f11101"), bytes.fromhex("82f1c75101")),
        ]
        identity = identify_native_module(
            "cf77caf4e127b9c2fb2e0075f594348cfa131d9254cd163c8f2ef184f68d0f54",
            "TCUWSilDCMPRLFlashWriter.dll",
        )
        provider = WireScript(pairs)
        events = []
        state_events = []
        transfer = SILTransferState2026(
            observer=lambda name, value: state_events.append((name, value))
        )
        progress = SILProgress2026(
            2, observer=lambda name, value: events.append((name, value))
        )
        self.assertEqual(
            sil_dcmprl_write(
                SILChannel(provider),
                identity,
                "31",
                "8",
                b"\x11\x22",
                500,
                progress=progress,
                transfer=transfer,
            ),
            2,
        )
        self.assertEqual(provider.timeout, 125)
        self.assertEqual(
            state_events,
            [
                ("wait_end_ms", 500),
                ("writing", True),
                ("wait_end_ms", 0),
                ("writing", False),
            ],
        )
        self.assertEqual(events, [("count", 4), ("percent", 100)])
        self.assertEqual(provider.pairs, [])
        assert_fault_and_cancel_boundaries(
            self,
            pairs,
            lambda channel: sil_dcmprl_write(
                channel, identity, "31", "8", b"\x11\x22", 500
            ),
        )

    def test_native_dcm_failure_continuation_resets_count_then_percent(self):
        identity = identify_native_module(
            "cf77caf4e127b9c2fb2e0075f594348cfa131d9254cd163c8f2ef184f68d0f54",
            "TCUWSilDCMPRLFlashWriter.dll",
        )
        events = []
        primitive = Primitive()

        def fail(event, remaining):
            if event["operation"] == "write_messages":
                raise NativeTransportError(7)
            return primitive(event, remaining)

        transfer = SILTransferState2026()
        progress = SILProgress2026(
            2,
            count=9,
            percent=90,
            observer=lambda name, value: events.append((name, value, transfer.status)),
        )
        with self.assertRaises(NativeJ2534Exception2026):
            sil_dcmprl_write(
                SILChannel(fail),
                identity,
                "31",
                "8",
                b"\x11\x22",
                500,
                progress=progress,
                transfer=transfer,
            )
        self.assertEqual((progress.count, progress.percent), (0, 0))
        self.assertEqual(events, [("count", 0, 2), ("percent", 0, 2)])
        self.assertEqual(transfer.status, 2)

    def test_native_hino_prepare_failure_uses_retained_notification_for_status(self):
        identity = identify_native_module(
            "831bbbe0cc53bf334f6ccc20581623ab048e6c3bf9bf66898cf14753e0f3e8c4",
            "TCUWSilHINOPrepareWriterForAMT.dll",
        )
        for writing in (False, True):
            provider = Primitive()

            def fail_baud(event, remaining, provider=provider):
                if event["operation"] == "ioctl" and event["ioctl"] == 2:
                    raise NativeTransportError(7)
                return provider(event, remaining)

            transfer = SILTransferState2026(writing=writing)
            with self.assertRaises(NativeJ2534Exception2026):
                sil_hino_prepare(SILChannel(fail_baud), identity, transfer=transfer)
            self.assertEqual(
                (
                    transfer.status,
                    transfer.writing,
                    transfer.error,
                    transfer.j2534_error,
                ),
                (1 + writing, writing, 1, 7),
            )

    def test_native_ecu_kind_literals(self):
        self.assertEqual(
            [ecu_kind(value) for value in ("0", "1", "", "10", "ENG")], [0, 2, 3, 3, 3]
        )

    def test_native_physical_table_and_unavailable_entries(self):
        self.assertEqual([physical_address(i, 0) for i in range(4)], [16, 19, 16, 19])
        self.assertEqual(physical_address(2, 1), 25)
        self.assertEqual(physical_address(0, 2), 22)
        for communication, kind in ((0, 1), (2, 2), (0, 3)):
            with self.assertRaises(LookupError):
                physical_address(communication, kind)
        for value in (True, -1, 4, "0"):
            with self.assertRaises(ValueError):
                physical_address(value, 0)  # type: ignore[arg-type]

    def test_init_literal_primitives(self):
        action = Primitive()
        channel = SILChannel(action)
        self.assertIsNone(channel.five_baud_init())
        channel.fast_init(16, 241, 1)
        self.assertEqual(
            action.events,
            [
                {
                    "operation": "ioctl",
                    "ioctl": 4,
                    "input": b"\x33",
                    "output_capacity": 256,
                },
                {"operation": "ioctl", "ioctl": 2, "config": ((20, 35),)},
                {"operation": "ioctl", "ioctl": 2, "config": ((21, 50),)},
                {
                    "operation": "ioctl",
                    "ioctl": 5,
                    "input": bytes.fromhex("8110f18103"),
                    "output_capacity": 4152,
                },
            ],
        )

    def test_pending_then_positive_restores_timeout(self):
        action = Primitive(
            [bytes.fromhex("83f1107f22789d"), bytes.fromhex("83f110620102e9")]
        )
        response = SILChannel(action).receive(
            bytes.fromhex("8310f1220102a9"),
            minimum=7,
            header=bytes.fromhex("83f110"),
            payload_prefix=b"\x62",
            pending_limit=1,
        )
        self.assertEqual(response[3:6], b"\x62\x01\x02")
        self.assertEqual(
            action.events[-1], {"operation": "set_timeout", "milliseconds": 125}
        )
        self.assertIn({"operation": "set_timeout", "milliseconds": 5000}, action.events)

    def test_malformed_pending_limit_io_and_cancel_restore(self):
        for reads, error in (
            ([b"x"], ValueError),
            ([bytes.fromhex("83f1107f22789d")], CommonResponseError),
        ):
            action = Primitive(reads)
            with self.assertRaises(error):
                SILChannel(action).receive(b"\x81\x10\xf1\x22", minimum=6)
            self.assertEqual(
                action.events[-1], {"operation": "set_timeout", "milliseconds": 125}
            )
        action = Primitive()
        action.fail = "read_messages"
        with self.assertRaises(OSError):
            SILChannel(action).receive(b"\x81\x10\xf1\x22", minimum=6)
        self.assertEqual(action.events[-1]["operation"], "set_timeout")
        action = Primitive()
        channel = SILChannel(action, cancelled=lambda: len(action.events) >= 1)
        with self.assertRaises(InterruptedError):
            channel.receive(b"\x81\x10\xf1\x22", minimum=6)
        # Cancellation after get_timeout prevents entry to receive, so no timeout was changed.
        self.assertEqual(action.events, [{"operation": "get_timeout"}])

    def test_exact_prepare_identity_and_native_noop(self):
        identity = identify_native_module(
            "14bc941c496e273fcf2c195609ff5cb5b4fe0bc84a5b65d54c486e7d75dfd1c0",
            "TCUWSilPrepareWriter.dll",
        )
        self.assertTrue(sil_prepare(identity))
        forged = NativeModuleIdentity(
            identity.sha256, identity.module_name, "2026", ("2026",), ()
        )
        with self.assertRaises(ValueError):
            sil_prepare(forged)

    def test_fast_init_faults_at_each_primitive(self):
        for fault in range(4):
            events = []

            def action(event, remaining, events=events, fault=fault):
                events.append(event)
                if len(events) - 1 == fault:
                    raise OSError("authored stage fault")
                if event["operation"] == "ioctl" and event["ioctl"] == 5:
                    return {"data": b"", "rx_status": 9}
                if event["operation"] == "read_messages":
                    return b"done"
                return None

            with self.assertRaises(OSError):
                SILChannel(action).fast_init(16, 241, 0)
            self.assertEqual(len(events), fault + 1)

    def test_busy_resends_but_pending_only_receives(self):
        action = Primitive(
            [
                bytes.fromhex("83f1107f22219d"),
                bytes.fromhex("83f1107f22789d"),
                bytes.fromhex("83f110620102e9"),
            ]
        )
        original = action.__call__

        def provider(event, remaining):
            if event["operation"] == "write_messages":
                action.events.append(event)
                return 1
            return original(event, remaining)

        result = SILChannel(provider).exchange(
            bytes.fromhex("8310f1220102a9"),
            minimum=7,
            payload_prefix=b"\x62",
            pending_limit=1,
            busy_limit=1,
            wait_ms=20,
        )
        self.assertEqual(result[3], 0x62)
        self.assertEqual(
            sum(e["operation"] == "write_messages" for e in action.events), 2
        )
        self.assertEqual(
            sum(e["operation"] == "read_messages" for e in action.events), 3
        )
        self.assertEqual(
            action.events[-1], {"operation": "set_timeout", "milliseconds": 125}
        )

    def test_explicit_header_length_and_pending_reset_busy_counter(self):
        responses = [
            b"\x80\xf1\x10\x03\x7f\x22\x21",
            b"\x80\xf1\x10\x03\x7f\x22\x78",
            b"\x80\xf1\x10\x03\x7f\x22\x21",
            b"\x80\xf1\x10\x01\x62",
        ]
        action = Primitive(responses)
        original = action.__call__

        def provider(event, remaining):
            if event["operation"] == "write_messages":
                action.events.append(event)
                return 1
            return original(event, remaining)

        result = SILChannel(provider).exchange(
            b"\x80\x10\xf1\x01\x22\xa4",
            minimum=5,
            payload_prefix=b"\x62",
            pending_limit=1,
            busy_limit=1,
            explicit_length=True,
        )
        self.assertEqual(result[-1], 0x62)
        self.assertEqual(
            sum(e["operation"] == "write_messages" for e in action.events), 3
        )
        self.assertEqual(sum(e["operation"] == "get_timeout" for e in action.events), 1)
        self.assertEqual(
            sil_message(b"\x22", 16, 241, explicit_length=True),
            b"\x80\x10\xf1\x01\x22\xa4",
        )

    def test_pending_limit_sends_native_stop_when_requested(self):
        action = Primitive([bytes.fromhex("83f1107f22789d")])
        original = action.__call__

        def provider(event, remaining):
            if event["operation"] == "write_messages":
                action.events.append(event)
                return 1
            return original(event, remaining)

        with self.assertRaises(CommonResponseError):
            SILChannel(provider).exchange(
                bytes.fromhex("8310f1220102a9"), minimum=6, stop_on_pending_limit=True
            )
        writes = [
            event["data"]
            for event in action.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes[-1], bytes.fromhex("8110f18204"))
        self.assertEqual(
            action.events[-1], {"operation": "set_timeout", "milliseconds": 125}
        )

    def test_exhausted_normal_budget_still_restores_timeout(self):
        action = Primitive()
        channel = SILChannel(action)
        channel.calls = 65535
        with self.assertRaises(ValueError):
            channel.receive(b"\x81\x10\xf1\x22", minimum=6)
        self.assertEqual(
            action.events[-1], {"operation": "set_timeout", "milliseconds": 125}
        )
        self.assertEqual(channel.cleanup_calls, 1)

    def test_deadline_bounds_and_no_side_effects_for_bad_input(self):
        action = Primitive()
        channel = SILChannel(action, clock=lambda: 0)
        for timeout in (False, 0, -1, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                SILChannel(action, timeout=timeout)
        for payload in (b"", bytes(256), bytearray(b"x")):
            with self.assertRaises(ValueError):
                sil_message(payload, 16, 241)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            channel.fast_init(-1, 241, 0)
        self.assertEqual(action.events, [])
        channel.clock = lambda: 31
        with self.assertRaises(TimeoutError):
            channel.five_baud_init()
        self.assertEqual(action.events, [])


if __name__ == "__main__":
    unittest.main()
