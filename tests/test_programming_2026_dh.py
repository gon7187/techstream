"""Literal controls for the recovered DH helper boundary."""

import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from scripts.calibration import CalibrationContainer
from scripts.calibration_2026 import (
    NativeArchive2026,
    native2026_archive,
    native2026_metadata,
    native2026_with_parser_parameters,
    parse_cuw_2026,
)
from scripts.calibration_catalog import CalibrationCatalog, SelectionContext
from scripts.cuw_2026 import CUWEngine2026
from scripts.cuw_persistence import (
    CUWPersistence,
    RecoveryCalibration,
    ReproInfoState,
    parse_recovery_info,
)
from scripts.demo_calibration import table
from scripts.j2534_2026 import NativeJ2534Error2026, NativePassThruError2026
from scripts.native_modules import identify_native_module
from scripts.programming import (
    NativeNegativeResponse,
    NativeProgrammingChannel,
    NativeTransportError,
)
from scripts.programming_2026_common import (
    CommonResponseError,
    ControlCommPhase2026,
    NativeGeneralParameters2026,
    NativeRuntime2026,
    NativeSecurityComposer2026,
    SecretInfoClient,
    bind_native_parameter2026,
)
from scripts.programming_2026_dh import (
    DHGateway2026,
    bind_dh_getter,
    bind_dh_prepare,
    bind_dhuds_getter,
    bind_gateway_client,
    bind_native_context,
    bind_stateful_dh_getter,
    calculate_seed_key,
    central_gateway_can_ids,
    central_gateway_request_can_id,
    change_default_session,
    change_phase5_session,
    change_reprog_gateway_session,
    change_reprogramming_mode,
    change_specific_service_session,
    check_gateway_connection,
    check_gateway_security_table_kind,
    check_gateway_specification,
    check_need_repro_center_authentication,
    checksum,
    collate_gateway_online_seed_key,
    collate_gateway_seed_key,
    convert_su_characters,
    decode_dhuds_software_ids,
    decode_p5_vehicle_info_cids,
    dh_sync_exchange,
    diagnostic_mask,
    diagnostic_mask_phase5,
    diagnostic_mask_su,
    ecu_reset,
    execute_context,
    extract_software_id,
    gateway_secret_info_identifier,
    get_dh_cids,
    get_dhuds_cids,
    get_software_info,
    get_stateful_dh_cids,
    multirom_image_segment,
    prepare_dh,
    read_current_session,
    read_dhuds_software_ids,
    read_hard_soft_info,
    read_soft_mask,
    read_software_id,
    replace_can_ids,
    request_download,
    request_seed,
    request_seed_specified_bytes,
    request_transfer_exit,
    request_verification_download,
    resume_communication,
    secret_info_type,
    send_key,
    start_sync_periodic,
    start_sync_periodic_phase5,
    stop_communication_phase5,
    su_tester_present,
    transfer_data,
    verify_checksum,
    verify_result,
    verify_soft_mask,
    verify_su_checksum,
    writable_verify_soft_mask,
    writable_write_soft_mask,
    writable_write_software_id,
    write_software_id,
)
from tests.private_evidence import read_private_bytes, require_private


def authored_general_source():
    return table(
        ["ParamFileKeySystemProtocolMicon", "M16CTypeFlag", "FORESTTypeFlag"],
        [[f"{kind}CAN383", "0", "0"] for kind in ("108", "109", "168")],
    )


def bind_dh_parameter_fixture(
    container, sources, operation, *, cpu_index=0, node=1, encoded=False, region=0
):
    sources = {"Parameter.ini": authored_general_source(), **sources}
    metadata = native2026_with_parser_parameters(
        native2026_metadata(container, node=node, cpu_index=cpu_index, region=region),
        NativeGeneralParameters2026.from_sources(sources, encoded=encoded),
    )
    return bind_native_parameter2026(
        container,
        sources,
        operation,
        cpu_index=cpu_index,
        node=node,
        encoded=encoded,
        metadata_state=metadata,
    )


def native_secret_client():
    root = Path("runtime/no-car-21/recovered")
    require_private(root)
    return SecretInfoClient.from_native_modules(
        read_private_bytes(root / "SecretInfo.dll"),
        read_private_bytes(root / "CUW.dll"),
    )


def dh_aes(identifier, seed=b"S" * 16):
    return NativeSecurityComposer2026.calculate_security_key(
        native_secret_client().get(identifier), seed
    )


def bind_authored_dh_online(test, runtime, seed, key, *, engine=None):
    """Actual113/36 producer with authored primitive chronology; no service I/O."""
    from scripts.cuw_online import OnlineKeyController2026
    from tests.test_calibration_2026 import cpu_text, cuw
    from tests.test_cuw_online import capture, configuration, step

    root = Path("runtime/no-car-21/recovered")
    require_private(root)
    if engine is None:
        engine = CUWEngine2026(read_private_bytes(root / "CUW.dll"))
        test.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(cuw(cpu_text()), region=2)
    control_bytes = read_private_bytes(root / "TCUWControlCommPhase.dll")
    worker = engine._worker
    if worker is None:
        worker = engine.bind_worker(
            ControlCommPhase2026(
                identify_native_module(
                    hashlib.sha256(control_bytes).hexdigest(),
                    "TCUWControlCommPhase.dll",
                ),
                runtime,
            )
        )
    engine.set_vin(b"JT123456789012345")
    online = OnlineKeyController2026(worker, configuration())
    chronology = capture(
        online,
        seed,
        [step("online.SetReprogrammingKey", key.hex().encode("ascii").hex())],
    )
    runtime.bind_p5_online(online, chronology, advance_clock=lambda _: None)
    return chronology


class UnitOnlineRuntime(NativeRuntime2026):
    """Unit-only malformed callback fixture; never a source-bound producer."""

    def __init__(self, value):
        super().__init__(lambda *_: None)
        self.value = value

    def call(self, operation, **values):
        if operation == "calculate_dh_gateway_online_key":
            return self.value
        return super().call(operation, **values)


class DHHelpers(unittest.TestCase):
    def test_multirom_native_record_cursor_partial_and_gap_concatenation(self):
        archive = NativeArchive2026(
            None, 0x1004, b"", ((0x1000, b"abcd"), (0x2000, b"efgh")), b""
        )
        self.assertEqual(multirom_image_segment(archive, 0x1001, 3, 0), (b"bcd", 0))
        self.assertEqual(multirom_image_segment(archive, 0x2000, 4, 1), (b"efgh", 1))
        self.assertEqual(multirom_image_segment(archive, 0x1000, 6, 0), (b"abcdef", 1))
        with self.assertRaisesRegex(ValueError, "overflow"):
            multirom_image_segment(archive, 0x1001, 2, 0)
        with self.assertRaisesRegex(ValueError, "uninitialized"):
            multirom_image_segment(archive, 0x2001, 4, 1)
        with self.assertRaises(ValueError):
            multirom_image_segment(archive, 0x1000, 0, 0)

    def test_location_hex_uses_native_two_byte_setnum(self):
        requests = []

        def exchange(ecu, request):
            requests.append(request)
            return bytes.fromhex("7b08")

        channel = NativeProgrammingChannel(exchange, "DH")
        for location in ("12", "", "AABBCC"):
            writable_write_soft_mask(channel, location)
        self.assertEqual(
            requests,
            [
                bytes.fromhex("3b080012"),
                bytes.fromhex("3b080000"),
                bytes.fromhex("3b08bbcc"),
            ],
        )

    def test_typed_primary_enum_is_not_a_driver_timeout(self):
        for error, unavailable in (
            (NativeJ2534Error2026(9), True),
            (NativePassThruError2026(9), False),
        ):

            def exchange(ecu, request, error=error):
                raise error

            channel = NativeProgrammingChannel(exchange, "DH")
            self.assertFalse(check_gateway_connection(channel))
            if unavailable:
                self.assertTrue(
                    change_reprog_gateway_session(channel, allow_unavailable=True)
                )
            else:
                with self.assertRaises(NativePassThruError2026):
                    change_reprog_gateway_session(channel, allow_unavailable=True)

    def test_verification_download_second_transfer_wire(self):
        requests = []

        def exchange(ecu, request):
            requests.append(request)
            return bytes.fromhex("7101f011200102")

        self.assertEqual(
            request_verification_download(
                NativeProgrammingChannel(exchange, "DH"),
                bytes.fromhex("12345678"),
                0x01020304,
            ),
            0x101,
        )
        self.assertEqual(requests, [bytes.fromhex("3101f0110001441234567801020304")])
        with self.assertRaises(CommonResponseError):
            request_verification_download(
                NativeProgrammingChannel(
                    lambda *_: bytes.fromhex("7101f0112001"), "DH"
                ),
                b"1234",
                1,
            )
        for size in (-1, True, 0x80000000):
            with self.assertRaises(ValueError):
                request_verification_download(
                    NativeProgrammingChannel(exchange, "DH"), b"1234", size
                )

    def test_writable_softmask_client_literals_and_failure(self):
        requests = []
        replies = iter(
            (bytes.fromhex("7b08"), bytes.fromhex("7b09"), bytes.fromhex("5a12ab"))
        )

        def exchange(ecu, request):
            requests.append(request)
            return next(replies)

        channel = NativeProgrammingChannel(exchange, "DH")
        writable_write_soft_mask(channel, "12aB")
        writable_write_software_id(channel, b"ABCDEF12345")
        writable_verify_soft_mask(channel, "12AB")
        self.assertEqual(
            requests,
            [bytes.fromhex("3b0812ab"), b"\x3b\x09" + b"12345", bytes.fromhex("1ab0")],
        )
        for reply, code in (
            (bytes.fromhex("5a12"), 0x2E),
            (bytes.fromhex("5a1234"), 0x2F),
        ):
            with self.assertRaises(CommonResponseError) as caught:
                writable_verify_soft_mask(
                    NativeProgrammingChannel(lambda *_, reply=reply: reply, "DH"),
                    "12AB",
                )
            self.assertEqual(caught.exception.code, code)
        for value in ("123", "12345", "12GG"):
            with self.assertRaises(ValueError):
                writable_write_soft_mask(channel, value)
        with self.assertRaises(ValueError):
            writable_write_software_id(channel, b"ABCDEF1234")

    def test_checksum(self):
        self.assertEqual(checksum(bytes(range(256)), b"\xff\x02"), 0x81)
        self.assertEqual(checksum(b""), 0)
        for count in (1, 2, 31, 32, 33, 63, 64, 65):
            self.assertEqual(checksum(b"\x81" * count), (0x81 * count) % 256)
        with self.assertRaises(ValueError):
            checksum(bytearray(b"x"))  # pyright: ignore[reportArgumentType]

    def test_security_wire_status_and_malformed_controls(self):
        pairs = [
            (bytes.fromhex("2701"), bytes.fromhex("670112345678aa")),
            (bytes.fromhex("27021234"), bytes.fromhex("670234")),
            (bytes.fromhex("2701"), bytes.fromhex("6701aabbccdd")),
            (bytes.fromhex("27021122"), bytes.fromhex("6702")),
            (bytes.fromhex("27023344"), bytes.fromhex("6702")),
        ]

        def exchange(ecu, request):
            expected, response = pairs.pop(0)
            self.assertEqual(request, expected)
            return response

        channel = NativeProgrammingChannel(exchange, "DH")
        self.assertEqual(request_seed(channel), bytes.fromhex("12345678"))
        send_key(channel, bytes.fromhex("1234"))
        self.assertEqual(
            request_seed(channel, flag_to_non_seed_resp_status=True),
            bytes.fromhex("aabbccdd"),
        )
        send_key(channel, bytes.fromhex("1122"), flag_to_non_send_key_resp_status=True)
        send_key(channel, bytes.fromhex("3344"), phase5=True)
        self.assertFalse(pairs)
        with self.assertRaises(ValueError):
            request_seed(
                NativeProgrammingChannel(lambda *_: bytes.fromhex("670112345678"), "DH")
            )
        with self.assertRaises(ValueError):
            send_key(
                NativeProgrammingChannel(lambda *_: bytes.fromhex("670200"), "DH"),
                b"xx",
            )

    def test_writable_identity_wire_and_mask_mismatch(self):
        pairs = [
            (bytes.fromhex("21a7"), bytes.fromhex("61a7a0b1")),
            (b"\xa0\x99ABCDE", b"\xe0\x99"),
            (b"\xa0\x99ABCDE", b"\xe0\x99\x01"),
        ]

        def exchange(ecu, request):
            expected, response = pairs.pop(0)
            self.assertEqual(request, expected)
            return response

        channel = NativeProgrammingChannel(exchange, "DH")
        verify_soft_mask(channel, "a0B1")
        write_software_id(channel, b"PREFIXABCDE")
        write_software_id(channel, b"PREFIXABCDE", write_software_id_resp_type=1)
        self.assertFalse(pairs)
        with self.assertRaises(ValueError):
            verify_soft_mask(
                NativeProgrammingChannel(lambda *_: b"\x61\xa7\xa0\xb2", "DH"), "a0B1"
            )
        with self.assertRaises(ValueError):
            write_software_id(channel, b"short")
        for expected in (" A0B1", ""):
            with self.assertRaises(CommonResponseError) as caught:
                verify_soft_mask(
                    NativeProgrammingChannel(
                        lambda *_: bytes.fromhex("61a7a0b1"), "DH"
                    ),
                    expected,
                )
            self.assertEqual(caught.exception.code, 0x2F)

    def test_dhuds_count_and_fifteen_character_truncation(self):
        self.assertEqual(decode_dhuds_software_ids(bytes.fromhex("62f18100")), ())
        response = (
            bytes.fromhex("62f18103")
            + b"1234567890123456"
            + b"\0" * 16
            + b"ID\0trailingbytes!"
            + b"extra"
        )
        self.assertEqual(
            decode_dhuds_software_ids(response), (b"123456789012345", b"ID")
        )
        writes = []

        def exchange(ecu, request):
            writes.append(request)
            return response

        self.assertEqual(
            read_dhuds_software_ids(NativeProgrammingChannel(exchange, "DH")),
            (b"123456789012345", b"ID"),
        )
        self.assertEqual(writes, [bytes.fromhex("22f181")])
        for malformed in (
            bytes.fromhex("62f181"),
            bytes.fromhex("62f18101") + b"x" * 15,
            bytes.fromhex("62f18000"),
        ):
            with self.assertRaises(ValueError):
                decode_dhuds_software_ids(malformed)

    def test_software_info_all_selectors_and_sanitization(self):
        pairs = [
            (bytes.fromhex("1a8800"), bytes.fromhex("5a880000020003")),
            (bytes.fromhex("1a8802"), b'\x5a\x88\x02ABC"\\\xff\0tail'),
            (bytes.fromhex("1a8803"), b"\x5a\x88\x03SECOND"),
        ]

        def exchange(ecu, request):
            expected, response = pairs.pop(0)
            self.assertEqual(request, expected)
            return response

        self.assertEqual(
            get_software_info(NativeProgrammingChannel(exchange, "DH")),
            (2, (b"ABC___", b"SECOND")),
        )
        self.assertFalse(pairs)
        self.assertEqual(
            get_software_info(
                NativeProgrammingChannel(lambda *_: bytes.fromhex("5a88000000"), "DH")
            ),
            (0, ()),
        )

    def test_specified_seed_options_status_and_phase5(self):
        writes = []

        def exchange(ecu, request):
            writes.append(request)
            return bytes.fromhex("670101020304ff")

        channel = NativeProgrammingChannel(exchange, "DH")
        self.assertEqual(
            request_seed_specified_bytes(channel, 4, option=3),
            bytes.fromhex("01020304"),
        )
        self.assertEqual(
            request_seed_specified_bytes(channel, 5, phase5=True),
            bytes.fromhex("01020304ff"),
        )
        self.assertEqual(writes, [bytes.fromhex("270103"), bytes.fromhex("2701")])
        with self.assertRaises(ValueError):
            request_seed_specified_bytes(channel, 4, phase5=True, option=1)
        with self.assertRaises(ValueError):
            request_seed_specified_bytes(channel, 5)

    def test_gateway_secret_identifier_and_raw_computation(self):
        self.assertEqual(gateway_secret_info_identifier(0, 0), 1)
        self.assertEqual(gateway_secret_info_identifier(1, 2), 0x15)
        self.assertEqual(gateway_secret_info_identifier(1, 3), 0x14)
        for kind, option in ((1, 0), (2, 2), (True, 2), (0, -1)):
            with self.assertRaises(ValueError):
                gateway_secret_info_identifier(kind, option)
        client = native_secret_client()
        writes = []

        def exchange(ecu, request):
            writes.append(request)
            return (
                b"\x67\x01" + bytes(range(16)) + b"\xaa"
                if request == bytes.fromhex("270103")
                else bytes.fromhex("670234")
            )

        crypto = []

        def primitive(event, remaining):
            crypto.append(event)
            return dh_aes(0x14, bytes(range(16)))

        collate_gateway_seed_key(
            NativeProgrammingChannel(exchange, "DH"),
            NativeRuntime2026(primitive),
            client,
            table_kind=1,
            option=3,
        )
        self.assertEqual(
            writes,
            [
                bytes.fromhex("270103"),
                bytes.fromhex("2702") + dh_aes(0x14, bytes(range(16))),
            ],
        )
        self.assertEqual(len(crypto), 0)

    def test_online_authentication_requires_raw_key_not_boolean(self):
        for key in (True, b"x" * 63, None):
            writes = []

            def invalid_exchange(ecu, request, writes=writes):
                writes.append(request)
                return bytes.fromhex("6701") + b"12345678" + b"\0"

            with self.assertRaises(CommonResponseError):
                collate_gateway_online_seed_key(
                    NativeProgrammingChannel(invalid_exchange, "DH"),
                    UnitOnlineRuntime(key),
                )
            self.assertEqual(writes, [bytes.fromhex("2701")])
        writes = []

        def exchange(ecu, request):
            writes.append(request)
            return (
                bytes.fromhex("6701") + b"12345678" + b"\0"
                if request == bytes.fromhex("2701")
                else bytes.fromhex("670234")
            )

        runtime = NativeRuntime2026(lambda *_: None)
        chronology = bind_authored_dh_online(self, runtime, b"12345678", b"K" * 64)
        collate_gateway_online_seed_key(
            NativeProgrammingChannel(exchange, "DH"),
            runtime,
        )
        self.assertTrue(chronology.used)
        self.assertEqual(
            writes, [bytes.fromhex("2701"), bytes.fromhex("2702") + b"K" * 64]
        )

    def test_gateway_addresses_and_periodic_ownership(self):
        self.assertEqual(
            central_gateway_can_ids(),
            (bytes.fromhex("00000786"), bytes.fromhex("0000078e")),
        )
        self.assertEqual(
            central_gateway_can_ids(online=True),
            (bytes.fromhex("000007a4"), bytes.fromhex("000007ac")),
        )
        self.assertEqual(central_gateway_request_can_id(), bytes.fromhex("0786"))
        events = []
        runtime = NativeRuntime2026(lambda event, remaining: events.append(event))
        start_sync_periodic(runtime, bytes.fromhex("00000786"), su_regulation=True)
        self.assertEqual(
            events,
            [
                {
                    "operation": "start_sync_periodic",
                    "frames": ((bytes.fromhex("000007863e01"), 0),),
                    "interval_ms": 3000,
                    "retry_ms": 100,
                    "count": 1,
                    "delay_ms": 100,
                }
            ],
        )
        runtime.release("stop_sync_periodic")
        self.assertEqual(events[-1], {"operation": "stop_sync_periodic"})
        self.assertEqual(runtime.close(), [])
        self.assertEqual(len(events), 2)

    def test_phase5_stop_and_resume_communication_literals(self):
        events = []

        def host(event, remaining):
            events.append(event)
            return 1 if event["operation"] == "write_messages" else None

        runtime = NativeRuntime2026(host)
        stop_communication_phase5(runtime)
        self.assertEqual(
            [
                event["data"].hex()
                for event in events
                if event["operation"] == "write_messages"
            ],
            [
                s
                for s in ("00000751288101", "00000777288101", "0000077ffe288101")
                for _ in range(3)
            ],
        )
        self.assertEqual(
            [event["milliseconds"] for event in events if event["operation"] == "wait"],
            [100] * 9,
        )
        events.clear()
        resume_communication(runtime)
        self.assertEqual(
            [event["data"].hex() for event in events],
            ["00000751288001", "00000777288001", "0000077ffe288001"],
        )

    def test_phase5_periodic_replacement_and_gateway_fourth_frame(self):
        events = []
        runtime = NativeRuntime2026(lambda event, remaining: events.append(event))
        start_sync_periodic(runtime, bytes.fromhex("00000786"))
        start_sync_periodic_phase5(runtime, 2)
        self.assertEqual(
            [event["operation"] for event in events],
            ["start_sync_periodic", "stop_sync_periodic", "start_sync_periodic"],
        )
        self.assertEqual(
            events[-1]["frames"],
            (
                (bytes.fromhex("000007513e80"), 0),
                (bytes.fromhex("000007773e80"), 0),
                (bytes.fromhex("0000077ffe3e80"), 128),
                (bytes.fromhex("000007863e01"), 0),
            ),
        )
        self.assertEqual(events[-1]["count"], 4)
        self.assertEqual(runtime.close(), [])
        self.assertEqual(
            [event["operation"] for event in events].count("stop_sync_periodic"), 2
        )

    def test_gateway_session_fallback_is_literal_and_optional(self):
        writes = []

        def exchange(ecu, request):
            writes.append(request)
            return (
                bytes.fromhex("5088")
                if request == bytes.fromhex("1088")
                else bytes.fromhex("7f1012")
            )

        channel = NativeProgrammingChannel(exchange, "DH")
        change_specific_service_session(channel)
        self.assertTrue(change_reprog_gateway_session(channel, allow_unavailable=True))
        with self.assertRaises(NativeNegativeResponse):
            change_reprog_gateway_session(channel)
        self.assertEqual(
            writes,
            [bytes.fromhex("1088"), bytes.fromhex("1087"), bytes.fromhex("1087")],
        )
        self.assertFalse(
            check_gateway_connection(
                NativeProgrammingChannel(lambda *_: bytes.fromhex("7f3e11"), "DH")
            )
        )
        self.assertTrue(
            check_gateway_connection(
                NativeProgrammingChannel(lambda *_: bytes.fromhex("7e00"), "DH")
            )
        )
        self.assertFalse(
            check_gateway_connection(
                NativeProgrammingChannel(lambda *_: bytes.fromhex("7e0001"), "DH")
            )
        )

    def test_native_can_id_replacement_only_exact_pair(self):
        before = (bytes.fromhex("0700"), bytes.fromhex("0708"))
        self.assertEqual(
            replace_can_ids(*before, "0786/078E"),
            (bytes.fromhex("0786"), bytes.fromhex("078e")),
        )
        for invalid in ("", "bad", "078600/078e00", "0786:078e", "/////0786"):
            self.assertEqual(replace_can_ids(*before, invalid), before)
        with self.assertRaises(ValueError):
            replace_can_ids(*before, "078X/078E")

    def test_secret_info_type_exact_override_and_fallback(self):
        for first, second, expected in (
            ("108", "383", 0x2E),
            ("141", "395", 0x38),
            ("141", "396", 0x39),
            ("202", "401", 0x3D),
            ("108", "other", 0x2D),
            ("202", "", 0x34),
            ("36", "", 0x33),
            ("17", "", 0x3E),
            ("208", "", 0x3C),
        ):
            self.assertEqual(secret_info_type(first, second), expected)
        for first, second in (
            ("141", "other"),
            (" 108", "383"),
            ("108 ", "383"),
            ("999", ""),
        ):
            with self.assertRaises(CommonResponseError):
                secret_info_type(first, second)
        self.assertEqual(secret_info_type("108\0ignored", "383"), 0x2E)

    def test_sync_exchange_pending_then_busy_retries_literal_request(self):
        events = []
        replies = [
            bytes.fromhex("0000078e7f1078"),
            bytes.fromhex("0000078e7f1021"),
            bytes.fromhex("0000078e5087"),
        ]

        def host(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 123
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                return replies.pop(0)

        runtime = NativeRuntime2026(host)
        self.assertEqual(
            dh_sync_exchange(
                runtime,
                bytes.fromhex("00000786"),
                bytes.fromhex("0000078e"),
                bytes.fromhex("1087"),
                bytes.fromhex("5087"),
                minimum=2,
            ),
            bytes.fromhex("5087"),
        )
        self.assertEqual(
            [
                event["data"].hex()
                for event in events
                if event["operation"] == "write_messages"
            ],
            ["000007861087"] * 2,
        )
        self.assertEqual(
            sum(event["operation"] == "read_specified_can_message" for event in events),
            3,
        )
        self.assertEqual(sum(event["operation"] == "lock" for event in events), 3)
        self.assertEqual(sum(event["operation"] == "unlock" for event in events), 3)
        self.assertEqual(events[-1], {"operation": "set_timeout", "milliseconds": 123})
        self.assertFalse(runtime.owns_resource("unlock"))

    def test_sync_pending_budget_and_callback_cancel_cleanup(self):
        for cancel_on in (None, "lock", "write_messages", "read_specified_can_message"):
            events = []
            cancelled = [False]

            def host(
                event,
                remaining,
                cancel_on=cancel_on,
                events=events,
                cancelled=cancelled,
            ):
                events.append(event)
                operation = event["operation"]
                if operation == cancel_on:
                    cancelled[0] = True
                if operation == "get_timeout":
                    return 123
                if operation == "write_messages":
                    return 1
                if operation == "read_specified_can_message":
                    return bytes.fromhex("0000078e7f1078")

            runtime = NativeRuntime2026(
                host, cancelled=lambda cancelled=cancelled: cancelled[0]
            )
            with self.assertRaises(
                CommonResponseError if cancel_on is None else InterruptedError
            ):
                dh_sync_exchange(
                    runtime,
                    bytes.fromhex("00000786"),
                    bytes.fromhex("0000078e"),
                    bytes.fromhex("1087"),
                    bytes.fromhex("5087"),
                    pending_limit=0,
                )
            self.assertIn("unlock", [event["operation"] for event in events])
            self.assertEqual(
                events[-1], {"operation": "set_timeout", "milliseconds": 123}
            )
            self.assertFalse(runtime.owns_resource("unlock"))

    def test_gateway_discovery_probes_literal_and_native_fallbacks(self):
        events = []
        replies = [
            bytes.fromhex("000006fe7e00"),
            bytes.fromhex("000007ac610501020304"),
            bytes.fromhex("000007ac62011e01"),
        ]

        def host(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] == "start_flow_control_filter":
                return len(events)
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                return replies.pop(0)

        runtime = NativeRuntime2026(host)
        self.assertEqual(check_gateway_security_table_kind(runtime), 0)
        self.assertEqual(check_gateway_specification(runtime), (1, False))
        check_need_repro_center_authentication(runtime)
        self.assertEqual(
            [
                event["data"].hex()
                for event in events
                if event["operation"] == "write_messages"
            ],
            ["000006f13e00", "000007a42105", "000007a422011e"],
        )
        self.assertEqual(
            sum(event["operation"] == "stop_filter" for event in events), 3
        )
        self.assertFalse(replies)
        self.assertEqual(runtime.close(), [])

    def test_gateway_discovery_timeout_and_negative_reply_rules(self):
        for code, expected in ((9, 1), (16, 1), (5, None)):
            events = []

            def host(event, remaining, code=code, events=events):
                events.append(event)
                if event["operation"] == "get_timeout":
                    return 1000
                if event["operation"] == "start_flow_control_filter":
                    return 7
                if event["operation"] == "write_messages":
                    return 1
                if event["operation"] == "read_specified_can_message":
                    raise NativeTransportError(code)

            runtime = NativeRuntime2026(host)
            if expected is None:
                with self.assertRaises(NativeTransportError):
                    check_gateway_security_table_kind(runtime)
            else:
                self.assertEqual(check_gateway_security_table_kind(runtime), expected)
                self.assertEqual(check_gateway_specification(runtime), (0, False))
            self.assertEqual(events[-1], {"operation": "stop_filter", "identifier": 7})
        events = []

        def negative(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] == "start_flow_control_filter":
                return 7
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                return bytes.fromhex("000007ac7f2112")

        self.assertEqual(
            check_gateway_specification(
                NativeRuntime2026(negative), allow_unavailable=True
            ),
            (1, True),
        )
        with self.assertRaises(CommonResponseError):
            check_gateway_specification(NativeRuntime2026(negative))
        self.assertEqual(events[-1], {"operation": "stop_filter", "identifier": 7})

    def test_seed_key_literal_rounds(self):
        self.assertEqual(
            calculate_seed_key(bytes.fromhex("00010203"), (bytes.fromhex("1020"),)),
            bytes.fromhex("57050001"),
        )
        self.assertEqual(
            calculate_seed_key(
                bytes.fromhex("00010203"), (bytes.fromhex("1020"), b"\0\0")
            ),
            bytes.fromhex("55055705"),
        )
        self.assertEqual(
            calculate_seed_key(bytes.fromhex("11223344"), ()), bytes.fromhex("11223344")
        )
        self.assertEqual(
            calculate_seed_key(bytes.fromhex("00008000"), (b"\0\0",)),
            bytes.fromhex("01000000"),
        )
        for seed, rounds in (
            (b"", ()),
            (b"abcde", ()),
            (b"abcd", (b"x",)),
            (b"abcd", (b"abc",)),
        ):
            with self.assertRaises(ValueError):
                calculate_seed_key(seed, rounds)

    def test_su_characters_slice(self):
        self.assertEqual(
            convert_su_characters(b'A"\\\x01\x7f\xff\0 Z', 1, 7), b"A_____\0 Z"
        )
        self.assertEqual(convert_su_characters(b'"', 1, 0), b'"')
        for start, count in ((-1, 1), (0, 2), (True, 1), (1, -1)):
            with self.assertRaises(ValueError):
                convert_su_characters(b"x", start, count)
        self.assertEqual(su_tester_present(), b"\0\0\x07\x86\x3e\x01")

    def test_software_id(self):
        self.assertEqual(extract_software_id(b"\x5aABCDEtail", b"PRE\0xx"), b"PREABCDE")
        self.assertEqual(extract_software_id(b"\x5aA\0BCD", b""), b"A")
        for response in (b"\x5aABCD", b"\x62ABCDE"):
            with self.assertRaises(ValueError):
                extract_software_id(response, b"")

    def test_download_literal_and_pending(self):
        writes = []

        def exchange(ecu, request):
            writes.append((ecu, request))
            return b"\x7f\x34\x78"

        channel = NativeProgrammingChannel(
            exchange, "DH", receive=lambda ecu: b"\x74\x20\x04\x00"
        )
        self.assertEqual(request_download(channel, b"\x12\x34\x56\x78", 0x102), 1023)
        self.assertEqual(writes, [("DH", bytes.fromhex("3401441234567800000102"))])

    def test_literal_wire_helpers(self):
        pairs = [
            (b"\x1a\x81", b"\x5aABCDE"),
            (b"\x36bc", b"\x76"),
            (b"\x37", b"\x77"),
            (b"\x11\x01", b"\x51"),
            (b"\x11\x01", b"\x51\x01"),
            (bytes.fromhex("3101f010"), bytes.fromhex("7101f010c7")),
            (bytes.fromhex("3101f01300"), bytes.fromhex("7101f01300")),
            (bytes.fromhex("3101f01101"), bytes.fromhex("7101f01100")),
        ]

        def exchange(ecu, request):
            expected, response = pairs.pop(0)
            self.assertEqual(request, expected)
            return response

        channel = NativeProgrammingChannel(exchange, "DH")
        self.assertEqual(read_software_id(channel, b"XY"), b"XYABCDE")
        self.assertEqual(transfer_data(channel, b"abcd", 1, 2), 3)
        request_transfer_exit(channel)
        ecu_reset(channel)
        ecu_reset(channel, phase5=True)
        verify_checksum(channel, 0xC7)
        verify_su_checksum(channel)
        verify_result(channel)
        self.assertFalse(pairs)

    def test_session_and_softmask_wire(self):
        pairs = [
            (bytes.fromhex("1089"), bytes.fromhex("5089")),
            (bytes.fromhex("1085"), bytes.fromhex("5085")),
            (bytes.fromhex("105f"), bytes.fromhex("5085")),
            (bytes.fromhex("22fd10"), bytes.fromhex("62fd10aabb")),
            (bytes.fromhex("21a7"), bytes.fromhex("61a70102030405060708")),
            (bytes.fromhex("21b0"), bytes.fromhex("61b099")),
        ]

        def exchange(ecu, request):
            expected, response = pairs.pop(0)
            self.assertEqual(request, expected)
            return response

        channel = NativeProgrammingChannel(exchange, "DH")
        change_default_session(channel)
        change_reprogramming_mode(channel)
        self.assertEqual(read_current_session(channel), 0x85)
        self.assertEqual(read_hard_soft_info(channel), bytes.fromhex("62fd10aabb"))
        self.assertEqual(read_soft_mask(channel), bytes.fromhex("61a70102030405060708"))
        self.assertEqual(
            read_soft_mask(
                channel, pid_for_read_soft_mask_id=0xB0, soft_mask_id_resp_data_size=3
            ),
            bytes.fromhex("61b099"),
        )
        self.assertFalse(pairs)
        with self.assertRaises(ValueError):
            read_soft_mask(channel, soft_mask_id_resp_data_size=1)
        with self.assertRaises(ValueError):
            read_soft_mask(NativeProgrammingChannel(lambda *_: b"\x61\xa7", "DH"))

    def test_raw_broadcast_literals_and_delays(self):
        events = []

        def host(event, remaining):
            events.append(event)
            return 1 if event["operation"] == "write_messages" else None

        runtime = NativeRuntime2026(host)
        change_phase5_session(runtime)
        expected = [
            bytes.fromhex(s)
            for s in ("000007511081", "000007771081", "0000077ffe1081")
            for _ in range(3)
        ]
        self.assertEqual(
            [e["data"] for e in events if e["operation"] == "write_messages"], expected
        )
        self.assertEqual(
            [e["tx_flags"] for e in events if e["operation"] == "write_messages"],
            [0] * 6 + [128] * 3,
        )
        self.assertEqual(
            [e["milliseconds"] for e in events if e["operation"] == "wait"], [100] * 9
        )
        events.clear()
        diagnostic_mask(runtime, extended_addressing=True)
        self.assertEqual(
            [e["data"].hex() for e in events if e["operation"] == "write_messages"],
            ["00000740fea027"] * 3,
        )
        events.clear()
        diagnostic_mask_su(runtime)
        self.assertEqual(
            [e["milliseconds"] for e in events if e["operation"] == "wait"],
            [100, 100, 2000],
        )
        events.clear()
        diagnostic_mask_phase5(runtime)
        self.assertEqual(
            [e["data"] for e in events if e["operation"] == "write_messages"],
            [
                bytes.fromhex(s)
                for s in ("000007518582", "000007778582", "0000077ffe8582")
                for _ in range(3)
            ],
        )

    def test_broadcast_fault_cancel_and_deadline(self):
        for invalid in (0, True, None, 2):
            events = []

            def host(event, remaining, events=events, invalid=invalid):
                events.append(event)
                return invalid

            with self.assertRaises(ValueError):
                diagnostic_mask(NativeRuntime2026(host))
            self.assertEqual(len(events), 1)
        with self.assertRaises(InterruptedError):
            diagnostic_mask(
                NativeRuntime2026(
                    lambda *_: self.fail("cancelled I/O"), cancelled=lambda: True
                )
            )
        now = [0.0]
        events = []

        def late(event, remaining):
            events.append(event)
            now[0] += 31
            return 1

        with self.assertRaises(TimeoutError):
            diagnostic_mask(NativeRuntime2026(late, clock=lambda: now[0]))
        self.assertEqual(len(events), 1)

    def test_transfer_failure_and_slice_bounds(self):
        channel = NativeProgrammingChannel(lambda *_: b"\x7f\x36\x72", "DH")
        with self.assertRaises(NativeNegativeResponse):
            transfer_data(channel, b"abcd", 1, 2)
        self.assertEqual(channel.attempt_count, 1)
        for offset, count in ((-1, 1), (0, 0), (4, 1), (1, 4), (True, 1)):
            with self.assertRaises(ValueError):
                transfer_data(channel, b"abcd", offset, count)
        self.assertEqual(channel.attempt_count, 1)
        with self.assertRaises(ValueError):
            verify_checksum(channel, 256)

    def test_download_fault_cancel_and_bounds(self):
        for value in (-1, 0x80000000, True):
            with self.assertRaises(ValueError):
                request_download(
                    NativeProgrammingChannel(lambda *_: b"", "DH"), b"1234", value
                )
        with self.assertRaises(NativeNegativeResponse):
            request_download(
                NativeProgrammingChannel(lambda *_: b"\x7f\x34\x31", "DH"), b"1234", 1
            )
        with self.assertRaises(InterruptedError):
            request_download(
                NativeProgrammingChannel(
                    lambda *_: self.fail("cancelled I/O"), "DH", cancelled=lambda: True
                ),
                b"1234",
                1,
            )
        with self.assertRaises(ValueError):
            request_download(
                NativeProgrammingChannel(lambda *_: b"\x74\x20\x01", "DH"), b"1234", 1
            )


class DHUDSGetterLifecycle(unittest.TestCase):
    def test_native_caller_channel_import_does_not_create_control_disconnect_owner(
        self,
    ):
        from scripts.j2534_2026 import (
            DriverMetadata2026,
            J2534Device2026,
            J2534InterfacePair2026,
            PrimitiveResult,
        )
        from scripts.programming_2026_dh import _require_dh_caller_channel

        events = []

        def provider(event, _remaining):
            events.append(event)
            if event["operation"] == "passthru_open":
                return PrimitiveResult(value=100)
            if event["operation"] == "passthru_connect":
                return PrimitiveResult(value=101)
            return PrimitiveResult()

        engine = self.engine_fixture()
        control_device = J2534Device2026(provider, background_workers=False)
        engine_device = J2534Device2026(provider, background_workers=False)
        pair = J2534InterfacePair2026(engine_device, control_device)
        runtime = NativeRuntime2026(control_device.primitive)
        image = Path(
            "runtime/no-car-21/recovered/TCUWControlCommPhase.dll"
        ).read_bytes()
        controller = ControlCommPhase2026(
            identify_native_module(
                hashlib.sha256(image).hexdigest(), "TCUWControlCommPhase.dll"
            ),
            runtime,
        )
        engine.bind_interface_pair(pair)
        engine.bind_worker(controller)
        with engine.controller_execution(controller, 1):
            with runtime.engine_device_calls(engine):
                runtime.call_owned("connect", "disconnect", protocol=6)
                self.assertTrue(runtime.owns_resource("disconnect"))
                # Unit fixture supplies the nonserialized native driver pointers.
                engine_device.set_current_driver(
                    DriverMetadata2026("authored", "fixture.dll")
                )
                exported = pair.export_from(engine_device)
            pair.import_into(control_device, exported)
            self.assertFalse(runtime.owns_resource("disconnect"))
            count, calls = len(events), runtime.calls
            _require_dh_caller_channel(runtime)
            self.assertEqual((len(events), runtime.calls), (count, calls))
            self.assertFalse(runtime.owns_resource("disconnect"))
        self.assertEqual(runtime.close(), [])
        self.assertEqual(sum(e["operation"] == "passthru_open" for e in events), 1)
        self.assertEqual(sum(e["operation"] == "passthru_connect" for e in events), 1)
        disconnected = NativeRuntime2026(
            J2534Device2026(provider, background_workers=False).primitive
        )
        count = len(events)
        with self.assertRaisesRegex(ValueError, "caller's connected channel"):
            _require_dh_caller_channel(disconnected)
        self.assertEqual(len(events), count)

    def test_empty_control_gateway_capability_and_native_boolean_semantics(self):
        import copy

        engine = self.engine_fixture()
        other_engine = self.engine_fixture()
        events = []
        runtime = NativeRuntime2026(lambda event, _: events.append(event))
        root = Path("runtime/no-car-21/recovered")
        control_bytes = (root / "TCUWControlCommPhase.dll").read_bytes()
        controller = ControlCommPhase2026(
            identify_native_module(
                hashlib.sha256(control_bytes).hexdigest(), "TCUWControlCommPhase.dll"
            ),
            runtime,
        )
        engine.bind_worker(controller)
        modules = {
            "dh_utils_module": (root / "TCUWDHUtils.dll").read_bytes(),
            "secret_info_module": (root / "SecretInfo.dll").read_bytes(),
            "cuw_module": (root / "CUW.dll").read_bytes(),
        }
        with engine.controller_execution(controller, 0):
            empty = controller.empty_control_parameter(engine)
            gateway = bind_gateway_client(runtime, empty, engine.dh_state, **modules)
            self.assertFalse(gateway._flag("FlagToNonSeed16ByteRespStatus"))
            self.assertEqual(empty.parameter.headers, ())
            self.assertEqual(empty.value("FlagToNonSeed16ByteRespStatus"), "")
            with self.assertRaises(TypeError):
                type(empty)()
            with self.assertRaises(ValueError):
                bind_gateway_client(
                    runtime, copy.copy(empty), engine.dh_state, **modules
                )
            with self.assertRaises(ValueError):
                bind_gateway_client(
                    runtime, object.__new__(type(empty)), engine.dh_state, **modules
                )
            with self.assertRaises(ValueError):
                bind_gateway_client(runtime, empty, other_engine.dh_state, **modules)
            with self.assertRaises(ValueError):
                bind_gateway_client(
                    NativeRuntime2026(lambda *_: None),
                    empty,
                    engine.dh_state,
                    **modules,
                )
            container = engine.native_metadata.source_container
            assert isinstance(container, CalibrationContainer)
            values = {
                "ParamFileKeySystemProtocolMicon": "108CAN383",
                "DLLFileNameForPrepareWrite": "TCUWCanDHPrepareWriter.dll",
                "FlagToNonSeed16ByteRespStatus": "2",
            }
            selection = bind_dh_parameter_fixture(
                container,
                {"108CAN383.ini": table(list(values), [list(values.values())])},
                "prepare",
            )
            selected = bind_gateway_client(
                runtime, selection, engine.dh_state, **modules
            )
            self.assertTrue(selected._flag("FlagToNonSeed16ByteRespStatus"))
            legacy = CalibrationCatalog.from_tables(
                {"unit.csv": table(list(values), [list(values.values())])},
                encoded=False,
            ).select("108CAN383")
            legacy_gateway = DHGateway2026(
                runtime, legacy, gateway.identity, gateway.secret_info
            )
            with self.assertRaises(ValueError):
                legacy_gateway._flag("FlagToNonSeed16ByteRespStatus")
            # Unit state control: LoadParameter replaces the constructor-empty pool.
            controller._retained_parameter_pool = (selection,)
            with self.assertRaises(ValueError):
                gateway.start_reprogramming_mode_for_multi_types()
        with self.assertRaises(ValueError):
            gateway.start_reprogramming_mode_for_multi_types()
        self.assertEqual(events, [])

    def test_canonical_gateway_prepare_session_and_raw_authentication(self):
        engine = self.engine_fixture()
        assert engine._source is not None
        container = parse_cuw_2026(engine._source)
        assert isinstance(container, CalibrationContainer)
        for su in (False, True):
            values = {
                "ParamFileKeySystemProtocolMicon": "108CAN383",
                "DLLFileNameForPrepareWrite": "TCUWCanDHGatewayPrepareWriter.dll",
                "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
                "CanIDForPrepareWrite": "0700/0708",
                "FlagToSURegulation": str(int(su)),
            }
            source = table(list(values), [list(values.values())])
            selection = bind_dh_parameter_fixture(
                container, {"108CAN383.ini": source}, "prepare", encoded=False
            )
            attachments = {
                name: Path("runtime/no-car-21/recovered", filename).read_bytes()
                for name, filename in (
                    ("selected_module", values["DLLFileNameForPrepareWrite"]),
                    ("dh_utils_module", "TCUWDHUtils.dll"),
                    ("secret_info_module", "SecretInfo.dll"),
                    ("cuw_module", "CUW.dll"),
                )
            }
            identity = identify_native_module(
                hashlib.sha256(attachments["selected_module"]).hexdigest(),
                values["DLLFileNameForPrepareWrite"],
            )
            context = bind_native_context(
                container,
                1,
                (),
                selection,
                identity,
                attachments,
                {"dh_state": engine.dh_state},
            )
            events, requests, pending = [], [], []

            def host(
                event,
                remaining,
                events=events,
                requests=requests,
                pending=pending,
                context=context,
                su=su,
            ):
                events.append(event)
                operation = event["operation"]
                if operation == "get_timeout":
                    return 110
                if operation == "get_send_timeout":
                    return 120
                if operation == "start_flow_control_filter":
                    return 17
                if operation == "is_sending_sync_periodic":
                    return False
                if operation == "calculate_dh_gateway_key":
                    self.assertEqual(event["seed"], b"S" * 16)
                    assert context.secret_info is not None
                    self.assertTrue(
                        event["secret"] == context.secret_info.get(0x15 if su else 2)
                    )
                    return dh_aes(0x15 if su else 2)
                if operation == "write_messages":
                    pdu = event["data"][4:]
                    if event["data"].startswith(bytes.fromhex("00000700")):
                        requests.append(pdu)
                        replies = {
                            bytes.fromhex("105f"): bytes.fromhex("5002"),
                            bytes.fromhex("1089"): bytes.fromhex("5089"),
                            bytes.fromhex("1085"): bytes.fromhex("5085"),
                            bytes.fromhex("270102"): bytes.fromhex("6701")
                            + b"S" * 16
                            + b"\0",
                            bytes.fromhex("2702")
                            + dh_aes(0x15 if su else 2): bytes.fromhex("670234"),
                        }
                        pending.append(replies[pdu])
                    return 1
                if operation == "read_specified_can_message":
                    return bytes.fromhex("00000708") + pending.pop(0)

            runtime = NativeRuntime2026(host)
            result = execute_context(context, runtime)
            self.assertIs(result["native_return"], True)
            self.assertEqual(result["state"], "prepare_completed")
            self.assertEqual(
                requests,
                [
                    bytes.fromhex("105f"),
                    bytes.fromhex("1089"),
                    bytes.fromhex("1085"),
                    bytes.fromhex("270102"),
                    bytes.fromhex("2702") + dh_aes(0x15 if su else 2),
                ],
            )
            self.assertEqual(
                events[-2:],
                [
                    {"operation": "set_timeout", "milliseconds": 110},
                    {"operation": "set_send_timeout", "milliseconds": 120},
                ],
            )
            self.assertEqual(runtime.close(), [])

    def test_canonical_dhuds_prepare_1002_authentication_and_native_catch(self):
        for kind in ("108", "109"):
            engine = self.engine_fixture(kind=kind)
            assert engine._source is not None
            container = parse_cuw_2026(engine._source)
            assert isinstance(container, CalibrationContainer)
            values = {
                "ParamFileKeySystemProtocolMicon": f"{kind}CAN383",
                "DLLFileNameForPrepareWrite": "TCUWCanDHUDSPrepareWriter.dll",
                "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
                "CanIDForPrepareWrite": "0700/0708",
                "CanIDForGetCID": "0710/0718",
                "FlagToNonChangeReprogGWModeProcess": "1",
            }
            selection = bind_dh_parameter_fixture(
                container,
                {f"{kind}CAN383.ini": table(list(values), [list(values.values())])},
                "prepare",
                encoded=False,
            )
            attachments = {
                name: Path("runtime/no-car-21/recovered", filename).read_bytes()
                for name, filename in (
                    ("selected_module", values["DLLFileNameForPrepareWrite"]),
                    ("dh_utils_module", "TCUWDHUtils.dll"),
                    ("secret_info_module", "SecretInfo.dll"),
                    ("cuw_module", "CUW.dll"),
                )
            }
            identity = identify_native_module(
                hashlib.sha256(attachments["selected_module"]).hexdigest(),
                values["DLLFileNameForPrepareWrite"],
            )
            context = bind_native_context(
                container,
                1,
                (),
                selection,
                identity,
                attachments,
                {"dh_state": engine.dh_state},
            )
            for failure in (False, True):
                events, requests, pending = [], [], []
                active = [False]
                engine.dh_state.record_native_error(2, 123, 17)

                def host(
                    event,
                    remaining,
                    events=events,
                    requests=requests,
                    pending=pending,
                    active=active,
                    failure=failure,
                    kind=kind,
                    context=context,
                ):
                    events.append(event)
                    operation = event["operation"]
                    if operation == "get_timeout":
                        return 110
                    if operation == "get_send_timeout":
                        return 120
                    if operation == "start_flow_control_filter":
                        return sum(e["operation"] == operation for e in events)
                    if operation == "start_sync_periodic":
                        active[0] = True
                    if operation == "stop_sync_periodic":
                        active[0] = False
                    if operation == "is_sending_sync_periodic":
                        return active[0]
                    if operation == "calculate_dh_gateway_key":
                        assert context.secret_info is not None
                        self.assertTrue(
                            event["secret"]
                            == context.secret_info.get(0x17 if kind == "109" else 0x18)
                        )
                        self.assertEqual(event["seed"], b"S" * 16)
                        return dh_aes(0x17 if kind == "109" else 0x18)
                    if operation == "write_messages":
                        data = event["data"]
                        if data[:4] in (
                            bytes.fromhex("000007a4"),
                            bytes.fromhex("00000710"),
                            bytes.fromhex("00000700"),
                        ):
                            requests.append(data)
                            if data[4:] == bytes.fromhex("2105"):
                                pending.append(NativeJ2534Error2026(9))
                            elif data[4:] == bytes.fromhex("1002"):
                                pending.append(bytes.fromhex("00000718500200000000"))
                            elif data[4:] == bytes.fromhex("2701"):
                                pending.append(
                                    bytes.fromhex("000007086701") + b"S" * 16 + b"\0"
                                )
                            elif data[4:] == bytes.fromhex("2702") + dh_aes(
                                0x17 if kind == "109" else 0x18
                            ):
                                pending.append(
                                    bytes.fromhex("000007087f2735")
                                    if failure
                                    else bytes.fromhex("00000708670234")
                                )
                            else:
                                self.fail(data.hex())
                        return 1
                    if operation == "read_specified_can_message":
                        reply = pending.pop(0)
                        if isinstance(reply, Exception):
                            raise reply
                        return reply

                runtime = NativeRuntime2026(host)
                result = execute_context(context, runtime)
                self.assertEqual(
                    result["state"], "failed" if failure else "prepare_completed"
                )
                self.assertFalse(pending)
                self.assertEqual(
                    [p[4:] for p in requests],
                    [
                        bytes.fromhex("2105"),
                        bytes.fromhex("1002"),
                        bytes.fromhex("2701"),
                        bytes.fromhex("2702") + dh_aes(0x17 if kind == "109" else 0x18),
                    ],
                )
                self.assertEqual(engine.dh_state.central_gateway_type, 1)
                self.assertEqual(engine.dh_state.error_kind, 1 if failure else 2)
                self.assertEqual(engine.dh_state.passthru_error, 17)
                self.assertEqual(sum(e["operation"] == "lock" for e in events), 3)
                self.assertIn({"operation": "wait", "milliseconds": 1000}, events)
                self.assertEqual(
                    events[-2:],
                    [
                        {"operation": "set_timeout", "milliseconds": 110},
                        {"operation": "set_send_timeout", "milliseconds": 120},
                    ],
                )
                self.assertEqual(active[0], not failure)
                self.assertEqual(runtime.close(), [])

    def test_canonical_p5dhuds_prepare_short_authentication_and_fixed_wait(self):
        for kind in ("108", "168"):
            engine = self.engine_fixture(kind=kind)
            assert engine._source is not None
            container = parse_cuw_2026(engine._source)
            assert isinstance(container, CalibrationContainer)
            values = {
                "ParamFileKeySystemProtocolMicon": f"{kind}CAN383",
                "DLLFileNameForPrepareWrite": "TCUWP5CanDHUDSPrepareWriter.dll",
                "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
                "CanIDForPrepareWrite": "0700/0708",
                "CanIDForGetCID": "0710/0718",
                "FlagToNonChangeReprogGWModeProcess": "1",
                "WaitTimeAfterReprogrammingMode": "3",
            }
            selection = bind_dh_parameter_fixture(
                container,
                {f"{kind}CAN383.ini": table(list(values), [list(values.values())])},
                "prepare",
                encoded=False,
            )
            attachments = {
                name: Path("runtime/no-car-21/recovered", filename).read_bytes()
                for name, filename in (
                    ("selected_module", values["DLLFileNameForPrepareWrite"]),
                    ("dh_utils_module", "TCUWDHUtils.dll"),
                    ("secret_info_module", "SecretInfo.dll"),
                    ("cuw_module", "CUW.dll"),
                )
            }
            identity = identify_native_module(
                hashlib.sha256(attachments["selected_module"]).hexdigest(),
                values["DLLFileNameForPrepareWrite"],
            )
            context = bind_native_context(
                container,
                1,
                (),
                selection,
                identity,
                attachments,
                {"dh_state": engine.dh_state},
            )
            for failure in (False, True):
                events, requests, pending = [], [], []
                active = [False]
                engine.dh_state.record_native_error(2, 123, 17)

                def host(
                    event,
                    remaining,
                    events=events,
                    requests=requests,
                    pending=pending,
                    active=active,
                    failure=failure,
                    kind=kind,
                    context=context,
                ):
                    events.append(event)
                    operation = event["operation"]
                    if operation == "get_timeout":
                        return 110
                    if operation == "get_send_timeout":
                        return 120
                    if operation == "start_flow_control_filter":
                        return sum(e["operation"] == operation for e in events)
                    if operation == "start_sync_periodic":
                        active[0] = True
                    if operation == "stop_sync_periodic":
                        active[0] = False
                    if operation == "is_sending_sync_periodic":
                        return active[0]
                    if operation == "calculate_dh_gateway_key":
                        assert context.secret_info is not None
                        self.assertTrue(
                            event["secret"]
                            == context.secret_info.get(0x35 if kind == "168" else 0x3B)
                        )
                        self.assertEqual(event["seed"], b"S" * 16)
                        return dh_aes(0x35 if kind == "168" else 0x3B)
                    if operation == "write_messages":
                        data = event["data"]
                        if data[:4] in (
                            bytes.fromhex("000007a4"),
                            bytes.fromhex("00000710"),
                            bytes.fromhex("00000700"),
                        ):
                            requests.append(data)
                            if data[4:] == bytes.fromhex("2105"):
                                pending.append(NativeJ2534Error2026(9))
                            elif data[4:] == bytes.fromhex("1002"):
                                pending.append(bytes.fromhex("00000718500200000000"))
                            elif data[4:] == bytes.fromhex("2701"):
                                pending.append(
                                    bytes.fromhex("000007086701") + b"S" * 16
                                )
                            elif data[4:] == bytes.fromhex("2702") + dh_aes(
                                0x35 if kind == "168" else 0x3B
                            ):
                                pending.append(
                                    bytes.fromhex("000007087f2735")
                                    if failure
                                    else bytes.fromhex("000007086702")
                                )
                            else:
                                self.fail(data.hex())
                        return 1
                    if operation == "read_specified_can_message":
                        reply = pending.pop(0)
                        if isinstance(reply, Exception):
                            raise reply
                        return reply

                runtime = NativeRuntime2026(host)
                result = execute_context(context, runtime)
                self.assertEqual(
                    result["state"], "failed" if failure else "prepare_completed"
                )
                self.assertFalse(pending)
                self.assertEqual(
                    [p[4:] for p in requests],
                    [
                        bytes.fromhex("2105"),
                        bytes.fromhex("1002"),
                        bytes.fromhex("2701"),
                        bytes.fromhex("2702") + dh_aes(0x35 if kind == "168" else 0x3B),
                    ],
                )
                self.assertEqual(engine.dh_state.central_gateway_type, 1)
                self.assertEqual(engine.dh_state.error_kind, 1 if failure else 2)
                self.assertEqual(engine.dh_state.passthru_error, 17)
                self.assertEqual(sum(e["operation"] == "lock" for e in events), 3)
                self.assertIn({"operation": "wait", "milliseconds": 1000}, events)
                self.assertEqual(
                    events[-2:],
                    [
                        {"operation": "set_timeout", "milliseconds": 110},
                        {"operation": "set_send_timeout", "milliseconds": 120},
                    ],
                )
                self.assertEqual(active[0], not failure)
                self.assertEqual(runtime.close(), [])

    def test_canonical_dhuds_retry_retains_write_row_and_native_bool(self):
        for kind in ("108", "109"):
            engine = self.engine_fixture(kind=kind)
            assert engine._source is not None
            container = parse_cuw_2026(engine._source)
            assert isinstance(container, CalibrationContainer)
            values = {
                "ParamFileKeySystemProtocolMicon": f"{kind}CAN383",
                "DLLFileNameForFlashWrite": "TCUWCanDHUDSFlashWriter.dll",
                "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
                "CanIDForPrepareWrite": "0700/0708",
                "CanIDForGetCID": "0710/0718",
                "FlagToNonChangeReprogGWModeProcess": "1",
            }
            selection = bind_dh_parameter_fixture(
                container,
                {f"{kind}CAN383.ini": table(list(values), [list(values.values())])},
                "write",
                encoded=False,
            )
            attachments = {
                name: Path("runtime/no-car-21/recovered", filename).read_bytes()
                for name, filename in (
                    ("selected_module", values["DLLFileNameForFlashWrite"]),
                    ("dh_utils_module", "TCUWDHUtils.dll"),
                    ("secret_info_module", "SecretInfo.dll"),
                    ("cuw_module", "CUW.dll"),
                )
            }
            attachments["retry_prepare_module"] = Path(
                "runtime/no-car-21/recovered",
                "TCUWP5CanDHUDSPrepareWriter.dll"
                if values["DLLFileNameForFlashWrite"].startswith("TCUWP5")
                else "TCUWCanDHUDSPrepareWriter.dll",
            ).read_bytes()
            identity = identify_native_module(
                hashlib.sha256(attachments["selected_module"]).hexdigest(),
                values["DLLFileNameForFlashWrite"],
            )
            context = bind_native_context(
                container,
                1,
                (),
                selection,
                identity,
                attachments,
                {"dh_state": engine.dh_state, "operation": "recovery"},
            )
            for failure in (False, True):
                events, requests, pending = [], [], []
                active = [False]
                engine.dh_state.record_native_error(2, 123, 17)

                def host(
                    event,
                    remaining,
                    events=events,
                    requests=requests,
                    pending=pending,
                    active=active,
                    failure=failure,
                    kind=kind,
                    context=context,
                ):
                    events.append(event)
                    operation = event["operation"]
                    if operation == "get_timeout":
                        return 110
                    if operation == "get_send_timeout":
                        return 120
                    if operation == "start_flow_control_filter":
                        return sum(e["operation"] == operation for e in events)
                    if operation == "start_sync_periodic":
                        active[0] = True
                    if operation == "stop_sync_periodic":
                        active[0] = False
                    if operation == "is_sending_sync_periodic":
                        return active[0]
                    if operation == "calculate_dh_gateway_key":
                        assert context.secret_info is not None
                        self.assertTrue(
                            event["secret"]
                            == context.secret_info.get(0x17 if kind == "109" else 0x18)
                        )
                        self.assertEqual(event["seed"], b"S" * 16)
                        return dh_aes(0x17 if kind == "109" else 0x18)
                    if operation == "write_messages":
                        data = event["data"]
                        if data[:4] in (
                            bytes.fromhex("000007a4"),
                            bytes.fromhex("00000710"),
                            bytes.fromhex("00000700"),
                        ):
                            requests.append(data)
                            if data[4:] == bytes.fromhex("2105"):
                                pending.append(NativeJ2534Error2026(9))
                            elif data[4:] == bytes.fromhex("1002"):
                                pending.append(bytes.fromhex("00000718500200000000"))
                            elif data[4:] == bytes.fromhex("2701"):
                                pending.append(
                                    bytes.fromhex("000007086701") + b"S" * 16 + b"\0"
                                )
                            elif data[4:] == bytes.fromhex("2702") + dh_aes(
                                0x17 if kind == "109" else 0x18
                            ):
                                pending.append(
                                    bytes.fromhex("000007087f2735")
                                    if failure
                                    else bytes.fromhex("00000708670234")
                                )
                            else:
                                self.fail(data.hex())
                        return 1
                    if operation == "read_specified_can_message":
                        reply = pending.pop(0)
                        if isinstance(reply, Exception):
                            raise reply
                        return reply

                runtime = NativeRuntime2026(host)
                result = execute_context(context, runtime)
                self.assertEqual(
                    result["state"], "failed" if failure else "prepare_retry_completed"
                )
                self.assertFalse(pending)
                self.assertEqual(
                    [p[4:] for p in requests],
                    [
                        bytes.fromhex("2105"),
                        bytes.fromhex("1002"),
                        bytes.fromhex("2701"),
                        bytes.fromhex("2702") + dh_aes(0x17 if kind == "109" else 0x18),
                    ],
                )
                self.assertEqual(engine.dh_state.central_gateway_type, 1)
                self.assertEqual(engine.dh_state.error_kind, 1 if failure else 2)
                self.assertEqual(engine.dh_state.passthru_error, 17)
                self.assertEqual(sum(e["operation"] == "lock" for e in events), 3)
                self.assertIn({"operation": "wait", "milliseconds": 1000}, events)
                self.assertEqual(
                    events[-2:],
                    [
                        {"operation": "set_timeout", "milliseconds": 110},
                        {"operation": "set_send_timeout", "milliseconds": 120},
                    ],
                )
                self.assertEqual(active[0], not failure)
                self.assertEqual(runtime.close(), [])

    def test_canonical_p5dhuds_retry_retains_write_row_and_native_bool(self):
        for kind in ("108", "168"):
            engine = self.engine_fixture(kind=kind)
            assert engine._source is not None
            container = parse_cuw_2026(engine._source)
            assert isinstance(container, CalibrationContainer)
            values = {
                "ParamFileKeySystemProtocolMicon": f"{kind}CAN383",
                "DLLFileNameForFlashWrite": "TCUWP5CanDHUDSFlashWriter.dll",
                "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
                "CanIDForPrepareWrite": "0700/0708",
                "CanIDForGetCID": "0710/0718",
                "FlagToNonChangeReprogGWModeProcess": "1",
                "WaitTimeAfterReprogrammingMode": "3",
            }
            selection = bind_dh_parameter_fixture(
                container,
                {f"{kind}CAN383.ini": table(list(values), [list(values.values())])},
                "write",
                encoded=False,
            )
            attachments = {
                name: Path("runtime/no-car-21/recovered", filename).read_bytes()
                for name, filename in (
                    ("selected_module", values["DLLFileNameForFlashWrite"]),
                    ("dh_utils_module", "TCUWDHUtils.dll"),
                    ("secret_info_module", "SecretInfo.dll"),
                    ("cuw_module", "CUW.dll"),
                )
            }
            attachments["retry_prepare_module"] = Path(
                "runtime/no-car-21/recovered",
                "TCUWP5CanDHUDSPrepareWriter.dll"
                if values["DLLFileNameForFlashWrite"].startswith("TCUWP5")
                else "TCUWCanDHUDSPrepareWriter.dll",
            ).read_bytes()
            identity = identify_native_module(
                hashlib.sha256(attachments["selected_module"]).hexdigest(),
                values["DLLFileNameForFlashWrite"],
            )
            context = bind_native_context(
                container,
                1,
                (),
                selection,
                identity,
                attachments,
                {"dh_state": engine.dh_state, "operation": "recovery"},
            )
            for failure in (False, True):
                events, requests, pending = [], [], []
                active = [False]
                engine.dh_state.record_native_error(2, 123, 17)

                def host(
                    event,
                    remaining,
                    events=events,
                    requests=requests,
                    pending=pending,
                    active=active,
                    failure=failure,
                    kind=kind,
                    context=context,
                ):
                    events.append(event)
                    operation = event["operation"]
                    if operation == "get_timeout":
                        return 110
                    if operation == "get_send_timeout":
                        return 120
                    if operation == "start_flow_control_filter":
                        return sum(e["operation"] == operation for e in events)
                    if operation == "start_sync_periodic":
                        active[0] = True
                    if operation == "stop_sync_periodic":
                        active[0] = False
                    if operation == "is_sending_sync_periodic":
                        return active[0]
                    if operation == "calculate_dh_gateway_key":
                        assert context.secret_info is not None
                        self.assertTrue(
                            event["secret"]
                            == context.secret_info.get(0x35 if kind == "168" else 0x3B)
                        )
                        self.assertEqual(event["seed"], b"S" * 16)
                        return dh_aes(0x35 if kind == "168" else 0x3B)
                    if operation == "write_messages":
                        data = event["data"]
                        if data[:4] in (
                            bytes.fromhex("000007a4"),
                            bytes.fromhex("00000710"),
                            bytes.fromhex("00000700"),
                        ):
                            requests.append(data)
                            if data[4:] == bytes.fromhex("2105"):
                                pending.append(NativeJ2534Error2026(9))
                            elif data[4:] == bytes.fromhex("1002"):
                                pending.append(bytes.fromhex("00000718500200000000"))
                            elif data[4:] == bytes.fromhex("2701"):
                                pending.append(
                                    bytes.fromhex("000007086701") + b"S" * 16
                                )
                            elif data[4:] == bytes.fromhex("2702") + dh_aes(
                                0x35 if kind == "168" else 0x3B
                            ):
                                pending.append(
                                    bytes.fromhex("000007087f2735")
                                    if failure
                                    else bytes.fromhex("000007086702")
                                )
                            else:
                                self.fail(data.hex())
                        return 1
                    if operation == "read_specified_can_message":
                        reply = pending.pop(0)
                        if isinstance(reply, Exception):
                            raise reply
                        return reply

                runtime = NativeRuntime2026(host)
                result = execute_context(context, runtime)
                self.assertEqual(
                    result["state"], "failed" if failure else "prepare_retry_completed"
                )
                self.assertFalse(pending)
                self.assertEqual(
                    [p[4:] for p in requests],
                    [
                        bytes.fromhex("2105"),
                        bytes.fromhex("1002"),
                        bytes.fromhex("2701"),
                        bytes.fromhex("2702") + dh_aes(0x35 if kind == "168" else 0x3B),
                    ],
                )
                self.assertEqual(engine.dh_state.central_gateway_type, 1)
                self.assertEqual(engine.dh_state.error_kind, 1 if failure else 2)
                self.assertEqual(engine.dh_state.passthru_error, 17)
                self.assertEqual(sum(e["operation"] == "lock" for e in events), 3)
                self.assertIn({"operation": "wait", "milliseconds": 1000}, events)
                self.assertEqual(
                    events[-2:],
                    [
                        {"operation": "set_timeout", "milliseconds": 110},
                        {"operation": "set_send_timeout", "milliseconds": 120},
                    ],
                )
                self.assertEqual(active[0], not failure)
                self.assertEqual(runtime.close(), [])

    def test_canonical_19pf_prepare_physical_and_online_authentication_order(self):
        for physical in (True, False):
            engine = self.engine_fixture(region=2)
            assert engine._source is not None
            container = parse_cuw_2026(engine._source)
            assert isinstance(container, CalibrationContainer)
            values = {
                "ParamFileKeySystemProtocolMicon": "108CAN383",
                "DLLFileNameForPrepareWrite": "TCUWCanDH19PFSURegGatewayPrepareWriter.dll",
                "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
                "CanIDForPrepareWrite": "0044/004c" if physical else "0003/000b",
            }
            selection = bind_dh_parameter_fixture(
                container,
                {"108CAN383.ini": table(list(values), [list(values.values())])},
                "prepare",
                encoded=False,
                region=2,
            )
            attachments = {
                name: Path("runtime/no-car-21/recovered", filename).read_bytes()
                for name, filename in (
                    ("selected_module", values["DLLFileNameForPrepareWrite"]),
                    ("dh_utils_module", "TCUWDHUtils.dll"),
                    ("secret_info_module", "SecretInfo.dll"),
                    ("cuw_module", "CUW.dll"),
                )
            }
            identity = identify_native_module(
                hashlib.sha256(attachments["selected_module"]).hexdigest(),
                values["DLLFileNameForPrepareWrite"],
            )
            context = bind_native_context(
                container,
                1,
                (),
                selection,
                identity,
                attachments,
                {"dh_state": engine.dh_state},
            )
            events, requests, pending, secrets = [], [], [], []
            active = [False]

            def host(
                event,
                remaining,
                events=events,
                requests=requests,
                pending=pending,
                secrets=secrets,
                active=active,
                context=context,
            ):
                events.append(event)
                op = event["operation"]
                if op in ("get_timeout", "get_send_timeout"):
                    return 111
                if op == "start_flow_control_filter":
                    return len(events)
                if op == "is_sending_sync_periodic":
                    return active[0]
                if op == "start_sync_periodic":
                    active[0] = True
                if op == "stop_sync_periodic":
                    active[0] = False
                if op == "calculate_dh_gateway_key":
                    assert context.secret_info is not None
                    self.assertEqual(event["seed"], b"S" * 16)
                    secrets.append(
                        next(
                            i
                            for i in (0x14, 0x15)
                            if event["secret"] == context.secret_info.get(i)
                        )
                    )
                    return b"K" * 16
                if op == "write_messages":
                    data = event["data"]
                    if data[:4] in (
                        bytes.fromhex("00000044"),
                        bytes.fromhex("000007a4"),
                        bytes.fromhex("00000786"),
                    ):
                        requests.append(data)
                        pdu = data[4:]
                        if pdu == bytes.fromhex("2105"):
                            reply = bytes.fromhex("610501020304")
                        elif pdu == bytes.fromhex("22011e"):
                            reply = bytes.fromhex("62011e01")
                        elif pdu[0] == 0x10:
                            reply = bytes((0x50, pdu[1]))
                        elif pdu[:2] == bytes.fromhex("2701"):
                            reply = (
                                bytes.fromhex("6701")
                                + b"S" * (8 if pdu[-1] in (6, 7) else 16)
                                + b"\0"
                            )
                        elif pdu[:2] == bytes.fromhex("2702"):
                            reply = bytes.fromhex("670234")
                        else:
                            self.fail(data.hex())
                        pending.append(
                            (int.from_bytes(data[:4], "big") + 8).to_bytes(4, "big")
                            + reply
                        )
                    return 1
                if op == "read_specified_can_message":
                    return pending.pop(0)

            runtime = NativeRuntime2026(host)
            chronology = bind_authored_dh_online(
                self, runtime, b"S" * 8, b"O" * 64, engine=engine
            )
            result = execute_context(context, runtime)
            self.assertTrue(chronology.used)
            self.assertIs(result["native_return"], True)
            self.assertEqual(result["state"], "prepare_completed")
            self.assertFalse(pending)
            self.assertEqual(engine.dh_state.central_gateway_type, 2)
            self.assertEqual(secrets, [])
            self.assertEqual(
                [p[4:] for p in requests],
                [
                    bytes.fromhex("2105"),
                    bytes.fromhex("22011e"),
                    bytes.fromhex("1085" if physical else "1087"),
                    bytes.fromhex("270106" if physical else "270107"),
                    b"\x27\x02" + b"O" * 64,
                    bytes.fromhex("270102" if physical else "270103"),
                    b"\x27\x02" + dh_aes(0x15 if physical else 0x14),
                    bytes.fromhex("1087" if physical else "1085"),
                    bytes.fromhex("270103" if physical else "270102"),
                    b"\x27\x02" + dh_aes(0x14 if physical else 0x15),
                ],
            )
            periodic = next(
                e for e in events if e["operation"] == "start_sync_periodic"
            )
            self.assertEqual(
                periodic["frames"],
                ((bytes.fromhex("000007a43e01" if physical else "000007863e01"), 0),),
            )
            self.assertIn({"operation": "set_timeout", "milliseconds": 0}, events)
            self.assertEqual(
                events[-2:],
                [
                    {"operation": "set_timeout", "milliseconds": 111},
                    {"operation": "set_send_timeout", "milliseconds": 111},
                ],
            )
            self.assertTrue(active[0])
            self.assertEqual(runtime.close(), [])

            def failed_key(event, remaining, host=host):
                if (
                    event["operation"] == "write_messages"
                    and event["data"][4:] == b"\x27\x02" + b"O" * 64
                ):
                    raise NativeJ2534Error2026(5)
                return host(event, remaining)

            runtime.action = runtime.cleanup_action = failed_key
            bind_authored_dh_online(self, runtime, b"S" * 8, b"O" * 64, engine=engine)
            result = execute_context(context, runtime)
            self.assertEqual(result["state"], "failed")
            self.assertIs(result["native_return"], False)
            self.assertEqual(
                (
                    engine.dh_state.error_kind,
                    engine.dh_state.primary_error,
                    engine.dh_state.passthru_error,
                ),
                (1, 1, 5),
            )
            self.assertFalse(active[0])
            self.assertEqual(runtime.close(), [])

    def test_canonical_multirom_prepare_restart_timeout_then_key_and_mode(self):
        engine = self.engine_fixture()
        assert engine._source is not None
        container = parse_cuw_2026(engine._source)
        assert isinstance(container, CalibrationContainer)
        values = {
            "ParamFileKeySystemProtocolMicon": "108CAN383",
            "DLLFileNameForPrepareWrite": "TCUWCanDHMultiROMPrepareWriter.dll",
            "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0700/0708",
            "SecurityKey": "0000",
        }
        selection = bind_dh_parameter_fixture(
            container,
            {"108CAN383.ini": table(list(values), [list(values.values())])},
            "prepare",
            encoded=False,
        )
        attachments = {
            name: Path("runtime/no-car-21/recovered", filename).read_bytes()
            for name, filename in (
                ("selected_module", values["DLLFileNameForPrepareWrite"]),
                ("dh_utils_module", "TCUWDHUtils.dll"),
                ("secret_info_module", "SecretInfo.dll"),
                ("cuw_module", "CUW.dll"),
            )
        }
        identity = identify_native_module(
            hashlib.sha256(attachments["selected_module"]).hexdigest(),
            values["DLLFileNameForPrepareWrite"],
        )
        context = bind_native_context(
            container,
            1,
            (),
            selection,
            identity,
            attachments,
            {"dh_state": engine.dh_state},
        )
        for restart in (9, 16, 5, None):
            events, requests, pending = [], [], []

            def host(
                event,
                remaining,
                events=events,
                requests=requests,
                pending=pending,
                restart=restart,
            ):
                events.append(event)
                op = event["operation"]
                if op in ("get_timeout", "get_send_timeout"):
                    return 111
                if op == "start_flow_control_filter":
                    return len(events)
                if op == "is_sending_sync_periodic":
                    return False
                if op == "write_messages":
                    data = event["data"]
                    if data[:4] in (
                        bytes.fromhex("00000792"),
                        bytes.fromhex("00000786"),
                        bytes.fromhex("00000700"),
                    ):
                        requests.append(data)
                        if data[4:] == bytes.fromhex("1083"):
                            pending.append(
                                NativeJ2534Error2026(restart)
                                if restart is not None
                                else bytes.fromhex("0000079a5083")
                            )
                        elif data[4:] == bytes.fromhex("3e00"):
                            pending.append(bytes.fromhex("0000078e7f3e12"))
                        elif data[4:] == bytes.fromhex("2701"):
                            pending.append(bytes.fromhex("0000070867010102030400"))
                        elif data[4:] == bytes.fromhex("270208040102"):
                            pending.append(bytes.fromhex("00000708670234"))
                        elif data[4:] == bytes.fromhex("1085"):
                            pending.append(bytes.fromhex("000007085085"))
                        else:
                            self.fail(data.hex())
                    return 1
                if op == "read_specified_can_message":
                    reply = pending.pop(0)
                    if isinstance(reply, Exception):
                        raise reply
                    return reply

            runtime = NativeRuntime2026(host)
            result = execute_context(context, runtime)
            self.assertEqual(
                result["state"],
                "prepare_completed" if restart in (9, 16) else "failed",
                (result, requests),
            )
            self.assertIs(result["native_return"], restart in (9, 16))
            self.assertFalse(pending)
            if restart in (9, 16):
                self.assertEqual(
                    [p[4:] for p in requests],
                    [
                        bytes.fromhex("1083"),
                        bytes.fromhex("3e00"),
                        bytes.fromhex("2701"),
                        bytes.fromhex("270208040102"),
                        bytes.fromhex("1085"),
                    ],
                )
            else:
                self.assertEqual(
                    engine.dh_state.primary_error, 1 if restart == 5 else 1000
                )
                self.assertEqual(engine.dh_state.error_kind, 1)
            self.assertNotIn("stop_sync_periodic", [e["operation"] for e in events])
            self.assertEqual(
                events[-2:],
                [
                    {"operation": "set_timeout", "milliseconds": 111},
                    {"operation": "set_send_timeout", "milliseconds": 111},
                ],
            )
            self.assertEqual(runtime.close(), [])

    def test_bound_gateway_shared_engine_enum_precedes_authentication_failure(self):
        engine = self.engine_fixture()
        assert engine._source is not None
        container = parse_cuw_2026(engine._source)
        assert isinstance(container, CalibrationContainer)
        values = {
            "ParamFileKeySystemProtocolMicon": "108CAN383",
            "DLLFileNameForPrepareWrite": "TCUWCanDHPrepareWriter.dll",
        }
        selection = bind_dh_parameter_fixture(
            container,
            {"108CAN383.ini": table(list(values), [list(values.values())])},
            "prepare",
            encoded=False,
        )
        modules = {
            name: Path("runtime/no-car-21/recovered", filename).read_bytes()
            for name, filename in (
                ("dh_utils_module", "TCUWDHUtils.dll"),
                ("secret_info_module", "SecretInfo.dll"),
                ("cuw_module", "CUW.dll"),
            )
        }
        requests, pending = [], []

        def host(event, remaining):
            operation = event["operation"]
            if operation == "get_timeout":
                return 111
            if operation == "start_flow_control_filter":
                return len(requests) + 1
            if operation == "is_sending_sync_periodic":
                return False
            if operation == "write_messages":
                requests.append(event["data"])
                if event["data"][4:] == bytes.fromhex("2105"):
                    pending.append(bytes.fromhex("000007ac610501020304"))
                else:
                    raise NativeJ2534Error2026(5)
                return 1
            if operation == "read_specified_can_message":
                return pending.pop(0)

        runtime = NativeRuntime2026(host)
        gateway = bind_gateway_client(runtime, selection, engine.dh_state, **modules)
        self.assertIs(gateway.engine_state, engine.dh_state)
        self.assertEqual(engine.dh_state.central_gateway_type, 0)
        with self.assertRaises(NativeJ2534Error2026):
            gateway.start_reprogramming_mode_for_multi_types()
        self.assertEqual(engine.dh_state.central_gateway_type, 2)
        self.assertEqual(
            requests, [bytes.fromhex("000007a42105"), bytes.fromhex("000007a41087")]
        )
        with self.assertRaises(ValueError):
            bind_gateway_client(
                runtime,
                selection,
                engine.dh_state,
                **dict(modules, cuw_module=b"unidentified"),
            )
        self.assertEqual(runtime.close(), [])

    def test_canonical_getter_actual2026_parameter_bytes_and_no_manual_geometry(self):
        engine = self.engine_fixture(version=10)
        assert engine._source is not None
        container = parse_cuw_2026(engine._source)
        assert isinstance(container, CalibrationContainer)
        values = {
            "ParamFileKeySystemProtocolMicon": "108CAN",
            "DLLFileNameForGetCID": "TCUWCanDHUDSSoftwareIDGetter.dll",
            "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
            "CanIDForGetCID": "0700/0708",
            "ReceiveTimeoutBeforeGetCID": "666",
        }
        source = table(list(values), [list(values.values())])
        selection = bind_dh_parameter_fixture(
            container, {"108CAN.ini": source}, "get_cid", encoded=False
        )
        module_name = values["DLLFileNameForGetCID"]
        module_bytes = Path("runtime/no-car-21/recovered", module_name).read_bytes()
        identity = identify_native_module(
            hashlib.sha256(module_bytes).hexdigest(), module_name
        )
        context = bind_native_context(
            container,
            1,
            (),
            selection,
            identity,
            {"selected_module": module_bytes},
            {"dh_state": engine.dh_state},
        )
        events = []

        def host(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 666
            if event["operation"] == "start_flow_control_filter":
                return 13
            if event["operation"] == "write_messages":
                self.assertEqual(event["data"], bytes.fromhex("0000070022f181"))
                return 1
            if event["operation"] == "read_specified_can_message":
                return bytes.fromhex("0000070862f18101") + b"AUTHORED".ljust(16, b"\0")

        result = execute_context(context, NativeRuntime2026(host))
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "read_completed")
        self.assertEqual(result["identifiers"][0]["identifier"], b"AUTHORED")

        def api_failure(event, remaining):
            if event["operation"] == "read_specified_can_message":
                raise NativeJ2534Error2026(5)
            return host(event, remaining)

        result = execute_context(context, NativeRuntime2026(api_failure))
        self.assertEqual(
            (
                engine.dh_state.error_kind,
                engine.dh_state.primary_error,
                engine.dh_state.passthru_error,
            ),
            (0, 1, 5),
        )
        self.assertEqual(result["native_passthru_error"], 5)

        def malformed(event, remaining):
            if event["operation"] == "read_specified_can_message":
                return bytes.fromhex("0000070862f18102") + b"one-record-only!"
            return host(event, remaining)

        result = execute_context(context, NativeRuntime2026(malformed))
        self.assertEqual(result["state"], "failed")
        self.assertEqual(
            (
                engine.dh_state.error_kind,
                engine.dh_state.primary_error,
                engine.dh_state.passthru_error,
            ),
            (0, 3, 5),
        )
        self.assertEqual(
            (result["native_primary_error"], result["native_passthru_error"]), (3, 5)
        )
        with self.assertRaises(ValueError):
            type(context)(context.native, selection)
        with self.assertRaises(ValueError):
            bind_native_context(
                container,
                1,
                (),
                selection,
                identity,
                {"selected_module": module_bytes},
                {"request_id": b"\x07\x00"},
            )
        with self.assertRaises(ValueError):
            bind_native_context(
                container,
                1,
                (),
                selection,
                identity,
                {"selected_module": b"authored unrecognized module"},
                {},
            )

    def test_gateway_writer_cpu0_checksum_and_separate_progress_mutations(self):
        engine = self.engine_fixture(
            version=8,
            cpu_count=2,
            cpu_index=0,
            image_data=b"S1071000646174614E\nS9031000EC\n",
        )
        state = engine.dh_state
        assert engine._source is not None
        container = parse_cuw_2026(engine._source)
        assert isinstance(container, CalibrationContainer)
        values = {
            "ParamFileKeySystemProtocolMicon": "108CAN383",
            "DLLFileNameForFlashWrite": "TCUWCanDHGatewayFlashWriter.dll",
            "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0700/0708",
            "StartAddress": "00001000",
            "FlagToNonChangeReprogGWModeProcess": "1",
        }
        raw_parameter = table(list(values), [list(values.values())])
        selection = bind_dh_parameter_fixture(
            container,
            {"108CAN383.ini": raw_parameter},
            "write",
            cpu_index=0,
            encoded=False,
        )
        module_name = "TCUWCanDHGatewayFlashWriter.dll"
        attachments = {
            name: Path("runtime/no-car-21/recovered", filename).read_bytes()
            for name, filename in (
                ("selected_module", module_name),
                ("dh_utils_module", "TCUWDHUtils.dll"),
                ("secret_info_module", "SecretInfo.dll"),
                ("cuw_module", "CUW.dll"),
            )
        }
        identity = identify_native_module(
            hashlib.sha256(attachments["selected_module"]).hexdigest(), module_name
        )
        context = bind_native_context(
            container,
            1,
            (),
            selection,
            identity,
            attachments,
            {"dh_state": state, "cpu_index": 0},
        )
        events, requests, pending, snapshots = [], [], [], []

        main_filter: list[int | None] = [None]
        filter_fault = [True]

        def host(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "get_timeout":
                return 101
            if operation == "get_send_timeout":
                return 102
            if operation == "start_flow_control_filter":
                if main_filter[0] is None:
                    main_filter[0] = len(events)
                return len(events)
            if (
                operation == "stop_filter"
                and event["identifier"] == main_filter[0]
                and filter_fault[0]
            ):
                filter_fault[0] = False
                raise NativeJ2534Error2026(5)
            if operation == "is_sending_sync_periodic":
                return False
            if operation == "notify_progress_count":
                snapshots.append((state.transferred_bytes, state.progress))
            if operation == "write_messages":
                pdu = event["data"][4:]
                requests.append(pdu)
                if pdu == bytes.fromhex("22fd10"):
                    pending.append(bytes.fromhex("62fd10"))
                elif pdu == bytes.fromhex("3101f010"):
                    pending.append(bytes.fromhex("7101f0109a"))
                elif pdu.startswith(b"\x34"):
                    pending.append(bytes.fromhex("74200003"))
                elif pdu.startswith(b"\x36"):
                    pending.append(b"\x76")
                elif pdu == b"\x37":
                    pending.append(b"\x77")
                elif pdu.startswith(bytes.fromhex("3101f011000144")):
                    pending.append(bytes.fromhex("7101f011200003"))
                elif pdu == bytes.fromhex("3101f01101"):
                    pending.append(bytes.fromhex("7101f01100"))
                elif pdu == bytes.fromhex("1101"):
                    pending.append(b"\x51")
                else:
                    self.fail("Unexpected native writer PDU")
                return 1
            if operation == "read_specified_can_message":
                return bytes.fromhex("00000708") + pending.pop(0)

        runtime = NativeRuntime2026(host)
        result = execute_context(context, runtime)
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["cleanup_errors"], ["NativeJ2534Error2026"])
        self.assertEqual(result["state"], "writer_completed")
        self.assertFalse(result["programming_completed"])
        self.assertEqual(
            requests,
            [
                bytes.fromhex("22fd10"),
                bytes.fromhex("3401440000100000000004"),
                b"\x36da",
                b"\x36ta",
                b"\x37",
                bytes.fromhex("3101f010"),
                bytes.fromhex("1101"),
            ],
        )
        self.assertEqual(state.progress, (100, 0))
        self.assertEqual(state.transferred_bytes, (4, 0))
        self.assertEqual(
            [
                event["progress"]
                for event in events
                if event["operation"] == "notify_progress_percent"
            ],
            [50, 100],
        )
        self.assertEqual(snapshots, [((2, 0), (0, 0)), ((4, 0), (50, 0))])
        self.assertNotIn("stop_sync_periodic", [event["operation"] for event in events])
        self.assertEqual(runtime.close(), [])

        events.clear()
        main_filter[0], filter_fault[0] = None, True
        requests.clear()
        snapshots.clear()

        def failed_host(event, remaining):
            if event["operation"] == "write_messages" and event["data"][4:].startswith(
                b"\x36"
            ):
                raise NativeJ2534Error2026(5)
            return host(event, remaining)

        runtime = NativeRuntime2026(failed_host)
        result = execute_context(context, runtime)
        self.assertEqual(result["state"], "failed")
        self.assertIs(result["native_return"], False)
        self.assertEqual(result["cleanup_errors"], ["NativeJ2534Error2026"])
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error), (2, 1, 5)
        )
        self.assertEqual(state.transferred_bytes, (0, 0))
        self.assertEqual(state.progress, (0, 0))
        self.assertEqual(snapshots, [((0, 0), (100, 0))])
        self.assertNotIn("stop_sync_periodic", [event["operation"] for event in events])
        self.assertEqual(runtime.close(), [])

    def test_19pf_writer_forced_su_checksum_atomic_progress_and_active_error_kind(self):
        engine = self.engine_fixture(
            version=8,
            cpu_count=2,
            cpu_index=0,
            image_data=b"S1071000646174614E\nS9031000EC\n",
        )
        state = engine.dh_state
        assert engine._source is not None
        container = parse_cuw_2026(engine._source)
        assert isinstance(container, CalibrationContainer)
        values = {
            "ParamFileKeySystemProtocolMicon": "108CAN383",
            "DLLFileNameForFlashWrite": "TCUWCanDH19PFSURegGatewayFlashWriter.dll",
            "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0700/0708",
            "StartAddress": "00001000",
            "FlagToNonChangeReprogGWModeProcess": "1",
        }
        raw_parameter = table(list(values), [list(values.values())])
        selection = bind_dh_parameter_fixture(
            container,
            {"108CAN383.ini": raw_parameter},
            "write",
            cpu_index=0,
            encoded=False,
        )
        module_name = "TCUWCanDH19PFSURegGatewayFlashWriter.dll"
        attachments = {
            name: Path("runtime/no-car-21/recovered", filename).read_bytes()
            for name, filename in (
                ("selected_module", module_name),
                ("dh_utils_module", "TCUWDHUtils.dll"),
                ("secret_info_module", "SecretInfo.dll"),
                ("cuw_module", "CUW.dll"),
            )
        }
        identity = identify_native_module(
            hashlib.sha256(attachments["selected_module"]).hexdigest(), module_name
        )
        context = bind_native_context(
            container,
            1,
            (),
            selection,
            identity,
            attachments,
            {"dh_state": state, "cpu_index": 0},
        )
        events, requests, pending, snapshots = [], [], [], []
        last = [b""]

        main_filter: list[int | None] = [None]
        filter_fault = [True]

        def host(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "get_timeout":
                return 101
            if operation == "get_send_timeout":
                return 102
            if operation == "start_flow_control_filter":
                if main_filter[0] is None:
                    main_filter[0] = len(events)
                return len(events)
            if (
                operation == "stop_filter"
                and event["identifier"] == main_filter[0]
                and filter_fault[0]
            ):
                filter_fault[0] = False
                raise NativeJ2534Error2026(5)
            if operation == "is_sending_sync_periodic":
                return False
            if operation == "notify_progress_count":
                snapshots.append((state.transferred_bytes, state.progress))
            if operation == "write_messages":
                last[0] = event["data"]
                pdu = event["data"][4:]
                requests.append(pdu)
                if pdu == bytes.fromhex("22fd10"):
                    pending.append(bytes.fromhex("62fd10"))
                elif pdu == bytes.fromhex("3101f01300"):
                    pending.append(bytes.fromhex("7101f01300"))
                elif pdu.startswith(b"\x34"):
                    pending.append(bytes.fromhex("74200003"))
                elif pdu.startswith(b"\x36"):
                    pending.append(b"\x76")
                elif pdu == b"\x37":
                    pending.append(b"\x77")
                elif pdu.startswith(bytes.fromhex("3101f011000144")):
                    pending.append(bytes.fromhex("7101f011200003"))
                elif pdu == bytes.fromhex("3101f01101"):
                    pending.append(bytes.fromhex("7101f01100"))
                elif pdu == bytes.fromhex("1089"):
                    pending.append(bytes.fromhex("5089"))
                elif pdu == bytes.fromhex("1101"):
                    pending.append(b"\x51")
                else:
                    self.fail("Unexpected native writer PDU")
                return 1
            if operation == "read_specified_can_message":
                return {
                    bytes.fromhex("000007a4"): bytes.fromhex("000007ac"),
                    bytes.fromhex("00000786"): bytes.fromhex("0000078e"),
                }.get(last[0][:4], bytes.fromhex("00000708")) + pending.pop(0)

        runtime = NativeRuntime2026(host)
        result = execute_context(context, runtime)
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["cleanup_errors"], ["NativeJ2534Error2026"])
        self.assertEqual(result["state"], "writer_completed")
        self.assertFalse(result["programming_completed"])
        self.assertEqual(
            requests,
            [
                bytes.fromhex("22fd10"),
                bytes.fromhex("3401440000100000000004"),
                b"\x36da",
                b"\x36ta",
                b"\x37",
                bytes.fromhex("3101f01300"),
                bytes.fromhex("1101"),
                bytes.fromhex("1089"),
                bytes.fromhex("1089"),
            ],
        )
        self.assertEqual(state.progress, (100, 0))
        self.assertEqual(state.transferred_bytes, (4, 0))
        self.assertEqual(
            [
                event["progress"]
                for event in events
                if event["operation"] == "notify_progress_percent"
            ],
            [50, 100],
        )
        self.assertEqual(snapshots, [((2, 0), (50, 0)), ((4, 0), (100, 0))])
        self.assertIn("stop_sync_periodic", [event["operation"] for event in events])
        self.assertEqual(runtime.close(), [])

        events.clear()
        main_filter[0], filter_fault[0] = None, True
        requests.clear()
        snapshots.clear()

        def failed_host(event, remaining):
            if event["operation"] == "write_messages" and event["data"][4:].startswith(
                b"\x36"
            ):
                raise NativeJ2534Error2026(5)
            return host(event, remaining)

        runtime = NativeRuntime2026(failed_host)
        result = execute_context(context, runtime)
        self.assertEqual(result["state"], "failed")
        self.assertIs(result["native_return"], False)
        self.assertEqual(result["cleanup_errors"], ["NativeJ2534Error2026"])
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error), (2, 1, 5)
        )
        self.assertEqual(state.transferred_bytes, (0, 0))
        self.assertEqual(state.progress, (0, 0))
        self.assertEqual(snapshots, [((0, 0), (100, 0))])
        self.assertIn("stop_sync_periodic", [event["operation"] for event in events])
        self.assertEqual(runtime.close(), [])

        fresh_engine = self.engine_fixture(
            version=8,
            cpu_count=2,
            cpu_index=0,
            image_data=b"S1071000646174614E\nS9031000EC\n",
        )
        fresh = bind_native_context(
            container,
            1,
            (),
            selection,
            identity,
            attachments,
            {"dh_state": fresh_engine.dh_state, "cpu_index": 0},
        )

        def failed_filter(event, remaining):
            if event["operation"] == "start_flow_control_filter":
                raise NativeJ2534Error2026(5)
            return host(event, remaining)

        runtime = NativeRuntime2026(failed_filter)
        result = execute_context(fresh, runtime)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(
            (
                fresh_engine.dh_state.error_kind,
                fresh_engine.dh_state.primary_error,
                fresh_engine.dh_state.passthru_error,
            ),
            (1, 1, 5),
        )
        self.assertFalse(bool(fresh_engine.dh_state.notification))
        assert fresh_engine._persistence is not None
        self.assertFalse(
            (
                fresh_engine._persistence.output_root / "Save" / "RecoveryInfo.ini"
            ).exists()
        )
        self.assertEqual(runtime.close(), [])

    def test_canonical_multirom_writer_records_sequence_and_parameter_progress(self):
        engine = self.engine_fixture(
            image_data=b"S1051000646125\nS1052000746105\nS10530007879D9\nS9031000EC\n"
        )
        state = engine.dh_state
        assert engine._source is not None
        container = parse_cuw_2026(engine._source)
        assert isinstance(container, CalibrationContainer)
        values = {
            "ParamFileKeySystemProtocolMicon": "108CAN383",
            "DLLFileNameForFlashWrite": "TCUWCanDHMultiROMFlashWriter.dll",
            "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0700/0708",
            "StartAddress": "00001000\n00002000",
            "EachWriteDataSize": "2\n2",
        }
        selection = bind_dh_parameter_fixture(
            container,
            {"108CAN383.ini": table(list(values), [list(values.values())])},
            "write",
            encoded=False,
        )
        attachments = {
            name: Path("runtime/no-car-21/recovered", filename).read_bytes()
            for name, filename in (
                ("selected_module", values["DLLFileNameForFlashWrite"]),
                ("dh_utils_module", "TCUWDHUtils.dll"),
                ("secret_info_module", "SecretInfo.dll"),
                ("cuw_module", "CUW.dll"),
            )
        }
        identity = identify_native_module(
            hashlib.sha256(attachments["selected_module"]).hexdigest(),
            values["DLLFileNameForFlashWrite"],
        )
        context = bind_native_context(
            container, 1, (), selection, identity, attachments, {"dh_state": state}
        )
        self.assertEqual(native2026_archive(state.metadata).flash_size, 6)
        for failure, stop_fault in (
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ):
            events, requests, pending, snapshots = [], [], [], []
            last = [b""]
            main_filter: list[int | None] = [None]
            filter_fault = [stop_fault]

            def host(
                event,
                remaining,
                failure=failure,
                events=events,
                requests=requests,
                pending=pending,
                snapshots=snapshots,
                last=last,
                main_filter=main_filter,
                filter_fault=filter_fault,
            ):
                events.append(event)
                op = event["operation"]
                if op in ("get_timeout", "get_send_timeout"):
                    return 111
                if op == "start_flow_control_filter":
                    if main_filter[0] is None:
                        main_filter[0] = len(events)
                    return len(events)
                if (
                    op == "stop_filter"
                    and event["identifier"] == main_filter[0]
                    and filter_fault[0]
                ):
                    filter_fault[0] = False
                    raise NativeJ2534Error2026(5)
                if op == "is_sending_sync_periodic":
                    return False
                if op == "notify_progress_count":
                    snapshots.append((state.transferred_bytes[0], state.progress[0]))
                if op == "write_messages":
                    data = event["data"]
                    last[0] = data[:4]
                    pdu = data[4:]
                    requests.append(pdu)
                    if pdu == bytes.fromhex("22fd10"):
                        reply = bytes.fromhex("62fd10")
                    elif pdu == bytes.fromhex("3101ff00"):
                        reply = bytes.fromhex("7101ff00")
                    elif pdu.startswith(b"\x34"):
                        reply = bytes.fromhex("74200003")
                    elif pdu.startswith(b"\x36"):
                        reply = b"\x76" + (b"\xff" if failure else pdu[1:2])
                    elif pdu == b"\x37":
                        reply = b"\x77"
                    elif pdu == bytes.fromhex("3101f01101"):
                        reply = bytes.fromhex("7101f01100")
                    elif pdu == bytes.fromhex("3e00"):
                        reply = bytes.fromhex("7f3e12")
                    else:
                        self.fail(pdu.hex())
                    pending.append(reply)
                    return 1
                if op == "read_specified_can_message":
                    return (int.from_bytes(last[0], "big") + 8).to_bytes(
                        4, "big"
                    ) + pending.pop(0)

            runtime = NativeRuntime2026(host)
            result = execute_context(context, runtime)
            self.assertEqual(
                result["state"], "failed" if failure else "writer_completed"
            )
            self.assertIs(result["native_return"], not failure)
            self.assertEqual(
                result["cleanup_errors"], ["NativeJ2534Error2026"] if stop_fault else []
            )
            self.assertFalse(pending)
            if not failure:
                self.assertEqual(
                    requests,
                    [
                        bytes.fromhex("22fd10"),
                        bytes.fromhex("3101ff00"),
                        bytes.fromhex("3401440000100000000002"),
                        b"\x36\x01d",
                        b"\x36\x02a",
                        b"\x37",
                        bytes.fromhex("3401440000200000000002"),
                        b"\x36\x01t",
                        b"\x36\x02a",
                        b"\x37",
                        bytes.fromhex("3101f01101"),
                        bytes.fromhex("3e00"),
                    ],
                )
                self.assertEqual(snapshots, [(1, 25), (2, 50), (3, 75), (4, 100)])
                periodic = next(
                    e for e in events if e["operation"] == "start_sync_periodic"
                )
                self.assertEqual(
                    periodic["frames"], ((bytes.fromhex("000007923e80"), 0),)
                )
                self.assertFalse(bool(state.notification))
            else:
                self.assertEqual((state.error_kind, state.primary_error), (2, 0x22))
                self.assertEqual(state.progress, (0,))
                self.assertEqual(state.transferred_bytes, (0,))
                self.assertEqual(snapshots, [(0, 100)])
                self.assertTrue(bool(state.notification))
            self.assertEqual(runtime.close(), [])

    def test_canonical_uds_writers_literal_counter_crc_and_native_failure_stage(self):
        for phase5, failure in (
            (False, ""),
            (True, ""),
            (False, "flash"),
            (True, "image"),
            (False, "stop_native"),
            (True, "stop_native"),
            (False, "cmac"),
            (True, "cmac"),
        ):
            with self.subTest(phase5=phase5, failure=failure):
                engine = self.engine_fixture(
                    image_data=b"S1071000646174614E\nS9031000EC\n"
                )
                state = engine.dh_state
                assert engine._source is not None
                container = parse_cuw_2026(engine._source)
                assert isinstance(container, CalibrationContainer)
                module = (
                    "TCUWP5CanDHUDSFlashWriter.dll"
                    if phase5
                    else "TCUWCanDHUDSFlashWriter.dll"
                )
                values = {
                    "ParamFileKeySystemProtocolMicon": "108CAN383",
                    "DLLFileNameForFlashWrite": module,
                    "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
                    "CanIDForPrepareWrite": "0700/0708",
                    "FlashCodeStartAddress": "00000000",
                    "StartAddress": "00001000",
                    "LogicalBlockMemorySize": "00000004",
                    "FalsificationCheckType": "2" if failure == "cmac" else "1",
                    "ValueSubtractedFromMaxNumberBlockLength": "1",
                    "FlagToNonChangeReprogGWModeProcess": "1",
                }
                selection = bind_dh_parameter_fixture(
                    container,
                    {"108CAN383.ini": table(list(values), [list(values.values())])},
                    "write",
                    encoded=False,
                )
                attachments = {
                    name: Path("runtime/no-car-21/recovered", filename).read_bytes()
                    for name, filename in (
                        ("selected_module", module),
                        ("dh_utils_module", "TCUWDHUtils.dll"),
                        ("secret_info_module", "SecretInfo.dll"),
                        ("cuw_module", "CUW.dll"),
                    )
                }
                identity = identify_native_module(
                    hashlib.sha256(attachments["selected_module"]).hexdigest(), module
                )
                context = bind_native_context(
                    container,
                    1,
                    (),
                    selection,
                    identity,
                    attachments,
                    {"dh_state": state},
                )
                requests, pending, snapshots, events = [], [], [], []
                filter_fault = [failure == "stop_native"]

                def host(
                    event,
                    remaining,
                    events=events,
                    state=state,
                    snapshots=snapshots,
                    requests=requests,
                    pending=pending,
                    failure=failure,
                    phase5=phase5,
                    filter_fault=filter_fault,
                ):
                    events.append(event)
                    op = event["operation"]
                    if op == "stop_filter" and filter_fault[0]:
                        filter_fault[0] = False
                        raise NativeJ2534Error2026(5)
                    if op in ("get_timeout", "get_send_timeout"):
                        return 111
                    if op == "start_flow_control_filter":
                        return 5
                    if op == "is_sending_sync_periodic":
                        return False
                    if op == "notify_progress_count":
                        snapshots.append(
                            (state.transferred_bytes[0], state.progress[0])
                        )
                    if op == "write_messages":
                        data = event["data"]
                        if data[:4] != bytes.fromhex("00000700"):
                            return 1
                        pdu = data[4:]
                        requests.append(pdu)
                        if pdu.startswith(b"\x34"):
                            reply = bytes.fromhex("74200003")
                        elif pdu == b"\x37":
                            reply = b"\x77"
                        elif pdu.startswith(b"\x36"):
                            reply = (
                                b"\x7f\x36\x31"
                                if failure == "image"
                                else b"\x76" + pdu[1:2]
                            )
                        elif pdu == bytes.fromhex("31010202") + bytes(20):
                            reply = bytes.fromhex("7101020200")
                        elif pdu == bytes.fromhex("3101020100"):
                            reply = (
                                b"\x7f\x31\x31"
                                if failure == "flash"
                                else bytes.fromhex("7101020100")
                            )
                        elif pdu.startswith(bytes.fromhex("3101ff0044")):
                            reply = bytes.fromhex("7101ff0000")
                        elif pdu == bytes.fromhex("3101ff01"):
                            reply = bytes.fromhex("7101ff0100")
                        elif pdu == b"\x11\x01":
                            reply = b"\x51\x01" if phase5 else b"\x51"
                        else:
                            self.fail(pdu.hex())
                        pending.append(reply)
                        return 1
                    if op == "read_specified_can_message":
                        return bytes.fromhex("00000708") + pending.pop(0)

                runtime = NativeRuntime2026(host)
                result = execute_context(context, runtime)
                self.assertIs(
                    result["native_return"], failure not in ("flash", "image")
                )
                self.assertFalse(pending)
                check = (
                    bytes.fromhex("31010202") + bytes(20)
                    if failure == "cmac"
                    else bytes.fromhex("3101020100")
                )
                prefix = [
                    bytes.fromhex("3401440000000000000000"),
                    b"\x37",
                    check,
                ]
                self.assertEqual(requests[:3], prefix)
                if failure not in ("flash", "image"):
                    self.assertEqual(
                        requests[3:],
                        [
                            bytes.fromhex("3101ff00440000100000000004"),
                            bytes.fromhex("3401440000100000000004"),
                            b"\x36\x01da",
                            b"\x36\x02ta",
                            b"\x37",
                            check,
                            bytes.fromhex("3101ff01"),
                            b"\x11\x01",
                        ],
                    )
                    self.assertEqual(snapshots, [(2, 50), (4, 100)])
                    self.assertFalse(bool(state.notification))
                else:
                    self.assertEqual(
                        (state.error_kind, state.primary_error),
                        (1, 0x3F3) if failure == "flash" else (2, 0x22),
                    )
                    self.assertEqual(state.progress, (0,))
                    self.assertEqual(state.transferred_bytes, (0,))
                    self.assertEqual(state.comm_phase, 1 if failure == "flash" else 0)
                    self.assertIs(bool(state.notification), failure != "flash")
                self.assertEqual(
                    events[-2:],
                    [
                        {"operation": "set_timeout", "milliseconds": 111},
                        {"operation": "set_send_timeout", "milliseconds": 111},
                    ],
                )
                self.assertEqual(runtime.close(), [])

    def test_canonical_dhuds_divided_physical_slots_resume_count_and_persistence(self):
        engine = self.engine_fixture(
            version=4,
            image_data=b"S1051000646125\nS9031000EC\n",
            extra_images=(b"S1052000746105\nS9032000DC\n",),
            flash_code_data=b"S104000046B5\nS9030000FC\n",
            cpu_extra="01_CPUImageName=ONE\n03_CPUImageName=THREE\n",
        )
        state = engine.dh_state
        assert engine._source is not None
        container = parse_cuw_2026(engine._source)
        assert isinstance(container, CalibrationContainer)
        values = {
            "ParamFileKeySystemProtocolMicon": "108CAN383",
            "DLLFileNameForFlashWrite": "TCUWCanDHUDSFlashWriter.dll",
            "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0700/0708",
            "FlashCodeStartAddress": "00000000",
            "StartAddress": "00001000\n00009900\n00002000\n00008800",
            "LogicalBlockMemorySize": "00000002\n00000099\n00000002\n00000088",
            "FalsificationCheckType": "1",
            "FlagToNonChangeReprogGWModeProcess": "1",
        }
        selection = bind_dh_parameter_fixture(
            container,
            {"108CAN383.ini": table(list(values), [list(values.values())])},
            "write",
            encoded=False,
        )
        attachments = {
            name: Path("runtime/no-car-21/recovered", filename).read_bytes()
            for name, filename in (
                ("selected_module", values["DLLFileNameForFlashWrite"]),
                ("dh_utils_module", "TCUWDHUtils.dll"),
                ("secret_info_module", "SecretInfo.dll"),
                ("cuw_module", "CUW.dll"),
            )
        }
        identity = identify_native_module(
            hashlib.sha256(attachments["selected_module"]).hexdigest(),
            values["DLLFileNameForFlashWrite"],
        )
        context = bind_native_context(
            container, 1, (), selection, identity, attachments, {"dh_state": state}
        )
        pending, requests, snapshots = [], [], []
        fail_second = [True]
        current_start = [b""]

        def host(event, remaining):
            op = event["operation"]
            if op in ("get_timeout", "get_send_timeout"):
                return 111
            if op == "start_flow_control_filter":
                return 7
            if op == "is_sending_sync_periodic":
                return False
            if op == "notify_progress_count":
                snapshots.append((state.transferred_bytes[0], state.progress[0]))
            if op == "write_messages":
                if event["data"][:4] != bytes.fromhex("00000700"):
                    return 1
                pdu = event["data"][4:]
                requests.append(pdu)
                if pdu.startswith(b"\x34"):
                    current_start[0] = pdu[3:7]
                    reply = bytes.fromhex("74200002")
                elif pdu.startswith(b"\x36"):
                    if current_start[0] == bytes.fromhex("00002000") and fail_second[0]:
                        fail_second[0] = False
                        reply = bytes.fromhex("7f3631")
                    else:
                        reply = b"\x76" + pdu[1:2]
                elif pdu == b"\x37":
                    reply = b"\x77"
                elif pdu == bytes.fromhex("3101020100"):
                    reply = bytes.fromhex("7101020100")
                elif pdu.startswith(bytes.fromhex("3101ff0044")):
                    reply = bytes.fromhex("7101ff0000")
                elif pdu == bytes.fromhex("3101ff01"):
                    reply = bytes.fromhex("7101ff0100")
                elif pdu == b"\x11\x01":
                    reply = b"\x51"
                else:
                    self.fail(pdu.hex())
                pending.append(reply)
                return 1
            if op == "read_specified_can_message":
                return bytes.fromhex("00000708") + pending.pop(0)

        runtime = NativeRuntime2026(host)
        failed = execute_context(context, runtime)
        self.assertIs(failed["native_return"], False)
        self.assertEqual(
            (state.divided_image_index, state.transferred_bytes, state.progress),
            (1, (0,), (0,)),
        )
        assert engine._persistence is not None
        self.assertEqual(
            engine._persistence.state.write_target_divided_cpu_image_index, 1
        )
        self.assertEqual(snapshots, [(0, 0), (1, 25), (2, 50), (0, 50)])
        requests.clear()
        snapshots.clear()
        completed = execute_context(context, runtime)
        self.assertIs(completed["native_return"], True)
        self.assertEqual(
            (state.divided_image_index, state.transferred_bytes, state.progress),
            (0, (4,), (100,)),
        )
        self.assertEqual(snapshots, [(0, 0), (3, 75), (4, 100)])
        self.assertEqual(
            [p for p in requests if p.startswith(bytes.fromhex("3101ff0044"))],
            [bytes.fromhex("3101ff00440000200000000002")],
        )
        self.assertEqual(
            engine._persistence.state.write_target_divided_cpu_image_index, 0
        )
        self.assertFalse(pending)
        self.assertEqual(runtime.close(), [])

    def test_canonical_usb_writer_native_routines_status_and_handler_restore(self):
        cases = (
            (0, False, None),
            (1, False, None),
            (0, True, None),
            (0, False, (b"TARGET",)),
            (0, False, (b"OTHER",)),
            (0, False, (b"OTHER", b"SECOND")),
            (0, False, (b"OTHER", b"")),
            (0, True, (b"OTHER",)),
        )
        for status_byte, stop_fault, recovery_values, fault_op in (
            *((status, stop, ids, "") for status, stop, ids in cases),
            *(
                (0, False, (b"OTHER",), op)
                for op in (
                    "write_messages",
                    "read_specified_can_message",
                    "stop_filter",
                    "notify_progress_percent",
                    "cancel:write_messages",
                    "keyboard:read_specified_can_message",
                    "cancel:stop_filter",
                    "keyboard:stop_filter",
                )
            ),
        ):
            should_program = (
                recovery_values is None
                or b"TARGET" in recovery_values
                or sum(bool(v) for v in recovery_values) != 1
            )
            engine = self.engine_fixture(
                cpu_extra="NumberOfTargets=1\n01_TargetCalibration=TARGET\n"
            )
            state = engine.dh_state
            assert engine._source is not None
            container = parse_cuw_2026(engine._source)
            assert isinstance(container, CalibrationContainer)
            values = {
                "ParamFileKeySystemProtocolMicon": "108CAN383",
                "DLLFileNameForFlashWrite": "TCUWCanDHUSBReproFlashWriter.dll",
                "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
                "CanIDForPrepareWrite": "0700/0708",
                "CanIDForGetCID": "0710/0718",
            }
            selection = bind_dh_parameter_fixture(
                container,
                {"108CAN383.ini": table(list(values), [list(values.values())])},
                "write",
                encoded=False,
            )
            attachments = {
                name: Path("runtime/no-car-21/recovered", filename).read_bytes()
                for name, filename in (
                    ("selected_module", values["DLLFileNameForFlashWrite"]),
                    ("dh_utils_module", "TCUWDHUtils.dll"),
                    ("secret_info_module", "SecretInfo.dll"),
                    ("cuw_module", "CUW.dll"),
                )
            }
            identity = identify_native_module(
                hashlib.sha256(attachments["selected_module"]).hexdigest(),
                values["DLLFileNameForFlashWrite"],
            )
            context = bind_native_context(
                container, 1, (), selection, identity, attachments, {"dh_state": state}
            )
            events, requests, pending, snapshots = [], [], [], []
            last = [b""]
            filter_fault = [stop_fault]
            main_filter: list[int | None] = [None]
            original_handler = state.notification.handler
            host_fault = (
                InterruptedError("authored USB cancellation")
                if fault_op.startswith("cancel:")
                else KeyboardInterrupt("authored USB interruption")
                if fault_op.startswith("keyboard:")
                else OSError("authored USB host fault")
            )
            fault_pending = [bool(fault_op)]

            def host(
                event,
                remaining,
                status_byte=status_byte,
                events=events,
                requests=requests,
                pending=pending,
                snapshots=snapshots,
                last=last,
                state=state,
                filter_fault=filter_fault,
                main_filter=main_filter,
                recovery_values=recovery_values,
                fault_pending=fault_pending,
                fault_op=fault_op,
                host_fault=host_fault,
            ):
                events.append(event)
                op = event["operation"]
                if (
                    op == fault_op.rsplit(":", 1)[-1]
                    and fault_pending[0]
                    and (
                        not fault_op.endswith(":stop_filter")
                        or event["identifier"] == main_filter[0]
                    )
                ):
                    fault_pending[0] = False
                    raise host_fault
                if (
                    op == "stop_filter"
                    and filter_fault[0]
                    and event["identifier"] == main_filter[0]
                ):
                    filter_fault[0] = False
                    raise NativeJ2534Error2026(5)
                if op in ("get_timeout", "get_send_timeout"):
                    return 111
                if op == "start_flow_control_filter":
                    if main_filter[0] is None:
                        main_filter[0] = len(events)
                    return len(events)
                if op == "is_sending_sync_periodic":
                    return False
                if op == "notify_progress_percent":
                    snapshots.append(state.progress)
                if op == "write_messages":
                    data = event["data"]
                    if data[:4] not in (
                        bytes.fromhex("00000700"),
                        bytes.fromhex("00000710"),
                        bytes.fromhex("000007a4"),
                        bytes.fromhex("00000786"),
                    ):
                        return 1
                    last[0] = data[:4]
                    pdu = data[4:]
                    requests.append(pdu)
                    if pdu == bytes.fromhex("1a8800"):
                        assert recovery_values is not None
                        reply = bytes.fromhex("5a8800") + bytes(
                            range(1, len(recovery_values) + 1)
                        )
                    elif pdu.startswith(bytes.fromhex("1a88")):
                        assert recovery_values is not None
                        reply = (
                            b"\x5a"
                            + pdu[1:]
                            + recovery_values[pdu[2] - 1].ljust(16, b"\0")
                        )
                    elif pdu in (bytes.fromhex("31010309"), bytes.fromhex("3101030a")):
                        reply = b"\x71" + pdu[1:]
                    elif pdu == bytes.fromhex("1101"):
                        reply = b"\x51"
                    elif pdu == bytes.fromhex("3e01"):
                        reply = b"\x7e"
                    elif pdu == bytes.fromhex("1ab1"):
                        reply = bytes((0x5A, 0xB1, status_byte))
                    elif pdu == bytes.fromhex("1089"):
                        reply = bytes.fromhex("5089")
                    else:
                        self.fail(pdu.hex())
                    pending.append(reply)
                    return 1
                if op == "read_specified_can_message":
                    return (int.from_bytes(last[0], "big") + 8).to_bytes(
                        4, "big"
                    ) + pending.pop(0)

            runtime = NativeRuntime2026(host)
            if recovery_values is not None:
                control_bytes = Path(
                    "runtime/no-car-21/recovered/TCUWControlCommPhase.dll"
                ).read_bytes()
                controller = ControlCommPhase2026(
                    identify_native_module(
                        hashlib.sha256(control_bytes).hexdigest(),
                        "TCUWControlCommPhase.dll",
                    ),
                    runtime,
                )
                worker = engine.bind_worker(controller)
                with engine.controller_execution(controller, 0):
                    engine._import_identifier_context()
                    engine.commit_received_identifiers(
                        (b"TARGET",), controller=controller
                    )
                    self.assertTrue(worker.mark_cid_reception_complete())
                container = engine.native_metadata.source_container
                assert isinstance(container, CalibrationContainer)
                selection = bind_native_parameter2026(
                    container,
                    selection.catalog_sources,
                    "write",
                    encoded=selection.encoded,
                    metadata_state=engine.native_metadata,
                )
                context = bind_native_context(
                    container,
                    1,
                    (),
                    selection,
                    identity,
                    attachments,
                    {"dh_state": state},
                )
                state.mark_native_retry()
                self.assertTrue(state.native_context_964)
            if fault_op:
                if (
                    isinstance(host_fault, OSError)
                    and not isinstance(host_fault, InterruptedError)
                ) or fault_op.endswith(":stop_filter"):
                    with self.assertRaises(type(host_fault)) as caught:
                        execute_context(context, runtime)
                    self.assertIs(caught.exception, host_fault)
                else:
                    cancelled_result = execute_context(context, runtime)
                    self.assertEqual(cancelled_result["state"], "cancelled")
                    self.assertIsNone(cancelled_result["native_return"])
                self.assertIs(state.notification.handler, original_handler)
                self.assertIn({"operation": "set_timeout", "milliseconds": 111}, events)
                self.assertIn(
                    {"operation": "set_send_timeout", "milliseconds": 111}, events
                )
                self.assertEqual((state.primary_error, state.passthru_error), (0, 0))
                self.assertEqual(runtime.close(), [])
                continue
            result = execute_context(context, runtime)
            self.assertEqual(
                result["state"], "writer_completed" if status_byte == 0 else "failed"
            )
            self.assertIs(result["native_return"], status_byte == 0)
            self.assertFalse(pending)
            if recovery_values is not None:
                self.assertEqual(
                    requests[: 1 + len(recovery_values)],
                    [bytes.fromhex("1a8800")]
                    + [
                        bytes((0x1A, 0x88, i))
                        for i in range(1, len(recovery_values) + 1)
                    ],
                )
                requests = requests[1 + len(recovery_values) :]
            self.assertEqual(
                requests[:5] if should_program else [],
                [
                    bytes.fromhex("31010309"),
                    bytes.fromhex("3101030a"),
                    bytes.fromhex("1101"),
                    bytes.fromhex("3e01"),
                    bytes.fromhex("1ab1"),
                ]
                if should_program
                else [],
            )
            self.assertIs(state.notification.handler, original_handler)
            assert engine._persistence is not None
            self.assertFalse(engine._persistence.state.logged)
            self.assertFalse((engine._persistence.output_root / "Save").exists())
            if status_byte == 0:
                self.assertEqual(
                    requests[5:] if should_program else requests,
                    [bytes.fromhex("1089"), bytes.fromhex("1089")],
                )
                self.assertEqual(snapshots, [(0,), (100,)])
                self.assertFalse(bool(state.notification))
            else:
                self.assertEqual((state.error_kind, state.primary_error), (2, 0x40F))
                self.assertEqual(state.progress, (0,))
                self.assertTrue(bool(state.notification))
            self.assertEqual(
                events[-2:],
                [
                    {"operation": "set_timeout", "milliseconds": 111},
                    {"operation": "set_send_timeout", "milliseconds": 111},
                ],
            )
            self.assertEqual(runtime.close(), [])

    def test_classic_writer_two_transfer_passes_actual_progress_and_error_reset(self):
        engine = self.engine_fixture(
            version=8,
            cpu_count=2,
            cpu_index=1,
            image_data=b"S1071000646174614E\nS9031000EC\n",
        )
        state = engine.dh_state
        assert engine._source is not None
        container = parse_cuw_2026(engine._source)
        assert isinstance(container, CalibrationContainer)
        values = {
            "ParamFileKeySystemProtocolMicon": "108CAN383",
            "DLLFileNameForFlashWrite": "TCUWCanDHFlashWriter.dll",
            "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0700/0708",
            "StartAddress": "00001000",
            "FlagToNonChangeReprogGWModeProcess": "1",
        }
        raw_parameter = table(list(values), [list(values.values())])
        selection = bind_dh_parameter_fixture(
            container,
            {"108CAN383.ini": raw_parameter},
            "write",
            cpu_index=1,
            encoded=False,
        )
        module_name = "TCUWCanDHFlashWriter.dll"
        attachments = {
            name: Path("runtime/no-car-21/recovered", filename).read_bytes()
            for name, filename in (
                ("selected_module", module_name),
                ("dh_utils_module", "TCUWDHUtils.dll"),
                ("secret_info_module", "SecretInfo.dll"),
                ("cuw_module", "CUW.dll"),
            )
        }
        identity = identify_native_module(
            hashlib.sha256(attachments["selected_module"]).hexdigest(), module_name
        )
        context = bind_native_context(
            container,
            1,
            (),
            selection,
            identity,
            attachments,
            {"dh_state": state, "cpu_index": 1},
        )
        unbound_engine = self.engine_fixture(
            version=8,
            cpu_count=2,
            cpu_index=1,
            image_data=b"S1071000646174614E\nS9031000EC\n",
            persistence=False,
        )
        unbound = bind_native_context(
            container,
            1,
            (),
            selection,
            identity,
            attachments,
            {"dh_state": unbound_engine.dh_state, "cpu_index": 1},
        )
        rejected_events = []
        with self.assertRaisesRegex(ValueError, "persistence"):
            execute_context(
                unbound,
                NativeRuntime2026(
                    lambda event, remaining: rejected_events.append(event)
                ),
            )
        self.assertEqual(rejected_events, [])
        events, requests, pending = [], [], []

        main_filter: list[int | None] = [None]
        filter_fault = [True]

        def host(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "get_timeout":
                return 101
            if operation == "get_send_timeout":
                return 102
            if operation == "start_flow_control_filter":
                if main_filter[0] is None:
                    main_filter[0] = len(events)
                return len(events)
            if (
                operation == "stop_filter"
                and event["identifier"] == main_filter[0]
                and filter_fault[0]
            ):
                filter_fault[0] = False
                raise NativeJ2534Error2026(5)
            if operation == "is_sending_sync_periodic":
                return False
            if operation == "write_messages":
                pdu = event["data"][4:]
                requests.append(pdu)
                if pdu.startswith(b"\x34"):
                    pending.append(bytes.fromhex("74200003"))
                elif pdu.startswith(b"\x36"):
                    pending.append(b"\x76")
                elif pdu == b"\x37":
                    pending.append(b"\x77")
                elif pdu.startswith(bytes.fromhex("3101f011000144")):
                    pending.append(bytes.fromhex("7101f011200003"))
                elif pdu == bytes.fromhex("3101f01101"):
                    pending.append(bytes.fromhex("7101f01100"))
                elif pdu == bytes.fromhex("1101"):
                    pending.append(b"\x51")
                else:
                    self.fail("Unexpected native writer PDU")
                return 1
            if operation == "read_specified_can_message":
                return bytes.fromhex("00000708") + pending.pop(0)

        runtime = NativeRuntime2026(host)
        result = execute_context(context, runtime)
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["cleanup_errors"], ["NativeJ2534Error2026"])
        self.assertEqual(result["state"], "writer_completed")
        self.assertFalse(bool(state.notification))
        assert engine._persistence is not None
        self.assertTrue(engine._persistence.state.logged)
        saved = engine._persistence.output_root / "Save"
        self.assertEqual((saved / "authored.cuw").read_bytes(), engine._source)
        recovery_file = parse_recovery_info((saved / "RecoveryInfo.ini").read_bytes())
        self.assertEqual(recovery_file.sections["RecoveryInfo"]["Writing"], "1")
        self.assertFalse(result["programming_completed"])
        self.assertEqual(
            requests,
            [
                bytes.fromhex("3401440000100000000004"),
                b"\x36da",
                b"\x36ta",
                b"\x37",
                bytes.fromhex("3101f0110001440000100000000004"),
                b"\x36da",
                b"\x36ta",
                b"\x37",
                bytes.fromhex("3101f01101"),
                bytes.fromhex("1101"),
            ],
        )
        self.assertEqual(state.progress, (0, 100))
        self.assertEqual(state.transferred_bytes, (0, 8))
        self.assertEqual(
            [
                event["progress"]
                for event in events
                if event["operation"] == "notify_progress"
            ],
            [25, 50, 75, 100],
        )
        self.assertEqual(runtime.close(), [])
        events.clear()
        main_filter[0], filter_fault[0] = None, True
        requests.clear()

        def failing(event, remaining):
            if event["operation"] == "write_messages" and event["data"][
                4:
            ] == bytes.fromhex("3101f01101"):
                events.append(event)
                raise NativeTransportError(9)
            return host(event, remaining)

        runtime = NativeRuntime2026(failing)
        result = execute_context(context, runtime)
        self.assertEqual(result["state"], "failed")
        self.assertIs(result["native_return"], False)
        self.assertEqual(result["cleanup_errors"], ["NativeJ2534Error2026"])
        self.assertEqual(state.transferred_bytes, (0, 0))
        self.assertEqual(state.progress, (0, 0))
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error), (2, 1, 9)
        )
        self.assertEqual(
            (
                result["native_error_kind"],
                result["native_primary_error"],
                result["native_passthru_error"],
            ),
            (2, 1, 9),
        )
        self.assertEqual(
            [
                event["operation"]
                for event in events
                if event["operation"].startswith("notify_progress_")
            ],
            ["notify_progress_count", "notify_progress_percent"],
        )
        self.assertEqual(runtime.close(), [])
        events.clear()

        def negative(event, remaining):
            if event["operation"] == "write_messages" and event["data"][
                4:
            ] == bytes.fromhex("3101f01101"):
                events.append(event)
                pending.append(bytes.fromhex("7f3172"))
                return 1
            return host(event, remaining)

        runtime = NativeRuntime2026(negative)
        result = execute_context(context, runtime)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error), (2, 0x21, 9)
        )
        self.assertEqual(
            (
                result["native_error_kind"],
                result["native_primary_error"],
                result["native_passthru_error"],
            ),
            (2, 0x21, 9),
        )
        self.assertEqual(state.progress, (0, 0))
        self.assertEqual(runtime.close(), [])
        host_fault = OSError("host transport callback failed")
        state.record_native_error(2, 0x21, 9)

        def faulty_host(event, remaining):
            if event["operation"] == "write_messages":
                raise host_fault
            return host(event, remaining)

        runtime = NativeRuntime2026(faulty_host)
        with self.assertRaises(OSError) as raised:
            execute_context(context, runtime)
        self.assertIs(raised.exception, host_fault)
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error), (2, 0x21, 9)
        )
        self.assertFalse(runtime.owns_resource("disconnect"))
        self.assertFalse(runtime.owns_resource("stop_filter", identifier=19))
        events.clear()
        requests.clear()
        attachments["retry_prepare_module"] = Path(
            "runtime/no-car-21/recovered/TCUWCanDHPrepareWriter.dll"
        ).read_bytes()
        recovery = bind_native_context(
            container,
            1,
            (),
            selection,
            identity,
            attachments,
            {"cpu_index": 1, "dh_state": state, "operation": "recovery"},
        )

        def retry_host(event, remaining):
            if event["operation"] == "write_messages":
                events.append(event)
                pdu = event["data"][4:]
                requests.append(pdu)
                if event["data"] == bytes.fromhex("000007a42105"):
                    raise NativeTransportError(9)
                if pdu == bytes.fromhex("1085"):
                    pending.append(bytes.fromhex("5085"))
                elif pdu == bytes.fromhex("2701"):
                    pending.append(bytes.fromhex("67010102030400"))
                elif pdu == bytes.fromhex("270201020304"):
                    pending.append(bytes.fromhex("670234"))
                return 1
            return host(event, remaining)

        runtime = NativeRuntime2026(retry_host)
        result = execute_context(recovery, runtime)
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "prepare_retry_completed")
        self.assertEqual(
            requests[-3:],
            [
                bytes.fromhex("1085"),
                bytes.fromhex("2701"),
                bytes.fromhex("270201020304"),
            ],
        )
        self.assertEqual(state.cpu_index, 1)
        self.assertEqual(state.central_gateway_type, 1)
        self.assertEqual(runtime.close(), [])
        events.clear()
        requests.clear()
        first_engine = self.engine_fixture(
            version=8,
            cpu_count=2,
            cpu_index=0,
            image_data=b"S1071000646174614E\nS9031000EC\n",
        )
        general_values = {
            "ParamFileKeySystemProtocolMicon": "108CAN383",
            "FlagToDoIGOFFONAtCPUTypeChange": "0",
            "M16CTypeFlag": "0",
            "FORESTTypeFlag": "0",
        }
        selected_values = dict(values, FlagToDoIGOFFONAtCPUTypeChange="1")
        general_sources = {
            "108CAN383.ini": table(
                list(selected_values), [list(selected_values.values())]
            ),
            "Parameter.ini": table(
                list(general_values), [list(general_values.values())]
            ),
        }
        first_engine = self.engine_fixture(
            version=8,
            cpu_count=2,
            cpu_index=0,
            image_data=b"S1071000646174614E\nS9031000EC\n",
            general_parameter_source=general_sources["Parameter.ini"],
        )
        first_binding = bind_dh_parameter_fixture(
            container, general_sources, "write", cpu_index=0, encoded=False
        )
        first_context = bind_native_context(
            container,
            1,
            (),
            first_binding,
            identity,
            attachments,
            {"cpu_index": 0, "dh_state": first_engine.dh_state},
        )
        runtime = NativeRuntime2026(host)
        result = execute_context(first_context, runtime)
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "writer_completed")
        self.assertIn({"operation": "notify_cpu_type_change", "cpu_index": 1}, events)
        self.assertEqual(first_engine.dh_state.progress, (100, 0))
        self.assertEqual(runtime.close(), [])

    def test_classic_prepare_native_mask_authentication_and_timeout_restore(self):
        state = self.engine_fixture().dh_state
        values = {
            "ParamFileKeySystemProtocolMicon": "synthetic-prepare-DH",
            "DLLFileNameForPrepareWrite": "TCUWCanDHPrepareWriter.dll",
            "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0700/0708",
            "KindOfDiagnosticMask": "1",
            "FlagToNonChangeReprogGWModeProcess": "1",
            "SecurityKey": "0000",
            "WaitTimeAfterDiagnosticMask": "3",
        }
        selection = CalibrationCatalog.from_tables(
            {"authored-prepare.csv": table(list(values), [list(values.values())])},
            encoded=False,
        ).select("synthetic-prepare-DH")
        identity = identify_native_module(
            "90ad0870339d233829f6e923de4150ed4fedc40a922a97de0e251760291985a5",
            "TCUWCanDHPrepareWriter.dll",
        )
        context = bind_dh_prepare(selection, SelectionContext(), identity, state)
        events, pending = [], []

        def host(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "get_timeout":
                return 101
            if operation == "get_send_timeout":
                return 102
            if operation == "is_sending_sync_periodic":
                return False
            if operation == "start_flow_control_filter":
                return len(events)
            if operation == "write_messages":
                request = event["data"]
                if request == bytes.fromhex("000007a42105"):
                    raise NativeTransportError(9)
                if request == bytes.fromhex("000007001085"):
                    pending.append(bytes.fromhex("000007085085"))
                elif request == bytes.fromhex("000007002701"):
                    pending.append(bytes.fromhex("0000070867010102030400"))
                elif request.startswith(bytes.fromhex("000007002702")):
                    self.assertEqual(request, bytes.fromhex("00000700270208040102"))
                    pending.append(bytes.fromhex("00000708670234"))
                return 1
            if operation == "read_specified_can_message":
                return pending.pop(0)

        runtime = NativeRuntime2026(host)
        utils_identity = identify_native_module(
            "dbf581e9a7c91364406a8f3bfff3a7cdf69535eb95f5f8ee1c75b0ae123c6640",
            "TCUWDHUtils.dll",
        )
        gateway = DHGateway2026(
            runtime,
            selection,
            utils_identity,
            SecretInfoClient(b"test", (), "synthetic"),
        )
        result = prepare_dh(context, runtime, gateway)
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "prepare_completed")
        self.assertEqual(state.central_gateway_type, 1)
        self.assertEqual(
            [event["milliseconds"] for event in events if event["operation"] == "wait"],
            [3, 3, 3, 100, 100, 100, 0, 0, 0],
        )
        self.assertEqual(
            events[-2:],
            [
                {"operation": "set_timeout", "milliseconds": 101},
                {"operation": "set_send_timeout", "milliseconds": 102},
            ],
        )
        self.assertFalse(
            any(event["operation"] == "stop_sync_periodic" for event in events)
        )
        self.assertEqual(runtime.close(), [])
        self.assertEqual(events[-1], {"operation": "disconnect"})
        events.clear()
        alternate_values = dict(values, KindOfDiagnosticMask="0")
        alternate_selection = CalibrationCatalog.from_tables(
            {
                "authored-protocol5.csv": table(
                    list(alternate_values), [list(alternate_values.values())]
                )
            },
            encoded=False,
        ).select("synthetic-prepare-DH")
        alternate_context = bind_dh_prepare(
            alternate_selection, SelectionContext(), identity, state
        )
        runtime = NativeRuntime2026(host)
        alternate_gateway = DHGateway2026(
            runtime, alternate_selection, utils_identity, gateway.secret_info
        )
        result = prepare_dh(alternate_context, runtime, alternate_gateway)
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "prepare_completed")
        self.assertEqual(
            [event["protocol"] for event in events if event["operation"] == "connect"],
            [6, 5, 6],
        )
        self.assertEqual(
            [
                event["data"]
                for event in events
                if event["operation"] == "write_messages" and event["protocol"] == 5
            ],
            [bytes.fromhex("0000072002a027e916000000")] * 3,
        )
        self.assertEqual(runtime.close(), [])
        events.clear()

        su_values = dict(values, FlagToSURegulation="1")
        su_selection = CalibrationCatalog.from_tables(
            {"authored-su.csv": table(list(su_values), [list(su_values.values())])},
            encoded=False,
        ).select("synthetic-prepare-DH")
        su_context = bind_dh_prepare(su_selection, SelectionContext(), identity, state)
        periodic = [False]

        def su_host(event, remaining):
            operation = event["operation"]
            if operation in (
                "start_sync_periodic",
                "stop_sync_periodic",
                "is_sending_sync_periodic",
                "calculate_dh_gateway_key",
            ):
                events.append(event)
                if operation == "start_sync_periodic":
                    periodic[0] = True
                elif operation == "stop_sync_periodic":
                    periodic[0] = False
                elif operation == "is_sending_sync_periodic":
                    return periodic[0]
                else:
                    self.assertEqual(event["seed"], b"S" * 16)
                    self.assertTrue(event["secret"] == secret_info.get(0x2E))
                    return dh_aes(0x2E)
                return None
            if operation == "write_messages" and event["data"] == bytes.fromhex(
                "00000700270102"
            ):
                events.append(event)
                pending.append(bytes.fromhex("000007086701") + b"S" * 16 + b"\0")
                return 1
            if operation == "write_messages" and event["data"].startswith(
                bytes.fromhex("000007002702")
            ):
                events.append(event)
                self.assertEqual(
                    event["data"], bytes.fromhex("000007002702") + dh_aes(0x2E)
                )
                pending.append(bytes.fromhex("00000708670234"))
                return 1
            return host(event, remaining)

        runtime = NativeRuntime2026(su_host)
        secret_info = native_secret_client()
        su_gateway = DHGateway2026(runtime, su_selection, utils_identity, secret_info)
        result = prepare_dh(su_context, runtime, su_gateway)
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "prepare_completed")
        self.assertTrue(periodic[0])
        self.assertEqual(sum(event["operation"] == "lock" for event in events), 3)
        self.assertEqual(sum(event["operation"] == "unlock" for event in events), 3)
        self.assertEqual(runtime.close(), [])
        self.assertFalse(periodic[0])
        events.clear()

        def failing(event, remaining):
            if event["operation"] == "write_messages" and event[
                "data"
            ] == bytes.fromhex("000007001085"):
                events.append(event)
                raise NativeTransportError(9)
            return host(event, remaining)

        runtime = NativeRuntime2026(failing)
        gateway = DHGateway2026(runtime, selection, utils_identity, gateway.secret_info)
        result = prepare_dh(context, runtime, gateway)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["internal_retry_count"], 30)
        self.assertEqual(
            sum(
                event["operation"] == "write_messages"
                and event["data"] == bytes.fromhex("000007001085")
                for event in events
            ),
            31,
        )
        self.assertIn({"operation": "stop_sync_periodic"}, events)
        self.assertEqual(
            events[-2:],
            [
                {"operation": "set_timeout", "milliseconds": 101},
                {"operation": "set_send_timeout", "milliseconds": 102},
            ],
        )
        self.assertEqual(runtime.close(), [])
        events.clear()
        cancelled = [False]

        def cancelling(event, remaining):
            answer = host(event, remaining)
            if event["operation"] == "write_messages" and event[
                "data"
            ] == bytes.fromhex("00000720a027"):
                cancelled[0] = True
            return answer

        runtime = NativeRuntime2026(cancelling, cancelled=lambda: cancelled[0])
        gateway = DHGateway2026(runtime, selection, utils_identity, gateway.secret_info)
        result = prepare_dh(context, runtime, gateway)
        self.assertIsNone(result["native_return"])
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(result["internal_retry_count"], 0)
        self.assertEqual(result["cleanup_errors"], [])
        self.assertEqual(
            events[-2:],
            [
                {"operation": "set_timeout", "milliseconds": 101},
                {"operation": "set_send_timeout", "milliseconds": 102},
            ],
        )
        self.assertEqual(runtime.close(), [])

    def engine_fixture(
        self,
        version=8,
        region=0,
        cpu_count=1,
        cpu_index=0,
        image_data=b"data",
        kind="108",
        persistence=True,
        general_parameter_source=None,
        cpu_extra="",
        extra_images=(),
        flash_code_data=None,
    ):
        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 engine identity absent")
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": authored_general_source()
                if general_parameter_source is None
                else general_parameter_source
            },
            encoded=False,
        )
        engine = CUWEngine2026(image.read_bytes(), general_parameters=general)
        engine.configure(struct.pack("<IIddII", cpu_count, 0, 1, 2, 0, 0))

        def record(header, data):
            return (
                struct.pack(">H", len(header))
                + header
                + struct.pack(">II", len(data), zlib.crc32(data))
                + data
            )

        text = f"[Format]\nVersion={version}\n[Vehicle]\nNumberOfCalibration={cpu_count}\nByteNumberOfTransmitting=FFF\nContactType=CAN\nKindOfECU={kind}\n[CPU01]\nCPUType=383\nCPUImageName=authored.bin\nLocationID=1234\nNewCID=ABCDEF12345\n".encode(
            "ascii"
        )
        text += cpu_extra.encode("ascii")
        text += b"".join(
            f"[CPU{index:02}]\nCPUType=383\nCPUImageName=authored.bin\nLocationID=1234\nNewCID=ABCDEF12345\n".encode(
                "ascii"
            )
            for index in range(2, cpu_count + 1)
        )
        body = (
            record(b"attach.att", text)
            + bytes((cpu_count + len(extra_images),))
            + b"".join(record(b"authored", image_data) for _ in range(cpu_count))
            + b"".join(record(b"divided", data) for data in extra_images)
            + (b"" if flash_code_data is None else record(b"flash", flash_code_data))
        )
        suffix = struct.pack(">I", 22 + len(body)) + body
        engine.load_cuw(
            b"\0CALIBRATION\0\x68" + struct.pack(">I", zlib.crc32(suffix)) + suffix,
            cpu_index=0,
            region=region,
        )
        if persistence:
            output = tempfile.TemporaryDirectory(dir="runtime/no-car-33")
            self.addCleanup(output.cleanup)
            assert engine._source is not None
            engine.bind_persistence(
                CUWPersistence(
                    Path(output.name),
                    ReproInfoState(
                        (RecoveryCalibration("authored.cuw", engine._source),)
                    ),
                )
            )
        if cpu_index:
            control_bytes = Path(
                "runtime/no-car-21/recovered/TCUWControlCommPhase.dll"
            ).read_bytes()
            control = ControlCommPhase2026(
                identify_native_module(
                    hashlib.sha256(control_bytes).hexdigest(),
                    "TCUWControlCommPhase.dll",
                ),
                NativeRuntime2026(lambda event, remaining: None),
            )
            engine.select_target(1, cpu_index, controller=control)
        return engine

    def test_stateful_writable_getter_engine_binding_and_retry_stage(self):
        state = self.engine_fixture().dh_state
        values = {
            "ParamFileKeySystemProtocolMicon": "synthetic-write-DH-2026",
            "DLLFileNameForGetCID": "TCUWCanDHWritableSoftMaskIDAndCIDGetter.dll",
            "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
            "CanIDForGetCID": "0700/0708",
            "ComplementCID": "P",
        }
        selection = CalibrationCatalog.from_tables(
            {"authored-stateful.csv": table(list(values), [list(values.values())])},
            encoded=False,
        ).select("synthetic-write-DH-2026")
        identity = identify_native_module(
            "6daa33b6bc5d3e86db07c70cc64268b2c96f76d81976626987c12320168f3010",
            values["DLLFileNameForGetCID"],
        )
        context = bind_stateful_dh_getter(
            selection, SelectionContext(), identity, state
        )
        events, requests = [], []
        replies = iter(
            (
                bytes.fromhex("000007085a") + b"ABCDE",
                bytes.fromhex("000007087b08"),
                bytes.fromhex("000007087b09"),
                bytes.fromhex("000007085a1234"),
                bytes.fromhex("000007085a") + b"12345",
            )
        )

        def host(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 0
            if event["operation"] == "start_flow_control_filter":
                return 23
            if event["operation"] == "write_messages":
                requests.append(event["data"])
                return 1
            if event["operation"] == "read_specified_can_message":
                return next(replies)

        # Unit fixture models the native writer's completed CPU status. Production
        # exposes no status setter; actual writer completion integration stays OPEN.
        object.__setattr__(state, "_progress", (100,))
        success_replies = replies
        replies = iter(
            (bytes.fromhex("000007085a") + b"ABCDE", bytes.fromhex("000007087f3b72"))
        )
        result = get_stateful_dh_cids(context, NativeRuntime2026(host))
        self.assertEqual(result["state"], "failed")
        self.assertEqual(state.getter_stage, 1)
        self.assertEqual(
            [event["operation"] for event in events][-2:], ["stop_filter", "disconnect"]
        )
        requests.clear()
        next(success_replies)  # The successful pre-read is retained in native stage1.
        replies = success_replies
        result = get_stateful_dh_cids(context, NativeRuntime2026(host))
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "read_completed")
        self.assertEqual(state.getter_stage, 4)
        self.assertEqual(result["identifiers"][0]["identifier"], b"P12345")
        self.assertEqual(
            [value[4:] for value in requests],
            [
                bytes.fromhex("3b081234"),
                b"\x3b\x09" + b"12345",
                bytes.fromhex("1ab0"),
                bytes.fromhex("1a81"),
            ],
        )
        requests.clear()
        replies = iter((bytes.fromhex("000007085a") + b"12345",))
        self.assertEqual(
            get_stateful_dh_cids(context, NativeRuntime2026(host))["state"],
            "read_completed",
        )
        self.assertEqual(requests, [bytes.fromhex("000007001a81")])

    def test_classic_normal_getter_actual_binding_and_offset_quirk(self):
        for suffix, expected in ((b"ABCDE", b"PABCDE"), (b"ZABCDE", b"PABCDE")):
            values = {
                "ParamFileKeySystemProtocolMicon": "synthetic-classic-DH-2026",
                "DLLFileNameForGetCID": "TCUWCanDHSoftwareIDGetter.dll",
                "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
                "CanIDForGetCID": "0700/0708",
                "ComplementCID": "P",
            }
            selection = CalibrationCatalog.from_tables(
                {"authored-classic.csv": table(list(values), [list(values.values())])},
                encoded=False,
            ).select("synthetic-classic-DH-2026")
            identity = identify_native_module(
                "4d87a35e34938411a0e6b97676c14536fdc5c693603ef7ebb5e445d61fd0a0de",
                values["DLLFileNameForGetCID"],
            )
            context = bind_dh_getter(selection, SelectionContext(), identity)
            events = []

            def host(event, remaining, events=events, suffix=suffix):
                events.append(event)
                operation = event["operation"]
                if operation == "start_flow_control_filter":
                    return 17
                if operation == "write_messages":
                    self.assertEqual(event["data"], bytes.fromhex("000007001a81"))
                    return 1
                if operation == "read_specified_can_message":
                    return bytes.fromhex("000007085a") + suffix
                if operation == "get_timeout":
                    return 0

            result = get_dh_cids(context, NativeRuntime2026(host))
            self.assertIs(result["native_return"], True)
            self.assertEqual(result["state"], "read_completed")
            self.assertEqual(result["identifiers"][0]["identifier"], expected)
            self.assertEqual(
                [event["operation"] for event in events][:2], ["connect", "set_timeout"]
            )
            self.assertEqual(
                [event["operation"] for event in events][-2:],
                ["stop_filter", "disconnect"],
            )

    @staticmethod
    def bind(**overrides):
        values = {
            "ParamFileKeySystemProtocolMicon": "synthetic-DH-2026",
            "DLLFileNameForGetCID": "TCUWCanDHUDSSoftwareIDGetter.dll",
            "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
            "CanIDForGetCID": "0700/0708",
            "ReceiveTimeoutBeforeGetCID": "666",
        }
        values.update(overrides)
        selection = CalibrationCatalog.from_tables(
            {"authored-DH.csv": table(list(values), [list(values.values())])},
            encoded=False,
        ).select("synthetic-DH-2026")
        identity = identify_native_module(
            "05f1c79be3cabb40633d4c8acf05c2ca1fa28c0bcc07ac04b682d96477d35982",
            "TCUWCanDHUDSSoftwareIDGetter.dll",
        )
        return bind_dhuds_getter(selection, SelectionContext(), identity)

    def test_actual_parameter_binding_and_wire_lifecycle(self):
        context = self.bind()
        self.assertEqual(context.receive_timeout_ms, 666)
        events = []
        replies = [
            bytes.fromhex("000007087f2278"),
            bytes.fromhex("0000070862f18101") + b"ACTUAL-ID".ljust(16, b"\0"),
        ]

        def host(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 666
            if event["operation"] == "start_flow_control_filter":
                self.assertEqual(event["request_address"], bytes.fromhex("00000700"))
                self.assertEqual(event["response_address"], bytes.fromhex("00000708"))
                return 7
            if event["operation"] == "write_messages":
                self.assertEqual(event["data"], bytes.fromhex("0000070022f181"))
                return 1
            if event["operation"] == "read_specified_can_message":
                return replies.pop(0)

        result = get_dhuds_cids(context, NativeRuntime2026(host))
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "read_completed")
        self.assertEqual(
            result["identifiers"],
            [
                {
                    "identifier": b"ACTUAL-ID",
                    "request_id": bytes.fromhex("0700"),
                    "response_id": bytes.fromhex("0708"),
                }
            ],
        )
        self.assertFalse(result["programming_completed"])
        self.assertEqual(
            [event["operation"] for event in events][-2:], ["stop_filter", "disconnect"]
        )
        self.assertEqual(
            sum(event["operation"] == "write_messages" for event in events), 1
        )
        self.assertEqual(events[0], {"operation": "set_timeout", "milliseconds": 666})
        self.assertFalse(replies)

    def test_softmask_getter_two_native_selectors(self):
        fields = {
            "ParamFileKeySystemProtocolMicon": "synthetic-mask",
            "DLLFileNameForGetCID": "TCUWCanDHSoftMaskIDGetter.dll",
            "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
            "CanIDForGetCID": "0700/0708",
            "ComplementCID": "PREFIX",
        }
        selection = CalibrationCatalog.from_tables(
            {"authored-mask.csv": table(list(fields), [list(fields.values())])},
            encoded=False,
        ).select("synthetic-mask")
        identity = identify_native_module(
            "a00951122898a8d93a17307efaf480bfdc4df3abb6c0a49303760764e019d0d5",
            "TCUWCanDHSoftMaskIDGetter.dll",
        )
        context = bind_dh_getter(selection, SelectionContext(), identity)
        events = []
        replies = [
            bytes.fromhex("000007085a8801") + b"ABCD",
            bytes.fromhex("000007085a8802") + b"EF\0G",
        ]

        def host(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 0
            if event["operation"] == "start_flow_control_filter":
                return 17
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                return replies.pop(0)

        result = get_dh_cids(context, NativeRuntime2026(host))
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "read_completed")
        self.assertEqual(
            [row["identifier"] for row in result["identifiers"]],
            [b"PREFIXABCD", b"PREFIXEF"],
        )
        self.assertEqual(
            [
                event["data"].hex()
                for event in events
                if event["operation"] == "write_messages"
            ],
            ["000007001a8801", "000007001a8802"],
        )
        self.assertEqual(
            [event["operation"] for event in events][-2:], ["stop_filter", "disconnect"]
        )
        self.assertFalse(replies)

    def test_combined_software_and_softmask_getter(self):
        fields = {
            "ParamFileKeySystemProtocolMicon": "synthetic-combined",
            "DLLFileNameForGetCID": "TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll",
            "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
            "CanIDForGetCID": "0700/0708",
            "ComplementCID": "PREFIX",
            "PIDForReadSoftMaskID": "B0",
            "SoftMaskIDRespDataSize": "10",
        }
        selection = CalibrationCatalog.from_tables(
            {"authored-combined.csv": table(list(fields), [list(fields.values())])},
            encoded=False,
        ).select("synthetic-combined")
        identity = identify_native_module(
            "f4c64d2611e599ca3be98d23e9850354e8808ef9dee221529fd5beb024849bd7",
            "TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll",
        )
        context = bind_dh_getter(selection, SelectionContext(), identity)
        events = []
        replies = [
            bytes.fromhex("000007085a") + b"ABCDE",
            bytes.fromhex("0000070861b0") + b"12345678",
        ]

        def host(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 0
            if event["operation"] == "start_flow_control_filter":
                return 17
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                return replies.pop(0)

        result = get_dh_cids(context, NativeRuntime2026(host))
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "read_completed")
        self.assertEqual(
            [row["identifier"] for row in result["identifiers"]],
            [b"PREFIXABCDE12345678"],
        )
        self.assertEqual(
            [
                event["data"].hex()
                for event in events
                if event["operation"] == "write_messages"
            ],
            ["000007001a81", "0000070021b0"],
        )
        self.assertFalse(replies)

    def test_phase5_vehicle_info_fixed_native_addresses_and_parser(self):
        fields = {
            "ParamFileKeySystemProtocolMicon": "synthetic-P5-DH",
            "DLLFileNameForGetCID": "TCUWP5CanDHVehicleInfoCIDGetter.dll",
        }
        selection = CalibrationCatalog.from_tables(
            {"authored-P5.csv": table(list(fields), [list(fields.values())])},
            encoded=False,
        ).select("synthetic-P5-DH")
        identity = identify_native_module(
            "1aed2dc5bf07e2fef9c240bced7bd8404112d5f99359a7dcec2f011758e126f5",
            "TCUWP5CanDHVehicleInfoCIDGetter.dll",
        )
        context = bind_dh_getter(selection, SelectionContext(), identity)
        events = []

        def host(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 0
            if event["operation"] == "start_flow_control_filter":
                self.assertEqual(event["request_address"], bytes.fromhex("000007e0"))
                self.assertEqual(event["response_address"], bytes.fromhex("000007e8"))
                return 17
            if event["operation"] == "write_messages":
                self.assertEqual(event["data"], bytes.fromhex("000007df0904"))
                return 1
            if event["operation"] == "read_specified_can_message":
                return bytes.fromhex("000007e8490401") + b"1234567890123456"

        result = get_dh_cids(context, NativeRuntime2026(host))
        self.assertIs(result["native_return"], True)
        self.assertEqual(result["state"], "read_completed")
        self.assertEqual(
            [row["identifier"] for row in result["identifiers"]], [b"1234567890123456"]
        )
        self.assertIn("lock", [event["operation"] for event in events])
        self.assertIn("unlock", [event["operation"] for event in events])
        self.assertEqual(
            [event["operation"] for event in events][-2:], ["stop_filter", "disconnect"]
        )
        self.assertEqual(decode_p5_vehicle_info_cids(bytes.fromhex("490400")), ())
        for invalid in (
            bytes.fromhex("4904"),
            bytes.fromhex("490401") + b"x" * 15,
            bytes.fromhex("490401") + bytes(16),
        ):
            with self.assertRaises(ValueError):
                decode_p5_vehicle_info_cids(invalid)

    def test_bad_catalog_geometry_or_timeout_fails_without_io(self):
        for override in (
            {"CanIDForGetCID": "070001/070801"},
            {"ReceiveTimeoutBeforeGetCID": "-1"},
            {"ReceiveTimeoutBeforeGetCID": "99999999999"},
            {"CanIDForGetCID": ""},
            {"DLLFileNameForGetCID": "Wrong.dll"},
        ):
            with self.assertRaises((ValueError, LookupError)):
                self.bind(**override)

    def test_faults_and_cancel_release_native_resources(self):
        context = self.bind()
        for fault in (
            "connect",
            "start_flow_control_filter",
            "write_messages",
            "read_specified_can_message",
            "stop_filter",
            "disconnect",
        ):
            events = []
            failure = OSError("injected primitive failure")

            def host(event, remaining, fault=fault, events=events, failure=failure):
                events.append(event)
                op = event["operation"]
                if op == fault:
                    raise failure
                if op == "get_timeout":
                    return 666
                if op == "start_flow_control_filter":
                    return 7
                if op == "write_messages":
                    return 1
                if op == "read_specified_can_message":
                    return bytes.fromhex("0000070862f18100")

            with self.assertRaises(OSError) as raised:
                get_dhuds_cids(context, NativeRuntime2026(host))
            self.assertIs(raised.exception, failure)
            self.assertIn("disconnect", [event["operation"] for event in events], fault)
            if fault not in ("connect", "start_flow_control_filter"):
                self.assertIn(
                    "stop_filter", [event["operation"] for event in events], fault
                )
        events = []
        cancel = [False]

        def cancelling(event, remaining):
            events.append(event["operation"])
            if event["operation"] == "start_flow_control_filter":
                cancel[0] = True
                return 7

        result = get_dhuds_cids(
            context, NativeRuntime2026(cancelling, cancelled=lambda: cancel[0])
        )
        self.assertIsNone(result["native_return"])
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(events[-2:], ["stop_filter", "disconnect"])


class GatewayStateLifecycle(unittest.TestCase):
    @staticmethod
    def gateway(host):
        fields = {
            "ParamFileKeySystemProtocolMicon": "synthetic-gateway",
            "DLLFileNameForPrepareWrite": "TCUWCanDHPrepareWriter.dll",
        }
        selection = CalibrationCatalog.from_tables(
            {"gateway.csv": table(list(fields), [list(fields.values())])}, encoded=False
        ).select("synthetic-gateway")
        identity = identify_native_module(
            "dbf581e9a7c91364406a8f3bfff3a7cdf69535eb95f5f8ee1c75b0ae123c6640",
            "TCUWDHUtils.dll",
        )
        client = native_secret_client()
        return DHGateway2026(NativeRuntime2026(host), selection, identity, client)

    def test_single_cpu_gateway_client_flow_and_timeout_restore(self):
        events = []
        timeout = [321]
        last = [b""]
        handle = [0]
        replies = {
            "000007863e00": "0000078e7e00",
            "000006f13e00": "000006fe7e00",
            "00000786105f": "0000078e5002",
            "000007861089": "0000078e5089",
            "000007861087": "0000078e5087",
        }

        def host(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "get_timeout":
                return timeout[0]
            if operation == "set_timeout":
                timeout[0] = event["milliseconds"]
            if operation == "start_flow_control_filter":
                handle[0] += 1
                return handle[0]
            if operation == "is_sending_sync_periodic":
                return False
            if operation == "write_messages":
                last[0] = event["data"]
                return 1
            if operation == "read_specified_can_message":
                if last[0] == bytes.fromhex("00000786270103"):
                    return bytes.fromhex("0000078e6701") + bytes(range(16)) + b"\xaa"
                if last[0] == bytes.fromhex("000007862702") + dh_aes(
                    1, bytes(range(16))
                ):
                    return bytes.fromhex("0000078e670234")
                return bytes.fromhex(replies[last[0].hex()])
            if operation == "calculate_dh_gateway_key":
                self.assertTrue(event["secret"] == gateway.secret_info.get(1))
                self.assertEqual(event["seed"], bytes(range(16)))
                return dh_aes(1, bytes(range(16)))

        gateway = self.gateway(host)
        self.assertFalse(gateway.mode_could_be_changed)
        gateway.start_reprogramming_mode()
        self.assertTrue(gateway.mode_could_be_changed)
        self.assertEqual(gateway.security_table_kind, 0)
        self.assertEqual(timeout[0], 321)
        self.assertEqual(
            [
                event["data"].hex()
                for event in events
                if event["operation"] == "write_messages"
            ],
            [
                "000007863e00",
                "000006f13e00",
                "00000786105f",
                "000007861089",
                "000007861087",
                "00000786270103",
                "000007862702" + (dh_aes(1, bytes(range(16)))).hex(),
            ],
        )
        self.assertEqual(
            [
                event["identifier"]
                for event in events
                if event["operation"] == "stop_filter"
            ],
            [2, 1],
        )
        self.assertEqual(gateway.runtime.close(), [])

    def test_online_two_cpu_authentication_uses_raw_keys_and_owned_periodic(self):
        events = []
        sending = [False]
        last = [b""]
        handles = [0]
        seed = bytes(range(16))
        pairs = [
            (bytes.fromhex("000007a41087"), bytes.fromhex("000007ac5087")),
            (
                bytes.fromhex("000007a4270107"),
                bytes.fromhex("000007ac6701") + b"12345678\0",
            ),
            (
                bytes.fromhex("000007a42702") + b"O" * 64,
                bytes.fromhex("000007ac670234"),
            ),
            (
                bytes.fromhex("000007a4270103"),
                bytes.fromhex("000007ac6701") + seed + b"\0",
            ),
            (
                bytes.fromhex("000007a42702") + dh_aes(0x14, bytes(range(16))),
                bytes.fromhex("000007ac670234"),
            ),
            (bytes.fromhex("000007861087"), bytes.fromhex("0000078e5087")),
            (
                bytes.fromhex("00000786270103"),
                bytes.fromhex("0000078e6701") + seed + b"\0",
            ),
            (
                bytes.fromhex("000007862702") + dh_aes(0x14, bytes(range(16))),
                bytes.fromhex("0000078e670234"),
            ),
        ]

        def host(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "get_timeout":
                return 321
            if operation == "start_flow_control_filter":
                handles[0] += 1
                return handles[0]
            if operation == "is_sending_sync_periodic":
                return sending[0]
            if operation == "start_sync_periodic":
                sending[0] = True
                self.assertEqual(event["frames"], ((bytes.fromhex("000007863e01"), 0),))
            if operation == "stop_sync_periodic":
                sending[0] = False
            if operation == "write_messages":
                last[0] = event["data"]
                return 1
            if operation == "read_specified_can_message":
                expected, response = pairs.pop(0)
                self.assertEqual(last[0], expected)
                return response
            if operation == "calculate_dh_gateway_online_key":
                self.assertEqual(event["seed"], b"12345678")
                return b"O" * 64
            if operation == "calculate_dh_gateway_key":
                self.assertTrue(event["secret"] == gateway.secret_info.get(20))
                self.assertEqual(event["seed"], seed)
                return dh_aes(0x14, bytes(range(16)))

        gateway = self.gateway(host)
        chronology = bind_authored_dh_online(
            self, gateway.runtime, b"12345678", b"O" * 64
        )
        gateway.start_online_reprogramming_mode(0)
        gateway.start_online_reprogramming_mode(1)
        self.assertTrue(chronology.used)
        self.assertEqual(gateway.security_table_kind, 1)
        self.assertTrue(sending[0])
        self.assertEqual(gateway.runtime.close(), [])
        self.assertFalse(sending[0])
        self.assertFalse(pairs)
        self.assertEqual(
            [
                event["identifier"]
                for event in events
                if event["operation"] == "stop_filter"
            ],
            [1, 2],
        )
        self.assertEqual(events[-1], {"operation": "stop_sync_periodic"})

    def test_specific_service_mode_is1088_and_option4_secret3(self):
        events = []
        last = [b""]
        pairs = [
            (bytes.fromhex("000007863e00"), bytes.fromhex("0000078e7e00")),
            (bytes.fromhex("00000786105f"), bytes.fromhex("0000078e5001")),
            (bytes.fromhex("000007861088"), bytes.fromhex("0000078e5088")),
            (
                bytes.fromhex("00000786270104"),
                bytes.fromhex("0000078e6701") + bytes(range(16)) + b"\0",
            ),
            (
                bytes.fromhex("000007862702") + dh_aes(3, bytes(range(16))),
                bytes.fromhex("0000078e670234"),
            ),
        ]

        def host(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "get_timeout":
                return 321
            if operation == "start_flow_control_filter":
                return 7
            if operation == "is_sending_sync_periodic":
                return False
            if operation == "write_messages":
                last[0] = event["data"]
                return 1
            if operation == "read_specified_can_message":
                expected, response = pairs.pop(0)
                self.assertEqual(last[0], expected)
                return response
            if operation == "calculate_dh_gateway_key":
                self.assertTrue(event["secret"] == gateway.secret_info.get(3))
                return dh_aes(3, bytes(range(16)))

        gateway = self.gateway(host)
        gateway.start_specific_service_mode()
        self.assertFalse(pairs)
        self.assertEqual(
            events[-2:],
            [
                {"operation": "stop_filter", "identifier": 7},
                {"operation": "set_timeout", "milliseconds": 321},
            ],
        )

    def test_two_cpu_end_defaults_are_best_effort_and_all_filters_release(self):
        events = []
        last = [b""]
        handle = [0]

        def host(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "get_timeout":
                return 321
            if operation == "start_flow_control_filter":
                handle[0] += 1
                return handle[0]
            if operation == "is_sending_sync_periodic":
                return False
            if operation == "write_messages":
                last[0] = event["data"]
                return 1
            if operation == "read_specified_can_message":
                if last[0] == bytes.fromhex("000007a41089"):
                    return bytes.fromhex("000007ac7f1012")
                return bytes.fromhex("0000078e5089")

        gateway = self.gateway(host)
        gateway.end_two_cpu_sessions()
        self.assertEqual(
            [
                event["data"].hex()
                for event in events
                if event["operation"] == "write_messages"
            ],
            ["000007a41089", "000007861089"],
        )
        self.assertEqual(
            [
                event["identifier"]
                for event in events
                if event["operation"] == "stop_filter"
            ],
            [1, 2],
        )
        self.assertEqual(gateway.runtime.close(), [])


if __name__ == "__main__":
    unittest.main()
