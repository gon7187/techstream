"""Public-byte producer/serializer/engine composition using authored CUW inputs."""

import hashlib
import io
import struct
import tempfile
import unittest
import zipfile
import zlib
from dataclasses import replace
from pathlib import Path

from scripts.calibration_2026 import (
    METADATA_VERSIONS,
    native2026_metadata,
    parse_cuw_2026,
)
from scripts.cuw_2026 import CUWEngine2026
from scripts.cuw_file_services import (
    admit_file_sources_2026,
    calibration_family_2026,
    compliance_2026,
    file_logger_2026,
    read_reprogramming_data_file_2026,
    validate_file_sources_2026,
)
from scripts.demo_calibration import table
from scripts.programming_2026_common import (
    NativeGeneralParameters2026,
    NativePassThruException2026,
)
from tests.test_calibration_2026 import cpu_text, cuw, logical_text


class PublicFileTests(unittest.TestCase):
    def setUp(self):
        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image unavailable")
        self.engine = CUWEngine2026(
            image.read_bytes(),
            general_parameters=NativeGeneralParameters2026.from_sources(
                {
                    "Parameter.ini": table(
                        (
                            "ParamFileKeySystemProtocolMicon",
                            "EngineTypeFlag",
                            "FlagToOutputAllAttachedInformation",
                            "CalibrationType",
                        ),
                        (("149CAN", "1", "0", "27"),),
                    )
                },
                encoded=False,
            ),
        )
        self.engine.configure(struct.pack("<IIddII", 2, 0, 0, 0, 0, 0))
        self.header = b"Z" * 0x98
        self.rows = (b"X" * 0xBBAC, b"Y" * 0xBBAC)
        self.source = cuw(
            cpu_text(10).replace("P5-Unified", "CAN")
            + "NewCID=NEWID\nTargetData=OLDID\n"
        )
        self.addCleanup(self.engine.close)

    def read(self, mode=1, **kw):
        return read_reprogramming_data_file_2026(
            self.engine, self.source, mode, 1, self.header, self.rows, **kw
        )

    def test_normal_actual_bytes_engine_and_padding(self):
        result = self.read()
        self.assertEqual(result.status, 0)
        self.assertEqual(
            self.engine.native_metadata.source_sha256, result.source_sha256[0]
        )
        self.assertEqual(result.header[0x5F:0x61], b"\1\0")
        self.assertEqual(struct.unpack_from("<I", result.header, 0x8C)[0], 1)
        self.assertEqual(result.cpus[0][:6], b"NEWID\0")
        self.assertEqual(struct.unpack_from("<I", result.cpus[0], 0xBBA8)[0], 27)
        self.assertEqual(result.cpus[1], self.rows[1])
        self.assertEqual(result.header[0x91:0x94], b"ZZZ")
        self.assertEqual(result.cpus[0][6:36], b"X" * 30)
        issued = self.engine.file_sources
        assert issued is not None
        self.assertEqual((issued.table_files, issued.table_file_names), ((), ()))

    def test_public_usb_original_bytes_retain_native_trailer_source(self):
        from scripts.calibration_2026 import (
            NativeUSBSource2026,
            native2026_usb_source_span,
        )

        trailer = b"ORIGINAL USB FILE\0\xff"
        raw = (
            cuw(
                cpu_text(12)
                .replace("P5-Unified", "CAN")
                .replace("KindOfECU=149", "KindOfECU=149\nCANIDTx_Phys_USDT=0795"),
                (struct.pack(">QI", 0x100000001, zlib.crc32(trailer)),),
            )
            + trailer
        )
        result = self.engine.read_reprogramming_data_file(
            raw, 1, 1, self.header, self.rows, source_name="original.cuw"
        )
        self.assertEqual(result.status, 0)
        metadata = self.engine.native_metadata
        self.assertIsInstance(metadata.source_container, NativeUSBSource2026)
        span = native2026_usb_source_span(metadata)
        self.assertEqual(span.read(), trailer)
        self.assertEqual(span.free_space_requirement, 0x100000001)
        self.assertEqual(span.source_sha256, result.source_sha256[0])
        issued = self.engine.file_sources
        assert issued is not None
        self.assertIs(issued.admission_source, raw)
        self.assertEqual(issued.recovery_sources(), (("original.cuw",), (raw,), 0))

    def test_public_usb_path_source_temporary_and_transferred_lifetime(self):
        from scripts.calibration_2026 import (
            native2026_usb_file_source,
            native2026_usb_source_span,
        )

        trailer = b"ORIGINAL FILE PAYLOAD"
        raw = (
            cuw(
                cpu_text(12)
                .replace("P5-Unified", "CAN")
                .replace("KindOfECU=149", "KindOfECU=149\nCANIDTx_Phys_USDT=0795"),
                (struct.pack(">QI", 64, zlib.crc32(trailer)),),
            )
            + trailer
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actual.cuw"
            path.write_bytes(raw)
            source = native2026_usb_file_source(path)
            self.addCleanup(source.close)
            result = self.engine.read_reprogramming_data_file(
                source, 2, 1, self.header, self.rows
            )
            self.assertEqual(result.status, 0)
            self.assertIsNone(self.engine.source_sha256)
            self.assertIsNone(source.raw)
            from scripts.calibration_2026 import native2026_metadata

            self.assertEqual(
                native2026_usb_source_span(native2026_metadata(source)).read(), trailer
            )
            unconfigured = CUWEngine2026(
                Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
            )
            self.addCleanup(unconfigured.close)
            with self.assertRaises(ValueError):
                unconfigured.read_reprogramming_data_file(
                    source, 1, 1, self.header, self.rows
                )
            self.assertEqual(
                native2026_usb_source_span(native2026_metadata(source)).read(), trailer
            )
            normal = self.engine.read_reprogramming_data_file(
                source, 1, 1, self.header, self.rows
            )
            self.assertEqual(normal.status, 0)
            metadata = self.engine.native_metadata
            self.assertIs(metadata.source_container, source)
            span = native2026_usb_source_span(metadata)
            self.assertEqual(span.read(), trailer)
            self.engine.load_cuw(self.source)
            with self.assertRaises(ValueError):
                span.read()
            replacement = native2026_usb_file_source(path)
            self.addCleanup(replacement.close)
            self.engine.read_reprogramming_data_file(
                replacement, 1, 1, self.header, self.rows
            )
            span = native2026_usb_source_span(self.engine.native_metadata)
            self.assertEqual(span.read(), trailer)
            self.engine.close()
            with self.assertRaises(ValueError):
                span.read()

    def test_public_usb_trailer_crc_fault_uses_native_catch_in_both_modes(self):
        trailer = b"USB TRAILER"
        raw = (
            cuw(
                cpu_text(12)
                .replace("P5-Unified", "CAN")
                .replace("KindOfECU=149", "KindOfECU=149\nCANIDTx_Phys_USDT=0795"),
                (struct.pack(">QI", 64, zlib.crc32(trailer)),),
            )
            + trailer[:-1]
            + b"!"
        )
        events = []
        self.engine.set_log_function(
            file_logger_2026(
                self.engine,
                Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
                lambda *args: events.append(args),
                to_wide=lambda value: value.decode("ascii"),
            )
        )
        for mode in (1, 2):
            result = self.engine.read_reprogramming_data_file(
                raw, mode, 1, self.header, self.rows
            )
            self.assertEqual(result.status, 1001)
            self.assertEqual((result.header, result.cpus), (self.header, self.rows))
            self.assertIsNone(self.engine.source_sha256)
        self.assertEqual(events, [(300, 3002, 2, "CUW.dll", "1(6)")] * 2)

    def test_public_pinned_usb_fresh_recovery_binding_saves_original_file(self):
        from scripts.calibration_2026 import native2026_usb_file_source
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )

        trailer = b"ORIGINAL PAYLOAD"
        raw = (
            cuw(
                cpu_text(12)
                .replace("P5-Unified", "CAN")
                .replace("KindOfECU=149", "KindOfECU=149\nCANIDTx_Phys_USDT=0795"),
                (struct.pack(">QI", 64, zlib.crc32(trailer)),),
            )
            + trailer
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "original.cuw"
            path.write_bytes(raw)
            source = native2026_usb_file_source(path)
            self.addCleanup(source.close)
            persistence = CUWPersistence(
                Path(directory) / "output",
                ReproInfoState((RecoveryCalibration("prior.cuw", self.source),)),
            )
            self.engine.bind_persistence(persistence)
            result = self.engine.read_reprogramming_data_file(
                source, 1, 1, self.header, self.rows, source_name=str(path)
            )
            self.assertEqual(result.status, 0)
            self.assertIs(persistence.state.calibrations[0].source_bytes, source)
            self.assertIsNone(source.raw)
            self.engine.notification.assign(True)
            self.assertEqual(
                (Path(directory) / "output" / "Save" / path.name).read_bytes(), raw
            )

    def test_recovery_temp_does_not_replace_bound_engine(self):
        self.engine.load_cuw(cuw(cpu_text(10) + "NewCID=BOUND\n"))
        before = self.engine.native_metadata
        result = self.read(2)
        self.assertIs(self.engine.native_metadata, before)
        self.assertEqual(result.header[0x5F:0x61], b"\1\1")
        self.assertEqual(result.header[0x8C:0x91], bytes(5))
        self.assertEqual(result.cpus[0][0xBBA8:], b"XXXX")

    def test_public_metadata2_model_year_retains_signed_native_remainder(self):
        self.engine.bind_general_parameters(
            NativeGeneralParameters2026.from_sources(
                {
                    "Parameter.ini": table(
                        (
                            "ParamFileKeySystemProtocolMicon",
                            "M16CTypeFlag",
                            "FORESTTypeFlag",
                        ),
                        (("0CAN0", "0", "0"),),
                    ),
                },
                encoded=False,
            )
        )
        for value, expected in (("-101", b"-1\0"), (" +2006tail", b"06\0")):
            source = cuw(
                cpu_text(2)
                .replace("P5-Unified", "CAN")
                .replace("KindOfECU=149", "KindOfECU=ENG & ECT")
                .replace("[CPU01]", f"ModelYear={value}\n[CPU01]")
                + "ECUType=32B 192K\n"
            )
            result = self.engine.read_reprogramming_data_file(
                source, 2, 1, self.header, self.rows
            )
            self.assertEqual(result.status, 0)
            self.assertEqual(result.header[0x26:0x29], expected)
            self.assertEqual(result.header[0x29:0x39], b"Z" * 16)

    def test_unknown_mode_has_native1001(self):
        for mode in (0, 3, -1, True):
            result = self.read(mode)
            self.assertEqual(result.status, 1001)
            self.assertEqual(result.header, self.header)
            self.assertEqual(result.cpus, self.rows)

    def test_cancel_before_read_preserves_engine(self):
        with self.assertRaises(InterruptedError):
            self.read(cancelled=lambda: True)
        self.assertIsNone(self.engine.source_sha256)

    def test_fault_is_not_business_success(self):
        self.source = self.source[:-1] + bytes([self.source[-1] ^ 1])
        with self.assertRaises(ValueError):
            self.read()
        self.assertIsNone(self.engine.source_sha256)

    def test_output_capacity_and_region(self):
        with self.assertRaises(ValueError):
            read_reprogramming_data_file_2026(
                self.engine, self.source, 2, 0, self.header, self.rows
            )
        with self.assertRaises(ValueError):
            read_reprogramming_data_file_2026(
                self.engine, self.source, 2, 1, self.header, ()
            )

    def test_no_date_locale_guess(self):
        text = cpu_text(10).replace("[Vehicle]", "[Vehicle]\nDateOfIssue=2026-01-02")
        self.source = cuw(text)
        with self.assertRaisesRegex(ValueError, "date formatter"):
            self.read(2)
        seen = []

        def formatter(parts):
            seen.append(parts)
            return b"02.01.2026"

        result = self.read(2, date_formatter=formatter)
        self.assertEqual(result.header[:11], b"02.01.2026\0")
        self.assertEqual(seen, [(2026, 1, 2)])

    def test_source_bound_compliance_formats_and_first_target(self):
        def metadata(text):
            return native2026_metadata(parse_cuw_2026(cuw(text)))

        non_p5 = metadata(cpu_text(10).replace("P5-Unified", "CAN"))
        self.assertEqual(compliance_2026((non_p5,)), 1)
        p5 = metadata(cpu_text(10) + "TargetData=00000751\n")
        self.assertEqual(compliance_2026((p5,)), 0)
        self.assertFalse(calibration_family_2026(non_p5))
        family = metadata(
            cpu_text(10).replace("[CPU01]", "CANIDTx_Phys_USDT=0791\n[CPU01]")
        )
        self.assertTrue(calibration_family_2026(family))
        self.assertFalse(calibration_family_2026(family, file_count=1))

    def test_compliance_reads_first_gateway_diagid_not_cpu_target(self):
        text = (
            logical_text(209)
            .replace(
                "NumberOfGateway=1",
                "NumberOfGateway=2\n01_GatewayDiagID=0700\n02_GatewayDiagID=0751",
            )
            .replace("authored-old", "0751")
        )
        metadata = native2026_metadata(parse_cuw_2026(cuw(text)))
        self.assertEqual(compliance_2026((metadata,)), 0)
        first = native2026_metadata(
            parse_cuw_2026(
                cuw(
                    text.replace(
                        "01_GatewayDiagID=0700", "01_GatewayDiagID=0751"
                    ).replace("01_TargetCalibration=0751", "01_TargetCalibration=OTHER")
                )
            )
        )
        self.assertEqual(compliance_2026((first,)), 1)

    def test_public_scuw_recovery_uses_header_only_without_archive_or_engine_bind(self):
        self.engine.load_cuw(self.source)
        previous = self.engine.native_metadata
        prefix = b"[Format]\nVersion=2\n[Vehicle]\nVehicleName=HEADER\nContactType=CAN\nNumberOfCalibration=1\n[CPU1]\nNewCID=HEADERCID\nNumberOfTargets=2\n01_TargetCalibration=OLD1\n02_TargetCalibration=OLD2\n"
        source = prefix + b"[DataCompression]\nnot a ZIP; recovery never extracts"
        result = read_reprogramming_data_file_2026(
            self.engine,
            source,
            2,
            4,
            self.header,
            self.rows,
            source_name="capture.scuw",
        )
        self.assertEqual(result.status, 0)
        self.assertIs(self.engine.native_metadata, previous)
        self.assertEqual(result.header[0x13:0x1A], b"HEADER\0")
        self.assertEqual(result.cpus[0][:10], b"HEADERCID\0")
        self.assertEqual(struct.unpack_from("<I", result.cpus[0], 0x24)[0], 2)
        self.assertEqual(struct.unpack_from("<I", result.header, 0x94)[0], 500)
        self.assertEqual(result.cpus[0][0xBBA8:], b"XXXX")
        self.assertFalse(result.delta_archive)
        self.assertFalse(result.multiple_files)

    def test_delta_capture_preserves_setting_filename_case(self):
        data = cuw(logical_text(209))
        source = self.archive(
            b"[Vehicle]\nContactType=P5-Unified\n",
            (
                (
                    "Setting.ini",
                    b"[DeltaReproCalFile]\nFileNum=1\nFileName1=PART.CUW\n[WholeReproCalFile]\nFileName=Whole.Cuw\n",
                ),
                ("part.cuw", data),
                ("whole.cuw", data),
            ),
        )
        issued = admit_file_sources_2026(self.engine, "input.scuw", source, region=0)
        self.assertEqual(issued.file_names, ("PART.CUW",))
        self.assertEqual(issued.selected_name, "Whole.Cuw")
        self.assertEqual(issued.delta_map, ())
        self.assertTrue(issued.current_is_retained_clone)
        mapped = admit_file_sources_2026(
            self.engine,
            "input.json",
            b'["part.scuw"]',
            region=0,
            source_files={"part.scuw": source},
        )
        self.assertEqual(mapped.delta_map, ((0, 0),))
        group = mapped.group_for_file(0)
        assert group is not None
        self.assertEqual(group[:2], (0, 1))
        self.assertTrue(mapped.current_is_retained_clone)

    def test_public_recovery_admits_exact_native_metadata_version_set(self):
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                    ),
                    (
                        ("149CAN0", "0", "0"),
                        ("0CAN0", "0", "0"),
                        ("149CAN311", "0", "0"),
                        ("149CAN", "0", "0"),
                    ),
                )
            },
            encoded=False,
        )
        self.engine.bind_general_parameters(parameters)
        self.assertEqual(len(METADATA_VERSIONS), 22)
        for version in sorted(METADATA_VERSIONS):
            with self.subTest(version=version):
                if version >= 101:
                    text = logical_text(version)
                else:
                    text = (
                        cpu_text(version).replace("P5-Unified", "CAN")
                        + "ECUType=32B 192K\nNewCID=TEST\n"
                    )
                    if version in (2, 3):
                        text = text.replace("KindOfECU=149", "KindOfECU=ENG & ECT")
                    if version == 9:
                        text += "NumberOfFiles=1\n[File1001]\nFileName=authored\nALFID=44\nDownloadAddress=0\nDownloadMemsize=4\n"
                result = read_reprogramming_data_file_2026(
                    self.engine, cuw(text), 2, 1, self.header, self.rows
                )
                self.assertEqual(
                    struct.unpack_from("<I", result.header, 0x94)[0], version
                )
        with self.assertRaisesRegex(ValueError, "Unsupported CUW2026 metadata version"):
            read_reprogramming_data_file_2026(
                self.engine, cuw(cpu_text(1)), 2, 1, self.header, self.rows
            )

    def test_large_source_recovery_retains_owner_then_normal_transfers_lifetime(self):
        from scripts.cuw_large import (
            LargeSource2026,
            native_large_cuw_2026,
            validate_large_container_2026,
        )
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from tests.test_cuw_large import fixture

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.cuw"
            fixture(
                path,
                metadata_override=logical_text(209, routine=True)
                .replace("P5-Unified", "CAN")
                .replace("[Vehicle]", "[Vehicle]\nKindOfECU=149")
                .replace("authored-new", "LARGECID")
                .replace("Nonce=" + "33" * 16, "Nonce=")
                .encode(),
            )
            container = native_large_cuw_2026(path)
            try:
                persistence = CUWPersistence(
                    Path(directory) / "output",
                    ReproInfoState((RecoveryCalibration("prior.cuw", self.source),)),
                )
                self.engine.bind_persistence(persistence)
                result = read_reprogramming_data_file_2026(
                    self.engine,
                    LargeSource2026(container),
                    2,
                    1,
                    self.header,
                    self.rows,
                )
                self.assertEqual(result.cpus[0][:9], b"LARGECID\0")
                self.assertIsNone(self.engine.source_sha256)
                validate_large_container_2026(container)
                normal = read_reprogramming_data_file_2026(
                    self.engine,
                    LargeSource2026(container),
                    1,
                    1,
                    self.header,
                    self.rows,
                    source_name=str(path),
                )
                self.assertEqual(
                    struct.unpack_from("<I", normal.cpus[0], 0xBBA8)[0], 27
                )
                self.assertIs(self.engine.source_container, container)
                saved_source = persistence.state.calibrations[0].source_bytes
                assert type(saved_source) is LargeSource2026
                self.assertIs(saved_source.container, container)
                self.engine.notification.assign(True)
                saved = Path(directory) / "output" / "Save" / path.name
                with saved.open("rb") as copied:
                    self.assertEqual(
                        hashlib.file_digest(copied, "sha256").hexdigest(),
                        container.digest,
                    )
                self.engine.close()
                with self.assertRaises(ValueError):
                    validate_large_container_2026(container)
            finally:
                container.close()

    def test_native_missing_profile_preserves_literal_partial_output_order(self):
        for missing in ("CalibrationType", "FlagToOutputAllAttachedInformation"):
            with self.subTest(missing=missing):
                headers = (
                    "ParamFileKeySystemProtocolMicon",
                    "EngineTypeFlag",
                    "FlagToOutputAllAttachedInformation",
                    "CalibrationType",
                )
                values = ("149CAN", "1", "0", "27")
                kept = tuple(
                    index for index, header in enumerate(headers) if header != missing
                )
                parameters = NativeGeneralParameters2026.from_sources(
                    {
                        "Parameter.ini": table(
                            tuple(headers[index] for index in kept),
                            (tuple(values[index] for index in kept),),
                        )
                    },
                    encoded=False,
                )
                self.engine.bind_general_parameters(parameters)
                result = self.read()
                self.assertEqual(result.status, 1001)
                self.assertEqual(result.cpus[0][:6], b"NEWID\0")
                self.assertEqual(result.header[0x94:], b"ZZZZ")
                if missing == "CalibrationType":
                    self.assertEqual(result.cpus[0][0xBBA8:], b"XXXX")
                    self.assertEqual(result.header[0x68:0x6B], b"ZZZ")
                    self.assertEqual(result.header[0x5F], ord("Z"))
                else:
                    self.assertEqual(
                        struct.unpack_from("<I", result.cpus[0], 0xBBA8)[0], 27
                    )
                    self.assertEqual(result.header[0x68:0x6C], b"CAN\0")
                    self.assertEqual(result.header[0x5F:0x61], b"\1Z")
                self.engine.close()

    def test_native_fault_classifier_and_untouched_pre_copy_outputs(self):
        from scripts.programming_2026_common import NativePassThruException2026

        source = cuw(
            cpu_text(10).replace("[Vehicle]", "[Vehicle]\nDateOfIssue=2026-01-02")
        )
        for error, expected in ((9999, 2001), (1021, 1002), (6, 1001)):
            with self.subTest(error=error):

                def formatter(parts, error=error):
                    raise NativePassThruException2026(error, "authored-capture", 1)

                result = read_reprogramming_data_file_2026(
                    self.engine,
                    source,
                    2,
                    1,
                    self.header,
                    self.rows,
                    date_formatter=formatter,
                )
                self.assertEqual(result.status, expected)
                self.assertEqual(result.header, self.header)
                self.assertEqual(result.cpus, self.rows)

    def test_public_engine_delegate_executes_installed_native_log_chronology(self):
        events = []
        converted = []

        def to_wide(value):
            converted.append(value)
            return value.decode("ascii")

        logger = file_logger_2026(
            self.engine,
            Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
            lambda *event: events.append(event),
            to_wide=to_wide,
        )
        self.assertEqual(len(logger.levels), 113)
        self.assertEqual((logger.levels[3001], logger.levels[3002]), (2, 2))
        self.engine.set_log_function(logger)
        result = self.engine.read_reprogramming_data_file(
            self.source, 1, 1, self.header, self.rows
        )
        self.assertEqual(result.status, 0)
        self.assertEqual(
            events,
            [
                (300, 1003, 0, "CUW.dll", "CAN"),
                (300, 1002, 0, "CUW.dll", "149"),
                (300, 1001, 0, "CUW.dll", ""),
                (300, 2016, 0, "CUW.dll", "0"),
            ],
        )
        self.assertEqual(converted, [b"CAN", b"149", b"", b"0"])
        self.engine.set_log_function(None)
        self.read(2)
        self.assertEqual(len(events), 4)
        with self.assertRaises(ValueError):
            self.engine.set_log_function(replace(logger))
        image = Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
        with self.assertRaises(ValueError):
            file_logger_2026(
                self.engine,
                image[:-1] + bytes((image[-1] ^ 1,)),
                lambda *event: None,
                to_wide=to_wide,
            )

    def test_native_log_fault_message_and_host_sink_failure_are_distinct(self):
        from scripts.programming_2026_common import NativePassThruException2026

        events = []
        self.engine.set_log_function(
            file_logger_2026(
                self.engine,
                Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
                lambda *event: events.append(event),
                to_wide=lambda value: value.decode("ascii"),
            )
        )
        self.source = cuw(
            cpu_text(10).replace("[Vehicle]", "[Vehicle]\nDateOfIssue=2026-01-02")
        )

        def formatter(parts):
            raise NativePassThruException2026(9999, "authored", 1)

        result = self.read(2, date_formatter=formatter)
        self.assertEqual(result.status, 2001)
        self.assertEqual(events, [(300, 3002, 2, "CUW.dll", "1(9999)")])
        host_fault = RuntimeError("captured sink unavailable")

        def sink(*event):
            raise host_fault

        self.engine.set_log_function(
            file_logger_2026(
                self.engine,
                Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
                sink,
                to_wide=lambda value: value.decode("ascii"),
            )
        )
        with self.assertRaises(RuntimeError) as caught:
            self.read(2, date_formatter=lambda parts: b"captured")
        self.assertIs(caught.exception, host_fault)

    def frontend_engine(self):
        from scripts.programming_2026_common import NativeFrontendParameters2026

        parameters = NativeFrontendParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "EngineTypeFlag",
                        "FlagToOutputAllAttachedInformation",
                    ),
                    (("P5-Unified", "0", "1"), ("Phase6", "0", "1")),
                ),
                "CanIDTable.ini": table(
                    ("RequestCANID", "CalibrationType"),
                    (("0700", "31"), ("0701", "32")),
                ),
                "LogicalAddressTable.ini": table(
                    ("LogicalAddress", "CalibrationType"), (("01", "41"),)
                ),
            },
            encoded=False,
        )
        engine = CUWEngine2026(Path("runtime/no-car-21/recovered/CUW.dll").read_bytes())
        engine.bind_frontend_parameters(parameters)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        self.addCleanup(engine.close)
        return engine

    def test_public_multifile_bytes_reach_engine_and_actual_serializers(self):
        engine = self.frontend_engine()
        first = cuw(
            logical_text(209)
            .replace("[Node01]", "[Node01]\nDiagID=0700")
            .replace("authored-new", "FIRST")
        )
        second = cuw(
            logical_text(209)
            .replace("[Node01]", "[Node01]\nDiagID=0701")
            .replace("authored-new", "SECOND")
        )
        result = read_reprogramming_data_file_2026(
            engine,
            b'["one.cuw","two.cuw"]',
            1,
            2,
            self.header,
            self.rows,
            source_name="input.json",
            source_files={"one.cuw": first, "two.cuw": second},
        )
        self.assertEqual(result.status, 0)
        self.assertTrue(result.multiple_files)
        self.assertFalse(result.delta_archive)
        self.assertEqual(struct.unpack_from("<I", result.header, 0x64)[0], 2)
        self.assertEqual(result.header[0x5F:0x61], b"\0\1")
        self.assertEqual(result.cpus[0][:6], b"FIRST\0")
        self.assertEqual(result.cpus[1][:7], b"SECOND\0")
        self.assertEqual(struct.unpack_from("<I", result.cpus[0], 0xBBA8)[0], 31)
        self.assertEqual(struct.unpack_from("<I", result.cpus[1], 0xBBA8)[0], 32)
        assert engine.file_sources is not None
        self.assertIs(engine.native_metadata, engine.file_sources.selected_metadata)
        self.assertEqual(engine.file_sources.file_names, ("one.cuw", "two.cuw"))
        self.assertEqual(engine.native_metadata.region, 1)

    def test_public_delta_whole_output_uses_actual_delta_compliance(self):
        engine = self.frontend_engine()
        part = cuw(
            logical_text(209)
            .replace("[Node01]", "[Node01]\nDiagID=0701")
            .replace("authored-new", "PART")
            .replace("NumberOfGateway=1", "NumberOfGateway=1\n01_GatewayDiagID=0751")
        )
        whole = cuw(
            logical_text(209)
            .replace("[Node01]", "[Node01]\nDiagID=0700")
            .replace("authored-new", "WHOLE")
        )
        source = self.archive(
            b"[Vehicle]\nContactType=P5-Unified\n",
            (
                (
                    "Setting.ini",
                    b"[DeltaReproCalFile]\nFileNum=1\nFileName1=part.cuw\n[WholeReproCalFile]\nFileName=whole.cuw\n",
                ),
                ("part.cuw", part),
                ("whole.cuw", whole),
            ),
        )
        result = read_reprogramming_data_file_2026(
            engine, source, 1, 1, self.header, self.rows, source_name="input.scuw"
        )
        self.assertTrue(result.delta_archive)
        self.assertTrue(result.multiple_files)
        self.assertEqual(result.cpus[0][:6], b"WHOLE\0")
        self.assertEqual(result.cpus[1], self.rows[1])
        self.assertEqual(struct.unpack_from("<I", result.header, 0x8C)[0], 1)
        self.assertEqual(struct.unpack_from("<I", result.cpus[0], 0xBBA8)[0], 31)
        assert engine.file_sources is not None
        self.assertIs(engine.native_metadata, engine.file_sources.output_files[0])
        self.assertIsNot(engine.native_metadata, engine.file_sources.files[0])
        previous = engine.native_metadata
        events = []
        engine.set_log_function(
            file_logger_2026(
                engine,
                Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
                lambda *event: events.append(event),
                to_wide=lambda value: value.decode("ascii"),
            )
        )
        recovery = engine.read_reprogramming_data_file(
            b"[Vehicle]\nContactType=CAN\nNumberOfCalibration=1\n[CPU1]\nNewCID=TEMP\n[DataCompression]\nnot-extracted",
            2,
            1,
            self.header,
            self.rows,
            source_name="temporary.scuw",
        )
        self.assertFalse(recovery.delta_archive)
        self.assertFalse(recovery.multiple_files)
        self.assertIs(engine.native_metadata, previous)
        self.assertTrue(engine.native_delta_active)
        self.assertEqual(events[-1], (300, 2016, 0, "CUW.dll", "1"))

    def test_public_phase6_files_merge_native_logical_owners_and_preserve_payloads(
        self,
    ):
        from scripts.calibration_2026 import (
            NativeCompositeSource2026,
            native2026_logical_archive,
            native2026_metadata_for_cpu,
        )
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )

        engine = self.frontend_engine()
        directory = self.enterContext(tempfile.TemporaryDirectory())
        output = Path(directory) / "output"
        persistence = CUWPersistence(
            output, ReproInfoState((RecoveryCalibration("prior.cuw", self.source),))
        )
        engine.bind_persistence(persistence)
        left = cuw(
            logical_text(209)
            .replace("P5-Unified", "Phase6")
            .replace("[Node01]", "[Node01]\nDiagID=0700")
            .replace("authored-new", "FIRST")
            .replace("authored-old", "OLD-FIRST"),
            (b"LEFT",),
        )
        right = cuw(
            logical_text(209, slot=2)
            .replace("P5-Unified", "Phase6")
            .replace("[Node01]", "[Node01]\nDiagID=0700")
            .replace("authored-new", "SECOND")
            .replace("authored-old", "OLD-SECOND"),
            (b"RGHT",),
        )
        result = engine.read_reprogramming_data_file(
            b'["left.cuw","right.cuw"]',
            1,
            1,
            self.header,
            self.rows,
            source_name="input.json",
            source_files={"left.cuw": left, "right.cuw": right},
        )
        self.assertEqual(result.status, 0)
        self.assertEqual(struct.unpack_from("<I", result.header, 0x64)[0], 2)
        self.assertEqual(result.cpus[0][:6], b"FIRST\0")
        self.assertEqual(result.cpus[1][:7], b"SECOND\0")
        issued = engine.file_sources
        assert issued is not None
        self.assertEqual(issued.file_names, ("left.cuw",))
        self.assertEqual(len(issued.files), 1)
        self.assertEqual(
            issued.recovery_sources(), (("left.cuw", "right.cuw"), (left, right), 2)
        )
        self.assertIsInstance(issued.selected_source, NativeCompositeSource2026)
        self.assertIs(engine.source_container, issued.selected_source)
        self.assertNotEqual(result.source_sha256[0], issued.admission_sha256)
        self.assertEqual(issued.admission_source, b'["left.cuw","right.cuw"]')
        for index, expected in enumerate((b"LEFT", b"RGHT")):
            metadata = native2026_metadata_for_cpu(engine.native_metadata, index)
            self.assertEqual(issued.recovery_index_for_metadata(metadata), 0)
            block = next(
                item for item in metadata.logical_blocks if item.cpu_index == index
            )
            self.assertEqual(
                native2026_logical_archive(metadata, block, "ReproData").data, expected
            )
        validate_file_sources_2026(issued, engine)
        with self.assertRaisesRegex(ValueError, "recovery FILE index proof"):
            issued.recovery_index_for_metadata(
                native2026_metadata(parse_cuw_2026(left))
            )
        engine.notification.assign(True)
        self.assertEqual((output / "Save" / "1_left.cuw").read_bytes(), left)
        self.assertEqual((output / "Save" / "2_right.cuw").read_bytes(), right)

    def test_public_phase6_collision_returns_native_generic_failure(self):
        engine = self.frontend_engine()
        source = cuw(
            logical_text(209)
            .replace("P5-Unified", "Phase6")
            .replace("[Node01]", "[Node01]\nDiagID=0700")
        )
        result = engine.read_reprogramming_data_file(
            b'["left.cuw","right.cuw"]',
            1,
            1,
            self.header,
            self.rows,
            source_name="input.json",
            source_files={"left.cuw": source, "right.cuw": source},
        )
        self.assertEqual(result.status, 1001)
        self.assertEqual(result.header, self.header)
        self.assertEqual(result.cpus, self.rows)
        self.assertIsNone(engine.file_sources)

    def test_public_composite_projects_actual_node_sources_without_multi_flag(self):
        from scripts.calibration_2026 import NativeNodeSource2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )

        engine = self.frontend_engine()
        directory = self.enterContext(tempfile.TemporaryDirectory())
        output = Path(directory) / "output"
        persistence = CUWPersistence(
            output, ReproInfoState((RecoveryCalibration("prior.cuw", self.source),))
        )
        engine.bind_persistence(persistence)
        text = (
            logical_text(209)
            .replace("ContactType=P5-Unified", "ContactType=Ethernet & P5-Unified")
            .replace("NumberOfNode=1", "NumberOfNode=2")
            .replace("[Node01]", "[Node01]\nContactType=P5-Unified\nDiagID=0700")
        )
        text += (
            "[Node02]\nContactType=Ethernet\nLogicalAddress=01\n"
            "RequiredSpecReproVer=03\nNumberOfLogicalBlock=1\n"
            "[LogicalBlock201]\nNewCID=SECOND\nNumberOfTargets=1\n"
            "01_TargetCalibration=OLD-SECOND\nReproMethod=00\n"
            "[ReproData201]\nStartAddress=2000\nLength=04\n"
        )
        raw = cuw(text, (b"ONE!", b"TWO!"))
        result = engine.read_reprogramming_data_file(
            raw, 1, 1, self.header, self.rows, source_name="composite.cuw"
        )
        self.assertEqual(result.status, 0)
        self.assertFalse(result.multiple_files)
        self.assertEqual(struct.unpack_from("<I", result.header, 0x64)[0], 2)
        self.assertEqual(struct.unpack_from("<I", result.cpus[0], 0xBBA8)[0], 31)
        self.assertEqual(struct.unpack_from("<I", result.cpus[1], 0xBBA8)[0], 41)
        issued = engine.file_sources
        assert issued is not None
        self.assertTrue(issued.composite_contact)
        self.assertEqual(
            issued.recovery_sources(),
            (("composite.cuw", "composite.cuw"), (raw, raw), 2),
        )
        self.assertEqual(
            tuple(issued.recovery_index_for_metadata(item) for item in issued.files),
            (0, 0),
        )
        self.assertEqual(issued.file_names, ("composite.cuw", "composite.cuw"))
        self.assertTrue(
            all(type(item) is NativeNodeSource2026 for item in issued.file_sources)
        )
        self.assertIs(issued.file_sources[0].parent, issued.file_sources[1].parent)
        self.assertEqual(issued.admission_source, raw)
        engine.notification.assign(True)
        self.assertEqual((output / "Save" / "1_composite.cuw").read_bytes(), raw)
        self.assertEqual((output / "Save" / "2_composite.cuw").read_bytes(), raw)

    def test_mapped_phase6_reorders_actual_files_before_initial_selection(self):
        engine = self.frontend_engine()

        def calibration(cid, address):
            return cuw(
                logical_text(209)
                .replace("P5-Unified", "Phase6")
                .replace("[Node01]", f"[Node01]\nDiagID=0700\nLogicalAddress={address}")
                .replace("authored-new", cid)
            )

        archive = self.archive(
            b"[Vehicle]\nContactType=Phase6\n",
            (
                (
                    "Setting.ini",
                    b"[DeltaReproCalFile]\nFileNum=1\nFileName1=part.cuw\n[WholeReproCalFile]\nFileName=whole.cuw\n",
                ),
                ("part.cuw", calibration("PART", "01")),
                ("whole.cuw", calibration("WHOLE", "01")),
            ),
        )
        result = engine.read_reprogramming_data_file(
            b'["group.scuw","plain.cuw"]',
            1,
            1,
            self.header,
            self.rows,
            source_name="input.json",
            source_files={
                "group.scuw": archive,
                "plain.cuw": calibration("FIRST", "02"),
            },
        )
        self.assertEqual(result.status, 0)
        self.assertEqual(result.cpus[0][:6], b"FIRST\0")
        self.assertEqual(result.cpus[1][:6], b"WHOLE\0")
        issued = engine.file_sources
        assert issued is not None
        self.assertEqual(issued.file_names, ("plain.cuw", "part.cuw"))
        self.assertEqual(issued.delta_map, ((1, 0),))
        self.assertEqual(issued.recovery_file_names, ("group.scuw", "plain.cuw"))
        self.assertEqual(issued.recovery_multi_count, 2)
        self.assertIs(issued.recovery_file_sources[0], archive)
        self.assertEqual(
            tuple(issued.recovery_index_for_metadata(item) for item in issued.files),
            (1, 0),
        )
        self.assertEqual(
            issued.recovery_index_for_metadata(issued.delta_groups[0][2]), 0
        )
        self.assertIs(issued.selected_metadata, issued.files[0])
        self.assertIsNone(issued.auxiliary_metadata)
        self.assertEqual(issued.group_for_file(1)[:2], (1, 1))
        rejected = engine.read_reprogramming_data_file(
            b'["group.scuw","plain.cuw"]',
            1,
            1,
            self.header,
            self.rows,
            source_name="input.json",
            source_files={
                "group.scuw": archive,
                "plain.cuw": calibration("FIRST", "01"),
            },
        )
        self.assertEqual(rejected.status, 1001)
        self.assertIs(engine.file_sources, issued)
        self.assertEqual(rejected.header, self.header)

    def test_initial_json_mapped_slot_selects_whole_pointer_and_auxiliary_alias(self):
        engine = self.frontend_engine()
        part = cuw(
            logical_text(209)
            .replace("[Node01]", "[Node01]\nDiagID=0701")
            .replace("authored-new", "PART")
        )
        whole = cuw(
            logical_text(209)
            .replace("[Node01]", "[Node01]\nDiagID=0700")
            .replace("authored-new", "WHOLE")
        )
        source = self.archive(
            b"[Vehicle]\nContactType=P5-Unified\n",
            (
                (
                    "Setting.ini",
                    b"[DeltaReproCalFile]\nFileNum=1\nFileName1=part.cuw\n[WholeReproCalFile]\nFileName=whole.cuw\n",
                ),
                ("part.cuw", part),
                ("whole.cuw", whole),
            ),
        )
        result = read_reprogramming_data_file_2026(
            engine,
            b'["group.scuw"]',
            1,
            1,
            self.header,
            self.rows,
            source_name="actual.json",
            source_files={"group.scuw": source},
        )
        issued = engine.file_sources
        assert issued is not None
        self.assertEqual(result.cpus[0][:6], b"WHOLE\0")
        self.assertIs(engine.native_metadata, issued.output_files[0])
        self.assertIs(issued.auxiliary_metadata, engine.native_metadata)
        self.assertIsNot(issued.files[0], engine.native_metadata)
        self.assertEqual(issued.delta_map_size, 1)
        self.assertTrue(issued.current_is_retained_clone)
        with self.assertRaisesRegex(ValueError, "worker"):
            issued.after_group_reset(0, worker=object())

    def test_native_list_admission_real_files_and_registry(self):
        first = cuw(logical_text(209).replace("authored-new", "FIRST"))
        second = cuw(logical_text(209).replace("authored-new", "SECOND"))
        sources = {"first.cuw": first, "second.cuw": second}
        issued = admit_file_sources_2026(
            self.engine,
            "actual.json",
            b'["first.cuw","second.cuw"]',
            region=0,
            source_files=sources,
        )
        validate_file_sources_2026(issued, self.engine)
        self.assertEqual(len(issued.files), 2)
        self.assertEqual(issued.file_sources, (first, second))
        self.assertFalse(issued.delta_archive)
        with self.assertRaises(ValueError):
            validate_file_sources_2026(replace(issued), self.engine)
        with self.assertRaises(NativePassThruException2026) as missing:
            admit_file_sources_2026(
                self.engine,
                "actual.json",
                b'["first.cuw", "second.cuw"]',
                region=0,
                source_files=sources,
            )
        self.assertEqual((missing.exception.error, missing.exception.line), (6, 0x330F))
        self.assertIsNone(self.engine.source_sha256)

    @staticmethod
    def archive(header, members):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            for name, content in members:
                archive.writestr(name, content)
        return header + b"[DataCompression]\n" + data.getvalue()

    def test_delta_archive_actual_settings_join(self):
        first = cuw(logical_text(209).replace("authored-new", "PART1"))
        second = cuw(logical_text(209).replace("authored-new", "PART2"))
        whole = cuw(logical_text(209).replace("authored-new", "WHOLE"))
        source = self.archive(
            b"[Vehicle]\nContactType=P5-Unified\n",
            (
                (
                    "Setting.ini",
                    b"[DeltaReproCalFile]\nFileNum=2\nFileName1=first.cuw\nFileName2=second.cuw\n[WholeReproCalFile]\nFileName=whole.cuw\n",
                ),
                ("first.cuw", first),
                ("second.cuw", second),
                ("whole.cuw", whole),
            ),
        )
        issued = admit_file_sources_2026(self.engine, "input.scuw", source, region=1)
        self.assertTrue(issued.delta_archive)
        self.assertEqual(issued.file_sources, (first, second))
        self.assertEqual(issued.selected_source, whole)
        self.assertEqual(issued.table_files, issued.files)
        self.assertEqual(issued.table_file_names, issued.file_names)
        self.assertEqual(issued.delta_groups[0][:2], (0, 2))
        self.assertEqual(issued.recovery_sources(), (("input.scuw",), (source,), 0))
        self.assertEqual(len(issued.output_files), 1)
        self.assertEqual(issued.output_files[0].region, 1)

    def test_native_profile_260_byte_path_buffers(self):
        part = cuw(logical_text(209).replace("authored-new", "PART"))
        whole = cuw(logical_text(209).replace("authored-new", "WHOLE"))
        delta_name, whole_name = "a" * 270 + ".cuw", "b" * 270 + ".cuw"
        settings = (
            f"[DeltaReproCalFile]\nFileNum=1\nFileName1={delta_name}\n"
            f"[WholeReproCalFile]\nFileName={whole_name}\n"
        ).encode("ascii")
        source = self.archive(
            b"[Vehicle]\nContactType=P5-Unified\n",
            (
                ("Setting.ini", settings),
                (delta_name[:259], part),
                (whole_name[:259], whole),
            ),
        )
        issued = admit_file_sources_2026(self.engine, "actual.scuw", source, region=0)
        self.assertEqual(issued.file_names, (delta_name[:259],))
        self.assertEqual(issued.selected_name, whole_name[:259])
        self.assertIs(issued.admission_source, source)
        for members, line in (
            (((delta_name, part), (whole_name[:259], whole)), 0x3226),
            (((delta_name[:259], part), (whole_name, whole)), 0x3233),
        ):
            source = self.archive(
                b"[Vehicle]\nContactType=P5-Unified\n",
                (("Setting.ini", settings), *members),
            )
            with self.assertRaises(NativePassThruException2026) as fault:
                admit_file_sources_2026(self.engine, "actual.scuw", source, region=0)
            self.assertEqual((fault.exception.error, fault.exception.line), (6, line))

    def test_public_scuw_fresh_recovery_binding_copies_original_archive(self):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )

        engine = self.frontend_engine()
        part = cuw(
            logical_text(209)
            .replace("[Node01]", "[Node01]\nDiagID=0701")
            .replace("authored-new", "PART")
        )
        whole = cuw(
            logical_text(209)
            .replace("[Node01]", "[Node01]\nDiagID=0700")
            .replace("authored-new", "WHOLE")
        )
        archive = self.archive(
            b"[Vehicle]\nContactType=P5-Unified\n",
            (
                (
                    "Setting.ini",
                    b"[DeltaReproCalFile]\nFileNum=1\nFileName1=part.cuw\n[WholeReproCalFile]\nFileName=whole.cuw\n",
                ),
                ("part.cuw", part),
                ("whole.cuw", whole),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            persistence = CUWPersistence(
                output,
                ReproInfoState(
                    (RecoveryCalibration("prior.cuw", self.source),), vin="PRESERVED"
                ),
            )
            engine.bind_persistence(persistence)
            result = engine.read_reprogramming_data_file(
                archive, 1, 1, self.header, self.rows, source_name="original.scuw"
            )
            self.assertEqual(result.status, 0)
            # 38880 runs23630 before admission, clearing the prior VIN.
            self.assertEqual(persistence.state.vin, "")
            self.assertEqual(
                persistence.state.calibrations[0].source_path, "original.scuw"
            )
            self.assertIs(persistence.state.calibrations[0].source_bytes, archive)
            self.assertEqual(engine.source_sha256, hashlib.sha256(whole).hexdigest())
            self.assertNotEqual(
                engine.source_sha256, hashlib.sha256(archive).hexdigest()
            )
            engine.validate_persistence_binding(persistence)
            engine.notification.assign(True)
            self.assertEqual((output / "Save" / "original.scuw").read_bytes(), archive)

    def test_native_empty_profile_counts_raise_actual_zero_count_faults(self):
        for name, header, members, line in (
            (
                "actual.scuw",
                b"[Vehicle]\n",
                (("Setting.ini", b"[DeltaReproCalFile]\nFileNum=\n"),),
                0x3218,
            ),
            ("actual.cuwc", b"[Vehicle]\nNumberOfCalibration=\n", (), 0x3399),
        ):
            with self.assertRaises(NativePassThruException2026) as fault:
                admit_file_sources_2026(
                    self.engine, name, self.archive(header, members), region=0
                )
            self.assertEqual((fault.exception.error, fault.exception.line), (6, line))

    def test_compressed_order_comes_from_newcid_filename_prefix(self):
        first = cuw(logical_text(209).replace("authored-new", "FIRST"))
        second = cuw(logical_text(209).replace("authored-new", "SECOND"))
        source = self.archive(
            b"[Vehicle]\nNumberOfCalibration=2\n[CPU01]\nNewCID=FIRST\n[CPU02]\nNewCID=SECOND\n",
            (("SECOND-extra.cuw", second), ("FIRST-extra.cuw", first)),
        )
        issued = admit_file_sources_2026(self.engine, "input.CUWC", source, region=0)
        self.assertEqual(issued.file_sources, (first, second))
        self.assertFalse(issued.delta_archive)
        self.assertEqual(
            issued.recovery_sources(),
            (("FIRST-extra.cuw", "SECOND-extra.cuw"), (first, second), 2),
        )
        collision = self.archive(
            b"[Vehicle]\nNumberOfCalibration=1\n[CPU01]\nNewCID=FIRST\n",
            (("FIRST-one.cuw", first), ("FIRST-two.cuw", second)),
        )
        with self.assertRaises(NativePassThruException2026) as collision_fault:
            admit_file_sources_2026(self.engine, "input.cuwc", collision, region=0)
        self.assertEqual(
            (collision_fault.exception.error, collision_fault.exception.line),
            (6, 0x3409),
        )

    def test_multifile_format10_12_rejected_from_actual_bytes(self):
        with self.assertRaises(NativePassThruException2026) as fault:
            admit_file_sources_2026(
                self.engine,
                "input.json",
                b'["file.cuw"]',
                region=0,
                source_files={"file.cuw": self.source},
            )
        self.assertEqual((fault.exception.error, fault.exception.line), (6, 0x318C))
        self.assertIn(
            fault.exception.source.encode("latin1") + b"\0",
            Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
        )

    def test_actual_file_table_capacity_faults_keep_native_branch_locations(self):
        data = cuw(logical_text(209))
        names = tuple(f"FILE{index:02d}.cuw" for index in range(1, 18))
        listing = ("[" + ",".join(f'"{name}"' for name in names) + "]").encode()
        compressed_header = (
            "[Vehicle]\nNumberOfCalibration=17\n"
            + "".join(
                f"[CPU{index:02d}]\nNewCID=FILE{index:02d}\n" for index in range(1, 18)
            )
        ).encode()
        settings = (
            "[DeltaReproCalFile]\nFileNum=17\n"
            + "".join(
                f"FileName{index}={name}\n" for index, name in enumerate(names, 1)
            )
            + "[WholeReproCalFile]\nFileName=whole.cuw\n"
        ).encode()
        members = tuple((name, data) for name in names)
        for filename, source, mapping, line in (
            ("input.json", listing, dict(members), 0x308F),
            ("input.cuwc", self.archive(compressed_header, members), None, 0x30BE),
            (
                "input.scuw",
                self.archive(
                    b"[Vehicle]\nContactType=P5-Unified\n",
                    (("Setting.ini", settings), *members, ("whole.cuw", data)),
                ),
                None,
                0x30D8,
            ),
        ):
            with self.assertRaises(NativePassThruException2026) as fault:
                admit_file_sources_2026(
                    self.engine, filename, source, region=0, source_files=mapping
                )
            self.assertEqual((fault.exception.error, fault.exception.line), (6, line))
            result = self.engine.read_reprogramming_data_file(
                source,
                1,
                1,
                self.header,
                self.rows,
                source_name=filename,
                source_files=mapping,
            )
            self.assertEqual(
                (result.status, result.header, result.cpus),
                (1001, self.header, self.rows),
            )

    def test_public_known_native_admission_fault_logs_pass_thru_catch(self):
        events = []
        self.engine.set_log_function(
            file_logger_2026(
                self.engine,
                Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
                lambda *args: events.append(args),
                to_wide=lambda value: value.decode("ascii"),
            )
        )
        result = self.engine.read_reprogramming_data_file(
            b'["missing.cuw"]',
            1,
            1,
            self.header,
            self.rows,
            source_name="input.json",
            source_files={},
        )
        self.assertEqual(result.status, 1001)
        self.assertEqual((result.header, result.cpus), (self.header, self.rows))
        self.assertEqual(events, [(300, 3002, 2, "CUW.dll", "1(6)")])


if __name__ == "__main__":
    unittest.main()
