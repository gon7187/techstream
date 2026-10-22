import hashlib
import os
import struct
import tempfile
import unittest
from pathlib import Path
from typing import cast

from scripts.calibration_catalog import (
    Address,
    CalibrationCatalog,
    SelectionContext,
    inspect_module,
    inspect_module_bytes,
    parse_address,
    parse_parameter_table,
    parse_version_resource,
)
from scripts.demo_calibration import authored_pe, create_calibration_examples, table

KEY = "ParamFileKeySystemProtocolMicon"


def catalog(**overrides):
    values = {
        KEY: "synthetic",
        "DLLFileNameForGetCID": "SyntheticCID.dll",
        "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
        "DLLFileNameForPrepareWrite": "SyntheticPrepare.dll",
        "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
        "DLLFileNameForFlashWrite": "SyntheticWrite.dll",
        "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromLocationIDForWrite",
        "CanIDForGetCID": "0100/0108\n0101/0109",
        "CanIDForPrepareWrite": "0200/0208",
        "CIDForCalcCpuNum": "ABC\nDEF",
        "CanIDMatchedPartOfCID": "0300/0308",
        "CanIDForReprogGateway": "0400/0408",
        "SecurityKey": "private-never-report",
    }
    values.update(overrides)
    raw = table(list(values), [list(values.values())])
    return CalibrationCatalog.from_tables({"authored.ini": raw}, encoded=False)


class CatalogTests(unittest.TestCase):
    def test_authored_gui_examples_dispatch(self):
        examples = create_calibration_examples()
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "SyntheticCID.dll"
            module.write_bytes(examples["SyntheticCID.dll"])
            info = inspect_module(module)
            selection = CalibrationCatalog.from_tables(
                {"synthetic.ini": examples["synthetic.ini"]}
            ).select("synthetic")
            result = selection.dispatch(
                "get_cid",
                SelectionContext(),
                {info["name"]: info["exports"]},
                module_versions={info["name"]: info["version"]},
            )
            self.assertEqual(result["operation"], "StartGetCID")
            self.assertTrue(result["module_version_checked"])

    def test_explicit_module_bytes_match_static_file_contract(self):
        result = inspect_module_bytes(authored_pe(), "SyntheticCID.dll")
        self.assertEqual(result["name"], "SyntheticCID.dll")
        self.assertIn("StartGetCID", result["exports"])
        for name in ("../x.dll", "", "x\\y.dll"):
            with self.assertRaises(ValueError):
                inspect_module_bytes(authored_pe(), name)
        with self.assertRaises(ValueError):
            inspect_module_bytes(cast(bytes, bytearray(authored_pe())), "x.dll")

    def test_static_module_file_and_malformed_pe(self):
        raw = authored_pe()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SyntheticCID.dll"
            path.write_bytes(raw)
            report = inspect_module(path)
            self.assertEqual(report["exports"], ["StartGetCID"])
            self.assertEqual(report["version"], "1.0.0007.0")
            self.assertEqual(report["sha256"], hashlib.sha256(raw).hexdigest())
            for length in (0, 63, 127, 151, 300, 511, 700, len(raw) - 1):
                path.write_bytes(raw[:length])
                with self.assertRaises(ValueError):
                    inspect_module(path)
            damaged = bytearray(raw)
            struct.pack_into("<I", damaged, 0x314, 0x80000000)
            path.write_bytes(damaged)
            with self.assertRaisesRegex(ValueError, "cyclic"):
                inspect_module(path)
            fifo = Path(directory) / "authored.fifo"
            os.mkfifo(fifo)
            for special in (fifo, Path(directory)):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    inspect_module(special)

    def test_version_resource_native_string_and_translation(self):
        def node(key, value=b"", children=(), kind=0):
            data = bytes(6) + (key + "\0").encode("utf-16le")
            data += bytes(-len(data) % 4)
            data += value
            for child in children:
                data += bytes(-len(data) % 4) + child
            return (
                struct.pack(
                    "<HHH", len(data), len(value) // 2 if kind else len(value), kind
                )
                + data[6:]
            )

        info = node(
            "StringFileInfo",
            children=(
                node(
                    "040904b0",
                    children=(
                        node("FileVersion", "1.0.0007.0\0".encode("utf-16le"), kind=1),
                    ),
                ),
            ),
        )
        translations = node(
            "VarFileInfo",
            children=(node("Translation", struct.pack("<HH", 0x409, 1200)),),
        )
        raw = node(
            "VS_VERSION_INFO", b"\xbd\x04\xef\xfe" + bytes(48), (info, translations)
        )
        self.assertEqual(parse_version_resource(raw), "1.0.0007.0")
        for length in range(len(raw)):
            with self.assertRaises((ValueError, LookupError)):
                parse_version_resource(raw[:length])

    def test_metadata_phase_and_spec_choose_exact_source(self):
        sources = {
            name + ".ini": table([KEY], [[name]])
            for name in ("P5-Unified", "P5-Unified03", "Ethernet", "Ethernet04")
        }
        c = CalibrationCatalog.from_tables(sources, encoded=False)
        self.assertEqual(
            c.select_metadata("", "", "P5-Unified", required_spec="03").key,
            "P5-Unified",
        )
        self.assertEqual(
            c.select_metadata(
                "", "", "P5-Unified", stage="write", required_spec="03"
            ).key,
            "P5-Unified03",
        )
        self.assertEqual(
            c.select_metadata(
                "", "", "Ethernet", stage="prepare", required_spec="04"
            ).key,
            "Ethernet04",
        )
        with self.assertRaises(LookupError):
            c.select_metadata("", "", "P5-Unified", stage="write", required_spec="04")

    def test_native_lexical_version_gate_and_optional_exports(self):
        selection = catalog(
            EnableDLLVersionInformation="1.0.0001.0\n1.0.0002.0\n1.0.0003.0\n-",
            PrepareRetryFlag="1",
            ConfirmAfterEndOfFlashingFlag="1",
        ).select("synthetic")
        context = SelectionContext(location_id=bytes(8))
        modules = {
            "SyntheticWrite.dll": (
                "StartFlashWrite",
                "PrepareRetry",
                "IsFinishReprogramming",
            )
        }
        for versions in (None, {"SyntheticWrite.dll": "1.0.0002.0"}):
            with self.assertRaises((ValueError, LookupError)):
                selection.dispatch("write", context, modules, module_versions=versions)
        self.assertTrue(
            selection.dispatch(
                "write",
                context,
                modules,
                module_versions={"SyntheticWrite.dll": "1.0.0003.0"},
            )["module_version_checked"]
        )
        with self.assertRaises(LookupError):
            selection.dispatch(
                "write",
                context,
                {"SyntheticWrite.dll": ("StartFlashWrite",)},
                module_versions={"SyntheticWrite.dll": "9"},
            )

    def test_encoded_csv_and_native_exact_key(self):
        raw = table([KEY, "Mode"], [["0ProtoCPU", "authored"]])
        encoded = bytes(
            ((nibble + 8) << 2) | 3 for byte in raw for nibble in (byte >> 4, byte & 15)
        )
        c = CalibrationCatalog.from_tables({"one.ini": encoded})
        self.assertEqual(c.select_native("0", "CPU", "Proto").value("Mode"), "authored")
        self.assertEqual(c.tables[0].sha256, hashlib.sha256(encoded).hexdigest())
        with self.assertRaises(LookupError):
            c.select("0protocpu")

    def test_all_stages_require_exact_module_and_export(self):
        selection = catalog().select("synthetic")
        modules = {
            "SyntheticCID.dll": ("StartGetCID",),
            "SyntheticPrepare.dll": ("StartPrepareWrite",),
            "SyntheticWrite.dll": ("StartFlashWrite",),
        }
        for stage in ("get_cid", "prepare", "write"):
            report = selection.dispatch(
                stage,
                SelectionContext(location_id=bytes.fromhex("0108010000000720")),
                modules,
            )
            self.assertFalse(report["programming_authorized"])
            self.assertFalse(report["vehicle_compatibility_validated"])
            self.assertNotIn("private-never-report", str(report))
        for modules in ({}, {"SyntheticCID.dll": ("Other",)}):
            with self.assertRaises(LookupError):
                selection.dispatch("get_cid", SelectionContext(), modules)

    def test_scopes_are_separate_and_conflicts_inside_scope_rejected(self):
        generic = table([KEY, "Flag"], [["synthetic", "0"]])
        specific = table(
            [KEY, "DLLFileNameForGetCID", "Flag"], [["synthetic", "Synthetic.dll", "1"]]
        )
        c = CalibrationCatalog.from_tables(
            {"general.ini": generic, "family.ini": specific}, encoded=False
        )
        self.assertEqual(c.select("synthetic").value("Flag"), "1")
        self.assertEqual(c.select("synthetic").value("Flag", general=True), "0")
        with self.assertRaises(ValueError):
            CalibrationCatalog.from_tables(
                {
                    "one.ini": generic,
                    "two.ini": table([KEY, "Flag"], [["synthetic", "1"]]),
                },
                encoded=False,
            )

    def test_sequential_selectors_accumulate_and_prefix_match_requires_two_cids(self):
        selection = catalog().select("synthetic")
        selectors = (
            "GetCanIDsFromParamMatchedPartOfCIDForPrepareWrite",
            "GetCanIDsFromParamForPrepareWrite",
        )
        self.assertEqual(
            len(selection.addresses(selectors, SelectionContext(cids=("ABC1",)))), 1
        )
        addresses = selection.addresses(
            selectors, SelectionContext(cids=("ABC1", "DEF2"))
        )
        self.assertEqual([a.request for a in addresses], [b"\x03\0", b"\x02\0"])
        self.assertEqual(
            len(
                selection.addresses(selectors, SelectionContext(cids=("xABC", "DEF2")))
            ),
            1,
        )

    def test_respond_cid_repeats_whole_address_list(self):
        selection = catalog().select("synthetic")
        for count in (0, 1, 3):
            got = selection.addresses(
                ("GetCanIDsFromParamRespondCID",), SelectionContext(cids=("A",) * count)
            )
            self.assertEqual(len(got), max(1, count))

    def test_location_id_normal_and_extended_functional_address(self):
        selection = catalog().select("synthetic")
        for suffix, request, extended in (
            ("0720", b"\x07\x20", False),
            ("0000", b"\x07\x40\xfe", True),
        ):
            addresses = selection.addresses(
                ("GetCanIDsFromLocationIDForWrite",),
                SelectionContext(location_id=bytes.fromhex("010801000000" + suffix)),
            )
            self.assertEqual(addresses[0], Address(b"\x01\0", b"\x01\x08"))
            self.assertEqual(
                addresses[1], Address(request, bytes(len(request)), extended)
            )

    def test_can_table_and_previous_cid_results(self):
        c = catalog()
        lookup = parse_parameter_table(
            "can.ini",
            table(
                ["RequestCANID", "ResponseCANID", "CalibrationType"],
                [["0100", "0108", "1"]],
            ),
            encoded=False,
        )
        c = CalibrationCatalog([*c.tables, lookup])
        selection = c.select("synthetic")
        got = selection.addresses(
            ("GetCanIDsFromCANIDTable",), SelectionContext(diag_ids=(b"\x01\0",))
        )
        self.assertEqual(got, (Address(b"\x01\0", b"\x01\x08"),))
        self.assertEqual(
            selection.addresses(
                ("GetCanIDsFromResultOfGetCID",),
                SelectionContext(previous_addresses=got),
            ),
            got,
        )
        with self.assertRaises(LookupError):
            selection.addresses(
                ("GetCanIDsFromCANIDTable",), SelectionContext(diag_ids=(b"\x02\0",))
            )

    def test_gateway_and_extended_ids(self):
        selection = catalog().select("synthetic")
        self.assertEqual(
            selection.addresses(
                ("GetCanIDsFromParamForReprogGateway",), SelectionContext()
            ),
            (Address(b"\x04\0", b"\x04\x08"),),
        )
        self.assertEqual(
            parse_address("0100FE/0108FE"),
            Address(b"\x01\0\xfe", b"\x01\x08\xfe", True),
        )
        for value in ("100/108", "0100/0108FE", "0100/0108/0109", "not-an-id"):
            with self.assertRaises(ValueError):
                parse_address(value)

    def test_missing_or_unknown_selectors_and_inputs_fail(self):
        selection = catalog().select("synthetic")
        for selectors, context in (
            ((), SelectionContext()),
            (("Unknown",), SelectionContext()),
            (("GetCanIDsFromLocationIDForWrite",), SelectionContext()),
            (("GetCanIDsFromCANIDTable",), SelectionContext()),
        ):
            with self.assertRaises((ValueError, LookupError)):
                selection.addresses(selectors, context)

    def test_ini_secrets_never_reported(self):
        raw = b"[Secret]\nPassword=private-never-report\n"
        c = CalibrationCatalog.from_tables({"private.ini": raw}, encoded=False)
        self.assertEqual(c.tables[0].kind, "ini")
        self.assertNotIn("private-never-report", str(c.report()))
        self.assertNotIn("private-never-report", repr(c.tables[0]))

    def test_parser_negative_boundaries(self):
        for raw in (
            b"",
            b"A,A\nx,y\n",
            b"A,B\nx\n",
            b"A\nx\nx\n",
            b'A\n"unfinished',
            b"A\nx\0y\n",
            b"[A]\nx=1\nx=2",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_parameter_table("bad.ini", raw, encoded=False)
        with self.assertRaises(ValueError):
            parse_parameter_table("bad.ini", b"odd")
        with self.assertRaises(ValueError):
            SelectionContext(location_id=b"short")


if __name__ == "__main__":
    unittest.main()
