# Native calibration parameter selection

`scripts/calibration_catalog.py` implements native CUW table decoding, exact key
selection, phase/specification dispatch, DLL dependency/version checks, and the
eight communication-address strategies. It never executes a PE module, opens a
device, searches a directory, or downloads a dependency implicitly.

```python
from scripts.calibration_catalog import (
    CalibrationCatalog, SelectionContext, inspect_module,
)

# Each file is explicitly supplied by its caller. Original parameters use the
# native two-character nibble representation; authored plaintext uses encoded=False.
catalog = CalibrationCatalog.from_tables({"synthetic.ini": parameter_bytes})
selected = catalog.select("synthetic")
module = inspect_module(explicit_module_path)
plan = selected.dispatch(
    "get_cid", SelectionContext(),
    {module["name"]: module["exports"]},
    module_versions={module["name"]: module["version"]},
)
```

The example requires caller-supplied input variables. A successful plan is an
actual resolution of supplied native table fields, addresses and dependencies.
It is not authorization to program a vehicle.

## Native keys and source scopes

`select(key)` performs a case-sensitive exact lookup. `select_native(first,
second, third)` follows the native `SetKeys` order: first + third + second,
without separators. The actual modern caller establishes these arguments as
KindOfECU, CPUType, ContactType. `select_metadata(kind_of_ecu, cpu_type,
contact_type, stage=..., required_spec=...)` accepts those literal metadata
strings, constructs the native key and requires the matching `key + ".ini"`
source file to have been explicitly supplied.

GetCID uses the base KindOfECU + ContactType + CPUType key. For P5-Unified and
Ethernet preparation/writing, specification `02` uses the base key; other
specifications insert their exact string between ContactType and CPUType. No
closest version, case folding, brand matching, or arbitrary protocol fallback
is performed. Missing source/key/version dependencies fail explicitly.

The general Parameter table and per-family tables are distinct native scopes.
They can legitimately contain different values for the same named field.
`selection.value(name, general=True)` explicitly accesses the general scope;
the default reads family fields, falling back to general fields only when the
family schema does not contain that column. An empty family value remains empty.
Conflicting values within one scope and duplicate keys within one source are
rejected. This is a conservative host policy; native row search picks the first
exact match in the loaded table. Mixing conflicting builds is rejected.

`parse_parameter_table` accepts quoted CSV with embedded newlines, and the two
observed plain INI table families after native decoding. Binary text is decoded
with Latin-1 to preserve exact ANSI byte comparisons. It does not silently
reinterpret unknown schemas. No source table is bundled publicly.

## Phase dependencies and native version comparison

`dispatch` accepts stages `get_cid`, `prepare`, `write`, and `gateway`. Native
field suffixes map to exports StartGetCID, StartPrepareWrite, StartFlashWrite,
and ChangeToReprogGatewayMode respectively. Writing additionally requires
PrepareRetry when PrepareRetryFlag is 1, and IsFinishReprogramming when
ConfirmAfterEndOfFlashingFlag is 1.

`inspect_module(path)` statically reads the explicit file's PE export names and
RT_VERSION resources, returning name, SHA-256, exports and FileVersion. It uses
standard-library parsing with bounded file size, section/RVA spans, export
names, resource directories and version-node recursion. Cyclic resources and
missing or conflicting version resources fail. This inspection does not prove
that a Windows dependency can run on Linux or that its protocol is implemented
by an injected Python provider.

`inspect_module_bytes(data, source_name)` performs the same static inspection on
explicit immutable bytes and a bounded module basename, allowing an imported
container to share the same export, version and source-hash checks.

`parse_version_resource(resource_bytes)` is available for callers that already
have an RT_VERSION payload. It follows VarFileInfo/Translation order and selects
the corresponding StringFileInfo/FileVersion string. It does not substitute the
numeric fixed-file version or invent a format. Native code compares that raw
version string lexically, byte by byte, against the selected entry of the
four-line EnableDLLVersionInformation field. This behavior is preserved rather
than replaced with semantic-version ordering. The entries are GetCID,
prepare, write, gateway, in that order. Missing required version information
fails; the host never assumes an installed module is recent enough.

## Address strategies

`SelectionContext` requires immutable, bounded inputs: calibration-ID strings,
an optional eight-byte LocationID, two/three-byte node diagnostic IDs and prior
GetCID addresses. `Address` retains request bytes, response bytes and the native
extended-address flag. Three bytes represent the native extended address form;
they are not interpreted as an ordinary 29-bit CAN integer.

| Selector | Recovered behavior |
|---|---|
| GetCanIDsFromParamForGetCID | Parse CanIDForGetCID request/response pairs |
| GetCanIDsFromParamForPrepareWrite | Parse CanIDForPrepareWrite pairs |
| GetCanIDsFromParamForReprogGateway | Parse CanIDForReprogGateway pairs |
| GetCanIDsFromParamMatchedPartOfCIDForPrepareWrite | Count supplied CIDs beginning with one of CIDForCalcCpuNum prefixes; at least two matches append CanIDMatchedPartOfCID pairs |
| GetCanIDsFromParamRespondCID | Repeat the complete preparation pair list for each supplied CID, with one list retained for zero/one CID |
| GetCanIDsFromResultOfGetCID | Append supplied prior GetCID addresses |
| GetCanIDsFromCANIDTable | Resolve every supplied node diagnostic ID against the native CAN-ID table |
| GetCanIDsFromLocationIDForWrite | Use LocationID bytes 2–3 as request, bytes 0–1 as response; append functional 0720 when bytes 6–7 equal 0720, otherwise extended 0740fe |

Selectors execute sequentially and accumulate addresses; they are not a
first-success fallback chain. A matched-CID selector with fewer than two prefix
matches adds no address, then the next selector runs. A selector failure stops
resolution. The host raises instead of returning a partial address list as a
usable dispatch plan. Unknown selectors and absent required context fail.

## Bounds, confidentiality and coverage

Inputs are bounded to 16 MiB per table/module and 64 MiB per catalog; table rows
are bounded to 4096, columns to 256 and cell values to 4096 characters. Native
address parameter lists are bounded to ten entries of at most 259 characters;
resolved addresses are bounded to 4096. Version resources are at most 65535 bytes,
1024 nodes and eight levels deep. Parsing does not modify process-global CSV
limits or load any dependency.

Reports include source hashes, schema names, selected module/export names and
resolved addresses. Raw row values and security/password/key fields are omitted.
`selection.value` is explicit raw access for an authorized host provider; callers
must not publish those returned values. Dataclass representations omit raw rows.

Private corpus verification parses all 328 original Techstream 12/18 parameter
files, statically inspects all 134 corresponding CUW DLLs, and resolves all 1085
declared phase dispatches against their real exports and FileVersion strings
using authored CID/address contexts. All seven selectors present in those
tables are exercised; the additional exported prior-GetCID strategy is covered
by an authored test. Public tests include malformed CSV/INI, conflicting scopes,
missing dependencies, version translations, PE truncations and resource cycles.

Native references are TCUWParameterForBCB.dll SHA-256
`2088b7066c749eab0bf60278afaf15fdf2acc65e7e033f07121bbba524e0a7e4`
(SetKeys RVA26e8, row comparison2378/3da8/11e78),
TCUWCommunicationAddress.dll SHA-256
`1553575ca772cadc75291466c3c64f5f37e565d88b600a1fdd7bfc8b97369b2a`
(selector dispatcher23f0, address splitter10c0, LocationID1cb0,
CAN table1f40, CID-prefix21a0, repeated-CID2320), and
TCUWControlCommPhase.dll SHA-256
`8c8d03d3e8ff9b32dcccf0b5ef5249304d720f19aed070b18894f1a78a3fabca`
(GetCID6470, unified prepare9350/write9c90, stage loaders1c30/1ce0/1d90,
version gate1f50, native FileVersion retrieval4f30). All addresses are RVAs.

Parameter/dependency compatibility is checked. Complete calibration-to-vehicle
hardware/identity/signature compatibility is a separate software contract and is
reported as unvalidated, rather than inferred from a matching catalog label.
Physical ECU/adapter acceptance remains PHYSICAL_UNCONFIRMED.

```sh
python -m unittest discover -s tests -p test_calibration_catalog.py -v
```
