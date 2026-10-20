"""Bounded native CUW parameter selection and communication-address dispatch.

Original parameter tables and libraries are supplied explicitly by the caller.
The static module inspector reads explicitly selected regular files. Native code,
devices, and remote services are never opened.
"""

from __future__ import annotations

import configparser
import csv
import hashlib
import io
import re
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from scripts.calibration import decode_cuw_text
from scripts.local_files import read_regular

KEY = "ParamFileKeySystemProtocolMicon"
MAX_BYTES = 16 * 1024 * 1024
STAGES = {
    "get_cid": ("GetCID", "StartGetCID"),
    "prepare": ("PrepareWrite", "StartPrepareWrite"),
    "write": ("FlashWrite", "StartFlashWrite"),
    "gateway": ("ChangeToReprogGatewayMode", "ChangeToReprogGatewayMode"),
}


def inspect_module(path: str | Path) -> dict:
    """Read PE exports and RT_VERSION statically from one explicit local file."""
    source = Path(path)
    return inspect_module_bytes(read_regular(source, limit=MAX_BYTES), source.name)


def inspect_module_bytes(data: bytes, source_name: str) -> dict:
    """Inspect explicitly supplied immutable PE bytes; never open or execute them."""
    if (
        not isinstance(source_name, str)
        or not 0 < len(source_name) <= 260
        or "\0" in source_name
        or "/" in source_name
        or "\\" in source_name
        or source_name in (".", "..")
    ):
        raise ValueError("Bounded module basename required")
    if type(data) is not bytes or not 64 <= len(data) <= MAX_BYTES or data[:2] != b"MZ":
        raise ValueError("Bounded PE module with DOS header required")

    def number(offset: int, width: int = 4) -> int:
        if offset < 0 or offset + width > len(data):
            raise ValueError("Truncated PE integer")
        return int.from_bytes(data[offset : offset + width], "little")

    pe = number(0x3C)
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    count, optional_size, optional = number(pe + 6, 2), number(pe + 20, 2), pe + 24
    magic = number(optional, 2)
    minimum = {0x10B: 96, 0x20B: 112}.get(magic)
    if minimum is None or optional_size < minimum + 24 or not 1 <= count <= 96:
        raise ValueError("Invalid PE optional header or section count")
    sections_start = optional + optional_size
    if sections_start + 40 * count > len(data):
        raise ValueError("Truncated PE section table")
    directory = optional + minimum
    if number(directory - 4) < 3:
        raise ValueError("PE export/resource directories unavailable")
    sections = []
    for index in range(count):
        row = sections_start + 40 * index
        rva, size, offset = number(row + 12), number(row + 16), number(row + 20)
        if size and (offset < sections_start + 40 * count or offset + size > len(data)):
            raise ValueError("Invalid PE section extent")
        sections.append((rva, size, offset))

    def mapped(rva: int, size: int) -> int:
        if size < 0 or rva < 0 or rva + size > 0x100000000:
            raise ValueError("Invalid PE RVA span")
        matches = [
            offset + rva - start
            for start, length, offset in sections
            if size <= length and start <= rva and rva - start <= length - size
        ]
        if len(matches) != 1:
            raise ValueError("Unmapped or ambiguous PE RVA")
        return matches[0]

    export_rva, export_size = number(directory), number(directory + 4)
    exports = []
    if export_rva or export_size:
        if export_size < 40:
            raise ValueError("Truncated PE export directory")
        base = mapped(export_rva, export_size)
        names = number(base + 24)
        if names > 4096 or names > number(base + 20):
            raise ValueError("Invalid PE named export count")
        functions = number(base + 20)
        if functions > 65536:
            raise ValueError("Excessive PE export function count")
        function_table = mapped(number(base + 28), functions * 4) if functions else 0
        ordinals = mapped(number(base + 36), names * 2) if names else 0
        pointers = mapped(number(base + 32), names * 4) if names else 0
        for index in range(names):
            ordinal = number(ordinals + index * 2, 2)
            if ordinal >= functions or not number(function_table + ordinal * 4):
                raise ValueError("Invalid PE named export function slot")
            name_rva = number(pointers + index * 4)
            name_bytes = bytearray()
            for distance in range(1024):
                byte = data[mapped(name_rva + distance, 1)]
                if not byte:
                    break
                name_bytes.append(byte)
            else:
                raise ValueError("Unterminated PE export name")
            try:
                name = bytes(name_bytes).decode("ascii")
            except UnicodeError as exc:
                raise ValueError("Non-ASCII PE export name") from exc
            if not name or name in exports:
                raise ValueError("Empty or duplicate PE export")
            exports.append(name)
    resource_rva, resource_size = number(directory + 16), number(directory + 20)
    versions = []
    if resource_rva or resource_size:
        resource = mapped(resource_rva, resource_size)
        visited = set()
        entries = 0

        def walk(relative: int, depth: int, version: bool) -> None:
            nonlocal entries
            if depth > 3 or relative in visited or relative + 16 > resource_size:
                raise ValueError("Invalid or cyclic PE resource directory")
            visited.add(relative)
            base = resource + relative
            count = number(base + 12, 2) + number(base + 14, 2)
            entries += count
            if entries > 4096 or relative + 16 + count * 8 > resource_size:
                raise ValueError("PE resource entry limit exceeded")
            for index in range(count):
                identifier, target = (
                    number(base + 16 + index * 8),
                    number(base + 20 + index * 8),
                )
                is_version = version if depth else identifier == 16
                if not is_version:
                    continue
                child = target & 0x7FFFFFFF
                if target & 0x80000000:
                    walk(child, depth + 1, is_version)
                else:
                    if child + 16 > resource_size:
                        raise ValueError("Truncated PE version resource entry")
                    value_rva, size = (
                        number(resource + child),
                        number(resource + child + 4),
                    )
                    offset = mapped(value_rva, size)
                    versions.append(
                        parse_version_resource(data[offset : offset + size])
                    )

        walk(0, 0, False)
    if not versions or len(set(versions)) != 1:
        raise LookupError("Missing or ambiguous native FileVersion resource")
    return {
        "name": source_name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "exports": exports,
        "version": versions[0],
        "provenance": "static-PE-exports-and-native-FileVersion-string",
    }


def parse_version_resource(data: bytes) -> str:
    """Read native StringFileInfo/FileVersion using VarFileInfo translations.

    Accepts an explicitly extracted RT_VERSION resource, not executable code.
    Numeric VS_FIXEDFILEINFO is not substituted for the native version string.
    """
    if type(data) is not bytes or not 6 <= len(data) <= 65535:
        raise ValueError("Bounded RT_VERSION bytes required")
    nodes = 0

    def node(start: int, limit: int, depth: int) -> tuple[str, bytes, list, int]:
        nonlocal nodes
        nodes += 1
        if depth > 8 or nodes > 1024 or start + 6 > limit:
            raise ValueError("Invalid version-resource tree bounds")
        size, length, kind = struct.unpack_from("<HHH", data, start)
        end, cursor = start + size, start + 6
        if size < 8 or end > limit or kind not in (0, 1):
            raise ValueError("Invalid version-resource node")
        key_start = cursor
        while cursor + 2 <= end and data[cursor : cursor + 2] != b"\0\0":
            cursor += 2
        if cursor + 2 > end or cursor - key_start > 520:
            raise ValueError("Unterminated version-resource key")
        try:
            key = data[key_start:cursor].decode("utf-16le")
        except UnicodeError as exc:
            raise ValueError("Invalid version-resource key text") from exc
        cursor = (cursor + 5) & ~3
        value_end = cursor + length * (2 if kind else 1)
        if value_end > end:
            raise ValueError("Truncated version-resource value")
        value = data[cursor:value_end]
        cursor = (value_end + 3) & ~3
        children = []
        while cursor + 2 <= end:
            if data[cursor:end] == bytes(end - cursor):
                cursor = end
                break
            child = node(cursor, end, depth + 1)
            children.append(child)
            cursor = (child[3] + 3) & ~3
        if cursor < end and any(data[cursor:end]):
            raise ValueError("Invalid version-resource trailing data")
        return key, value, children, end

    root = node(0, len(data), 0)
    if (
        root[0] != "VS_VERSION_INFO"
        or len(root[1]) != 52
        or root[1][:4] != b"\xbd\x04\xef\xfe"
        or root[3] != len(data)
    ):
        raise ValueError("Invalid VS_VERSION_INFO root")
    translations = []
    versions = {}
    for key, _, children, _ in root[2]:
        if key == "VarFileInfo":
            for name, value, _, _ in children:
                if name == "Translation":
                    if len(value) % 4:
                        raise ValueError("Invalid version translation data")
                    translations.extend(struct.iter_unpack("<HH", value))
        elif key == "StringFileInfo":
            for table, _, strings, _ in children:
                for name, value, _, _ in strings:
                    if name == "FileVersion":
                        try:
                            version = value.decode("utf-16le").split("\0", 1)[0]
                        except UnicodeError as exc:
                            raise ValueError("Invalid FileVersion string") from exc
                        if (
                            not version
                            or len(version) > 259
                            or table.casefold() in versions
                        ):
                            raise ValueError(
                                "Missing or duplicate FileVersion translation"
                            )
                        versions[table.casefold()] = version
    for language, codepage in translations:
        key = f"{language:04x}{codepage:04x}"
        if key in versions:
            return versions[key]
    raise LookupError("No native FileVersion string for declared translation")


def _text(value: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\0" in value:
        raise ValueError("Invalid bounded parameter text")
    return value


@dataclass(frozen=True)
class Address:
    request: bytes
    response: bytes
    extended: bool = False

    def __post_init__(self) -> None:
        width = 3 if self.extended else 2
        if (
            type(self.extended) is not bool
            or type(self.request) is not bytes
            or type(self.response) is not bytes
            or len(self.request) != width
            or len(self.response) != width
        ):
            raise ValueError(
                "Native communication address must contain two or three bytes per direction"
            )

    def report(self) -> dict:
        return {
            "request_hex": self.request.hex(),
            "response_hex": self.response.hex(),
            "extended": self.extended,
        }


def parse_address(value: str) -> Address:
    """SeparateCanID RVA0x10c0: paired two-byte or three-byte binary IDs."""
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:[0-9a-fA-F]{4}/[0-9a-fA-F]{4}|[0-9a-fA-F]{6}/[0-9a-fA-F]{6})", value
    ):
        raise ValueError("Expected paired native hexadecimal communication IDs")
    request, response = value.split("/")
    return Address(bytes.fromhex(request), bytes.fromhex(response), len(request) == 6)


@dataclass(frozen=True)
class SelectionContext:
    cids: tuple[str, ...] = ()
    location_id: bytes | None = None
    diag_ids: tuple[bytes, ...] = ()
    previous_addresses: tuple[Address, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.cids, tuple) or len(self.cids) > 4096:
            raise ValueError("Bounded immutable calibration identities required")
        for cid in self.cids:
            _text(cid, 260)
        if self.location_id is not None and (
            type(self.location_id) is not bytes or len(self.location_id) != 8
        ):
            raise ValueError("Native LocationID requires eight supplied bytes")
        if (
            not isinstance(self.diag_ids, tuple)
            or len(self.diag_ids) > 4096
            or any(
                type(value) is not bytes or len(value) not in (2, 3)
                for value in self.diag_ids
            )
        ):
            raise ValueError("Bounded two/three-byte diagnostic IDs required")
        if (
            not isinstance(self.previous_addresses, tuple)
            or len(self.previous_addresses) > 4096
            or any(not isinstance(value, Address) for value in self.previous_addresses)
        ):
            raise ValueError("Invalid prior GetCID communication addresses")


@dataclass(frozen=True)
class ParameterTable:
    name: str
    sha256: str
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...] = field(repr=False)
    kind: str = "csv"

    def report(self) -> dict:
        return {
            "source": self.name,
            "sha256": self.sha256,
            "kind": self.kind,
            "columns": list(self.headers),
            "rows": len(self.rows),
        }


def parse_parameter_table(
    name: str, data: bytes, *, encoded: bool = True
) -> ParameterTable:
    _text(name, 260)
    if (
        not name
        or type(data) is not bytes
        or not 0 < len(data) <= MAX_BYTES
        or type(encoded) is not bool
    ):
        raise ValueError("Explicit bounded source bytes required")
    digest = hashlib.sha256(data).hexdigest()
    plain = decode_cuw_text(data) if encoded else data
    if b"\0" in plain:
        raise ValueError("NUL in parameter source")
    text = plain.decode("latin-1")
    if text.lstrip().startswith("["):
        if len(plain) > 1024 * 1024 or text.count("\n") > 8192:
            raise ValueError("INI parameter source limit exceeded")
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            parser.read_string(text)
        except configparser.Error as exc:
            raise ValueError("Invalid native INI parameter source") from exc
        if parser.defaults() or len(parser.sections()) > 256:
            raise ValueError("Unsupported inherited/default INI parameters")
        rows = []
        for section in parser.sections():
            _text(section, 128)
            for key, value in parser[section].items():
                rows.append((_text(section), _text(key, 128), _text(value)))
        if len(rows) > 4096:
            raise ValueError("INI parameter row limit exceeded")
        return ParameterTable(
            name, digest, ("section", "key", "value"), tuple(rows), "ini"
        )
    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        headers = next(reader, [])
        if not 1 <= len(headers) <= 256:
            raise ValueError("Parameter CSV column limit exceeded")
        rows = []
        for row in reader:
            if len(rows) >= 4096 or len(row) != len(headers):
                raise ValueError("Ragged or excessive parameter CSV rows")
            for value in row:
                _text(value)
            rows.append(row)
    except csv.Error as exc:
        raise ValueError("Malformed native parameter CSV") from exc
    if any(not column for column in headers) or len(set(headers)) != len(headers):
        raise ValueError("Empty or duplicate parameter column")
    for row in [headers, *rows]:
        if len(row) != len(headers):
            raise ValueError("Ragged parameter CSV")
        for value in row:
            _text(value)
    if len({row[0] for row in rows}) != len(rows):
        raise ValueError("Duplicate native lookup key in one table")
    return ParameterTable(name, digest, tuple(headers), tuple(map(tuple, rows)))


class CalibrationCatalog:
    def __init__(self, tables: Sequence[ParameterTable]):
        if not isinstance(tables, (tuple, list)) or len(tables) > 4096:
            raise ValueError("Bounded parameter table sequence required")
        self.tables = tuple(tables)
        self._rows: dict[str, dict[str, str]] = {}
        self._general: dict[str, dict[str, str]] = {}
        self._sources: dict[str, list[ParameterTable]] = {}
        self.can_ids: dict[bytes, bytes] = {}
        self.logical_addresses: dict[bytes, dict[str, str]] = {}
        retained = 0
        names = set()
        for table in tables:
            if not isinstance(table, ParameterTable) or table.name in names:
                raise ValueError("Invalid or duplicate parameter source")
            names.add(table.name)
            retained += sum(len(value) for row in table.rows for value in row)
            if retained > 64 * 1024 * 1024:
                raise ValueError("Catalog aggregate byte budget exceeded")
            if table.kind == "ini":
                continue
            for row in table.rows:
                values = dict(zip(table.headers, row, strict=True))
                if KEY in values:
                    key = values[KEY]
                    if not key or len(key) > 260:
                        raise ValueError("Invalid native parameter key")
                    family = any(
                        column.startswith("DLLFileNameFor") for column in table.headers
                    )
                    merged = (self._rows if family else self._general).setdefault(
                        key, {}
                    )
                    self._rows.setdefault(key, {})
                    for column, value in values.items():
                        if value and merged.get(column, value) != value:
                            raise ValueError(
                                f"Conflicting parameter source for key {key!r}, column {column!r}"
                            )
                        if value or column not in merged:
                            merged[column] = value
                    self._sources.setdefault(key, []).append(table)
                elif "RequestCANID" in values and "ResponseCANID" in values:
                    pair = parse_address(
                        values["RequestCANID"] + "/" + values["ResponseCANID"]
                    )
                    if self.can_ids.get(pair.request, pair.response) != pair.response:
                        raise ValueError("Conflicting native CAN-ID lookup")
                    self.can_ids[pair.request] = pair.response
                elif "LogicalAddress" in values:
                    address = values["LogicalAddress"]
                    if not re.fullmatch(r"[0-9a-fA-F]{4}", address):
                        raise ValueError("Invalid logical-address lookup key")
                    address_bytes = bytes.fromhex(address)
                    if self.logical_addresses.get(address_bytes, values) != values:
                        raise ValueError("Conflicting native logical-address lookup")
                    self.logical_addresses[address_bytes] = values
                else:
                    raise ValueError("Unknown native parameter table schema")

    @classmethod
    def from_tables(
        cls, sources: Mapping[str, bytes], *, encoded: bool = True
    ) -> CalibrationCatalog:
        if (
            not isinstance(sources, Mapping)
            or len(sources) > 4096
            or any(type(value) is not bytes for value in sources.values())
            or sum(len(value) for value in sources.values()) > 64 * 1024 * 1024
        ):
            raise ValueError("Invalid bounded catalog source mapping")
        return cls(
            tuple(
                parse_parameter_table(name, data, encoded=encoded)
                for name, data in sources.items()
            )
        )

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(self._rows)

    def select(self, key: str) -> CalibrationSelection:
        _text(key, 260)
        if key not in self._rows:
            raise LookupError("No exact native calibration parameter key")
        return CalibrationSelection(self, key)

    def select_native(
        self, first: str, second: str, third: str
    ) -> CalibrationSelection:
        # SetKeys appends formal argument1, then3, then2 without separators.
        return self.select(_text(first, 260) + _text(third, 260) + _text(second, 260))

    def select_metadata(
        self,
        kind_of_ecu: str,
        cpu_type: str,
        contact_type: str,
        *,
        stage: str = "get_cid",
        required_spec: str = "02",
    ) -> CalibrationSelection:
        if stage not in STAGES:
            raise ValueError("Unknown native calibration stage")
        protocol = _text(contact_type, 128)
        if stage in ("prepare", "write") and protocol in ("P5-Unified", "Ethernet"):
            spec = _text(required_spec, 16)
            if not spec:
                raise ValueError("Required native reprogramming specification missing")
            if spec != "02":
                protocol += spec
        selection = self.select_native(kind_of_ecu, cpu_type, protocol)
        if not any(
            source.name == selection.key + ".ini"
            for source in self._sources[selection.key]
        ):
            raise LookupError("Native key-specific parameter source file unavailable")
        return selection

    def report(self) -> dict:
        return {
            "sources": [table.report() for table in self.tables],
            "parameter_keys": len(self._rows),
            "can_id_rows": len(self.can_ids),
            "logical_address_rows": len(self.logical_addresses),
            "vehicle_compatibility_validated": False,
            "provenance": "native-CUW-parameter-table-framing-and-exact-key-selection",
        }


class CalibrationSelection:
    def __init__(self, catalog: CalibrationCatalog, key: str):
        self.catalog, self.key = catalog, key

    def value(self, name: str, *, general: bool = False) -> str:
        """Explicit raw access for native providers; never included in reports."""
        if general:
            return self.catalog._general.get(self.key, {}).get(name, "")
        values = self.catalog._rows[self.key]
        return (
            values[name]
            if name in values
            else self.catalog._general.get(self.key, {}).get(name, "")
        )

    def _lines(self, name: str) -> tuple[str, ...]:
        value = self.value(name)
        lines = tuple(value.splitlines()) if value else ()
        if len(lines) > 10 or any(not line or len(line) > 259 for line in lines):
            raise ValueError("Native parameter list exceeds ten bounded entries")
        return lines

    def addresses(
        self, selectors: Sequence[str], context: SelectionContext
    ) -> tuple[Address, ...]:
        if (
            not isinstance(selectors, (tuple, list))
            or not 0 < len(selectors) <= 10
            or not isinstance(context, SelectionContext)
        ):
            raise ValueError("Explicit bounded selectors and context required")
        result = []
        for selector in selectors:
            columns = {
                "GetCanIDsFromParamForGetCID": "CanIDForGetCID",
                "GetCanIDsFromParamForPrepareWrite": "CanIDForPrepareWrite",
                "GetCanIDsFromParamForReprogGateway": "CanIDForReprogGateway",
            }
            if selector in columns:
                lines = self._lines(columns[selector])
                if not lines:
                    raise LookupError("Missing native communication-address parameter")
                result.extend(map(parse_address, lines))
            elif selector == "GetCanIDsFromParamMatchedPartOfCIDForPrepareWrite":
                prefixes = self._lines("CIDForCalcCpuNum")
                if not prefixes:
                    raise LookupError("Missing native CID prefix parameter")
                if (
                    sum(
                        any(cid.startswith(prefix) for prefix in prefixes)
                        for cid in context.cids
                    )
                    >= 2
                ):
                    lines = self._lines("CanIDMatchedPartOfCID")
                    if not lines:
                        raise LookupError(
                            "Missing native matched-CID communication addresses"
                        )
                    result.extend(map(parse_address, lines))
            elif selector == "GetCanIDsFromParamRespondCID":
                lines = self._lines("CanIDForPrepareWrite")
                if not lines:
                    raise LookupError("Missing native prepare communication addresses")
                result.extend(
                    tuple(map(parse_address, lines)) * max(1, len(context.cids))
                )
            elif selector == "GetCanIDsFromResultOfGetCID":
                result.extend(context.previous_addresses)
            elif selector == "GetCanIDsFromCANIDTable":
                if not context.diag_ids:
                    raise LookupError("Native node diagnostic IDs required")
                for request in context.diag_ids:
                    if request not in self.catalog.can_ids:
                        raise LookupError(
                            "Native diagnostic ID absent from CAN-ID table"
                        )
                    result.append(
                        Address(
                            request, self.catalog.can_ids[request], len(request) == 3
                        )
                    )
            elif selector == "GetCanIDsFromLocationIDForWrite":
                location = context.location_id
                if location is None:
                    raise LookupError("Native LocationID required")
                result.append(Address(location[2:4], location[:2]))
                functional = (
                    b"\x07\x20" if location[6:8] == b"\x07\x20" else b"\x07\x40\xfe"
                )
                result.append(
                    Address(functional, bytes(len(functional)), len(functional) == 3)
                )
            else:
                raise ValueError("Unknown native communication-address selector")
            if len(result) > 4096:
                raise ValueError("Native address result budget exceeded")
        return tuple(result)

    def dispatch(
        self,
        stage: str,
        context: SelectionContext,
        available_modules: Mapping[str, Sequence[str]],
        *,
        module_versions: Mapping[str, str] | None = None,
    ) -> dict:
        if not isinstance(stage, str) or stage not in STAGES:
            raise ValueError("Unknown native calibration stage")
        if not isinstance(context, SelectionContext) or not isinstance(
            available_modules, Mapping
        ):
            raise TypeError("Explicit dispatch context and module inventory required")
        suffix, export = STAGES[stage]
        module = self.value("DLLFileNameFor" + suffix)
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.dll", module):
            raise LookupError("Native dispatch DLL field unavailable or invalid")
        if module in available_modules and (
            not isinstance(available_modules[module], (tuple, list))
            or len(available_modules[module]) > 4096
            or any(
                not isinstance(name, str) or len(name) > 1024
                for name in available_modules[module]
            )
        ):
            raise ValueError("Invalid native named export inventory")
        if module not in available_modules or export not in available_modules[module]:
            raise LookupError("Required native module/export dependency unavailable")
        required_exports = [export]
        if stage == "write":
            for flag, extra in (
                ("PrepareRetryFlag", "PrepareRetry"),
                ("ConfirmAfterEndOfFlashingFlag", "IsFinishReprogramming"),
            ):
                value = self.value(flag)
                if value not in ("", "0", "1"):
                    raise ValueError("Native dispatch flag is not a boolean")
                if value == "1":
                    required_exports.append(extra)
            if any(name not in available_modules[module] for name in required_exports):
                raise LookupError("Required native retry/finish export unavailable")
        versions = self._lines("EnableDLLVersionInformation")
        if versions:
            if (
                len(versions) != 4
                or module_versions is None
                or module not in module_versions
            ):
                raise LookupError(
                    "Native four-phase DLL version dependency unavailable"
                )
            actual = _text(module_versions[module], 259)
            expected = versions[("get_cid", "prepare", "write", "gateway").index(stage)]
            try:
                outdated = actual.encode("latin-1") < expected.encode("latin-1")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    "Native DLL version must be an ANSI byte string"
                ) from exc
            if outdated:
                raise ValueError("Native DLL FileVersion is below phase requirement")
        selectors = self._lines("GetCANIDFunctionNameFor" + suffix)
        addresses = self.addresses(selectors, context) if selectors else ()
        return {
            "module": module,
            "operation": export,
            "required_exports": required_exports,
            "module_version_checked": bool(versions),
            "selectors": list(selectors),
            "addresses": [address.report() for address in addresses],
            "sources": [
                {"source": source.name, "sha256": source.sha256}
                for source in self.catalog._sources[self.key]
            ],
            "vehicle_compatibility_validated": False,
            "programming_authorized": False,
            "provenance": "native-CUW-library-field-and-communication-selector-dispatch",
        }
