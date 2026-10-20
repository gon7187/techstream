"""Bounded native language pools with explicit source and Unicode provenance."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from scripts.diagnostic_db import MAX_SIZE, parse_database
from scripts.local_files import read_regular

MAX_TRANSLATION_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 250_000


@dataclass(frozen=True)
class ResourceText:
    identifier: int
    text: str
    source_sha256: str
    namespace: str
    pool_sha256: str
    pool_offset: int
    byte_length: int
    encoding: str = "utf-16le"

    def report(self) -> dict:
        return {
            "id": self.identifier,
            "text": self.text,
            "source_sha256": self.source_sha256,
            "namespace": self.namespace,
            "section": 0,
            "pool_sha256": self.pool_sha256,
            "pool_offset": self.pool_offset,
            "byte_length": self.byte_length,
            "encoding": self.encoding,
            "presentation": "source-unicode",
        }


class TextResources:
    """DWORD IDs in an explicitly selected native language resource.

    Management and legacy pools share their stored format, not their ID space.
    The returned Unicode precedes native Windows CP_ACP presentation conversion.
    """

    def __init__(
        self,
        data: bytes,
        *,
        namespace: str,
        expected_sha256: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self._cancelled = cancelled
        self._check()
        if namespace not in ("management", "legacy", "viewer", "utility"):
            raise ValueError("Unknown native language namespace")
        if type(data) is not bytes or len(data) > MAX_SIZE:
            raise ValueError("Language resource must be bounded bytes")
        digest = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None:
            if (
                type(expected_sha256) is not str
                or len(expected_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_sha256)
            ):
                raise ValueError(
                    "Expected source SHA-256 must be lowercase hexadecimal"
                )
            if digest != expected_sha256:
                raise ValueError("Selected language source SHA-256 mismatch")
        database = parse_database(data)
        self._check()
        expected_kind = {"viewer": 5, "utility": 6}.get(namespace, 4)
        expected_sections = {0, 1} if namespace == "utility" else {0}
        if (
            database.kind != expected_kind
            or set(database.sections) != expected_sections
        ):
            raise ValueError("Language kind does not match its explicit namespace")
        section = database.sections[0]
        if section.count > MAX_RECORDS:
            raise ValueError("Language record count exceeds its host budget")
        payload = section.payload
        base = section.count * 6
        if base > len(payload):
            raise ValueError("Language index exceeds source section")
        pool_hash = hashlib.sha256(payload).hexdigest()
        rows = []
        expected = 0
        for index in range(section.count):
            self._check()
            offset, size = struct.unpack_from("<IH", payload, index * 6)
            if offset != expected or size % 2 or base + offset + size > len(payload):
                raise ValueError("Invalid native language string bounds")
            encoded = payload[base + offset : base + offset + size]
            if size and not encoded.endswith(b"\0\0"):
                raise ValueError("Unterminated native language string")
            # Native WideCharToMultiByte(...,-1,...) consumes the first wide NUL.
            text = encoded.decode("utf-16le").split("\0", 1)[0]
            rows.append(
                ResourceText(
                    index + 1, text, digest, namespace, pool_hash, base + offset, size
                )
            )
            expected += size
        if base + expected != len(payload):
            raise ValueError("Trailing native language pool bytes")
        self._rows = tuple(rows)
        self.source_sha256 = digest
        self.namespace = namespace
        self.version = database.version
        self._check()

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        namespace: str,
        expected_sha256: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> TextResources:
        if cancelled is not None and cancelled():
            raise InterruptedError("Language lookup cancelled")
        data = read_regular(path, limit=MAX_SIZE)
        return cls(
            data,
            namespace=namespace,
            expected_sha256=expected_sha256,
            cancelled=cancelled,
        )

    def _check(self) -> None:
        if self._cancelled is not None and self._cancelled():
            raise InterruptedError("Language lookup cancelled")

    def resolve(self, identifier: int) -> ResourceText:
        self._check()
        if type(identifier) is not int or not 1 <= identifier <= len(self._rows):
            raise ValueError(
                "Native translation ID must reference a selected source string"
            )
        return self._rows[identifier - 1]

    def translate(self, identifiers: Sequence[int]) -> tuple[ResourceText, ...]:
        self._check()
        if not isinstance(identifiers, (tuple, list)) or len(identifiers) > 4096:
            raise ValueError("Native translation ID list exceeds its host budget")
        # Preserve native order and duplicates; a bad ID fails the whole request.
        result = []
        size = 0
        for identifier in identifiers:
            row = self.resolve(identifier)
            size += len(row.text.encode("utf-8"))
            if size > MAX_TRANSLATION_BYTES:
                raise ValueError("Translation output exceeds its aggregate byte budget")
            result.append(row)
        return tuple(result)


class UtilityTextResources:
    """TY2 LangIDTable -> UtilityDB 0x601 K1 -> selected U-language pool.

    The selected utility group is an explicit native caller input. Common group
    20000 and the selected group populate one map in source order (last ID wins).
    Original symbol/key domains are ASCII; unsupported ANSI conversion is never
    silently inferred from the Linux locale.
    """

    def __init__(
        self,
        data: bytes,
        symbols: bytes,
        *,
        utility_group: int,
        expected_sha256: str | None = None,
        symbols_sha256: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self._cancelled = cancelled
        self._check()
        if type(utility_group) is not int or not 0 <= utility_group <= 0xFFFFFFFF:
            raise ValueError("Utility group must be an explicit DWORD")
        if type(symbols) is not bytes or len(symbols) > MAX_SIZE:
            raise ValueError("Utility symbols must be bounded bytes")
        digest = hashlib.sha256(symbols).hexdigest()
        if symbols_sha256 is not None and (
            type(symbols_sha256) is not str
            or len(symbols_sha256) != 64
            or any(c not in "0123456789abcdef" for c in symbols_sha256)
            or digest != symbols_sha256
        ):
            raise ValueError("Selected utility symbols SHA-256 mismatch")
        self.language = TextResources(
            data,
            namespace="utility",
            expected_sha256=expected_sha256,
            cancelled=cancelled,
        )
        database = parse_database(data)
        section = database.sections[1]
        if section.count > MAX_RECORDS:
            raise ValueError("Utility key table exceeds its host record budget")
        groups: dict[str, list[tuple[int, str, ResourceText]]] = {}
        previous = None
        closed: set[str] = set()
        for index, row in enumerate(section.rows(164)):
            self._check()
            keys = []
            for field in (row[:80], row[80:160]):
                decoded = field.decode("utf-16le")
                key, separator, _tail = decoded.partition("\0")
                if not separator:
                    raise ValueError("Unterminated native utility key")
                # Key presentation is Windows CP_ACP, independent of source text.
                # Exact ASCII keys avoid guessing an unobserved ANSI code page.
                if not key.isascii():
                    raise ValueError(
                        "Utility key requires an observed Windows ANSI encoding"
                    )
                keys.append(key)
            primary, secondary = keys
            if primary != previous:
                if primary in closed:
                    raise ValueError("Noncontiguous native utility key group")
                if previous is not None:
                    closed.add(previous)
                previous = primary
            group = groups.setdefault(primary, [])
            if len(group) >= 32767:
                raise ValueError("Utility group exceeds native signed SHORT count")
            resource = self.language.resolve(struct.unpack_from("<I", row, 160)[0])
            group.append((index, secondary, resource))
        self._groups = {key: tuple(value) for key, value in groups.items()}
        position, count = 0, 0
        mapping: dict[int, tuple[str, int, int]] = {}
        while position < len(symbols):
            self._check()
            if count >= MAX_RECORDS or len(symbols) - position < 10:
                raise ValueError("Invalid utility symbol count/header")
            offset = position
            group_id, identifier, size = struct.unpack_from("<IIH", symbols, position)
            position += 10
            if not size or size % 2 or size > 128 or size > len(symbols) - position:
                raise ValueError("Invalid native utility symbol length")
            encoded = symbols[position : position + size]
            # TY2 3F149..3F189 appends each UTF16 low byte to CString. Preserve
            # this byte semantics; it is not a wide string language-pool index.
            encoded.decode("utf-16le")
            key_bytes = encoded[::2].split(b"\0", 1)[0]
            if not key_bytes.isascii():
                raise ValueError("Utility symbol requires an observed ANSI encoding")
            key = key_bytes.decode("ascii")
            if group_id in (20000, utility_group):
                mapping[identifier] = (key, group_id, offset)
            position += size
            count += 1
        self._symbols = mapping
        self.utility_group = utility_group
        self.symbols_sha256 = digest
        self.source_sha256 = self.language.source_sha256
        self._check()

    @classmethod
    def load(
        cls,
        path: str | Path,
        symbols_path: str | Path,
        *,
        utility_group: int,
        expected_sha256: str | None = None,
        symbols_sha256: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> UtilityTextResources:
        if cancelled is not None and cancelled():
            raise InterruptedError("Utility text lookup cancelled")
        data = read_regular(path, limit=MAX_SIZE)
        if cancelled is not None and cancelled():
            raise InterruptedError("Utility text lookup cancelled")
        symbols = read_regular(symbols_path, limit=MAX_SIZE)
        return cls(
            data,
            symbols,
            utility_group=utility_group,
            expected_sha256=expected_sha256,
            symbols_sha256=symbols_sha256,
            cancelled=cancelled,
        )

    def _check(self) -> None:
        if self._cancelled is not None and self._cancelled():
            raise InterruptedError("Utility text lookup cancelled")

    def resolve(self, identifier: int) -> dict:
        self._check()
        if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
            raise ValueError("Utility resource ID must be a DWORD")
        result = {
            "id": identifier,
            "utility_group": self.utility_group,
            "source_sha256": self.source_sha256,
            "database_version": self.language.version,
            "symbols_sha256": self.symbols_sha256,
            "broker": "LangIDTable.GetUtilityString_K1.0x601",
            "status": "missing_symbol",
            "text": "",
            "resource": None,
        }
        symbol = self._symbols.get(identifier)
        if symbol is None:
            return result
        key, group_id, offset = symbol
        result.update(
            key=key,
            symbol_group=group_id,
            symbol_offset=offset,
            symbol_encoding="utf-16le-low-byte-cstring",
        )
        rows = self._groups.get(key)
        if not rows:
            result["status"] = "missing_key"
            return result
        index, secondary, resource = rows[0]
        result.update(
            status="resolved",
            text=resource.text,
            resource=resource.report(),
            row_index=index,
            row_offset=index * 164,
            section=1,
            secondary_key=secondary,
        )
        return result


class ViewerHelpResources:
    """Native ViewerDb 0x302 help rows joined to their selected V-language pool."""

    def __init__(
        self,
        viewer: bytes,
        language: TextResources,
        *,
        expected_sha256: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self._cancelled = cancelled
        self._check()
        if type(viewer) is not bytes or len(viewer) > MAX_SIZE:
            raise ValueError("Viewer resource must be bounded bytes")
        digest = hashlib.sha256(viewer).hexdigest()
        if expected_sha256 is not None:
            if (
                type(expected_sha256) is not str
                or len(expected_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_sha256)
            ):
                raise ValueError(
                    "Expected Viewer SHA-256 must be lowercase hexadecimal"
                )
            if digest != expected_sha256:
                raise ValueError("Selected Viewer source SHA-256 mismatch")
        if not isinstance(language, TextResources) or language.namespace != "viewer":
            raise ValueError("Help rows require an explicitly selected V-language pool")
        database = parse_database(viewer)
        self._check()
        if database.kind != 3 or 2 not in database.sections:
            raise ValueError("Viewer resource has no native HelpInfo section")
        section = database.sections[2]
        if section.count > MAX_RECORDS:
            raise ValueError("Help record count exceeds its host budget")
        rows: dict[int, list[tuple[int, int, int]]] = {}
        previous = 0
        for index, row in enumerate(section.rows(12)):
            self._check()
            string_id, identifier, kind = struct.unpack_from("<IIH", row)
            if identifier < previous:
                raise ValueError("Help keys are not in native contiguous index order")
            previous = identifier
            # Validate the selected language dependency even for other row kinds.
            language.resolve(string_id)
            group = rows.setdefault(identifier, [])
            if len(group) >= 0x7FFF:
                raise ValueError("Help key group exceeds native signed count")
            group.append((kind, string_id, index))
        self._rows = {key: tuple(value) for key, value in rows.items()}
        self.language = language
        self.source_sha256 = digest
        self._check()

    @classmethod
    def load(
        cls,
        viewer_path: str | Path,
        language_path: str | Path,
        *,
        viewer_sha256: str | None = None,
        language_sha256: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ViewerHelpResources:
        language = TextResources.load(
            language_path,
            namespace="viewer",
            expected_sha256=language_sha256,
            cancelled=cancelled,
        )
        language._check()
        viewer = read_regular(viewer_path, limit=MAX_SIZE)
        return cls(viewer, language, expected_sha256=viewer_sha256, cancelled=cancelled)

    def _check(self) -> None:
        if self._cancelled is not None and self._cancelled():
            raise InterruptedError("Help resource lookup cancelled")

    def resolve(self, identifier: int, *, kind: int = 1) -> dict | None:
        """C45920 and C45B30 overwrite on every matching type: last row wins."""
        self._check()
        if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
            raise ValueError("Help identifier must fit DWORD")
        if type(kind) is not int or kind not in (1, 2, 3, 4):
            raise ValueError("Unsupported native help row kind")
        selected = next(
            (
                (string_id, index)
                for row_kind, string_id, index in reversed(
                    self._rows.get(identifier, ())
                )
                if row_kind == kind
            ),
            None,
        )
        if selected is None:
            return None
        string_id, index = selected
        result = self.language.resolve(string_id).report()
        return result | {
            "help_id": identifier,
            "help_kind": kind,
            "viewer_sha256": self.source_sha256,
            "viewer_section": 2,
            "viewer_row": index,
            "viewer_row_offset": index * 12,
        }

    def active_details(self, identifier: int) -> dict:
        """Native active List help key, in CGetActiveTestDetailsInfo ABI order.

        The three output buffers select kinds 2, 4, 3 respectively. They are
        separate from the authored kind-1 Init instruction presentation.
        """
        self._check()
        if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
            raise ValueError("Active help key must fit DWORD")
        return {
            "help_id": identifier,
            "broker": "ViewerDb.0x302.active-details",
            "outputs": [
                {"kind": kind, "resource": self.resolve(identifier, kind=kind)}
                for kind in (2, 4, 3)
            ],
            "viewer_sha256": self.source_sha256,
            "language_sha256": self.language.source_sha256,
        }

    def instruction_texts(self, identifiers: Mapping[str, int]) -> dict[str, dict]:
        """Compose recovered Init numeric help references with the help broker.

        This exposes the backend resource join, not Win32 information-list state.
        Zero references and missing nonzero references remain distinguishable.
        """
        self._check()
        roles = ("caution", "help", "prohibition", "info", "comment")
        if not isinstance(identifiers, Mapping) or set(identifiers) != set(roles):
            raise ValueError("Instruction IDs must contain the five native Init roles")
        result = {}
        for role in roles:
            identifier = identifiers[role]
            if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
                raise ValueError("Help ID must be a DWORD")
            text = None if identifier == 0 else self.resolve(identifier)
            result[role] = {
                "id": identifier,
                "status": "absent"
                if identifier == 0
                else "missing"
                if text is None
                else "resolved",
                "resource": text,
                "broker": "ViewerDb.0x302.kind1",
                "presentation_policy": "host-init-kind1",
                "native_dialog_dispatch": "unresolved",
                "viewer_sha256": self.source_sha256,
                "language_sha256": self.language.source_sha256,
            }
        return result


def create_utility_text_examples() -> dict[str, bytes]:
    """Authored Door source IDs and text for the native group4934 consumer."""
    from scripts.demo import _ddb, _language

    texts = [f"Authored Door instruction {index + 1}" for index in range(8)]
    texts.append("Authored acknowledge")
    identifiers = (*range(0x94B5, 0x94BD), 0x1043)
    pool = parse_database(_language(texts)).sections[0]
    records, symbols = bytearray(), bytearray()
    for index, identifier in enumerate(identifiers):
        key = f"IDS_AUTHORED_DOOR_{index + 1}"
        encoded = key.encode("utf-16le")
        records.extend((encoded + b"\0\0").ljust(80, b"\0"))
        records.extend(bytes(80))
        records.extend(struct.pack("<I", index + 1))
        group = 20000 if identifier == 0x1043 else 4934
        symbols.extend(struct.pack("<IIH", group, identifier, len(encoded)))
        symbols.extend(encoded)
    return {
        "U_Example.ddb": _ddb(
            6, {0: (pool.count, pool.payload), 1: (len(identifiers), bytes(records))}
        ),
        "UtilityResID_NK.rsd": bytes(symbols),
    }


def create_text_examples() -> dict[str, bytes]:
    """Author-created Viewer/V files for local UI checks; no vendor content."""
    from scripts.demo import _ddb, _language
    from scripts.diagnostic_db import parse_database

    strings = [
        "Authored example: keep the vehicle stationary.",
        "Authored help: choose a value, then run the captured workflow.",
        "Authored prohibition: stop before disconnecting the session.",
        "Authored information: this example uses recorded responses.",
        "Authored comment: source text is preserved as Unicode. Клапан 日本語",
        "Authored active detail: the selected test controls the demo fan.",
        "Authored active detail: use the recorded workflow supplied with the example.",
        "Authored active detail: stop the test after observing the recorded result.",
    ]
    section = parse_database(_language(strings)).sections[0]
    language = _ddb(5, {0: (section.count, section.payload)})
    entries = [(index, index, 1) for index in range(1, 6)]
    entries.extend(((6, 2, 2), (7, 2, 3), (8, 2, 4)))
    entries.sort(key=lambda row: row[1])
    rows = b"".join(
        struct.pack("<IIHH", string_id, identifier, kind, 0)
        for string_id, identifier, kind in entries
    )
    return {
        "Viewer.ddb": _ddb(3, {2: (len(entries), rows)}),
        "V_Example.ddb": language,
    }


def create_active_text_examples() -> dict[str, bytes]:
    """Authored active workflows whose Init references select the text example."""
    import json

    from scripts.active_replay import create_active_examples
    from scripts.demo import _ddb

    files = create_active_examples()
    identities = {}
    for name, payload in tuple(files.items()):
        if not name.endswith("/DemoEngine.ddb"):
            continue
        database = parse_database(payload)
        sections = {
            key: (section.count, section.payload)
            for key, section in database.sections.items()
        }
        # Roles are caution/help/prohibition/info/comment; modern comment is
        # absent in the native Init producer and must not overwrite DWORD0.
        for slot, width, offsets in (
            (11, 92, (48, 40, 52, 44, 36)),
            (68, 64, (24, 16, 28, 20)),
            (71, 64, (20, 12, 24, 16)),
        ):
            count, body = sections[slot]
            rows = bytearray(body)
            for row in range(count):
                for identifier, offset in enumerate(offsets, 1):
                    struct.pack_into("<I", rows, row * width + offset, identifier)
            sections[slot] = (count, bytes(rows))
        updated = _ddb(2, sections)
        identities[database.sha256] = hashlib.sha256(updated).hexdigest()
        files[name] = updated
    for name, payload in tuple(files.items()):
        if not name.startswith("active-") or not name.endswith(".json"):
            continue
        document = json.loads(payload)
        document["context"]["ecu_sha256"] = identities[
            document["context"]["ecu_sha256"]
        ]
        files[name] = (json.dumps(document, indent=2) + "\n").encode()
    for region in ("JP", "EU", "NA"):
        for name, payload in create_text_examples().items():
            files[f"Techstream_DB_{region}/{name}"] = payload
    manifest = json.loads(files["demo-manifest.json"])
    manifest["files"] = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in files.items()
        if name != "demo-manifest.json"
    }
    files["demo-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    return files
