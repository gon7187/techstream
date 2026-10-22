"""Bounded UtilityNeo XML execution with explicit host I/O and library bindings.

Only authored host code runs. Native resources may be decrypted by script_vm;
no vendor binary or transport is loaded by this module.
"""

from __future__ import annotations

import csv
import io
import json
import operator
import re
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable

from scripts.script_vm import MAX_SIZE, UtilityResource

Value = int | bytes
Library = Callable[[str, tuple[str, ...], dict[str, Value]], Value]

# Observed XML grammar, plus INITACTION present in the native parser table.
_ATTRIBUTES = {
    "UTILITY": set(),
    "VERSION": set(),
    "FUNCTION": set(),
    "NAME": set(),
    "FUNCID": set(),
    "STORAGE": set(),
    "DATA": {"DATAID", "LENGTH"},
    "BLOCK": {"ID", "TYPE", "ICON"},
    "TITLE": set(),
    "SCRN_FUNCID": set(),
    "AREA": {"ID", "TYPE"},
    "TEXT": set(),
    "RADIOTYPE": {"ID", "OUT", "DEFAULT"},
    "RADIO": {"ID"},
    "INITACTION": set(),
    "FASTACTION": set(),
    "DISPACTION": set(),
    "KEYSTATE": {"ID", "MODE"},
    "KEYTYPE": set(),
    "KEY": {"ID", "MODE"},
    "IF": {"COND"},
    "THEN": set(),
    "ELSE": set(),
    "ACTION": {"MODE", "NEXT"},
    "CALLFUNC": {"NAME", "OUT"},
    "CALC": {"OUT", "OPE"},
    "COMM": {"COMMID"},
    "EVENT": {"TYPE", "TIMEOUT", "MODE", "NEXT", "RETRY", "WAITTIME", "REPEAT"},
    "FRAME": set(),
    "AFTER": set(),
    "PROGRESS": {"PROGRESSTIME", "UPDATETIME"},
    "RECEIVE": {"OUT", "POS", "SIZE", "ENDIAN"},
    "LANGUAGE": set(),
}
_EXECUTABLE = {"IF", "CALC", "CALLFUNC", "ACTION", "RECEIVE", "KEYSTATE"}
_CHILDREN = {
    "UTILITY": {"VERSION", "FUNCTION", "LANGUAGE"},
    "FUNCTION": {"NAME", "FUNCID", "STORAGE", "BLOCK"},
    "STORAGE": {"DATA"},
    "BLOCK": {
        "TITLE",
        "SCRN_FUNCID",
        "AREA",
        "RADIOTYPE",
        "KEYTYPE",
        "COMM",
        "INITACTION",
        "FASTACTION",
        "DISPACTION",
        "PROGRESS",
    },
    "AREA": {"TEXT"},
    "RADIOTYPE": {"RADIO"},
    "RADIO": {"TEXT"},
    "KEYTYPE": {"KEY"},
    "KEY": _EXECUTABLE | {"TEXT"},
    "IF": _EXECUTABLE | {"THEN", "ELSE"},
    "THEN": _EXECUTABLE,
    "ELSE": _EXECUTABLE,
    "INITACTION": _EXECUTABLE,
    "FASTACTION": _EXECUTABLE,
    "DISPACTION": _EXECUTABLE,
    "PROGRESS": _EXECUTABLE,
    "AFTER": _EXECUTABLE,
    "COMM": {"EVENT"},
    "EVENT": {"FRAME", "AFTER"},
}
_REQUIRED = {
    "DATA": {"DATAID"},
    "BLOCK": {"ID"},
    "AREA": {"ID", "TYPE"},
    "RADIOTYPE": {"ID", "OUT"},
    "RADIO": {"ID"},
    "KEY": {"ID"},
    "KEYSTATE": {"ID", "MODE"},
    "IF": {"COND"},
    "ACTION": {"MODE", "NEXT"},
    "CALLFUNC": {"NAME", "OUT"},
    "CALC": {"OUT", "OPE"},
    "COMM": {"COMMID"},
    "EVENT": {"TYPE"},
    "PROGRESS": {"PROGRESSTIME", "UPDATETIME"},
    "RECEIVE": {"OUT", "POS", "SIZE"},
}
_OPERATORS = {
    "EQ": operator.eq,
    "NE": operator.ne,
    "GT": operator.gt,
    "GE": operator.ge,
    "LT": operator.lt,
    "LE": operator.le,
    "AND": operator.and_,
    "OR": operator.or_,
    "_PLUS": operator.add,
}


class UtilityRuntime:
    """Execute one utility using injected ECU, UI, timing and library callbacks.

    exchange(ecu, request) returns response bytes (b'' denotes no response).
    receive(ecu) continues a pending response without resending the request.
    library(name, raw_arguments, storage) returns CALLFUNC's integer status and
    may update declared storage for by-reference parameters. Quoting is removed;
    argument spelling and order are retained, including INT/BYTE references.
    dialog(screen) returns a key string or {'key': ..., 'values': {...}}.
    """

    def __init__(
        self,
        resource: UtilityResource,
        *,
        exchange: Callable[[str, bytes], bytes] | None = None,
        receive: Callable[[str], bytes] | None = None,
        library: Library | None = None,
        dialog: Callable[[dict], str | dict] | None = None,
        ecu: str = "utility",
        cancelled: Callable[[], bool] | None = None,
        wait: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        max_steps: int = 10000,
        max_bytes: int = MAX_SIZE,
        timeout: float = 300.0,
    ):
        for name, value, ceiling in (
            ("max_steps", max_steps, 1000000),
            ("max_bytes", max_bytes, MAX_SIZE),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"Invalid utility {name}")
        if isinstance(timeout, bool) or not 0 < timeout <= 3600:
            raise ValueError("Invalid utility timeout")
        self.resource, self.exchange, self.receive = resource, exchange, receive
        self.library, self.dialog, self.ecu = library, dialog, ecu
        self.cancelled, self.wait, self.clock = cancelled, wait, clock
        self.max_steps, self.max_bytes, self.timeout = max_steps, max_bytes, timeout
        self.storage: dict[str, Value] = {}
        self.widths: dict[str, int] = {}
        self.blocks: dict[str, ET.Element] = {}
        self.history: list[str] = []
        self.popups: list[str] = []
        self.trace: list[dict] = []
        self._trace_bytes = 0
        self.current = ""
        self.done = False
        self.steps = 0
        self.started = 0.0
        self.response = b""
        self.keys: dict[str, bool] = {}
        self.progress_time = 0
        self.block_instance = 0
        self.validate()

    def validate(self) -> None:
        root = self.resource.root
        if root.tag != "UTILITY":
            raise ValueError("Expected UTILITY XML root")
        # LANGUAGE is presentation-only, and language/key identifiers are open.
        pending = [(root, 0, False)]
        nodes = 0
        while pending:
            element, depth, language = pending.pop()
            nodes += 1
            if nodes > 100000:
                raise ValueError("Utility XML node budget exceeded")
            if depth > 128:
                raise ValueError("Utility XML nesting budget exceeded")
            if language or element.tag == "LANGUAGE":
                pending.extend((child, depth + 1, True) for child in element)
                continue
            allowed = _ATTRIBUTES.get(element.tag)
            if allowed is None or set(element.attrib) - allowed:
                raise ValueError(
                    f"Unsupported utility XML element/attributes: {element.tag}"
                )
            if _REQUIRED.get(element.tag, set()) - set(element.attrib):
                raise ValueError(f"Missing utility XML attributes: {element.tag}")
            if {child.tag for child in element} - _CHILDREN.get(element.tag, set()):
                raise ValueError(f"Unsupported utility XML children: {element.tag}")
            if element.tag in ("ACTION", "EVENT") and "MODE" in element.attrib:
                if element.get("MODE") not in ("BLOCK", "POPUP", "COMM"):
                    raise ValueError("Unsupported utility action mode")
                if "NEXT" not in element.attrib:
                    raise ValueError("Utility action requires NEXT")
            if element.tag == "EVENT" and element.get("TYPE") not in (
                "SEND",
                "SUCCESS",
                "NEGRETRY",
                "NEGREPEAT",
                "OTHER",
                "NORESP",
            ):
                raise ValueError("Unsupported utility communication event")
            if element.tag == "KEY" and element.get("MODE", "ENABLE") not in (
                "ENABLE",
                "DISABLED",
            ):
                raise ValueError("Unsupported utility key mode")
            if (
                element.tag == "COMM"
                and len(element.findall("EVENT[@TYPE='SEND']")) != 1
            ):
                raise ValueError("Utility COMM requires exactly one SEND event")
            if element.tag == "IF":
                then, otherwise = element.findall("THEN"), element.findall("ELSE")
                if (
                    len(then) > 1
                    or len(otherwise) > 1
                    or (otherwise and not then)
                    or (then and any(child.tag in _EXECUTABLE for child in element))
                ):
                    raise ValueError("Malformed utility IF branches")
            pending.extend((child, depth + 1, False) for child in element)
        if len(ET.tostring(root, encoding="utf-8")) > self.max_bytes:
            raise ValueError("Utility XML byte budget exceeded")
        identifiers = [f.findtext("FUNCID", "") for f in root.findall("FUNCTION")]
        if (
            not identifiers
            or any(not x for x in identifiers)
            or len(set(identifiers)) != len(identifiers)
        ):
            raise ValueError("Missing or duplicate utility function ID")

    def _check(self) -> None:
        if self.cancelled is not None and self.cancelled():
            raise InterruptedError("Utility execution cancelled")
        if self.clock() - self.started >= self.timeout:
            raise TimeoutError("Utility execution deadline exceeded")
        self.steps += 1
        if self.steps > self.max_steps:
            raise ValueError("Utility instruction budget exceeded")
        if len(self.history) + len(self.popups) > 4096:
            raise ValueError("Utility navigation stack budget exceeded")
        retained = len(self.response) + sum(
            len(v) if isinstance(v, bytes) else 4 for v in self.storage.values()
        )
        retained += self._trace_bytes
        if retained > self.max_bytes:
            raise ValueError("Utility aggregate byte budget exceeded")

    def _log(self, **event) -> None:
        size = len(json.dumps(event, separators=(",", ":")).encode())
        if size + self._trace_bytes > self.max_bytes:
            raise ValueError("Utility trace byte budget exceeded")
        self._trace_bytes += size
        self.trace.append(event)
        self._check()

    def _pause(self, milliseconds: int) -> None:
        if milliseconds < 0 or milliseconds / 1000 > self.timeout - (
            self.clock() - self.started
        ):
            raise TimeoutError("Utility wait exceeds execution deadline")
        self._check()
        self.wait(milliseconds / 1000)
        self._check()

    def _value(self, token: str) -> int:
        token = token.strip()
        if token in self.storage:
            value = self.storage[token]
            if isinstance(value, bytes):
                return int.from_bytes(value, "little")
            return value
        if re.fullmatch(r"\$[0-9a-fA-F]+", token):
            return int(token[1:], 16)
        if re.fullmatch(r"-?\d+", token):
            value = int(token)
            if not -2147483648 <= value <= 4294967295:
                raise ValueError("Utility integer outside 32-bit range")
            return value
        raise ValueError(f"Unknown utility value {token!r}")

    def _expression(self, text: str) -> int:
        tokens = text.split()
        if len(tokens) == 1:
            return self._value(tokens[0])
        if len(tokens) == 3 and tokens[1] in _OPERATORS:
            return int(
                _OPERATORS[tokens[1]](self._value(tokens[0]), self._value(tokens[2]))
            )
        raise ValueError(f"Unsupported utility expression {text!r}")

    def _store(self, key: str, value: Value) -> None:
        if key not in self.storage:
            raise ValueError(f"Undeclared utility storage {key!r}")
        width = self.widths.get(key)
        if width is not None:
            if type(value) is int:
                if value < 0 or value.bit_length() > 8 * width:
                    raise ValueError("Utility byte value outside declared width")
                value = value.to_bytes(width, "little")
            if type(value) is not bytes or len(value) != width:
                raise ValueError("Invalid utility byte storage width")
        elif type(value) is not int or not -2147483648 <= value <= 4294967295:
            raise ValueError("Invalid utility integer storage value")
        self.storage[key] = value

    def start(self, function_id: str) -> dict:
        function = next(
            (
                f
                for f in self.resource.root.findall("FUNCTION")
                if f.findtext("FUNCID") == function_id
            ),
            None,
        )
        if function is None:
            raise ValueError("Unknown utility function ID")
        self.storage, self.widths = {}, {}
        for item in function.findall("STORAGE/DATA"):
            key = item.attrib["DATAID"]
            if key in self.storage:
                raise ValueError("Duplicate utility storage")
            if key.startswith("BYTE"):
                width = int(item.get("LENGTH", "1"))
                if not 1 <= width <= self.max_bytes:
                    raise ValueError("Invalid utility storage length")
                retained = sum(
                    len(v) if isinstance(v, bytes) else 4 for v in self.storage.values()
                )
                if retained + width > self.max_bytes:
                    raise ValueError(
                        "Utility aggregate byte budget exceeded before storage allocation"
                    )
                self.widths[key] = width
                self.storage[key] = bytes(width)
            elif key.startswith("INT"):
                self.storage[key] = 0
            else:
                raise ValueError("Unsupported utility storage type")
        self.blocks = {}
        for block in function.findall("BLOCK"):
            key = block.attrib["ID"]
            if key in self.blocks:
                raise ValueError("Duplicate utility block ID")
            self.blocks[key] = block
        if not self.blocks:
            raise ValueError("Utility function has no blocks")
        self.history, self.popups, self.trace = [], [], []
        self.current = ""
        self._trace_bytes = 0
        self.steps, self.started = 0, self.clock()
        self.done, self.response = False, b""
        self._check()
        self._enter(next(iter(self.blocks)))
        return self.screen()

    def _commands(self, parent: ET.Element | None) -> tuple[str, str] | None:
        if parent is None:
            return None
        for element in parent:
            self._check()
            tag = element.tag
            transition = None
            if tag == "ACTION":
                return element.attrib["MODE"], element.attrib["NEXT"]
            if tag == "IF":
                truth = self._expression(element.attrib["COND"]) != 0
                then, otherwise = element.find("THEN"), element.find("ELSE")
                if then is not None:
                    transition = self._commands(then if truth else otherwise)
                elif truth:
                    transition = self._commands(element)
            elif tag == "CALC":
                self._store(
                    element.attrib["OUT"], self._expression(element.attrib["OPE"])
                )
            elif tag == "CALLFUNC":
                if self.library is None:
                    raise ValueError(
                        f"Unavailable utility library function {element.get('NAME')}"
                    )
                raw = (element.text or "").strip()
                args = (
                    tuple(next(csv.reader(io.StringIO(raw), strict=True)))
                    if raw
                    else ()
                )
                candidate = self.storage.copy()
                result = self.library(element.attrib["NAME"], args, candidate)
                self._check()
                if set(candidate) != set(self.storage):
                    raise ValueError("Utility library changed storage declarations")
                old = self.storage.copy()
                try:
                    for key, value in candidate.items():
                        self._store(key, value)
                    self._store(element.attrib["OUT"], result)
                except (TypeError, ValueError):
                    self.storage = old
                    raise
                self._log(kind="call", name=element.attrib["NAME"])
            elif tag == "RECEIVE":
                position, size = (
                    int(element.attrib["POS"]) - 1,
                    int(element.attrib["SIZE"]),
                )
                if position < 0 or size < 1 or position + size > len(self.response):
                    raise ValueError("Utility RECEIVE outside response")
                endian = element.get("ENDIAN", "BIG")
                if endian not in ("LITTLE", "BIG"):
                    raise ValueError("Unsupported utility RECEIVE endian")
                self._store(
                    element.attrib["OUT"],
                    int.from_bytes(
                        self.response[position : position + size],
                        "little" if endian == "LITTLE" else "big",
                    ),
                )
            elif tag == "KEYSTATE":
                if element.get("MODE") not in ("ENABLE", "DISABLE", "DISABLED"):
                    raise ValueError("Unsupported utility key state")
                key_id = element.attrib["ID"]
                if key_id != "0" and key_id not in self.keys:
                    raise ValueError("Unknown utility key state target")
                for key in self.keys if key_id == "0" else (key_id,):
                    self.keys[key] = element.get("MODE") == "ENABLE"
            elif tag == "TEXT":
                continue
            else:
                raise ValueError(f"Unsupported utility executable tag {tag}")
            if transition is not None:
                return transition
        return None

    def _enter(self, block_id: str, mode: str = "BLOCK") -> None:
        # Iterative transitions keep XML loops off the Python call stack.
        transition: tuple[str, str] | None = (mode, block_id)
        while transition is not None and not self.done:
            self._check()
            mode, target = transition
            if mode == "COMM":
                transition = self._communicate(target)
                continue
            if mode not in ("BLOCK", "POPUP"):
                raise ValueError(f"Unsupported utility action mode {mode}")
            if target == "END":
                self.done = True
                self._log(kind="end")
                return
            restoring = target in ("RETURN", "POPUP_OFF")
            if restoring:
                stack = self.history if target == "RETURN" else self.popups
                if not stack:
                    raise ValueError("Utility navigation stack underflow")
                target = stack.pop()
            elif self.current:
                if mode == "POPUP":
                    self.popups.append(self.current)
                else:
                    self.history.append(self.current)
            if target not in self.blocks:
                raise ValueError(f"Unknown utility block {target}")
            self.current = target
            self.block_instance += 1
            self.progress_time = 0
            block = self.blocks[target]
            for radio in block.findall("RADIOTYPE"):
                if radio.get("DEFAULT") is not None:
                    self._store(radio.attrib["OUT"], int(radio.attrib["DEFAULT"]))
            self.keys = {
                key.attrib["ID"]: key.get("MODE") != "DISABLED"
                for key in block.findall("KEYTYPE/KEY")
            }
            self._log(kind="block", id=target, mode=mode)
            transition = self._commands(block.find("INITACTION"))
            if transition:
                continue
            transition = self._commands(block.find("FASTACTION"))
            if transition:
                continue
            transition = self._commands(block.find("DISPACTION"))

    def _frame(self, text: str, *, pattern: bool = False) -> list[int | None]:
        tokens = [x.strip() for x in text.split(",") if x.strip()]
        result: list[int | None] = []
        for token in tokens:
            if token == "*" and pattern:
                result.append(None)
            elif isinstance(value := self.storage.get(token), bytes):
                result.extend(value)
            else:
                value = self._value(token)
                if not 0 <= value <= 255:
                    raise ValueError("Utility FRAME value outside byte range")
                result.append(value)
        if not result:
            raise ValueError("Empty utility FRAME")
        return result

    def _communicate(self, communication_id: str) -> tuple[str, str] | None:
        if self.exchange is None:
            raise ValueError("Utility exchange callback is unavailable")
        block = self.blocks[self.current]
        comm = next(
            (c for c in block.findall("COMM") if c.get("COMMID") == communication_id),
            None,
        )
        if comm is None:
            raise ValueError("Unknown utility communication ID")
        events = list(comm.findall("EVENT"))
        send = next((e for e in events if e.get("TYPE") == "SEND"), None)
        if send is None:
            raise ValueError("Utility COMM has no SEND event")
        request = bytes(self._frame(send.findtext("FRAME", "")))  # type: ignore[arg-type]
        counts: dict[str, int] = {}
        pending_since = self.clock()
        response: bytes | None = None
        while True:
            self._check()
            if response is None:
                sent_at = self.clock()
                try:
                    response = self.exchange(self.ecu, request)
                except TimeoutError:
                    response = b""
                timeout_ms = int(send.get("TIMEOUT", "0"))
                if timeout_ms < 0:
                    raise ValueError("Invalid utility send timeout")
                if timeout_ms and (self.clock() - sent_at) * 1000 >= timeout_ms:
                    response = b""
            if type(response) is not bytes or len(response) > self.max_bytes:
                raise ValueError("Invalid utility exchange response")
            self.response = response
            self._log(kind="exchange", request=request.hex(), response=response.hex())
            chosen = None
            for event in events:
                kind = event.get("TYPE")
                if kind not in (
                    "SEND",
                    "SUCCESS",
                    "NEGRETRY",
                    "NEGREPEAT",
                    "OTHER",
                    "NORESP",
                ):
                    raise ValueError("Unsupported utility communication event")
                if kind == "SEND":
                    continue
                if kind == "NORESP":
                    matches = not response
                else:
                    frame = self._frame(event.findtext("FRAME", ""), pattern=True)
                    matches = (
                        bool(response)
                        and len(response) >= len(frame)
                        and all(
                            value is None or value == response[i]
                            for i, value in enumerate(frame)
                        )
                    )
                if matches:
                    chosen = event
                    break
            if chosen is None:
                raise ValueError("No matching utility communication event")
            kind = chosen.attrib["TYPE"]
            counts[kind] = counts.get(kind, 0) + 1
            self._log(
                kind="comm_event",
                communication=communication_id,
                type=kind,
                attempt=counts[kind],
            )
            retry = int(chosen.get("RETRY", "0"))
            if retry < 0:
                raise ValueError("Invalid utility retry count")
            if kind == "NEGREPEAT":
                repeat = int(chosen.get("REPEAT", "0"))
                elapsed = (self.clock() - pending_since) * 1000
                limit = int(chosen.get("TIMEOUT", "0"))
                again = (repeat > 0 and counts[kind] <= repeat) or (
                    limit > 0 and elapsed < limit
                )
                if again:
                    if self.receive is None:
                        raise ValueError(
                            "Utility pending response requires receive callback"
                        )
                    response = self.receive(self.ecu)
                    continue
            elif counts[kind] <= retry:
                response = None
                continue
            self._pause(int(chosen.get("WAITTIME", "0")))
            transition = self._commands(chosen.find("AFTER"))
            if transition:
                return transition
            if "MODE" in chosen.attrib and "NEXT" in chosen.attrib:
                return chosen.attrib["MODE"], chosen.attrib["NEXT"]
            return None

    def screen(self) -> dict:
        block = self.blocks.get(self.current)
        if block is None:
            return {
                "done": self.done,
                "block": None,
                "block_instance": None,
                "progress_elapsed_ms": self.progress_time,
            }
        return {
            "done": self.done,
            "block": self.current,
            "block_instance": None if self.done else self.block_instance,
            "progress_elapsed_ms": self.progress_time,
            "type": block.get("TYPE", ""),
            "icon": block.get("ICON", ""),
            "title": block.findtext("TITLE", ""),
            "function": block.findtext("SCRN_FUNCID", ""),
            "areas": [
                {"id": a.get("ID"), "text": a.findtext("TEXT", "")}
                for a in block.findall("AREA")
            ],
            "keys": [
                {
                    "id": k.get("ID"),
                    "enabled": self.keys.get(k.get("ID", ""), False),
                    "text": k.findtext("TEXT", ""),
                }
                for k in block.findall("KEYTYPE/KEY")
            ],
            "radios": [
                {
                    "out": r.get("OUT"),
                    "default": r.get("DEFAULT"),
                    "value": self.storage.get(r.get("OUT", "")),
                    "choices": [c.get("ID") for c in r.findall("RADIO")],
                    "options": [
                        {"id": c.get("ID"), "text": c.findtext("TEXT", "")}
                        for c in r.findall("RADIO")
                    ],
                }
                for r in block.findall("RADIOTYPE")
            ],
            "progress": dict(progress.attrib)
            if (progress := block.find("PROGRESS")) is not None
            else None,
        }

    def key(self, key_id: str, values: dict[str, Value] | None = None) -> dict:
        self._check()
        if self.done:
            raise ValueError("Utility already ended")
        if not self.keys.get(key_id, False):
            raise ValueError("Unknown or disabled utility key")
        self._select(values)
        block = self.blocks[self.current]
        key = next(k for k in block.findall("KEYTYPE/KEY") if k.get("ID") == key_id)
        transition = self._commands(key)
        if transition:
            self._transition(transition)
        return self.screen()

    def _select(self, values: dict[str, Value] | None) -> None:
        block = self.blocks[self.current]
        allowed = {
            radio.get("OUT"): {int(c.attrib["ID"]) for c in radio.findall("RADIO")}
            for radio in block.findall("RADIOTYPE")
        }
        if values is not None and not isinstance(values, dict):
            raise ValueError("Utility radio values must be a mapping")
        for name, value in (values or {}).items():
            if (
                type(value) is not int
                or name not in allowed
                or value not in allowed[name]
            ):
                raise ValueError("Invalid utility radio selection")
        for name, value in (values or {}).items():
            self._store(name, value)

    def display(self, values: dict[str, Value] | None = None) -> dict:
        """Submit native display/selection event and execute DISPACTION."""
        self._check()
        if self.done:
            raise ValueError("Utility already ended")
        self._select(values)
        transition = self._commands(self.blocks[self.current].find("DISPACTION"))
        if transition:
            self._transition(transition)
        return self.screen()

    def _transition(self, transition: tuple[str, str]) -> None:
        mode, target = transition
        self._enter(target, mode)

    def progress(self, elapsed_ms: int) -> dict:
        self._check()
        if type(elapsed_ms) is not int or elapsed_ms < self.progress_time:
            raise ValueError("Utility progress clock must be monotonic")
        progress = self.blocks[self.current].find("PROGRESS")
        if progress is None:
            raise ValueError("Utility block has no progress event")
        interval = int(progress.attrib["UPDATETIME"])
        if interval <= 0 or int(progress.attrib["PROGRESSTIME"]) <= 0:
            raise ValueError("Invalid utility progress timing")
        if elapsed_ms < self.progress_time + interval:
            return self.screen()
        self.progress_time = elapsed_ms
        transition = self._commands(progress)
        if transition:
            self._transition(transition)
        return self.screen()

    def run(self, function_id: str) -> dict:
        self.start(function_id)
        while not self.done:
            self._check()
            if self.dialog is None:
                raise ValueError("Utility dialog callback is unavailable")
            selection = self.dialog(self.screen())
            self._check()
            if isinstance(selection, str):
                self.key(selection)
            elif isinstance(selection, dict) and "key" in selection:
                self.key(selection["key"], selection.get("values"))
            elif isinstance(selection, dict) and set(selection) == {"elapsed_ms"}:
                self.progress(selection["elapsed_ms"])
            elif isinstance(selection, dict) and set(selection) == {"display"}:
                self.display(selection["display"])
            else:
                raise ValueError("Invalid utility dialog event")
        return self.report()

    def report(self) -> dict:
        return {
            "status": "completed" if self.done else "waiting",
            "block": self.current,
            "storage": {
                key: value.hex() if isinstance(value, bytes) else value
                for key, value in self.storage.items()
            },
            "steps": self.steps,
            "events": self.trace.copy(),
            "provenance": "recovered-xml-injected-host",
            "physical": "PHYSICAL_UNCONFIRMED",
        }


class NativeUtilityRuntime:
    """Recovered TY18 DoorClear/DCM45 controllers with the XML host interface.

    The procedure and its imports are fixed by the shipped caller, never supplied
    as an operation plan. Unrecovered native procedures fail closed.
    """

    def __init__(self, libraries, *, cancelled=None, clock=time.monotonic):
        from scripts.script_libraries import NativeProcedureLibraries

        if not isinstance(libraries, NativeProcedureLibraries):
            raise TypeError("Source-bound native procedure libraries required")
        if libraries.caller_sha256 != (
            "ecba533aeaa2ec2a014fa59a113d025a8efe90338767c2786b8a5a891ca0f599"
        ):
            raise LookupError("Native procedure controller unavailable for caller")
        self.libraries = libraries
        self.cancelled = cancelled or (lambda: False)
        self.clock = clock
        self.deadline = 0.0
        self.current = 0
        self.done = False
        self.status = "idle"
        self.result = None
        self.trace = []
        self.elapsed = 0
        self._started = False
        self._opened = False
        self._progress_open = False
        self._owns_worker = False
        self._dispatch_pending = False
        self._saved_result = None
        self.function_id = 0
        self.receiver = bytearray(4)

    @property
    def utility_group(self) -> int:
        return 0x1352 if self.function_id == 0x13723 else 0x1346

    def _call(self, iat_rva: int) -> int:
        result = self.libraries.invoke_iat(iat_rva)
        if type(result) is not int:
            raise ValueError("Native procedure requires an integer wrapper result")
        self.trace.append({"iat_rva": iat_rva, "result": result})
        return result

    def _close_progress(self) -> None:
        if self._progress_open:
            self.trace.append({"event": "close_progress", "timer_id": 0xFA00})
            self._progress_open = False

    def open(self, function_id: int) -> dict:
        """Present the native entry screen before its source Next callback."""
        if type(function_id) is not int or function_id not in (0x1381D, 0x13723):
            raise LookupError("Native utility procedure has no recovered controller")
        if self._opened or self._started:
            raise ValueError("Native utility runtime already opened")
        if function_id == 0x13723:
            # Full entry uses NativeDCM45Runtime and its CGW prelude.
            raise LookupError("Use NativeDCM45Runtime for full CGW entry")
        if self.cancelled():
            raise InterruptedError("Native utility cancelled before opening")
        self._opened = True
        self.current = self.function_id = function_id
        self.status = "ready"
        self.deadline = self.clock() + 300
        return self.screen()

    def start(self, function_id: int) -> dict:
        if type(function_id) is not int or function_id not in (0x1381D, 0x13723):
            raise LookupError("Native utility procedure has no recovered controller")
        if self._started:
            raise ValueError("Native utility runtime already started")
        if self._opened and self.function_id != function_id:
            raise ValueError("Native utility selection changed after opening")
        self._started = True
        self.deadline = self.clock() + 300
        self.current = function_id
        self.function_id = function_id
        self.elapsed = 0
        self.status = "waiting"
        if self.cancelled():
            self.status, self.done = "cancelled", True
            raise InterruptedError("Native utility cancelled before start")
        try:
            if function_id == 0x13723:
                # TY18 332b0 -> 33180: the same this+e8 storage survives the worker.
                self.result = self.libraries.call_method(0x33180, self.receiver)
                if type(self.result) is not int:
                    raise ValueError(
                        "Native procedure requires an integer wrapper result"
                    )
                self.trace.append({"method_rva": 0x33180, "result": self.result})
                self.trace.append({"controller_state": 1000})
            else:
                self.result = self._call(0xC1898)
            if self.result == 15:
                self._progress_open = self._owns_worker = True
            else:
                if function_id == 0x13723:
                    self._complete()
                else:
                    self.status = "error"
            return self.screen()
        except BaseException:
            self.status = "fault"
            raise

    def progress(self, elapsed_ms: int) -> dict:
        if not (self._progress_open or self._dispatch_pending) or self.done:
            raise ValueError("Native utility has no active progress dialog")
        if type(elapsed_ms) is not int or elapsed_ms < self.elapsed:
            raise ValueError("Monotonic native progress milliseconds required")
        if self.cancelled():
            self.cancel()
            raise InterruptedError("Native utility cancelled")
        if (
            self.clock() > self.deadline
            or elapsed_ms > 300000
            or len(self.trace) >= 10000
        ):
            self.cancel()
            raise TimeoutError("Native utility host deadline or event budget exceeded")
        if elapsed_ms - self.elapsed < 1000:
            return self.screen()
        self.elapsed = elapsed_ms
        try:
            if self._dispatch_pending:
                self._complete()
                return self.screen()
            self.result = self._call(0xC1958)
        except BaseException:
            if self.libraries.engine.worker._thread is None:
                self._owns_worker = False
            self._close_progress()
            self.status = "fault"
            raise
        if self.result != 15:
            self._owns_worker = False
            self._complete()
        return self.screen()

    def _poll_completion_dispatch(self) -> bool:
        # TY3b040 leaves native state2 pending while another worker is busy.
        self._close_progress()
        if not self._dispatch_pending:
            self._saved_result = self.result
            self.trace.append({"controller_state": 2, "stored_result": self.result})
        try:
            status = self._call(0xC1958)
        except BaseException:
            self.status = "fault"
            raise
        if status == 15:
            self._dispatch_pending = True
            self.status = "waiting"
            return False
        self._dispatch_pending = False
        self.result = self._saved_result
        return True

    def _complete(self) -> None:
        self._close_progress()
        if self.function_id == 0x13723 and not self._poll_completion_dispatch():
            return
        if self.result == 0:
            self.current = 0x13724 if self.function_id == 0x13723 else 0x1381E
            self.status = "completed"
        elif self.result == (2005 if self.function_id == 0x13723 else 1000):
            self.status = "native-result"
        else:
            self.status = "error"

    def key(self, key_id: str, values=None) -> dict:
        if key_id == "next" and values is None and self.status == "ready":
            self.trace.append({"event": "next", "callback_rva": 0x38150})
            return self.start(self.function_id)
        if (
            key_id != "acknowledge"
            or values is not None
            or self.status not in ("completed", "error", "native-result")
        ):
            raise ValueError("Native utility event is unavailable for current screen")
        if self.status == "error" and self.function_id == 0x1381D:
            # 38160/381bf show the error and return to the same initial screen.
            self._started, self._opened = False, True
            self.status, self.result = "ready", None
            self.trace.append({"event": "return_to_initial_screen"})
            return self.screen()
        self.done = True
        self.trace.append({"event": "close_procedure"})
        return self.screen()

    def cancel(self) -> dict:
        # Host policy: cooperatively join owned work; never fake native termination.
        if not (self._started or self._opened) or self.done:
            raise ValueError("Native utility is not active")
        from scripts.toyota_session import Cancelled

        try:
            if self._owns_worker:
                self.libraries.engine.worker.stop()
        except (Cancelled, InterruptedError):
            if self.libraries.engine.worker._thread is not None:
                self.status = "cleanup-failed"
                raise
        except BaseException:
            self.status = "cleanup-failed"
            raise
        self._owns_worker = False
        self._dispatch_pending = False
        self._close_progress()
        self.done, self.status = True, "cancelled"
        return self.screen()

    def screen(self) -> dict:
        result = {"block": str(self.current), "status": self.status, "keys": []}
        dcm = self.function_id == 0x13723
        if self.status == "ready":
            result.update(title_id=0x94B5, message_id=0x94B8, keys=[{"id": "next"}])
        elif self._dispatch_pending and not self.done:
            result.update(
                progress={"PROGRESSTIME": 10000, "UPDATETIME": 1000},
                native_progress_open=False,
                host_completion_timer=True,
            )
            if dcm:
                result.update(title_id=0x948A, message_id=0x948D)
        elif self._progress_open:
            result.update(
                title_id=0x948B if dcm else 0x94B6,
                message_id=0x9490 if dcm else 0x94BA,
                progress={"PROGRESSTIME": 10000, "UPDATETIME": 1000},
            )
        elif self.status in ("error", "native-result"):
            result.update(
                title_id=(0x948C if dcm else 0x94B7)
                if self.status == "native-result"
                else 0x104A,
                message_id=(0x9492 if dcm else 0x94BC)
                if self.status == "native-result"
                else 0x104B,
            )
        elif dcm and self.status == "completed":
            result.update(
                title_id=0x948A, message_id=0x948E, output=str(self.receiver[0])
            )
        if not self.done and self.status in ("completed", "error", "native-result"):
            result["keys"] = [{"id": "acknowledge"}]
        return result

    def report(self) -> dict:
        return {
            "status": self.status,
            "done": self.done,
            "block": self.current,
            "result": self.result,
            "utility_group": self.utility_group,
            "events": self.trace.copy(),
            "dispatch_pending": self._dispatch_pending,
            "provenance": "recovered-native-procedure-injected-host",
            "caller_sha256": self.libraries.caller_sha256,
            "engine_sha256": self.libraries.engine.context.module_sha256,
            "physical": "PHYSICAL_UNCONFIRMED",
        }


class _NativeTYCGWRuntime(NativeUtilityRuntime):
    """Shared TY18 parent4fcc0/security3aef0 virtual controller flow."""

    def _void_call(self, iat_rva: int) -> None:
        value = self.libraries.invoke_iat(iat_rva)
        self.trace.append({"iat_rva": iat_rva, "result": value})

    def _begin_security(self, callback_rva: int) -> dict:
        if self.cancelled():
            self.done, self.status = True, "cancelled"
            raise InterruptedError("Native utility cancelled before start")
        self.trace.append({"event": "next", "callback_rva": callback_rva})
        self._started = True
        self.phase, self.status = "security", "waiting"
        self.elapsed = 0
        self.doip = self.libraries.engine.context.broker(112) == 20
        try:
            if self.doip:
                self._void_call(0xC194C)
            self.result = self._call(0xC1964)
            if self.result == 15:
                self._progress_open = self._owns_worker = True
            else:
                self.status = "error"
        except BaseException:
            self.status = "fault"
            raise
        return self.screen()

    def key(self, key_id: str, values=None) -> dict:
        if self.phase == "security" and values is None:
            if self.status == "security-choice":
                if key_id == "retry":
                    # Shared virtual+180 is the source no-op for these controllers.
                    self.status, self.phase = "ready", "conditions"
                    return self.screen()
                if key_id != "close":
                    raise ValueError("Native security confirmation event unavailable")
                self.done = True
                self.trace.append({"event": "close_procedure"})
                return self.screen()
            if key_id == "acknowledge" and self.status in ("error", "security-error"):
                self.done = True
                self.trace.append({"event": "close_procedure"})
                return self.screen()
        return super().key(key_id, values)

    def _complete(self) -> None:
        if self.phase != "security":
            raise ValueError("Shared native security completion outside its phase")
        if self.doip:
            self._void_call(0xC1988)
        self._close_progress()
        if self.result == 0:
            self._security_succeeded()
        elif self.result in (10002, 10003, 10004):
            self.status = "security-error"
        elif self.result in (10005, 10006, 10007):
            self.status = "security-choice"
        else:
            self.status = "error"

    def _security_succeeded(self) -> None:
        raise LookupError("Native source virtual+174 controller unavailable")

    def screen(self) -> dict:
        screen = super().screen()
        if self.phase == "security" and self._progress_open:
            screen.update(title_id=0x10B7, message_id=0x10BA)
        elif self.status == "security-error":
            screen.update(
                title_id=0x10B6,
                message_id=0x10B9,
                keys=[] if self.done else [{"id": "acknowledge", "text_id": 0x10B5}],
            )
        elif self.status == "security-choice":
            screen.update(
                title_id=0x10B6,
                message_id=0x10B8,
                keys=[]
                if self.done
                else [
                    {"id": "retry", "text_id": 0x1044},
                    {"id": "close", "text_id": 0x1046},
                ],
            )
        return screen

    def report(self) -> dict:
        return {**super().report(), "phase": self.phase, "doip": self.doip}


class NativeDCM45Runtime(_NativeTYCGWRuntime):
    """TY18 full DCM45 entry, including its shared CGW security controller."""

    def start(self, function_id: int) -> dict:
        return self.open(function_id)

    def open(self, function_id: int) -> dict:
        if type(function_id) is not int or function_id != 0x13723:
            raise LookupError("Native DCM45 entry unavailable")
        if self._opened or self._started:
            raise ValueError("Native utility runtime already opened")
        if self.cancelled():
            raise InterruptedError("Native utility cancelled before opening")
        self._opened = True
        self.current = self.function_id = function_id
        self.phase, self.status = "conditions", "ready"
        self.doip = False
        self.deadline = self.clock() + 300
        return self.screen()

    def key(self, key_id: str, values=None) -> dict:
        if values is not None:
            raise ValueError("DCM45 has no editable input")
        if self.status == "ready" and key_id == "next":
            return self._begin_security(0x32DC0)
        return super().key(key_id, values)

    def _security_succeeded(self) -> None:
        self.phase = "business"
        self._started = False
        NativeUtilityRuntime.start(self, 0x13723)

    def _complete(self) -> None:
        if self.phase == "security":
            super()._complete()
            return
        if not self._poll_completion_dispatch():
            return
        if self.doip:
            self._void_call(0xC1988)
        if self.result == 0:
            self.current, self.status = 0x13724, "completed"
        elif self.result == 2005:
            self.status = "native-result"
        else:
            self.status = "error"

    def screen(self) -> dict:
        screen = super().screen()
        if self.status == "ready":
            screen.update(title_id=0x948A, message_id=0x948D)
        return screen


class NativeBSMRuntime(_NativeTYCGWRuntime):
    """TY18 BSM27/28 probe, conditional CGW, and action1 controllers."""

    def start(self, function_id: int) -> dict:
        return self.open(function_id)

    @property
    def utility_group(self):
        return 0x134A + self.variant

    def open(self, function_id):
        if type(function_id) is not int or function_id not in (0x137B8, 0x137EA):
            raise LookupError("BSM source entry unavailable")
        if self._opened or self._started:
            raise ValueError("Native utility runtime already opened")
        if self.cancelled():
            raise InterruptedError("Native utility cancelled before opening")
        self.variant = int(function_id == 0x137EA)
        self._opened = True
        self.current = self.function_id = function_id
        self.receiver = bytearray(8)
        self.phase = "probe"
        self.doip = False
        return self._launch(0)

    def _flag(self):
        return int.from_bytes(self.receiver[4:8], "little")

    def _launch(self, action):
        self._started = True
        self.elapsed = 0
        self.deadline = self.clock() + 300
        self.status = "waiting"
        method = (0x37390, 0x37A00)[self.variant]
        try:
            self.result = self.libraries.call_method(method, self.receiver, (action,))
            if type(self.result) is not int:
                raise ValueError("Native scalar wrapper result required")
            self.trace.append(
                {"method_rva": method, "action": action, "result": self.result}
            )
            if self.result == 15:
                self._progress_open = self._owns_worker = True
            elif self.phase == "write" and not self._flag():
                self._complete()
            else:
                self.status = "error"
        except BaseException:
            self.status = "fault"
            raise
        return self.screen()

    def key(self, key_id, values=None):
        if values is not None:
            raise ValueError("BSM has no editable input")
        if self.status == "ready" and key_id == "next":
            if self.cancelled():
                self.done, self.status = True, "cancelled"
                raise InterruptedError("Native utility cancelled before start")
            if self._flag():
                self.phase = "write"
                return self._launch(1)
            return self._begin_security(0x37600 + self.variant * 0x670)
        if self.status == "native-warning":
            if key_id == "close":
                self.trace.append({"event": "modal_result", "result": 200})
                self.done = True
            elif key_id == "continue":
                self.trace.append({"event": "modal_result", "result": 100})
                self.status = "ready"
            else:
                raise ValueError("Native BSM warning event unavailable")
            return self.screen()
        if self.status == "error" and self.phase == "write" and key_id == "acknowledge":
            self.status = "ready"
            return self.screen()
        return super().key(key_id, values)

    def _security_succeeded(self):
        self.phase = "write"
        self._launch(1)

    def _complete(self):
        if self.phase == "security":
            super()._complete()
            return
        self._close_progress()
        if self.phase == "probe":
            if self.result == 0:
                self.current, self.status = self.function_id + 1, "ready"
            else:
                self.status = "error"
            return
        if not self._flag():
            if not self._poll_completion_dispatch():
                return
            if self.doip:
                self._void_call(0xC1988)
        if self.result == 0:
            self.current, self.status = self.function_id + 4, "completed"
        elif self._flag() or self.result == 2000:
            self.status = "native-warning"
        else:
            self.status = "error"

    def screen(self):
        screen = super().screen()
        offset = self.variant * 8
        if self.phase != "security":
            screen["title_id"] = 0x9090 + offset
            if self._progress_open:
                screen.update(title_id=0x9091 + offset, message_id=0x9095 + offset)
            elif self._dispatch_pending:
                screen.update(message_id=0x9093 + offset)
            elif self.status == "ready":
                screen.update(message_id=0x9093 + offset, keys=[{"id": "next"}])
            elif self.status == "completed":
                screen.update(message_id=0x9094 + offset)
            elif self.status == "error":
                screen.update(title_id=0x104A, message_id=0x104B)
            elif self.status == "native-warning":
                screen.update(
                    title_id=0x9092 + offset,
                    message_id=0x9097 + offset,
                    keys=[
                        {"id": "continue", "text_id": 0x103F},
                        {"id": "close", "text_id": 0x1040},
                    ],
                )
        if self.done:
            screen["keys"] = []
        return screen

    def report(self):
        return {
            **super().report(),
            "bsm_probe_flag": self._flag(),
            "receiver_dwords": [
                int.from_bytes(self.receiver[i : i + 4], "little") for i in (0, 4)
            ],
        }


class NativeEFI61Runtime(NativeUtilityRuntime):
    """TY18 support -> conditions -> supported selections -> write controller."""

    @property
    def utility_group(self) -> int:
        return 0x1334

    def start(self, function_id: int) -> dict:
        return self.open(function_id)

    def open(self, function_id: int) -> dict:
        if type(function_id) is not int or function_id != 0x13308:
            raise LookupError("Native EFI61 entry unavailable")
        if self._opened or self._started:
            raise ValueError("Native utility runtime already opened")
        if self.cancelled():
            raise InterruptedError("Native utility cancelled before opening")
        self._opened = True
        self.function_id = self.current = function_id
        # Parent1fde0 puts its first screen at+100: exactly24 bytes at+e8.
        self.receiver = bytearray(24)
        self.phase = "support"
        return self._launch(0x1FFE0)

    def _launch(self, method_rva: int) -> dict:
        self._started = True
        self.elapsed = 0
        self.deadline = self.clock() + 300
        self.status = "waiting"
        try:
            self.result = self.libraries.call_method(method_rva, self.receiver)
            if type(self.result) is not int:
                raise ValueError("Native procedure requires an integer wrapper result")
            self.trace.append({"method_rva": method_rva, "result": self.result})
            if self.result == 15:
                self._progress_open = self._owns_worker = True
            else:
                # 200a9/20380 reject every non15 immediate wrapper result.
                self.status = "error"
        except BaseException:
            self.status = "fault"
            raise
        return self.screen()

    def _complete(self) -> None:
        self._close_progress()
        if self.result:
            self.status = "error"
        elif self.phase == "support":
            self.current, self.status = 0x13309, "ready"
        else:
            self.current, self.status = 0x1330C, "completed"

    def _dword(self, offset: int) -> int:
        return int.from_bytes(self.receiver[offset : offset + 4], "little")

    def key(self, key_id: str, values=None) -> dict:
        if key_id == "next" and self.status == "ready" and values is None:
            # 20200 clears selections;203d0 projects only supported list rows.
            self.receiver[16:24] = bytes(8)
            for offset in (0, 4):
                self.receiver[8 + offset : 12 + offset] = int(
                    self._dword(offset) != 0
                ).to_bytes(4, "little")
            self.current, self.status = 0x1330D, "selection"
            self.trace.append({"event": "next", "callback_rva": 0x20200})
            return self.screen()
        if key_id == "next" and self.status == "selection":
            if type(values) is not dict or set(values) != {"selected"}:
                raise ValueError("Native EFI61 selected list required")
            selected = values["selected"]
            if (
                type(selected) is not list
                or not 1 <= len(selected) <= 2
                or any(
                    type(index) is not int or index not in (0, 1) for index in selected
                )
                or len(set(selected)) != len(selected)
                or any(not self._dword(8 + 4 * index) for index in selected)
            ):
                raise ValueError("Native EFI61 selection unavailable")
            # 204b0 toggles the corresponding flags; Next20370 consumes them.
            for index in (0, 1):
                self.receiver[16 + 4 * index : 20 + 4 * index] = int(
                    index in selected
                ).to_bytes(4, "little")
            self.phase = "write"
            self.trace.append({"event": "next", "callback_rva": 0x20370})
            return self._launch(0x1FFF0)
        if key_id == "acknowledge" and self.status == "error" and values is None:
            if self.phase == "support":
                self.done = True
                self.trace.append({"event": "close_procedure"})
            else:
                self.current, self.status = 0x13309, "ready"
                self.trace.append({"event": "return_to_conditions"})
            return self.screen()
        return super().key(key_id, values)

    def screen(self) -> dict:
        screen = {
            "block": str(self.current),
            "status": self.status,
            "title_id": 0x9AE3,
            "keys": [],
        }
        if self._progress_open:
            screen.update(
                title_id=0x9AE4,
                message_id=0x9AEB,
                progress={"PROGRESSTIME": 10000, "UPDATETIME": 1000},
            )
        elif self.status == "ready":
            screen.update(message_id=0x9AE6, keys=[{"id": "next"}])
        elif self.status == "selection":
            screen.update(
                message_id=0x9AE8,
                keys=[{"id": "next", "enabled": False}],
                requires_selection=True,
                choices=[
                    {
                        "id": index,
                        "text_id": 0x9AE9 + index,
                        "selected": bool(self._dword(16 + 4 * index)),
                    }
                    for index in (0, 1)
                    if self._dword(8 + 4 * index)
                ],
            )
        elif self.status == "completed":
            screen.update(message_id=0x9AE7, keys=[{"id": "acknowledge"}])
        elif self.status == "error":
            screen.update(
                title_id=0x104A, message_id=0x104B, keys=[{"id": "acknowledge"}]
            )
        if self.done:
            screen["keys"] = []
        return screen

    def report(self) -> dict:
        return {
            **super().report(),
            "phase": getattr(self, "phase", None),
            "receiver_dwords": [
                self._dword(offset) for offset in range(0, len(self.receiver), 4)
            ],
        }


class NativeUtilityRecording:
    """Bounded raw DRIVER/OS chronology, never a utility-operation provider."""

    def __init__(self, raw: bytes, caller_sha256: str, engine_sha256: str):
        import hashlib
        from functools import partial

        from scripts.native_replay import _object
        from scripts.programming_replay import ProgrammingTrace
        from scripts.utility_ex import _DRIVER_SLOTS, _SIS_DRIVER_SLOTS, uint32

        if type(raw) is not bytes or not 0 < len(raw) <= MAX_SIZE:
            raise ValueError("Bounded native utility recording bytes required")
        try:
            doc = json.loads(raw, object_pairs_hook=_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ValueError("Malformed native utility recording JSON") from error
        if (
            type(doc) is not dict
            or set(doc) - {"broker_data"}
            != {
                "schema",
                "source",
                "caller_sha256",
                "engine_sha256",
                "broker",
                "events",
            }
            or doc["schema"] != "techstream-native-utility-v1"
        ):
            raise ValueError("Exact native utility recording schema required")
        if doc["source"] not in ("authored_synthetic", "recorded_unverified"):
            raise ValueError("Explicit native utility recording provenance required")
        if (doc["caller_sha256"], doc["engine_sha256"]) != (
            caller_sha256,
            engine_sha256,
        ):
            raise ValueError("Recording does not match selected native source pair")
        broker = doc["broker"]
        if type(broker) is not dict or len(broker) > 64:
            raise ValueError("Bounded explicit native broker snapshot required")
        self.broker = {}
        for key, value in broker.items():
            if type(key) is not str or re.fullmatch(r"0|[1-9][0-9]{0,9}", key) is None:
                raise ValueError("Canonical decimal native broker keys required")
            self.broker[uint32(int(key))] = uint32(value)
        data = doc.get("broker_data", {})
        if type(data) is not dict or len(data) > 64:
            raise ValueError("Bounded explicit broker byte snapshot required")
        self.data = {}
        for key, value in data.items():
            if type(key) is not str or re.fullmatch(r"0|[1-9][0-9]{0,9}", key) is None:
                raise ValueError("Canonical decimal native broker data keys required")
            if (
                type(value) is not str
                or len(value) % 2
                or re.fullmatch(r"[0-9a-fA-F]*", value) is None
            ):
                raise ValueError("Strict hexadecimal native broker bytes required")
            self.data[uint32(int(key))] = bytes.fromhex(value)
        self.trace = ProgrammingTrace.validate(doc["events"])
        if any(row["kind"] != "action" for row in self.trace.rows):
            raise ValueError("Only individual DRIVER and wait primitives admitted")
        names = set(_DRIVER_SLOTS.values()) | set(_SIS_DRIVER_SLOTS.values())
        if any(
            row["request"].get("operation") not in names | {"wait"}
            for row in self.trace.rows
        ):
            raise ValueError("Unknown or business-level native recording operation")
        if sum(row["elapsed_ms"] for row in self.trace.rows) > 300000:
            raise ValueError("Native recording exceeds host deadline")
        self.source = doc["source"]
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.driver_exports = {
            name: partial(self.driver, name) for name in _DRIVER_SLOTS.values()
        }
        self.sis_driver_exports = {
            name: partial(self.driver, name) for name in _SIS_DRIVER_SLOTS.values()
        }

    def get_parameter(self, key: int) -> int:
        if key not in self.broker:
            raise LookupError(f"Native broker key {key} absent from recording")
        return self.broker[key]

    def get_data_size(self, key: int) -> int:
        return len(self.get_data(key))

    def get_data(self, key: int) -> bytes:
        if key not in self.data:
            raise LookupError("Native broker data absent from recording")
        return self.data[key]

    def set_parameter(self, key: int, value: int) -> int:
        raise LookupError("Native recording has no parameter-write producer")

    def write_parameters(self) -> int:
        raise LookupError("Native recording has no parameter-write producer")

    def ticks(self) -> int:
        return int(self.trace.clock() * 1000) & 0xFFFFFFFF

    def sleep(self, milliseconds: int) -> None:
        result = self.trace.consume(
            "action", {"operation": "wait", "milliseconds": milliseconds}
        )
        if result is not None:
            raise ValueError("Recorded OS wait must have a void result")

    def driver(self, name: str, *arguments: object):
        from scripts.j2534_2026 import PrimitiveResult
        from scripts.programming_replay import _driver_value2026, _native_request
        from scripts.utility_ex import uint32

        actual = _native_request(
            [bytes(arg) if type(arg) is bytearray else arg for arg in arguments]
        )
        result = self.trace.consume("action", {"operation": name, "arguments": actual})
        if (
            type(result) is not dict
            or set(result) != {"status", "outputs"}
            or type(result["outputs"]) is not dict
        ):
            raise ValueError(
                "Recorded raw DRIVER status and positional outputs required"
            )
        status = uint32(result["status"])
        writes = []
        for index, value in result["outputs"].items():
            if (
                type(index) is not str
                or re.fullmatch(r"0|[1-9][0-9]*", index) is None
                or int(index) >= len(arguments)
            ):
                raise ValueError("Invalid recorded DRIVER output index")
            target = arguments[int(index)]
            value = _driver_value2026(value)
            if (
                type(target) is bytearray
                and type(value) is bytes
                and len(target) == len(value)
                or type(target) is list
                and type(value) is list
                and len(value) <= 8
            ):
                writes.append((target, value))
            else:
                raise ValueError("Recorded DRIVER output type or capacity mismatch")
        for target, value in writes:
            target[:] = value
        return PrimitiveResult(status)

    def assert_complete(self) -> None:
        if self.trace.position != len(self.trace.rows):
            raise ValueError("Native utility has unconsumed recorded primitives")

    def report(self) -> dict:
        return {
            "source": self.source,
            "sha256": self.sha256,
            "consumed": self.trace.position,
            "total": len(self.trace.rows),
        }


def open_native_utility(
    caller_path, engine_path, recording_path, *, cancelled=None, function_id=0x1381D
):
    """Build the real native controller over raw replay; unported lowers still fail."""
    import hashlib

    from scripts.local_files import read_regular
    from scripts.script_libraries import NativeProcedureLibraries
    from scripts.utility_ex import UtilityExContext, UtilityExEngine

    if type(function_id) is not int or function_id not in (
        0x1381D,
        0x13723,
        0x13308,
        0x137B8,
        0x137EA,
    ):
        raise LookupError("Native utility procedure has no recovered controller")
    caller = read_regular(caller_path, limit=MAX_SIZE)
    module = read_regular(engine_path, limit=MAX_SIZE)
    recording = NativeUtilityRecording(
        read_regular(recording_path, limit=MAX_SIZE),
        hashlib.sha256(caller).hexdigest(),
        hashlib.sha256(module).hexdigest(),
    )
    context = UtilityExContext(
        module,
        recording,
        None,
        None,
        driver_exports=recording.driver_exports,
        sis_driver_exports=recording.sis_driver_exports,
    )
    controller = {
        0x13308: NativeEFI61Runtime,
        0x13723: NativeDCM45Runtime,
        0x137B8: NativeBSMRuntime,
        0x137EA: NativeBSMRuntime,
    }.get(function_id, NativeUtilityRuntime)
    runtime = controller(
        NativeProcedureLibraries(caller, UtilityExEngine(context)), cancelled=cancelled
    )
    return runtime, recording


def native_utility_screen(runtime: NativeUtilityRuntime, texts) -> dict:
    """Adapt the selected native IDs to the existing host dialog contract."""
    from scripts.text_resources import UtilityTextResources

    if (
        not isinstance(texts, UtilityTextResources)
        or texts.utility_group != runtime.utility_group
    ):
        raise ValueError("Source-selected native utility language group required")
    screen = runtime.screen()
    dcm = runtime.function_id == 0x13723
    references = [texts.resolve(screen.get("title_id", 0x948A if dcm else 0x94B5))]
    if "message_id" in screen:
        references.append(texts.resolve(screen["message_id"]))
    elif runtime.status == "completed":
        references.append(texts.resolve(0x94B9))
    key_references = [
        texts.resolve(
            key.get(
                "text_id",
                0x102F if runtime.status in ("ready", "selection") else 0x1043,
            )
        )
        for key in screen["keys"]
    ]
    references.extend(key_references)
    checkboxes = []
    for choice in screen.get("choices", []):
        entry = texts.resolve(choice["text_id"])
        references.append(entry)
        checkboxes.append(
            {
                "id": choice["id"],
                "text": entry["text"],
                "selected": choice["selected"],
                "enabled": True,
            }
        )
    if any(row["status"] != "resolved" for row in references):
        raise LookupError("Native utility source resource text is unavailable")
    return {
        **screen,
        "done": runtime.done,
        "block_instance": (
            f"{runtime.current}:{runtime.status}:{getattr(runtime, 'phase', '')}:"
            f"{int(runtime._dispatch_pending)}"
        ),
        "title": references[0]["text"],
        "areas": (
            [{"id": "message", "text": references[1]["text"]}]
            if len(references) > 1
            else []
        )
        + (
            [{"id": "native_output", "text": screen["output"]}]
            if "output" in screen
            else []
        ),
        "keys": [
            {
                "id": key["id"],
                "text": entry["text"],
                "enabled": key.get("enabled", True),
            }
            for key, entry in zip(screen["keys"], key_references, strict=True)
        ],
        "radios": [],
        "checkboxes": checkboxes,
        "progress": screen.get("progress"),
        "progress_elapsed_ms": runtime.elapsed,
        "deadline_monotonic": runtime.deadline,
        "resources": references,
        "presentation_policy": "host-native-result-acknowledge",
        "output": screen.get("output"),
    }


def replay_native_utility(
    caller_path,
    engine_path,
    recording_path,
    language_path,
    symbols_path,
    *,
    dialog,
    cancelled=None,
    function_id=0x1381D,
) -> dict:
    """Normal source-selected native replay; no caller-authored operation plan."""
    from scripts.text_resources import UtilityTextResources

    if type(function_id) is not int or function_id not in (
        0x1381D,
        0x13723,
        0x13308,
        0x137B8,
        0x137EA,
    ):
        raise LookupError("Native utility procedure has no recovered controller")
    group = {
        0x1381D: 0x1346,
        0x13723: 0x1352,
        0x13308: 0x1334,
        0x137B8: 0x134A,
        0x137EA: 0x134B,
    }[function_id]
    texts = UtilityTextResources.load(
        language_path, symbols_path, utility_group=group, cancelled=cancelled
    )
    # Resolve all possible controller result paths before starting native work.
    resources = []
    identifiers = {
        0x1352: (
            0x948A,
            0x948B,
            0x948C,
            0x948D,
            0x948E,
            0x9490,
            0x9492,
            0x102F,
            0x10B5,
            0x10B6,
            0x10B7,
            0x10B8,
            0x10B9,
            0x10BA,
            0x1044,
            0x1046,
        ),
        0x1346: (0x94B5, 0x94B6, 0x94B7, 0x94B8, 0x94B9, 0x94BA, 0x94BC, 0x102F),
        0x1334: (*range(0x9AE3, 0x9AED), 0x102F),
        0x134A: (
            *range(0x9090, 0x9098),
            0x103F,
            0x1040,
            0x102F,
            *range(0x10B5, 0x10BB),
            0x1044,
            0x1046,
        ),
        0x134B: (
            *range(0x9098, 0x90A0),
            0x103F,
            0x1040,
            0x102F,
            *range(0x10B5, 0x10BB),
            0x1044,
            0x1046,
        ),
    }[group]
    for identifier in (*identifiers, 0x104A, 0x104B, 0x1043):
        entry = texts.resolve(identifier)
        if entry["status"] != "resolved":
            raise LookupError("Native utility source resource text is unavailable")
        resources.append(entry)
    runtime, recording = open_native_utility(
        caller_path,
        engine_path,
        recording_path,
        cancelled=cancelled,
        function_id=function_id,
    )
    try:
        runtime.open(function_id)
        while not runtime.done:
            if runtime.cancelled():
                runtime.cancel()
                raise InterruptedError("Native utility cancelled")
            event = dialog(native_utility_screen(runtime, texts))
            if type(event) is dict and set(event) == {"elapsed_ms"}:
                runtime.progress(event["elapsed_ms"])
            elif (
                type(event) is dict
                and set(event) <= {"key", "values"}
                and "key" in event
                and (event.get("values") is None or type(event.get("values")) is dict)
            ):
                runtime.key(event["key"], event.get("values") or None)
            elif type(event) is str:
                runtime.key(event)
            else:
                raise ValueError("Invalid native utility host dialog event")
        recording.assert_complete()
    except BaseException as error:
        if runtime._owns_worker and runtime.libraries.engine.worker._thread is not None:
            try:
                runtime.cancel()
            except BaseException as cleanup:  # noqa: BLE001 - preserve the primary fault
                error.add_note(f"Native utility cleanup also failed: {cleanup}")
        raise
    return {
        **runtime.report(),
        "recording": recording.report(),
        "resources": resources,
        "text_sources": {
            "language_sha256": texts.source_sha256,
            "symbols_sha256": texts.symbols_sha256,
            "utility_group": group,
        },
    }
