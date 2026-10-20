"""Offline workbench data, local selections and passive USB inventory."""

import csv
import io
import json
import os
import tempfile
from pathlib import Path

from scripts.pid_catalog import list_groups, show_group


def measurement_text(record: dict) -> tuple[str, str]:
    names = {
        "coolant_temperature": "Температура охлаждающей жидкости",
        "engine_speed": "Частота вращения двигателя",
        "vehicle_speed": "Скорость автомобиля",
        "throttle_position": "Положение дроссельной заслонки",
        "calculated_load": "Расчётная нагрузка",
        "intake_temperature": "Температура впускного воздуха",
        "mass_air_flow": "Массовый расход воздуха",
        "engine_runtime": "Время работы двигателя",
    }
    name: str = record["name"]
    title = names.get(name, name.replace("_", " "))
    number = record["value"]
    value = (
        f"{number:.2f}".rstrip("0").rstrip(".")
        if isinstance(number, float)
        else str(number)
    )
    unit = {"degC": "°C", "rpm": "об/мин"}.get(record["unit"], record["unit"])
    return title, f"{value} {unit}".strip()


def catalog_roots(root: Path) -> dict[str, Path]:
    application = (
        root.parent.parent
        if root.name == "PIDGroup"
        and root.parent.name
        in {"Techstream_Data_NA", "Techstream_Data_EU", "Techstream_Data_JP"}
        else root
    )
    regions = {
        code: application / f"Techstream_Data_{code}" / "PIDGroup"
        for code in ("NA", "EU", "JP")
        if (application / f"Techstream_Data_{code}" / "PIDGroup").is_dir()
    }
    return regions or {"custom": root}


class CatalogIndex:
    """Parse each group once; damaged groups remain visible as errors."""

    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        self.groups: dict[str, dict] = {}
        self.errors: dict[str, str] = {}
        self._searchable: list[tuple[dict[str, str], str]] = []
        for group in list_groups(self.root):
            try:
                content = show_group(self.root, group)
            except (OSError, ValueError) as exc:
                self.errors[group] = str(exc)
                continue
            self.groups[group] = content
            for record in content["records"]:
                item = {**record, "group": group, "sha256": content["sha256"]}
                self._searchable.append(
                    (
                        item,
                        f"{group} {record['name']} {record['short_name']} {record['unit']}".casefold(),
                    )
                )
        self.record_count = len(self._searchable)

    def search(self, query: str, group: str | None = None) -> list[dict[str, str]]:
        words = query.casefold().split()
        return [
            item
            for item, text in self._searchable
            if (group is None or item["group"] == group)
            and all(word in text for word in words)
        ]


def _validate_saved(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise ValueError("Saved groups must be an object keyed by source directory")  # noqa: TRY004 - Invalid JSON schema is a data error.
    for root, groups in value.items():
        if not isinstance(root, str) or not isinstance(groups, list):
            raise ValueError("Invalid saved group source")  # noqa: TRY004 - Invalid JSON schema is a data error.
        for group in groups:
            if (
                not isinstance(group, str)
                or not group
                or "\0" in group
                or Path(group).is_absolute()
                or ".." in Path(group).parts
                or Path(group).suffix.upper() != ".CT"
            ):
                raise ValueError("Invalid saved group path")
    return value


def load_saved(path: Path) -> dict[str, list[str]]:
    try:
        with path.open(encoding="utf-8") as source:
            text = source.read(1024 * 1024 + 1)
    except FileNotFoundError:
        return {}
    if len(text) > 1024 * 1024:
        raise ValueError("Saved groups file exceeds 1 MiB")
    return _validate_saved(json.loads(text))


def _atomic_text(path: Path, text: str, *, create_parent: bool = False) -> None:
    if create_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as target:
            temporary = Path(target.name)
            target.write(text)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_saved(path: Path, saved: dict[str, list[str]]) -> None:
    text = json.dumps(_validate_saved(saved), ensure_ascii=False, indent=2) + "\n"
    _atomic_text(path, text, create_parent=True)


def export_csv(path: Path, records: list[dict[str, str]]) -> None:
    """Atomic UTF-8 CSV; neutralize formula prefixes in spreadsheet cells."""
    output = io.StringIO(newline="")
    columns = [
        "group",
        "name",
        "short_name",
        "unit",
        "parameter_id",
        "unit_conversion_category",
        "saved_list_field",
        "metadata_hex",
        "sha256",
    ]
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for record in records:
        writer.writerow(
            {
                key: "'" + value
                if value.lstrip().startswith(("=", "+", "-", "@"))
                or value.startswith(("\t", "\r", "\n"))
                else value
                for key in columns
                for value in [record.get(key, "")]
            }
        )
    _atomic_text(path, "\ufeff" + output.getvalue())


def usb_devices(root: Path = Path("/sys/bus/usb/devices")) -> list[dict]:
    """Read sysfs descriptors only; never open a USB device node."""
    devices = []
    if not root.exists():
        return devices
    for entry in sorted(root.iterdir()):
        try:
            vendor = (entry / "idVendor").read_text().strip().lower()
            product = (entry / "idProduct").read_text().strip().lower()
        except (OSError, UnicodeError):
            continue
        description = {}
        for name in ("manufacturer", "product"):
            try:
                description[name] = (entry / name).read_text().strip()
            except (OSError, UnicodeError):
                description[name] = ""
        identity = f"{vendor}:{product}"
        model = {"18e1:0100": "MongoosePro MFC", "18e1:0104": "MongoosePro JLR"}.get(
            identity, ""
        )
        devices.append(
            {
                "id": identity,
                "port": entry.name,
                **description,
                "candidate": bool(model),
                "model": model,
            }
        )
    return devices
