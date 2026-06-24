from __future__ import annotations

import csv
from pathlib import Path

from .models import MGARecord


REQUIRED_COLUMNS = {"mga_name", "url"}
OPTIONAL_COLUMNS = {"program_name", "carrier_of_record", "notes"}


def load_records(path: str | Path) -> list[MGARecord]:
    input_path = Path(path)
    text = input_path.read_text(encoding="utf-8-sig")
    if "|" in text and "," not in text.splitlines()[0]:
        return parse_text_records(text)
    return load_csv_records(input_path)


def load_csv_records(path: str | Path) -> list[MGARecord]:
    records: list[MGARecord] = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return records
        lower_map = {name.lower().strip(): name for name in reader.fieldnames}
        if "mga_name" not in lower_map:
            raise ValueError("Input CSV must include mga_name")
        for row in reader:
            normalized = {
                key: (row.get(original) or "").strip()
                for key, original in lower_map.items()
            }
            records.append(
                MGARecord(
                    mga_name=normalized.get("mga_name", ""),
                    url=normalized.get("url") or None,
                    program_name=normalized.get("program_name") or None,
                    carrier_of_record=normalized.get("carrier_of_record") or None,
                    notes=normalized.get("notes") or None,
                )
            )
    return records


def parse_text_records(text: str) -> list[MGARecord]:
    records: list[MGARecord] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "|" not in stripped:
            records.append(MGARecord(mga_name=stripped, url=None))
            continue
        name, url = [part.strip() for part in stripped.split("|", 1)]
        records.append(MGARecord(mga_name=name, url=url or None))
    return records
