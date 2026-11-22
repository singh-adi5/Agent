"""Load detection content from detections/<name>/.

Each detection folder holds:

    analytic.yaml  Sentinel scheduled analytics rule
    hunting.yaml   Sentinel hunting query
    tests.json     emulator test cases
    README.md      technique, logic, tuning and response notes

Run as a module to print every query as JSON, for the Kusto parser check:

    python -m tools.catalog | node tools/kql-parser/check.js
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_FILE = Path(__file__).resolve().parent / "securityevent.schema"

ANALYTIC = "analytic.yaml"
HUNTING = "hunting.yaml"
TESTS = "tests.json"
README = "README.md"
REQUIRED_FILES = (ANALYTIC, HUNTING, TESTS, README)


def detection_dirs(root: Path = REPO_ROOT) -> list[Path]:
    base = root / "detections"
    if not base.is_dir():
        return []
    return sorted(path for path in base.iterdir() if path.is_dir())


def load_yaml(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_cases(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def load_schema(path: Path = SCHEMA_FILE) -> list[tuple[str, str]]:
    """Columns of the SecurityEvent table as (name, type), in file order."""
    columns = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            name, kind = (part.strip() for part in line.split(":", 1))
            columns.append((name, kind))
    return columns


def queries(root: Path = REPO_ROOT) -> list[dict[str, str]]:
    """Every analytic and hunting query that loads, labelled by its file path."""
    found = []
    for folder in detection_dirs(root):
        for filename in (ANALYTIC, HUNTING):
            path = folder / filename
            if not path.is_file():
                continue
            document = load_yaml(path)
            if isinstance(document, dict) and isinstance(document.get("query"), str):
                found.append({"label": str(path.relative_to(root)), "query": document["query"]})
    return found


if __name__ == "__main__":
    json.dump(queries(), sys.stdout)
