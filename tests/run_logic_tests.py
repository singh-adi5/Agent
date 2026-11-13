#!/usr/bin/env python3
"""Run each detection's real KQL against sample events and check it fires correctly.

Unlike the parser check, this executes the query. It stands up a Microsoft Kusto
emulator, loads the sample events in tests/logic/<detection>.json as an inline
SecurityEvent table, runs the exact query from detections/<detection>/query.kql,
and asserts each case fires (returns rows) or stays silent (returns none).

Start the emulator first:
    docker run -d --name kustainer -p 8080:8080 -e ACCEPT_EULA=Y -m 4G \
        mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest

Then:
    python tests/run_logic_tests.py

Set KUSTO_URL to point at another engine. Exit code 0 when every case passes.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOGIC_DIR = ROOT / "tests" / "logic"
SCHEMA_FILE = ROOT / "scripts" / "securityevent.schema"
KUSTO_URL = os.environ.get("KUSTO_URL", "http://localhost:8080")


def load_schema() -> list[tuple[str, str]]:
    columns = []
    for line in SCHEMA_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            name, kind = (part.strip() for part in line.split(":"))
            columns.append((name, kind))
    return columns


def kql_literal(value, kind: str, now: datetime) -> str:
    """Render one cell as a KQL literal for a datatable."""
    if kind == "datetime":
        # Fixtures give TimeGenerated as whole minutes before now, so every run
        # places the events inside the query's relative time window.
        minutes = 0 if value is None else float(value)
        stamp = (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return f"datetime({stamp})"
    if kind == "int":
        return "int(null)" if value is None else f"int({int(value)})"
    if value is None:
        return '""'
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def build_csl(columns: list[tuple[str, str]], events: list[dict], query: str, now: datetime) -> str:
    header = ", ".join(f"{name}:{kind}" for name, kind in columns)
    rows = []
    for event in events:
        cells = [kql_literal(event.get(name), kind, now) for name, kind in columns]
        rows.append(", ".join(cells))
    body = ",\n".join(rows)
    table = f"let SecurityEvent = datatable({header})\n[\n{body}\n];\n"
    return table + query


def run_query(csl: str) -> int:
    """Return the row count of the query's first result table."""
    payload = json.dumps({"db": "NetDefaultDB", "csl": csl}).encode("utf-8")
    request = urllib.request.Request(
        f"{KUSTO_URL}/v1/rest/query",
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.loads(response.read().decode("utf-8"))
    for table in result.get("Tables", []):
        if table.get("TableName") == "Table_0":
            return len(table.get("Rows", []))
    return len(result["Tables"][0]["Rows"])


def main() -> int:
    columns = load_schema()
    now = datetime.now(timezone.utc)
    fixtures = sorted(LOGIC_DIR.glob("*.json"))
    if not fixtures:
        print(f"FAIL no fixtures found under {LOGIC_DIR}")
        return 1

    failures, total = 0, 0
    for fixture in fixtures:
        detection = fixture.stem
        query = (ROOT / "detections" / detection / "query.kql").read_text(encoding="utf-8")
        cases = json.loads(fixture.read_text(encoding="utf-8"))["cases"]
        print(f"# {detection}")
        for case in cases:
            total += 1
            expect_fire = case["expect"] == "fire"
            csl = build_csl(columns, case["events"], query, now)
            try:
                rows = run_query(csl)
            except (urllib.error.URLError, OSError) as exc:
                print(f"  ERROR {case['name']}: cannot reach the engine ({exc})")
                return 2
            fired = rows > 0
            ok = fired == expect_fire
            if not ok:
                failures += 1
            verb = "fired" if fired else "silent"
            want = "fire" if expect_fire else "silent"
            print(f"  {'PASS' if ok else 'FAIL'} [{want:6}] {case['name']} -> {verb} ({rows} rows)")

    print(f"{total - failures} of {total} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
