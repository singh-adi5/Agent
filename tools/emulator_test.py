"""Run every query against its test cases on a Kusto engine.

For each detection, the events in tests.json are loaded as an inline SecurityEvent
table and the query from analytic.yaml is run over them unchanged:

    fire    the rule must return at least one row
    silent  the rule must return no rows

The hunting query is then run over every 'fire' case and must return rows too.
It has no thresholds, so 'silent' cases do not apply to it.

Event fields are SecurityEvent columns, plus 'age_minutes': how long before the
test run the event happened. Columns an event leaves out are empty.

    make emulator          # start the Kusto emulator in Docker
    make emulator-test     # python -m tools.emulator_test --wait 120
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from tools import catalog

DEFAULT_URL = os.environ.get("KUSTO_URL", "http://localhost:8080")
DATABASE = "NetDefaultDB"


def kql_literal(value: object, kind: str, now: datetime) -> str:
    """Render one table cell as a KQL literal."""
    if kind == "datetime":
        minutes = 0.0 if value is None else float(value)
        stamp = (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return f"datetime({stamp})"
    if kind == "int":
        return "int(null)" if value is None else f"int({int(value)})"
    if value is None:
        return '""'
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def build_csl(columns: list[tuple[str, str]], events: list[dict], query: str, now: datetime) -> str:
    """Prefix the query with a `let SecurityEvent = datatable(...)` holding the events."""
    header = ", ".join(f"{name}:{kind}" for name, kind in columns)
    rows = []
    for event in events:
        values = dict(event)
        values["TimeGenerated"] = values.pop("age_minutes", 0)
        rows.append(", ".join(kql_literal(values.get(n), k, now) for n, k in columns))
    body = ",\n".join(rows)
    return f"let SecurityEvent = datatable({header})\n[\n{body}\n];\n{query}"


class Engine:
    def __init__(self, url: str) -> None:
        if urlparse(url).scheme not in ("http", "https"):
            raise ValueError(f"engine URL must be http or https: {url}")
        self.endpoint = url.rstrip("/") + "/v1/rest/query"

    def rows(self, csl: str) -> int:
        """Row count of the query's primary result."""
        payload = json.dumps({"db": DATABASE, "csl": csl}).encode("utf-8")
        # S310: the scheme is restricted to http and https in __init__.
        request = urllib.request.Request(  # noqa: S310
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            result = json.loads(response.read().decode("utf-8"))
        for table in result.get("Tables", []):
            if table.get("TableName") == "Table_0":
                return len(table.get("Rows", []))
        return len(result["Tables"][0]["Rows"])

    def wait(self, seconds: int) -> None:
        deadline = time.monotonic() + seconds
        while True:
            try:
                self.rows("print 1")
                return
            except (urllib.error.URLError, OSError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(3)


def run(engine: Engine) -> tuple[int, int]:
    columns = catalog.load_schema()
    now = datetime.now(UTC)
    passed = failed = 0

    for folder in catalog.detection_dirs():
        cases = catalog.load_cases(folder / catalog.TESTS)
        targets = [
            ("analytic", catalog.load_yaml(folder / catalog.ANALYTIC)["query"], cases),
            (
                "hunting",
                catalog.load_yaml(folder / catalog.HUNTING)["query"],
                [c for c in cases if c["expect"] == "fire"],
            ),
        ]
        print(folder.name)
        for kind, query, selected in targets:
            for case in selected:
                rows = engine.rows(build_csl(columns, case["events"], query, now))
                fired = rows > 0
                ok = fired == (case["expect"] == "fire")
                passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
                status = "ok  " if ok else "FAIL"
                plural = "" if rows == 1 else "s"
                print(f"  {status} {kind:8} {case['expect']:6} {case['name']} ({rows} row{plural})")
    return passed, failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_URL, help="Kusto engine URL (env KUSTO_URL)")
    parser.add_argument("--wait", type=int, default=0, help="seconds to wait for the engine")
    args = parser.parse_args(argv)

    engine = Engine(args.url)
    try:
        engine.wait(args.wait)
        passed, failed = run(engine)
    except (urllib.error.URLError, OSError) as exc:
        print(f"cannot reach the Kusto engine at {args.url}: {exc}", file=sys.stderr)
        return 2
    print(f"{passed} of {passed + failed} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
