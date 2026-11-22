"""Run every query against its test cases on a Kusto engine.

For each detection, the events in tests.json are loaded as an inline SecurityEvent
table and the query from analytic.yaml is run over them unchanged:

    fire    the rule must return at least one row
    silent  the rule must return no rows

A 'fire' case may also carry 'assert': column values that at least one returned
row must have, so the test checks what the rule reports, not only that it fired.

The hunting query is then run over every 'fire' case and must return rows too.
It has no thresholds, so 'silent' cases and assertions do not apply to it.

Event fields are SecurityEvent columns, plus 'age_minutes': how long before the
test run the event happened. Columns an event leaves out are empty.

_GetWatchlist() is a Sentinel function the emulator does not have, so each query
runs behind a stand-in serving the items in watchlists/, plus any 'watchlist' rows
the case adds.

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

from tools import catalog, watchlists

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


def build_csl(
    columns: list[tuple[str, str]], events: list[dict], query: str, now: datetime, prefix: str = ""
) -> str:
    """Prefix the query with a `let SecurityEvent = datatable(...)` holding the events."""
    header = ", ".join(f"{name}:{kind}" for name, kind in columns)
    rows = []
    for event in events:
        values = dict(event)
        values["TimeGenerated"] = values.pop("age_minutes", 0)
        rows.append(", ".join(kql_literal(values.get(n), k, now) for n, k in columns))
    body = ",\n".join(rows)
    return f"{prefix}let SecurityEvent = datatable({header})\n[\n{body}\n];\n{query}"


class Engine:
    def __init__(self, url: str) -> None:
        if urlparse(url).scheme not in ("http", "https"):
            raise ValueError(f"engine URL must be http or https: {url}")
        self.endpoint = url.rstrip("/") + "/v1/rest/query"

    def rows(self, csl: str) -> int:
        """Row count of the query's primary result."""
        return len(self.query(csl)[1])

    def query(self, csl: str) -> tuple[list[str], list[list]]:
        """Column names and rows of the query's primary result."""
        payload = json.dumps({"db": DATABASE, "csl": csl}).encode("utf-8")
        # S310: the scheme is restricted to http and https in __init__.
        request = urllib.request.Request(  # noqa: S310
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            result = json.loads(response.read().decode("utf-8"))
        tables = result.get("Tables", [])
        table = next((t for t in tables if t.get("TableName") == "Table_0"), tables[0])
        return [c["ColumnName"] for c in table.get("Columns", [])], table.get("Rows", [])

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


def matches(columns: list[str], rows: list[list], expected: dict) -> bool:
    """True when at least one row has every expected column value."""
    for row in rows:
        values = dict(zip(columns, row, strict=False))
        if all(str(values.get(k)) == str(v) for k, v in expected.items()):
            return True
    return False


def run(engine: Engine) -> tuple[int, int]:
    columns = catalog.load_schema()
    lists = watchlists.load()
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
                prefix = watchlists.stub(lists, case.get("watchlist"))
                csl = build_csl(columns, case["events"], query, now, prefix)
                names, rows = engine.query(csl)
                ok = (len(rows) > 0) == (case["expect"] == "fire")
                note = f"{len(rows)} row{'' if len(rows) == 1 else 's'}"
                if ok and kind == "analytic" and case.get("assert"):
                    ok = matches(names, rows, case["assert"])
                    note += ", values match" if ok else f", no row has {case['assert']}"
                passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
                status = "ok  " if ok else "FAIL"
                print(f"  {status} {kind:8} {case['expect']:6} {case['name']} ({note})")
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
