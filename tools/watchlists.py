"""Sentinel watchlists read by the detections with _GetWatchlist().

watchlists/watchlists.yaml lists each watchlist; its items are in a CSV file beside
it. The same definitions feed the ARM build, the linter, and the `_GetWatchlist`
stand-in used where the real Sentinel function does not exist (the Kusto emulator
and the offline parser check).
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path

from tools import catalog
from tools.kql import string_literal

INDEX_FILE = "watchlists.yaml"
INDEX_FIELDS = ("alias", "displayName", "description", "itemsSearchKey", "file")
PROVIDER = "/Microsoft.SecurityInsights"
ALIAS_REFERENCE = re.compile(r"""_GetWatchlist\(\s*["']([^"']+)["']\s*\)""")


@dataclass(frozen=True)
class Watchlist:
    alias: str
    display_name: str
    description: str
    search_key: str
    path: Path

    def read(self) -> tuple[list[str], list[dict[str, str]]]:
        """Header and rows of the CSV file."""
        text = self.path.read_text(encoding="utf-8")
        reader = csv.DictReader(io.StringIO(text))
        rows = [{k: (v or "").strip() for k, v in row.items()} for row in reader]
        return list(reader.fieldnames or []), rows

    def raw_content(self) -> str:
        return self.path.read_text(encoding="utf-8")


def watchlist_dir(root: Path = catalog.REPO_ROOT) -> Path:
    return root / "watchlists"


def load(root: Path = catalog.REPO_ROOT) -> list[Watchlist]:
    """Watchlists from the index. Raises on a malformed index; the linter reports why."""
    folder = watchlist_dir(root)
    index = folder / INDEX_FILE
    if not index.is_file():
        return []
    entries = catalog.load_yaml(index) or []
    return [
        Watchlist(
            alias=entry["alias"],
            display_name=entry["displayName"],
            description=entry["description"],
            search_key=entry["itemsSearchKey"],
            path=folder / entry["file"],
        )
        for entry in entries
    ]


def referenced_aliases(query: str) -> set[str]:
    return set(ALIAS_REFERENCE.findall(query))


def stub(watchlists: list[Watchlist], extra_items: list[dict] | None = None) -> str:
    """A `let _GetWatchlist = ...` statement serving the watchlist items inline.

    The real function returns, per alias, a SearchKey column plus the CSV columns.
    This stand-in returns the union of every watchlist's columns, which is why the
    detections read CSV columns through column_ifexists().

    extra_items are rows added for a single test case: {"alias": ..., <column>: ...}.
    """
    by_alias = {w.alias: w for w in watchlists}
    headers = {w.alias: w.read()[0] for w in watchlists}
    columns = sorted({c for header in headers.values() for c in header})

    rows: list[tuple[str, str, dict[str, str]]] = []
    for w in watchlists:
        for item in w.read()[1]:
            rows.append((w.alias, item.get(w.search_key, ""), item))
    for item in extra_items or []:
        w = by_alias[item["alias"]]
        values = {k: str(v) for k, v in item.items() if k != "alias"}
        rows.append((w.alias, values.get(w.search_key, ""), values))

    schema = ", ".join(
        ["WatchlistAlias:string", "SearchKey:string"] + [f"{c}:string" for c in columns]
    )
    lines = []
    for alias, key, values in rows:
        cells = [string_literal(alias), string_literal(key)]
        cells += [string_literal(values.get(c, "")) for c in columns]
        lines.append("        " + ", ".join(cells))
    body = ",\n".join(lines)
    return (
        "let _GetWatchlist = (watchlistAlias: string) {\n"
        f"    datatable({schema})\n"
        f"    [\n{body}\n    ]\n"
        "    | where WatchlistAlias == watchlistAlias\n"
        "};\n"
    )


def to_resource(watchlist: Watchlist) -> dict:
    """ARM resource for one watchlist, in the 2023-02-01 Microsoft.SecurityInsights schema."""
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/Watchlists",
        "apiVersion": "2023-02-01",
        "name": f"[concat(parameters('workspace'), '{PROVIDER}/{watchlist.alias}')]",
        "properties": {
            "displayName": watchlist.display_name,
            "description": watchlist.description,
            "provider": "Custom",
            "source": "Local file",
            "itemsSearchKey": watchlist.search_key,
            "contentType": "text/csv",
            "numberOfLinesToSkip": 0,
            "rawContent": watchlist.raw_content(),
        },
    }
