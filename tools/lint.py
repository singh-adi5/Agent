"""Lint the detection content in detections/<name>/.

Checks structure and consistency only. Query syntax is checked by the Kusto
language service (tools/kql-parser) and query behaviour by the emulator tests
(tools/emulator_test.py).

    python -m tools.lint            # exit code 0 when everything passes
"""

from __future__ import annotations

import csv
import io
import re
import sys
import uuid
from datetime import date
from pathlib import Path

from tools import arm, catalog, watchlists
from tools.kql import output_columns, placeholders

ANALYTIC_FIELDS = (
    "id",
    "name",
    "description",
    "severity",
    "requiredDataConnectors",
    "queryFrequency",
    "queryPeriod",
    "triggerOperator",
    "triggerThreshold",
    "tactics",
    "relevantTechniques",
    "query",
    "entityMappings",
)
HUNTING_FIELDS = (
    "id",
    "name",
    "description",
    "requiredDataConnectors",
    "tactics",
    "relevantTechniques",
    "query",
)
SEVERITIES = {"Informational", "Low", "Medium", "High"}
TRIGGER_OPERATORS = {"gt", "lt", "eq", "ne"}
TACTICS = {
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
}
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
TIMESPAN = re.compile(r"^(\d+)([mhd])$")
MINUTES = {"m": 1, "h": 60, "d": 1440}
# Sentinel accepts 5 minutes to 14 days for both frequency and period.
MIN_MINUTES, MAX_MINUTES = 5, 14 * 1440
AGE_KEY = "age_minutes"


def to_minutes(value: object) -> int | None:
    match = TIMESPAN.match(str(value))
    if not match:
        return None
    return int(match.group(1)) * MINUTES[match.group(2)]


def _load_mapping(path: Path) -> tuple[dict | None, list[str]]:
    try:
        document = catalog.load_yaml(path)
    except Exception as exc:  # any parse failure is a lint failure, never a crash
        return None, [f"not valid YAML: {exc}"]
    if not isinstance(document, dict):
        return None, ["top level is not a mapping"]
    return document, []


def _check_common(document: dict, required: tuple[str, ...]) -> list[str]:
    """Checks shared by analytic rules and hunting queries."""
    errors = [f"missing field '{f}'" for f in required if document.get(f) in (None, "", [], {})]
    if errors:
        return errors

    try:
        uuid.UUID(str(document["id"]))
    except ValueError:
        errors.append("id is not a GUID")

    tactics = document["tactics"] if isinstance(document["tactics"], list) else []
    errors += [f"unknown tactic '{t}'" for t in tactics if t not in TACTICS]

    techniques = document["relevantTechniques"]
    if not isinstance(techniques, list) or not all(
        isinstance(t, str) and TECHNIQUE.match(t) for t in techniques
    ):
        errors.append("relevantTechniques must be a list of ATT&CK ids such as T1558.003")

    connectors = document["requiredDataConnectors"]
    if not isinstance(connectors, list) or not all(
        isinstance(c, dict) and c.get("connectorId") and c.get("dataTypes") for c in connectors
    ):
        errors.append("each requiredDataConnectors entry needs connectorId and dataTypes")

    query = document["query"]
    if not isinstance(query, str) or not query.strip():
        errors.append("query is empty")
    elif "SecurityEvent" not in query:
        errors.append("query does not read the SecurityEvent table")
    return errors


def lint_analytic(path: Path) -> list[str]:
    rule, errors = _load_mapping(path)
    if rule is None:
        return errors
    errors = _check_common(rule, ANALYTIC_FIELDS)
    if any(e.startswith("missing field") for e in errors):
        return errors

    if rule.get("kind") != "Scheduled":
        errors.append("kind must be 'Scheduled'")
    if rule["severity"] not in SEVERITIES:
        errors.append(f"severity must be one of {sorted(SEVERITIES)}")
    if rule["triggerOperator"] not in TRIGGER_OPERATORS:
        errors.append(f"triggerOperator must be one of {sorted(TRIGGER_OPERATORS)}")
    threshold = rule["triggerThreshold"]
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        errors.append("triggerThreshold must be an integer")

    frequency, period = to_minutes(rule["queryFrequency"]), to_minutes(rule["queryPeriod"])
    if frequency is None or period is None:
        errors.append("queryFrequency and queryPeriod must look like 30m, 1h or 1d")
    else:
        if not (MIN_MINUTES <= frequency <= MAX_MINUTES and MIN_MINUTES <= period <= MAX_MINUTES):
            errors.append("queryFrequency and queryPeriod must be between 5m and 14d")
        if period < frequency:
            errors.append("queryPeriod is shorter than queryFrequency, so events would be skipped")

    produced = output_columns(rule["query"]) if isinstance(rule["query"], str) else set()
    if not produced:
        errors.append("query must end with a project that names its output columns")

    mappings = rule["entityMappings"]
    if not isinstance(mappings, list):
        return errors + ["entityMappings must be a list"]
    for mapping in mappings:
        fields = mapping.get("fieldMappings") if isinstance(mapping, dict) else None
        if not isinstance(mapping, dict) or not mapping.get("entityType"):
            errors.append("each entityMappings entry needs an entityType")
            continue
        if not isinstance(fields, list) or not fields:
            errors.append(f"{mapping['entityType']} mapping needs a list of fieldMappings")
            continue
        for field in fields:
            column = field.get("columnName") if isinstance(field, dict) else None
            if not column or not field.get("identifier"):
                errors.append("each fieldMappings entry needs identifier and columnName")
            elif column not in produced:
                errors.append(f"entity column '{column}' is not an output column of the query")

    custom = rule.get("customDetails") or {}
    if not isinstance(custom, dict):
        errors.append("customDetails must map a name to a column")
    else:
        errors += [
            f"customDetails column '{c}' is not an output column of the query"
            for c in custom.values()
            if str(c) not in produced
        ]

    override = rule.get("alertDetailsOverride") or {}
    if not isinstance(override, dict):
        errors.append("alertDetailsOverride must be a mapping")
    else:
        for key, template in override.items():
            if not isinstance(template, str):
                errors.append(f"alertDetailsOverride.{key} must be a string")
                continue
            errors += [
                f"alertDetailsOverride.{key} uses '{c}', which is not an output column"
                for c in sorted(placeholders(template) - produced)
            ]
    return errors


def lint_hunting(path: Path) -> list[str]:
    hunt, errors = _load_mapping(path)
    if hunt is None:
        return errors
    return _check_common(hunt, HUNTING_FIELDS)


def lint_tests(
    path: Path,
    columns: set[str],
    watchlist_headers: dict[str, list[str]] | None = None,
    produced: set[str] | None = None,
) -> list[str]:
    """Fixture rules: a fire and a silent case, real column names, known watchlists,
    and assertions only on columns the analytic query outputs."""
    watchlist_headers = watchlist_headers or {}
    try:
        cases = catalog.load_cases(path)
    except Exception as exc:  # any parse failure is a lint failure, never a crash
        return [f"not valid test JSON: {exc}"]
    if not isinstance(cases, list) or not cases:
        return ["needs a non-empty 'cases' list"]

    errors = []
    expectations = set()
    for index, case in enumerate(cases):
        label = case.get("name", f"case {index}") if isinstance(case, dict) else f"case {index}"
        if not isinstance(case, dict) or case.get("expect") not in ("fire", "silent"):
            errors.append(f"{label}: expect must be 'fire' or 'silent'")
            continue
        expectations.add(case["expect"])
        events = case.get("events")
        if not isinstance(events, list) or not events:
            errors.append(f"{label}: needs a non-empty events list")
            continue
        for event in events:
            if not isinstance(event, dict):
                errors.append(f"{label}: each event must be an object")
                continue
            unknown = sorted(set(event) - columns - {AGE_KEY})
            if unknown:
                errors.append(f"{label}: unknown column(s) {', '.join(unknown)}")

        for item in case.get("watchlist", []):
            alias = item.get("alias") if isinstance(item, dict) else None
            if alias not in watchlist_headers:
                errors.append(f"{label}: unknown watchlist '{alias}'")
                continue
            extra = sorted(set(item) - {"alias"} - set(watchlist_headers[alias]))
            if extra:
                errors.append(f"{label}: {alias} has no column(s) {', '.join(extra)}")

        expected = case.get("assert")
        if expected is not None:
            if case["expect"] != "fire" or not isinstance(expected, dict) or not expected:
                errors.append(f"{label}: assert must be a non-empty object on a 'fire' case")
            elif produced is not None:
                missing = sorted(set(expected) - produced)
                if missing:
                    errors.append(f"{label}: assert uses non-output column(s) {', '.join(missing)}")
    errors += [
        f"needs at least one '{e}' case" for e in ("fire", "silent") if e not in expectations
    ]
    return errors


def lint_watchlists(root: Path, detection_names: set[str]) -> dict[str, list[str]]:
    """Watchlist index and CSV files. Returns problems per file."""
    folder = watchlists.watchlist_dir(root)
    index = folder / watchlists.INDEX_FILE
    label = str(index.relative_to(root))
    if not index.is_file():
        return {label: ["missing watchlist index"]}
    try:
        entries = catalog.load_yaml(index)
    except Exception as exc:  # any parse failure is a lint failure, never a crash
        return {label: [f"not valid YAML: {exc}"]}
    if not isinstance(entries, list) or not entries:
        return {label: ["must be a non-empty list of watchlists"]}

    results: dict[str, list[str]] = {label: []}
    aliases = set()
    for entry in entries:
        if not isinstance(entry, dict) or any(not entry.get(f) for f in watchlists.INDEX_FIELDS):
            results[label].append(f"each entry needs {', '.join(watchlists.INDEX_FIELDS)}")
            continue
        if not arm.ALIAS.match(str(entry["alias"])):
            results[label].append(f"alias '{entry['alias']}' must match {arm.ALIAS.pattern}")
        if entry["alias"] in aliases:
            results[label].append(f"alias '{entry['alias']}' is listed twice")
        aliases.add(entry["alias"])

        csv_path = folder / entry["file"]
        csv_label = str(csv_path.relative_to(root))
        if not csv_path.is_file():
            results[label].append(f"{entry['alias']}: file {entry['file']} not found")
            continue
        reader = csv.DictReader(io.StringIO(csv_path.read_text(encoding="utf-8")))
        rows = list(reader)
        header = reader.fieldnames or []
        errors = []
        key = entry["itemsSearchKey"]
        if key not in header:
            errors.append(f"itemsSearchKey '{key}' is not a column")
        for number, row in enumerate(rows, start=2):
            if not (row.get(key) or "").strip():
                errors.append(f"line {number}: empty {key}")
            detection = (row.get("Detection") or "").strip()
            if "Detection" in header and detection not in detection_names:
                errors.append(f"line {number}: unknown detection '{detection}'")
            expires = (row.get("ExpiresOn") or "").strip()
            if expires:
                try:
                    date.fromisoformat(expires)
                except ValueError:
                    errors.append(f"line {number}: ExpiresOn must be YYYY-MM-DD")
        results[csv_label] = errors
    return results


def lint_repository(root: Path = catalog.REPO_ROOT) -> dict[str, list[str]]:
    """Problems per file, relative to `root`. A file with an empty list passed."""
    columns = {name for name, _ in catalog.load_schema()}
    folders = catalog.detection_dirs(root)
    if not folders:
        return {"detections/": ["no detection folders found"]}

    results = lint_watchlists(root, {f.name for f in folders})
    try:
        headers = {w.alias: w.read()[0] for w in watchlists.load(root) if w.path.is_file()}
    except Exception:  # reported by lint_watchlists
        headers = {}
    seen_ids: dict[str, str] = {}

    for folder in folders:
        missing = [name for name in catalog.REQUIRED_FILES if not (folder / name).is_file()]
        if missing:
            results[str(folder.relative_to(root))] = [f"missing {name}" for name in missing]

        produced = None
        for filename, check in ((catalog.ANALYTIC, lint_analytic), (catalog.HUNTING, lint_hunting)):
            path = folder / filename
            if not path.is_file():
                continue
            label = str(path.relative_to(root))
            errors = check(path)
            document, _ = _load_mapping(path)
            if document:
                query = document.get("query") if isinstance(document.get("query"), str) else ""
                unknown = sorted(watchlists.referenced_aliases(query) - set(headers))
                errors += [f"query reads unknown watchlist '{a}'" for a in unknown]
                if filename == catalog.ANALYTIC:
                    produced = output_columns(query)
                content_id = str(document.get("id"))
                if content_id in seen_ids:
                    errors.append(f"id is also used by {seen_ids[content_id]}")
                seen_ids.setdefault(content_id, label)
            results[label] = errors

        tests = folder / catalog.TESTS
        if tests.is_file():
            results[str(tests.relative_to(root))] = lint_tests(tests, columns, headers, produced)
    return results


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else catalog.REPO_ROOT
    results = lint_repository(root)
    failed = 0
    for label, errors in results.items():
        if errors:
            failed += 1
            print(f"FAIL {label}")
            for error in errors:
                print(f"     {error}")
        else:
            print(f"ok   {label}")
    print(f"{len(results) - failed} of {len(results)} files passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
