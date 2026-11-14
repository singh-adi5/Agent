#!/usr/bin/env python3
"""Validate every Sentinel analytics rule in detections/*/rule.yaml and hunting query in hunting/*.yaml.

Checks structure only. It does not run a query against a workspace.
Exit code 0 when every rule passes, 1 otherwise.
"""
from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path

import yaml

REQUIRED_FIELDS = (
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
SEVERITIES = {"Informational", "Low", "Medium", "High"}
TRIGGER_OPERATORS = {"gt", "lt", "eq", "ne"}
TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
}
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
TIMESPAN = re.compile(r"^(\d+)([mhd])$")
MINUTES = {"m": 1, "h": 60, "d": 1440}
HEADER_KEYS = ("// Name:", "// Purpose:", "// Data source:", "// ATT&CK:", "// Fires when:")
# Sentinel limits: frequency 5 minutes to 14 days, period 5 minutes to 14 days.
MIN_MINUTES, MAX_MINUTES = 5, 14 * 1440


def to_minutes(value: object) -> int | None:
    match = TIMESPAN.match(str(value))
    if not match:
        return None
    return int(match.group(1)) * MINUTES[match.group(2)]


def split_top_level(text: str, separator: str) -> list[str]:
    """Split on `separator`, ignoring any inside (), [], or quotes."""
    parts, depth, quote, start = [], 0, "", 0
    for i, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def output_columns(query: str) -> set[str]:
    """Columns the final `project` emits: aliases and bare column names only.

    An unaliased expression such as `pack(...)` emits no name we can verify, so it
    is ignored rather than counted by the identifiers inside it. Comments and the
    `let` statements before the main pipeline are stripped first.
    """
    code = "\n".join(line for line in query.splitlines() if not line.lstrip().startswith("//"))
    pipeline = split_top_level(code, ";")[-1]
    segments = split_top_level(pipeline, "|")
    project = None
    for segment in segments:
        stripped = segment.strip()
        if stripped.startswith(("project ", "project-reorder ", "project\n", "project-reorder\n")):
            project = stripped.split(None, 1)[1]
    if project is None:
        return set()

    columns = set()
    for term in split_top_level(project, ","):
        term = term.strip()
        if not term:
            continue
        head = split_top_level(term, "=")[0].strip()  # the alias, or the term itself
        if IDENTIFIER.match(head):
            columns.add(head)
    return columns


def normalise(query: str) -> str:
    return "\n".join(line.rstrip() for line in query.strip().splitlines())


def validate_rule(rule_path: Path) -> list[str]:
    """Return a list of problems. An empty list means the rule passed."""
    try:
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"not valid YAML: {exc}"]
    if not isinstance(rule, dict):
        return ["top level of the file is not a mapping"]

    errors = [f"missing required field '{f}'" for f in REQUIRED_FIELDS if rule.get(f) in (None, "", [], {})]
    if errors:
        return errors

    try:
        uuid.UUID(str(rule["id"]))
    except ValueError:
        errors.append("id is not a GUID")
    if rule.get("kind") != "Scheduled":
        errors.append("kind must be 'Scheduled'")
    if rule["severity"] not in SEVERITIES:
        errors.append(f"severity '{rule['severity']}' is not one of {sorted(SEVERITIES)}")
    if rule["triggerOperator"] not in TRIGGER_OPERATORS:
        errors.append(f"triggerOperator '{rule['triggerOperator']}' is not one of {sorted(TRIGGER_OPERATORS)}")
    if not isinstance(rule["triggerThreshold"], int) or isinstance(rule["triggerThreshold"], bool):
        errors.append("triggerThreshold must be an integer")

    frequency, period = to_minutes(rule["queryFrequency"]), to_minutes(rule["queryPeriod"])
    if frequency is None or period is None:
        errors.append("queryFrequency and queryPeriod must look like 30m, 1h or 1d")
    else:
        if not MIN_MINUTES <= frequency <= MAX_MINUTES or not MIN_MINUTES <= period <= MAX_MINUTES:
            errors.append("queryFrequency and queryPeriod must be between 5m and 14d")
        if period < frequency:
            errors.append("queryPeriod is shorter than queryFrequency, so events would be skipped")

    tactics = rule["tactics"] if isinstance(rule["tactics"], list) else []
    errors += [f"unknown tactic '{t}'" for t in tactics if t not in TACTICS]
    techniques = rule["relevantTechniques"] if isinstance(rule["relevantTechniques"], list) else []
    if not techniques or not all(isinstance(t, str) and TECHNIQUE.match(t) for t in techniques):
        errors.append("relevantTechniques must be a list of ATT&CK ids such as T1558.003")

    connectors = rule["requiredDataConnectors"]
    if not isinstance(connectors, list) or not all(
        isinstance(c, dict) and c.get("connectorId") and c.get("dataTypes") for c in connectors
    ):
        errors.append("each requiredDataConnectors entry needs connectorId and dataTypes")

    query = rule["query"]
    if not isinstance(query, str) or not query.strip():
        return errors + ["query is empty"]
    if "SecurityEvent" not in query:
        errors.append("query does not reference the SecurityEvent table")
    errors += [f"query header is missing '{key}'" for key in HEADER_KEYS if key not in query]
    for technique in techniques:
        if isinstance(technique, str) and technique not in query:
            errors.append(f"query header does not name technique {technique}")

    kql_path = rule_path.with_name("query.kql")
    if not kql_path.is_file():
        errors.append("query.kql is missing next to rule.yaml")
    elif normalise(kql_path.read_text(encoding="utf-8")) != normalise(query):
        errors.append("query in rule.yaml differs from query.kql")

    produced = output_columns(query)
    if not produced:
        errors.append("query must end with a '| project' that lists its output columns")

    mappings = rule["entityMappings"]
    if not isinstance(mappings, list):
        return errors + ["entityMappings must be a list"]
    for mapping in mappings:
        fields = mapping.get("fieldMappings") if isinstance(mapping, dict) else None
        if not isinstance(mapping, dict) or not mapping.get("entityType") or not fields:
            errors.append("each entityMappings entry needs entityType and fieldMappings")
            continue
        if not isinstance(fields, list):
            errors.append("fieldMappings must be a list")
            continue
        for field in fields:
            column = field.get("columnName") if isinstance(field, dict) else None
            if not column or not field.get("identifier"):
                errors.append("each fieldMappings entry needs identifier and columnName")
            elif column not in produced:
                errors.append(f"entity column '{column}' is not produced by the query")
    custom = rule.get("customDetails") or {}
    if not isinstance(custom, dict):
        errors.append("customDetails must be a mapping of name to column")
    else:
        for column in custom.values():
            if str(column) not in produced:
                errors.append(f"customDetails column '{column}' is not produced by the query")
    return errors


HUNTING_FIELDS = ("id", "name", "description", "requiredDataConnectors", "tactics", "relevantTechniques", "query")
HUNTING_HEADER_KEYS = ("// Name:", "// Purpose:", "// Data source:", "// ATT&CK:", "// Use:")


def validate_hunting_query(yaml_path: Path) -> list[str]:
    """Check one hunting/<name>.yaml and its <name>.kql twin."""
    try:
        hunt = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"not valid YAML: {exc}"]
    if not isinstance(hunt, dict):
        return ["top level of the file is not a mapping"]
    errors = [f"missing required field '{f}'" for f in HUNTING_FIELDS if hunt.get(f) in (None, "", [], {})]
    if errors:
        return errors

    try:
        uuid.UUID(str(hunt["id"]))
    except ValueError:
        errors.append("id is not a GUID")
    tactics = hunt["tactics"] if isinstance(hunt["tactics"], list) else []
    errors += [f"unknown tactic '{t}'" for t in tactics if t not in TACTICS]
    techniques = hunt["relevantTechniques"] if isinstance(hunt["relevantTechniques"], list) else []
    if not techniques or not all(isinstance(t, str) and TECHNIQUE.match(t) for t in techniques):
        errors.append("relevantTechniques must be a list of ATT&CK ids such as T1558.003")

    query = hunt["query"]
    if not isinstance(query, str) or not query.strip():
        return errors + ["query is empty"]
    errors += [f"query header is missing '{key}'" for key in HUNTING_HEADER_KEYS if key not in query]
    for technique in techniques:
        if isinstance(technique, str) and technique not in query:
            errors.append(f"query header does not name technique {technique}")
    kql_path = yaml_path.with_suffix(".kql")
    if not kql_path.is_file():
        errors.append(f"{kql_path.name} is missing next to {yaml_path.name}")
    elif normalise(kql_path.read_text(encoding="utf-8")) != normalise(query):
        errors.append(f"query in {yaml_path.name} differs from {kql_path.name}")
    return errors


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    rule_paths = sorted((root / "detections").glob("*/rule.yaml"))
    if not rule_paths:
        print(f"FAIL no rule.yaml files found under {root / 'detections'}")
        return 1

    failed = 0
    seen_ids: dict[str, Path] = {}
    for rule_path in rule_paths:
        try:
            errors = validate_rule(rule_path)
        except Exception as exc:  # a malformed file must fail this rule, not abort the run
            errors = [f"could not be validated: {exc!r}"]
        try:
            rule_id = str(yaml.safe_load(rule_path.read_text(encoding="utf-8")).get("id"))
        except (yaml.YAMLError, AttributeError):
            rule_id = ""
        if rule_id and rule_id in seen_ids:
            errors.append(f"id is also used by {seen_ids[rule_id].relative_to(root)}")
        seen_ids.setdefault(rule_id, rule_path)

        label = rule_path.relative_to(root)
        if errors:
            failed += 1
            print(f"FAIL {label}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"PASS {label}")

    print(f"{len(rule_paths) - failed} of {len(rule_paths)} rules passed")

    hunt_paths = sorted((root / "hunting").glob("*.yaml"))
    hunt_failed = 0
    for hunt_path in hunt_paths:
        try:
            errors = validate_hunting_query(hunt_path)
            hunt_id = str(yaml.safe_load(hunt_path.read_text(encoding="utf-8")).get("id"))
        except Exception as exc:  # a malformed file must fail this query, not abort the run
            errors, hunt_id = [f"could not be validated: {exc!r}"], ""
        if hunt_id and hunt_id in seen_ids:
            errors.append(f"id is also used by {seen_ids[hunt_id].relative_to(root)}")
        seen_ids.setdefault(hunt_id, hunt_path)
        label = hunt_path.relative_to(root)
        if errors:
            hunt_failed += 1
            print(f"FAIL {label}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"PASS {label}")
    if hunt_paths:
        print(f"{len(hunt_paths) - hunt_failed} of {len(hunt_paths)} hunting queries passed")
    return 1 if failed or hunt_failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
