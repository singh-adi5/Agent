"""Build one ARM template holding every analytics rule in detections/*/analytic.yaml.

    python -m tools.build_arm -o build/sentinel-analytics.json
    az deployment group create -g <RESOURCE_GROUP> \
        --template-file build/sentinel-analytics.json --parameters workspace=<WORKSPACE_NAME>

The template takes the workspace name as its only parameter and contains no
subscription, tenant or workspace identifiers. Rules are created disabled.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from tools import catalog

API_VERSION = "2023-02-01"
OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
TIMESPAN = re.compile(r"^(\d+)([mhd])$")
OPTIONAL_PROPERTIES = ("customDetails", "alertDetailsOverride", "eventGroupingSettings")


def iso8601(value: str) -> str:
    """30m -> PT30M, 1h -> PT1H, 1d -> P1D."""
    match = TIMESPAN.match(str(value))
    if not match:
        raise ValueError(f"unsupported timespan '{value}'")
    amount, unit = match.groups()
    return f"P{amount}D" if unit == "d" else f"PT{amount}{unit.upper()}"


def to_resource(rule: dict) -> dict:
    properties = {
        "displayName": rule["name"],
        "description": " ".join(str(rule["description"]).split()),
        "severity": rule["severity"],
        # Enable each rule after its allow-lists are set for the environment.
        "enabled": False,
        "query": rule["query"],
        "queryFrequency": iso8601(rule["queryFrequency"]),
        "queryPeriod": iso8601(rule["queryPeriod"]),
        "triggerOperator": OPERATORS[rule["triggerOperator"]],
        "triggerThreshold": rule["triggerThreshold"],
        "suppressionDuration": "PT5H",
        "suppressionEnabled": False,
        "tactics": rule["tactics"],
        # This API version takes parent technique ids only.
        "techniques": sorted({t.split(".")[0] for t in rule["relevantTechniques"]}),
        "entityMappings": rule["entityMappings"],
        "incidentConfiguration": {
            "createIncident": True,
            # Scheduled runs overlap so no event is skipped. Grouping on matching
            # entities folds the repeat alert into the open incident.
            "groupingConfiguration": {
                "enabled": True,
                "reopenClosedIncident": False,
                "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities",
                "groupByEntities": [],
                "groupByAlertDetails": [],
                "groupByCustomDetails": [],
            },
        },
    }
    for name in OPTIONAL_PROPERTIES:
        if rule.get(name):
            properties[name] = rule[name]
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": API_VERSION,
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{rule['id']}')]",
        "kind": "Scheduled",
        "properties": properties,
    }


def build_template(root: Path = catalog.REPO_ROOT) -> dict:
    paths = [d / catalog.ANALYTIC for d in catalog.detection_dirs(root)]
    paths = [p for p in paths if p.is_file()]
    if not paths:
        raise SystemExit(f"no {catalog.ANALYTIC} files under {root / 'detections'}")
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {"description": "Log Analytics workspace with Sentinel enabled."},
            }
        },
        "resources": [to_resource(catalog.load_yaml(p)) for p in paths],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-o", "--output", type=Path, help="write here instead of stdout")
    args = parser.parse_args(argv)

    text = json.dumps(build_template(), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
