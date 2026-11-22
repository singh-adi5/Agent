"""Small helpers for reading KQL text. Not a parser: the Kusto language service does that."""

from __future__ import annotations

import re

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def split_top_level(text: str, separator: str) -> list[str]:
    """Split on `separator`, ignoring any inside (), [] or a string literal."""
    parts, depth, quote, start = [], 0, "", 0
    for index, char in enumerate(text):
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
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def strip_comments(query: str) -> str:
    return "\n".join(line for line in query.splitlines() if not line.lstrip().startswith("//"))


def output_columns(query: str) -> set[str]:
    """Columns emitted by the last `project` of the main pipeline.

    Only aliases and bare column names count. An unaliased expression such as
    `pack(...)` has no output name, so the identifiers inside it are ignored.
    """
    pipeline = split_top_level(strip_comments(query), ";")[-1]
    project = None
    for segment in split_top_level(pipeline, "|"):
        words = segment.strip().split(None, 1)
        if len(words) == 2 and words[0] in ("project", "project-reorder"):
            project = words[1]
    if project is None:
        return set()

    columns = set()
    for term in split_top_level(project, ","):
        head = split_top_level(term.strip(), "=")[0].strip()
        if IDENTIFIER.match(head):
            columns.add(head)
    return columns


def placeholders(template: str) -> set[str]:
    """Column names referenced as {{Column}} in an alert detail template."""
    return set(PLACEHOLDER.findall(template))
