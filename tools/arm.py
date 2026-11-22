"""Helpers for writing repository content into ARM templates safely."""

from __future__ import annotations

import re

# Watchlist aliases go into a resource name built with concat(), so they are restricted.
ALIAS = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def literal(value: object) -> object:
    """Escape content so ARM never evaluates it as a template expression.

    ARM treats a string that starts with `[` and ends with `]` as an expression, and a
    leading `[[` as an escaped literal bracket. Every string taken from detection or
    watchlist files passes through here before it enters a template.
    """
    if isinstance(value, str):
        return "[" + value if value.startswith("[") and value.endswith("]") else value
    if isinstance(value, dict):
        return {key: literal(item) for key, item in value.items()}
    if isinstance(value, list):
        return [literal(item) for item in value]
    return value
