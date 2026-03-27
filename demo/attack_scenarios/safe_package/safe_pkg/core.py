"""Core helpers for the safe demo package."""

from __future__ import annotations


def slugify(value: str) -> str:
    """Convert a string into a lowercase slug."""
    return "-".join(value.strip().lower().split())


def mean(values: list[float]) -> float:
    """Return the arithmetic mean for a non-empty list of numbers."""
    if not values:
        raise ValueError("values must not be empty")
    return sum(values) / len(values)
