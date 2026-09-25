from __future__ import annotations

import uuid
from typing import Any


def _confirmed_upload(source_id: str) -> bool:
    try:
        uuid.UUID(source_id)
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def pipeline_states(
    records: list[dict[str, Any]],
    selected_record: dict[str, Any] | None,
    recovery_exists: bool,
    recovery_verified: bool,
) -> tuple[bool, bool, bool, bool, bool, bool, bool, bool]:
    """Return observed workflow states; recovery state is scoped to the selected record."""
    by_upload_type: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        if _confirmed_upload(record.get("source_id")):
            by_upload_type.setdefault((record["source_id"], record["file_type"]), []).append(record)

    adjacent_pairs = [
        (first, second)
        for fragments in by_upload_type.values()
        for ordered in [sorted(fragments, key=lambda item: item["offset"])]
        for first, second in zip(ordered, ordered[1:])
        if first["offset"] + first["length"] == second["offset"]
    ]
    if selected_record is not None:
        has_compatibility = any(
            selected_record["id"] in {first["id"], second["id"]}
            for first, second in adjacent_pairs
        )
    else:
        has_compatibility = bool(adjacent_pairs)

    has_candidates = bool(records)
    return (
        has_candidates,
        has_candidates,
        any(record["length"] > 0 for record in records),
        has_candidates,
        has_compatibility,
        recovery_exists and selected_record is not None,
        recovery_exists and selected_record is not None,
        recovery_verified and selected_record is not None,
    )
