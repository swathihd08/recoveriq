from __future__ import annotations

import hashlib
import io
import re
import uuid
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

SIGNATURES = (
    (b"%PDF-", "PDF", "application/pdf", "document"),
    (b"\xff\xd8\xff", "JPEG", "image/jpeg", "image"),
    (b"\x89PNG\r\n\x1a\n", "PNG", "image/png", "image"),
    (b"PK\x03\x04", "ZIP", "application/zip", "archive"),
)


@dataclass
class Candidate:
    id: str
    file_name: str
    file_type: str
    mime_type: str
    offset: int
    length: int
    restorability: int
    integrity: str
    status: str
    category: str
    preview: str
    sha256: str
    relationship: str
    source: str
    source_id: str
    priority: str
    created_at: str
    payload: bytes

    def public(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("payload")
        return value


def _printable_text(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    return "".join(char for char in text if char.isprintable() or char in "\r\n\t")


def _make_candidate(
    source: str,
    file_type: str,
    mime_type: str,
    category: str,
    offset: int,
    payload: bytes,
    complete: bool,
    preview: str = "",
    source_id: str | None = None,
) -> Candidate:
    structurally_complete = verify_payload(file_type, payload)["verified"] if file_type in {"JPEG", "PNG", "PDF", "ZIP", "TEXT"} else complete
    digest = hashlib.sha256(payload).hexdigest()
    return Candidate(
        id=str(uuid.uuid4()),
        file_name=f"{source.rsplit('.', 1)[0]}_fragment_{offset:06x}.{file_type.lower() if file_type != 'TEXT' else 'txt'}",
        file_type=file_type,
        mime_type=mime_type,
        offset=offset,
        length=len(payload),
        restorability=0,
        integrity="Verified" if structurally_complete else "Unverified",
        status="Recovered" if structurally_complete else "Partial",
        category=category,
        preview=preview[:280],
        sha256=digest,
        relationship="Not established",
        source=source,
        source_id=source_id or source,
        priority="Not ranked",
        created_at=datetime.now(timezone.utc).isoformat(),
        payload=payload,
    )


def analyze_bytes(source: str, blob: bytes, source_id: str | None = None) -> list[Candidate]:
    """Find known file signatures and readable text runs without modifying evidence bytes."""
    if not blob:
        return []
    hits: list[tuple[int, str, str, str, int]] = []
    for signature, file_type, mime_type, category in SIGNATURES:
        position = 0
        while True:
            position = blob.find(signature, position)
            if position < 0:
                break
            hits.append((position, file_type, mime_type, category, len(signature)))
            position += len(signature)
    hits.sort(key=lambda hit: hit[0])
    candidates: list[Candidate] = []
    carved_ranges: list[tuple[int, int]] = []

    for index, (offset, file_type, mime_type, category, _) in enumerate(hits):
        next_offset = hits[index + 1][0] if index + 1 < len(hits) else len(blob)
        end = min(next_offset, offset + 4 * 1024 * 1024)
        data = blob[offset:end]
        complete = False
        if file_type == "PDF":
            terminator = data.find(b"%%EOF")
            if terminator >= 0:
                data = data[: terminator + 5]
                complete = True
        elif file_type == "JPEG":
            terminator = data.find(b"\xff\xd9", 3)
            if terminator >= 0:
                data = data[: terminator + 2]
                complete = True
        elif file_type == "PNG":
            terminator = data.find(b"IEND")
            if terminator >= 0:
                data = data[: terminator + 8]
                complete = True
        elif file_type == "ZIP":
            complete = b"PK\x05\x06" in data or b"PK\x06\x06" in data
        carved_ranges.append((offset, offset + len(data)))
        text = _printable_text(data)
        candidates.append(_make_candidate(source, file_type, mime_type, category, offset, data, complete, text, source_id))

    printable = [(match.start(), match.group()) for match in re.finditer(rb"[\x20-\x7e\r\n\t]{48,}", blob)]
    for offset, raw_text in printable:
        if any(start <= offset < end for start, end in carved_ranges):
            continue
        text = raw_text.decode("utf-8", errors="replace").strip()
        if len(text) < 48:
            continue
        candidates.append(
            _make_candidate(source, "TEXT", "text/plain", "document", offset, raw_text, True, text, source_id)
        )

    return sorted(candidates, key=lambda item: item.offset)


def verify_payload(file_type: str, payload: bytes) -> dict[str, Any]:
    checks = {
        "JPEG": (payload.startswith(b"\xff\xd8\xff"), payload.endswith(b"\xff\xd9")),
        "PNG": (payload.startswith(b"\x89PNG\r\n\x1a\n"), b"IEND" in payload[-16:]),
        "PDF": (payload.startswith(b"%PDF-"), b"%%EOF" in payload[-2048:]),
        "ZIP": (payload.startswith(b"PK\x03\x04"), b"PK\x05\x06" in payload[-65557:] or b"PK\x06\x06" in payload[-65557:]),
        "TEXT": (bool(payload), bool(payload.strip())),
    }
    signature_valid, ending_valid = checks.get(file_type, (False, False))
    container_valid = False
    if signature_valid and ending_valid and file_type in {"JPEG", "PNG"}:
        try:
            from PIL import Image

            with Image.open(io.BytesIO(payload)) as image:
                image.load()
                container_valid = image.format == file_type
        except Exception:
            container_valid = False
    elif signature_valid and ending_valid and file_type == "PDF":
        try:
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(payload), strict=True)
            container_valid = reader.trailer is not None
        except Exception:
            container_valid = False
    elif signature_valid and ending_valid and file_type == "ZIP":
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                container_valid = archive.testzip() is None
        except (OSError, zipfile.BadZipFile):
            container_valid = False
    elif file_type == "TEXT":
        container_valid = signature_valid and ending_valid
    return {
        "signature_valid": signature_valid,
        "ending_valid": ending_valid,
        "container_valid": container_valid,
        "size_valid": bool(payload),
        "verified": signature_valid and ending_valid and container_valid and bool(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def serialize_candidate(candidate: Candidate) -> dict[str, Any]:
    return candidate.public()
