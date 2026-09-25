from backend.store import Store


def candidate(record_id: str, source_id: str, source: str) -> dict[str, object]:
    return {
        "id": record_id,
        "file_name": f"{source}_fragment_000000.txt",
        "file_type": "TEXT",
        "mime_type": "text/plain",
        "offset": 0,
        "length": 8,
        "restorability": 0,
        "integrity": "Unverified",
        "status": "Partial",
        "category": "document",
        "preview": "evidence",
        "sha256": "a" * 64,
        "relationship": "Not established",
        "source": source,
        "source_id": source_id,
        "priority": "Not ranked",
        "created_at": "2026-09-26T00:00:00+00:00",
    }


def test_delete_upload_removes_only_that_upload_and_linked_recoveries(tmp_path):
    store = Store(tmp_path / "delete-test.sqlite3")
    source_a = "11111111-1111-4111-8111-111111111111"
    source_b = "22222222-2222-4222-8222-222222222222"
    item_a = candidate("asset-a", source_a, "same-name.img")
    item_b = candidate("asset-b", source_b, "same-name.img")
    store.save_asset(item_a, b"evidence")
    store.save_asset(item_b, b"evidence")
    recovery = {
        "id": "recovery-a",
        "source_asset_id": "asset-a",
        "file_name": "recovered.txt",
        "file_type": "TEXT",
        "mime_type": "text/plain",
        "sha256": "b" * 64,
        "verified": False,
        "validation": "{}",
        "created_at": "2026-09-26T00:00:00+00:00",
    }
    store.save_recovery(recovery, b"evidence")

    assert store.delete_upload_records(source_a) == 1
    assert store.get_asset("asset-a") is None
    assert store.get_recovery("recovery-a") is None
    assert store.get_asset("asset-b") is not None


def test_delete_unknown_upload_is_noop(tmp_path):
    store = Store(tmp_path / "delete-empty.sqlite3")
    assert store.delete_upload_records("unknown-upload") == 0
