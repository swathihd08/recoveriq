from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_DATA_DIR = Path(os.getenv("RECOVERIQ_DATA_DIR", "./data"))


class Store:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DEFAULT_DATA_DIR / "recoveriq.sqlite3"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY, file_name TEXT NOT NULL, file_type TEXT NOT NULL,
                    mime_type TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL,
                    restorability INTEGER NOT NULL, integrity TEXT NOT NULL, status TEXT NOT NULL,
                    category TEXT NOT NULL, preview TEXT NOT NULL, sha256 TEXT NOT NULL,
                    relationship TEXT NOT NULL, source TEXT NOT NULL, source_id TEXT NOT NULL DEFAULT '', priority TEXT NOT NULL,
                    created_at TEXT NOT NULL, payload BLOB NOT NULL
                )
            """)
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(assets)")}
            if "source_id" not in columns:
                connection.execute("ALTER TABLE assets ADD COLUMN source_id TEXT NOT NULL DEFAULT ''")
                connection.execute("UPDATE assets SET source_id = 'legacy:' || id WHERE source_id = ''")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            connection.execute("""
                CREATE TABLE IF NOT EXISTS recoveries (
                    id TEXT PRIMARY KEY, source_asset_id TEXT NOT NULL, file_name TEXT NOT NULL,
                    file_type TEXT NOT NULL, mime_type TEXT NOT NULL, sha256 TEXT NOT NULL,
                    verified INTEGER NOT NULL, validation TEXT NOT NULL, payload BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            if version < 3:
                from .analyzer import verify_payload

                rows = connection.execute("SELECT id, file_type, payload FROM assets").fetchall()
                for row in rows:
                    status = "Verified" if verify_payload(row["file_type"], row["payload"])["verified"] else "Unverified"
                    connection.execute(
                        "UPDATE assets SET relationship = 'Not established', priority = 'Not ranked', restorability = 0, integrity = ?, status = ? WHERE id = ?",
                        (status, status, row["id"]),
                    )
                connection.execute("PRAGMA user_version = 3")
                version = 3
            if version < 4:
                legacy_demo_ids = connection.execute(
                    "SELECT id FROM assets WHERE source = ? AND source_id = ?",
                    ("usb_case_04.img", "usb_case_04.img"),
                ).fetchall()
                ids = [row["id"] for row in legacy_demo_ids]
                if ids:
                    placeholders = ", ".join("?" for _ in ids)
                    connection.execute(f"DELETE FROM recoveries WHERE source_asset_id IN ({placeholders})", ids)
                    connection.execute(f"DELETE FROM assets WHERE id IN ({placeholders})", ids)
                connection.execute("UPDATE assets SET source_id = 'legacy:' || id WHERE source_id = source")
                connection.execute("PRAGMA user_version = 4")

    def remove_legacy_demo_assets(self) -> None:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id FROM assets WHERE source = ? AND source_id = ?",
                ("usb_case_04.img", "usb_case_04.img"),
            ).fetchall()
            ids = [row["id"] for row in rows]
            if ids:
                placeholders = ", ".join("?" for _ in ids)
                connection.execute(f"DELETE FROM recoveries WHERE source_asset_id IN ({placeholders})", ids)
                connection.execute(f"DELETE FROM assets WHERE id IN ({placeholders})", ids)

    def save_asset(self, item: dict[str, Any], payload: bytes) -> None:
        fields = ["id", "file_name", "file_type", "mime_type", "offset", "length", "restorability", "integrity", "status", "category", "preview", "sha256", "relationship", "source", "source_id", "priority", "created_at"]
        values = [item[field] for field in fields] + [payload]
        with self.connect() as connection:
            connection.execute(
                f"INSERT OR REPLACE INTO assets ({', '.join(fields)}, payload) VALUES ({', '.join('?' for _ in values)})",
                values,
            )

    def list_assets(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM assets ORDER BY created_at DESC, offset ASC").fetchall()
        hidden = {"payload", "restorability", "priority", "relationship"}
        return [{key: row[key] for key in row.keys() if key not in hidden} for row in rows]

    def get_asset(self, asset_id: str) -> tuple[dict[str, Any], bytes] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if row is None:
            return None
        hidden = {"payload", "restorability", "priority", "relationship"}
        return ({key: row[key] for key in row.keys() if key not in hidden}, row["payload"])

    def update_status(self, asset_id: str, status: str) -> None:
        with self.connect() as connection:
            connection.execute("UPDATE assets SET status = ? WHERE id = ?", (status, asset_id))

    def save_recovery(self, item: dict[str, Any], payload: bytes) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO recoveries (id, source_asset_id, file_name, file_type, mime_type, sha256, verified, validation, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (item["id"], item["source_asset_id"], item["file_name"], item["file_type"], item["mime_type"], item["sha256"], int(item["verified"]), item["validation"], payload, item["created_at"]),
            )

    def get_recovery(self, recovery_id: str) -> tuple[dict[str, Any], bytes] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM recoveries WHERE id = ?", (recovery_id,)).fetchone()
        if row is None:
            return None
        item = {key: row[key] for key in row.keys() if key != "payload"}
        item["verified"] = bool(item["verified"])
        return item, row["payload"]

    def list_assets_for_source_type(self, source_id: str, file_type: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM assets WHERE source_id = ? AND file_type = ? ORDER BY offset ASC",
                (source_id, file_type),
            ).fetchall()
        hidden = {"payload", "restorability", "priority", "relationship"}
        return [{key: row[key] for key in row.keys() if key not in hidden} for row in rows]
