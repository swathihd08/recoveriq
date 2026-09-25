from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

from backend.analyzer import analyze_bytes, verify_payload
from backend.store import Store

st.set_page_config(page_title="RecoverIQ", page_icon="🔎", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
:root { color-scheme: light; }
html, body, [class*="st-"] { font-size: 17px; }
[data-testid="stSidebar"] { background: #f4f6f7; }
[data-testid="stSidebar"] button { min-height: 48px; font-size: 16px; }
h1 { font-size: 2.15rem !important; }
h2 { font-size: 1.45rem !important; }
h3 { font-size: 1.15rem !important; }
[data-testid="stMetricValue"] { font-size: 1.7rem; }
[data-testid="stDataFrame"] { font-size: 15px; }
small, .stCaption { font-size: 14px !important; }
.block-container { max-width: 1500px; padding-top: 2rem; padding-bottom: 3rem; }
</style>
""", unsafe_allow_html=True)

store = Store()


def assets() -> list[dict[str, Any]]:
    return store.list_assets()


def selected_asset(records: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    if not records:
        return None
    labels = {f"{item['file_name']} · {item['file_type']} · offset {item['offset']:,} · {item['id'][:8]}": item for item in records}
    selected_label = st.selectbox("Select candidate", list(labels), key=key)
    return labels[selected_label]


def has_confirmed_upload_id(source_id: str) -> bool:
    try:
        uuid.UUID(source_id)
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def compatible_chain(asset: dict[str, Any]) -> list[dict[str, Any]]:
    if not has_confirmed_upload_id(asset["source_id"]):
        return [asset]
    candidates = store.list_assets_for_source_type(asset["source_id"], asset["file_type"])
    chain = [asset]
    while True:
        preceding = next((item for item in candidates if item["id"] not in {part["id"] for part in chain} and item["offset"] + item["length"] == chain[0]["offset"]), None)
        if preceding is None:
            break
        chain.insert(0, preceding)
    while True:
        following = next((item for item in candidates if item["id"] not in {part["id"] for part in chain} and chain[-1]["offset"] + chain[-1]["length"] == item["offset"]), None)
        if following is None:
            break
        chain.append(following)
    return chain


def source_records_page() -> None:
    st.title("Evidence sources")
    st.write("Upload source files. The original bytes are scanned locally and are not modified.")
    st.info("Analysis reports detected signatures, byte ranges, hashes, and format-check results. It does not infer topics or investigative conclusions.")
    upload_key = f"evidence_file_{st.session_state.get('upload_widget_version', 0)}"
    with st.form("evidence_upload_form", clear_on_submit=True):
        uploads = st.file_uploader("Choose files", type=None, accept_multiple_files=True, key=upload_key, help="Maximum 64 MB per file")
        submitted = st.form_submit_button("Scan selected files", type="primary")
    if submitted and uploads:
        for uploaded in uploads:
            payload = uploaded.getvalue()
            if len(payload) > 64 * 1024 * 1024:
                st.error(f"{uploaded.name}: exceeds 64 MB and was not scanned.")
                continue
            upload_id = str(uuid.uuid4())
            candidates = analyze_bytes(Path(uploaded.name).name, payload, upload_id)
            for candidate in candidates:
                store.save_asset(candidate.public(), candidate.payload)
            st.success(f"{Path(uploaded.name).name}: {len(payload):,} bytes scanned; {len(candidates)} candidates detected.")
        st.session_state.upload_widget_version = st.session_state.get("upload_widget_version", 0) + 1
        st.rerun()

    records = assets()
    if not records:
        st.subheader("Stored source filenames")
        st.caption("No evidence files have been scanned in this database.")
        return
    by_source: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_source.setdefault(record["source"], []).append(record)
    st.subheader("Stored source filenames")
    st.caption("Records are grouped by observed filename only; matching filenames do not prove identical uploads.")
    st.dataframe([
        {
            "Source filename": name,
            "Candidate records": len(items),
            "Candidate bytes": sum(item["length"] for item in items),
            "Detected types": ", ".join(sorted({item["file_type"] for item in items})),
        }
        for name, items in sorted(by_source.items())
    ], width="stretch", hide_index=True)


def fragments_page() -> None:
    st.title("File candidates")
    st.write("Observed signature, byte offset, carved length, source filename, and SHA-256.")
    records = assets()
    query = st.text_input("Filter candidates", placeholder="Filename, type, source, or hash")
    if query:
        query_lower = query.lower()
        records = [item for item in records if query_lower in f"{item['file_name']} {item['file_type']} {item['source']} {item['sha256']}".lower()]
    if not records:
        st.info("No matching candidate records.")
        return
    st.dataframe([
        {
            "Filename": item["file_name"],
            "Detected signature": item["file_type"],
            "Source filename": item["source"],
            "Byte offset": item["offset"],
            "Length (bytes)": item["length"],
            "SHA-256": item["sha256"],
            "Format check": item["integrity"],
        }
        for item in records
    ], width="stretch", hide_index=True)
    st.caption(f"{len(records)} candidate record(s)")


def compatibility_page() -> None:
    st.title("Fragment compatibility")
    st.write("A compatible range is reported only when it is byte-adjacent, the same detected type, and has the same confirmed upload ID.")
    item = selected_asset(assets(), "compatibility_candidate")
    if item is None:
        st.info("Scan a source file to create candidate records.")
        return
    st.subheader("Selected candidate facts")
    left, right = st.columns(2)
    left.write(f"**Source filename:** {item['source']}")
    left.write(f"**Detected signature:** {item['file_type']}")
    right.write(f"**Byte range:** {item['offset']:,}–{item['offset'] + item['length']:,}")
    right.write(f"**Length:** {item['length']:,} bytes")
    if not has_confirmed_upload_id(item["source_id"]):
        st.warning("This older record has no confirmed upload ID. Compatibility cannot be established from the filename alone.")
        return
    chain = compatible_chain(item)
    others = [candidate for candidate in chain if candidate["id"] != item["id"]]
    if not others:
        st.info("No exact byte-adjacent candidate was observed for this upload and type.")
        return
    st.success(f"{len(others)} adjacent candidate(s) observed")
    st.dataframe([
        {"Filename": candidate["file_name"], "Type": candidate["file_type"], "Offset": candidate["offset"], "Length (bytes)": candidate["length"]}
        for candidate in others
    ], width="stretch", hide_index=True)


def integrity_page() -> None:
    st.title("Integrity and recovery")
    st.write("Run format validators against a selected carved range, then store and download the resulting byte sequence.")
    records = assets()
    item = selected_asset(records, "integrity_candidate")
    if item is None:
        st.info("Scan a source file to create candidate records.")
        return
    selected = store.get_asset(item["id"])
    if selected is None:
        st.error("Candidate record is no longer available.")
        return
    item, payload = selected
    st.caption(f"Source: {item['source']} · {item['file_type']} · offset {item['offset']:,} · {len(payload):,} bytes")
    existing_id = st.session_state.get("recovery_id")
    existing_source = st.session_state.get("recovery_source_id")
    if st.button("Reconstruct and verify", type="primary", key="reconstruct_button"):
        chain = compatible_chain(item)
        parts = [store.get_asset(part["id"])[1] for part in chain if store.get_asset(part["id"]) is not None]
        recovered_bytes = b"".join(parts)
        result = verify_payload(item["file_type"], recovered_bytes)
        extension = {"JPEG": ".jpg", "PNG": ".png", "PDF": ".pdf", "ZIP": ".zip", "TEXT": ".txt"}.get(item["file_type"], ".bin")
        base = item["file_name"].rsplit("_fragment_", 1)[0]
        recovery_id = str(uuid.uuid4())
        recovery = {
            "id": recovery_id,
            "source_asset_id": item["id"],
            "file_name": f"{base}_recovered{extension}",
            "file_type": item["file_type"],
            "mime_type": item["mime_type"],
            "sha256": result["sha256"],
            "verified": result["verified"],
            "validation": json.dumps(result),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        store.save_recovery(recovery, recovered_bytes)
        store.update_status(item["id"], "Reconstructed" if result["verified"] else "Unverified reconstruction")
        st.session_state.recovery_id = recovery_id
        st.session_state.recovery_source_id = item["id"]
        st.rerun()

    recovery_id = st.session_state.get("recovery_id") if existing_source == item["id"] else None
    recovery_result = store.get_recovery(recovery_id) if recovery_id else None
    if recovery_result:
        recovered, recovered_bytes = recovery_result
        try:
            validation = json.loads(recovered["validation"])
        except (KeyError, TypeError, json.JSONDecodeError):
            validation = verify_payload(item["file_type"], recovered_bytes)
        st.subheader("Format-check results")
        st.json({key: validation[key] for key in ("signature_valid", "ending_valid", "container_valid", "size_valid", "verified", "bytes", "sha256")})
        if validation["verified"] and item["file_type"] in {"JPEG", "PNG"}:
            st.image(recovered_bytes, caption=recovered["file_name"], use_container_width=True)
        st.download_button("Download reconstructed bytes", data=recovered_bytes, file_name=recovered["file_name"], mime="application/octet-stream", type="primary")
    else:
        st.info("Select the action to store a candidate artifact and run format checks.")
    st.subheader("Source candidate facts")
    st.code(item["sha256"], language=None)


def relationships_page() -> None:
    st.title("Observed byte relationships")
    st.write("Connections represent exact adjacent byte ranges from a single confirmed upload and detected type. No semantic or filename-based links are created.")
    records = assets()
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in records:
        if has_confirmed_upload_id(item["source_id"]):
            groups.setdefault((item["source_id"], item["file_type"]), []).append(item)
    edges: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for fragments in groups.values():
        fragments.sort(key=lambda candidate: candidate["offset"])
        for first, second in zip(fragments, fragments[1:]):
            if first["offset"] + first["length"] == second["offset"]:
                edges.append((first, second))
    st.metric("Exact adjacent links", len(edges))
    if not edges:
        st.info("No exact byte-adjacent fragment pairs with confirmed upload identity were observed.")
        return
    st.dataframe([
        {
            "First candidate": first["file_name"],
            "First range end": first["offset"] + first["length"],
            "Next candidate": second["file_name"],
            "Next range start": second["offset"],
            "Source filename": first["source"],
            "Type": first["file_type"],
        }
        for first, second in edges
    ], use_container_width=True, hide_index=True)
    lines = ["digraph evidence {", '  graph [rankdir="LR"];', '  node [shape=box, style="rounded"];']
    node_names: dict[str, str] = {}
    for index, (first, second) in enumerate(edges):
        for record in (first, second):
            if record["id"] not in node_names:
                node_names[record["id"]] = f"node{len(node_names)}"
                label = f"{record['file_type']}\\n{record['file_name']}\\nOffset {record['offset']:,} · {record['length']:,} bytes"
                lines.append(f"  {node_names[record['id']]} [label={json.dumps(label)}];")
        lines.append(f"  {node_names[first['id']]} -> {node_names[second['id']]} [label=\"Adjacent\"];")
    lines.append("}")
    st.graphviz_chart("\n".join(lines), width="stretch")


pages = [
    st.Page(source_records_page, title="Evidence sources", icon=":material/folder_open:", default=True),
    st.Page(fragments_page, title="File candidates", icon=":material/find_in_page:"),
    st.Page(compatibility_page, title="Compatibility", icon=":material/compare_arrows:"),
    st.Page(integrity_page, title="Integrity and recovery", icon=":material/verified:"),
    st.Page(relationships_page, title="Byte relationships", icon=":material/account_tree:"),
]

navigation = st.navigation(pages, position="sidebar")
st.sidebar.divider()
st.sidebar.caption("Local evidence facts · no semantic inference")
navigation.run()
