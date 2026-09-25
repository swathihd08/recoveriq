from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

from backend.analyzer import analyze_bytes, verify_payload
from backend.store import Store
from backend.workflow import pipeline_states

st.set_page_config(page_title="RecoverIQ", page_icon="🔎", layout="wide", initial_sidebar_state="collapsed")
st.markdown("""
<style>
:root { color-scheme: light; }
html, body, [class*="st-"] { font-size: 17px; }
.stApp { background: linear-gradient(180deg, #edf3f5 0%, #f7f9fa 320px, #f7f9fa 100%); color: #213744; }
[data-testid="stSidebar"] { background: #eaf0f2; border-right: 1px solid #d5e0e4; }
[data-testid="stSidebar"] button { min-height: 48px; font-size: 16px; border-radius: 9px; }
[data-testid="stSidebar"] [aria-current="page"] { background: #d8e9e3; }
h1 { font-size: 2.05rem !important; color: #173d4a; letter-spacing: -0.02em; }
h2 { font-size: 1.45rem !important; color: #224b56; }
h3 { font-size: 1.15rem !important; color: #315964; }
[data-testid="stMetric"] { padding: 14px 16px; border: 1px solid #d7e2e5; border-radius: 12px; background: #fff; box-shadow: 0 2px 8px #1f46530a; }
[data-testid="stMetricLabel"] { color: #56717a; font-size: 0.9rem; }
[data-testid="stMetricValue"] { color: #173d4a; font-size: 1.65rem; }
[data-testid="stDataFrame"] { font-size: 15px; border: 1px solid #d7e2e5; border-radius: 10px; overflow: hidden; }
small, .stCaption { font-size: 14px !important; }
.block-container { max-width: 1500px; padding-top: 5rem; padding-bottom: 3rem; }
.rqi-masthead { display:flex; justify-content:space-between; align-items:center; gap:18px; margin:0 0 24px; padding:20px 24px; color:#edf7f4; background:linear-gradient(105deg,#183e4b,#286c6d 62%,#458f78); border:1px solid #376d73; border-radius:15px; box-shadow:0 10px 28px #193d4b1a; }
.rqi-brand { display:flex; align-items:center; gap:14px; }
.rqi-mark { display:grid; width:44px; height:44px; place-items:center; border:1px solid #ffffff42; border-radius:12px; background:#ffffff17; font-size:23px; }
.rqi-name { margin:0; color:#fff; font-size:21px; font-weight:750; line-height:1.15; }
.rqi-subtitle { margin:5px 0 0; color:#d0e5df; font-size:13px; }
.rqi-local { padding:8px 11px; border:1px solid #ffffff4a; border-radius:999px; color:#e5f5ee; background:#ffffff12; font-size:12px; white-space:nowrap; }
.rqi-intro { margin:4px 0 20px; padding:0 1px; }
.rqi-eyebrow { margin-bottom:7px; color:#367b71; font-size:11px; font-weight:750; letter-spacing:.11em; text-transform:uppercase; }
.rqi-deck { margin-top:-8px; color:#58717a; font-size:15px; }
.rqi-pipeline { display:grid; grid-template-columns:repeat(8,minmax(0,1fr)); gap:8px; margin:16px 0 24px; padding:16px; border:1px solid #d7e2e5; border-radius:13px; background:#fff; box-shadow:0 3px 12px #1f465308; }
.rqi-step { position:relative; display:flex; min-height:74px; flex-direction:column; align-items:center; justify-content:center; gap:7px; padding:8px 4px; border:1px solid #e1e9eb; border-radius:9px; color:#6b7f86; background:#f8fafb; text-align:center; }
.rqi-step:not(:last-child):after { position:absolute; z-index:2; top:24px; right:-11px; color:#95a8ad; content:'›'; font-size:21px; font-weight:700; }
.rqi-step-icon { display:grid; width:26px; height:26px; place-items:center; border-radius:50%; color:#62777e; background:#e7edef; font-size:13px; font-weight:700; }
.rqi-step-label { font-size:11px; font-weight:650; line-height:1.25; }
.rqi-step.done { border-color:#c9e1d5; color:#2f6652; background:#f1f8f4; }
.rqi-step.done .rqi-step-icon { color:#fff; background:#398267; }
.rqi-step.current { border-color:#62a698; color:#174c54; background:#eaf5f3; box-shadow:inset 0 0 0 1px #62a698; }
.rqi-step.current .rqi-step-icon { color:#fff; background:#286c6d; }
.rqi-section-heading { margin:24px 0 12px; padding:0 0 10px; border-bottom:1px solid #d7e2e5; }
.rqi-section-title { margin:0 0 4px; color:#214953; font-size:18px; font-weight:700; }
.rqi-section-copy { margin:0; color:#657c83; font-size:13px; }
.rqi-empty { padding:18px; border:1px dashed #bdcdd1; border-radius:10px; color:#536c74; background:#f7fafb; }
.rqi-footnote { margin:22px 0 0; padding-top:12px; border-top:1px solid #d7e2e5; color:#627980; font-size:12px; }
div[data-testid="stForm"] { padding:18px; border:1px solid #d5e1e4; border-radius:13px; background:#fff; }
div[data-testid="stFormSubmitButton"] button[kind="primary"],button[kind="primary"] { min-height:44px; border-radius:8px; font-weight:700; }
@media (max-width:1100px) { .rqi-pipeline { grid-template-columns:repeat(4,minmax(0,1fr)); } .rqi-step:nth-child(4):after { display:none; } }
@media (max-width:600px) { .block-container { padding-top:4.8rem; } .rqi-masthead { align-items:flex-start; flex-direction:column; padding:16px; } .rqi-pipeline { grid-template-columns:repeat(2,minmax(0,1fr)); padding:10px; } .rqi-step:nth-child(2n):after { display:none; } .rqi-step { min-height:64px; } }
</style>
""", unsafe_allow_html=True)

store = Store()


def assets() -> list[dict[str, Any]]:
    return store.list_assets()


def render_masthead() -> None:
    st.markdown("""
    <div class="rqi-masthead">
      <div class="rqi-brand"><div class="rqi-mark">⌕</div><div><p class="rqi-name">RecoverIQ</p><p class="rqi-subtitle">Digital evidence recovery workbench</p></div></div>
      <div class="rqi-local">● &nbsp;Local byte analysis</div>
    </div>
    """, unsafe_allow_html=True)


def render_page_intro(eyebrow: str, title: str, description: str) -> None:
    st.markdown(
        f'<div class="rqi-intro"><div class="rqi-eyebrow">{eyebrow}</div><h1>{title}</h1><div class="rqi-deck">{description}</div></div>',
        unsafe_allow_html=True,
    )


def render_workflow(
    records: list[dict[str, Any]],
    current_stage: int,
    selected_record: dict[str, Any] | None = None,
) -> None:
    stages = [
        "Source file",
        "Signature detection",
        "File carving",
        "Fragment identification",
        "Compatibility check",
        "Reconstruction",
        "Integrity verification",
        "Recovered file",
    ]
    recovery_record = store.get_recovery_for_asset(selected_record["id"]) if selected_record else None
    recovered_file_verified = bool(recovery_record and recovery_record[0]["verified"])
    states = pipeline_states(records, selected_record, recovery_record is not None, recovered_file_verified)
    symbols = ["1", "⌕", "▤", "⋈", "↔", "⚙", "◷", "↓"]
    tiles = []
    for index, label in enumerate(stages, start=1):
        state_class = "done" if states[index - 1] else "current" if index == current_stage else ""
        marker = "✓" if states[index - 1] else symbols[index - 1]
        tiles.append(
            f'<div class="rqi-step {state_class}"><div class="rqi-step-icon">{marker}</div><div class="rqi-step-label">{label}</div></div>'
        )
    st.markdown('<div class="rqi-pipeline">' + "".join(tiles) + "</div>", unsafe_allow_html=True)


def section(title: str, description: str = "") -> None:
    copy = f'<p class="rqi-section-copy">{description}</p>' if description else ""
    st.markdown(f'<div class="rqi-section-heading"><p class="rqi-section-title">{title}</p>{copy}</div>', unsafe_allow_html=True)


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


def source_groups(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(record["source_id"], []).append(record)
    return [
        {
            "source_id": source_id,
            "source": items[0]["source"],
            "records": sorted(items, key=lambda item: item["offset"]),
            "identity_confirmed": has_confirmed_upload_id(source_id),
        }
        for source_id, items in grouped.items()
    ]


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
    records = assets()
    render_page_intro("01 / INGEST", "Evidence sources", "Scan source files locally. Original bytes remain unchanged during analysis.")
    deletion_notice = st.session_state.pop("upload_deleted_notice", None)
    if deletion_notice:
        st.success(deletion_notice)
    render_workflow(records, current_stage=1 if not records else 5)
    if not records:
        st.markdown('<div class="rqi-empty"><b>Ready for source evidence</b><br>Choose a damaged file or storage image below. Nothing is added until you press Scan selected files.</div>', unsafe_allow_html=True)
    else:
        source_count = len({item["source"] for item in records})
        total_bytes = sum(item["length"] for item in records)
        columns = st.columns(3)
        columns[0].metric("Candidate records", f"{len(records):,}")
        columns[1].metric("Source filenames", f"{source_count:,}")
        columns[2].metric("Carved byte ranges", f"{total_bytes:,} bytes")
    section("Add source files", "Select one or more files up to 64 MB each.")
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
        section("Stored sources")
        st.markdown('<div class="rqi-empty">No source filenames have been scanned in this app database yet.</div>', unsafe_allow_html=True)
        return
    section("Stored uploads", "Delete removes candidate records and reconstructions for that upload ID only. Files with the same name stay separate.")
    for upload in sorted(source_groups(records), key=lambda value: (value["source"].lower(), value["source_id"])):
        candidates = upload["records"]
        heading = f"{upload['source']} · {len(candidates)} candidate(s)"
        with st.expander(heading):
            st.caption(
                f"Upload ID: {upload['source_id']}" if upload["identity_confirmed"]
                else f"Legacy record identity: {upload['source_id']} (not confirmed as a complete upload)"
            )
            st.dataframe([
                {"Candidate": item["file_name"], "Type": item["file_type"], "Offset": item["offset"], "Length (bytes)": item["length"], "SHA-256": item["sha256"]}
                for item in candidates
            ], width="stretch", hide_index=True)
            pending_key = f"delete_upload_{upload['source_id']}"
            confirm_key = f"confirm_delete_{upload['source_id']}"
            if not st.session_state.get(pending_key, False):
                if st.button("Delete this upload", key=f"request_{upload['source_id']}", type="secondary"):
                    st.session_state[pending_key] = True
                    st.rerun()
            else:
                st.warning(f"This permanently deletes {len(candidates)} candidate record(s) and their reconstructed artifacts from the app database. It does not delete or change the original file on your device.")
                confirm_col, cancel_col = st.columns(2)
                if confirm_col.button("Permanently delete", key=confirm_key, type="primary"):
                    deleted = store.delete_upload_records(upload["source_id"])
                    st.session_state.pop(pending_key, None)
                    if st.session_state.get("recovery_source_id") in {item["id"] for item in candidates}:
                        st.session_state.pop("recovery_id", None)
                        st.session_state.pop("recovery_source_id", None)
                    st.session_state.upload_deleted_notice = f"Deleted {deleted} candidate record(s) for {upload['source']}."
                    st.rerun()
                if cancel_col.button("Cancel", key=f"cancel_{upload['source_id']}"):
                    st.session_state.pop(pending_key, None)
                    st.rerun()


def fragments_page() -> None:
    records = assets()
    render_page_intro("02 / DETECT & CARVE", "File candidates", "Inspect signatures and byte ranges found in the source data.")
    render_workflow(records, current_stage=2)
    columns = st.columns(3)
    columns[0].metric("Candidate records", f"{len(records):,}")
    columns[1].metric("Detected file types", f"{len({item['file_type'] for item in records}):,}")
    columns[2].metric("Byte ranges", f"{sum(item['length'] for item in records):,} bytes")
    section("Carved candidates", "Values below come directly from detected bytes and parser results.")
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
    records = assets()
    render_page_intro("03 / MATCH BYTE RANGES", "Fragment compatibility", "Check whether candidates meet the exact source, type, and byte-adjacency rules.")
    item = selected_asset(records, "compatibility_candidate")
    render_workflow(records, current_stage=5, selected_record=item)
    section("Compatibility check", "No filename similarity, semantic match, or inferred missing bytes are used.")
    if item is None:
        st.markdown('<div class="rqi-empty">Scan a source file to create candidate records.</div>', unsafe_allow_html=True)
        return
    st.markdown("**Selected candidate facts**")
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
        st.markdown('<div class="rqi-empty">No exact byte-adjacent candidate was observed for this upload and type.</div>', unsafe_allow_html=True)
        return
    st.success(f"{len(others)} adjacent candidate(s) observed")
    st.dataframe([
        {"Filename": candidate["file_name"], "Type": candidate["file_type"], "Offset": candidate["offset"], "Length (bytes)": candidate["length"]}
        for candidate in others
    ], width="stretch", hide_index=True)


def integrity_page() -> None:
    records = assets()
    render_page_intro("04 / RECONSTRUCT & VERIFY", "Integrity and recovery", "Join only confirmed contiguous ranges, validate structure, then export the stored result.")
    item = selected_asset(records, "integrity_candidate")
    recovery_for_selected = store.get_recovery_for_asset(item["id"]) if item else None
    stage = 8 if recovery_for_selected and recovery_for_selected[0]["verified"] else 6
    render_workflow(records, current_stage=stage, selected_record=item)
    section("Reconstruction candidate", "Format checks describe parser/decoder results; they do not establish authenticity.")
    if item is None:
        st.markdown('<div class="rqi-empty">Scan a source file to create candidate records.</div>', unsafe_allow_html=True)
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
        st.session_state.last_recovery_verified = result["verified"]
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
    records = assets()
    render_page_intro("05 / OBSERVED CONNECTIONS", "Byte relationships", "The diagram links only confirmed, exactly adjacent byte ranges of the same type.")
    render_workflow(records, current_stage=0)
    source_options = {
        f"{group['source']} · {group['source_id'][:8]} · {len(group['records'])} candidates": group
        for group in source_groups(records)
        if group["identity_confirmed"]
    }
    if not source_options:
        section("Byte-range map", "Only exact byte boundaries can form an edge; filename matches do not establish a relationship.")
        st.markdown('<div class="rqi-empty">No candidates with confirmed upload IDs are stored.</div>', unsafe_allow_html=True)
        return
    selected_source = st.selectbox("Choose uploaded source", list(source_options), key="relationship_upload")
    upload_group = source_options[selected_source]
    source_records = upload_group["records"]
    section("Byte-range map", "Every node represents one stored candidate. Edges appear only where same-type ranges touch exactly.")
    st.caption(f"Source filename: {upload_group['source']} · Confirmed upload ID: {upload_group['source_id']}")
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in source_records:
        groups.setdefault(item["file_type"], []).append(item)
    edges: list[tuple[dict[str, Any], dict[str, Any]]] = []
    linked_ids: set[str] = set()
    for fragments in groups.values():
        fragments.sort(key=lambda candidate: candidate["offset"])
        for first, second in zip(fragments, fragments[1:]):
            if first["offset"] + first["length"] == second["offset"]:
                edges.append((first, second))
                linked_ids.update((first["id"], second["id"]))
    st.metric("Exact adjacent links", len(edges))
    st.dataframe([
        {
            "Candidate": item["file_name"],
            "Type": item["file_type"],
            "Start byte": item["offset"],
            "End byte (exclusive)": item["offset"] + item["length"],
            "Length": item["length"],
            "Observed adjacency": "Has exact adjacent range" if item["id"] in linked_ids else "No exact adjacent range",
        }
        for item in source_records
    ], width="stretch", hide_index=True)
    lines = ["digraph evidence {", '  graph [rankdir="LR", nodesep="0.35", ranksep="0.55"];', '  node [shape=box, style="rounded,filled", fillcolor="#f1f7f3", color="#438263", fontname="Arial", fontsize=11];', '  edge [color="#438263", penwidth=1.7, label="Adjacent"];']
    node_names: dict[str, str] = {}
    for record in source_records:
        node_names[record["id"]] = f"node{len(node_names)}"
        label = f"{record['file_type']}\\n{record['file_name']}\\nBytes {record['offset']:,}–{record['offset'] + record['length']:,}"
        lines.append(f"  {node_names[record['id']]} [label={json.dumps(label)}];")
    for first, second in edges:
        lines.append(f"  {node_names[first['id']]} -> {node_names[second['id']]} [label=\"Adjacent\"];")
    lines.append("}")
    st.graphviz_chart("\n".join(lines), width="stretch")
    if not edges:
        st.info("No exact adjacent ranges were found in this source. Candidates appear as unconnected nodes; no relationships were inferred.")


pages = [
    st.Page(source_records_page, title="Evidence sources", icon=":material/folder_open:", default=True),
    st.Page(fragments_page, title="File candidates", icon=":material/find_in_page:"),
    st.Page(compatibility_page, title="Compatibility", icon=":material/compare_arrows:"),
    st.Page(integrity_page, title="Integrity and recovery", icon=":material/verified:"),
    st.Page(relationships_page, title="Byte relationships", icon=":material/account_tree:"),
]

navigation = st.navigation(pages, position="top")
render_masthead()
navigation.run()
