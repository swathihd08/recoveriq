# RecoverIQ

Streamlit-only, local-first evidence triage. The app reports observed file signatures, source filenames, byte offsets, carved lengths, SHA-256 hashes, format-check results, and exact adjacent byte ranges. It does not infer semantic topics, confidence scores, or investigative conclusions, and it creates no sample evidence.

## Pages

- **Evidence sources:** upload files and review source filenames present in SQLite.
- **File candidates:** inspect detected signatures, offsets, carved lengths, statuses, and hashes.
- **Compatibility:** report exact adjacent candidates only when a confirmed upload ID and file type match.
- **Integrity and recovery:** rebuild contiguous candidate ranges, validate their format, store a reconstruction, and download it. JPEG/PNG candidates that fail format checks can also be decoded and re-encoded as a separate salvage copy.
- **Byte relationships:** view a graph and table of exact adjacency links only.

Previously scanned uploads can be removed from the Evidence sources page. Deletion requires confirmation and removes only records for that upload ID plus reconstructed artifacts linked to those candidate IDs; same-named uploads are kept separate. Original files on the user's device are not changed.

JPEG, PNG, PDF, ZIP, and readable-text candidates are detected. JPEG/PNG decoding, strict PDF parsing, ZIP integrity checks, and text checks are used for format validation. Validation is not proof of forensic authenticity; missing bytes are never fabricated.

Image salvage is best-effort: it can re-encode pixels that the decoder can still read, but cannot recreate missing or corrupted visual information. Re-encoding may discard metadata. It creates a derived copy and does not change the stored source candidate. Already-valid images are not re-encoded by the repair action.

## Run locally

Requirements: Python 3.11 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run streamlit_app.py
```

Open the local URL printed by Streamlit, normally `http://localhost:8501`. SQLite data is stored in `data/recoveriq.sqlite3`; set `RECOVERIQ_DATA_DIR` to change the data directory.

## Deploy to Streamlit Community Cloud

1. Push this repository to GitHub.
2. Sign in to Streamlit Community Cloud with an account that has access to the repository.
3. Create an app from `swathihd08/recoveriq`, select the deployment branch, and set the main file to `streamlit_app.py`.
4. Deploy. Streamlit Cloud installs dependencies from `requirements.txt`.

Community Cloud local disk is ephemeral and is not suitable for durable forensic storage. For persistent evidence, deploy the same Streamlit entry point on a host with an attached persistent disk, restrict access, and back up SQLite. Do not upload evidence to a public app.

## Test

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest backend/tests -q
```

Run the interface with `streamlit run streamlit_app.py`.

## Evidence handling

Work from verified forensic copies, preserve source media read-only, and retain chain-of-custody records. This MVP does not implement authentication, audit logs, encryption at rest, secure deletion, or evidence immutability controls. Structural checks do not establish authenticity or prove that all source data has been recovered.
