# RecoverIQ Workspace Notes

## Project
- Streamlit multipage app, Python binary analyzer, and SQLite persistence.
- Report observed file type, source filename, byte offsets, lengths, hashes, and parser/decoder outcomes only.
- Do not assign confidence scores, semantic topics, or inferred relationships. Compatibility requires a confirmed upload ID, type match, and exact byte adjacency.
- Never include uploaded evidence, SQLite data, local secrets, or the virtual environment in commits.

## Development
- Install with `python -m pip install -r requirements.txt`.
- Run with `streamlit run streamlit_app.py`.
- Run tests with `python -m pytest backend/tests -q`.
- Streamlit Community Cloud entry point is `streamlit_app.py`.
