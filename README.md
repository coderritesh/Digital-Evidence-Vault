# Digital Evidence Vault

An investigation-support prototype that preserves digital image evidence, proves its integrity, and produces a structured report. Built with Python and Streamlit.

> **Advisory only.** Error Level Analysis (ELA) and the risk score are indicators to guide a human investigator. They are not proof that an image is genuine or manipulated, and they are not final legal proof.

## What it does

1. **Evidence Vault** - stores the uploaded file byte-for-byte, read-only, named by its SHA-256 hash. Duplicates are detected.
2. **Integrity verification** - re-hashes the stored file at any time and reports INTACT or TAMPERED.
3. **Metadata extractor** - reads EXIF data (camera, dates, software, GPS) and lists advisory observations.
4. **Image analyzer** - Error Level Analysis map plus an advisory 0-100 risk score with every contributing factor shown.
5. **Chain-of-custody ledger** - every action is logged in a hash-linked chain; editing or deleting an old entry is detected.
6. **PDF report** - evidence summary, metadata, analysis, limitations and custody log in one document.

## Run it

Requires Python 3.10 or newer.

```
python -m venv venv
venv\Scripts\activate          (Windows)
source venv/bin/activate       (Mac/Linux)
pip install -r requirements.txt
streamlit run app.py
```

Enter your name in the sidebar, then follow sections 1 to 6 on the page.

## Project structure

| File | Purpose |
|---|---|
| `app.py` | Streamlit interface |
| `vault.py` | Hashing, read-only storage, SQLite records, integrity check |
| `metadata.py` | EXIF extraction and observations |
| `analyzer.py` | ELA and advisory risk score |
| `custody.py` | Tamper-evident hash-chained ledger |
| `report.py` | PDF generation (ReportLab) |
| `tamper_ledger.py` | Test script that edits a ledger entry to prove detection |

## Testing tamper detection

- **Evidence file:** append a byte to a stored file, then press "Verify now". It reports TAMPERED.
- **Ledger:** run `python tamper_ledger.py 1 "Someone Else"`, then reload the page. The ledger turns red. Run it again with the original name to restore it.

## Limitations

- Someone with full access to the machine could rewrite both the files and the database. Copy the latest chain hash somewhere outside the computer to detect this.
- ELA works best on JPEG. Re-shared or heavily compressed images can look "edited" when they are not, and careful edits can look clean.
- The score weights are heuristic and have not been validated on a real dataset.
- Images only. No video or document support.
- No user accounts or passwords.

## Privacy

Evidence files, the database and generated reports can contain sensitive data such as GPS locations. They are excluded from this repository by `.gitignore`. Do not commit real evidence.

## Possible future work

Trusted external storage for chain hashes, real authentication, calibration on public image-tampering datasets, and video support.
