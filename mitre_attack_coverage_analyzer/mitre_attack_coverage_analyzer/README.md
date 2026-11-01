# MITRE ATT&CK Coverage Analyzer

A local, defensive security assessment tool for mapping controls and detections to MITRE ATT&CK Enterprise techniques, identifying coverage gaps, and exporting ATT&CK Navigator layers.

## 1. Features

- Loads Enterprise ATT&CK techniques and sub-techniques from the official MITRE ATT&CK STIX repository.
- Caches the dataset locally and falls back to a small offline demonstration dataset if the first download is unavailable.
- SQLite persistence for mappings.
- Technique-level covered / partial / not-covered status.
- Detection and prevention coverage metrics.
- Tactic-level coverage chart, searchable technique matrix, and gap list.
- Evidence, telemetry/log source, owner, confidence, and notes per mapping.
- CSV import/export and ATT&CK Navigator layer JSON export.
- No login, cloud backend, or paid service required.

## 2. Requirements

- Python 3.10 or newer (3.11 recommended)
- Internet connection for the initial/current ATT&CK dataset download (optional after cache is created)

## 3. Installation

### Windows

```powershell
cd mitre_attack_coverage_analyzer
py -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

### macOS / Linux

```bash
cd mitre_attack_coverage_analyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Streamlit opens the app in your browser, usually at `http://localhost:8501`.

## 4. First run

On first launch, the app attempts to download the public Enterprise ATT&CK STIX JSON from:

`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`

The file is cached at `data/enterprise-attack.json`. If the download fails, a small built-in sample keeps the app usable. The app displays which data source is active. Refresh the page after restoring network access; the dataset cache is retained locally.

## 5. Workflow

1. Open **Manage Mappings**.
2. Choose the ATT&CK technique/sub-technique.
3. Add the defensive control or detection name.
4. Choose Detection, Prevention, Response, or Visibility.
5. Set status to Partial until the mapping has been validated.
6. Record evidence (rule ID, policy, test case), data source, owner/product, confidence, and validation notes.
7. Review **Dashboard** and **ATT&CK Matrix** for gaps.
8. Export a CSV for analysis or a Navigator layer JSON for visualization in ATT&CK Navigator.

## 6. CSV import format

Minimum required column:

```csv
technique_id,control
T1059.001,PowerShell script block logging alert
T1003.001,Credential dumping behavior analytic
```

Recommended complete format:

```csv
technique_id,control,kind,status,confidence,evidence,log_source,owner,notes
T1059.001,PowerShell script block alert,Detection,Partial,3,SOC-RULE-014,PowerShell 4104,SIEM,Needs purple-team validation
T1021.001,RDP ingress policy,Prevention,Covered,4,NET-POL-02,Firewall logs,Network Team,Validated in lab
```

Only technique IDs present in the loaded ATT&CK dataset are imported. Invalid rows are skipped and reported.

## 7. Scoring model

### Technique status

- **Not covered:** no mapping exists.
- **Partial:** at least one mapping exists, but none is marked Covered.
- **Covered:** at least one mapping is marked Covered.

### Metrics

- **Overall technique coverage:** `(Covered + Partial) / total techniques × 100`
- **Detection coverage:** percentage of techniques with at least one Detection mapping.
- **Prevention coverage:** percentage of techniques with at least one Prevention mapping.
- **Tactic coverage:** percentage of techniques associated with a tactic that have at least one mapping.

Confidence is stored as an analyst assessment (1–5) and does not alter the score. This avoids presenting low-quality evidence as stronger coverage. A technique can have multiple controls mapped to it.

These are documentation/assessment metrics, not a guarantee of detection or prevention. Validate coverage with telemetry checks, rule tests, controlled purple-team exercises, and evidence review.

## 8. ATT&CK Navigator export

The exported JSON is a Navigator layer for the Enterprise domain. Technique scores are:
- `0`: Not covered
- `1`: Partial
- `2`: Covered

Import it into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) using the layer import/open option. Navigator schema versions may evolve; if a future Navigator release changes its layer schema, update the `versions` and layer structure in `analyzer.py`.

## 9. Data storage and privacy

- Mapping records are stored in `data/coverage.db` (SQLite).
- ATT&CK source data is stored in `data/enterprise-attack.json`.
- No mappings are transmitted by the app.
- The initial dataset fetch contacts the public MITRE ATT&CK GitHub repository.
- Back up the `data/` directory to preserve mappings and the local dataset cache.

## 10. Project structure

```text
mitre_attack_coverage_analyzer/
├── app.py                 # Streamlit user interface
├── attack_data.py         # MITRE STIX download, parsing, cache, fallback
├── analyzer.py            # SQLite, scoring, CSV import, Navigator export
├── requirements.txt
├── README.md
├── docs/
│   ├── USER_GUIDE.md
│   ├── ARCHITECTURE.md
│   └── SCORING.md
├── data/
│   └── .gitkeep
└── tests/
    └── test_analyzer.py
```

## 11. Troubleshooting

- **`streamlit` is not recognized:** activate the virtual environment and run `python -m streamlit run app.py`.
- **Dataset shows offline sample:** check internet access, then restart the app. The cache is written only after a successful download.
- **Port already in use:** run `python -m streamlit run app.py --server.port 8502`.
- **Reset local mappings:** stop the app and back up/delete `data/coverage.db`. This permanently removes the local mapping database.
- **Import skips rows:** confirm the `technique_id` exists in the currently loaded Enterprise dataset and uses the exact ATT&CK ID format.

## 12. Responsible use

This application is intended for defensive security engineering, control validation, detection engineering, and risk assessment. It does not execute attack techniques or perform network scanning.
