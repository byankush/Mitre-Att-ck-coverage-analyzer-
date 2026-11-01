# Architecture

## Components

- `app.py`: Streamlit pages, forms, filters, charts, and downloads.
- `attack_data.py`: retrieves the official Enterprise ATT&CK STIX bundle, caches it, parses active `attack-pattern` objects and ATT&CK kill-chain phases, and supplies a small fallback set.
- `analyzer.py`: SQLite persistence, mapping import/export, coverage aggregation, and Navigator layer generation.
- `data/coverage.db`: local mapping database.
- `data/enterprise-attack.json`: local source dataset cache.

## Data flow

1. App startup initializes SQLite.
2. ATT&CK loader downloads or reads cached STIX JSON.
3. STIX attack-pattern objects are converted to technique records with external ATT&CK IDs, tactic shortnames, platforms, and URLs.
4. Mapping records are loaded from SQLite.
5. Aggregation computes technique-level and tactic-level metrics.
6. UI displays the metrics and provides CSV/Navigator exports.

## Storage schema

`mappings` fields:
- `id`: primary key
- `technique_id`: ATT&CK technique/sub-technique ID
- `control`: control or detection name
- `kind`: Detection / Prevention / Response / Visibility
- `status`: Covered / Partial
- `confidence`: integer 1–5
- `evidence`, `log_source`, `owner`, `notes`: analyst-maintained metadata
- `created_at`: UTC ISO timestamp

## Extension points

Potential next steps include ATT&CK Mobile and ICS domains, Navigator layer import, multiple assessment workspaces, role-based access, audit history, control frameworks (NIST CSF, CIS Controls), and API integrations with SIEM/EDR platforms.
