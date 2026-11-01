"""Persistence, scoring, CSV import, and ATT&CK Navigator export."""
from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

def _connect(db_path):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technique_id TEXT NOT NULL,
            control TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'Detection',
            status TEXT NOT NULL DEFAULT 'Partial',
            confidence INTEGER NOT NULL DEFAULT 3,
            evidence TEXT DEFAULT '',
            log_source TEXT DEFAULT '',
            owner TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mappings_tid ON mappings(technique_id)")

def get_mappings(db_path):
    with _connect(db_path) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM mappings ORDER BY technique_id, id")]

def save_mapping(db_path, item):
    with _connect(db_path) as conn:
        conn.execute("""
        INSERT INTO mappings (technique_id, control, kind, status, confidence, evidence, log_source, owner, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item["technique_id"], item["control"], item.get("kind","Detection"),
            item.get("status","Partial"), max(1,min(5,int(item.get("confidence",3)))),
            item.get("evidence",""), item.get("log_source",""), item.get("owner",""),
            item.get("notes",""), datetime.now(timezone.utc).isoformat()
        ))

def delete_mapping(db_path, mapping_id):
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM mappings WHERE id = ?", (int(mapping_id),))

def import_mappings(db_path, frame, valid_ids):
    count, errors = 0, []
    for idx, row in frame.iterrows():
        tid = str(row.get("technique_id", "")).strip()
        if tid not in valid_ids:
            errors.append(f"row {idx+2}: unknown technique_id {tid or '(blank)'}")
            continue
        control = str(row.get("control", "Imported control")).strip()
        if not control or control.lower() == "nan":
            control = "Imported control"
        kind = str(row.get("kind", "Detection"))
        if kind not in ["Detection","Prevention","Response","Visibility"]:
            kind = "Detection"
        status = str(row.get("status", "Partial"))
        if status not in ["Covered","Partial"]:
            status = "Partial"
        try:
            confidence = int(row.get("confidence", 3))
        except (ValueError, TypeError):
            confidence = 3
        save_mapping(db_path, {
            "technique_id":tid, "control":control, "kind":kind, "status":status,
            "confidence":max(1,min(5,confidence)),
            "evidence":str(row.get("evidence","")) if pd.notna(row.get("evidence","")) else "",
            "log_source":str(row.get("log_source","")) if pd.notna(row.get("log_source","")) else "",
            "owner":str(row.get("owner","")) if pd.notna(row.get("owner","")) else "",
            "notes":str(row.get("notes","")) if pd.notna(row.get("notes","")) else ""
        })
        count += 1
    return count, errors

def mapping_to_frame(mappings, tech_by_id):
    rows = []
    for m in mappings:
        t = tech_by_id.get(m["technique_id"], {})
        rows.append({**m, "technique_name":t.get("name","Unknown technique"),
                     "tactics":", ".join(t.get("tactics",[]))})
    return pd.DataFrame(rows)

def coverage_summary(techniques, mappings):
    total = len(techniques)
    by_tid = {}
    for m in mappings:
        by_tid.setdefault(m["technique_id"], []).append(m)
    covered = partial = 0
    detect = set()
    prevent = set()
    tactic_stats = {}
    gaps = []
    for t in techniques:
        tid = t["technique_id"]
        ms = by_tid.get(tid, [])
        status = "Not covered" if not ms else ("Covered" if any(m["status"] == "Covered" for m in ms) else "Partial")
        if status == "Covered": covered += 1
        elif status == "Partial": partial += 1
        else: gaps.append({"technique_id":tid,"name":t["name"],"tactic":", ".join(t["tactics"]),"platforms":", ".join(t["platforms"])})
        if any(m["kind"] == "Detection" for m in ms): detect.add(tid)
        if any(m["kind"] == "Prevention" for m in ms): prevent.add(tid)
        for tactic in t["tactics"]:
            stat = tactic_stats.setdefault(tactic, {"total":0,"mapped":0})
            stat["total"] += 1
            if ms: stat["mapped"] += 1
    mapped = covered + partial
    def pct(n, d): return (n / d * 100) if d else 0.0
    by_tactic = []
    for tactic, v in tactic_stats.items():
        by_tactic.append({"tactic":tactic.replace("-"," ").title(),"coverage_pct":round(pct(v["mapped"],v["total"]),1),
                          "mapped":v["mapped"],"total":v["total"]})
    by_tactic.sort(key=lambda x: x["tactic"])
    return {
        "total":total,"mapped":mapped,"covered":covered,"partial":partial,
        "not_covered":max(0,total-mapped),"coverage_pct":pct(mapped,total),
        "detection_pct":pct(len(detect),total),"prevention_pct":pct(len(prevent),total),
        "by_tactic":by_tactic,"gaps":gaps[:25]
    }

def export_navigator_layer(techniques, mappings):
    by_tid = {}
    for m in mappings:
        by_tid.setdefault(m["technique_id"], []).append(m)
    techniques_out = []
    for t in techniques:
        ms = by_tid.get(t["technique_id"], [])
        score = 0 if not ms else (2 if any(m["status"] == "Covered" for m in ms) else 1)
        techniques_out.append({
            "techniqueID":t["technique_id"], "score":score,
            "comment":"; ".join(sorted({m["control"] for m in ms})),
            "enabled":True, "metadata":[{"name":"coverage_status","value":"Covered" if score == 2 else ("Partial" if score == 1 else "Not covered")}]
        })
    return {
        "name":"ATT&CK Coverage Analyzer export",
        "versions":{"attack":"current","navigator":"4.9.1","layer":"4.5"},
        "domain":"enterprise-attack","description":"Coverage exported from MITRE ATT&CK Coverage Analyzer.",
        "filters":{"platforms":[],"tactics":[],"techniques":[]},
        "sorting":0,"layout":{"layout":"side","aggregateFunction":"average","showID":True,"showName":True},
        "hideDisabled":False,"techniques":techniques_out,
        "gradient":{"colors":["#ff6666","#ffe766","#8ecf8e"],"minValue":0,"maxValue":2},
        "legendItems":[{"label":"Not covered","color":"#ff6666"},{"label":"Partial","color":"#ffe766"},{"label":"Covered","color":"#8ecf8e"}],
        "metadata":[{"name":"generated_at","value":datetime.now(timezone.utc).isoformat()}]
    }
