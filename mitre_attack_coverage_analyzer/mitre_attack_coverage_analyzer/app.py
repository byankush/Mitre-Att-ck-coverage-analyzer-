from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from attack_data import load_techniques, TACTIC_ORDER
from analyzer import (
    init_db, get_mappings, save_mapping, delete_mapping, import_mappings,
    export_navigator_layer, coverage_summary, mapping_to_frame
)

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "data" / "coverage.db"

st.set_page_config(page_title="ATT&CK Coverage Analyzer", page_icon="🛡️", layout="wide")
init_db(DB_PATH)

@st.cache_data(ttl=3600, show_spinner=False)
def get_attack_data():
    return load_techniques()

techniques, source_note = get_attack_data()
tech_by_id = {t["technique_id"]: t for t in techniques}
mappings = get_mappings(DB_PATH)
mapping_frame = mapping_to_frame(mappings, tech_by_id)
summary = coverage_summary(techniques, mappings)

st.title("🛡️ MITRE ATT&CK Coverage Analyzer")
st.caption("Defensive security control mapping, detection coverage measurement, and gap analysis.")
with st.expander("Dataset status", expanded=False):
    st.write(source_note)
    st.write(f"Loaded **{len(techniques):,}** active Enterprise ATT&CK techniques and sub-techniques.")

page = st.sidebar.radio("Workspace", ["Dashboard", "ATT&CK Matrix", "Manage Mappings", "Import / Export", "Methodology"])
st.sidebar.divider()
st.sidebar.metric("Techniques loaded", f"{len(techniques):,}")
st.sidebar.metric("Mapped techniques", f"{summary['mapped']:,}")
st.sidebar.metric("Coverage", f"{summary['coverage_pct']:.1f}%")

if page == "Dashboard":
    st.header("Coverage overview")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Technique coverage", f"{summary['coverage_pct']:.1f}%", f"{summary['mapped']} / {summary['total']}")
    c2.metric("Detection coverage", f"{summary['detection_pct']:.1f}%")
    c3.metric("Prevention coverage", f"{summary['prevention_pct']:.1f}%")
    c4.metric("Mappings recorded", f"{len(mappings):,}")

    left, right = st.columns([1.15, 1])
    with left:
        st.subheader("Coverage by tactic")
        tactic_df = pd.DataFrame(summary["by_tactic"])
        if not tactic_df.empty:
            fig = px.bar(tactic_df, x="tactic", y="coverage_pct", text="coverage_pct",
                         labels={"tactic": "Tactic", "coverage_pct": "Coverage (%)"},
                         range_y=[0, 100])
            fig.update_traces(texttemplate="%{text:.1f}%", textposition="outside")
            fig.update_layout(height=420, xaxis_tickangle=-35, margin=dict(t=20,b=100))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No tactic data is available.")
    with right:
        st.subheader("Coverage status")
        status_df = pd.DataFrame([
            {"Status": "Covered", "Techniques": summary["covered"]},
            {"Status": "Partial", "Techniques": summary["partial"]},
            {"Status": "Not covered", "Techniques": summary["not_covered"]},
        ])
        fig = px.pie(status_df, names="Status", values="Techniques", hole=.55)
        fig.update_layout(height=420, margin=dict(t=20,b=20))
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Highest-priority coverage gaps")
    gaps = summary["gaps"]
    if gaps:
        gap_df = pd.DataFrame(gaps)
        st.dataframe(gap_df[["technique_id","name","tactic","platforms"]], use_container_width=True, hide_index=True)
    else:
        st.success("Every loaded technique has at least one mapping. Review evidence quality and confidence.")

elif page == "ATT&CK Matrix":
    st.header("ATT&CK Enterprise coverage matrix")
    q = st.text_input("Search technique ID or name")
    tactic_filter = st.multiselect("Tactics", TACTIC_ORDER, default=[])
    status_filter = st.multiselect("Coverage status", ["Covered", "Partial", "Not covered"],
                                   default=["Covered", "Partial", "Not covered"])
    rows = []
    by_tid = {}
    for m in mappings:
        by_tid.setdefault(m["technique_id"], []).append(m)
    for t in techniques:
        if q and q.lower() not in (t["technique_id"] + " " + t["name"]).lower():
            continue
        if tactic_filter and not any(x in tactic_filter for x in t["tactics"]):
            continue
        ms = by_tid.get(t["technique_id"], [])
        status = "Not covered" if not ms else ("Covered" if any(x["status"] == "Covered" for x in ms) else "Partial")
        if status not in status_filter:
            continue
        rows.append({
            "Technique ID": t["technique_id"], "Technique": t["name"],
            "Tactics": ", ".join(t["tactics"]), "Platforms": ", ".join(t["platforms"]),
            "Coverage": status, "Mappings": len(ms)
        })
    df = pd.DataFrame(rows)
    st.caption(f"Showing {len(df):,} techniques")
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True,
                     column_config={"Coverage": st.column_config.TextColumn("Coverage")})
        st.download_button("Download filtered matrix CSV", df.to_csv(index=False).encode("utf-8"),
                           "attack_matrix_filtered.csv", "text/csv")
    else:
        st.info("No techniques match the selected filters.")

elif page == "Manage Mappings":
    st.header("Manage defensive control mappings")
    with st.expander("➕ Add a mapping", expanded=True):
        with st.form("add_mapping", clear_on_submit=True):
            tid = st.selectbox("ATT&CK technique", options=sorted(tech_by_id),
                               format_func=lambda x: f"{x} — {tech_by_id[x]['name']}")
            control = st.text_input("Control / detection name", placeholder="e.g. EDR process creation alert")
            kind = st.selectbox("Capability type", ["Detection", "Prevention", "Response", "Visibility"])
            status = st.selectbox("Coverage status", ["Covered", "Partial"])
            confidence = st.slider("Confidence", 1, 5, 3, help="Analyst confidence in the mapping/evidence.")
            evidence = st.text_input("Evidence / rule / control reference")
            log_source = st.text_input("Data source / telemetry", placeholder="e.g. Sysmon Event ID 1, Windows Security")
            owner = st.text_input("Owner / product")
            notes = st.text_area("Notes and validation details")
            submitted = st.form_submit_button("Save mapping", type="primary")
            if submitted:
                if not control.strip():
                    st.error("A control or detection name is required.")
                else:
                    save_mapping(DB_PATH, {
                        "technique_id": tid, "control": control.strip(), "kind": kind,
                        "status": status, "confidence": confidence, "evidence": evidence,
                        "log_source": log_source, "owner": owner, "notes": notes
                    })
                    st.success("Mapping saved.")
                    st.rerun()

    st.subheader("Existing mappings")
    if mappings:
        mf = pd.DataFrame(mappings)
        show_cols = ["id","technique_id","control","kind","status","confidence","evidence","log_source","owner"]
        st.dataframe(mf[show_cols], use_container_width=True, hide_index=True)
        selected = st.selectbox("Select mapping to delete", options=[m["id"] for m in mappings],
                                format_func=lambda x: next(f"#{m['id']} — {m['technique_id']} / {m['control']}" for m in mappings if m["id"] == x))
        if st.button("Delete selected mapping", type="secondary"):
            delete_mapping(DB_PATH, selected)
            st.success("Mapping deleted.")
            st.rerun()
    else:
        st.info("No mappings yet. Add a control above or import a mapping CSV.")

elif page == "Import / Export":
    st.header("Import and export")
    st.subheader("Import mappings from CSV")
    st.write("Required column: `technique_id`. Recommended columns: `control`, `kind`, `status`, `confidence`, `evidence`, `log_source`, `owner`, `notes`.")
    upload = st.file_uploader("Choose mapping CSV", type=["csv"])
    if upload is not None:
        try:
            preview = pd.read_csv(upload)
            st.dataframe(preview.head(20), use_container_width=True, hide_index=True)
            if st.button("Import these mappings", type="primary"):
                count, errors = import_mappings(DB_PATH, preview, set(tech_by_id))
                st.success(f"Imported {count} mappings.")
                if errors:
                    st.warning("Some rows were skipped: " + "; ".join(errors[:10]))
                st.rerun()
        except Exception as exc:
            st.error(f"Could not read CSV: {exc}")

    st.divider()
    st.subheader("Export")
    if mappings:
        export_df = pd.DataFrame(mappings)
        st.download_button("Download all mappings (CSV)", export_df.to_csv(index=False).encode("utf-8"),
                           "attack_coverage_mappings.csv", "text/csv")
        nav = export_navigator_layer(techniques, mappings)
        st.download_button("Download ATT&CK Navigator layer (JSON)", json.dumps(nav, indent=2).encode("utf-8"),
                           "attack_coverage_navigator_layer.json", "application/json")
    else:
        st.info("Add or import mappings to enable exports.")
    st.caption("The Navigator layer uses technique scores: 0 = no mapped coverage, 1 = partial, 2 = covered.")

elif page == "Methodology":
    st.header("Scoring methodology and interpretation")
    st.markdown("""
**Technique status**
- **Not covered:** no mapping exists for the technique.
- **Partial:** mappings exist, but none is marked Covered.
- **Covered:** at least one mapping is marked Covered.

**Coverage percentage** = number of techniques marked Covered or Partial ÷ total loaded techniques × 100.

**Detection coverage** and **prevention coverage** use the same technique-level rule, but only count mappings of the corresponding capability type. A technique is counted when it has at least one mapping of that type.

**Confidence** is an analyst-assigned evidence-quality indicator from 1 (low) to 5 (high). It is recorded for review; it does not silently inflate coverage scores.

**Important:** a mapped technique is not proof that an attack will be detected or prevented. Validate mappings with controlled purple-team exercises, telemetry checks, rule tests, and documented evidence. Coverage is a measurement of documented defensive capability, not a guarantee of security.
""")
    st.subheader("Recommended workflow")
    st.markdown("""
1. Load the current Enterprise ATT&CK dataset.
2. Inventory controls, EDR/SIEM detections, prevention policies, and telemetry.
3. Map each control to the most specific applicable technique or sub-technique.
4. Attach evidence, log sources, owner, and confidence.
5. Mark mappings Partial until tested; mark Covered only after validation.
6. Review gaps by tactic and prioritize based on business risk and threat relevance.
7. Export an ATT&CK Navigator layer for workshops and reporting.
""")
    st.subheader("Data handling")
    st.write("Mappings are stored in a local SQLite database at `data/coverage.db`. No mapping data is sent to a server by this application. The optional ATT&CK dataset refresh downloads public MITRE STIX data.")
