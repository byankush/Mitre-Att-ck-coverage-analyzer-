import tempfile
from pathlib import Path
import pandas as pd
from analyzer import init_db, save_mapping, get_mappings, coverage_summary, export_navigator_layer, import_mappings

def test_mapping_and_coverage():
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "test.db"
        init_db(db)
        techniques = [
            {"technique_id":"T1000","name":"Example A","tactics":["execution"],"platforms":["Windows"]},
            {"technique_id":"T2000","name":"Example B","tactics":["impact"],"platforms":["Linux"]},
        ]
        save_mapping(db, {"technique_id":"T1000","control":"Test alert","kind":"Detection","status":"Covered"})
        maps = get_mappings(db)
        result = coverage_summary(techniques, maps)
        assert result["mapped"] == 1
        assert result["covered"] == 1
        assert result["not_covered"] == 1
        assert result["detection_pct"] == 50.0
        layer = export_navigator_layer(techniques, maps)
        assert layer["techniques"][0]["score"] == 2
        assert layer["techniques"][1]["score"] == 0

def test_csv_import_skips_unknown():
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "test.db"
        init_db(db)
        frame = pd.DataFrame([{"technique_id":"T1000","control":"Rule A"},{"technique_id":"T9999","control":"Bad"}])
        count, errors = import_mappings(db, frame, {"T1000"})
        assert count == 1
        assert len(errors) == 1
