"""Load MITRE ATT&CK Enterprise techniques from the official STIX repository."""
from __future__ import annotations
import json
from pathlib import Path
from urllib.request import Request, urlopen

STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE = Path(__file__).resolve().parent / "data" / "enterprise-attack.json"

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact"
]

def _fallback():
    """Small fallback dataset so the app remains usable offline."""
    return [
        {"technique_id":"T1566.001","name":"Spearphishing Attachment","tactics":["initial-access"],"platforms":["Windows","macOS","Linux"],"url":"https://attack.mitre.org/techniques/T1566/001/"},
        {"technique_id":"T1059.001","name":"PowerShell","tactics":["execution"],"platforms":["Windows"],"url":"https://attack.mitre.org/techniques/T1059/001/"},
        {"technique_id":"T1003.001","name":"LSASS Memory","tactics":["credential-access"],"platforms":["Windows"],"url":"https://attack.mitre.org/techniques/T1003/001/"},
        {"technique_id":"T1021.001","name":"Remote Desktop Protocol","tactics":["lateral-movement"],"platforms":["Windows"],"url":"https://attack.mitre.org/techniques/T1021/001/"},
        {"technique_id":"T1486","name":"Data Encrypted for Impact","tactics":["impact"],"platforms":["Windows","macOS","Linux"],"url":"https://attack.mitre.org/techniques/T1486/"},
        {"technique_id":"T1078","name":"Valid Accounts","tactics":["defense-evasion","persistence","privilege-escalation","initial-access"],"platforms":["Windows","macOS","Linux","Cloud"],"url":"https://attack.mitre.org/techniques/T1078/"},
    ]

def _parse_stix(data):
    objects = data.get("objects", [])
    tactic_names = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic" and not obj.get("x_mitre_deprecated") and not obj.get("revoked"):
            tactic_names[obj.get("x_mitre_shortname")] = obj.get("name", obj.get("x_mitre_shortname"))
    result = []
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                break
        if not ext_id:
            continue
        phases = [p.get("phase_name") for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        tactics = [p for p in TACTIC_ORDER if p in phases] + [p for p in phases if p not in TACTIC_ORDER]
        result.append({
            "technique_id": ext_id, "name": obj.get("name", ext_id),
            "tactics": tactics, "platforms": obj.get("x_mitre_platforms", []),
            "url": next((r.get("url") for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), "")
        })
    result.sort(key=lambda x: x["technique_id"])
    return result

def load_techniques(force_refresh=False):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = None
    source = ""
    if force_refresh or not CACHE_FILE.exists():
        try:
            req = Request(STIX_URL, headers={"User-Agent": "ATTACK-Coverage-Analyzer/1.0"})
            with urlopen(req, timeout=20) as response:
                raw = response.read()
            parsed = json.loads(raw.decode("utf-8"))
            CACHE_FILE.write_text(json.dumps(parsed), encoding="utf-8")
            data = parsed
            source = "Loaded current public Enterprise ATT&CK STIX data from the official MITRE ATT&CK GitHub repository."
        except Exception as exc:
            source = f"Could not refresh online ({exc}). "
    if data is None and CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            source += "Using locally cached Enterprise ATT&CK STIX data."
        except Exception:
            data = None
    if data:
        try:
            techniques = _parse_stix(data)
            if techniques:
                return techniques, source
        except Exception:
            pass
    return _fallback(), source + "Using a small built-in offline sample; refresh when internet access is available."
