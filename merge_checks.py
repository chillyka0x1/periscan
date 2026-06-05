"""Merge-Tool: haengt die exposure_checks aus dem v0.4-Workflow-Output an fingerprints.py an.

Aufruf:  python merge_checks.py <pfad-zum-workflow-output.json>
Liest die aktuelle FINGERPRINTS (inkl. manueller Tweaks), matcht per App-Name und
schreibt fingerprints.py neu (mit exposure_checks-Feld, wo vorhanden).
"""
import json
import sys

from fingerprints import FINGERPRINTS

if len(sys.argv) < 2:
    print("Usage: python merge_checks.py <workflow-output.json>")
    sys.exit(1)

data = json.load(open(sys.argv[1], encoding="utf-8"))
apps_out = data.get("result", data).get("apps", [])
checks_by_name = {a["app"].strip().lower(): a.get("exposure_checks", []) for a in apps_out}

LIST_KEYS = ["titles", "servers", "headers", "body_markers", "login_paths"]
merged = []
matched = 0
for fp in FINGERPRINTS:
    name = fp.get("app") or fp.get("name")
    entry = dict(fp)
    chk = checks_by_name.get((name or "").strip().lower())
    if chk:
        entry["exposure_checks"] = chk
        matched += 1
    merged.append(entry)

merged.sort(key=lambda e: (e.get("app") or e.get("name") or "").lower())


def write_entry(f, e):
    f.write("    {\n")
    f.write(f'        "app": {(e.get("app") or e.get("name"))!r}, "category": {e.get("category", "")!r},\n')
    f.write(f'        "risk": {e.get("risk", "LOW")!r}, "intended_public": {bool(e.get("intended_public", False))!r},\n')
    for k in LIST_KEYS:
        f.write(f'        "{k}": {e.get(k, [])!r},\n')
    if e.get("exposure_checks"):
        f.write(f'        "exposure_checks": {e["exposure_checks"]!r},\n')
    f.write("    },\n")


with open("fingerprints.py", "w", encoding="utf-8") as f:
    f.write('"""Fingerprint-Datenbank selbstgehosteter Apps fuer Periscan.\n\n')
    f.write(f"Auto-generiert aus verifizierter Multi-Agent-Recherche ({len(merged)} Apps, ")
    f.write(f"exposure_checks fuer {matched} Apps).\n")
    f.write("Felder: app, category, risk, intended_public, titles, servers, headers,\n")
    f.write("        body_markers, login_paths, exposure_checks.\n")
    f.write('"""\n\nFINGERPRINTS = [\n')
    for e in merged:
        write_entry(f, e)
    f.write("]\n")

print(f"merged exposure_checks into {matched} of {len(merged)} apps")
