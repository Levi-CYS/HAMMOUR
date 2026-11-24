#!/usr/bin/env python3
"""
HAMMOUR — Vuln module (vulnerability matching)
==============================================
Map says who is on the network and what they are. Vuln asks: do those devices
have known weaknesses? It matches each OT asset against an advisory database:

  * CVEs           — real, version-specific product flaws (Siemens, Schneider,
                     Rockwell ...). Passive discovery rarely reveals firmware, so
                     product CVEs are flagged "potential — confirm model/version".
  * Weaknesses     — protocol-level flaws that hold regardless of version (Modbus
                     has no auth, S7comm STOP is unauthenticated, traffic is
                     cleartext). These are confirmed from the protocols we saw.

Each finding carries CVSS / severity, KEV flag, CWE, a fix, and the NCA OTCC
control it maps to. Findings are prioritised by KEV, CVSS and asset criticality.

Usage:  python3 hammour_vuln.py capture.pcap     # -> vuln.json
Passive only.
"""
import json, os
from scapy.all import rdpcap
from hammour_map import build_model

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CRITICALITY = {"PLC": 1.0, "SCADA Server": 0.7, "Engineering WS": 0.7, "HMI": 0.6}
# only real OT infrastructure gets a vuln profile (IT / external / unknown do not)
OT_ASSET_ROLES = {"PLC", "SCADA Server", "HMI", "Engineering WS"}


def _load_db():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "advisories.json")
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _vendor_match(node_vendor, cve_vendor):
    return bool(node_vendor) and cve_vendor.lower() in node_vendor.lower()


def build_vuln(src, model=None):
    if model is None:
        model = build_model(src if isinstance(src, str) else rdpcap(src))
    db = _load_db()
    cves, weaknesses = db["cves"], db["weaknesses"]

    assets = []
    for n in sorted(model["nodes"], key=lambda x: x["ip"]):
        ot = n.get("ot_protocols") or []
        if n["role"] not in OT_ASSET_ROLES:
            continue                      # only OT infrastructure gets a vuln profile

        findings = []
        # protocol-level weaknesses. The "no authentication" flaws describe the
        # commanded device, so they apply to the PLC (server), not to supervisory
        # clients. Cleartext ("*") applies to any OT asset's traffic.
        is_plc = n["role"] == "PLC"
        for w in weaknesses:
            if w["protocol"] == "*":
                applies = bool(ot)
            else:
                applies = is_plc and (w["protocol"] in ot)
            if not applies:
                continue
            findings.append({
                "kind": "weakness", "id": w["id"], "ref": w["cwe"],
                "severity": w["severity"], "cvss": None, "kev": False,
                "cwe": w["cwe"], "title": w["title"], "fix": w["fix"],
                "nca": w["nca"], "confidence": "confirmed",
                "scope": f"{w['protocol'] if w['protocol']!='*' else 'all OT'} protocol",
            })
        # product CVEs. Firmware is rarely seen passively, so a vendor-only match
        # is "potential"; when fingerprinting gave us the model (and version), the
        # match becomes "confirmed".
        model = (n.get("product") or "")
        fw = n.get("firmware")
        for c in cves:
            if not _vendor_match(n.get("vendor"), c["vendor"]):
                continue
            if c.get("protocol_hint") and ot and c["protocol_hint"] not in ot:
                continue
            model_hit = any(prod.lower() in model.lower() for prod in c["products"]) if model else False
            if c.get("require_model") and not model_hit:
                continue                  # e.g. SIPROTEC CVE needs a confirmed model
            confirmed = model_hit and fw
            scope = (f"{model} {fw}" if confirmed
                     else f"{c['vendor']} {', '.join(c['products'][:2])} (version not confirmed)")
            findings.append({
                "kind": "cve", "id": c["id"], "ref": c["advisory"],
                "severity": c["severity"], "cvss": c["cvss"], "kev": c["kev"],
                "cwe": c["cwe"], "title": c["title"], "fix": c["fix"],
                "nca": c["nca"], "confidence": "confirmed" if confirmed else "potential",
                "scope": scope,
            })

        if not findings:
            continue
        crit = CRITICALITY.get(n["role"], 0.4)
        for f in findings:
            base = (f["cvss"] / 10.0) if f["cvss"] else {"high": 0.75, "medium": 0.5, "low": 0.3}.get(f["severity"], 0.5)
            f["priority"] = round((2 if f["kev"] else 0) + base + crit, 3)
        findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), -f["priority"]))
        assets.append({
            "ip": n["ip"], "role": n["role"], "vendor": n.get("vendor") or "unknown",
            "protocols": ot, "top_severity": findings[0]["severity"],
            "findings": findings,
        })

    all_find = [f for a in assets for f in a["findings"]]
    counts = {s: sum(1 for f in all_find if f["severity"] == s)
              for s in ("critical", "high", "medium", "low")}
    assets.sort(key=lambda a: (SEV_RANK.get(a["top_severity"], 9), -CRITICALITY.get(a["role"], 0)))
    return {
        "meta": {"source": src if isinstance(src, str) else "capture",
                 "assets_scanned": len(assets), "findings": len(all_find),
                 "critical": counts["critical"], "high": counts["high"],
                 "medium": counts["medium"], "low": counts["low"],
                 "note": "Firmware versions are not seen passively; product CVEs are potential matches — confirm model/version to finalise."},
        "assets": assets,
    }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_factory.pcap"
    v = build_vuln(path)
    with open("vuln.json", "w", encoding="utf-8") as f:
        json.dump(v, f, indent=2, ensure_ascii=False)
    m = v["meta"]
    print(f"[+] vuln.json — {m['assets_scanned']} assets, {m['findings']} findings "
          f"(crit={m['critical']} high={m['high']} med={m['medium']} low={m['low']})")
    for a in v["assets"]:
        print(f"  {a['ip']:16} {a['role']:14} {a['vendor']}")
        for f in a["findings"]:
            tag = "KEV " if f["kev"] else ""
            cvss = f"CVSS {f['cvss']}" if f["cvss"] else f["severity"]
            print(f"       [{f['severity']:8}] {tag}{f['id']:16} {cvss:10} {f['confidence']:9} {f['title'][:52]}")
