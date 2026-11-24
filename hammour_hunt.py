#!/usr/bin/env python3
"""
HAMMOUR — Hunt module (threat detection)
========================================
Map answers "who is on the network". Hunt answers "what dangerous thing is
happening". It opens the OT payloads, reads the actual commands, and raises
alerts, each mapped to MITRE ATT&CK for ICS and NCA OTCC controls.

Engines, combined:
  * RULES     — commands dangerous by nature (STOP, program download, writes).
                Deep-decoded for S7comm, Modbus, DNP3 and (best-effort) EtherNet/IP.
  * COVERAGE  — any OT-protocol access from a non-supervisory source is flagged
                even when the specific command can't be decoded, so an
                unauthorised path never slips through (and Map's red lines always
                surface here too).
  * BASELINE  — learns the legit controllers (SCADA / HMI / Eng-WS from Map) and,
                within a learning window, the normal control tuples; flags
                control from unexpected sources, new control behaviour from a
                known device, and scanning.
  * CHAINS    — correlates discovery + a control command from the same source.

Usage:
    python3 hammour_hunt.py capture.pcap             # -> hunt.json

Passive only: it never sends a packet.
"""
import json
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import rdpcap, IP, TCP, Raw
from hammour_map import build_model, OT_PORTS

# ---- command catalogues: code -> (label, category) ------------------------
# category drives base severity: program/mode high, write medium/high, read info
S7_CMD = {
    0x04: ("S7 Read Var", "read"), 0x05: ("S7 Write Var", "write"),
    0x1a: ("S7 Request Download", "program"), 0x1b: ("S7 Download Block", "program"),
    0x1c: ("S7 Download Ended", "program"), 0x1d: ("S7 Start Upload", "program"),
    0x1e: ("S7 Upload", "program"), 0x1f: ("S7 End Upload", "program"),
    0x28: ("S7 PLC Control", "mode"), 0x29: ("S7 PLC Stop", "mode"),
}
MODBUS_CMD = {
    0x01: ("Modbus Read Coils", "read"), 0x02: ("Modbus Read Discrete Inputs", "read"),
    0x03: ("Modbus Read Holding Regs", "read"), 0x04: ("Modbus Read Input Regs", "read"),
    0x05: ("Modbus Write Single Coil", "write"), 0x06: ("Modbus Write Single Reg", "write"),
    0x0f: ("Modbus Write Multiple Coils", "write"), 0x10: ("Modbus Write Multiple Regs", "write"),
    0x08: ("Modbus Diagnostics", "mode"),
}
DNP3_CMD = {
    0x01: ("DNP3 Read", "read"), 0x02: ("DNP3 Write", "write"),
    0x03: ("DNP3 Select", "write"), 0x04: ("DNP3 Operate", "write"),
    0x05: ("DNP3 Direct Operate", "write"), 0x06: ("DNP3 Direct Operate (no ack)", "write"),
    0x0d: ("DNP3 Cold Restart", "mode"), 0x0e: ("DNP3 Warm Restart", "mode"),
    0x12: ("DNP3 Stop Application", "mode"),
}
# EtherNet/IP CIP service codes (request side)
ENIP_CMD = {
    0x4c: ("CIP Read Tag", "read"), 0x52: ("CIP Read Tag Fragmented", "read"),
    0x0e: ("CIP Get Attribute", "read"), 0x55: ("CIP Get Instance Attr List", "read"),
    0x4d: ("CIP Write Tag", "write"), 0x53: ("CIP Write Tag Fragmented", "write"),
    0x10: ("CIP Set Attribute", "write"), 0x4e: ("CIP Read-Modify-Write", "write"),
    0x05: ("CIP Reset", "mode"), 0x06: ("CIP Start", "mode"), 0x07: ("CIP Stop", "mode"),
}

# ---- ATT&CK for ICS + NCA OTCC mapping ------------------------------------
# IDs verified against attack.mitre.org/techniques/ics and NCA OTCC (otcc_en).
MAP = {
    "program": {"attack": [("T0843", "Program Download")],
                "nca": ["1-5-3 (change management: validate changes)",
                        "1-5-3-5 (automated change detection)"]},
    "mode": {"attack": [("T0858", "Change Operating Mode"), ("T0816", "Device Restart/Shutdown")],
             "nca": ["2-2-1 (identity & access to OT)", "2-11-1 (logging & monitoring)"]},
    "write": {"attack": [("T0836", "Modify Parameter")],
              "nca": ["2-2-1 (identity & access to OT)", "2-11-1 (logging & monitoring)"]},
    "unauthorized": {"attack": [("T0855", "Unauthorized Command Message"), ("T0831", "Manipulation of Control")],
                     "nca": ["2-4-1-9 (no direct corporate-to-OT; use DMZ jump host)",
                             "2-2-1 (identity & access to OT)"]},
    "access": {"attack": [("T0855", "Unauthorized Command Message")],
               "nca": ["2-4-1-9 (no direct corporate-to-OT; use DMZ jump host)",
                       "2-11-1 (logging & monitoring)"]},
    "recon": {"attack": [("T0846", "Remote System Discovery")],
              "nca": ["2-11-1 (logging & monitoring)", "2-4-1-2 (zone segmentation)"]},
    "newbehavior": {"attack": [("T0836", "Modify Parameter")],
                    "nca": ["1-5-3-5 (automated change detection)", "2-11-1 (logging & monitoring)"]},
}
SUPERVISORY = {"SCADA Server", "HMI", "Engineering WS"}
SCAN_FANOUT = 5
LEARN_FRACTION = 0.2    # first 20% of the timeline is the baseline window


def _s7_cmd(raw):
    i = raw.find(b"\x32")
    if i < 0 or len(raw) <= i + 1:
        return None
    if raw[i + 1] == 0x01 and len(raw) > i + 10:       # ROSCTR = Job
        c = S7_CMD.get(raw[i + 10])
        if c:
            return c
    # S7comm-plus (S7-1200/1500) uses protocol id 0x72 — not deep-decoded
    if raw.find(b"\x72") >= 0 and b"\x32" not in raw[:3]:
        return ("S7comm-plus session", "access")
    return None


def _modbus_cmd(raw):
    if len(raw) >= 8 and raw[2] == 0x00 and raw[3] == 0x00:   # MBAP proto id = 0
        return MODBUS_CMD.get(raw[7])
    return None


def _dnp3_cmd(raw):
    i = raw.find(b"\x05\x64")
    if i < 0 or len(raw) <= i + 12:
        return None
    func = raw[i + 12]                 # app function code (after 10B hdr + transport + app ctrl)
    if func >= 0x80:                   # responses have high codes; we want requests
        return None
    return DNP3_CMD.get(func)


def _enip_cmd(raw):
    # EtherNet/IP encapsulation: command (LE) at 0..2
    if len(raw) < 26:
        return None
    cmd = raw[0] | (raw[1] << 8)
    if cmd == 0x006f:          # SendRRData (unconnected): CIP service at offset 40
        off = 40
    elif cmd == 0x0070:        # SendUnitData (connected): CIP service at offset 46
        off = 46
    else:
        return None
    if len(raw) <= off:
        return None
    svc = raw[off] & 0x7f       # strip reply bit
    if raw[off] & 0x80:         # reply, not a request
        return None
    return ENIP_CMD.get(svc)


def _decode(dport, raw):
    """Return (label, category) for an OT request, or a generic access event."""
    proto = OT_PORTS.get(dport)
    if proto is None:
        return None
    if dport == 102:
        c = _s7_cmd(raw)
    elif dport == 502:
        c = _modbus_cmd(raw)
    elif dport == 20000:
        c = _dnp3_cmd(raw)
    elif dport == 44818:
        c = _enip_cmd(raw)
    else:
        c = None
    if c:
        return c
    # known OT port but command not decoded -> generic access (coverage net)
    return (f"{proto} access", "access")


def _fmt_time(ts):
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%H:%M:%S")
    except Exception:
        return "--:--:--"


def build_hunt(src, model=None):
    pkts = rdpcap(src) if isinstance(src, str) else src
    if model is None:
        model = build_model(pkts)
    role_of = {n["ip"]: n["role"] for n in model["nodes"]}
    normal_src = {ip for ip, r in role_of.items() if r in SUPERVISORY}

    # collect OT events (any OT port; deep-decoded where possible)
    events = defaultdict(lambda: {"count": 0, "first": None, "last": None})
    fanout = defaultdict(set)
    for p in pkts:
        if IP not in p or TCP not in p or Raw not in p:
            continue
        dport = int(p[TCP].dport)
        if dport not in OT_PORTS:
            continue
        dec = _decode(dport, bytes(p[Raw].load))
        if not dec:
            continue
        srcip, dstip = p[IP].src, p[IP].dst
        label, cat = dec
        fanout[srcip].add(dstip)
        e = events[(srcip, dstip, label, cat)]
        e["count"] += 1
        t = float(p.time)
        e["first"] = t if e["first"] is None else min(e["first"], t)
        e["last"] = t if e["last"] is None else max(e["last"], t)

    # baseline learning window: tuples seen in the first LEARN_FRACTION of time
    firsts = [e["first"] for e in events.values() if e["first"]]
    learn_tuples = set()
    if len(events) >= 30 and firsts:
        t0, t1 = min(firsts), max(e["last"] for e in events.values())
        cut = t0 + LEARN_FRACTION * (t1 - t0)
        learn_tuples = {(s, d, l) for (s, d, l, c), e in events.items() if e["first"] <= cut}

    CONTROL = ("write", "program", "mode")
    alerts = []
    for (srcip, dstip, label, cat), e in events.items():
        anomalous = srcip not in normal_src
        why, extra, situation = [], None, cat

        if cat == "read":
            if not anomalous:
                continue                     # routine reads are noise
            situation, severity = "recon", "medium"
            why.append(f"{role_of.get(srcip,'unknown')} reading OT data it normally wouldn't")
        elif cat == "access":
            if not anomalous:
                continue                     # expected supervisory access we can't decode
            situation, severity = "access", "high"
            why.append(f"{role_of.get(srcip,'unknown')} reaching a controller over {label}, an unauthorised path")
        elif cat == "program":
            situation, severity = "program", "high"
            why.append("program download/upload changes the PLC logic itself")
        elif cat == "mode":
            situation, severity = "mode", "high"
            why.append("changes the controller's run state (can halt the process)")
        else:  # write
            if anomalous:
                situation, severity = "write", "high"
                why.append("writes a value into the controller")
            else:
                situation, severity = "write", "low"
                why.append("routine control write from a supervisory device (expected)")

        # baseline escalation: control from a non-supervisory source
        if anomalous and cat in CONTROL:
            severity, extra = "high", "unauthorized"
            why.append(f"source is {role_of.get(srcip,'unknown')}, not a supervisory device")

        # behavioural baseline: a known device doing a control action not seen
        # during the learning window
        new_behavior = (learn_tuples and not anomalous and cat in CONTROL
                        and (srcip, dstip, label) not in learn_tuples)
        if new_behavior and severity == "low":
            situation, severity = "newbehavior", "medium"
            why.append("new control behaviour: not seen during the baseline window")
        elif new_behavior:
            why.append("also new vs the baseline window")

        attack = list(MAP[situation]["attack"])
        nca = list(MAP[situation]["nca"])
        if extra:
            attack += MAP[extra]["attack"]
            nca = MAP[extra]["nca"] + nca
        attack = list(dict.fromkeys(attack))
        nca = list(dict.fromkeys(nca))

        alerts.append({
            "severity": severity, "src": srcip, "src_role": role_of.get(srcip, "unknown"),
            "dst": dstip, "dst_role": role_of.get(dstip, "unknown"),
            "command": label, "count": e["count"],
            "first": _fmt_time(e["first"]), "last": _fmt_time(e["last"]), "ts": e["first"] or 0,
            "attack": [{"id": i, "name": n} for i, n in attack], "nca": nca,
            "why": "; ".join(why), "chain": False,
        })

    # scanning / discovery
    recon_srcs = set()
    for s, dsts in fanout.items():
        if len(dsts) >= SCAN_FANOUT and s not in normal_src:
            recon_srcs.add(s)
            alerts.append({
                "severity": "medium", "src": s, "src_role": role_of.get(s, "unknown"),
                "dst": f"{len(dsts)} devices", "dst_role": "multiple",
                "command": "OT discovery / scan", "count": len(dsts),
                "first": "--:--:--", "last": "--:--:--", "ts": 0,
                "attack": [{"id": i, "name": n} for i, n in MAP["recon"]["attack"]],
                "nca": MAP["recon"]["nca"],
                "why": f"one source touched {len(dsts)} OT devices, a scanning pattern",
                "chain": False,
            })
    recon_srcs |= {a["src"] for a in alerts if a["command"] != "OT discovery / scan"
                   and any(t["id"] == "T0846" for t in a["attack"])}

    # attack-chain correlation: discovery + a high command from the same source
    chains = 0
    for a in alerts:
        if a["severity"] == "high" and a["src"] in recon_srcs:
            a["chain"] = True
            a["why"] += "; part of a pattern — this source also performed OT discovery"
            chains += 1

    order = {"high": 0, "medium": 1, "low": 2}
    alerts.sort(key=lambda a: (0 if a["chain"] else 1, order.get(a["severity"], 9), a["ts"]))
    counts = {s: sum(1 for a in alerts if a["severity"] == s) for s in ("high", "medium", "low")}

    return {
        "meta": {"source": src if isinstance(src, str) else "capture", "alerts": len(alerts),
                 "high": counts["high"], "medium": counts["medium"], "low": counts["low"],
                 "chains": chains, "controllers": sorted(normal_src)},
        "alerts": alerts,
    }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_factory.pcap"
    h = build_hunt(path)
    with open("hunt.json", "w", encoding="utf-8") as f:
        json.dump(h, f, indent=2, ensure_ascii=False)
    m = h["meta"]
    print(f"[+] hunt.json — {m['alerts']} alerts "
          f"(high={m['high']} medium={m['medium']} low={m['low']} chains={m['chains']})")
    for a in h["alerts"][:14]:
        tag = "CHAIN " if a["chain"] else ""
        print(f"  [{a['severity'].upper():6}] {tag}{a['src']} -> {str(a['dst']):16} {a['command']:30} "
              f"{','.join(x['id'] for x in a['attack'])}")
