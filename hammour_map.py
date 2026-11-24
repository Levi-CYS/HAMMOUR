#!/usr/bin/env python3
"""
HAMMOUR — Map module (passive discovery + role classification)
==============================================================
Reads a PCAP, builds an asset inventory and a communication graph, classifies
each host's OT role with a confidence score and human-readable evidence, and
flags Purdue-level violations.

100% passive: it only reads the capture, never sends a packet.

Usage:
    python3 hammour_map.py sample_factory.pcap            # -> network.json + map.html
    python3 hammour_map.py capture.pcap -o out.html
    python3 hammour_map.py capture.pcap --json-only

Design notes:
  * No single signal decides a role. We gather evidence (protocols spoken,
    client vs server direction, enterprise ports, OUI) and score each role.
    The winning role carries a confidence % and the reasons behind it, so the
    engineer can see WHY and override if wrong.
  * Firmware/model are left blank when the passive capture doesn't reveal them
    (honest: the Map module discovers presence and role; the Vuln module later
    fills model/version from CSAF + optional manual import).
"""
import argparse, json, struct
from collections import defaultdict, Counter

from scapy.all import rdpcap, IP, TCP, UDP, Ether, Raw

# --- Industrial / enterprise port map -------------------------------------
OT_PORTS = {
    102:   "S7comm",          # Siemens
    502:   "Modbus",
    44818: "EtherNet/IP",
    20000: "DNP3",
    2404:  "IEC 60870-5-104",
    4840:  "OPC UA",
    1911:  "Niagara Fox",
    47808: "BACnet",
}
IT_PORTS = {80: "HTTP", 443: "HTTPS", 445: "SMB", 139: "SMB",
            3389: "RDP", 22: "SSH", 53: "DNS", 135: "RPC"}

# --- OUI -> vendor (minimal built-in table; extend freely) ----------------
OUI = {
    "00:1b:1b": "Siemens",
    "00:0e:8c": "Siemens",
    "28:63:36": "Siemens",
    "00:80:f4": "Schneider/Telemecanique",
    "00:a0:45": "Phoenix Contact",
    "00:1d:9c": "Rockwell/Allen-Bradley",
    "00:00:bc": "Rockwell/Allen-Bradley",
    "00:0c:29": "VMware (virtual host)",
    "00:50:56": "VMware (virtual host)",
    "3c:fd:fe": "Intel",
    "a4:5e:60": "Apple",
}

# --- S7 / Modbus function-code meaning (for later Hunt module, surfaced now)
S7_FUNCS = {0x04: "Read Var", 0x05: "Write Var", 0x1a: "Download (program)",
            0x1b: "Download block", 0x1d: "Upload", 0x28: "PLC STOP",
            0x29: "PLC START"}
MODBUS_FUNCS = {0x03: "Read Holding Regs", 0x06: "Write Single Reg",
                0x10: "Write Multiple Regs", 0x05: "Write Single Coil",
                0x0f: "Write Multiple Coils"}


def is_private(ip):
    """RFC1918 / link-local / loopback = internal network."""
    try:
        o = [int(x) for x in ip.split(".")]
    except ValueError:
        return True
    if len(o) != 4:
        return True
    return (o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31) or
            (o[0] == 192 and o[1] == 168) or o[0] == 127 or
            (o[0] == 169 and o[1] == 254))


def _port_name(pt):
    return OT_PORTS.get(pt) or IT_PORTS.get(pt) or f"port {pt}"


def oui_vendor(mac):
    if not mac:
        return None
    return OUI.get(mac.lower()[:8])


def _s7_func(raw):
    # locate the S7 header (0x32) after COTP; return function byte if a Job.
    # S7 header: [0]=0x32 [1]=ROSCTR [2-3]=reserved [4-5]=pduref
    # [6-7]=param len [8-9]=data len [10]=function code (first param byte)
    i = raw.find(b"\x32")
    if i >= 0 and len(raw) > i + 10 and raw[i + 1] == 0x01:
        return raw[i + 10]
    return None


def _modbus_func(raw):
    # MBAP is 7 bytes, function code is byte 7
    if len(raw) >= 8 and raw[2] == 0x00 and raw[3] == 0x00:
        return raw[7]
    return None


class Host:
    def __init__(self, ip):
        self.ip = ip
        self.mac = None
        self.vendor = None
        self.pkts = 0
        self.ot_proto = set()          # OT protocols seen on this host (any dir)
        self.it_proto = set()
        self.serves_ot = set()         # OT protocols where host is the SERVER
        self.ot_client_pkts = 0        # pkts where host acts as OT client
        self.it_pkts = 0               # pkts of enterprise traffic
        self.l4_pkts = 0               # any TCP/UDP activity (client or server)
        self.listen_ports = Counter()  # ports this host was contacted ON (services)
        self.talks_to = defaultdict(int)   # peer_ip -> packet count (outbound)
        self.funcs = set()             # notable function codes (meaning strings)
        self.product = None            # fingerprinted product/model name
        self.firmware = None           # fingerprinted firmware/revision
        # role scoring filled later
        self.role = "Unknown"
        self.confidence = 0
        self.reasons = []
        self.level = None              # Purdue level


def _fp_enip_identity(raw):
    """EtherNet/IP List Identity reply -> (product_name, 'rev major.minor')."""
    if len(raw) < 64 or (raw[0] | (raw[1] << 8)) != 0x0063:
        return None
    try:
        rev = f"Rev {raw[54]}.{raw[55]}"
        nlen = raw[62]
        name = raw[63:63 + nlen].decode("ascii", "ignore").strip()
        if name and all(32 <= ord(c) < 127 for c in name):
            return (name, rev)
    except Exception:
        return None
    return None


def _fp_modbus_devid(raw):
    """Modbus Read Device ID (fn 0x2B / MEI 0x0E) reply -> (product, version)."""
    if len(raw) < 11 or raw[7] != 0x2b or raw[8] != 0x0e:
        return None
    # MBAP(7) + func + MEI + readcode + conformity + more + nextobj + numobj = 14
    i, objs = 14, []
    while i + 2 <= len(raw):
        olen = raw[i + 1]
        val = raw[i + 2:i + 2 + olen].decode("ascii", "ignore")
        if val:
            objs.append(val)
        i += 2 + olen
        if len(objs) >= 4:
            break
    if objs:
        product = " ".join(objs[:2]).strip()
        version = objs[2].strip() if len(objs) > 2 else None
        return (product or None, version)
    return None


def parse(src):
    # src may be a file path (str) or already-loaded packets, so a caller that
    # also needs the packets (e.g. Hunt) can read the capture only once.
    pkts = rdpcap(src) if isinstance(src, str) else src
    hosts = {}

    def H(ip):
        if ip not in hosts:
            hosts[ip] = Host(ip)
        return hosts[ip]

    edges = defaultdict(lambda: {"count": 0, "protocols": set()})

    for p in pkts:
        if IP not in p:
            continue
        src, dst = p[IP].src, p[IP].dst
        hs, hd = H(src), H(dst)
        hs.pkts += 1
        if Ether in p:
            if not hs.mac:
                hs.mac = p[Ether].src
            if not hd.mac:
                hd.mac = p[Ether].dst

        proto_name = None
        if TCP in p or UDP in p:
            l4 = p[TCP] if TCP in p else p[UDP]
            sport, dport = int(l4.sport), int(l4.dport)
            raw = bytes(p[Raw].load) if Raw in p else b""
            hs.l4_pkts += 1; hd.l4_pkts += 1
            # the lower port is almost always the listening service side
            svc = min(sport, dport)
            (hd if dport <= sport else hs).listen_ports[svc] += 1

            # device fingerprinting: identity replies come FROM the device (src)
            if raw:
                fp = None
                if sport == 44818:
                    fp = _fp_enip_identity(raw)
                elif sport == 502:
                    fp = _fp_modbus_devid(raw)
                if fp:
                    if fp[0] and not hs.product:
                        hs.product = fp[0]
                    if fp[1] and not hs.firmware:
                        hs.firmware = fp[1]

            # OT: classify by the well-known server port (the lower/standard side)
            for port, name in OT_PORTS.items():
                if dport == port:
                    proto_name = name
                    hs.ot_proto.add(name); hd.ot_proto.add(name)
                    hd.serves_ot.add(name)      # dst is the server (PLC)
                    hs.ot_client_pkts += 1      # src is the OT client
                    # decode a couple of function codes for context
                    if name == "S7comm":
                        f = _s7_func(raw)
                        if f in S7_FUNCS:
                            hs.funcs.add(f"S7: {S7_FUNCS[f]}")
                    elif name == "Modbus":
                        f = _modbus_func(raw)
                        if f in MODBUS_FUNCS:
                            hs.funcs.add(f"Modbus: {MODBUS_FUNCS[f]}")
                    break
                elif sport == port:
                    proto_name = name
                    hs.ot_proto.add(name); hd.ot_proto.add(name)
                    hs.serves_ot.add(name)      # src is the server
                    break
            # IT ports
            if proto_name is None:
                for port, name in IT_PORTS.items():
                    if dport == port or sport == port:
                        proto_name = name
                        hs.it_proto.add(name); hd.it_proto.add(name)
                        hs.it_pkts += 1
                        break

        hs.talks_to[dst] += 1
        key = tuple(sorted((src, dst)))
        edges[key]["count"] += 1
        if proto_name:
            edges[key]["protocols"].add(proto_name)

    for h in hosts.values():
        h.vendor = oui_vendor(h.mac)

    return hosts, edges


# --- Role classification ---------------------------------------------------
def _subnet(ip):
    return ".".join(ip.split(".")[:3])


def classify(hosts):
    # Which /24 holds the most PLCs? That's the "OT subnet"; hosts outside it
    # that still speak OT are suspicious.
    plc_subnets = defaultdict(int)
    for h in hosts.values():
        if h.serves_ot:
            plc_subnets[_subnet(h.ip)] += 1
    ot_subnet = max(plc_subnets, key=plc_subnets.get) if plc_subnets else None

    # Local subnets = /24s the plant actually uses (several hosts, or an OT device),
    # even when they sit in public IANA space (common in ICS, e.g. 141.81.x).
    sub_count = Counter(_subnet(ip) for ip in hosts)
    ot_subnets = {_subnet(h.ip) for h in hosts.values() if h.serves_ot}
    local_subnets = {s for s, c in sub_count.items() if c >= 3} | ot_subnets

    # Enterprise protocols that a legit HMI/SCADA/PLC never originates as a client
    WORKSTATION_PROTO = {"SMB", "RDP", "SSH", "HTTP", "HTTPS", "RPC"}

    for h in hosts.values():
        scores = defaultdict(int)
        reasons = defaultdict(list)
        n_ot_peers = sum(1 for peer in h.talks_to
                         if peer in hosts and hosts[peer].serves_ot)
        serves = bool(h.serves_ot)
        speaks_ot = bool(h.ot_proto)
        speaks_it = bool(h.it_proto)
        prog = any("Download" in f or "Upload" in f for f in h.funcs)
        ws_proto = h.it_proto & WORKSTATION_PROTO
        # does enterprise traffic dominate this host's conversations?
        it_dominant = h.it_pkts > h.ot_client_pkts

        # ---- External / Internet: public address outside the plant --------
        # An internet endpoint is not a plant IT asset even if it speaks HTTP,
        # so this decision comes first and overrides the IT rule. A public host
        # that actually *serves* OT is a field device, so it's excluded here.
        external = (not is_private(h.ip)) and (_subnet(h.ip) not in local_subnets)
        if external and not serves:
            top = ", ".join(_port_name(pt) for pt, _ in h.listen_ports.most_common(3))
            r = ["outside the plant's local subnets (public address)"]
            if top:
                r.append(f"services: {top}")
            h.role, h.confidence, h.reasons = "External / Internet", 90, r
            continue

        # ---- PLC: answers OT requests (acts as server) --------------------
        if serves:
            scores["PLC"] += 60
            reasons["PLC"].append(f"responds to {', '.join(sorted(h.serves_ot))} (acts as server)")
            if h.vendor and any(v in (h.vendor or "") for v in
                                ("Siemens", "Schneider", "Rockwell", "Phoenix")):
                scores["PLC"] += 25
                reasons["PLC"].append(f"industrial vendor MAC ({h.vendor})")

        # ---- IT / Enterprise: enterprise protocols dominate ---------------
        if ws_proto and (not speaks_ot or it_dominant) and not serves and not prog:
            scores["IT/Enterprise"] += 65
            reasons["IT/Enterprise"].append(
                f"enterprise protocols dominate ({', '.join(sorted(ws_proto))})")
            if ot_subnet and _subnet(h.ip) != ot_subnet:
                scores["IT/Enterprise"] += 15
                reasons["IT/Enterprise"].append(
                    f"sits outside the OT subnet ({_subnet(h.ip)}.0/24)")

        # ---- Engineering WS: programs PLCs --------------------------------
        if prog:
            scores["Engineering WS"] += 75
            reasons["Engineering WS"].append("issues program download/upload to PLC(s)")
            if speaks_it:
                scores["Engineering WS"] += 10
                reasons["Engineering WS"].append("mixes OT programming with IT protocols")

        # ---- SCADA: OT client to MANY PLCs --------------------------------
        if speaks_ot and n_ot_peers >= 3 and not serves and not prog and not it_dominant:
            scores["SCADA Server"] += 70
            reasons["SCADA Server"].append(f"polls {n_ot_peers} PLCs as a client")

        # ---- HMI: OT client to 1–2 PLCs, OT-dominant ----------------------
        if speaks_ot and 1 <= n_ot_peers <= 2 and not serves and not prog and not it_dominant:
            scores["HMI"] += 55
            reasons["HMI"].append(f"reads {n_ot_peers} PLC(s) as a client")

        # ---- fallbacks so few hosts stay "Unknown" ------------------------
        if not scores:
            top = ", ".join(_port_name(pt) for pt, _ in h.listen_ports.most_common(3))
            local = _subnet(h.ip) in local_subnets
            if not local and not is_private(h.ip):
                scores["External / Internet"] += 50
                reasons["External / Internet"].append("outside the plant's local subnets (public address)")
                if top:
                    reasons["External / Internet"].append(f"services: {top}")
            elif h.l4_pkts > 0:
                scores["IT / Host"] += 45
                reasons["IT / Host"].append(
                    f"host on the local network, non-industrial traffic ({top})" if top
                    else "host on the local network, non-industrial traffic")
            elif h.pkts > 0:
                # active host, but only non-TCP/UDP traffic (ICMP, ARP, etc.)
                scores["IT / Host"] += 40
                reasons["IT / Host"].append("active host, only non-TCP/UDP traffic (ICMP/ARP)")
            else:
                h.role, h.confidence, h.reasons = "Unknown", 0, ["seen only via ARP/broadcast; no traffic to classify"]
                continue

        role = max(scores, key=scores.get)
        raw = scores[role]
        total = sum(scores.values()) or 1
        conf = min(99, int(40 + 0.5 * raw + 25 * (raw / total)))
        h.role, h.confidence, h.reasons = role, conf, reasons[role]

    # Purdue level from role
    LEVEL = {"IT/Enterprise": "Level 4/5 — Enterprise IT",
             "IT / Host": "Level 4/5 — Enterprise IT",
             "SCADA Server": "Level 2 — Supervisory",
             "HMI": "Level 2 — Supervisory",
             "Engineering WS": "Level 2 — Supervisory",
             "PLC": "Level 1 — Control",
             "External / Internet": "External",
             "Unknown": "Unassigned"}
    for h in hosts.values():
        h.level = LEVEL.get(h.role, "Unassigned")


# --- Purdue violation detection -------------------------------------------
LEVEL_RANK = {"External": 5, "Level 4/5 — Enterprise IT": 4, "Level 2 — Supervisory": 2,
              "Level 1 — Control": 1, "Unassigned": 99}


def find_violations(hosts, edges):
    violations = []
    for (a, b), meta in edges.items():
        if a not in hosts or b not in hosts:
            continue
        ha, hb = hosts[a], hosts[b]
        ra, rb = LEVEL_RANK.get(ha.level, 99), LEVEL_RANK.get(hb.level, 99)
        ot = [p for p in meta["protocols"] if p in OT_PORTS.values()]
        # An Enterprise (L4/5) OR External host speaking OT straight to a
        # Control-level device skips the supervisory layer = segmentation break.
        hi, lo = max(ra, rb), min(ra, rb)
        if ot and hi >= 4 and lo == 1:
            src = a if ra >= 4 else b
            plc = b if ra >= 4 else a
            zone = "External" if hi == 5 else "Enterprise"
            violations.append({
                "severity": "high",
                "from": src, "to": plc,
                "protocols": sorted(ot),
                "title": f"{zone} host talks industrial protocol directly to a controller",
                "detail": f"{src} ({zone}) reached {plc} (Control) over "
                          f"{', '.join(sorted(ot))}, skipping the supervisory layer. "
                          f"This breaks Purdue segmentation (maps to NCA OTCC network "
                          f"segregation controls)."
            })
    return violations


def is_asset_ip(ip):
    """Exclude non-asset addresses: multicast, broadcast, unspecified."""
    try:
        o = [int(x) for x in ip.split(".")]
    except ValueError:
        return True
    if len(o) != 4:
        return True
    if 224 <= o[0] <= 239:      # multicast
        return False
    if o[0] == 0 or ip == "255.255.255.255":
        return False
    if o[3] == 255:             # /24 broadcast (good enough for OT LANs)
        return False
    return True


def build_model(src):
    hosts, edges = parse(src)
    pcap_path = src if isinstance(src, str) else "capture"
    # drop non-asset addresses (multicast / broadcast) before classifying
    hosts = {ip: h for ip, h in hosts.items() if is_asset_ip(ip)}
    edges = {k: v for k, v in edges.items() if is_asset_ip(k[0]) and is_asset_ip(k[1])}
    classify(hosts)
    violations = find_violations(hosts, edges)
    viol_pairs = {tuple(sorted((v["from"], v["to"]))) for v in violations}

    risk_of = {}
    for h in hosts.values():
        if any(h.ip in pair for pair in viol_pairs):
            risk_of[h.ip] = "high"
        elif h.role == "PLC":
            risk_of[h.ip] = "medium"       # exposed control asset, watch it
        else:
            risk_of[h.ip] = "low"

    nodes = []
    for h in sorted(hosts.values(), key=lambda x: x.ip):
        nodes.append({
            "ip": h.ip, "mac": h.mac, "vendor": h.vendor,
            "role": h.role, "confidence": h.confidence, "reasons": h.reasons,
            "level": h.level, "packets": h.pkts,
            "protocols": sorted(h.ot_proto | h.it_proto),
            "ot_protocols": sorted(h.ot_proto),
            "functions": sorted(h.funcs),
            "ports": [_port_name(pt) for pt, _ in h.listen_ports.most_common(6)],
            "product": h.product, "firmware": h.firmware,
            "risk": risk_of[h.ip],
        })
    links = []
    for (a, b), meta in sorted(edges.items()):
        links.append({
            "source": a, "target": b, "count": meta["count"],
            "protocols": sorted(meta["protocols"]),
            "violation": tuple(sorted((a, b))) in viol_pairs,
        })

    return {
        "meta": {
            "source": pcap_path,
            "hosts": len(nodes),
            "flows": len(links),
            "violations": len(violations),
        },
        "nodes": nodes, "links": links, "violations": violations,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="HAMMOUR Map — passive OT discovery")
    ap.add_argument("pcap")
    ap.add_argument("-o", "--output", default="map.html")
    ap.add_argument("--json-only", action="store_true")
    args = ap.parse_args()

    model = build_model(args.pcap)
    with open("network.json", "w") as f:
        json.dump(model, f, indent=2, ensure_ascii=False)
    print(f"[+] network.json written — {model['meta']['hosts']} hosts, "
          f"{model['meta']['flows']} flows, {model['meta']['violations']} violation(s)")

    if not args.json_only:
        from render_map import render
        from hammour_hunt import build_hunt
        from hammour_vuln import build_vuln
        hunt = build_hunt(args.pcap, model)   # Hunt tab
        vuln = build_vuln(args.pcap, model)   # Vuln tab
        render(model, args.output, hunt, vuln)
        print(f"[+] {args.output} written — Map + Hunt + Vuln "
              f"({hunt['meta']['high']} hunt-high / {vuln['meta']['high']+vuln['meta']['critical']} vuln-high+crit)")
