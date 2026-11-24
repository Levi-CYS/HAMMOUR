#!/usr/bin/env python3
"""
HAMMOUR - Synthetic Industrial PCAP Generator
===============================================
Crafts a realistic small-factory OT capture so the HAMMOUR Map module has
something to parse before the real virtual factory is ready.

It models a water-tank station:
  - SCADA server       polls all PLCs      (Purdue L2)
  - HMI panel          reads 1 PLC         (Purdue L2)
  - Engineering WS      programs the PLCs   (Purdue L2, TIA Portal style)
  - 2x Siemens S7 PLC   (Purdue L1)
  - 1x Modbus PLC       (Purdue L1)
  - IT laptop           web + file shares   (Purdue L3/IT)
  - ONE violation:      IT laptop talks S7 straight to a PLC (L3 -> L1)

Protocols are crafted at the byte level on the correct ports so a passive
parser can fingerprint them the same way it would on real traffic:
  S7comm   TCP/102   (COTP + S7 header, function codes)
  Modbus   TCP/502   (MBAP + function code)
  EtherNet/IP TCP/44818 (list identity-ish)
  plus HTTP/SMB/RDP for the IT and engineering hosts.

Output: sample_factory.pcap
"""
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
import random, struct

random.seed(42)

# ---- Asset table: ip -> (mac, label-for-truth-only) -----------------------
# MAC OUIs are real vendor prefixes so the parser's OUI lookup is meaningful.
ASSETS = {
    "192.168.10.10": ("00:1b:1b:11:22:01", "Siemens"),   # S7 PLC 1
    "192.168.10.11": ("00:1b:1b:11:22:02", "Siemens"),   # S7 PLC 2
    "192.168.10.20": ("00:80:f4:aa:bb:01", "Telemecanique/Schneider"),  # Modbus PLC
    "192.168.10.50": ("00:0c:29:33:44:55", "VMware"),     # SCADA server
    "192.168.10.51": ("00:0c:29:33:44:66", "VMware"),     # HMI panel
    "192.168.10.60": ("3c:fd:fe:77:88:99", "Intel"),      # Engineering WS
    "192.168.20.100": ("a4:5e:60:ab:cd:ef", "Apple"),     # IT laptop
}

MAC = {ip: m for ip, (m, _) in ASSETS.items()}

packets = []
_ts = 1_760_000_000.0  # base epoch; monotonically increasing per packet

def _emit(src, dst, pkt):
    """Attach L2/L3, stamp time, append."""
    global _ts
    e = Ether(src=MAC[src], dst=MAC[dst]) / IP(src=src, dst=dst) / pkt
    _ts += round(random.uniform(0.002, 0.05), 4)
    e.time = _ts
    packets.append(e)

# ---- Protocol payload builders -------------------------------------------
def s7_read(sport):
    # COTP data (0x02 0xf0 0x80) + S7 ROSCTR=Job(0x01), func = Read Var (0x04)
    cotp = bytes([0x02, 0xf0, 0x80])
    s7 = bytes([0x32, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x0e, 0x00, 0x00,
                0x04, 0x01, 0x12, 0x0a, 0x10, 0x02])
    return TCP(sport=sport, dport=102, flags="PA") / Raw(cotp + s7)

def s7_response(sport, dport):
    cotp = bytes([0x02, 0xf0, 0x80])
    s7 = bytes([0x32, 0x03, 0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0x00, 0x05,
                0x00, 0x00, 0x04, 0x01, 0xff, 0x04])
    return TCP(sport=102, dport=dport, flags="PA") / Raw(cotp + s7)

def s7_download(sport):
    # S7 Job with function Download (0x1a) - a program change: HIGH interest
    cotp = bytes([0x02, 0xf0, 0x80])
    s7 = bytes([0x32, 0x01, 0x00, 0x00, 0x06, 0x00, 0x00, 0x20, 0x00, 0x00,
                0x1a, 0x00])
    return TCP(sport=sport, dport=102, flags="PA") / Raw(cotp + s7)

def modbus_read(sport, tid):
    # MBAP header + function 0x03 (read holding registers)
    mbap = struct.pack(">HHHB", tid, 0, 6, 1)  # tid, proto, len, unit
    pdu = bytes([0x03, 0x00, 0x00, 0x00, 0x0a])
    return TCP(sport=sport, dport=502, flags="PA") / Raw(mbap + pdu)

def modbus_write(sport, tid):
    # function 0x10 (write multiple registers) - a control action
    mbap = struct.pack(">HHHB", tid, 0, 11, 1)
    pdu = bytes([0x10, 0x00, 0x10, 0x00, 0x02, 0x04, 0x00, 0x64, 0x00, 0xc8])
    return TCP(sport=sport, dport=502, flags="PA") / Raw(mbap + pdu)

def enip_identity(sport):
    # EtherNet/IP List Identity command (0x63)
    enip = struct.pack("<HHIIQ", 0x0063, 0, 0, 0, 0) + b"\x00" * 4
    return TCP(sport=sport, dport=44818, flags="PA") / Raw(enip)

def http_get(sport, dport):
    return TCP(sport=sport, dport=dport, flags="PA") / Raw(
        b"GET /index.html HTTP/1.1\r\nHost: portal\r\n\r\n")

def smb_hello(sport):
    return TCP(sport=sport, dport=445, flags="PA") / Raw(b"\x00\x00\x00\x2f\xffSMB")

def rdp_hello(sport):
    return TCP(sport=sport, dport=3389, flags="PA") / Raw(b"\x03\x00\x00\x13\x0e")

# ---- Traffic scenario -----------------------------------------------------
SCADA = "192.168.10.50"
HMI   = "192.168.10.51"
ENGWS = "192.168.10.60"
PLC1  = "192.168.10.10"
PLC2  = "192.168.10.11"
MB    = "192.168.10.20"
IT    = "192.168.20.100"

# SCADA polls every PLC repeatedly (it's the busy hub -> classified as SCADA)
for i in range(40):
    sp = random.randint(40000, 50000)
    _emit(SCADA, PLC1, s7_read(sp));      _emit(PLC1, SCADA, s7_response(102, sp))
    _emit(SCADA, PLC2, s7_read(sp + 1));  _emit(PLC2, SCADA, s7_response(102, sp + 1))
    _emit(SCADA, MB,   modbus_read(sp + 2, i)); _emit(SCADA, MB, modbus_read(sp + 2, i))

# HMI reads just PLC1 (one upstream link -> HMI)
for i in range(25):
    sp = random.randint(50000, 60000)
    _emit(HMI, PLC1, s7_read(sp)); _emit(PLC1, HMI, s7_response(102, sp))

# Engineering WS: programs PLC1 & PLC2 (download block) + EtherNet/IP identity
for i in range(6):
    sp = random.randint(60000, 61000)
    _emit(ENGWS, PLC1, s7_download(sp))
    _emit(ENGWS, PLC2, s7_download(sp + 1))
    _emit(ENGWS, PLC1, enip_identity(sp + 2))
# Eng WS also does normal reads
for i in range(10):
    sp = random.randint(61000, 62000)
    _emit(ENGWS, PLC1, s7_read(sp)); _emit(PLC1, ENGWS, s7_response(102, sp))

# IT laptop: normal enterprise traffic to the Eng WS (web/smb/rdp)
for i in range(15):
    sp = random.randint(30000, 40000)
    _emit(IT, ENGWS, http_get(sp, 80))
    _emit(IT, ENGWS, smb_hello(sp + 1))
    _emit(IT, ENGWS, rdp_hello(sp + 2))

# --- THE VIOLATION: IT laptop (L3) talks S7 straight to PLC2 (L1) ----------
for i in range(4):
    sp = random.randint(45000, 46000)
    _emit(IT, PLC2, s7_read(sp)); _emit(PLC2, IT, s7_response(102, sp))
# ...and even pushes a Modbus write to the Modbus PLC
_emit(IT, MB, modbus_write(random.randint(46000, 47000), 999))

# Sort by time and write
packets.sort(key=lambda p: p.time)
wrpcap("sample_factory.pcap", packets)
print(f"Wrote sample_factory.pcap  ({len(packets)} packets, {len(ASSETS)} hosts)")
