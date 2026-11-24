#!/usr/bin/env python3
"""
HAMMOUR — Map renderer (v2)
===========================
Branded, self-contained HTML network map.
  * card-style device nodes (icon + IP + role, risk accent)
  * curved bezier edges (no messy crossings), violations animated in red
  * Purdue-layered bands with a segmentation boundary
  * the real HAMMOUR logo in the header
  * depth-gradient background (surface IT -> deep control)
Click any device for its evidence card.
"""
import json, html, os, base64

BRAND = "#04DE6F"

# band order, display name, accent colour (cool at top -> green/teal in OT)
BANDS = [
    ("External",                  "External / Internet", "#6E88A6"),
    ("Level 4/5 — Enterprise IT", "IT / Enterprise", "#8FB4D6"),
    ("Level 2 — Supervisory",     "Supervisory",     "#04DE6F"),
    ("Level 1 — Control",         "Control",         "#15C08C"),
    ("Unassigned",                "Unassigned",      "#7C9388"),
]
RISK_COLOR = {"high": "#FF5368", "medium": "#F2A93B", "low": "#04DE6F"}
ROLE_SHAPE = {"PLC": "plc", "SCADA Server": "scada", "HMI": "hmi",
              "Engineering WS": "engws", "IT/Enterprise": "it", "IT / Host": "host",
              "External / Internet": "cloud", "Unknown": "unknown"}

W = 1200
BAND_H = 180
PAD_TOP = 44
CARD_W = 170
CARD_H = 58


def _b64_logo():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo_b64.txt")
    try:
        return open(p).read().strip()
    except FileNotFoundError:
        return ""


def _layout(model):
    """Lay nodes into Purdue bands; wrap a crowded band into several rows."""
    present = [b for b in BANDS if any(n["level"] == b[0] for n in model["nodes"])]
    x0, x1 = 150, W - 40            # usable horizontal span for cards
    min_pitch = CARD_W + 26         # min horizontal centre-to-centre spacing
    max_cols = max(1, int((x1 - x0) / min_pitch))
    row_h = CARD_H + 34             # vertical spacing between wrapped rows

    pos = {}
    band_rows = {}                  # band -> number of rows it uses
    for b in present:
        members = sorted([n for n in model["nodes"] if n["level"] == b[0]],
                         key=lambda n: n["ip"])
        k = len(members)
        cols = min(k, max_cols)
        rows = (k + cols - 1) // cols
        band_rows[b[0]] = rows

    # vertical placement, band after band, each sized to its row count
    y = PAD_TOP
    band_top = {}
    for b in present:
        band_top[b[0]] = y
        inner = max(BAND_H, 70 + band_rows[b[0]] * row_h)
        y += inner
    height = y + PAD_TOP

    for b in present:
        members = sorted([n for n in model["nodes"] if n["level"] == b[0]],
                         key=lambda n: n["ip"])
        k = len(members)
        cols = min(k, max_cols) or 1
        top = band_top[b[0]] + 58
        for i, n in enumerate(members):
            r, c = divmod(i, cols)
            ncols = cols if (r < k // cols or k % cols == 0) else (k % cols)
            gap = (x1 - x0) / (ncols + 1)
            cx = x0 + gap * (c + 1)
            cy = top + r * row_h + CARD_H / 2
            pos[n["ip"]] = (cx, cy)
    return pos, present, height, band_top


def _glyph(kind, c):
    """role icon drawn inside a 36x36 tile centred at (0,0). One clear silhouette each."""
    sw = 'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"'
    if kind == "plc":  # industrial controller: display strip + two rows of I/O terminals
        return (f'<rect x="-12" y="-12" width="24" height="24" rx="3" fill="none" stroke="{c}" {sw}/>'
                f'<rect x="-7" y="-9" width="14" height="4" rx="1.2" fill="{c}" opacity="0.4"/>'
                f'<line x1="-12" y1="-2.5" x2="12" y2="-2.5" stroke="{c}" stroke-width="1.1" opacity="0.5"/>'
                + "".join(f'<circle cx="{x}" cy="2.5" r="1.5" fill="{c}"/><circle cx="{x}" cy="8" r="1.5" fill="{c}"/>'
                          for x in (-7, 0, 7)))
    if kind == "scada":  # server rack: three units, each with a status LED
        return "".join(f'<rect x="-12" y="{y}" width="24" height="6.6" rx="1.6" fill="none" stroke="{c}" {sw}/>'
                       f'<circle cx="-7.5" cy="{y+3.3}" r="1.3" fill="{c}"/>'
                       f'<line x1="2" y1="{y+3.3}" x2="8" y2="{y+3.3}" stroke="{c}" stroke-width="1.3" opacity="0.6"/>'
                       for y in (-12, -3.3, 5.4))
    if kind == "hmi":  # operator panel: screen with a gauge dial + stand
        return (f'<rect x="-12" y="-12" width="24" height="18" rx="2.5" fill="none" stroke="{c}" {sw}/>'
                f'<path d="M -5 0 A 5 5 0 0 1 5 0" fill="none" stroke="{c}" {sw}/>'
                f'<line x1="0" y1="0" x2="3.4" y2="-3.4" stroke="{c}" {sw}/>'
                f'<line x1="0" y1="10" x2="0" y2="6" stroke="{c}" {sw}/>'
                f'<line x1="-6" y1="11" x2="6" y2="11" stroke="{c}" {sw}/>')
    if kind == "engws":  # engineering laptop with code brackets </>
        return (f'<rect x="-11" y="-11" width="22" height="15" rx="2" fill="none" stroke="{c}" {sw}/>'
                f'<path d="M -3.5 -7 L -6.5 -3.5 L -3.5 0" fill="none" stroke="{c}" {sw}/>'
                f'<path d="M 3.5 -7 L 6.5 -3.5 L 3.5 0" fill="none" stroke="{c}" {sw}/>'
                f'<path d="M -13 9 L 13 9 L 10.5 4 L -10.5 4 Z" fill="none" stroke="{c}" {sw}/>')
    if kind == "it":  # globe: enterprise / network
        return (f'<circle r="11.5" fill="none" stroke="{c}" {sw}/>'
                f'<ellipse rx="4.6" ry="11.5" fill="none" stroke="{c}" stroke-width="1.5"/>'
                f'<line x1="-11.5" y1="0" x2="11.5" y2="0" stroke="{c}" stroke-width="1.5"/>'
                f'<path d="M -10 -5.5 L 10 -5.5 M -10 5.5 L 10 5.5" stroke="{c}" stroke-width="1.5" opacity="0.75"/>')
    if kind == "host":  # generic computer: monitor + tower
        return (f'<rect x="-12" y="-11" width="17" height="13" rx="2" fill="none" stroke="{c}" {sw}/>'
                f'<line x1="-6" y1="2" x2="-6" y2="7" stroke="{c}" {sw}/>'
                f'<line x1="-10" y1="8" x2="-2" y2="8" stroke="{c}" {sw}/>'
                f'<rect x="7" y="-11" width="6" height="19" rx="1.6" fill="none" stroke="{c}" {sw}/>'
                f'<circle cx="10" cy="-7" r="1" fill="{c}"/>')
    if kind == "cloud":  # external / internet
        return (f'<path d="M -9 5 A 5 5 0 0 1 -8 -4 A 6 6 0 0 1 4 -5 A 4.5 4.5 0 0 1 8 5 Z" '
                f'fill="none" stroke="{c}" {sw}/>')
    return f'<circle r="12" fill="none" stroke="{c}" stroke-width="1.7" stroke-dasharray="3 3"/>'


def _edge_path(a, b):
    """smooth bezier between two card centres, meeting card edges, not centres."""
    ax, ay = a; bx, by = b
    if abs(ay - by) < 4:  # same band -> side to side, gentle bow
        if ax <= bx:
            sx, ex = ax + CARD_W / 2, bx - CARD_W / 2
        else:
            sx, ex = ax - CARD_W / 2, bx + CARD_W / 2
        midy = ay + 34
        return f"M {sx:.0f} {ay:.0f} C {(sx+ex)/2:.0f} {midy:.0f} {(sx+ex)/2:.0f} {midy:.0f} {ex:.0f} {by:.0f}"
    # vertical: start at bottom of upper card, end at top of lower card
    if ay < by:
        sx, sy = ax, ay + CARD_H / 2
        ex, ey = bx, by - CARD_H / 2
    else:
        sx, sy = ax, ay - CARD_H / 2
        ex, ey = bx, by + CARD_H / 2
    c1y = sy + (ey - sy) * 0.5
    c2y = ey - (ey - sy) * 0.5
    return f"M {sx:.0f} {sy:.0f} C {sx:.0f} {c1y:.0f} {ex:.0f} {c2y:.0f} {ex:.0f} {ey:.0f}"


def _svg(model):
    pos, present, height, band_top = _layout(model)
    p = [f'<svg id="map" viewBox="0 0 {W} {height:.0f}" preserveAspectRatio="xMidYMid meet" '
         f'xmlns="http://www.w3.org/2000/svg">']
    # defs: depth gradient + soft glow
    p.append('<defs>'
             '<linearGradient id="depth" x1="0" y1="0" x2="0" y2="1">'
             '<stop offset="0" stop-color="#061310"/><stop offset="1" stop-color="#020A0C"/>'
             '</linearGradient>'
             '<filter id="soft" x="-40%" y="-40%" width="180%" height="180%">'
             '<feGaussianBlur stdDeviation="3.5"/></filter></defs>')
    p.append(f'<rect x="0" y="0" width="{W}" height="{height:.0f}" fill="url(#depth)"/>')

    # bands
    order = [b[0] for b in present]
    for i, b in enumerate(present):
        y0 = band_top[b[0]]
        p.append(f'<text x="28" y="{y0+30:.0f}" class="band-tag" fill="{b[2]}">{b[1]}</text>')
        p.append(f'<text x="28" y="{y0+48:.0f}" class="band-sub">{html.escape(b[0])}</text>')
        if "4/5" in b[0]:
            # boundary sits just above the next band down
            nb = order[i + 1] if i + 1 < len(order) else None
            yb = (band_top[nb] if nb else height) - 6
            p.append(f'<rect x="0" y="{yb-1:.0f}" width="{W}" height="2" fill="#FF5368" opacity="0.14"/>')
            p.append(f'<line x1="0" y1="{yb:.0f}" x2="{W}" y2="{yb:.0f}" stroke="#FF5368" '
                     f'stroke-width="1.2" stroke-dasharray="1 7" stroke-linecap="round" opacity="0.6"/>')
            p.append(f'<text x="{W-28}" y="{yb-9:.0f}" text-anchor="end" class="dmz">Purdue segmentation boundary</text>')

    # edges (normal first, violations on top)
    normal = [l for l in model["links"] if not l["violation"]]
    viol = [l for l in model["links"] if l["violation"]]
    for l in normal:
        if l["source"] in pos and l["target"] in pos:
            d = _edge_path(pos[l["source"]], pos[l["target"]])
            p.append(f'<path class="edge" data-a="{l["source"]}" data-b="{l["target"]}" d="{d}"/>')
    for l in viol:
        if l["source"] in pos and l["target"] in pos:
            d = _edge_path(pos[l["source"]], pos[l["target"]])
            p.append(f'<path class="edge viol-glow" d="{d}"/>')
            p.append(f'<path class="edge viol" data-a="{l["source"]}" data-b="{l["target"]}" d="{d}"/>')

    # nodes as cards
    for n in model["nodes"]:
        if n["ip"] not in pos:
            continue
        x, y = pos[n["ip"]]
        kind = ROLE_SHAPE.get(n["role"], "unknown")
        c = RISK_COLOR.get(n["risk"], BRAND)
        lx, ly = x - CARD_W / 2, y - CARD_H / 2
        alert = ' card-alert' if n["risk"] == "high" else ''
        p.append(f'<g class="node{alert}" data-ip="{n["ip"]}" tabindex="0" style="--rc:{c}">')
        # glow behind high-risk
        if n["risk"] == "high":
            p.append(f'<rect x="{lx-3:.0f}" y="{ly-3:.0f}" width="{CARD_W+6}" height="{CARD_H+6}" rx="14" '
                     f'fill="{c}" opacity="0.14" filter="url(#soft)" class="glow"/>')
        p.append(f'<rect class="card" x="{lx:.0f}" y="{ly:.0f}" width="{CARD_W}" height="{CARD_H}" rx="12"/>')
        p.append(f'<rect x="{lx:.0f}" y="{ly:.0f}" width="4" height="{CARD_H}" rx="2" fill="{c}"/>')
        # icon tile
        tx, ty = lx + 14, y
        p.append(f'<rect x="{tx:.0f}" y="{ty-18:.0f}" width="36" height="36" rx="9" fill="{c}" opacity="0.12"/>')
        p.append(f'<g transform="translate({tx+18:.0f},{ty:.0f})">{_glyph(kind, c)}</g>')
        # text
        p.append(f'<text x="{lx+60:.0f}" y="{y-4:.0f}" class="c-ip">{n["ip"]}</text>')
        p.append(f'<text x="{lx+60:.0f}" y="{y+13:.0f}" class="c-role" fill="{c}">{html.escape(n["role"])}</text>')
        p.append(f'<circle cx="{lx+CARD_W-14:.0f}" cy="{ly+14:.0f}" r="3.5" fill="{c}"/>')
        p.append('</g>')

    p.append('</svg>')
    return "".join(p).replace('stroke="#12premium" opacity="0"', 'stroke="none"')


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HAMMOUR — Network Map</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#020A0C; --panel:#07130F; --panel2:#050E0B; --line:#123029; --line2:#1A3B32;
  --brand:#04DE6F; --brand-dim:#0C7D4C; --ink:#EAF3EF; --ink2:#B9CCC4; --muted:#6F887D;
  --high:#FF5368; --med:#F2A93B;
  --font-d:"Space Grotesk",system-ui,sans-serif; --font-b:Inter,system-ui,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font-b);-webkit-font-smoothing:antialiased}
body{min-height:100vh;
  background-image:radial-gradient(1200px 520px at 72% -12%, rgba(4,222,111,.05), transparent 60%),
    linear-gradient(rgba(255,255,255,.012) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.012) 1px,transparent 1px);
  background-size:auto,48px 48px,48px 48px}
.wrap{max-width:1400px;margin:0 auto;padding:26px 26px 40px}

header{display:flex;align-items:center;justify-content:space-between;gap:20px;
  padding-bottom:20px;margin-bottom:24px;border-bottom:1px solid var(--line)}
.brand-logo{height:46px;width:auto;display:block}
nav{display:flex;gap:8px;font-family:var(--font-d);font-size:12.5px;letter-spacing:.14em}
nav span{padding:8px 17px;border:1px solid var(--line2);border-radius:8px;color:var(--muted);text-transform:uppercase;font-weight:500}
nav span.on{color:#042017;background:var(--brand);border-color:var(--brand);font-weight:600;
  box-shadow:0 0 22px rgba(4,222,111,.35)}

.grid{display:grid;grid-template-columns:274px 1fr;gap:20px}
@media(max-width:920px){.grid{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px}
.side{padding:20px}
.side h3{font-family:var(--font-d);font-size:11px;letter-spacing:.22em;text-transform:uppercase;
  color:var(--muted);margin:0 0 14px;font-weight:600}
.side h3:not(:first-child){margin-top:26px}

.stat{display:flex;align-items:baseline;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--line)}
.stat:last-of-type{border-bottom:0}
.stat .k{font-size:13px;color:var(--ink2)}
.stat .v{font-family:var(--font-d);font-size:28px;font-weight:600;color:var(--ink);line-height:1}
.stat .v.alert{color:var(--high)}
.legend .row{display:flex;align-items:center;gap:11px;font-size:12.5px;color:var(--ink2);padding:6px 0}
.legend .sw{width:28px;height:28px;flex:0 0 auto;display:grid;place-items:center}
.legend .dot{width:11px;height:11px;border-radius:50%}

.canvas{padding:10px;overflow:hidden}
#map{display:block;width:100%;height:auto}
.band-tag{font-family:var(--font-d);font-size:12.5px;font-weight:600;letter-spacing:.16em;text-transform:uppercase}
.band-sub{font-size:10px;fill:var(--muted);letter-spacing:.04em}
.dmz{font-size:10px;fill:var(--high);letter-spacing:.16em;text-transform:uppercase;opacity:.85}
.edge{fill:none;stroke:#245043;stroke-width:1.4;transition:stroke .15s,opacity .15s,stroke-width .15s}
.edge.dim{opacity:.1}.edge.hot{stroke:var(--brand);stroke-width:2.2}
.edge.viol{stroke:var(--high);stroke-width:2;stroke-dasharray:8 6;animation:flow 1s linear infinite}
.edge.viol-glow{stroke:var(--high);stroke-width:7;opacity:.14;filter:url(#soft)}
@keyframes flow{to{stroke-dashoffset:-28}}
@media(prefers-reduced-motion:reduce){.edge.viol{animation:none}}

.node{cursor:pointer}
.card{fill:var(--panel);stroke:var(--line2);stroke-width:1.2;transition:stroke .15s,fill .15s}
.node:hover .card,.node:focus .card{stroke:var(--rc);fill:#0E1D18}
.node.sel .card{stroke:var(--rc);stroke-width:2;fill:#0E1D18}
.node:focus{outline:none}
.c-ip{font-family:var(--font-d);font-size:13px;fill:var(--ink);font-weight:500}
.c-role{font-size:10px;letter-spacing:.03em;font-family:var(--font-b);font-weight:500}
.card-alert .glow{animation:pulse 2s ease-in-out infinite}
@keyframes pulse{50%{opacity:.26}}
@media(prefers-reduced-motion:reduce){.card-alert .glow{animation:none}}

.detail{margin-top:20px;padding:22px}
.detail .empty{color:var(--muted);font-size:13px}
.d-head{display:flex;align-items:center;gap:14px;margin-bottom:18px}
.d-badge{font-family:var(--font-d);font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;padding:6px 12px;border-radius:7px}
.d-title{font-family:var(--font-d);font-size:22px;font-weight:600;letter-spacing:.02em}
.d-meta{font-size:12.5px;color:var(--muted);margin-top:3px}
.d-cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:22px}
.d-sec h4{font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin:0 0 9px;font-family:var(--font-d);font-weight:600}
.kv{font-size:13px;line-height:1.95}.kv b{color:var(--muted);font-weight:500}
.chip{display:inline-block;font-size:11px;padding:3px 10px;border:1px solid var(--line2);border-radius:6px;margin:0 5px 6px 0;color:var(--ink2);background:var(--panel2);font-family:var(--font-d);letter-spacing:.02em}
.chip.ot{border-color:var(--brand-dim);color:var(--brand)}
.chip.fn{border-color:#6b5420;color:var(--med)}
.reasons{list-style:none;padding:0;margin:8px 0 0}
.reasons li{font-size:13px;padding:6px 0 6px 20px;position:relative;color:var(--ink)}
.reasons li::before{content:"";position:absolute;left:3px;top:11px;width:7px;height:7px;border-radius:50%;background:var(--brand)}
.conf{height:6px;background:var(--panel2);border:1px solid var(--line);border-radius:4px;overflow:hidden}
.conf i{display:block;height:100%;background:linear-gradient(90deg,var(--brand-dim),var(--brand))}

.viol-banner{display:flex;gap:13px;align-items:flex-start;background:rgba(255,83,104,.07);
  border:1px solid rgba(255,83,104,.35);border-radius:14px;padding:15px 18px;margin-bottom:22px}
.viol-banner .ic{color:var(--high);font-size:20px;line-height:1.2}
.viol-banner h4{margin:0 0 5px;font-size:14px;color:var(--high);font-family:var(--font-d);letter-spacing:.03em;font-weight:600}
.viol-banner p{margin:3px 0 0;font-size:12.5px;color:var(--ink2);line-height:1.6}
nav span{cursor:pointer}
/* Hunt view */
.hunt-tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
.tile .n{font-family:var(--font-d);font-size:34px;font-weight:600;line-height:1}
.tile .l{font-size:12px;color:var(--ink2);margin-top:8px;letter-spacing:.04em}
.tile.high .n{color:var(--high)} .tile.med .n{color:var(--med)} .tile.low .n{color:var(--brand)}
.hfilter{display:flex;gap:8px;margin-bottom:16px;font-family:var(--font-d);font-size:12px;letter-spacing:.08em}
.hfilter span{padding:7px 15px;border:1px solid var(--line2);border-radius:8px;color:var(--muted);text-transform:uppercase;cursor:pointer}
.hfilter span.on{color:#042017;background:var(--brand);border-color:var(--brand);font-weight:600}
.alert{display:flex;gap:14px;align-items:flex-start;background:var(--panel);border:1px solid var(--line);
  border-left-width:3px;border-radius:12px;padding:15px 18px;margin-bottom:12px}
.alert.high{border-left-color:var(--high)} .alert.medium{border-left-color:var(--med)} .alert.low{border-left-color:var(--brand)}
.alert .sev{font-family:var(--font-d);font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
  padding:5px 10px;border-radius:6px;flex:0 0 auto;margin-top:2px}
.alert.high .sev{background:var(--high);color:#2a0810} .alert.medium .sev{background:var(--med);color:#2a1a04} .alert.low .sev{background:var(--brand);color:#042017}
.alert .body{flex:1;min-width:0}
.alert .cmd{font-family:var(--font-d);font-size:15px;font-weight:500}
.alert .flow{font-size:12.5px;color:var(--ink2);margin:3px 0 7px}
.alert .flow b{color:var(--ink);font-weight:500} .alert .flow .rl{color:var(--muted)}
.alert .why{font-size:12.5px;color:var(--ink2);line-height:1.5;margin-bottom:9px}
.alert .maps{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.alert .t-att{border-color:#3a5a86;color:#8FB4D6}
.alert .t-nca{border-color:var(--brand-dim);color:var(--brand)}
.alert .when{font-size:11px;color:var(--muted);font-family:var(--font-d);white-space:nowrap;margin-top:2px}
.hunt-empty{color:var(--muted);font-size:13.5px;padding:30px;text-align:center}
.chainbadge{font-family:var(--font-d);font-size:10px;font-weight:600;letter-spacing:.06em;color:var(--high);
  border:1px solid var(--high);border-radius:5px;padding:1px 7px;margin-left:8px;vertical-align:middle}
/* Vuln view */
.hunt-tiles{grid-template-columns:repeat(4,1fr)}
.tile.crit .n{color:#C026D3}
.vnote{font-size:12px;color:var(--muted);margin-bottom:18px;line-height:1.5}
.vasset{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:0;margin-bottom:14px;overflow:hidden}
.vahead{display:flex;align-items:center;gap:12px;padding:15px 18px;border-bottom:1px solid var(--line)}
.vahead .ip{font-family:var(--font-d);font-size:15px;font-weight:500;color:var(--ink)}
.vahead .meta{font-size:12.5px;color:var(--muted)}
.vahead .cnt{margin-left:auto;font-size:12px;color:var(--ink2)}
.vahead .shield{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;flex:0 0 auto;font-size:15px}
.vfind{display:flex;gap:13px;align-items:flex-start;padding:14px 18px;border-top:1px solid var(--line)}
.vfind:first-child{border-top:0}
.vfind .sev{font-family:var(--font-d);font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
  padding:5px 9px;border-radius:6px;flex:0 0 auto;margin-top:1px;min-width:62px;text-align:center}
.sev-critical{background:#C026D3;color:#fff} .sev-high{background:var(--high);color:#2a0810}
.sev-medium{background:var(--med);color:#2a1a04} .sev-low{background:var(--brand);color:#042017}
.vfind .vbody{flex:1;min-width:0}
.vfind .vtitle{font-size:14px;color:var(--ink);font-weight:500;line-height:1.4}
.vfind .vid{font-family:var(--font-d);font-size:12px;color:var(--ink2);margin:4px 0 2px}
.vfind .vid b{color:var(--ink)}
.vfind .conf{display:inline-block;font-family:var(--font-d);font-size:10px;padding:1px 7px;border-radius:5px;margin-left:8px;vertical-align:middle}
.conf-confirmed{border:1px solid var(--brand-dim);color:var(--brand)}
.conf-potential{border:1px solid #6b5420;color:var(--med)}
.kevtag{background:#C026D3;color:#fff;font-family:var(--font-d);font-size:9px;font-weight:600;padding:1px 6px;border-radius:4px;margin-left:6px;letter-spacing:.05em}
.vfind .vfix{font-size:12.5px;color:var(--ink2);line-height:1.5;margin-top:7px}
.vfind .vfix b{color:var(--muted);font-weight:500}
.vfind .vmaps{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}
.vfind .t-cwe{border-color:#5a4a6a;color:#b89fd6}
/* posture bar */
.posture{display:flex;align-items:center;gap:22px;background:var(--panel);border:1px solid var(--line);
  border-radius:14px;padding:16px 22px;margin-bottom:22px}
.posture .score{display:flex;align-items:baseline;gap:8px}
.posture .score .big{font-family:var(--font-d);font-size:40px;font-weight:700;line-height:1}
.posture .score .den{font-family:var(--font-d);font-size:15px;color:var(--muted)}
.posture .lbl{font-family:var(--font-d);font-size:12px;letter-spacing:.1em;text-transform:uppercase;padding:5px 12px;border-radius:7px;font-weight:600}
.posture .pstats{display:flex;gap:26px;margin-left:auto;flex-wrap:wrap}
.posture .ps{text-align:center}
.posture .ps .pn{font-family:var(--font-d);font-size:22px;font-weight:600}
.posture .ps .pl{font-size:11px;color:var(--muted);margin-top:3px;letter-spacing:.03em}
.navbtn{padding:8px 15px;border:1px solid var(--brand-dim);border-radius:8px;color:var(--brand);
  background:transparent;font-family:var(--font-d);font-size:12.5px;letter-spacing:.08em;cursor:pointer;text-transform:uppercase}
.navbtn:hover{background:rgba(4,222,111,.08)}
/* report */
#view-report{background:#fff;color:#111;border-radius:14px;padding:38px 42px;margin-top:6px}
#view-report h1{font-family:var(--font-d);font-size:22px;margin:0 0 4px;color:#0a2a1c}
#view-report h2{font-family:var(--font-d);font-size:15px;margin:26px 0 10px;color:#0a2a1c;border-bottom:2px solid #04DE6F;padding-bottom:5px}
#view-report .rmeta{color:#555;font-size:12.5px;margin-bottom:18px}
#view-report table{width:100%;border-collapse:collapse;font-size:12.5px}
#view-report th,#view-report td{text-align:left;padding:7px 9px;border-bottom:1px solid #e3e3e3;vertical-align:top}
#view-report th{background:#f3f6f4;font-family:var(--font-d);font-weight:600;color:#0a2a1c}
#view-report .rtag{font-family:var(--font-d);font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;white-space:nowrap}
#view-report .r-crit{background:#C026D3;color:#fff}.r-high{background:#e23b3b;color:#fff}.r-med{background:#e09422;color:#fff}.r-low{background:#2faa5a;color:#fff}
#view-report .rbar{display:flex;gap:18px;margin:14px 0 6px;flex-wrap:wrap}
#view-report .rbar .rb{background:#f3f6f4;border-radius:10px;padding:12px 18px;min-width:96px}
#view-report .rbar .rb .n{font-family:var(--font-d);font-size:26px;font-weight:700;color:#0a2a1c}
#view-report .rbar .rb .l{font-size:11px;color:#666;margin-top:3px}
#view-report .rfoot{margin-top:26px;font-size:11px;color:#888;border-top:1px solid #e3e3e3;padding-top:12px}
@media print{
  body{background:#fff !important}
  header,.posture,#view-map,#view-hunt,#view-vuln{display:none !important}
  #view-report{display:block !important;border:0;padding:0}
  .wrap{max-width:none;padding:0}
}
</style></head>
<body><div class="wrap">
<header>
  <img class="brand-logo" alt="HAMMOUR — OT Security" src="data:image/png;base64,__LOGO__">
  <nav><span class="on" onclick="showView('map',this)">Map</span><span onclick="showView('hunt',this)">Hunt</span><span onclick="showView('vuln',this)">Vuln</span>
  <button class="navbtn" onclick="openReport()">&#9906; Report</button></nav>
</header>

<div class="posture" id="posture"></div>

<div id="view-map">
__VIOL_BANNER__

<div class="grid">
  <aside class="side panel">
    <h3>Scan summary</h3>
    <div class="stat"><span class="k">Assets found</span><span class="v">__HOSTS__</span></div>
    <div class="stat"><span class="k">Comm flows</span><span class="v">__FLOWS__</span></div>
    <div class="stat"><span class="k">Violations</span><span class="v __VCLASS__">__VIOLS__</span></div>
    <h3>Shape = role</h3>
    <div class="legend" id="legend-role"></div>
    <h3>Colour = risk</h3>
    <div class="legend">
      <div class="row"><span class="sw"><span class="dot" style="background:#FF5368"></span></span>High — needs attention</div>
      <div class="row"><span class="sw"><span class="dot" style="background:#F2A93B"></span></span>Medium — exposed control</div>
      <div class="row"><span class="sw"><span class="dot" style="background:#04DE6F"></span></span>Low — expected</div>
    </div>
  </aside>
  <main>
    <div class="panel canvas">__SVG__</div>
    <section class="panel detail" id="detail">
      <div class="empty">Select a device on the map to see its evidence — role, confidence, protocols and who it talks to.</div>
    </section>
  </main>
</div>
</div>

<div id="view-hunt" style="display:none">
  <div class="hunt-tiles">
    <div class="tile high"><div class="n" id="h-high">0</div><div class="l">High — act now</div></div>
    <div class="tile med"><div class="n" id="h-med">0</div><div class="l">Medium — review</div></div>
    <div class="tile low"><div class="n" id="h-low">0</div><div class="l">Low — expected activity</div></div>
  </div>
  <div class="hfilter" id="hfilter">
    <span class="on" data-f="all" onclick="filterHunt('all',this)">All</span>
    <span data-f="high" onclick="filterHunt('high',this)">High</span>
    <span data-f="medium" onclick="filterHunt('medium',this)">Medium</span>
    <span data-f="low" onclick="filterHunt('low',this)">Low</span>
  </div>
  <div id="hunt-list"></div>
</div>

<div id="view-vuln" style="display:none">
  <div class="hunt-tiles">
    <div class="tile crit"><div class="n" id="v-crit">0</div><div class="l">Critical</div></div>
    <div class="tile high"><div class="n" id="v-high">0</div><div class="l">High</div></div>
    <div class="tile med"><div class="n" id="v-med">0</div><div class="l">Medium</div></div>
    <div class="tile low"><div class="n" id="v-low">0</div><div class="l">Low</div></div>
  </div>
  <div class="vnote" id="v-note"></div>
  <div id="vuln-list"></div>
</div>

<div id="view-report" style="display:none"></div>
</div>

<script>
const HUNT=__HUNT__;
const VULN=__VULN__;
const MODEL=__MODEL__;
const BY_IP=Object.fromEntries(MODEL.nodes.map(n=>[n.ip,n]));
const RISK={high:"#FF5368",medium:"#F2A93B",low:"#04DE6F"};
const RISK_LABEL={high:"High risk",medium:"Medium",low:"Low"};
const ROLES=[["PLC","plc"],["SCADA Server","scada"],["HMI","hmi"],["Engineering WS","engws"],["IT/Enterprise","it"],["IT / Host","host"],["External / Internet","cloud"]];
function mini(kind){const c="#A7C0B6";const s='stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"';
  const m={
  plc:'<rect x="-12" y="-12" width="24" height="24" rx="3" fill="none" stroke="'+c+'" '+s+'/><rect x="-7" y="-9" width="14" height="4" rx="1.2" fill="'+c+'" opacity="0.4"/><line x1="-12" y1="-2.5" x2="12" y2="-2.5" stroke="'+c+'" stroke-width="1" opacity="0.5"/>'+[-7,0,7].map(x=>'<circle cx="'+x+'" cy="2.5" r="1.5" fill="'+c+'"/><circle cx="'+x+'" cy="8" r="1.5" fill="'+c+'"/>').join(''),
  scada:[-12,-3.3,5.4].map(y=>'<rect x="-12" y="'+y+'" width="24" height="6.6" rx="1.6" fill="none" stroke="'+c+'" '+s+'/><circle cx="-7.5" cy="'+(y+3.3)+'" r="1.3" fill="'+c+'"/><line x1="2" y1="'+(y+3.3)+'" x2="8" y2="'+(y+3.3)+'" stroke="'+c+'" stroke-width="1.2" opacity="0.6"/>').join(''),
  hmi:'<rect x="-12" y="-12" width="24" height="18" rx="2.5" fill="none" stroke="'+c+'" '+s+'/><path d="M -5 0 A 5 5 0 0 1 5 0" fill="none" stroke="'+c+'" '+s+'/><line x1="0" y1="0" x2="3.4" y2="-3.4" stroke="'+c+'" '+s+'/><line x1="0" y1="10" x2="0" y2="6" stroke="'+c+'" '+s+'/><line x1="-6" y1="11" x2="6" y2="11" stroke="'+c+'" '+s+'/>',
  engws:'<rect x="-11" y="-11" width="22" height="15" rx="2" fill="none" stroke="'+c+'" '+s+'/><path d="M -3.5 -7 L -6.5 -3.5 L -3.5 0" fill="none" stroke="'+c+'" '+s+'/><path d="M 3.5 -7 L 6.5 -3.5 L 3.5 0" fill="none" stroke="'+c+'" '+s+'/><path d="M -13 9 L 13 9 L 10.5 4 L -10.5 4 Z" fill="none" stroke="'+c+'" '+s+'/>',
  it:'<circle r="11.5" fill="none" stroke="'+c+'" '+s+'/><ellipse rx="4.6" ry="11.5" fill="none" stroke="'+c+'" stroke-width="1.4"/><line x1="-11.5" y1="0" x2="11.5" y2="0" stroke="'+c+'" stroke-width="1.4"/><path d="M -10 -5.5 L 10 -5.5 M -10 5.5 L 10 5.5" stroke="'+c+'" stroke-width="1.4" opacity="0.75"/>',
  host:'<rect x="-12" y="-11" width="17" height="13" rx="2" fill="none" stroke="'+c+'" '+s+'/><line x1="-6" y1="2" x2="-6" y2="7" stroke="'+c+'" '+s+'/><line x1="-10" y1="8" x2="-2" y2="8" stroke="'+c+'" '+s+'/><rect x="7" y="-11" width="6" height="19" rx="1.6" fill="none" stroke="'+c+'" '+s+'/><circle cx="10" cy="-7" r="1" fill="'+c+'"/>',
  cloud:'<path d="M -9 5 A 5 5 0 0 1 -8 -4 A 6 6 0 0 1 4 -5 A 4.5 4.5 0 0 1 8 5 Z" fill="none" stroke="'+c+'" '+s+'/>'};
  return '<svg viewBox="0 0 34 34" width="26" height="26"><g transform="translate(17,17)">'+m[kind]+'</g></svg>';}
document.getElementById('legend-role').innerHTML=
  ROLES.map(([n,k])=>'<div class="row"><span class="sw">'+mini(k)+'</span>'+n+'</div>').join('');
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

function showDetail(ip){
  const n=BY_IP[ip];if(!n)return;
  document.querySelectorAll('.node').forEach(g=>g.classList.toggle('sel',g.dataset.ip===ip));
  document.querySelectorAll('.edge').forEach(e=>{
    if(e.classList.contains('viol')||e.classList.contains('viol-glow'))return;
    const hot=e.dataset.a===ip||e.dataset.b===ip;
    e.classList.toggle('hot',hot);e.classList.toggle('dim',!hot);});
  const c=RISK[n.risk];
  const peers=MODEL.links.filter(l=>l.source===ip||l.target===ip)
    .map(l=>{const o=l.source===ip?l.target:l.source;return{ip:o,role:(BY_IP[o]||{}).role||'?',protos:l.protocols,viol:l.violation};});
  const ot=n.ot_protocols||[],it=(n.protocols||[]).filter(p=>!ot.includes(p));
  document.getElementById('detail').innerHTML=`
    <div class="d-head">
      <span class="d-badge" style="color:#07140F;background:${c}">${esc(RISK_LABEL[n.risk])}</span>
      <div><div class="d-title">${esc(n.role)}</div>
      <div class="d-meta">${esc(n.ip)} &nbsp;·&nbsp; ${esc(n.level)} &nbsp;·&nbsp; ${n.packets} pkts</div></div>
    </div>
    <div class="d-cols">
      <div class="d-sec"><h4>Why this role · ${n.confidence}%</h4>
        <div class="conf"><i style="width:${n.confidence}%"></i></div>
        <ul class="reasons">${n.reasons.map(r=>'<li>'+esc(r)+'</li>').join('')}</ul></div>
      <div class="d-sec"><h4>Identity</h4>
        <div class="kv"><b>Vendor (MAC):</b> ${esc(n.vendor||'unknown')}</div>
        <div class="kv"><b>MAC:</b> ${esc(n.mac||'—')}</div>
        <div class="kv"><b>Model / firmware:</b> ${(n.product||n.firmware)?('<span style="color:var(--brand)">'+esc([n.product,n.firmware].filter(Boolean).join(' · '))+'</span>'):'<span style="color:var(--muted)">not seen passively</span>'}</div>
        <h4 style="margin-top:16px">Protocols</h4>
        <div>${ot.map(p=>'<span class="chip ot">'+esc(p)+'</span>').join('')}${it.map(p=>'<span class="chip">'+esc(p)+'</span>').join('')||'<span style="color:var(--muted);font-size:12px">none</span>'}</div>
        ${(n.ports&&n.ports.length)?'<h4 style="margin-top:16px">Observed ports</h4><div>'+n.ports.map(p=>'<span class="chip">'+esc(p)+'</span>').join('')+'</div>':''}
        ${(n.functions&&n.functions.length)?'<h4 style="margin-top:16px">Observed commands</h4><div>'+n.functions.map(f=>'<span class="chip fn">'+esc(f)+'</span>').join('')+'</div>':''}
      </div>
      <div class="d-sec"><h4>Talks to (${peers.length})</h4>
        <div class="kv">${peers.map(p=>`<div style="padding:3px 0">${p.viol?'<span style="color:var(--high)">⚠ </span>':''}<b style="color:var(--ink)">${esc(p.ip)}</b> <span style="color:var(--muted)">${esc(p.role)}</span> ${p.protos.map(x=>'<span class="chip" style="padding:1px 7px;font-size:10px">'+esc(x)+'</span>').join('')}</div>`).join('')||'<span style="color:var(--muted)">—</span>'}</div></div>
    </div>`;
  document.getElementById('detail').scrollIntoView({behavior:'smooth',block:'nearest'});
}
document.querySelectorAll('.node').forEach(g=>{
  g.addEventListener('click',()=>showDetail(g.dataset.ip));
  g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();showDetail(g.dataset.ip);}});
});

/* ---- tab switching ---- */
function showView(v,el){
  ['map','hunt','vuln','report'].forEach(x=>{document.getElementById('view-'+x).style.display=(x===v)?'':'none';});
  document.querySelectorAll('nav span').forEach(s=>s.classList.remove('on'));
  if(el)el.classList.add('on');
}

/* ---- security posture (combines Map + Hunt + Vuln) ---- */
function computePosture(){
  let score=100;
  score-=(MODEL.meta.violations||0)*12;
  score-=(HUNT.meta.high||0)*10 + (HUNT.meta.medium||0)*3;
  score-=(VULN.meta.critical||0)*10 + (VULN.meta.high||0)*4;
  score=Math.max(5,Math.min(100,Math.round(score)));
  let band,col;
  if(score>=80){band='Good';col='#04DE6F';}
  else if(score>=60){band='Fair';col='#F2A93B';}
  else if(score>=35){band='At risk';col='#FF5368';}
  else {band='Critical';col='#C026D3';}
  return {score,band,col};
}
function renderPosture(){
  const p=computePosture();
  const threats=(HUNT.meta.high||0)+(HUNT.meta.medium||0);
  document.getElementById('posture').innerHTML=`
    <div class="score"><span class="big" style="color:${p.col}">${p.score}</span><span class="den">/ 100</span></div>
    <span class="lbl" style="background:${p.col}22;color:${p.col}">${p.band}</span>
    <div class="pstats">
      <div class="ps"><div class="pn">${MODEL.meta.hosts}</div><div class="pl">assets</div></div>
      <div class="ps"><div class="pn" style="color:${MODEL.meta.violations?'#FF5368':'var(--ink)'}">${MODEL.meta.violations}</div><div class="pl">segmentation</div></div>
      <div class="ps"><div class="pn" style="color:${threats?'#FF5368':'var(--ink)'}">${threats}</div><div class="pl">active threats</div></div>
      <div class="ps"><div class="pn" style="color:${VULN.meta.critical+VULN.meta.high?'#F2A93B':'var(--ink)'}">${(VULN.meta.critical||0)+(VULN.meta.high||0)}</div><div class="pl">crit+high vulns</div></div>
    </div>`;
}
renderPosture();

/* ---- one-click NCA / compliance report (print to PDF) ---- */
function ncaSet(){
  const s=new Set();
  HUNT.alerts.forEach(a=>a.nca.forEach(n=>s.add(n)));
  VULN.assets.forEach(a=>a.findings.forEach(f=>f.nca.forEach(n=>s.add(n))));
  return [...s].sort();
}
function openReport(){
  const p=computePosture();
  const hv=HUNT.alerts.filter(a=>a.severity==='high');
  const vv=[];VULN.assets.forEach(a=>a.findings.forEach(f=>{if(f.severity==='critical'||f.severity==='high')vv.push({...f,ip:a.ip,role:a.role});}));
  const row=(c)=>`<span class="rtag r-${c}">${c}</span>`;
  const d=new Date().toISOString().slice(0,16).replace('T',' ');
  document.getElementById('view-report').innerHTML=`
    <h1>HAMMOUR — OT Security Assessment</h1>
    <div class="rmeta">Source: <b>${esc(MODEL.meta.source||'capture')}</b> &nbsp;·&nbsp; Generated: ${d} UTC &nbsp;·&nbsp; Passive analysis</div>
    <div class="rbar">
      <div class="rb"><div class="n" style="color:${p.col}">${p.score}/100</div><div class="l">Posture — ${p.band}</div></div>
      <div class="rb"><div class="n">${MODEL.meta.hosts}</div><div class="l">OT assets</div></div>
      <div class="rb"><div class="n">${MODEL.meta.violations}</div><div class="l">Segmentation violations</div></div>
      <div class="rb"><div class="n">${HUNT.meta.high}</div><div class="l">High threats</div></div>
      <div class="rb"><div class="n">${(VULN.meta.critical||0)+(VULN.meta.high||0)}</div><div class="l">Critical+High vulns</div></div>
    </div>
    <h2>High-severity threats (Hunt)</h2>
    ${hv.length?`<table><tr><th>Command</th><th>Source → Target</th><th>ATT&CK</th><th>NCA OTCC</th></tr>
      ${hv.map(a=>`<tr><td>${row('high')} ${esc(a.command)}</td><td>${esc(a.src)} (${esc(a.src_role)}) → ${esc(a.dst)}</td><td>${a.attack.map(t=>esc(t.id)).join(', ')}</td><td>${a.nca.map(esc).join('<br>')}</td></tr>`).join('')}</table>`
      :'<p style="color:#2faa5a;font-size:13px">No high-severity threats detected in this capture.</p>'}
    <h2>Critical &amp; high vulnerabilities (Vuln)</h2>
    ${vv.length?`<table><tr><th>Severity</th><th>Asset</th><th>Finding</th><th>Reference</th><th>NCA OTCC</th></tr>
      ${vv.map(f=>`<tr><td>${row(f.severity)}${f.kev?' '+row('crit').replace('>critical<','>KEV<'):''}</td><td>${esc(f.ip)}<br><span style="color:#888">${esc(f.role)}</span></td><td>${esc(f.title)}<br><span style="color:#888">${esc(f.id)} (${esc(f.confidence)})</span></td><td>${esc(f.ref||f.cwe)}</td><td>${f.nca.map(esc).join('<br>')}</td></tr>`).join('')}</table>`
      :'<p style="color:#2faa5a;font-size:13px">No critical or high vulnerabilities matched.</p>'}
    <h2>NCA OTCC controls touched</h2>
    <p style="font-size:12.5px;color:#333;line-height:1.8">${ncaSet().map(n=>'NCA '+esc(n)).join(' &nbsp;·&nbsp; ')||'—'}</p>
    <div class="rfoot">Generated by HAMMOUR · passive OT discovery, threat hunting and vulnerability matching. Product CVEs are potential matches unless the model/version was fingerprinted; confirm before acting. Mapped to MITRE ATT&CK for ICS and NCA OTCC.</div>`;
  showView('report',null);
  setTimeout(()=>window.print(),300);
}

/* ---- Hunt view ---- */
let huntFilter='all';
function renderHunt(){
  const list=document.getElementById('hunt-list');
  document.getElementById('h-high').textContent=HUNT.meta.high;
  document.getElementById('h-med').textContent=HUNT.meta.medium;
  document.getElementById('h-low').textContent=HUNT.meta.low;
  const rows=HUNT.alerts.filter(a=>huntFilter==='all'||a.severity===huntFilter);
  if(!rows.length){list.innerHTML='<div class="hunt-empty">No alerts at this level. For a real capture that is a good sign.</div>';return;}
  list.innerHTML=rows.map(a=>`
    <div class="alert ${a.severity}">
      <span class="sev">${a.severity}</span>
      <div class="body">
        <div class="cmd">${esc(a.command)}${a.chain?' <span class="chainbadge">&#9741; chain</span>':''}</div>
        <div class="flow"><b>${esc(a.src)}</b> <span class="rl">${esc(a.src_role)}</span> &rarr; <b>${esc(a.dst)}</b> <span class="rl">${esc(a.dst_role)}</span>${a.count>1?` · ${a.count}&times;`:''}</div>
        <div class="why">${esc(a.why)}</div>
        <div class="maps">${a.attack.map(t=>`<span class="chip t-att">${esc(t.id)} ${esc(t.name)}</span>`).join('')}${a.nca.map(n=>`<span class="chip t-nca">NCA ${esc(n)}</span>`).join('')}</div>
      </div>
      <div class="when">${esc(a.first)}</div>
    </div>`).join('');
}
function filterHunt(f,el){
  huntFilter=f;
  document.querySelectorAll('#hfilter span').forEach(s=>s.classList.remove('on'));
  if(el)el.classList.add('on');
  renderHunt();
}
renderHunt();

/* ---- Vuln view ---- */
function renderVuln(){
  const m=VULN.meta;
  document.getElementById('v-crit').textContent=m.critical;
  document.getElementById('v-high').textContent=m.high;
  document.getElementById('v-med').textContent=m.medium;
  document.getElementById('v-low').textContent=m.low;
  document.getElementById('v-note').innerHTML='&#9432; '+esc(m.note);
  const list=document.getElementById('vuln-list');
  if(!VULN.assets.length){list.innerHTML='<div class="hunt-empty">No OT assets with known weaknesses were found.</div>';return;}
  const shield={critical:'#C026D3',high:'#FF5368',medium:'#F2A93B',low:'#04DE6F'};
  list.innerHTML=VULN.assets.map(a=>`
    <div class="vasset">
      <div class="vahead">
        <span class="shield" style="background:${shield[a.top_severity]}22;color:${shield[a.top_severity]}">&#9823;</span>
        <div><div class="ip">${esc(a.ip)}</div>
        <div class="meta">${esc(a.role)} &middot; ${esc(a.vendor)} &middot; ${a.protocols.map(esc).join(', ')||'—'}</div></div>
        <div class="cnt">${a.findings.length} finding${a.findings.length>1?'s':''}</div>
      </div>
      ${a.findings.map(f=>`
        <div class="vfind">
          <span class="sev sev-${f.severity}">${f.severity}</span>
          <div class="vbody">
            <div class="vtitle">${esc(f.title)}</div>
            <div class="vid"><b>${esc(f.id)}</b>${f.cvss?` &middot; CVSS ${f.cvss}`:''}${f.kev?'<span class="kevtag">KEV</span>':''}
              <span class="conf conf-${f.confidence}">${f.confidence}</span>
              <span style="color:var(--muted)"> &middot; ${esc(f.scope)}</span></div>
            <div class="vfix"><b>Fix:</b> ${esc(f.fix)}</div>
            <div class="vmaps"><span class="chip t-cwe">${esc(f.cwe)}</span>${f.nca.map(n=>`<span class="chip t-nca">NCA ${esc(n)}</span>`).join('')}</div>
          </div>
        </div>`).join('')}
    </div>`).join('');
}
renderVuln();
</script>
</body></html>"""


def build_html(model, hunt=None, vuln=None):
    """Render the full page (Map + Hunt + Vuln tabs) to an HTML string."""
    if hunt is None:
        hunt = {"meta": {"high": 0, "medium": 0, "low": 0, "alerts": 0}, "alerts": []}
    if vuln is None:
        vuln = {"meta": {"critical": 0, "high": 0, "medium": 0, "low": 0,
                         "findings": 0, "note": "Run a capture to scan assets."}, "assets": []}
    v = model["meta"]["violations"]
    banner = ""
    if model["violations"]:
        items = "".join(
            f'<p>{html.escape(x["from"])} → {html.escape(x["to"])} over '
            f'{", ".join(x["protocols"])} · {html.escape(x["title"])}.</p>'
            for x in model["violations"])
        banner = (f'<div class="viol-banner"><div class="ic">&#9888;</div><div>'
                  f'<h4>{v} segmentation violation(s) detected</h4>{items}</div></div>')
    out = (TEMPLATE
           .replace("__LOGO__", _b64_logo())
           .replace("__SVG__", _svg(model))
           .replace("__MODEL__", json.dumps(model, ensure_ascii=False))
           .replace("__HUNT__", json.dumps(hunt, ensure_ascii=False))
           .replace("__VULN__", json.dumps(vuln, ensure_ascii=False))
           .replace("__HOSTS__", str(model["meta"]["hosts"]))
           .replace("__FLOWS__", str(model["meta"]["flows"]))
           .replace("__VIOLS__", str(v))
           .replace("__VCLASS__", "alert" if v else "")
           .replace("__VIOL_BANNER__", banner))
    # client asked to avoid the em dash anywhere in the UI; use a middot instead
    return out.replace("—", "·").replace("–", "·")


def render(model, out_path="map.html", hunt=None, vuln=None):
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(build_html(model, hunt, vuln))
    return out_path
