#!/usr/bin/env python3
"""
HAMMOUR — web platform (Map module)
===================================
A small Flask app so you can upload a PCAP in the browser and get the map,
instead of running the scripts by hand.

    pip install flask scapy
    python3 app.py
    # open http://127.0.0.1:5000

Routes:
    GET  /        branded upload page
    POST /scan    receives a .pcap, runs the passive discovery, returns the map
"""
import os, tempfile
from flask import Flask, request, Response, redirect, url_for

from scapy.all import rdpcap
from hammour_map import build_model
from hammour_hunt import build_hunt
from hammour_vuln import build_vuln
from render_map import build_html, _b64_logo

MAX_MB = 80
ALLOWED = (".pcap", ".pcapng", ".cap")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024

UPLOAD_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HAMMOUR · Upload capture</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#020A0C;--panel:#07130F;--line:#123029;--line2:#1A3B32;--brand:#04DE6F;
  --brand-dim:#0C7D4C;--ink:#EAF3EF;--ink2:#B9CCC4;--muted:#6F887D;--high:#FF5368;
  --font-d:"Space Grotesk",system-ui,sans-serif;--font-b:Inter,system-ui,sans-serif;}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);font-family:var(--font-b);-webkit-font-smoothing:antialiased}
body{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px;
  background-image:radial-gradient(1000px 460px at 50% -10%,rgba(4,222,111,.06),transparent 60%),
   linear-gradient(rgba(255,255,255,.012) 1px,transparent 1px),
   linear-gradient(90deg,rgba(255,255,255,.012) 1px,transparent 1px);
  background-size:auto,48px 48px,48px 48px}
.logo{height:52px;margin-bottom:34px}
.card{width:100%;max-width:560px;background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:34px}
h1{font-family:var(--font-d);font-size:20px;font-weight:600;letter-spacing:.01em;margin:0 0 6px}
.sub{color:var(--muted);font-size:13.5px;margin:0 0 26px;line-height:1.6}
.drop{display:block;border:1.5px dashed var(--line2);border-radius:14px;padding:40px 24px;text-align:center;
  cursor:pointer;transition:border-color .15s,background .15s}
.drop:hover,.drop.over{border-color:var(--brand);background:rgba(4,222,111,.05)}
.drop .ic{color:var(--brand);font-size:30px;line-height:1}
.drop .t{font-family:var(--font-d);font-size:15px;margin-top:12px}
.drop .h{color:var(--muted);font-size:12.5px;margin-top:6px}
.fname{color:var(--brand);font-size:13px;margin-top:14px;min-height:18px;font-family:var(--font-d)}
input[type=file]{display:none}
.btn{margin-top:22px;width:100%;padding:14px;border:0;border-radius:11px;background:var(--brand);
  color:#042017;font-family:var(--font-d);font-weight:600;font-size:14px;letter-spacing:.06em;
  text-transform:uppercase;cursor:pointer;transition:filter .15s}
.btn:hover{filter:brightness(1.07)}
.btn:disabled{opacity:.5;cursor:default}
.note{color:var(--muted);font-size:11.5px;margin-top:16px;text-align:center;letter-spacing:.02em}
.err{color:var(--high);font-size:13px;margin-top:14px;min-height:16px}
.overlay{position:fixed;inset:0;background:rgba(2,10,12,.92);display:none;flex-direction:column;
  align-items:center;justify-content:center;z-index:9}
.overlay.on{display:flex}
.spin{width:42px;height:42px;border:3px solid var(--line2);border-top-color:var(--brand);
  border-radius:50%;animation:sp .8s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.overlay .t{margin-top:18px;font-family:var(--font-d);color:var(--ink2);font-size:14px;letter-spacing:.08em}
</style></head>
<body>
<img class="logo" alt="HAMMOUR" src="data:image/png;base64,__LOGO__">
<div class="card">
  <h1>Upload a network capture</h1>
  <p class="sub">HAMMOUR reads the PCAP passively, builds the asset map, classifies each device and flags segmentation violations. Nothing is sent to the network.</p>
  <form id="f" method="post" action="/scan" enctype="multipart/form-data">
    <label class="drop" id="drop">
      <div class="ic"><i>&#8681;</i></div>
      <div class="t">Drop a .pcap here or click to browse</div>
      <div class="h">.pcap · .pcapng · .cap &nbsp;up to __MAX__ MB</div>
      <div class="fname" id="fname"></div>
      <input type="file" id="file" name="pcap" accept=".pcap,.pcapng,.cap">
    </label>
    <button class="btn" id="go" type="submit" disabled>Build the map</button>
    <div class="err" id="err">__ERR__</div>
  </form>
  <div class="note">Tip: no capture handy? Try a sample from ITI/ICS-Security-Tools or Netresec 4SICS.</div>
</div>
<div class="overlay" id="ov"><div class="spin"></div><div class="t">Analysing capture…</div></div>
<script>
const drop=document.getElementById('drop'),file=document.getElementById('file'),
  fname=document.getElementById('fname'),go=document.getElementById('go');
function set(){if(file.files.length){fname.textContent=file.files[0].name;go.disabled=false;}}
file.addEventListener('change',set);
['dragover','dragenter'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('over');}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('over');}));
drop.addEventListener('drop',ev=>{if(ev.dataTransfer.files.length){file.files=ev.dataTransfer.files;set();}});
document.getElementById('f').addEventListener('submit',()=>{if(!file.files.length)return;document.getElementById('ov').classList.add('on');});
</script>
</body></html>"""


def _page(err=""):
    return (UPLOAD_PAGE.replace("__LOGO__", _b64_logo())
            .replace("__MAX__", str(MAX_MB)).replace("__ERR__", err))


@app.route("/")
def index():
    return _page()


@app.route("/scan", methods=["POST"])
def scan():
    f = request.files.get("pcap")
    if not f or not f.filename:
        return _page("Pick a capture file first."), 400
    if not f.filename.lower().endswith(ALLOWED):
        return _page("Unsupported file. Use .pcap, .pcapng or .cap."), 400
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "capture" + os.path.splitext(f.filename)[1])
        f.save(path)
        try:
            pkts = rdpcap(path)              # read the capture once
            model = build_model(pkts)        # Map
            hunt = build_hunt(pkts, model)   # Hunt (reuses packets + roles)
            vuln = build_vuln(pkts, model)   # Vuln (reuses roles)
        except Exception as e:
            return _page(f"Could not parse that capture: {e}"), 400
        model["meta"]["source"] = f.filename
        return Response(build_html(model, hunt, vuln), mimetype="text/html")


if __name__ == "__main__":
    print("HAMMOUR running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
