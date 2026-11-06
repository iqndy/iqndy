#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPInvestigator — interface web locale.

Lance un petit serveur sur http://127.0.0.1:8765 et ouvre le navigateur :
on saisit une adresse IP, on suit l'analyse en direct, le rapport s'affiche
dans la page et peut être téléchargé. Aucun module externe requis.

  python webapp.py            # accessible depuis ce PC uniquement
  python webapp.py --lan      # accessible aussi depuis le téléphone (même Wi-Fi)
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipinvestigator as inv  # noqa: E402  (installe les modules facultatifs au 1er lancement)

OUT_DIR = os.path.join(inv.BASE_DIR, "rapports")
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


# --------------------------------------------------------------------------- #
# Tâches d'analyse
# --------------------------------------------------------------------------- #
def run_job(job: dict, target: str, ports: list[int], shot: bool) -> None:
    def sink(msg: str) -> None:
        job["log"].append(msg)

    inv.set_log_sink(sink)
    try:
        sink(f"Cible : {target}")
        ip = inv.resolve_target(target)
        if ip != target:
            sink(f"{target} → {ip}")
        job["ip"] = ip
        ipobj = inv.ipaddress.ip_address(ip)
        if ipobj.is_private or ipobj.is_loopback:
            sink("Adresse privée : les sources Internet ne renverront rien d'utile")
        r = inv.investigate(ip, ports, OUT_DIR, do_shot=shot)
        sink("Génération du rapport …")
        base = inv.save_report(r, OUT_DIR)
        s = r["summary"]
        job.update(status="done", report=os.path.basename(base) + ".html",
                   json=os.path.basename(base) + ".json",
                   summary={"site": s["site_name"], "location": s["location"],
                            "anycast": s["anycast"], "nature": s["nature"],
                            "operator": " ".join(x for x in [f"AS{s['asn']}" if s["asn"] else "",
                                                             s["as_org"] or ""] if x),
                            "ports": {str(p): v["state"] for p, v in r["scan"].items()},
                            "duration": r["duration_s"]})
        sink(f"Terminé en {r['duration_s']} s")
    except (OSError, ValueError) as exc:
        job.update(status="error", error=f"Adresse invalide ou introuvable : {exc}")
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        job.update(status="error", error=f"{type(exc).__name__}: {exc}")
    finally:
        inv.set_log_sink(None)


def list_reports() -> list[dict]:
    if not os.path.isdir(OUT_DIR):
        return []
    items = []
    for name in os.listdir(OUT_DIR):
        if not name.endswith(".html"):
            continue
        path = os.path.join(OUT_DIR, name)
        stem = name[:-5]
        parts = stem.rsplit("-", 2)
        ip = parts[0] if len(parts) == 3 else stem
        item = {"file": name, "ip": ip, "mtime": os.path.getmtime(path)}
        try:
            with open(os.path.join(OUT_DIR, stem + ".json"), encoding="utf-8") as fh:
                d = json.load(fh)
            item["site"] = d.get("summary", {}).get("site_name")
            item["location"] = d.get("summary", {}).get("location")
            item["generated"] = d.get("generated")
        except (OSError, ValueError):
            pass
        items.append(item)
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items[:100]


# --------------------------------------------------------------------------- #
# Serveur HTTP
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "IPInvestigator"

    def log_message(self, fmt, *args):  # console plus lisible
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def do_GET(self):  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            return self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
        if u.path == "/api/reports":
            return self._json(list_reports())
        if u.path.startswith("/api/job/"):
            job = JOBS.get(u.path.rsplit("/", 1)[-1])
            if not job:
                return self._json({"error": "tâche inconnue"}, 404)
            since = int(q.get("since", ["0"])[0])
            out = {k: v for k, v in job.items() if k != "log"}
            out["log"] = job["log"][since:]
            out["log_total"] = len(job["log"])
            return self._json(out)
        if u.path.startswith("/rapports/"):
            name = os.path.basename(urllib.parse.unquote(u.path[len("/rapports/"):]))
            path = os.path.join(OUT_DIR, name)
            if not name or not os.path.isfile(path):
                return self._send(404, b"introuvable", "text/plain; charset=utf-8")
            ctype = {"html": "text/html; charset=utf-8", "json": "application/json; charset=utf-8",
                     "png": "image/png"}.get(name.rsplit(".", 1)[-1], "application/octet-stream")
            extra = {}
            if q.get("download"):
                extra["Content-Disposition"] = f'attachment; filename="{name}"'
            with open(path, "rb") as fh:
                return self._send(200, fh.read(), ctype, extra)
        self._send(404, b"introuvable", "text/plain; charset=utf-8")

    def do_POST(self):  # noqa: N802
        if self.path != "/api/scan":
            return self._send(404, b"introuvable", "text/plain; charset=utf-8")
        try:
            n = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(min(n, 10000)) or b"{}")
            target = str(data.get("target", "")).strip()
            if not target:
                raise ValueError("adresse vide")
            ports = inv.parse_ports(data.get("ports", "80,443"))
            shot = bool(data.get("screenshot", True))
        except (ValueError, TypeError) as exc:
            return self._json({"error": str(exc)}, 400)
        jid = uuid.uuid4().hex[:12]
        job = {"id": jid, "target": target, "status": "running", "log": [], "started": time.time()}
        with JOBS_LOCK:
            JOBS[jid] = job
        threading.Thread(target=run_job, args=(job, target, ports, shot), daemon=True).start()
        self._json({"id": jid})


def lan_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))  # aucune donnée envoyée
            return s.getsockname()[0]
    except OSError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Interface web d'IPInvestigator")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--lan", action="store_true",
                    help="rendre l'interface accessible aux autres appareils du réseau local")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)
    threading.Thread(target=inv.ensure_db, daemon=True).start()

    host = "0.0.0.0" if a.lan else "127.0.0.1"
    port = a.port
    for _ in range(20):
        try:
            srv = ThreadingHTTPServer((host, port), Handler)
            break
        except OSError:
            port += 1
    else:
        print("Impossible d'ouvrir un port local.")
        return 1

    url = f"http://127.0.0.1:{port}/"
    print(f"\n=== {inv.APP} {inv.VERSION} — interface web ===\n")
    print(f"  Ouvrez : {url}")
    if a.lan and lan_ip():
        print(f"  Depuis le téléphone (même Wi-Fi) : http://{lan_ip()}:{port}/")
    print("\n  Laissez cette fenêtre ouverte pendant l'utilisation (Ctrl+C pour arrêter).\n")
    if not a.no_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# --------------------------------------------------------------------------- #
# Page web
# --------------------------------------------------------------------------- #
INDEX_HTML = r"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IPInvestigator</title>
<style>
:root{--bg:#f4f5f8;--card:#fff;--fg:#1d2330;--muted:#6b7280;--line:#e3e6ec;--head:#f0f2f6;
--accent:#2457d6;--accent-fg:#fff;--ok:#127a3e;--okbg:#e3f5ea;--bad:#b42318;--badbg:#fde8e7;--warn:#9a6700;--warnbg:#fff4d6}
@media (prefers-color-scheme:dark){:root{--bg:#11141a;--card:#1a1e26;--fg:#e6e9ef;--muted:#9aa3b2;
--line:#2c323d;--head:#222733;--accent:#7aa2ff;--accent-fg:#0b1020;--ok:#5fd394;--okbg:#14301f;
--bad:#ff8a80;--badbg:#3a1714;--warn:#f5c451;--warnbg:#3a2e10}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
header h1{margin:0;font-size:26px;letter-spacing:-.4px}
header p{margin:0;color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-top:18px}
.card h2{margin:0 0 12px;font-size:17px}
form .row{display:flex;gap:10px;flex-wrap:wrap}
input[type=text]{flex:1 1 260px;font:inherit;font-size:18px;padding:12px 14px;border:1px solid var(--line);
 border-radius:10px;background:var(--bg);color:var(--fg);min-width:0}
input[type=text]:focus{outline:2px solid var(--accent);outline-offset:1px}
button,.btn{font:inherit;font-weight:600;padding:12px 20px;border-radius:10px;border:0;cursor:pointer;
 background:var(--accent);color:var(--accent-fg);text-decoration:none;display:inline-block}
button:disabled{opacity:.55;cursor:wait}
.btn.sec{background:var(--head);color:var(--fg)}
.opts{display:flex;gap:18px;flex-wrap:wrap;margin-top:12px;color:var(--muted);font-size:14px;align-items:center}
.opts input[type=text]{flex:0 0 140px;font-size:14px;padding:6px 10px}
.examples{margin-top:10px;font-size:13px;color:var(--muted)}
.examples a{color:var(--accent);cursor:pointer;margin-right:10px}
#log{font:12.5px/1.6 ui-monospace,Consolas,monospace;background:var(--head);border-radius:8px;padding:10px 12px;
 max-height:240px;overflow:auto;white-space:pre-wrap;margin:0}
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--line);border-top-color:var(--accent);
 border-radius:50%;animation:s 0.8s linear infinite;vertical-align:-2px;margin-right:8px}
@keyframes s{to{transform:rotate(360deg)}}
.sum{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-bottom:14px}
.sum div{background:var(--head);border-radius:8px;padding:8px 12px}
.sum b{display:block;font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.3px}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
iframe{width:100%;height:80vh;border:1px solid var(--line);border-radius:10px;background:#fff}
.err{color:var(--bad);background:var(--badbg);padding:10px 12px;border-radius:8px}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.badge.warn{color:var(--warn);background:var(--warnbg)}
table{width:100%;border-collapse:collapse;font-size:14px}
td{padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
td.when{color:var(--muted);white-space:nowrap;font-size:13px}
.hist a{color:var(--accent);cursor:pointer;font-weight:600;text-decoration:none}
.muted{color:var(--muted)} .hidden{display:none}
.note{color:var(--muted);font-size:12.5px;margin-top:18px}
@media (max-width:640px){.wrap{padding:16px 12px 40px} button{width:100%} td.when{display:none} iframe{height:75vh}}
</style></head><body><div class="wrap">
<header><h1>IPInvestigator</h1><p>scan des ports web, capture et fiche complète d'une adresse IP</p></header>

<section class="card">
 <form id="f" autocomplete="off">
  <div class="row">
   <input type="text" id="target" placeholder="Adresse IP, ex. 45.33.32.156" required autofocus>
   <button id="go" type="submit">Analyser</button>
  </div>
  <div class="opts">
   <label>Ports <input type="text" id="ports" value="80,443"></label>
   <label><input type="checkbox" id="shot" checked> Capture d'écran</label>
  </div>
  <div class="examples">Exemples :
   <a data-ip="45.33.32.156">45.33.32.156 (scanme.nmap.org)</a>
   <a data-ip="1.1.1.1">1.1.1.1</a>
   <a data-ip="15.197.175.4">15.197.175.4</a>
  </div>
 </form>
</section>

<section class="card hidden" id="progress">
 <h2 id="ptitle"><span class="spin"></span>Analyse en cours…</h2>
 <pre id="log"></pre>
</section>

<section class="card hidden" id="result">
 <h2 id="rtitle">Résultat</h2>
 <div class="sum" id="sum"></div>
 <div class="actions">
  <a class="btn" id="open" target="_blank">Ouvrir le rapport en plein écran</a>
  <a class="btn sec" id="dl">Télécharger le HTML</a>
  <a class="btn sec" id="dljson">Télécharger le JSON</a>
 </div>
 <iframe id="frame" title="Rapport"></iframe>
</section>

<section class="card">
 <h2>Rapports précédents</h2>
 <div id="hist" class="hist"><p class="muted">Aucun rapport pour l'instant.</p></div>
</section>

<p class="note">N'analysez que des adresses pour lesquelles vous êtes autorisé. La géolocalisation IP
indique la zone de l'opérateur, pas l'adresse d'une personne.</p>
</div>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let timer = null;

document.querySelectorAll(".examples a").forEach(a => a.onclick = () => { $("target").value = a.dataset.ip; $("target").focus(); });

$("f").onsubmit = async e => {
  e.preventDefault();
  const target = $("target").value.trim();
  if (!target) return;
  $("go").disabled = true;
  $("result").classList.add("hidden");
  $("progress").classList.remove("hidden");
  $("ptitle").innerHTML = '<span class="spin"></span>Analyse de ' + esc(target) + '…';
  $("log").textContent = "";
  try {
    const r = await fetch("/api/scan", {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target, ports: $("ports").value, screenshot: $("shot").checked})});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "erreur");
    poll(d.id, 0);
  } catch (err) { fail(err.message); }
};

async function poll(id, since) {
  try {
    const r = await fetch("/api/job/" + id + "?since=" + since);
    const d = await r.json();
    if (d.log.length) { $("log").textContent += d.log.join("\n") + "\n"; $("log").scrollTop = 1e9; }
    if (d.status === "running") { timer = setTimeout(() => poll(id, d.log_total), 700); return; }
    if (d.status === "error") return fail(d.error);
    done(d);
  } catch (err) { timer = setTimeout(() => poll(id, since), 1500); }
}

function fail(msg) {
  $("go").disabled = false;
  $("ptitle").innerHTML = '<span class="err">Échec : ' + esc(msg) + '</span>';
}

function showReport(file, jsonFile, title, summary) {
  const url = "/rapports/" + encodeURIComponent(file);
  $("rtitle").textContent = title;
  $("open").href = url;
  $("dl").href = url + "?download=1";
  $("dljson").href = "/rapports/" + encodeURIComponent(jsonFile) + "?download=1";
  $("frame").src = url;
  const s = summary || {};
  const cells = [];
  if (s.site !== undefined) cells.push(["Site", s.site || "—"]);
  if (s.location !== undefined) cells.push(["Localisation", (s.location || "—") + (s.anycast ? ' <span class="badge warn">anycast</span>' : "")]);
  if (s.operator !== undefined) cells.push(["Opérateur", s.operator || "—"]);
  if (s.nature) cells.push(["Nature", s.nature]);
  if (s.ports) cells.push(["Ports", Object.entries(s.ports).map(([p, st]) => p + " : " + st).join("<br>")]);
  $("sum").innerHTML = cells.map(([k, v]) => "<div><b>" + esc(k) + "</b>" + (k === "Localisation" || k === "Ports" ? v : esc(v)) + "</div>").join("");
  $("result").classList.remove("hidden");
  $("result").scrollIntoView({behavior: "smooth"});
}

function done(d) {
  $("go").disabled = false;
  $("progress").classList.add("hidden");
  showReport(d.report, d.json, "Résultat — " + (d.ip || d.target), d.summary);
  loadHistory();
}

async function loadHistory() {
  try {
    const items = await (await fetch("/api/reports")).json();
    if (!items.length) return;
    $("hist").innerHTML = "<table>" + items.map(it =>
      "<tr><td><a data-f=\"" + esc(it.file) + "\" data-ip=\"" + esc(it.ip) + "\">" + esc(it.ip) + "</a></td>" +
      "<td>" + esc(it.site || "") + "</td><td>" + esc(it.location || "") + "</td>" +
      '<td class="when">' + esc(it.generated || new Date(it.mtime * 1000).toLocaleString()) + "</td></tr>").join("") + "</table>";
    $("hist").querySelectorAll("a[data-f]").forEach(a => a.onclick = () =>
      showReport(a.dataset.f, a.dataset.f.replace(/\.html$/, ".json"), "Rapport — " + a.dataset.ip, {}));
  } catch (e) {}
}
loadHistory();
</script></body></html>"""


if __name__ == "__main__":
    sys.exit(main())
