"""Periscan Web-UI (lokal).

Start:  python webapp.py   ->   http://127.0.0.1:8000
Eine kleine Flask-App, die scan() aus periscan.py nutzt und die Ergebnisse
in einem Dark-Mode-Dashboard (Light/Dark umschaltbar) anzeigt.
"""
from flask import Flask, request, jsonify, Response

from periscan import scan

app = Flask(__name__)

PAGE = r"""<!doctype html>
<html lang="de" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Periscan</title>
<style>
  :root{
    --bg:#0d1117; --panel:#161b22; --panel2:#1c2330; --border:#2a3340;
    --text:#e6edf3; --muted:#8b949e; --accent:#3b82f6; --accent2:#1e40af;
    --crit:#ff4d4f; --high:#ff7a45; --med:#f0a020; --low:#3b82f6; --info:#3fb950; --ok:#6e7681; --unknown:#a371f7;
    --shadow:0 8px 30px rgba(0,0,0,.35);
  }
  [data-theme="light"]{
    --bg:#f4f6fa; --panel:#ffffff; --panel2:#f0f3f8; --border:#dce3ec;
    --text:#1b2330; --muted:#5b6675; --accent:#2563eb; --accent2:#1d4ed8;
    --crit:#d62f30; --high:#e8590c; --med:#c77700; --low:#1d6fe0; --info:#1a7f37; --ok:#8c98a6; --unknown:#7c3aed;
    --shadow:0 8px 30px rgba(20,40,80,.10);
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Inter,system-ui,sans-serif;
    background:var(--bg);color:var(--text);transition:background .25s,color .25s;line-height:1.5}
  .wrap{max-width:1080px;margin:0 auto;padding:28px 20px 60px}
  header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:6px}
  .brand{display:flex;align-items:center;gap:12px}
  .logo{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;
    background:linear-gradient(135deg,var(--accent),var(--accent2));font-size:22px;box-shadow:var(--shadow)}
  h1{font-size:22px;margin:0;letter-spacing:-.3px}
  .sub{color:var(--muted);font-size:13px;margin-top:2px}
  .toggle{background:var(--panel);border:1px solid var(--border);color:var(--text);
    border-radius:10px;padding:9px 13px;cursor:pointer;font-size:14px;display:flex;gap:8px;align-items:center}
  .toggle:hover{border-color:var(--accent)}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:16px;
    padding:18px;box-shadow:var(--shadow)}
  form.searchbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:22px 0 8px}
  input[type=text]{flex:1;min-width:240px;background:var(--panel2);border:1px solid var(--border);
    color:var(--text);border-radius:12px;padding:14px 16px;font-size:16px;outline:none}
  input[type=text]:focus{border-color:var(--accent)}
  button.scan{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:0;
    border-radius:12px;padding:14px 22px;font-size:16px;font-weight:600;cursor:pointer}
  button.scan:disabled{opacity:.6;cursor:default}
  .opts{display:flex;gap:18px;color:var(--muted);font-size:13px;margin:2px 2px 0}
  .opts label{display:flex;gap:7px;align-items:center;cursor:pointer}
  .hint{color:var(--muted);font-size:12.5px;margin:8px 2px 0}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}
  .stat{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px 18px}
  .stat .n{font-size:30px;font-weight:700;line-height:1}
  .stat .l{color:var(--muted);font-size:12.5px;margin-top:7px;text-transform:uppercase;letter-spacing:.5px}
  .sec-title{font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:26px 4px 10px}
  table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:14px}
  th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.5px;background:var(--panel2)}
  tr:last-child td{border-bottom:0}
  .host{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
  .badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700;color:#fff;white-space:nowrap}
  .b-CRITICAL{background:var(--crit)} .b-HIGH{background:var(--high)} .b-MEDIUM{background:var(--med)}
  .b-LOW{background:var(--low)} .b-INFO{background:var(--info)} .b-OK{background:var(--ok)} .b-UNKNOWN{background:var(--unknown)}
  .finding{border-left:3px solid var(--crit);background:var(--panel2);border-radius:10px;padding:12px 14px;margin-bottom:10px}
  .finding .h{font-family:ui-monospace,monospace;font-size:13.5px;font-weight:700}
  .finding .p{color:var(--muted);font-size:13px;margin-top:4px}
  .spinner{width:34px;height:34px;border:3px solid var(--border);border-top-color:var(--accent);
    border-radius:50%;animation:spin .8s linear infinite;margin:30px auto}
  @keyframes spin{to{transform:rotate(360deg)}}
  .muted{color:var(--muted)} .hidden{display:none}
  .rowtoggle{color:var(--accent);cursor:pointer;font-size:13px;user-select:none}
  .tls-bad{color:var(--crit);font-weight:600}.tls-ok{color:var(--info)}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="logo">🛡</div>
      <div><h1>Periscan</h1><div class="sub">Was von deiner Domain ist öffentlich erreichbar?</div></div>
    </div>
    <button class="toggle" id="themeBtn" onclick="toggleTheme()">🌙 <span>Dark</span></button>
  </header>

  <div class="card">
    <form class="searchbar" onsubmit="doScan(event)">
      <input type="text" id="domain" placeholder="deine-domain.tld" autocomplete="off" autofocus>
      <button class="scan" id="scanBtn" type="submit">Scannen</button>
    </form>
    <div class="opts">
      <label><input type="checkbox" id="crt"> auch Certificate-Transparency (crt.sh)</label>
      <label><input type="checkbox" id="local"> lokaler DNS (interner Blick)</label>
    </div>
    <div class="hint">Nur eigene Domains scannen. Standard: öffentlicher DNS (DoH) = echter Außen-Blick.</div>
  </div>

  <div id="out"></div>
</div>

<script>
const ORDER={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4,UNKNOWN:5,OK:6};
const LABEL={CRITICAL:"Kritisch",HIGH:"Hoch",MEDIUM:"Mittel",LOW:"Niedrig",INFO:"Info",OK:"Geschützt",UNKNOWN:"Unbekannt"};

function setTheme(t){
  document.documentElement.setAttribute("data-theme",t);
  localStorage.setItem("es-theme",t);
  const b=document.getElementById("themeBtn");
  b.innerHTML = t==="dark" ? '🌙 <span>Dark</span>' : '☀️ <span>Light</span>';
}
function toggleTheme(){setTheme(document.documentElement.getAttribute("data-theme")==="dark"?"light":"dark");}
setTheme(localStorage.getItem("es-theme")||"dark");

function isNoise(r){return !r.scheme || r.app.startsWith("kein Dienst") || r.app==="Unbekannter Dienst";}
function esc(s){return (s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}

async function doScan(e){
  e.preventDefault();
  const domain=document.getElementById("domain").value.trim();
  if(!domain)return;
  const crt=document.getElementById("crt").checked?1:0;
  const local=document.getElementById("local").checked?1:0;
  const out=document.getElementById("out"), btn=document.getElementById("scanBtn");
  btn.disabled=true;
  out.innerHTML='<div class="spinner"></div><p class="muted" style="text-align:center">Scanne '+esc(domain)+' von außen …</p>';
  try{
    const res=await fetch(`/api/scan?domain=${encodeURIComponent(domain)}&crt=${crt}&local=${local}`);
    const data=await res.json();
    if(data.error){out.innerHTML='<div class="card">Fehler: '+esc(data.error)+'</div>';btn.disabled=false;return;}
    render(data);
  }catch(err){out.innerHTML='<div class="card">Fehler: '+esc(String(err))+'</div>';}
  btn.disabled=false;
}

function render(data){
  const rows=data.results.filter(r=>r.scheme).sort((a,b)=>(ORDER[a.risk]??9)-(ORDER[b.risk]??9)||a.host.localeCompare(b.host));
  const count=k=>rows.filter(r=>r.risk===k).length;
  const findings=[];rows.forEach(r=>(r.findings||[]).forEach(f=>findings.push({host:r.host,...f})));
  const cards=[
    ["Kritisch",count("CRITICAL"),"crit"],["Hoch",count("HIGH"),"high"],
    ["Mittel",count("MEDIUM"),"med"],["Geschützt",count("OK"),"ok"],
    ["Dienste",rows.filter(r=>!isNoise(r)).length,"low"]
  ].map(([l,n,c])=>`<div class="stat"><div class="n" style="color:var(--${c})">${n}</div><div class="l">${l}</div></div>`).join("");

  let html=`<div class="cards">${cards}</div>`;

  if(findings.length){
    html+=`<div class="sec-title">Unauth erreichbare Endpunkte</div>`;
    findings.sort((a,b)=>(ORDER[a.risk]??9)-(ORDER[b.risk]??9));
    html+=findings.map(f=>`<div class="finding" style="border-left-color:var(--${f.risk.toLowerCase()})">
      <div class="h">${esc(f.host)}${esc(f.path)} <span class="badge b-${f.risk}">${LABEL[f.risk]||f.risk}</span></div>
      <div class="p">${esc(f.proves)}</div></div>`).join("");
  }

  const main=rows.filter(r=>!isNoise(r)), noise=rows.filter(isNoise);
  html+=`<div class="sec-title">Öffentlich erreichbare Dienste — ${esc(data.domain)}</div>`;
  html+=`<div class="card" style="padding:0"><table><thead><tr>
    <th>Host</th><th>Dienst</th><th>Status</th><th>TLS</th><th>Risiko</th></tr></thead><tbody>`;
  html+=main.map(rowHtml).join("");
  html+=`</tbody></table></div>`;
  if(noise.length){
    html+=`<p class="rowtoggle" onclick="document.getElementById('noise').classList.toggle('hidden')">▸ ${noise.length} weitere ohne erkennbaren Dienst (anzeigen/ausblenden)</p>`;
    html+=`<div id="noise" class="card hidden" style="padding:0;margin-top:8px"><table><tbody>`+noise.map(rowHtml).join("")+`</tbody></table></div>`;
  }

  if(data.ports&&data.ports.length){
    html+=`<div class="sec-title">Direkt erreichbare Ports (ohne Reverse-Proxy)</div>`;
    html+=`<div class="card" style="padding:0"><table><thead><tr><th>IP : Port</th><th>Dienst</th><th>Risiko</th></tr></thead><tbody>`;
    html+=data.ports.sort((a,b)=>(ORDER[a.risk]??9)-(ORDER[b.risk]??9)).map(p=>
      `<tr><td class="host">${esc(p.ip)}:${p.port}</td><td>${esc(p.service)}</td>
       <td><span class="badge b-${p.risk}">${LABEL[p.risk]||p.risk}</span></td></tr>`).join("");
    html+=`</tbody></table></div>`;
  }

  document.getElementById("out").innerHTML=html;
}

function rowHtml(r){
  const tls=r.tls||{};
  const tlsHtml = tls.valid&&!tls.expired ? '<span class="tls-ok">ok</span>'
    : (tls.expired?'<span class="tls-bad">abgelaufen</span>':'<span class="tls-bad">'+esc((tls.error||"-").slice(0,28))+'</span>');
  const accMap={"geschützt":" (geschützt)","Login":" (Login-Seite)","offen":" (offen, keine Auth)"};
  const acc=accMap[r.access]||"";
  const app = esc(r.app) + (acc?' <span class="muted">'+acc+'</span>':'');
  return `<tr><td class="host">${esc(r.host)}</td><td>${app}</td><td>${r.status??"-"}</td>
    <td>${tlsHtml}</td><td><span class="badge b-${r.risk}">${LABEL[r.risk]||r.risk}</span></td></tr>`;
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


@app.route("/api/scan")
def api_scan():
    domain = (request.args.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "Domain fehlt"}), 400
    use_crt = request.args.get("crt", "0") == "1"
    use_doh = request.args.get("local", "0") != "1"
    data = scan(domain, use_crt=use_crt, timeout=6, workers=20, use_doh=use_doh)
    return jsonify({"domain": domain, "results": data["results"], "ports": data["ports"]})


def main_web():
    """Startet die Web-UI lokal und öffnet automatisch den Browser. Entry-Point: periscan-web."""
    import os
    import sys
    import threading
    import webbrowser
    port = int(os.environ.get("PORT") or (sys.argv[1] if len(sys.argv) > 1 else 8000))
    url = f"http://127.0.0.1:{port}"
    print(f"Periscan Web-UI läuft auf  {url}   (Strg+C zum Beenden)")
    if os.environ.get("ES_NO_BROWSER") != "1":
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main_web()
