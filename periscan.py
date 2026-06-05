#!/usr/bin/env python3
"""
Periscan — Homelab Exposure Checker

Prüft von außen, welche Dienste deiner Domain öffentlich erreichbar sind,
erkennt bekannte Self-Hosting-Apps (Proxmox, NPM, Portainer, Pi-hole,
code-server, Vaultwarden, Grafana ...) und bewertet das Risiko in Klartext.

NUR auf eigenen Domains anwenden.

Usage:
    python periscan.py chillyka.uk
    python periscan.py chillyka.uk --no-crt --timeout 5 --json report.json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore
except ImportError:
    print("Fehlt: 'requests'. Installieren mit:  pip install requests rich")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    _console = Console()
    _RICH = True
except ImportError:
    _RICH = False
    _console = None

UA = "Periscan/0.7 (+https://github.com/)"

# Übliche Subdomains im Self-Hosting-Umfeld (Wortliste-Fallback)
COMMON_SUBS = [
    "www", "vault", "photos", "immich", "npm", "proxy", "portainer", "docker",
    "proxmox", "pve", "pihole", "dns", "grafana", "prometheus", "git", "gitea",
    "code", "vscode", "wiki", "docs", "paperless", "tasks", "vikunja", "n8n",
    "automate", "home", "dash", "dashboard", "uptime", "status", "beszel",
    "tools", "invoice", "cloud", "nextcloud", "jellyfin", "plex", "media",
    "opnsense", "router", "fw", "firewall", "ollama", "ai", "bookmarks",
    "karakeep", "admin", "panel", "mail", "vpn", "wg",
]

# Fingerprint-DB (62 verifizierte Self-Hosting-Apps) — ausgelagert in fingerprints.py
# Felder je Eintrag: app, category, risk, intended_public, titles, servers, headers, body_markers, login_paths
from fingerprints import FINGERPRINTS

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5, "OK": 6}
RISK_COLOR = {"CRITICAL": "bold white on red", "HIGH": "red", "MEDIUM": "yellow",
              "LOW": "cyan", "INFO": "green", "UNKNOWN": "magenta", "OK": "dim"}


def crt_sh_subdomains(domain: str, timeout: int) -> set[str]:
    """Subdomains aus Certificate-Transparency-Logs (crt.sh)."""
    found: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=timeout + 10, headers={"User-Agent": UA})
        if r.status_code == 200 and r.text.strip():
            for entry in r.json():
                for name in str(entry.get("name_value", "")).split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain) and "@" not in name:
                        found.add(name)
    except Exception as e:  # crt.sh down / rate-limit -> Wortliste reicht
        _warn(f"crt.sh nicht erreichbar ({e}) – nutze nur Wortliste.")
    return found


def candidate_hosts(domain: str, use_crt: bool, timeout: int) -> list[str]:
    hosts: set[str] = {domain}
    hosts.update(f"{sub}.{domain}" for sub in COMMON_SUBS)
    if use_crt:
        hosts.update(crt_sh_subdomains(domain, timeout))
    return sorted(hosts)


# DoH-Resolver für den echten Außen-Blick (umgeht lokales/Split-Horizon-DNS)
DOH_ENDPOINTS = [
    ("https://1.1.1.1/dns-query", {"accept": "application/dns-json"}),
    ("https://dns.google/resolve", {}),
]


def resolve_public(host: str, timeout: int) -> str | None:
    """Öffentliche IP über DoH (Cloudflare, Fallback Google). Bevorzugt A (IPv4),
    fällt auf AAAA (IPv6) zurück → deckt auch IPv6-only-Homelabs (CGNAT) ab."""
    for url, extra in DOH_ENDPOINTS:
        for rtype, code in (("A", 1), ("AAAA", 28)):
            try:
                r = requests.get(url, params={"name": host, "type": rtype},
                                 headers={"User-Agent": UA, **extra}, timeout=timeout)
                if r.status_code != 200:
                    continue
                for ans in r.json().get("Answer", []):
                    if ans.get("type") == code:
                        return ans.get("data")
            except Exception:
                continue
    return None


def resolve_local(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def adjust_risk(res: dict, risk: str) -> str:
    """Status-/TLS-basierte Korrektur des Risikos."""
    status = res.get("status")
    if status in (401, 403):           # Zugriffsschutz/Access-List -> nicht offen exponiert
        return "OK"
    if status is not None and status >= 500:   # Origin/Proxy-Fehler -> nicht wirklich erreichbar
        return "LOW"
    tls = res.get("tls", {})
    if res.get("scheme") == "https" and not tls.get("valid") and risk in ("INFO", "LOW", "OK"):
        return "MEDIUM"
    return risk


def detect_access(res: dict) -> str:
    """Konservative Zugangs-Einstufung: nur behaupten, was belegbar ist.
    'geschützt' (401/403) oder 'Login' (Passwortfeld im HTML). Sonst leer —
    SPAs rendern Login per JS, fehlendes Passwortfeld beweist KEINE fehlende Auth.
    Der echte 'wirklich offen'-Beweis kommt aus den aktiven exposure_checks (findings)."""
    st = res.get("status")
    if st in (401, 403):
        return "geschützt"
    if st and 200 <= st < 400:
        body = res.get("body") or ""
        if 'type="password"' in body or 'name="password"' in body or 'id="password"' in body:
            return "Login"
    return ""


def tls_info(host: str, timeout: int) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        not_after = cert.get("notAfter")
        expired = False
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expired = exp < datetime.now(timezone.utc)
        return {"valid": True, "expired": expired, "not_after": not_after}
    except ssl.SSLError as e:
        return {"valid": False, "error": f"Zertifikat ungültig/self-signed ({e.__class__.__name__})"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""


def probe(host: str, ip: str, timeout: int) -> dict | None:
    """Versucht den (bereits aufgelösten) Host von außen zu erreichen (https, dann http)."""
    priv = _is_private(ip)

    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}", timeout=timeout, allow_redirects=True,
                             verify=False, headers={"User-Agent": UA})
        except Exception:
            continue
        res = {
            "host": host, "ip": ip, "private": priv, "scheme": scheme, "status": r.status_code,
            "final_url": r.url, "server": r.headers.get("Server", ""),
            "title": extract_title(r.text),
            "headers_str": " ".join(f"{k}: {v}" for k, v in r.headers.items()).lower(),
            "body": (r.text or "")[:20000].lower(),
            "tls": tls_info(host, timeout) if scheme == "https" else {"valid": False, "error": "nur HTTP"},
        }
        return res
    return {"host": host, "ip": ip, "private": priv, "scheme": None, "status": None,
            "final_url": "", "server": "", "title": "",
            "tls": {"valid": False, "error": "offener Port, keine HTTP-Antwort"}}


def identify(res: dict):
    """-> (App-Name, Risiko, matched_fp_or_None)."""
    status = res.get("status")
    if status in (520, 521, 522, 523, 524, 525, 526, 530):  # Cloudflare-Origin-Fehler = kein Dienst
        return "kein Dienst (Cloudflare Origin-Fehler)", "LOW", None
    title = (res.get("title") or "").lower()
    server = (res.get("server") or "").lower()
    headers_str = res.get("headers_str") or ""
    body = res.get("body") or ""
    for fp in FINGERPRINTS:
        name = fp.get("app") or fp.get("name") or "?"
        if (any(t.lower() in title for t in fp.get("titles", []))
                or any(s.lower() in server for s in fp.get("servers", []))
                or any(h.lower() in headers_str for h in fp.get("headers", []))
                or any(b.lower() in body for b in fp.get("body_markers", []))):
            return name, fp["risk"], fp
    if res.get("status") is None:
        return "Offener Port (keine Web-App)", "UNKNOWN", None
    return "Unbekannter Dienst", "LOW", None


_VER_RE = re.compile(r'"?(?:version(?:string)?)"?\s*[:=]\s*"?v?(\d+\.\d+[\w.\-]{0,18})', re.I)


def _extract_version(r) -> str | None:
    """Zieht eine Versionsangabe aus einer Unauth-Antwort (JSON-Feld oder Regex). Nur Info, KEIN Vuln-Urteil."""
    try:
        j = r.json()
        if isinstance(j, dict):
            for k in ("version", "versionstring", "Version", "VersionString"):
                if j.get(k):
                    return str(j[k])[:24]
            d = j.get("data")
            if isinstance(d, dict) and d.get("version"):
                return str(d["version"])[:24]
    except Exception:
        pass
    m = _VER_RE.search(r.text or "")
    return m.group(1)[:24] if m else None


def run_checks(host: str, fp: dict, timeout: int) -> list[dict]:
    """v0.4: aktive Unauth-Pfad-Checks. Bestätigt App-Identität + deckt offene Endpunkte/Setups auf.
    Jeder Check: {path, status=200, body_contains=[...], proves, risk}. v1.0: + Versions-Erkennung."""
    findings = []
    for chk in fp.get("exposure_checks", []):
        path = chk.get("path", "/")
        try:
            r = requests.get(f"https://{host}{path}", timeout=timeout, allow_redirects=True,
                             verify=False, headers={"User-Agent": UA})
        except Exception:
            continue
        if r.status_code != chk.get("status", 200):
            continue
        markers = chk.get("body_contains", [])
        text = (r.text or "").lower()
        if markers and not any(m.lower() in text for m in markers):
            continue
        findings.append({"path": path, "proves": chk.get("proves", ""),
                         "risk": chk.get("risk", "MEDIUM"), "version": _extract_version(r)})
    return findings


RECO = {
    "CRITICAL": "SOFORT vom Internet trennen — nur via VPN/Access-List erreichbar machen.",
    "HIGH": "Nicht öffentlich exponieren — hinter VPN oder IP-Allowlist legen.",
    "MEDIUM": "Prüfen ob öffentlich nötig; starke Auth + 2FA erzwingen.",
    "LOW": "Bewusst exponiert? Falls nein, internal-only setzen.",
    "INFO": "Für öffentliche Nutzung gedacht — Auth/2FA & Updates aktuell halten.",
    "UNKNOWN": "Manuell prüfen, was hier läuft.",
}


# Gängige Self-Hosting-Ports (für direkte Port-Forwards ohne Reverse-Proxy). kind: raw/http/https
PORT_SERVICES = {
    2375: ("Docker Engine API (unverschlüsselt)", "CRITICAL", "raw"),
    2376: ("Docker Engine API (TLS)", "HIGH", "raw"),
    6379: ("Redis", "HIGH", "raw"),
    5432: ("PostgreSQL", "HIGH", "raw"),
    3306: ("MySQL/MariaDB", "HIGH", "raw"),
    27017: ("MongoDB", "HIGH", "raw"),
    11211: ("Memcached", "MEDIUM", "raw"),
    9200: ("Elasticsearch", "HIGH", "http"),
    8006: ("Proxmox VE", "CRITICAL", "https"),
    8007: ("Proxmox Backup Server", "HIGH", "https"),
    81: ("Nginx Proxy Manager (Admin)", "HIGH", "http"),
    9000: ("Portainer / MinIO / Web-App", "HIGH", "http"),
    9443: ("Portainer (HTTPS)", "HIGH", "https"),
    8123: ("Home Assistant", "HIGH", "http"),
    8200: ("HashiCorp Vault", "HIGH", "https"),
    5000: ("Synology DSM / Web-App", "MEDIUM", "http"),
    5001: ("Synology DSM (HTTPS)", "MEDIUM", "https"),
    9090: ("Cockpit / Prometheus", "MEDIUM", "http"),
    19999: ("Netdata", "MEDIUM", "http"),
    11434: ("Ollama API", "MEDIUM", "http"),
    8384: ("Syncthing GUI", "MEDIUM", "http"),
    3000: ("Web-App (Grafana/Gitea/…)", "MEDIUM", "http"),
    8080: ("Web-App (HTTP-Alt)", "MEDIUM", "http"),
    8443: ("Web-App (HTTPS-Alt)", "MEDIUM", "https"),
    8096: ("Jellyfin", "INFO", "http"),
    32400: ("Plex", "INFO", "http"),
    3001: ("Uptime Kuma / Web-App", "LOW", "http"),
    7878: ("Radarr", "LOW", "http"),
    8989: ("Sonarr", "LOW", "http"),
    9696: ("Prowlarr", "LOW", "http"),
}


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _worst_risk(*risks) -> str:
    worst = min(RISK_ORDER.get(r, 9) for r in risks)
    return next(k for k, v in RISK_ORDER.items() if v == worst)


def scan_ports(ips: list[str], timeout: int, workers: int) -> list[dict]:
    """Prüft gängige Self-Hosting-Ports auf direkten (Nicht-CDN-)Public-IPs."""
    pairs = [(ip, port) for ip in ips for port in PORT_SERVICES]

    def check(pair):
        ip, port = pair
        if not _tcp_open(ip, port, min(timeout, 3)):
            return None
        name, risk, kind = PORT_SERVICES[port]
        f = {"ip": ip, "port": port, "service": name, "risk": risk, "status": None}
        if kind in ("http", "https"):
            scheme = "https" if kind == "https" else "http"
            try:
                r = requests.get(f"{scheme}://{ip}:{port}", timeout=timeout, verify=False,
                                 allow_redirects=True, headers={"User-Agent": UA})
                res = {"title": extract_title(r.text), "server": r.headers.get("Server", ""),
                       "headers_str": " ".join(f"{k}: {v}" for k, v in r.headers.items()).lower(),
                       "body": (r.text or "")[:20000].lower(), "status": r.status_code}
                app, arisk, _ = identify(res)
                if app and app != "Unbekannter Dienst" and not app.startswith("kein Dienst"):
                    f["service"], f["risk"] = app, _worst_risk(risk, arisk)
                f["status"] = r.status_code
            except Exception:
                pass
        return f

    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for f in ex.map(check, pairs):
            if f:
                findings.append(f)
    findings.sort(key=lambda x: (RISK_ORDER.get(x["risk"], 9), x["ip"], x["port"]))
    return findings


def scan(domain: str, use_crt: bool, timeout: int, workers: int,
         use_doh: bool = True, do_ports: bool = True) -> dict:
    hosts = candidate_hosts(domain, use_crt, timeout)
    mode = "öffentlicher DNS (DoH) – echter Außen-Blick" if use_doh else "lokaler DNS – interner Blick"
    _info(f"Löse {len(hosts)} mögliche Hosts auf via {mode} ...")

    resolver = (lambda h: resolve_public(h, timeout)) if use_doh else resolve_local
    mapping: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for host, ip in zip(hosts, ex.map(resolver, hosts)):
            if ip:
                mapping[host] = ip
    _info(f"{len(mapping)} Hosts lösen auf – prüfe Erreichbarkeit ...")

    # getaddrinfo so patchen, dass Verbindungen zur öffentlichen IP gehen,
    # SNI/Host aber der Hostname bleiben (sonst routen Cloudflare/NPM falsch).
    restore = None
    if use_doh:
        _orig_gai = socket.getaddrinfo
        socket.getaddrinfo = lambda h, *a, **k: _orig_gai(mapping.get(h, h), *a, **k)
        restore = _orig_gai
    try:
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for res in ex.map(lambda it: probe(it[0], it[1], timeout), list(mapping.items())):
                if res:
                    app, risk, fp = identify(res)
                    res["app"], res["risk"], res["_fp"] = app, adjust_risk(res, risk), fp
                    res["access"] = detect_access(res)
                    results.append(res)
        # v0.4: aktive Pfad-Checks für identifizierte Apps mit definierten exposure_checks
        checkable = [r for r in results if r.get("_fp") and r["_fp"].get("exposure_checks")]
        if checkable:
            _info(f"Aktive Endpunkt-Checks für {len(checkable)} identifizierte Dienste ...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                for r, finds in zip(checkable, ex.map(
                        lambda rr: run_checks(rr["host"], rr["_fp"], timeout), checkable)):
                    if finds:
                        r["findings"] = finds
                        worst = min([RISK_ORDER.get(r["risk"], 9)]
                                    + [RISK_ORDER.get(f["risk"], 9) for f in finds])
                        r["risk"] = next(k for k, v in RISK_ORDER.items() if v == worst)
    finally:
        if restore:
            socket.getaddrinfo = restore
    for r in results:
        r.pop("_fp", None)
    results.sort(key=lambda r: (RISK_ORDER.get(r["risk"], 9), r["host"]))

    # Direkte Port-Checks auf Public-IPs, die NICHT hinter Cloudflare/CDN liegen
    port_findings = []
    if do_ports:
        cdn = {r["ip"] for r in results
               if "cloudflare" in (r.get("server", "").lower())
               or "cloudflare" in (r.get("headers_str") or "")}
        targets = sorted({ip for ip in mapping.values() if not _is_private(ip)} - cdn)[:8]
        if targets:
            _info(f"Port-Checks auf {len(targets)} direkte IP(s) ...")
            port_findings = scan_ports(targets, timeout, workers)
        elif cdn:
            _info("Alle Hosts hinter Cloudflare/CDN — direkte Port-Checks übersprungen (Origin verborgen).")
    for r in results:                       # große Felder nach CDN-Erkennung entfernen
        r.pop("headers_str", None)
        r.pop("body", None)
    return {"results": results, "ports": port_findings}


# ---------- Ausgabe ----------
def _info(msg: str):
    print(f"[*] {msg}") if not _RICH else _console.print(f"[bold blue]›[/] {msg}")


def _warn(msg: str):
    print(f"[!] {msg}") if not _RICH else _console.print(f"[yellow]![/] {msg}")


def render(domain: str, results: list[dict], ports: list[dict] = None):
    ports = ports or []
    reachable = [r for r in results if r["scheme"]]
    internal = [r for r in reachable if r.get("private")]
    split_horizon = bool(internal) and len(internal) >= max(1, len(reachable) // 2)
    if split_horizon:
        msg = (f"{len(internal)} Hosts lösen auf PRIVATE IPs auf (z. B. 10.x/192.168.x) — "
               "dieser Rechner nutzt internes/Split-Horizon-DNS.\n"
               "Das misst die INTERNE Erreichbarkeit, NICHT die echte Internet-Exposition.\n"
               "Für einen echten Außen-Test: von außerhalb deines Netzes laufen lassen "
               "(oder später die Hosted-Version).")
        if _RICH:
            _console.print(Panel(msg, title="[yellow]Achtung: interner Blick[/]", border_style="yellow"))
        else:
            _warn("INTERNER BLICK (Split-Horizon-DNS) — nicht die echte Internet-Exposition.")
    if _RICH:
        table = Table(title=f"Öffentlich erreichbare Dienste — {domain}", show_lines=False)
        table.add_column("Host", overflow="fold")
        table.add_column("Dienst")
        table.add_column("Status", justify="right")
        table.add_column("TLS")
        table.add_column("Risiko")
        for r in reachable:
            tls = r["tls"]
            tls_txt = "[green]ok[/]" if tls.get("valid") and not tls.get("expired") else \
                ("[red]abgelaufen[/]" if tls.get("expired") else f"[red]{tls.get('error','-')[:24]}[/]")
            style = RISK_COLOR.get(r["risk"], "")
            acc = {"geschützt": " (geschützt)", "Login": " (Login-Seite)",
                   "offen": " (offen, keine Auth)"}.get(r.get("access", ""), "")
            app_txt = r["app"] + acc
            table.add_row(r["host"], app_txt, str(r["status"] or "-"), tls_txt,
                          f"[{style}]{r['risk']}[/]")
        _console.print(table)
        crit = [r for r in reachable if r["risk"] in ("CRITICAL", "HIGH")]
        if crit:
            lines = [f"[bold]{r['host']}[/] — {r['app']}\n   → {RECO.get(r['risk'])}" for r in crit]
            _console.print(Panel("\n".join(lines), title="[red]Dringend prüfen[/]", border_style="red"))
        else:
            _console.print(Panel("Keine kritischen Expositionen gefunden.", border_style="green"))
        findings = [(r["host"], f) for r in reachable for f in r.get("findings", [])]
        if findings:
            lines = []
            for h, f in findings:
                ver = f" · Version {f['version']} (CVEs prüfen)" if f.get("version") else ""
                lines.append(f"[bold]{h}{f['path']}[/] — {f['proves']}{ver} "
                             f"[{RISK_COLOR.get(f['risk'], '')}]{f['risk']}[/]")
            _console.print(Panel("\n".join(lines), title="[red]Unauth erreichbare Endpunkte[/]",
                                 border_style="red"))
        if ports:
            pt = Table(title="Direkt erreichbare Ports (ohne Reverse-Proxy)", show_lines=False)
            pt.add_column("IP:Port")
            pt.add_column("Dienst")
            pt.add_column("Risiko")
            for p in ports:
                pt.add_row(f"{p['ip']}:{p['port']}", p["service"],
                           f"[{RISK_COLOR.get(p['risk'], '')}]{p['risk']}[/]")
            _console.print(pt)
        _console.print(f"[dim]{len(reachable)} erreichbar von {len(results)} aufgelösten Hosts.[/]")
    else:
        print(f"\n=== Öffentlich erreichbar — {domain} ===")
        for r in reachable:
            suffix = {"geschützt": " (geschützt)", "Login": " (Login)",
                      "offen": " (offen)"}.get(r.get("access", ""), "")
            print(f"[{r['risk']:8}] {r['host']:35} {r['app']}{suffix}  (HTTP {r['status']})")
        for r in reachable:
            for f in r.get("findings", []):
                print(f"   ! UNAUTH {r['host']}{f['path']} — {f['proves']} [{f['risk']}]")
        if ports:
            print("\n=== Direkt erreichbare Ports ===")
            for p in ports:
                print(f"[{p['risk']:8}] {p['ip']}:{p['port']}  {p['service']}")
        print(f"\n{len(reachable)} erreichbar von {len(results)} aufgelösten Hosts.")


# ---------- Monitoring: Snapshots, Diff über Zeit, Alerts ----------
def _state_path(state_dir: str, domain: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)
    return os.path.join(state_dir, f"{safe}.json")


def _load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(path: str, data: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def exposures(data: dict) -> dict:
    """Reduziert ein Scan-Ergebnis auf die bemerkenswerten Expositionen (für Diff/Alert)."""
    items = {}
    for r in data["results"]:
        if not r.get("scheme") or r["risk"] in ("OK", "UNKNOWN"):
            continue
        app = r.get("app", "")
        if app.startswith("kein Dienst") or app == "Unbekannter Dienst":
            continue
        items[f"host:{r['host']}"] = {"label": f"{r['host']} — {app}", "risk": r["risk"]}
        for f in r.get("findings", []):
            items[f"find:{r['host']}{f['path']}"] = {
                "label": f"{r['host']}{f['path']} — {f.get('proves', '')[:90]}", "risk": f["risk"]}
    for p in data.get("ports", []):
        items[f"port:{p['ip']}:{p['port']}"] = {"label": f"{p['ip']}:{p['port']} — {p['service']}", "risk": p["risk"]}
    return items


def diff_exposures(prev: dict, curr: dict):
    added = [dict(key=k, **v) for k, v in curr.items() if k not in prev]
    removed = [dict(key=k, **v) for k, v in prev.items() if k not in curr]
    changed = [dict(key=k, was=prev[k]["risk"], **v)
               for k, v in curr.items() if k in prev and prev[k]["risk"] != v["risk"]]
    return added, removed, changed


def _alert_text(domain, added, removed, changed):
    lines = [f"🛡 Periscan — Änderungen bei {domain}"]
    for a in added:
        lines.append(f"🔴 NEU [{a['risk']}] {a['label']}")
    for c in changed:
        lines.append(f"⚠ GEÄNDERT [{c['was']}→{c['risk']}] {c['label']}")
    for r in removed:
        lines.append(f"✅ WEG  {r['label']}")
    return "\n".join(lines)


def _post_discord(url, content):
    try:
        requests.post(url, json={"content": content[:1900]}, timeout=10)
        _info("Discord-Alert gesendet.")
    except Exception as e:
        _warn(f"Discord-Alert fehlgeschlagen: {e}")


def _post_webhook(url, payload):
    try:
        requests.post(url, json=payload, timeout=10)
        _info("Webhook-Alert gesendet.")
    except Exception as e:
        _warn(f"Webhook-Alert fehlgeschlagen: {e}")


def report_changes(domain, data, state_dir, discord=None, webhook=None, alert_min="MEDIUM"):
    """Vergleicht mit dem letzten Snapshot, zeigt + alarmiert Änderungen, speichert neuen Snapshot."""
    curr = exposures(data)
    path = _state_path(state_dir, domain)
    prev = _load_state(path)
    added, removed, changed = diff_exposures(prev, curr)
    _save_state(path, curr)
    if not prev:
        _info(f"Erster Snapshot gespeichert ({len(curr)} Expositionen) — ab jetzt werden Änderungen erkannt.")
        return
    if not (added or removed or changed):
        _info("Keine Änderungen seit letztem Scan.")
        return
    text = _alert_text(domain, added, removed, changed)
    if _RICH:
        _console.print(Panel(text, title="[yellow]Änderungen seit letztem Scan[/]", border_style="yellow"))
    else:
        print("\n" + text)
    thr = RISK_ORDER.get(alert_min, 2)
    worth = [x for x in (added + changed) if RISK_ORDER.get(x["risk"], 9) <= thr]
    if worth and (discord or webhook):
        if discord:
            _post_discord(discord, text)
        if webhook:
            _post_webhook(webhook, {"domain": domain, "added": added, "removed": removed, "changed": changed})


def main():
    p = argparse.ArgumentParser(description="Periscan — Homelab Exposure Checker (nur eigene Domains!)")
    p.add_argument("domain", nargs="*", help="Eine oder mehrere Domains, z.B. chillyka.uk meine-domain.de")
    p.add_argument("--no-crt", action="store_true", help="Certificate-Transparency-Lookup überspringen")
    p.add_argument("--local-dns", action="store_true",
                   help="Lokalen DNS statt DoH nutzen (interner Blick, z.B. im eigenen LAN)")
    p.add_argument("--timeout", type=int, default=6, help="Timeout pro Host in Sekunden (Default 6)")
    p.add_argument("--workers", type=int, default=20, help="Parallele Checks (Default 20)")
    p.add_argument("--no-ports", action="store_true", help="Direkte Port-Checks überspringen")
    p.add_argument("--config", metavar="DATEI", help="Datei mit einer Domain pro Zeile (# = Kommentar)")
    p.add_argument("--diff", action="store_true", help="Mit letztem Scan vergleichen (Änderungen anzeigen)")
    p.add_argument("--watch", type=int, metavar="SEK", help="Dauer-Modus: alle SEK Sekunden scannen + Änderungen melden")
    p.add_argument("--discord", metavar="URL", help="Discord-Webhook-URL für Alerts bei Änderungen")
    p.add_argument("--webhook", metavar="URL", help="Generische Webhook-URL (JSON) für Alerts")
    p.add_argument("--alert-min", default="MEDIUM", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Mindest-Risiko für Alerts (Default MEDIUM)")
    p.add_argument("--state-dir", default=os.path.join(os.path.expanduser("~"), ".periscan"),
                   help="Speicherort der Scan-Snapshots (Default ~/.periscan)")
    p.add_argument("--json", metavar="DATEI", help="Ergebnis zusätzlich als JSON speichern")
    p.add_argument("--html", metavar="DATEI", help="Report als HTML speichern")
    p.add_argument("--svg", metavar="DATEI", help="Report als SVG speichern (Terminal-Look als Bild)")
    args = p.parse_args()

    try:  # Windows-Konsole auf UTF-8 (sonst crasht cp1252 bei → und Box-Zeichen)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if _RICH and (args.html or args.svg):
        global _console
        _console = Console(record=True)

    if _RICH:
        _console.print(Panel.fit("[bold]Periscan[/] v1.0 — prüft, was von deiner Domain öffentlich erreichbar ist.\n"
                                 "[yellow]Nur auf eigenen Domains anwenden.[/]", border_style="blue"))
    domains = list(args.domain)
    if args.config:
        try:
            with open(args.config, encoding="utf-8") as f:
                domains += [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
        except Exception as e:
            p.error(f"--config nicht lesbar: {e}")
    domains = list(dict.fromkeys(domains))  # dedupe, Reihenfolge erhalten
    if not domains:
        p.error("Keine Domain angegeben (als Argument oder via --config).")

    monitoring = args.diff or args.watch or args.discord or args.webhook

    def one_pass():
        collected = []
        for dom in domains:
            d = scan(dom, use_crt=not args.no_crt, timeout=args.timeout,
                     workers=args.workers, use_doh=not args.local_dns, do_ports=not args.no_ports)
            render(dom, d["results"], d["ports"])
            if monitoring:
                report_changes(dom, d, state_dir=args.state_dir,
                               discord=args.discord, webhook=args.webhook, alert_min=args.alert_min)
            collected.append({"domain": dom, **d})
        return collected

    if args.watch:
        _info(f"Watch-Modus: {len(domains)} Domain(s), alle {args.watch}s scannen (Strg+C zum Beenden).")
        while True:
            one_pass()
            time.sleep(args.watch)

    data = one_pass()
    out = data if len(data) > 1 else data[0]
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        _info(f"JSON gespeichert: {args.json}")
    if _RICH and args.svg:
        _console.save_svg(args.svg, title="Periscan", clear=False)
    if _RICH and args.html:
        _console.save_html(args.html, clear=False)
    if args.svg:
        print(f"SVG gespeichert: {args.svg}")
    if args.html:
        print(f"HTML gespeichert: {args.html}")


if __name__ == "__main__":
    main()
