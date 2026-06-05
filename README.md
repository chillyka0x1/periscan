# Periscan

**Der Homelab-Exposure-Checker, der deine Apps versteht.**

Pentester-Tools wie Nmap oder Nuclei sagen dir *Ports und CVEs* — aber nicht, ob du
aus Versehen dein **Proxmox**, deinen **code-server** oder dein **Nginx-Proxy-Manager-Admin**
ins offene Internet gestellt hast. Periscan prüft deine Domain von außen, erkennt die
typischen Self-Hosting-Apps und sagt dir in Klartext, **was gefährlich ist und was zu tun ist**.

> ⚠️ **Nur auf eigenen Domains anwenden.** Das Scannen fremder Hosts kann rechtswidrig sein.

## Was es tut

- Findet Subdomains über **Certificate-Transparency-Logs (crt.sh)** + eine Self-Hosting-Wortliste
- Löst über **öffentlichen DNS (DoH)** auf → echter **Außen-Blick** statt internem Split-Horizon
- Prüft pro Host: **öffentlich erreichbar?** HTTP-Status, **TLS gültig/abgelaufen?**
- **Erkennt ~60 Self-Hosting-Apps** (Proxmox, OPNsense, pfSense, Portainer, NPM, Pi-hole,
  code-server, n8n, Grafana, Gitea, Vaultwarden, Immich, Jellyfin, Nextcloud, TrueNAS, Synology …)
- **Aktive Unauth-Checks:** unterscheidet *„nur Login sichtbar"* (geschützt) von
  *„Daten/Setup wirklich offen"* (echte Lücke, z. B. offener Install-Wizard = Account-Takeover)
- **Risiko-Report** (CRITICAL → INFO) als **CLI** oder **Web-Dashboard** (Dark Mode)

## Installation

```bash
pip install .
```

Das installiert zwei Befehle:

```bash
periscan deine-domain.tld          # CLI-Scan im Terminal
periscan-web                       # Web-Oberfläche, öffnet den Browser (http://127.0.0.1:8000)
```

CLI-Optionen: `--no-crt`, `--local-dns`, `--timeout`, `--workers`, `--json/--html/--svg DATEI`.

### Monitoring (Änderungen erkennen + alarmieren)

```bash
periscan deine-domain.tld --diff                           # Änderungen seit letztem Scan
periscan deine-domain.tld --watch 3600 --discord <URL>     # alle 60 Min scannen, bei neuer Exposition Discord-Alert
```

Periscan merkt sich jeden Scan (Snapshot in `~/.periscan`) und meldet **neue / geänderte / verschwundene** Expositionen — ideal als Cronjob oder Dauerdienst. Alerts via `--discord <Webhook-URL>` oder `--webhook <URL>` (JSON-POST); Schwelle über `--alert-min`.

### Per Docker (läuft als lokaler Dienst)

```bash
docker build -t periscan .
docker run --rm -p 8000:8000 periscan      # dann http://localhost:8000 öffnen
```

> ⚠️ **Nur auf eigenen Domains anwenden.** Es läuft komplett **lokal auf deinem Rechner** — nichts wird an einen Server gesendet.

## Datenschutz & Vertrauen

Läuft **zu 100 % lokal**. Kein Account, keine Telemetrie, **keine Daten an die Autoren** oder einen Cloud-Dienst. Der Code ist offen — prüf es selbst.

Nach außen kontaktiert das Tool nur:
- **crt.sh** — Subdomains aus Certificate-Transparency-Logs (abschaltbar mit `--no-crt`)
- **öffentliche DoH-Resolver** (Cloudflare `1.1.1.1`, Google `dns.google`) — um „von außen" aufzulösen (abschaltbar mit `--local-dns`)
- **die Domain/IP, die du scannst**

Deine Ergebnisse werden **nirgendwohin** gesendet. Der User-Agent identifiziert das Tool ehrlich.

**Ethik & Recht:** Scanne **nur Hosts, die dir gehören** oder für die du eine ausdrückliche Erlaubnis hast. Aktive Port-/Endpunkt-Checks gegen fremde Systeme können rechtswidrig sein.

## Roadmap

- [x] CLI + DoH-Außen-Blick
- [x] ~60-App-Fingerprint-DB + aktive Unauth-Checks
- [x] Web-Dashboard (Dark/Light) + pip-/Docker-Installation
- [x] Direkte Port-Checks (auch ohne Reverse-Proxy)
- [x] **Monitoring:** wiederkehrende Scans + Diff über Zeit + Discord/Webhook-Alerts
- [x] IPv6/AAAA-Fallback · Multi-Domain-Scan · Auth-Labeling (geschützt/Login)
- [x] Tests + CI (GitHub Actions)
- [ ] CVE-Abgleich aus erkannten Versionen · Config-Datei für viele Domains
- [ ] Logo/Favicon, Light-Theme-Feinschliff
- [ ] Gehostete Version (Scan von außerhalb + Dauer-Monitoring) — der spätere bezahlte Teil

## Status

Entstanden aus einem echten Homelab (Proxmox/OPNsense/NPM/Pi-hole) — hat dort beim ersten
Lauf ein versehentlich offenes Proxmox + OPNsense gefunden. Feedback & Issues willkommen.
