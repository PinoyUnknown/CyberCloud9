[README.md](https://github.com/user-attachments/files/33581584/README.md)
# CyberCloud9# 🛡️ CyberCloud9 & Cyber Intelligence Suite. Developed by PinoyUnknown ~ TeamWhiteHatDev

[![Theme](https://img.shields.io/badge/Theme-CyberSecurityPro--Theme_v2.2.0_(12_Animated_Themes)-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black)](https://github.com/PinoyUnknown/CyberCloud9)
[![Security Posture](https://img.shields.io/badge/Posture-100%25_Defensive_%26_Non--Invasive-00F0FF?style=for-the-badge)](https://github.com/PinoyUnknown/CyberCloud9)
[![Developer](https://img.shields.io/badge/Developer-PinoyUnknown_~_TeamWhiteHatDev-FF9D42?style=for-the-badge)](https://github.com/unidentifiedcyberghost)
[![Python](https://img.shields.io/badge/Python-3.10%2B_%7C_PyQt6_HUD-00FF88?style=for-the-badge&logo=python)](https://github.com/PinoyUnknown/CyberCloud9)

> **Official Application Title**: `CyberCloud9 & Cyber Intelligence Suite. Developed by PinoyUnknown ~ TeamWhiteHatDev`  
> **Developers & Repository Links**:  
> **Team White Hat** - ["https://github.com/unidentifiedcyberghost"](https://github.com/unidentifiedcyberghost) ; ["https://github.com/PinoyUnknown/CyberCloud9"](https://github.com/PinoyUnknown/CyberCloud9)  
> **Origin Architecture**: Extracted & Upgraded from [`unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS`](https://github.com/unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS/)  
> **Theme Forge Collection**: [`https://addons.mozilla.org/en-US/firefox/addon/cybersecurity-theme-v1-0-1/`](https://addons.mozilla.org/en-US/firefox/addon/cybersecurity-theme-v1-0-1/)

---

## 📌 Purpose & Overview of the Suite

**CyberCloud9 & Cyber Intelligence Suite** is a real-time, dual-engine **Defensive Cybersecurity & OSINT Desktop GUI Platform** engineered in Python (`PyQt6`) featuring **12 selectable animated themes** (`CyberSecurityPro-Theme` + all 11 animated themes from `CyberSecurity Theme v1.0.1`), dual collapsible/detachable tool columns, and an automatically undocked, edge-resizable **Tactical Streaming Telemetry & Security Guard Log** window.

---

### 1. `[☁️] CYBERCLOUD9 // CLOUDFLARE ORIGIN SHIELD & DEFENSIVE POSTURE AUDITOR`

**Purpose**: Defensive origin verification, DNS proxy mesh audit, mail/SPF leak detector, origin ingress firewall tester, and edge security posture auditor.

- **DEFENSIVE AUDIT**: Validates DNS proxy status, checks subdomain leaks, tests firewall shield & checks mail SPF/DMARC hygiene.
- **SAFE VERIFICATION**: 100% Non-invasive administrative review. No bypass exploits or evasion scripts.
- **Core Capabilities**:
  1. **Apex DNS & Edge Proxy Shield Audit (`[⌖]`)**: Resolves `A`, `AAAA`, `CNAME`, and `CAA` records via Cloudflare & Google DNS-over-HTTPS (DoH) and verifies whether traffic resolves strictly to official Cloudflare Anycast CIDR blocks (`Orange Cloud ACTIVE`) or exposes direct origin IPs (`Gray Cloud Leak`).
  2. **Origin Direct Ingress Firewall Tester (`[⚓]`)**: Safely tests your known backend Origin Server IP on ports `443` and `80` to verify that a host firewall (`DROP`/`REJECT` policy) blocks direct non-Cloudflare internet probes.
  3. **Subdomain Proxy Mesh & Leak Detector (`[🕸️]`)**: Concurrently audits 24 common subdomains (`www`, `api`, `dev`, `staging`, `mail`, `cpanel`, `direct`, `origin`, `vpn`, etc.) to detect gray-cloud origin IP exposures.
  4. **Mail Infrastructure, SPF & DMARC Hygiene (`[✉]`)**: Inspects `MX`, `SPF (v=spf1)`, and `_dmarc` TXT records to ensure `ip4:`/`ip6:` directives or mail hosts do not accidentally publish the web origin server IP.
  5. **Edge Security & Response Header Auditor (`[🔒]`)**: Audits `CF-Ray`, `CF-Cache-Status`, `Strict-Transport-Security (HSTS)`, `Content-Security-Policy (CSP)`, `X-Frame-Options`, `X-Content-Type-Options`, and detects internal backend banner leaks (`X-Powered-By`, `Server`, `X-AspNet-Version`).
  6. **Sensitive Debug & Backup Path Auditor (`[📂]`)**: Checks for accidental public exposure of `/.env`, `/.git/config`, `/phpinfo.php`, `/wp-config.php.bak`, `/database.sql`, `/actuator/env`, and `/server-status`.
  7. **Automated Origin Firewall Lockdown Script Generator (`[🛡️]`)**: Generates ready-to-deploy firewall lockdown scripts restricting ports `80/443` exclusively to Cloudflare IPv4/IPv6 CIDRs (`UFW`, `iptables`, `nftables`, `Windows PowerShell`, `NGINX mTLS AOP`, and `Cloudflare Zero-Trust Tunnel`).
  8. **Official Cloudflare REST API v4 Read-Only Diagnostics (`[⚡]`)**: Connects using a site owner's Read-Only API Token and 32-character Zone ID to inspect live Zone status, Security Level, SSL/TLS Mode, Always Use HTTPS, Bot Fight Mode, and active WAF rule counts.

---

### 2. `[🌐] CYBER INTELLIGENCE SUITE // IP, NETWORK, GEOLOCATION & INFRASTRUCTURE OSINT`

**Purpose**: Modular multi-source cyber intelligence engine: authoritative IP intelligence, geolocation estimates, cellular carrier metadata, forward/reverse DNS, VPN & proxy detection, Cloudflare Anycast identification, HTTP/TLS forensics, and cross-entity evidence correlation.

- **Core 20-Module Intelligence Capabilities**:
  1. **`[01]` Global IP & Location Intelligence**: Public/Private IPv4 & IPv6 classification, Reverse DNS (`PTR`), RIR allocation registry (`ARIN`, `RIPE NCC`, `APNIC`, `LACNIC`, `AFRINIC`), and multi-provider estimated geolocation (`Country`, `Region`, `City`, `Approx Coordinates ±50km`, `Timezone`, `ISP`, `ASN`).
  2. **`[02]` VPN, Proxy, Tor & Datacenter Detection**: Probabilistic classification against commercial VPN ASNs, cloud hosting datacenters, and exit nodes with confidence scoring.
  3. **`[03]` Cloudflare & Reverse-Proxy Forensics**: Identifies Cloudflare Anycast Edge ingress, `CF-Ray` header telemetry, and backend origin concealment status.
  4. **`[04]` Authoritative Registration & WHOIS / RDAP Dossier**: Queries ICANN/RIR RDAP endpoints for Registrar, Registry Handle, Creation/Expiration/Updated timestamps, DNSSEC delegation status, Nameservers, and Domain Status flags.
  5. **`[05]` Multi-Record DNS Archive & Propagation Matrix**: Concurrent DoH harvester for `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `CAA`, `DNSKEY`, and `DS` records with interactive category filters (`ALL`, `ADDRESS`, `ROUTING`, `SECURITY`).
  6. **`[06]` Web Application & TLS X.509 Certificate Forensics**: Live HTTP status & latency measurement, TLS protocol version & cipher suite inspection, Issuing Certificate Authority (CA), certificate expiration days remaining, and Subject Alternative Names (`SAN`).
  7. **`[07]` Cellular, GSM, LTE & 5G Telecommunications Metadata**: Maps mobile carrier networks, `MCC`/`MNC` codes, and radio technologies (`5G-NR / LTE-A / UMTS / GSM`).
  8. **`[08]` Client Request Observations vs. Voluntary Device GPS**: Displays workstation network interface metadata alongside an explicit user-consent diagnostic dialog.
  9. **`[09]` Cross-Entity Evidence Correlation Engine**: Links `TARGET` -> `RESOLVED_IP` -> `REVERSE_PTR` -> `AUTONOMOUS_SYSTEM` -> `TELECOM_CARRIER` -> `DNSSEC_STATUS` -> `CLOUDFLARE_EDGE` -> `TLS_AUTHORITY` and signs the forensic JSON dossier with a **SHA-256 cryptographic hash**.

---

## 🎨 12 Collapsible & Animated Themes (`CyberSecurityPro-Theme-Collections/`)

Click **`[🎨 THEMES ▼]`** in the top command bar to expand the collapsible Theme Selector Drawer and switch between **12 live animated themes** at any time (with an **`[✨ ANIMATION: ON/OFF]`** toggle):

1. 🛡️ **CyberSecurityPro-Theme** (`htb` cyber-lab mesh)
2. ⚡ **Cyberpunk Neon** (`grid` neon grid & particles)
3. ⌨ **Blackhat Hacker** (`matrix` falling code rain)
4. ◈ **Sci-Fi HUD** (`orbit` planetary HUD rings)
5. ◇ **Glass HUD** (`bubbles` glassmorphism float)
6. ⬡ **Cyberpunk HUD** (`hex` Night City honeycomb)
7. ◉ **PinoyUnknown** (`stars` brand starfield)
8. ☢ **Dystopian** (`static` crimson interference)
9. ♡ **Pink Candy** (`hearts` pastel rose particles)
10. 🔐 **CyberSecurity Dark** (`grid` deep navy & neon green)
11. ▧ **Glitch** (`glitch` chromatic scan fragments)
12. ⬢ **HackTheBox** (`htb` green-on-black terminal crosshairs)

All 12 themes, their SVG wallpapers, JSON Design Tokens, Web CSS3, Python QSS, Android Jetpack Compose `.kt`, Android XML, and Flutter `.dart` bundles are backed up inside [`CyberSecurityPro-Theme-Collections/`](file:///C:/Project-PinoyUnknown/CyberCloud9/CyberCloud9/CyberSecurityPro-Theme-Collections/README.md).

---

## 🖥️ Automatically Undocked & Edge-Resizable Tactical Log Console

- **Automatically Undocked on Launch**: When the application starts, the **`Tactical Streaming Telemetry & Security Guard Log`** opens in its own separate, draggable, and edge-resizable window so you can place it anywhere on your screen.
- **Hover Top-Edge Resize & One-Click View Controls**:
  - Hover your cursor on the top edge (`⬍ HOVER TOP EDGE & DRAG UP/DOWN TO RESIZE LOG ⬍`) to drag-resize vertically.
  - Click **`[⤢ FULL VIEW LOG]`** to expand to full view or **`[⤡ DEFAULT SIZE]`** to restore the default size.
  - Click **`[⏎ DOCK LOG]`** / **`[🗗 UNDOCK LOG]`** to dock it into the Main Window's vertical `QSplitter` or pop it back out at any time.

---

## 📜 CHANGE LOGS (Version-by-Version & Time-by-Time)

| Version | Date & Time (UTC+8) | Author | Summary of Changes | Backup Location |
| :--- | :--- | :--- | :--- | :--- |
| **`v1.0.0`** | `2026-10-17 03:37:00` | **PinoyUnknown ~ TeamWhiteHatDev** | • Initial creation of `CyberCloud9` (`cyber_cloud9.py`) and `Cyber Intelligence Suite` (`cyber_intel.py`) modules inside `AEGIS-DEFENSIVE-TOOLKITS` and initial `PinoyUnknown/CyberCloud9` repository bootstrap (`README.md`, `LICENSE`, `.gitignore`). | `OldVersion/v1.0.0_Initial_Baseline/` |
| **`v2.0.0`** | `2026-10-17 04:20:00` | **PinoyUnknown ~ TeamWhiteHatDev** | • Built standalone Python `PyQt6` Desktop GUI with custom **`CyberSecurityPro-Theme`**, Dual Separate & Collapsible Columns (`QSplitter`), Detachable Standalone Windows, `SecurityGuard` `.gitignore` protection, and `OldVersion/` backup manager. | `OldVersion/v2.0.0_*` |
| **`v2.1.0`** | `2026-10-17 04:48:00` | **PinoyUnknown ~ TeamWhiteHatDev** | • Removed `[📦] BACKUP TO OldVersion` button from the GUI top bar.<br>• Added vertical `QSplitter` edge-resize handle, `[⤢ FULL VIEW LOG]`, and `[⤡ DEFAULT SIZE]` controls to the Tactical Streaming Telemetry & Security Guard Log.<br>• Added distinct Sci-Fi colors across all module categories and columns, and created `CyberSecurityPro-Theme-Collections/`. | `OldVersion/v2.1.0_*` |
| **`v2.2.0`** | `2026-10-17 05:55:00` | **PinoyUnknown ~ TeamWhiteHatDev** | • **Integrated all 11 Animated Themes from Firefox Add-on v1.0.1** (`Cyberpunk Neon`, `Blackhat Hacker`, `Sci-Fi HUD`, `Glass HUD`, `Cyberpunk HUD`, `PinoyUnknown`, `Dystopian`, `Pink Candy`, `CyberSecurity Dark`, `Glitch`, `HackTheBox`) into a **Collapsible `[🎨 THEMES ▼]` Selector Drawer** with live particle animations (`AnimatedThemeBackdrop`), and backed up all 12 themes + wallpapers into `CyberSecurityPro-Theme-Collections/`.<br>• **Automatically Undocked `"Tactical Streaming Telemetry & Security Guard Log"` on Launch** into a separate draggable & edge-resizable window (`StandaloneLogWindow`), while preserving vertical `QSplitter` docking (`[⏎ DOCK LOG]`), top-edge hover-and-drag resizing, `[⤢ FULL VIEW LOG]`, and `[⤡ DEFAULT SIZE]`.<br>• **Cleaned Title Bar, Presets, Text Color Labels, Git Push Button & Footer**: Removed `[CyberSecurityPro-Theme v2.1.0]` badge from the top bar (displaying strictly `CyberCloud9 & Cyber Intelligence Suite. Developed by PinoyUnknown ~ TeamWhiteHatDev`), removed quick target preset buttons, removed bracketed color name text indicators (`[CYAN]`, `[GOLD]`, etc.) from headers, removed the `[☁️] GIT PUSH` GUI button, and simplified the left footer label to `🛡️ Team White Hat` while keeping the browser link buttons. | `OldVersion/v2.2.0_*` |

---

## 👨‍💻 Developer & Attribution

- **Application**: `CyberCloud9 & Cyber Intelligence Suite. Developed by PinoyUnknown ~ TeamWhiteHatDev`
- **Team White Hat**: [https://github.com/unidentifiedcyberghost](https://github.com/unidentifiedcyberghost)
- **Official Repository**: [https://github.com/PinoyUnknown/CyberCloud9](https://github.com/PinoyUnknown/CyberCloud9)
