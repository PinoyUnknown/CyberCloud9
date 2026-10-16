"""
================================================================================
AEGIS DEFENSIVE TOOLKIT // CYBERCLOUD9 DEFENSIVE ORIGIN SHIELD
================================================================================
Component: CyberCloud9 - Cloudflare & CDN Origin Posture, DNS Shield & Hardening
Author: Team White Hat Dev (@unidentifiedcyberghost / @pinoyUnknown)
License: Authorized Defensive Security & Educational Infrastructure Hardening Only

PURPOSE & SAFETY COMPLIANCE:
This module is strictly DEFENSIVE and non-bypass oriented. It audits and validates:
1. Origin Shield & Firewall Verification (Ensuring origin blocks direct connections)
2. DNS Proxy Coverage & Subdomain Leak Audit (Identifying unproxied A records)
3. SPF/MX Mail Infrastructure Leak Detection
4. Cloudflare Edge Security Header & HSTS Audit
5. Information Disclosure & Debug Endpoint Verification
6. Origin Ingress Firewall Rule Generators (UFW, iptables, Windows, NGINX)
7. Official Cloudflare REST API Diagnostics (Read-Only Zone Health & WAF Settings)
================================================================================
"""

import socket
import ssl
import time
import ipaddress
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
import requests

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    try:
        from requests.packages import urllib3 as r_urllib3
        r_urllib3.disable_warnings()
    except Exception:
        pass

# Official Published Cloudflare IPv4 & IPv6 CIDR Blocks
CLOUDFLARE_IPV4_CIDRS = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22"
]

CLOUDFLARE_IPV6_CIDRS = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32"
]

COMMON_SUBDOMAINS = [
    "www", "api", "dev", "stage", "staging", "mail", "webmail", "smtp",
    "cpanel", "whm", "ftp", "direct", "origin", "admin", "portal",
    "vpn", "remote", "autodiscover", "test", "legacy"
]

EXPOSURE_DEBUG_PATHS = [
    ("/.env", "Environment Variables File", "HIGH"),
    ("/phpinfo.php", "PHP Configuration & Server Status", "HIGH"),
    ("/server-status", "Apache HTTP Server Diagnostics", "MEDIUM"),
    ("/.git/config", "Git Repository Metadata", "CRITICAL"),
    ("/.git/HEAD", "Git Repository Head", "CRITICAL"),
    ("/info.php", "Server Information Page", "HIGH"),
    ("/wp-config.php.bak", "WordPress Database Backup", "CRITICAL"),
    ("/database.sql", "Raw SQL Database Dump", "CRITICAL"),
    ("/.DS_Store", "macOS Finder Artifact File", "LOW")
]


def is_cloudflare_ip(ip_str: str) -> bool:
    """Checks whether an IPv4 or IPv6 address belongs to Cloudflare's official CIDR blocks."""
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        if addr.version == 4:
            for cidr in CLOUDFLARE_IPV4_CIDRS:
                if addr in ipaddress.ip_network(cidr):
                    return True
        elif addr.version == 6:
            for cidr in CLOUDFLARE_IPV6_CIDRS:
                if addr in ipaddress.ip_network(cidr):
                    return True
    except Exception:
        pass
    return False


def query_doh(name: str, record_type: str = "A") -> List[str]:
    """Resolves DNS records using Cloudflare DoH with fallback to Google DoH."""
    answers = []
    headers = {"Accept": "application/dns-json", "User-Agent": "Aegis-CyberCloud9/1.0"}
    
    # 1. Cloudflare DoH
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={record_type}"
        r = requests.get(url, headers=headers, timeout=4)
        if r.status_code == 200:
            data = r.json()
            for ans in data.get("Answer", []):
                val = ans.get("data", "").strip()
                if val:
                    answers.append(val)
            if answers:
                return answers
    except Exception:
        pass

    # 2. Google DoH Fallback
    try:
        url = f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={record_type}"
        r = requests.get(url, headers=headers, timeout=4)
        if r.status_code == 200:
            data = r.json()
            for ans in data.get("Answer", []):
                val = ans.get("data", "").strip()
                if val:
                    answers.append(val)
    except Exception:
        pass

    return answers


def audit_origin_dns_shield(domain: str) -> Dict[str, Any]:
    """
    Audits the apex domain's DNS resolution to verify if traffic is proxied through Cloudflare.
    """
    clean_domain = domain.strip().lower()
    if clean_domain.startswith("http://") or clean_domain.startswith("https://"):
        parsed = urllib.parse.urlparse(clean_domain)
        clean_domain = parsed.hostname or clean_domain

    a_records = query_doh(clean_domain, "A")
    aaaa_records = query_doh(clean_domain, "AAAA")
    cname_records = query_doh(clean_domain, "CNAME")

    proxied_ips = []
    unproxied_ips = []

    for ip in a_records:
        if is_cloudflare_ip(ip):
            proxied_ips.append(ip)
        else:
            unproxied_ips.append(ip)

    is_apex_proxied = len(proxied_ips) > 0 and len(unproxied_ips) == 0

    return {
        "domain": clean_domain,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "cname_records": cname_records,
        "proxied_cloudflare_ips": proxied_ips,
        "unproxied_ips": unproxied_ips,
        "is_apex_proxied": is_apex_proxied,
        "status": "SECURE_PROXIED" if is_apex_proxied else ("EXPOSED_UNPROXIED" if unproxied_ips else "NO_RECORDS"),
        "verdict": "Apex domain traffic is routed through Cloudflare edge proxy (Orange Cloud ACTIVE)." if is_apex_proxied
                   else "WARNING: Apex domain resolves directly to non-Cloudflare IP addresses! Origin server is directly accessible."
    }


def audit_subdomain_proxy_mesh(domain: str) -> List[Dict[str, Any]]:
    """
    Checks common subdomains to see if any are resolving directly to origin servers (gray cloud leaks).
    """
    clean_domain = domain.strip().lower()
    if clean_domain.startswith("http://") or clean_domain.startswith("https://"):
        clean_domain = urllib.parse.urlparse(clean_domain).hostname or clean_domain

    results = []

    def check_sub(sub: str):
        fqdn = f"{sub}.{clean_domain}"
        a_records = query_doh(fqdn, "A")
        if not a_records:
            return None
        
        is_cf = any(is_cloudflare_ip(ip) for ip in a_records)
        has_direct = any(not is_cloudflare_ip(ip) for ip in a_records)
        
        return {
            "subdomain": sub,
            "fqdn": fqdn,
            "ips": a_records,
            "is_cloudflare": is_cf,
            "is_origin_exposed": has_direct,
            "status": "PROXIED" if (is_cf and not has_direct) else ("EXPOSED_DIRECT" if has_direct else "UNKNOWN"),
            "risk_level": "HIGH" if has_direct else "LOW"
        }

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(check_sub, s): s for s in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    results.sort(key=lambda x: (x["risk_level"] != "HIGH", x["subdomain"]))
    return results


def audit_mail_spf_hygiene(domain: str) -> Dict[str, Any]:
    """
    Audits MX and SPF (TXT) records to detect whether the mail infrastructure accidentally
    publishes origin web server IP addresses in SPF directives (e.g. 'v=spf1 ip4:...').
    """
    clean_domain = domain.strip().lower()
    if clean_domain.startswith("http://") or clean_domain.startswith("https://"):
        clean_domain = urllib.parse.urlparse(clean_domain).hostname or clean_domain

    mx_records = query_doh(clean_domain, "MX")
    txt_records = query_doh(clean_domain, "TXT")

    spf_record = None
    spf_ips = []
    
    for txt in txt_records:
        if "v=spf1" in txt.lower():
            spf_record = txt
            # Extract explicit IPv4 addresses in SPF
            import re
            found_ips = re.findall(r'ip4:([0-9\.\/]+)', txt)
            spf_ips.extend(found_ips)

    mx_details = []
    for mx in mx_records:
        # MX record format in DoH: "10 mail.example.com."
        parts = mx.split()
        mx_host = parts[-1].rstrip(".") if parts else mx
        resolved_ips = query_doh(mx_host, "A")
        is_cf = any(is_cloudflare_ip(ip) for ip in resolved_ips)
        mx_details.append({
            "record": mx,
            "host": mx_host,
            "resolved_ips": resolved_ips,
            "is_cloudflare": is_cf,
            "risk": "Mail servers cannot proxy SMTP through standard HTTP Cloudflare proxies without Cloudflare Spectrum; direct MX is normal but must not share the web origin IP."
        })

    return {
        "domain": clean_domain,
        "mx_records": mx_details,
        "spf_record": spf_record,
        "spf_declared_ips": spf_ips,
        "recommendation": "Ensure your web server and mail server are on separate hosting instances. Never use the web origin IP in your SPF record."
    }


def verify_origin_direct_ingress_shield(origin_ip: str, port: int = 443) -> Dict[str, Any]:
    """
    Tests if the specified origin IP address is properly firewalled against direct internet connections.
    SAFE TEST: Attempts a simple TCP handshake with a short 2.5-second timeout.
    If the connection drops or times out, the firewall is correctly shielding the origin.
    """
    clean_ip = origin_ip.strip()
    result = {
        "origin_ip": clean_ip,
        "port": port,
        "is_shielded": False,
        "status": "UNKNOWN",
        "latency_ms": None,
        "message": ""
    }

    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.5)
        conn = s.connect_ex((clean_ip, port))
        latency = round((time.time() - t0) * 1000, 2)
        result["latency_ms"] = latency
        s.close()

        if conn == 0:
            # Port is open and accepting traffic from anyone!
            result["is_shielded"] = False
            result["status"] = "EXPOSED"
            result["message"] = f"CRITICAL: Port {port} on origin IP {clean_ip} is OPEN to the public internet! Non-Cloudflare traffic can connect directly, bypassing your WAF and DDoS protection."
        else:
            result["is_shielded"] = True
            result["status"] = "SHIELDED"
            result["message"] = f"PASS: Connection refused on port {port}. Origin is rejecting direct internet probes."
    except socket.timeout:
        result["is_shielded"] = True
        result["status"] = "SHIELDED"
        result["message"] = f"PASS: Connection timed out on port {port} (DROP policy active). Origin is properly hidden behind firewall."
    except Exception as e:
        result["is_shielded"] = True
        result["status"] = "SHIELDED"
        result["message"] = f"PASS: Handshake failed ({type(e).__name__}). Origin port is not reachable directly."

    return result


def audit_edge_security_headers(target_url: str) -> Dict[str, Any]:
    """
    Checks HTTP response headers to verify Cloudflare Edge features and ensure
    internal backend headers (PHP, Apache, NGINX versions) are not leaking.
    """
    url = target_url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    headers_out = {
        "url": url,
        "status_code": None,
        "server_header": None,
        "cf_ray": None,
        "cf_cache_status": None,
        "hsts_active": False,
        "hsts_header": None,
        "csp_active": False,
        "origin_leaks": [],
        "is_cloudflare_active": False
    }

    try:
        r = requests.get(url, headers={"User-Agent": "Aegis-CyberCloud9-Auditor/1.0"}, timeout=6, allow_redirects=True, verify=False)
        headers_out["status_code"] = r.status_code
        h = r.headers

        headers_out["server_header"] = h.get("Server")
        headers_out["cf_ray"] = h.get("cf-ray")
        headers_out["cf_cache_status"] = h.get("cf-cache-status")
        headers_out["hsts_header"] = h.get("Strict-Transport-Security")
        headers_out["hsts_active"] = "Strict-Transport-Security" in h
        headers_out["csp_active"] = "Content-Security-Policy" in h

        if headers_out["cf_ray"] or (headers_out["server_header"] and "cloudflare" in headers_out["server_header"].lower()):
            headers_out["is_cloudflare_active"] = True

        # Check for leaking internal backend headers
        leak_keys = ["X-Powered-By", "X-AspNet-Version", "X-Runtime", "Server"]
        for k in leak_keys:
            val = h.get(k)
            if val and "cloudflare" not in val.lower():
                headers_out["origin_leaks"].append({"header": k, "value": val, "risk": "Leaks internal server/runtime technology banner."})

    except Exception as e:
        headers_out["error"] = str(e)

    return headers_out


def audit_origin_debug_endpoints(target_url: str) -> List[Dict[str, Any]]:
    """
    Defensive scan to ensure the web server does not host common debug, configuration,
    or backup endpoints that leak origin details or internal server status.
    """
    base_url = target_url.strip().rstrip("/")
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "https://" + base_url

    results = []

    def check_endpoint(path: str, description: str, severity: str):
        full_url = base_url + path
        try:
            r = requests.get(full_url, headers={"User-Agent": "Aegis-CyberCloud9-Auditor/1.0"}, timeout=4, verify=False, allow_redirects=False)
            is_exposed = r.status_code in [200, 206]
            return {
                "path": path,
                "url": full_url,
                "status_code": r.status_code,
                "description": description,
                "severity": severity,
                "is_exposed": is_exposed,
                "status": "EXPOSED (ALERT)" if is_exposed else "PROTECTED"
            }
        except Exception:
            return {
                "path": path,
                "url": full_url,
                "status_code": None,
                "description": description,
                "severity": severity,
                "is_exposed": False,
                "status": "UNREACHABLE"
            }

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(check_endpoint, path, desc, sev) for path, desc, sev in EXPOSURE_DEBUG_PATHS]
        for f in as_completed(futures):
            results.append(f.result())

    results.sort(key=lambda x: (not x["is_exposed"], x["path"]))
    return results


def generate_origin_firewall_rules(platform: str = "ufw") -> str:
    """
    Generates automated defensive firewall lock-down scripts to enforce that the origin
    server ONLY accepts HTTP/HTTPS traffic from Cloudflare's published IP ranges.
    """
    plat = platform.lower().strip()

    if plat == "ufw":
        lines = [
            "#!/usr/bin/env bash",
            "# ==================================================================",
            "# AEGIS // CYBERCLOUD9 DEFENSIVE ORIGIN FIREWALL (UFW LOCKDOWN)",
            "# Restrict ports 80 and 443 strictly to Cloudflare edge IP ranges",
            "# ==================================================================",
            "set -e",
            "echo '[*] Configuring UFW to only allow Cloudflare Edge IPs...'",
            ""
        ]
        for cidr in CLOUDFLARE_IPV4_CIDRS:
            lines.append(f"sudo ufw allow proto tcp from {cidr} to any port 80,443 comment 'Cloudflare Edge'")
        for cidr in CLOUDFLARE_IPV6_CIDRS:
            lines.append(f"sudo ufw allow proto tcp from {cidr} to any port 80,443 comment 'Cloudflare IPv6 Edge'")
        lines.extend([
            "",
            "# IMPORTANT: Allow your management SSH port before enabling!",
            "sudo ufw allow 22/tcp comment 'SSH Administration'",
            "sudo ufw default deny incoming",
            "sudo ufw default allow outgoing",
            "sudo ufw enable",
            "echo '[+] Origin server firewall successfully locked down to Cloudflare edge only!'"
        ])
        return "\n".join(lines)

    elif plat == "iptables":
        lines = [
            "#!/usr/bin/env bash",
            "# ==================================================================",
            "# AEGIS // CYBERCLOUD9 DEFENSIVE IPTABLES ORIGIN SHIELD",
            "# ==================================================================",
            "# 1. Create a dedicated Cloudflare chain",
            "iptables -N CLOUDFLARE",
            ""
        ]
        for cidr in CLOUDFLARE_IPV4_CIDRS:
            lines.append(f"iptables -A CLOUDFLARE -s {cidr} -j ACCEPT")
        lines.extend([
            "",
            "# 2. Direct web traffic to CLOUDFLARE chain and drop unauthorized probes",
            "iptables -A INPUT -p tcp -m multiport --dports 80,443 -j CLOUDFLARE",
            "iptables -A INPUT -p tcp -m multiport --dports 80,443 -j DROP",
            "echo '[+] iptables rules applied. Non-Cloudflare direct web probes dropped!'"
        ])
        return "\n".join(lines)

    elif plat in ["windows", "powershell"]:
        lines = [
            "# ==================================================================",
            "# AEGIS // CYBERCLOUD9 WINDOWS DEFENDER FIREWALL RULES",
            "# Execute in elevated PowerShell Administrator console",
            "# ==================================================================",
            "$cf_ipv4 = @("
        ]
        for cidr in CLOUDFLARE_IPV4_CIDRS:
            lines.append(f'    "{cidr}",')
        lines.extend([
            ")",
            "",
            "# Remove any legacy public web rules",
            "Remove-NetFirewallRule -DisplayName 'Allow-Cloudflare-Web-Inbound' -ErrorAction SilentlyContinue",
            "",
            "# Create restricted inbound rule for ports 80, 443",
            "New-NetFirewallRule -DisplayName 'Allow-Cloudflare-Web-Inbound' `",
            "    -Direction Inbound `",
            "    -Action Allow `",
            "    -Protocol TCP `",
            "    -LocalPort 80,443 `",
            "    -RemoteAddress $cf_ipv4 `",
            "    -Description 'Only allow inbound traffic from official Cloudflare proxy network'",
            "",
            "Write-Host '[+] Windows Defender Firewall locked down to Cloudflare IPs only!' -ForegroundColor Green"
        ])
        return "\n".join(lines)

    elif plat == "nginx":
        lines = [
            "# ==================================================================",
            "# AEGIS // CYBERCLOUD9 NGINX AUTHENTICATED REAL-IP & ACCESS RULES",
            "# Add to your nginx.conf http {} or server {} block",
            "# ==================================================================",
            "# 1. Restore real visitor IP from Cloudflare header"
        ]
        for cidr in CLOUDFLARE_IPV4_CIDRS:
            lines.append(f"set_real_ip_from {cidr};")
        for cidr in CLOUDFLARE_IPV6_CIDRS:
            lines.append(f"set_real_ip_from {cidr};")
        lines.extend([
            "real_ip_header CF-Connecting-IP;",
            "",
            "# 2. Restrict direct access if not firewalled at OS layer",
            "# (Uncomment below to reject any connection not matching set_real_ip_from)",
            "# allow 173.245.48.0/20;",
            "# ...",
            "# deny all;",
            "",
            "# 3. Authenticated Origin Pulls (AOP) Configuration",
            "# Download the official Cloudflare Origin CA certificate to /etc/ssl/certs/cloudflare-aop.crt",
            "ssl_client_certificate /etc/ssl/certs/cloudflare-aop.crt;",
            "ssl_verify_client on;"
        ])
        return "\n".join(lines)

    elif plat in ["tunnel", "cloudflared"]:
        return """# ==================================================================
# AEGIS // CYBERCLOUD9 ZERO-TRUST CLOUDFLARE TUNNEL (RECOMMENDED)
# ==================================================================
# Cloudflare Tunnel (cloudflared) eliminates public origin IP exposure completely.
# Outbound connections are established from your server to Cloudflare edge.
# ALL INBOUND PORTS (80, 443) CAN BE CLOSED ON THE SERVER!

# Step 1: Install cloudflared daemon
# Linux (Debian/Ubuntu):
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared bullseye main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install cloudflared -y

# Step 2: Authenticate with your Cloudflare Account
cloudflared tunnel login

# Step 3: Create your named origin tunnel
cloudflared tunnel create aegis-origin-tunnel

# Step 4: Configure ingress rules (~/.cloudflared/config.yml)
# tunnel: <YOUR-TUNNEL-UUID>
# credentials-file: /root/.cloudflared/<YOUR-TUNNEL-UUID>.json
# ingress:
#   - hostname: yourdomain.com
#     service: http://localhost:80
#   - service: http_status:404

# Step 5: Route DNS to the tunnel
cloudflared tunnel route dns aegis-origin-tunnel yourdomain.com

# Step 6: Run as a permanent system service
sudo cloudflared service install
sudo systemctl start cloudflared
sudo systemctl enable cloudflared

# Step 7: Close ports 80/443 on your hosting firewall completely!
"""

    return "Unknown platform format. Supported: 'ufw', 'iptables', 'windows', 'nginx', 'tunnel'."


def query_cloudflare_official_api(api_token: str, zone_id: str) -> Dict[str, Any]:
    """
    Safely queries official Cloudflare REST API v4 using the site owner's read-only API token.
    Displays live security settings: WAF status, security level, SSL mode, and bot fight mode.
    """
    if not api_token or not zone_id:
        return {"error": "Missing Cloudflare API Token or Zone ID."}

    headers = {
        "Authorization": f"Bearer {api_token.strip()}",
        "Content-Type": "application/json"
    }
    base = f"https://api.cloudflare.com/client/v4/zones/{zone_id.strip()}"

    res = {
        "zone_id": zone_id,
        "is_authenticated": False,
        "zone_name": None,
        "security_level": None,
        "ssl_mode": None,
        "waf_status": None,
        "bot_fight_mode": None,
        "always_use_https": None,
        "firewall_rules_count": 0
    }

    try:
        # 1. Zone details
        r_zone = requests.get(base, headers=headers, timeout=6)
        if r_zone.status_code == 200:
            res["is_authenticated"] = True
            zdata = r_zone.json().get("result", {})
            res["zone_name"] = zdata.get("name")
            res["status"] = zdata.get("status")
        else:
            return {"error": f"API authentication failed (HTTP {r_zone.status_code}): {r_zone.text}"}

        # 2. Security Level
        r_sec = requests.get(f"{base}/settings/security_level", headers=headers, timeout=6)
        if r_sec.status_code == 200:
            res["security_level"] = r_sec.json().get("result", {}).get("value")

        # 3. SSL mode
        r_ssl = requests.get(f"{base}/settings/ssl", headers=headers, timeout=6)
        if r_ssl.status_code == 200:
            res["ssl_mode"] = r_ssl.json().get("result", {}).get("value")

        # 4. HTTPS redirect
        r_https = requests.get(f"{base}/settings/always_use_https", headers=headers, timeout=6)
        if r_https.status_code == 200:
            res["always_use_https"] = r_https.json().get("result", {}).get("value")

        # 5. Bot Fight Mode
        r_bot = requests.get(f"{base}/settings/bot_fight_mode", headers=headers, timeout=6)
        if r_bot.status_code == 200:
            res["bot_fight_mode"] = r_bot.json().get("result", {}).get("value")

        # 6. Firewall Rules Count
        r_fw = requests.get(f"{base}/firewall/rules", headers=headers, timeout=6)
        if r_fw.status_code == 200:
            res["firewall_rules_count"] = len(r_fw.json().get("result", []))

    except Exception as e:
        res["error"] = str(e)

    return res


def run_full_cybercloud9_audit(target_domain: str, known_origin_ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes a comprehensive, non-invasive CyberCloud9 defensive audit across:
    1. Apex DNS & Edge Proxy Verification
    2. Subdomain Proxy Mesh & Exposure Detection
    3. Mail/SPF IP Leakage Hygiene
    4. Edge Security & Backend Header Leak Audit
    5. Exposure & Debug Endpoint Check
    6. Direct Origin Ingress Shield Check (if known origin IP provided by owner)
    """
    raw_target = (target_domain or "127.0.0.1").strip()
    is_http = raw_target.lower().startswith("http://")
    parsed = urllib.parse.urlparse(raw_target if "://" in raw_target else f"https://{raw_target}")
    clean_domain = (parsed.hostname or raw_target).lower().strip()
    port = parsed.port

    # Reconstruct correct protocol and port for HTTP/HTTPS probes
    scheme = "http" if is_http else (parsed.scheme or "https")
    port_suffix = f":{port}" if port and port not in (80, 443) else ""
    target_url = f"{scheme}://{clean_domain}{port_suffix}"

    is_local = clean_domain in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or clean_domain.startswith("192.168.") or clean_domain.startswith("10.")

    # Run checks concurrently
    with ThreadPoolExecutor(max_workers=5) as executor:
        f_dns = executor.submit(audit_origin_dns_shield, clean_domain)
        # Skip subdomain bruteforcing for localhost
        f_subs = executor.submit(lambda: [] if is_local else audit_subdomain_proxy_mesh(clean_domain))
        f_mail = executor.submit(audit_mail_spf_hygiene, clean_domain)
        f_headers = executor.submit(audit_edge_security_headers, target_url)
        f_endpoints = executor.submit(audit_origin_debug_endpoints, target_url)

        dns_res = f_dns.result()
        subs_res = f_subs.result()
        mail_res = f_mail.result()
        headers_res = f_headers.result()
        endpoints_res = f_endpoints.result()

    origin_shield_res = None
    if known_origin_ip and known_origin_ip.strip():
        origin_shield_res = verify_origin_direct_ingress_shield(known_origin_ip.strip())

    # Calculate overall Defensive Cloudflare Posture Score (0 - 100)
    score = 100
    deductions = []

    if not dns_res.get("is_apex_proxied"):
        score -= 40
        deductions.append("Apex domain A records do not resolve through Cloudflare proxy (-40)")

    exposed_subs = [s for s in subs_res if s.get("is_origin_exposed")]
    if exposed_subs:
        penalty = min(25, len(exposed_subs) * 10)
        score -= penalty
        deductions.append(f"{len(exposed_subs)} subdomain(s) resolve directly to non-Cloudflare IPs (-{penalty})")

    if not headers_res.get("hsts_active"):
        score -= 10
        deductions.append("HSTS header missing at Cloudflare Edge (-10)")

    if headers_res.get("origin_leaks"):
        score -= 10
        deductions.append("Internal backend server/runtime headers leaked in responses (-10)")

    exposed_eps = [e for e in endpoints_res if e.get("is_exposed")]
    if exposed_eps:
        score -= 20
        deductions.append(f"{len(exposed_eps)} dangerous debug/config endpoints publicly exposed (-20)")

    if origin_shield_res and not origin_shield_res.get("is_shielded"):
        score -= 30
        deductions.append("Origin IP accepts direct connections without firewall drop policy (-30)")

    final_score = max(0, min(100, score))

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "target_domain": clean_domain,
        "known_origin_ip": known_origin_ip,
        "posture_score": final_score,
        "deductions": deductions,
        "dns_shield": dns_res,
        "subdomains": subs_res,
        "mail_hygiene": mail_res,
        "edge_headers": headers_res,
        "debug_endpoints": endpoints_res,
        "origin_ingress_shield": origin_shield_res,
        "status": "HARDENED" if final_score >= 80 else ("ELEVATED_RISK" if final_score < 50 else "MODERATE_SHIELD")
    }
