"""
Knull - core/scanner.py

Recon layer: runs nmap against an authorized target, parses open
ports/services/versions, and correlates each service against the NVD
(National Vulnerability Database) API. Output is a structured JSON "asset
profile" -- this is the ONLY thing the AI advisor layer ever sees. It never
gets raw network access or the ability to construct its own scan.
"""

import subprocess
import xml.etree.ElementTree as ET
import time
import requests
import os
import tempfile

import config
from core import scope


import socket
import ssl
from concurrent.futures import ThreadPoolExecutor


COMMON_PORTS = {
    21: ("ftp", "FTP"),
    22: ("ssh", "SSH"),
    25: ("smtp", "SMTP"),
    53: ("domain", "DNS"),
    80: ("http", "HTTP Web Server"),
    110: ("pop3", "POP3"),
    143: ("imap", "IMAP"),
    443: ("https", "HTTPS Secure Web"),
    3306: ("mysql", "MySQL Database"),
    5432: ("postgresql", "PostgreSQL Database"),
    8080: ("http-alt", "HTTP Web Server"),
    8443: ("https-alt", "HTTPS Secure Web"),
}


def _check_port(target_host: str, port: int) -> dict:
    """Connect to a target port, grab banner if possible, and extract HTTP headers if web port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        res = sock.connect_ex((target_host, port))
        if res == 0:
            svc_name, svc_desc = COMMON_PORTS.get(port, ("unknown", "Unknown Service"))
            product = ""
            version = ""
            
            # Grabbing banner / HTTP headers for web ports
            if port in (80, 443, 8080, 8443):
                try:
                    proto = "https" if port in (443, 8443) else "http"
                    url = f"{proto}://{target_host}:{port}/"
                    resp = requests.get(url, timeout=2.5, verify=False, headers={"User-Agent": "Knull/1.0 Security Inspector"})
                    server_hdr = resp.headers.get("Server", "")
                    if server_hdr:
                        product = server_hdr.split("/")[0] if "/" in server_hdr else server_hdr
                        version = server_hdr.split("/")[1] if "/" in server_hdr else ""
                    else:
                        product = "Web Server"
                except Exception:
                    pass
            else:
                # Socket banner grab
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
                    if banner:
                        product = banner[:30]
                except Exception:
                    pass
            
            sock.close()
            return {
                "port": str(port),
                "protocol": "tcp",
                "service": svc_name,
                "product": product or svc_desc,
                "version": version or "",
            }
        sock.close()
    except Exception:
        pass
    return None


def run_native_python_scan(target: str, ports: str = "1-1000") -> dict:
    """Performs a real native Python concurrent socket port scan & banner grab."""
    # Clean target
    clean_host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    
    # Parse port list or use common ports
    target_ports = list(COMMON_PORTS.keys())
    if ports and "," in ports:
        try:
            target_ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        except ValueError:
            pass
            
    open_services = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_check_port, clean_host, p) for p in target_ports]
        for f in futures:
            res = f.result()
            if res:
                open_services.append(res)
                
    return {
        "target": target,
        "scan_engine": "Native Python Network Inspector",
        "open_services": open_services
    }


def run_nmap_scan(target: str, ports: str = "1-1000") -> dict:
    """
    Runs an nmap version-detection scan and returns parsed results.
    Falls back to native Python socket scan if nmap binary is missing.
    """
    scope.assert_authorized(target)

    temp_dir = tempfile.gettempdir()
    xml_out = os.path.join(temp_dir, "knull_nmap_scan.xml")
    cmd = ["nmap", "-sV", "-p", ports, "-oX", xml_out, target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            return run_native_python_scan(target, ports)
    except FileNotFoundError:
        return run_native_python_scan(target, ports)
    except Exception:
        return run_native_python_scan(target, ports)

    return _parse_nmap_xml(xml_out, target)


def _parse_nmap_xml(xml_path: str, target: str) -> dict:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        return {"error": f"Failed to parse nmap output XML: {str(e)}", "target": target}

    services = []
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            services.append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": service.get("name") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            })

    return {"target": target, "open_services": services}


def correlate_nvd(product: str, version: str) -> list:
    """
    Queries the NVD API for CVEs matching a product/version string.
    Returns a trimmed list of {cve_id, description, cvss_score}.
    """
    # Exclude generic service names or missing versions to prevent hallucinated/broad CVE matches
    generic_names = ("dns", "domain", "http", "https", "web server", "ftp", "smtp", "unknown", "")
    if not product or product.lower().strip() in generic_names or not version:
        return []

    query = f"{product} {version}".strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": 10}
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [{"error": str(e)}]

    findings = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "unknown")
        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss_score = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                cvss_score = metrics[metric_key][0]["cvssData"].get("baseScore")
                break
        findings.append({"cve_id": cve_id, "description": desc_text[:300], "cvss_score": cvss_score})

    # be polite to the NVD rate limit on multi-service scans
    time.sleep(1.5 if not config.NVD_API_KEY else 0.3)
    return findings


def build_asset_profile(target: str, ports: str = "1-1000") -> dict:
    """
    Full recon pass: nmap scan + NVD correlation per detected service.
    This structured object is what gets handed to the AI advisor.
    """
    scan = run_nmap_scan(target, ports)
    if "error" in scan:
        return scan

    for svc in scan["open_services"]:
        svc["known_cves"] = correlate_nvd(svc.get("product", ""), svc.get("version", ""))

    return scan
