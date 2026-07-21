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


def get_mock_scan_results(target: str) -> dict:
    """Returns mock/simulated scan results when nmap is not installed."""
    return {
        "target": target,
        "is_mock": True,
        "note": "nmap binary not found on this system. Operating in simulation mode with mock scan results.",
        "open_services": [
            {
                "port": "22",
                "protocol": "tcp",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "8.2p1 Ubuntu 4ubuntu0.5"
            },
            {
                "port": "80",
                "protocol": "tcp",
                "service": "http",
                "product": "Apache httpd",
                "version": "2.4.41"
            },
            {
                "port": "443",
                "protocol": "tcp",
                "service": "ssl/http",
                "product": "Apache httpd",
                "version": "2.4.41"
            }
        ]
    }


def run_nmap_scan(target: str, ports: str = "1-1000") -> dict:
    """
    Runs an nmap version-detection scan and returns parsed results.
    Requires the target to already be authorized -- checked here again
    as defense in depth even though callers should check first.
    """
    scope.assert_authorized(target)

    temp_dir = tempfile.gettempdir()
    xml_out = os.path.join(temp_dir, "knull_nmap_scan.xml")
    cmd = ["nmap", "-sV", "-p", ports, "-oX", xml_out, target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            return {"error": result.stderr or f"nmap exited with code {result.returncode}", "target": target}
    except FileNotFoundError:
        return get_mock_scan_results(target)
    except Exception as e:
        return {"error": f"Failed to execute nmap: {str(e)}", "target": target}

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
    Rate-limited by NVD (5 req / 30s without a key, 50 req / 30s with one) --
    callers should space out calls accordingly for multi-service scans.
    """
    if not product:
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
