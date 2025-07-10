import os
import json
from pathlib import Path
from collections import Counter
from datetime import datetime
from dotenv import load_dotenv
import requests

# Setup
base = Path(__file__).resolve().parents[2]
data_dir = base / "data"
report_dir = base / "reports"
report_dir.mkdir(exist_ok=True)
data_dir.mkdir(exist_ok=True)
load_dotenv(base / ".env")

# --- FEED 1: AlienVault OTX ---
def fetch_otx():
    otx_api_key = os.getenv("OTX_API_KEY")
    if not otx_api_key:
        print("[!] OTX API key missing.")
        return []

    headers = {"X-OTX-API-KEY": otx_api_key}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json().get("results", [])
        filename = data_dir / f"otx_{datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data
    else:
        print("[!] OTX error:", response.status_code)
        return []

# --- FEED 2: ThreatFox ---
def fetch_threatfox():
    print("[*] Fetching data from ThreatFox...")

    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "Content-Type": "application/json",
        "Auth-Key": os.getenv("THREATFOX_API_KEY")
    }

    payload = {
        "query": "get_iocs",  # Working API Query according to https://threatfox.abuse.ch/api/#recent-iocs
        "days": 1
        # days replaced: "limit": 100
    }

    response = requests.post(url, headers=headers, json=payload)

    print(f"[DEBUG] Response status: {response.status_code}")
    print("[DEBUG] Full response body:")
    print(response.text[:500])

    if response.status_code != 200:
        print(f"[!] ThreatFox error: {response.status_code}")
        return []

    result = response.json()
    if not isinstance(result.get("data"), list):
        print("[!] Unexpected format: 'data' is not a list")
        return []

    # Save to JSON
    filename = data_dir / f"threatfox_{datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(result.get("data"), f, indent=2)

    print(f"[+] ThreatFox: {len(result.get('data'))} indicators")
    return result.get("data")

# --- FEED 3: AbuseIPDB ---
def fetch_abuseipdb():
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if not abuse_key:
        print("[!] AbuseIPDB API key missing.")
        return []

    url = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90"
    headers = {"Key": abuse_key, "Accept": "application/json"}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json().get("data", [])
        filename = data_dir / f"abuseipdb_{datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data
    else:
        print("[!] AbuseIPDB error:", response.status_code)
        return []

# --- PARSE + REPORT GENERATION ---
def parse_otx(data):
    return [{
        "source": "OTX",
        "malware_family": pulse.get("malware_family", "Unknown"),
        "tags": pulse.get("tags", []),
        "references": pulse.get("references", [])
    } for pulse in data]

def parse_threatfox(data):
    parsed = []
    for entry in data:
        if not isinstance(entry, dict):
            continue  # skip strings or malformed entries

        parsed.append({
            "source": "ThreatFox",
            "ioc": entry.get("ioc"),
            "threat_type": entry.get("threat_type"),
            "malware": entry.get("malware", "Unknown"),
            "confidence_level": entry.get("confidence_level", 0),
            "tags": entry.get("tags", [])
        })
    return parsed


# --- MAIN EXECUTION ---
print("[*] Fetching feeds...")
otx_data = fetch_otx()
tf_data = fetch_threatfox()
abuse_data = fetch_abuseipdb()

print("[*] Generating report...")
otx_parsed = parse_otx(otx_data)
tf_parsed = parse_threatfox(tf_data)

malware_counter = Counter()
tags_counter = Counter()
for item in otx_parsed + tf_parsed:
    malware = item.get("malware_family", item.get("malware", "Unknown"))
    malware_counter[malware] += 1
    tags_counter.update(item.get("tags", []))

# Write markdown report
timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
report_lines = [
    "# Daily Threat Intelligence Report",
    f"**Generated:** {timestamp}",
    "## 🔍 Summary",
    f"- Total OTX Pulses: {len(otx_data)}",
    f"- Total ThreatFox IOCs: {len(tf_data)}",
    f"- Total AbuseIPDB Records: {len(abuse_data)}",
    "\n## 🧬 Top Malware Families",
    *[f"- {m}: {c}" for m, c in malware_counter.most_common(10)],
    "\n## 🏷️ Top Tags",
    *[f"- {tag}: {count}" for tag, count in tags_counter.most_common(10)],
    "\n## 📌 Sample ThreatFox IOCs",
    *[f"- {entry['ioc']} ({entry.get('threat_type')})" for entry in tf_parsed[:10]],
    "\n## 📌 Sample OTX References",
    *[f"- {ref}" for pulse in otx_parsed[:5] for ref in pulse.get("references", [])[:2]],
    "\n---\n_Report auto-generated by CTI Tools V2._"
]

report_path = report_dir / f"threat_report_{datetime.utcnow().strftime('%Y-%m-%d')}_combo.md"
with open(report_path, "w", encoding="utf-8") as f:
    f.write("\n".join(report_lines))

print(f"[+] Report saved to: {report_path}")