import os
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Load API keys from .env file
load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")

# Get absolute path to /data/ folder
script_dir = os.path.dirname(os.path.abspath(__file__))
data_folder = os.path.join(script_dir, "..", "data")

def save_json(data, name_prefix):
    # Ensure the data folder exists
    os.makedirs(data_folder, exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')
    filename = os.path.join(data_folder, f"{name_prefix}_{timestamp}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved {name_prefix} data to {filename}")

# -------------------- OTX --------------------
def fetch_otx():
    print("[*] Fetching data from AlienVault OTX...")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print(f"[!] OTX error: {r.status_code}")
        return []
    data = r.json()["results"]
    save_json(data, "otx")
    print(f"[+] OTX: {len(data)} pulses")
    return data

# -------------------- AbuseIPDB --------------------
def fetch_abuseipdb():
    print("[*] Fetching data from AbuseIPDB...")
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"confidenceMinimum": "90"}
    r = requests.get(url, headers=headers, params=params)
    if r.status_code != 200:
        print(f"[!] AbuseIPDB error: {r.status_code}")
        return []
    data = r.json()["data"]
    save_json(data, "abuseipdb")
    print(f"[+] AbuseIPDB: {len(data)} blacklisted IPs")
    return data

# -------------------- ThreatFox --------------------
def fetch_threatfox():
    print("[*] Fetching data from ThreatFox...")
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "Content-Type": "application/json",
        "Auth-Key": THREATFOX_API_KEY
    }
    payload = {
        "query": "get_iocs",
        "limit": 100
    }
    r = requests.post(url, headers=headers, json=payload)
    if r.status_code != 200:
        print(f"[!] ThreatFox error: {r.status_code}")
        print(r.text)
        return []
    data = r.json().get("data", [])
    save_json(data, "threatfox")
    print(f"[+] ThreatFox: {len(data)} indicators")
    return data

# -------------------- Main Execution --------------------
if __name__ == "__main__":
    print("[*] Starting Combined Feed Fetch...\n")
    otx_data = fetch_otx()
    abuse_data = fetch_abuseipdb()
    threatfox_data = fetch_threatfox()
    print("\n[*] All feeds pulled and saved successfully.")
