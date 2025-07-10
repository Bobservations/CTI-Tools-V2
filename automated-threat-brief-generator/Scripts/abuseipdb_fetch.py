import os
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def fetch_abuseipdb_data():
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    params = {
        "confidenceMinimum": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        raise Exception(f"Error: {response.status_code}")
    return response.json()

def save_to_file(data):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')
    filename = f"../data/abuseipdb_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        import json
        json.dump(data, f, indent=2)
    print(f"[+] Saved AbuseIPDB data to {filename}")

if __name__ == "__main__":
    print("[*] Fetching high-confidence IPs from AbuseIPDB...")
    data = fetch_abuseipdb_data()
    print(f"[+] Retrieved {len(data.get('data', []))} blacklisted IPs.")
    save_to_file(data)

