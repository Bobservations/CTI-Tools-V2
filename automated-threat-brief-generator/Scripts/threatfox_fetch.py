import os
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Load API key
load_dotenv()
API_KEY = os.getenv("THREATFOX_API_KEY")

if not API_KEY:
    raise ValueError("Missing THREATFOX_API_KEY in .env file")

url = "https://threatfox.abuse.ch/api/v1/"

def fetch_threatfox_data():
    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "query": "get_iocs",
        "limit": 100,
        "api_key": API_KEY
    }

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code != 200:
        print(response.text)  # Helpful debug
        raise Exception(f"Error: {response.status_code}")

    result = response.json()
    return result["data"]

def save_to_file(data):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')
    filename = f"../data/threatfox_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved ThreatFox data to {filename}")

if __name__ == "__main__":
    print("[*] Fetching recent indicators from ThreatFox...")
    data = fetch_threatfox_data()
    print(f"[+] Retrieved {len(data)} indicators.")
    save_to_file(data)
