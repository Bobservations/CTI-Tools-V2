import os
import requests
from dotenv import load_dotenv
from datetime import datetime

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("OTX_API_KEY")

if not API_KEY:
    raise ValueError("Missing OTX_API_KEY in .env file")

headers = {
    'X-OTX-API-KEY': API_KEY
}

# OTX endpoint to fetch latest threat pulses
url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

def fetch_pulses():
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"API error: {response.status_code}")
    data = response.json()
    return data['results']

def save_raw_data(data):
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')
    filename = f"../data/otx_raw_{timestamp}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        import json
        json.dump(data, f, indent=2)
    print(f"[+] Saved raw data to {filename}")

def print_summary(pulses):
    for pulse in pulses[:5]:  # Only show first 5
        print(f"Title: {pulse['name']}")
        print(f"Tags: {pulse.get('tags', [])}")
        print(f"Created: {pulse['created']}")
        print("-" * 50)

if __name__ == "__main__":
    print("[*] Fetching threat pulses from AlienVault OTX...")
    pulses = fetch_pulses()
    print_summary(pulses)
    save_raw_data(pulses)
