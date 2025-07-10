from taxii2client.v20 import Server
from stix2 import MemoryStore

# Connect to MITRE's TAXII 2.0 Server
print("[*] Connecting to MITRE TAXII server...")
server = Server("https://cti-taxii.mitre.org/taxii/")

# Get API root
api_root = server.api_roots[0]

# Find Enterprise ATT&CK collection
collection = None
for c in api_root.collections:
    if "Enterprise ATT&CK" in c.title:
        collection = c
        break

if not collection:
    print("[!] Enterprise ATT&CK collection not found.")
    exit()

print(f"[+] Connected to: {collection.title}")
