from stix2 import FileSystemSource, Filter
from pathlib import Path
import json
from datetime import datetime

# Update this path to your actual MITRE repo path
MITRE_PATH = "C:/Users/<User>/Documents/CTI GIT Project/cti/enterprise-attack"


print(f"[*] Loading STIX files from: {MITRE_PATH}")
fs = FileSystemSource(MITRE_PATH)

# Get all malware entries
malware_list = fs.query([Filter("type", "=", "malware")])
print(f"[+] Loaded {len(malware_list)} malware entries.")

# Print a few to verify
for mw in malware_list[:5]:
    print(f"- {mw.name}")


print("\n[*] Parsing relationships between malware and techniques...")

# Fetch all relationships
relationships = fs.query([Filter("type", "=", "relationship")])

# Build a dictionary: malware_name -> list of technique_names
malware_to_techniques = {}

for rel in relationships:
    if rel.relationship_type != "uses":
        continue
    try:
        # Only look for malware → technique links
        source = fs.get(rel.source_ref)
        target = fs.get(rel.target_ref)
        if source is None or target is None:
            continue
        if source.type == "malware" and target.type == "attack-pattern":
            malware_name = source.name
            technique_name = target.name

            if malware_name not in malware_to_techniques:
                malware_to_techniques[malware_name] = []
            malware_to_techniques[malware_name].append(technique_name)
    except Exception as e:
        continue  # skip malformed records

# Print a sample mapping
print("\n[+] Sample Malware → Techniques Mapping:")
for malware, techniques in list(malware_to_techniques.items())[:5]:
    print(f"\n{malware}:")
    for t in techniques:
        print(f"  - {t}")

import json
from datetime import datetime

# Prepare data for export
export_data = []
for malware, techniques in malware_to_techniques.items():
    export_data.append({
        "malware": malware,
        "techniques": list(set(techniques))  # remove duplicates
    })

# Save to file
script_path = Path(__file__).resolve()
base_path = script_path.parent.parent  # Goes up to automated-threat-brief-generator
data_path = base_path / "data"
data_path.mkdir(parents=True, exist_ok=True)

date_str = datetime.now().strftime("%Y-%m-%d")
output_path = data_path / f"malware_mitre_mapping_{date_str}.json"

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(export_data, f, indent=2)

print(f"\n✅ Mapping exported to: {output_path}")
