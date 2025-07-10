import os
import glob
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt

# === Paths ===
script_path = Path(__file__).resolve()
base_path = script_path.parent.parent  # Takes us to .../automated-threat-brief-generator
data_path = base_path / "data"

# Find latest MITRE mapping file
def get_latest_mapping_file():
    files = sorted(data_path.glob("malware_mitre_mapping_*.json"), key=os.path.getmtime, reverse=True)
    return files[0] if files else None

# Load and parse techniques
def extract_techniques(mapping_file):
    with open(mapping_file, "r", encoding="utf-8") as f:
        mapping_data = json.load(f)

    technique_counter = Counter()
    for entry in mapping_data:
        for technique in entry.get("techniques", []):
            technique_counter[technique] += 1
    return technique_counter

# Main
mapping_file = get_latest_mapping_file()
if not mapping_file:
    print("[-] No MITRE mapping file found.")
    exit(1)

technique_counter = extract_techniques(mapping_file)

# Plot
top_techniques = technique_counter.most_common(15)
if not top_techniques:
    print("[-] No techniques found to plot.")
    exit(1)

techniques, counts = zip(*top_techniques)
max_count = max(counts)

plt.figure(figsize=(12, 8))
bars = plt.barh(techniques, counts, edgecolor='black')

# Add labels to each bar
for bar in bars:
    width = bar.get_width()
    plt.text(width + 1.0, bar.get_y() + bar.get_height() / 2,
             f'{int(width)} threats', va='center', fontsize=9)

# Set X-axis limit dynamically to fit text
plt.xlim(0, max_count + max_count * 0.2)

# Titles and labels
plt.xlabel("Frequency (Number of Mapped Malware Families)", fontsize=12)
plt.title("Top 15 MITRE ATT&CK Techniques Mapped from Malware", fontsize=14, fontweight='bold')
plt.gca().invert_yaxis()  # Most frequent on top
plt.grid(axis='x', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.show()
