import os
import json
import glob
from collections import Counter
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt
import networkx as nx

# === Paths ===
script_path = Path(__file__).resolve()
base_path = script_path.parent.parent  # Go up to `automated-threat-brief-generator`
data_path = base_path / "data"
data_path.mkdir(parents=True, exist_ok=True)

# === Load latest malware-to-technique mapping ===
def get_latest_mapping_file():
    files = sorted(data_path.glob("malware_mitre_mapping_*.json"), key=os.path.getmtime, reverse=True)
    return files[0] if files else None

def load_mapping_data():
    mapping_file = get_latest_mapping_file()
    if not mapping_file:
        print("[-] No mapping file found.")
        return []
    with open(mapping_file, "r", encoding="utf-8") as f:
        return json.load(f)

# === Load latest feed malware ===
def get_latest_file(prefix):
    files = sorted(data_path.glob(f"{prefix}_*.json"), key=os.path.getmtime, reverse=True)
    return files[0] if files else None

def load_json(filepath):
    if not filepath:
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def extract_malware_from_feeds():
    otx_data = load_json(get_latest_file("otx")) or []
    threatfox_data = load_json(get_latest_file("threatfox")) or []
    seen = set()
    for pulse in otx_data:
        seen.add(pulse.get("malware_family", "").lower())
    for tf in threatfox_data:
        seen.add(tf.get("malware", "").lower())
    return sorted(seen - {""})

# === Build Graph ===
def build_graph(mapping_data, focus_malware):
    G = nx.Graph()
    for entry in mapping_data:
        malware = entry.get("malware", "").lower()
        techniques = entry.get("techniques", [])
        if not malware or not techniques:
            continue
        if malware not in focus_malware:
            continue
        for tech in techniques:
            G.add_node(malware, type="malware")
            G.add_node(tech, type="technique")
            G.add_edge(malware, tech)
    return G

# === Plot Bar Chart ===
def plot_top_techniques(mapping_data):
    technique_counter = Counter()
    for entry in mapping_data:
        for t in entry.get("techniques", []):
            technique_counter[t] += 1
    if not technique_counter:
        print("[-] No techniques found.")
        return
    top_techniques = technique_counter.most_common(15)
    techniques, counts = zip(*top_techniques)
    plt.figure(figsize=(10, 6))
    bars = plt.barh(techniques, counts)
    plt.xlabel("Number of Mapped Malware Families")
    plt.title("Top 15 MITRE ATT&CK Techniques (All Mappings)")
    plt.gca().invert_yaxis()
    for bar, count in zip(bars, counts):
        plt.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2, str(count), va='center')
    plt.tight_layout()
    plt.show()

# === Plot Relationship Graph ===
def plot_relationship_graph(G):
    if G.number_of_nodes() == 0:
        print("[-] No graph data to visualize.")
        return
    plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(G, k=0.7)
    malware_nodes = [n for n, d in G.nodes(data=True) if d["type"] == "malware"]
    technique_nodes = [n for n, d in G.nodes(data=True) if d["type"] == "technique"]
    nx.draw_networkx_nodes(G, pos, nodelist=malware_nodes, node_color="lightcoral", label="Malware", node_size=600)
    nx.draw_networkx_nodes(G, pos, nodelist=technique_nodes, node_color="skyblue", label="Technique", node_size=600)
    nx.draw_networkx_edges(G, pos, alpha=0.4)
    nx.draw_networkx_labels(G, pos, font_size=8)
    plt.title("Malware ↔ MITRE Technique Relationships (Top 20 Malware Observed Today)")
    plt.axis("off")
    plt.tight_layout()
    plt.legend()
    plt.show()

# === Main Execution ===
print("[*] Extracting today's malware...")
observed = extract_malware_from_feeds()
observed = sorted(observed)[:20]  # Top 20
print(f"[+] Today's malware families: {observed}")

print("[*] Loading mapping data...")
mapping_data = load_mapping_data()
if not mapping_data:
    print("[-] No mapping data available.")
    exit(1)

print("[*] Building graph...")
G = build_graph(mapping_data, observed)

print("[DEBUG] Total nodes in full graph:", G.number_of_nodes())
print("[DEBUG] Malware in final subgraph:", [n for n in G.nodes if G.nodes[n]['type'] == 'malware'])

# === Output Charts ===
plot_top_techniques(mapping_data)
plot_relationship_graph(G)
