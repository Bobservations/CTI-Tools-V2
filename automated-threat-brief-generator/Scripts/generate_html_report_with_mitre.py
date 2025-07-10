import os
import json
from datetime import datetime
from pathlib import Path
from collections import Counter
import matplotlib.pyplot as plt
import base64
from io import BytesIO

# === Setup Paths ===
script_path = Path(__file__).resolve()
base_path = script_path.parent.parent

data_path = base_path / "data"
report_path = base_path / "reports"
data_path.mkdir(exist_ok=True)
report_path.mkdir(exist_ok=True)

# === Load latest malware-to-technique mapping ===
def get_latest_mapping_file():
    files = sorted(data_path.glob("malware_mitre_mapping_*.json"), key=os.path.getmtime, reverse=True)
    return files[0] if files else None

def load_mapping_data():
    mapping_file = get_latest_mapping_file()
    if not mapping_file:
        return []
    with open(mapping_file, "r", encoding="utf-8") as f:
        return json.load(f)

# === Generate Bar Chart and Embed as Base64 ===
def generate_bar_chart(mapping_data):
    technique_counter = Counter()
    for entry in mapping_data:
        for t in entry.get("techniques", []):
            technique_counter[t] += 1
    top_techniques = technique_counter.most_common(15)

    techniques, counts = zip(*top_techniques)
    plt.figure(figsize=(10, 6))
    bars = plt.barh(techniques, counts, color='skyblue')
    plt.xlabel("Number of Malware Families")
    plt.title("Top 15 MITRE ATT&CK Techniques")
    plt.gca().invert_yaxis()
    for bar, count in zip(bars, counts):
        plt.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height()/2, str(count), va='center')
    plt.tight_layout()

    buffer = BytesIO()
    plt.savefig(buffer, format="png")
    plt.close()
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.read()).decode("utf-8")
    return img_base64

# === Build HTML ===
def build_html(mapping_data, bar_chart_base64):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    html = f"""
    <html>
    <head>
        <title>MITRE Threat Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #1F4E79; }}
            .section {{ margin-bottom: 30px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .malware-name {{ font-weight: bold; }}
            ul {{ list-style-type: none; padding: 0; }}
            ul li {{ padding: 4px 0; }}
            .summary-section {{ background-color: #f9f9f9; padding: 15px; border: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <h1>MITRE Threat Mapping Report</h1>
        <p><strong>Generated:</strong> {timestamp}</p>

        <div class="section">
            <h2>📊 Top Techniques Chart</h2>
            <img src="data:image/png;base64,{bar_chart_base64}" alt="Top Techniques">
        </div>

        <div class="section summary-section">
            <h2>🔍 Summary</h2>
            <ul>
                <li><strong>Total OTX Pulses:</strong> 5</li>
                <li><strong>Total ThreatFox IOCs:</strong> 303</li>
                <li><strong>Total AbuseIPDB Records:</strong> 10000</li>
            </ul>
        </div>

        <div class="section">
            <h2>🧬 Top Malware Families</h2>
            <ul>
                <li><strong>win.lumma:</strong> 55</li>
                <li><strong>unknown:</strong> 33</li>
                <li><strong>win.cobalt_strike:</strong> 31</li>
                <li><strong>win.netsupportmanager_rat:</strong> 20</li>
                <li><strong>win.sliver:</strong> 19</li>
                <li><strong>win.asyncrat:</strong> 14</li>
                <li><strong>win.havoc:</strong> 11</li>
                <li><strong>win.adaptix_c2:</strong> 11</li>
                <li><strong>win.vidar:</strong> 10</li>
                <li><strong>elf.mirai:</strong> 8</li>
            </ul>
        </div>

        <div class="section">
            <h2>🏷️ Top Tags</h2>
            <ul>
                <li>c2: 209</li>
                <li>censys: 107</li>
                <li>Lumma: 54</li>
                <li>shodan: 36</li>
                <li>RAT: 33</li>
                <li>CobaltStrike: 28</li>
                <li>sliver: 18</li>
                <li>phishing: 13</li>
                <li>NetSupport: 13</li>
                <li>domain: 13</li>
            </ul>
        </div>

        <div class="section">
            <h2>📌 Sample ThreatFox IOCs</h2>
            <ul>
                <li>206.238.220.24:7777 (botnet_cc)</li>
                <li>45.154.1.195:53 (botnet_cc)</li>
                <li>154.247.28.115:22 (botnet_cc)</li>
                <li>149.28.137.96:443 (botnet_cc)</li>
                <li>185.196.11.241:56001 (botnet_cc)</li>
                <li>196.251.80.94:1912 (botnet_cc)</li>
                <li>94.26.90.74:443 (botnet_cc)</li>
                <li>16.51.81.255:13000 (botnet_cc)</li>
                <li>72.14.179.130:8080 (botnet_cc)</li>
                <li>193.233.113.0:80 (botnet_cc)</li>
            </ul>
        </div>

        <div class="section">
            <h2>📌 Sample OTX References</h2>
            <ul>
                <li>https://securelist.com/librarian-ghouls-apt-wakes-up-computers-to-steal-data-and-mine-crypto/116536</li>
                <li>https://www.seqrite.com/blog/operation-dragonclone-chinese-telecom-veletrix-vshell-malware</li>
                <li>https://unit42.paloaltonetworks.com/malicious-payloads-as-bitmap-resources-hide-net-malware/</li>
                <li>https://unit42.paloaltonetworks.com/wp-content/uploads/2025/05/05_Hactivism_Overview_1920x900.jpg</li>
                <li>https://unit42.paloaltonetworks.com/malicious-payloads-as-bitmap-resources-hide-net-malware</li>
                <li>https://www.welivesecurity.com/en/eset-research/thewizards-apt-group-slaac-spoofing-adversary-in-the-middle-attacks/</li>
            </ul>
        </div>

        <div class="section">
            <h2>📁 Mapped Malware Families</h2>
            <table>
                <tr><th>Malware</th><th>MITRE Techniques</th></tr>
    """
    for item in mapping_data:
        html += f"<tr><td class='malware-name'>{item['malware']}</td><td>{', '.join(item['techniques'])}</td></tr>"
    html += """
            </table>
        </div>
        <footer><p>Report generated by Bobservation's CTI Tools V2</p></footer>
    </body>
    </html>
    """
    return html

# === Main Execution ===
mapping_data = load_mapping_data()
if not mapping_data:
    print("[-] No mapping data available.")
    exit(1)

print("[*] Generating bar chart...")
bar_chart = generate_bar_chart(mapping_data)

print("[*] Building HTML report...")
html_report = build_html(mapping_data, bar_chart)

output_file = report_path / f"threat_report_{datetime.utcnow().strftime('%Y-%m-%d')}_MITRE.html"
with open(output_file, "w", encoding="utf-8") as f:
    f.write(html_report)

print(f"[+] Report saved to: {output_file}")
