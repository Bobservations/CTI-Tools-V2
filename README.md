# CTI Tools V2: Automated Threat Intelligence Reporting

This project provides a streamlined solution to fetch, parse, and visualize threat intelligence data using open-source feeds such as OTX, ThreatFox, and MITRE ATT&CK. The goal is to generate enriched HTML (or optionally PDF) reports with actionable context for cybersecurity teams and executives.

## 🔧 Getting Started

### 1. Prerequisites

- Python 3.11
- [Git Bash](https://git-scm.com/)
- [Visual Studio Code](https://code.visualstudio.com/)
- Install Python packages:
  ```bash
  pip install requests python-dotenv matplotlib networkx stix2
  ```

##Project Structure
Clone this repo and structure it like this:
CTI-Tools-V2/
├── data/                      # Raw data from feeds (auto-created)
* ├── reports/                   # Output reports (auto-created)
* ├── .env                       # Your API keys (see below)
* ├── automated-threat-brief-generator/
* │   ├── scripts/
* │   │   ├── fetch_and_generate.py
* │   │   ├── mitre_stix_parser.py
* │   │   ├── exec_combined_mitre_visual.py
* │   │   └── generate_html_report_with_mitre.py

##Environment Configuration
Create a .env file in the CTI-Tools-V2/ root:
```git
      touch .env
```
```git
OTX_API_KEY=your_otx_key_here
THREATFOX_API_KEY=your_threatfox_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

##Initial Setup

