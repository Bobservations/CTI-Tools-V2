# Automated Threat Brief Generator

This tool aggregates and summarizes cyber threat intelligence from multiple OSINT sources (e.g., AlienVault OTX, ThreatFox, AbuseIPDB) to generate structured threat briefs in Markdown or PDF.

## Features
- Fetches and normalizes IoCs from public feeds
- Categorizes threats by relevance and severity
- Outputs daily/weekly threat summaries

## Planned
- PDF export
- Email integration
- Sector-specific filtering (e.g., finance)


## Scripts
You will need to generate a few scripts to be able to pull the information from the different feeds. 
##What Feeds: 
- OTX
- ABUSEIPDB
- THREATFOX

Scripts can be named how you like, code will reflect my naming convention. 


```git
touch [filename.py]
```

```git
nano [filename.py]
```

- abuseipdb_fetch.py
- exec_combined_mitre_visual.py
- exec_fintech_malware_CTI_graph.py
- fetch_all_feeds.py
- generate_html_report.py
- generate_html_report_with_mitre.py
- generate_markdown_report.py
- mitre_stix_parser.py
- mitre_taxii_parser.py
- otx_fetch.py
- plot_malware_techniques_graph.py
- plot_top_techniques.py
- threatfox_fetch.py
