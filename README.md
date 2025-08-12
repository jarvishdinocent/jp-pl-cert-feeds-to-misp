# JP-PL-CERT-Feeds-to-MISP

This project is a **Python automation tool** that downloads and processes cyber threat intelligence data from two very active national CERTs:

- **JPCERT/CC (Japan)**
- **CERT-PL (Poland, English and Polish feeds)**

It extracts **Indicators of Compromise (IOCs)** such as:
- Malicious IP addresses
- Compromised domain names
- Dangerous URLs
- Malware file hashes (MD5, SHA1, SHA256)

All valid and unique IOCs are then **automatically uploaded to a MISP instance**, fully tagged and ready for analysis.

---

## 📌 Why These Two CERT Feeds?
Not all CERTs publish IOCs in a machine-readable way.  
Some post advisories without raw indicators, and some require logins or special agreements.

**JPCERT/CC** and **CERT-PL** are different — they:
- Regularly release threat intelligence that includes real, actionable IOCs
- Use formats that can be processed automatically
- Publish in a way that doesn’t require authentication

By starting with these two sources, we get **high-quality, frequent, and open data**.  
Later, this script can be expanded to include other CERT feeds to improve coverage.

---

## 🚀 What This Script Does
1. **Download** the latest advisories from JPCERT/CC and CERT-PL.
2. **Extract** IOCs from HTML, text, or linked PDF files.
3. **Remove duplicates** (both from the current run and from MISP history).
4. **Optionally check** if the IOC is marked as malicious in VirusTotal.
5. **Create MISP events** — one per feed — and tag them for easy searching.
6. **Publish** the events in MISP so they are immediately usable.

---

## 🏷 Automatic Tagging in MISP
Each event is tagged with:
- `osint`
- `source:cert`
- `country:jp` or `country:pl`
- `feed:jpcert` or `feed:cert-pl`
- `tlp:white` (default TLP)
- Any additional tags you configure

---

## 🛠 Requirements
Python 3.8+  
Install the dependencies with:
```bash
pip install -r requirements.txt

---

## 📥 Installation & Running
git clone https://github.com/jarvishdinocent/jp-pl-cert-feeds-to-misp.git
cd jp-pl-cert-feeds-to-misp
pip install -r requirements.txt
python3 cert-feeds-to-misp.py





