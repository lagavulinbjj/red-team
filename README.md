# 🕵️‍♂️ AD Recon & Enumeration Tool (Python)

A simple Python-based Active Directory enumeration script designed for initial recon in internal engagements. The tool collects basic domain metadata, enumerates users, groups, and service accounts using native Windows commands — ideal for junior penetration testers, Blue Team apprentices, and students of offensive security.

---

## 🔍 Features

- Enumerates domain users and groups
- Discovers domain controller information
- Lists local admins, sessions, and shares
- Collects hostname, IP, OS version, and other recon data
- Easy to modify and extend

---

## 🚀 Use Cases

- Initial foothold enumeration post-access
- Lab recon (e.g., Hack The Box, TryHackMe, or home labs)
- Blue Team testing: detection rule validation
- Great project to show scripting + AD skills on a resume

---

## ⚙️ Requirements

- Windows target with PowerShell or CMD
- Python 3.x (recommended: 3.10+)
- Run in an environment where basic recon is permitted (test labs or red-team assignments)

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/ad-recon-tool.git
cd ad-recon-tool
python3 ad_recon.py

