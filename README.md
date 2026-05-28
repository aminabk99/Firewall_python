<div align="center">

# 🛡️ Firewall Simulator
### A Python Algorithmic Bouncer for Network Traffic

A Python-based cybersecurity simulation that demonstrates how a network firewall monitors and filters incoming packets — enforcing **whitelists**, **blacklists**, **signature detection**, and **DoS protection** — with results logged to a timestamped file.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Network-Firewall_Simulation-CC0000?style=for-the-badge&logo=hackthebox&logoColor=white)
![Logging](https://img.shields.io/badge/Output-TXT_Log_File-555555?style=for-the-badge&logo=files&logoColor=white)
![DoS](https://img.shields.io/badge/Protection-DoS_%26_Signature-FF6600?style=for-the-badge&logo=shield&logoColor=white)

</div>

---

## How It Works

1. A stream of simulated network packets arrives, each carrying a source IP and payload
2. Every packet is evaluated through a **4-layer rule chain** in order:
   - ✅ **Whitelist check** — trusted IPs bypass all other checks
   - 🚫 **Blacklist check** — known bad IPs are blocked immediately
   - 🔍 **Signature detection** — payloads are scanned for malicious strings (e.g. Nimda worm)
   - ⚡ **DoS protection** — IPs exceeding the packet threshold are blocked and blacklisted
3. Each decision is logged to a daily **timestamped `.txt` log file**
4. Blocked IPs are **dynamically added to the blacklist** for the rest of the session

**Rules enforced:** 🟢 Whitelist · 🔴 Blacklist · 🦠 Malware Signatures · 💥 DoS Threshold

---

## Setup

**Requirements:** Python 3.11+ · No external libraries needed

**1. Clone & run**
```bash
git clone https://github.com/aminabk99/Firewall_python
cd Firewall_python
python Firewall.py
```

Check the `logs/` folder for a timestamped log file after running.

---

## Configuration

Inside `Firewall.py`, three constants control firewall behavior:

```python
THRESHOLD = 5                          # Max packets before DoS block
WHITELIST = {"192.168.1.1", "127.0.0.1"}  # IPs that bypass all checks
MALICIOUS_SIGNATURE = "GET /scripts/root.exe"  # Nimda worm signature
```

---

## Hardest Part
**Getting the rule chain order right** — whitelisted IPs must bypass signature and DoS checks entirely, but blacklisted IPs must be caught before signature scanning wastes cycles. The ordering of the `if/elif` chain is the actual firewall logic.

## Most Interesting
**Dynamic blacklisting** — once an IP triggers a DoS or signature rule, it gets added to the blacklist mid-session. Subsequent packets from that IP are blocked instantly without re-scanning, which is exactly how real firewall rule caches work.

---

## Files

- `Firewall.py` — core firewall engine with all rule logic
- `firewall_log.txt` — sample output log from a previous run
- `logs/` — generated daily log files (auto-created at runtime)

---

## Files to Delete
> These are Visual Studio project files and have no use on GitHub:
- `Firewall.pyproj`
- `Firewall.slnx`

---

<div align="center">
  <sub>Built by <a href="https://github.com/aminabk99">Amina Bilal</a> · <a href="https://linkedin.com/in/amina-bilal-926340382">LinkedIn</a></sub>
</div>
<img width="352" height="214" alt="image" src="https://github.com/user-attachments/assets/a145119d-e6d5-44bf-8a87-d82d42f01abf" />
