# Pulse Log Forge

A blue team training tool that generates realistic, scenario-based server logs for SOC analysts, DFIR students, and CTF challenge authors. Produce authentic attack logs across six log formats with configurable difficulty levels and built-in answer keys.

## Features

- **6 log formats** — Apache, Nginx, IIS (W3C Extended), SSH auth.log, Windows Security Event Log (CSV), Firewall (iptables syslog)
- **10 attack scenarios** — LFI, HTTP Bruteforce, Webshell RCE, SSH Bruteforce, SSH Password Spray, Windows Logon Bruteforce, Post-Exploitation, Port Scan, C2 Beaconing, Data Exfiltration
- **3 difficulty levels** — Easy (obvious, high-volume), Medium (mixed noise), Hard (low-and-slow, stealthy)
- **Answer keys** — Every generated file comes with a JSON answer key listing attacker IPs, commands, compromised accounts, and more
- **Preview mode** — See the first 20 and last 10 lines before downloading
- **Advanced overrides** — Customize attacker IPs, shell paths, target endpoints, beacon intervals, and more via JSON

## Quick Start

### Requirements

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Install & Run

```bash
# Clone the repository
git clone https://github.com/ChickenLoner/Pulse-log-generator.git
cd Pulse-log-generator

# Create a virtual environment and install dependencies
uv venv .venv
uv pip install flask

# Run the server
.venv/bin/python server.py
# On Windows:  .venv\Scripts\python server.py
```

Then open **http://localhost:5000** in your browser.

## Usage

1. **Select a log type** from the six cards (Apache, Nginx, IIS, SSH, Windows, Firewall)
2. **Check one or more attack scenarios** for that log type
3. **Configure** noise lines, difficulty, attacker count, and time window
4. Click **Generate & Download** to get the `.log` / `.csv` file plus a `_answers.json` key, or **Preview** to inspect lines in-browser

### Advanced Overrides

Expand the **Advanced** panel to pass a JSON object with optional overrides:

```json
{
  "custom_attacker_ips": ["10.10.10.99", "203.0.113.5"],
  "shell_path": "/uploads/img/.thumb.php",
  "lfi_endpoint": "/view.php",
  "ssh_hostname": "prod-web02",
  "fw_c2_ip": "192.0.2.200",
  "fw_beacon_interval": 300
}
```

## Log Formats & Scenarios

| Log Type | Scenarios |
|---|---|
| Apache | LFI, HTTP Bruteforce, Webshell |
| Nginx | LFI, HTTP Bruteforce, Webshell |
| IIS (W3C) | LFI, HTTP Bruteforce, Webshell |
| SSH auth.log | SSH Bruteforce, SSH Password Spray |
| Windows Event Log | Logon Bruteforce (4625/4624), Post-Exploitation (4688/4720/4732/7045) |
| Firewall (iptables) | Port Scan, C2 Beaconing, Data Exfiltration |

## Project Structure

```
server.py           Flask app — serves UI, /generate, /download
index.html          Frontend UI
assets/
  app.js            Frontend controller
  style.css         Styles
generators/
  config.py         Constants, IP pools, log format functions
  traffic.py        Apache noise
  pages.py          LFI (Apache)
  auth.py           HTTP Bruteforce (Apache)
  cache.py          Webshell (Apache)
  proxy.py          All Nginx generators
  service.py        All IIS generators
  remote.py         All SSH generators
  events.py         All Windows Event Log generators
  netflow.py        All Firewall generators
includes/           Original PHP source (kept for reference)
```

## License

MIT — see [LICENSE](LICENSE)
