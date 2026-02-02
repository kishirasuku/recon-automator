# Recon Automator

A Python GUI application for Kali Linux that automates web reconnaissance with a single button click.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-black.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

- **Single-click reconnaissance** - Enter a target domain and start scanning
- **5 Recon Modules**:
  - Subdomain enumeration (subfinder)
  - Port scanning (nmap)
  - Technology detection (whatweb/httpx)
  - Directory enumeration (gobuster)
  - Wayback URL discovery (waybackurls/gau)
- **3 Scan Profiles**: Quick, Standard, Deep
- **Real-time log output** with timestamps
- **Results export** to JSON and TXT files
- **Modern dark-themed GUI** using CustomTkinter

## Screenshots

```
┌─────────────────────────────────────────────────────────────┐
│  Recon Automator                                            │
├─────────────────────────────────────────────────────────────┤
│  Target: [example.com                    ]                  │
│  Profile: [Standard ▼]                                      │
│                                                             │
│  [Start Scan]  [Cancel]  [Open Output]                      │
│                                                             │
│  ═══════════════════════════════════════                    │
│  Running scan on example.com...                             │
│  ┌─────────────────────────────┬───────────────────┐        │
│  │ Log Output                  │ Module Status     │        │
│  │ [12:34:56] Starting...      │ ✓ subdomain      │        │
│  │ [12:34:57] Found: sub1...   │ ● portscan       │        │
│  │ [12:35:01] Scanning ports.. │ ○ techdetect     │        │
│  │                             │ ○ directory      │        │
│  │                             │ ○ wayback        │        │
│  └─────────────────────────────┴───────────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

### System Requirements
- Kali Linux (or any Linux with the required tools)
- Python 3.10+

### Required Tools
Install these tools on Kali Linux:
```bash
sudo apt update
sudo apt install subfinder nmap whatweb gobuster
go install github.com/tomnomnom/waybackurls@latest
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/recon-automator.git
cd recon-automator

# Install Python dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## Usage

1. **Launch the application**:
   ```bash
   python main.py
   ```

2. **Enter target domain** (e.g., `example.com`)

3. **Select scan profile**:
   - **Quick**: Fast scan, limited ports, no directory brute-forcing
   - **Standard**: Balanced scan with common checks
   - **Deep**: Comprehensive scan, all ports, large wordlists

4. **Click "Start Scan"** and monitor progress in real-time

5. **View results** in the `output/` directory

## Output Structure

```
output/{target}_{timestamp}/
├── results.json      # All findings in structured format
├── subdomains.txt    # Discovered subdomains
├── ports.txt         # Open ports with services
├── technologies.txt  # Detected technologies
├── directories.txt   # Found directories/files
├── wayback.txt       # Historical URLs
└── summary.txt       # Human-readable summary
```

## Configuration

Edit `config/settings.yaml` to customize:
- Tool paths
- Scan profiles and timeouts
- Wordlist locations
- Output directory

## Project Structure

```
recon-automator/
├── main.py                 # Entry point
├── requirements.txt        # Python dependencies
├── config/
│   └── settings.yaml       # Configuration
├── core/
│   ├── runner.py           # Async execution engine
│   └── reporter.py         # Result export
├── modules/
│   ├── base.py             # Abstract base class
│   ├── subdomain.py        # Subfinder wrapper
│   ├── portscan.py         # Nmap wrapper
│   ├── techdetect.py       # WhatWeb/httpx wrapper
│   ├── directory.py        # Gobuster wrapper
│   └── wayback.py          # Waybackurls wrapper
├── gui/
│   ├── app.py              # Main window
│   └── widgets.py          # Custom widgets
└── output/                 # Scan results
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always obtain proper authorization before scanning any systems you do not own.
