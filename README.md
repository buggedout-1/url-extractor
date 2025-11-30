<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.7+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg" alt="Platform">
</p>

<h1 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/javascript.svg" width="100" height="100" alt="Logo">
  <br>
  URL Extractor
  <br>
</h1>

<h4 align="center">A powerful reconnaissance tool for extracting URLs from JavaScript files</h4>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-examples">Examples</a> •
  <a href="#-output">Output</a>
</p>

---

## Overview

**URL Extractor** is a fast, multi-threaded Python tool designed for security researchers, penetration testers, and bug bounty hunters. It extracts and filters URLs from JavaScript files to discover hidden endpoints, API routes, configuration files, and sensitive information.

```
$ python url-extractor.py --url https://target.com/app.js -v

                    === URL Extractor v2.0.0 ===

[INFO] Processing 1 URL(s)...
[INFO] Extracted 15 URLs from https://target.com/app.js
  [+] https://target.com/api/v1/users
  [+] https://target.com/api/v1/admin/settings
  [+] https://target.com/api/internal/debug
  [+] https://target.com/config.json

[INFO] Processed: 1 successful, 0 failed
[INFO] Total URLs extracted: 15
[INFO] Unique URLs written to extracted_links.txt: 15
```

---

## ✨ Features

<table>
<tr>
<td>

**Core**
- Extract HTTP/HTTPS URLs from JS files
- Smart regex with URL normalization
- Automatic scope detection
- Deduplication built-in

</td>
<td>

**Filtering**
- Domain scope filtering
- Subdomain inclusion (`-s`)
- Parameter URLs only (`-p`)
- JS/JSON files only (`-j`)

</td>
</tr>
<tr>
<td>

**Performance**
- Multi-threaded requests
- Configurable concurrency
- Rate limiting support
- Automatic retry logic

</td>
<td>

**Flexibility**
- Custom User-Agent
- Proxy support (HTTP/SOCKS)
- TXT & JSON output formats
- Silent & verbose modes

</td>
</tr>
</table>

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/url-extractor.git

# Navigate to directory
cd url-extractor

# Install dependencies
pip install -r requirements.txt
```

**Requirements:** Python 3.7+

---

## 🚀 Usage

### Quick Start

```bash
# Single URL
python url-extractor.py --url https://example.com/app.js

# Multiple URLs from file
python url-extractor.py -l urls.txt -o results.txt
```

### Command Reference

<details>
<summary><b>📥 Input Options</b></summary>

| Flag | Description |
|:-----|:------------|
| `-l, --input-file` | File with JS URLs (one per line) |
| `--url` | Single JavaScript URL |

</details>

<details>
<summary><b>📤 Output Options</b></summary>

| Flag | Description |
|:-----|:------------|
| `-o, --output` | Output file path (default: `extracted_links.txt`) |
| `-f, --format` | Output format: `txt` \| `json` |

</details>

<details>
<summary><b>🔍 Filter Options</b></summary>

| Flag | Description |
|:-----|:------------|
| `-p, --params-only` | Only URLs with `=` (parameters) |
| `-j, --js-json-only` | Only `.js` and `.json` files |
| `-s, --include-subdomains` | Include all subdomains |

</details>

<details>
<summary><b>🌐 Request Options</b></summary>

| Flag | Description |
|:-----|:------------|
| `-t, --timeout` | Request timeout in seconds (default: `10`) |
| `-d, --delay` | Delay between requests (default: `0`) |
| `--threads` | Concurrent threads (default: `5`) |
| `-r, --retries` | Retry attempts (default: `2`) |
| `-A, --user-agent` | Custom User-Agent header |
| `-x, --proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) |

</details>

<details>
<summary><b>🖥️ Display Options</b></summary>

| Flag | Description |
|:-----|:------------|
| `--silent` | Suppress all output |
| `-v, --verbose` | Show extracted URLs live |
| `--no-color` | Disable colors |
| `--no-banner` | Hide banner |
| `-V, --version` | Show version |

</details>

---

## 📋 Examples

<details>
<summary><b>🎯 Bug Bounty Recon</b></summary>

```bash
# Extract all URLs with verbose output
python url-extractor.py --url https://target.com/main.js -v

# Find API endpoints with parameters
python url-extractor.py --url https://target.com/app.js -p -v

# Discover all JS files for further analysis
python url-extractor.py --url https://target.com/bundle.js -j -s
```

</details>

<details>
<summary><b>🔥 Batch Processing</b></summary>

```bash
# Process multiple targets with rate limiting
python url-extractor.py -l targets.txt -d 1.0 --threads 3

# Export comprehensive JSON report
python url-extractor.py -l targets.txt -f json -o report.json
```

</details>

<details>
<summary><b>🔒 Through Proxy (Burp/ZAP)</b></summary>

```bash
# Route through Burp Suite
python url-extractor.py --url https://target.com/app.js -x http://127.0.0.1:8080

# With custom User-Agent
python url-extractor.py --url https://target.com/app.js -A "Mozilla/5.0 (X11; Linux x86_64)"
```

</details>

<details>
<summary><b>⚡ High Performance</b></summary>

```bash
# Fast extraction with 10 threads
python url-extractor.py -l large_list.txt --threads 10 --silent

# Include all subdomains
python url-extractor.py -l targets.txt -s --threads 8
```

</details>

---

## 📊 Output

### TXT Format
```
https://target.com/api/v1/users
https://target.com/api/v1/products
https://target.com/api/v1/admin/settings
https://target.com/static/config.json
```

### JSON Format
```json
{
  "total_sources": 3,
  "successful": 3,
  "failed": 0,
  "total_urls_found": 45,
  "unique_url_count": 32,
  "unique_urls": [
    "https://target.com/api/v1/users",
    "https://target.com/api/v1/products"
  ],
  "results": [
    {
      "source": "https://target.com/app.js",
      "status_code": 200,
      "urls_found": 15,
      "urls": ["..."]
    }
  ]
}
```

---

## 🎯 Use Cases

| Scenario | Command |
|:---------|:--------|
| **Find hidden APIs** | `--url target.js -v` |
| **Discover admin endpoints** | `--url target.js -p -v` |
| **Map JS dependencies** | `--url target.js -j -s` |
| **Bulk recon** | `-l urls.txt --threads 10` |
| **Generate report** | `-l urls.txt -f json -o report.json` |

---

## 📝 Changelog

### v2.0.0
```diff
+ Multi-threaded concurrent processing
+ Retry logic for failed requests
+ Proxy support (HTTP/SOCKS)
+ Subdomain filtering option
+ JSON output format
+ Automatic deduplication
+ Improved URL regex pattern
+ Type hints throughout
! Fixed file extension detection with query strings
! Fixed terminal crash in non-interactive mode
! Fixed input validation
```

### v1.0.0
- Initial release

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing** and **educational purposes** only. Users are responsible for ensuring they have proper authorization before testing any systems they do not own.

---

## 📄 License

MIT License - feel free to use, modify, and distribute.

---

<p align="center">
  <b>Made for Bug Bounty Hunters</b>
  <br>
  <sub>If you find this useful, give it a ⭐</sub>
</p>
