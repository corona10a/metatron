# EXPLOITRON

**EXPLOITRON by Cortex Labs (Carlos Alcocer)** is an AI-assisted security assessment CLI for Parrot OS.

It uses DeepSeek through the cloud API, stores scan history in MariaDB, and exports clean PDF/HTML reports.

---

## Overview

EXPLOITRON helps organize authorized security assessments from a terminal interface. It collects recon output, sends the collected context to DeepSeek for analysis, saves structured findings to MariaDB, and lets you review/export previous sessions.

Use this project only on systems you own or have explicit written permission to assess.

---

## Features

- AI analysis powered by DeepSeek API
- CLI workflow for new scans and history review
- MariaDB backend with linked scan sessions, findings, fixes, recorded exploit attempts, and summaries
- PDF and HTML report export
- Environment-variable based configuration
- Green terminal branding and `exploitron>` prompt

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3 |
| AI Backend | DeepSeek Chat Completions API |
| Default Model | `deepseek-chat` |
| Database | MariaDB |
| OS | Parrot OS / Debian-based Linux |
| Search | DuckDuckGo via Python package |
| Reports | ReportLab + HTML |

---

## Installation

```bash
git clone https://github.com/corona10a/metatron.git
cd metatron
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Install the required system tools for your authorized assessment workflow:

```bash
sudo apt install nmap whois whatweb curl dnsutils nikto mariadb-server
```

---

## Environment Variables

Recommended `.env` or shell exports:

```bash
export EXPLOITRON_DEEPSEEK_API_KEY="your_deepseek_api_key_here"
export EXPLOITRON_MODEL_NAME="deepseek-chat"

export EXPLOITRON_DB_HOST="localhost"
export EXPLOITRON_DB_USER="exploitron"
export EXPLOITRON_DB_PASSWORD="123"
export EXPLOITRON_DB_NAME="exploitron"

export EXPLOITRON_REPORT_DIR="$HOME/EXPLOITRON/reports"
```

`DEEPSEEK_API_KEY` may still be used as a compatibility fallback by `llm.py`, but the preferred variable is `EXPLOITRON_DEEPSEEK_API_KEY`.

---

## Database Setup

Start MariaDB:

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

Create the database and user:

```bash
mysql -u root
```

```sql
CREATE DATABASE exploitron;
CREATE USER 'exploitron'@'localhost' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON exploitron.* TO 'exploitron'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Create the tables:

```bash
mysql -u exploitron -p123 exploitron
```

```sql
CREATE TABLE history (
  sl_no INT AUTO_INCREMENT PRIMARY KEY,
  target VARCHAR(255) NOT NULL,
  scan_date DATETIME NOT NULL,
  status VARCHAR(50) DEFAULT 'active'
);

CREATE TABLE vulnerabilities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sl_no INT,
  vuln_name TEXT,
  severity VARCHAR(50),
  port VARCHAR(20),
  service VARCHAR(100),
  description TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE fixes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sl_no INT,
  vuln_id INT,
  fix_text TEXT,
  source VARCHAR(50),
  FOREIGN KEY (sl_no) REFERENCES history(sl_no),
  FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE exploits_attempted (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sl_no INT,
  exploit_name TEXT,
  tool_used TEXT,
  payload LONGTEXT,
  result TEXT,
  notes TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE summary (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sl_no INT,
  raw_scan LONGTEXT,
  ai_analysis LONGTEXT,
  risk_level VARCHAR(50),
  generated_at DATETIME,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);
```

---

## Usage

```bash
source venv/bin/activate
python exploitron.py
```

Main menu:

```text
[1] New Scan
[2] View History
[3] Exit
```

Prompt:

```text
exploitron>
```

---

## Project Structure

```text
EXPLOITRON/
├── exploitron.py      # main CLI entry point
├── db.py              # MariaDB connection and CRUD operations
├── tools.py           # authorized recon tool runners
├── llm.py             # DeepSeek interface and AI analysis loop
├── search.py          # DuckDuckGo web search and CVE lookup helper
├── export.py          # PDF/HTML report exporter
├── requirements.txt   # Python dependencies
├── .gitignore         # local artifacts and secrets ignore rules
├── LICENSE            # MIT License
└── screenshots/       # terminal screenshots for documentation
```

---

## Reports

Reports are saved by default to:

```text
~/EXPLOITRON/reports
```

Override with:

```bash
export EXPLOITRON_REPORT_DIR="/custom/report/path"
```

Generated files use the prefix:

```text
exploitron_SL<session>_<target>.pdf
exploitron_SL<session>_<target>.html
```

---

## Disclaimer

EXPLOITRON is intended for educational use and authorized security assessments only.

Only use it on systems you own or have explicit written permission to assess. Unauthorized scanning, intrusion, or misuse may be illegal. The author is not responsible for misuse of this tool.

---

## Author

**Cortex Labs**  
**Carlos Alcocer**

---

## License

MIT License. See [LICENSE](LICENSE).
