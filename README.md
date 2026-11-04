# Automated and Integrated AI Security Agent

**Author:** Mitchell Sheiry
**Course:** CYBR 498, Dr. Almalag
**Platform:** Ubuntu 26.04 LTS, on-prem homelab (Proxmox)

The AI security agent scans a Linux server, uses the Anthropic API to turn the results into easy-to-read reports, and emails them on a need-to-know basis. Security analysts get the full technical report, including the ClamAV malware scan. Everyone, including managers, gets a plain-English summary. A human approves the summary before it reaches managers. The goal is to save security analysts time and help non-technical stakeholders understand their risk.

## How it works

1. `week6_clamav_email/initial_scan_demo.py` collects:
   - system info and pending updates
   - failed SSH logins (last 24 hours, or 7 days on weekly runs)
   - failed services
   - listening ports and firewall status
   - a ClamAV malware scan (initial and weekly only)
2. Usernames and MAC addresses are redacted, and the data is sent to Claude Haiku through the Anthropic API.
3. Claude returns two reports:
   - **Technical report** for security analysts: findings, risk level, ClamAV results, and fix commands
   - **Summary** for everyone: plain English, one line on the virus scan, no file paths, commands, or IPs
4. Recipients come from MySQL: `security_analysts` gets both emails, and `managers_higher_ups` gets the summary only. Managers are optional. If none are listed, the summary goes to analysts only.
5. Reports are saved to `reports/` (root-only) and emailed through Gmail over an encrypted connection.

| Report  | When                          | ClamAV | Logs checked  |
|---------|-------------------------------|--------|---------------|
| initial | once, by hand at deployment   | yes    | last 24 hours |
| nightly | every day, 2:00 AM            | no     | last 24 hours |
| weekly  | Sunday, 3:00 AM               | yes    | last 7 days   |

## Human in the loop

- **Run by hand:** the script asks before sending each email.
- **Run by cron:** the technical report goes to the security analysts, who are the reviewers. The summary is held as pending until an analyst approves it:
  ```bash
  sudo .venv/bin/python week6_clamav_email/initial_scan_demo.py send-summary
  ```
  Each pending summary can be sent (`y`), rejected (`n`), or skipped (`s`).

Summaries move through `pending_summary` → `sent_summary` or `rejected_summary` in `reports/`.

## Project structure

```
ai-security-agent/
├── .env                          # api key, db and gmail credentials (not in git)
├── .venv/                        # python virtual environment (not in git)
├── reports/                      # generated reports, root-only (not in git)
├── week2_database/
│   ├── populate.sql              # creates the tables
│   └── seed_data.sql             # adds the server as the first endpoint
├── week3_api_scripts/            # multi-host version, see "Adding more hosts"
│   ├── collect.sh
│   ├── agent.py
│   ├── approve.py
│   └── run.sh
└── week6_clamav_email/
    ├── initial_scan_demo.py      # scan, claude reports, clamav, email
    └── scheduled_scan.sh         # cron entry point
```

## Requirements

- Ubuntu 26.04 LTS ([download](https://ubuntu.com/download/server)), 2 vCPU and 4 GB RAM recommended (ClamAV needs about 1.5 GB)
- Python 3, MySQL Server, ClamAV
- An Anthropic API key from the [Claude Console](https://console.anthropic.com), with credit loaded
- A Gmail account with 2-Step Verification and an [app password](https://myaccount.google.com/apppasswords)
- Outbound access to `smtp.gmail.com` on port 465

## Setup

### 1. Install packages

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y python3 python3-venv mysql-server git clamav
sudo mysql_secure_installation
sudo systemctl stop clamav-freshclam && sudo freshclam
sudo systemctl enable --now clamav-freshclam mysql
sudo timedatectl set-timezone America/New_York
```

### 2. Python environment

```bash
cd ~/ai-security-agent
python3 -m venv .venv
.venv/bin/pip install anthropic pymysql python-dotenv cryptography
```

### 3. Database

```bash
sudo mysql
```
```sql
CREATE DATABASE ai_security_agent;
CREATE USER 'agent_app'@'localhost' IDENTIFIED BY 'your-strong-password';
GRANT ALL PRIVILEGES ON ai_security_agent.* TO 'agent_app'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```
```bash
mysql -u agent_app -p < week2_database/populate.sql
mysql -u agent_app -p < week2_database/seed_data.sql
```

Add recipients:
```sql
INSERT INTO security_analysts (staff_name, staff_role, staff_email) VALUES ('Name', 'Security Analyst', 'analyst@example.com');
INSERT INTO managers_higher_ups (manager_name, manager_email, manager_department) VALUES ('Name', 'manager@example.com', 'Department');
```

### 4. Environment file

Create `~/ai-security-agent/.env` with no quotes around values:
```
ANTHROPIC_API_KEY=your-key
DB_USER=agent_app
DB_PASSWORD=your-strong-password
DB_NAME=ai_security_agent
REVIEWER_EMAIL=analyst@example.com
GMAIL_USER=yourname@gmail.com
GMAIL_APP_PASSWORD=16-letter-app-password
```
Then lock it down:
```bash
chmod 600 .env
```

### 5. Permissions

```bash
chmod 750 ~/ai-security-agent
chmod 750 week6_clamav_email/scheduled_scan.sh
chmod 640 week6_clamav_email/initial_scan_demo.py
sudo touch /var/log/ai-agent.log && sudo chmod 600 /var/log/ai-agent.log
```

### 6. Initial report

```bash
sudo .venv/bin/python week6_clamav_email/initial_scan_demo.py initial
```

### 7. Schedule

```bash
sudo crontab -e
```
```
0 2 * * * /home/capstone/ai-security-agent/week6_clamav_email/scheduled_scan.sh nightly
0 3 * * 0 /home/capstone/ai-security-agent/week6_clamav_email/scheduled_scan.sh weekly
```

Check a scheduled run with:
```bash
sudo tail -n 30 /var/log/ai-agent.log
```

## Security

- The API key, database password, and Gmail app password live only in `.env` (`chmod 600`), which is excluded from git.
- Usernames and MAC addresses are redacted before anything is sent to the API, and each run sends at most 60,000 characters.
- Email is sent over TLS on port 465 with Gmail's certificate verified. Recipients are BCC'd so they can't see each other.
- ClamAV details (file paths, detection names) go to security analysts only. A code-level filter strips them from the summary even if the AI includes them.
- Reports, the log, and the `reports/` folder are root-only (`600` / `700`).
- `scheduled_scan.sh` uses `umask 077` and a lock file, so new files are private and two scans never run at once.
- The prompt tells the AI never to recommend deleting data, disabling security tools, or opening ports, to always allow SSH before enabling the firewall, and to ignore virtual BIOS dates.
- Nothing is sent to managers until a human approves it.

## Testing

**Email login** (sends nothing):
```bash
.venv/bin/python - << 'EOF'
import os, smtplib, ssl
from dotenv import load_dotenv
load_dotenv(".env")
s = smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context(), timeout=15)
s.login(os.getenv("GMAIL_USER"), os.getenv("GMAIL_APP_PASSWORD"))
print("465 login ok")
s.quit()
EOF
```

**ClamAV detection:** put the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) (a harmless file every antivirus flags) in `/tmp` and run a weekly scan:
```bash
sudo .venv/bin/python week6_clamav_email/initial_scan_demo.py weekly
```
The technical report should list it, and the summary should only say the virus scan found a suspicious file.

## Adding more hosts

`week3_api_scripts/` holds the multi-host version: each host runs `collect.sh` and sends its results to this server, and `agent.py` and `approve.py` process them. It uses the `endpoints` table as an allow-list, so only listed hosts get reports.

## Troubleshooting

| Problem | Check |
|---------|-------|
| No report created | `sudo tail /var/log/ai-agent.log` |
| `No database selected` or `0 analyst(s)` | `DB_NAME` and other `DB_` values in `.env` |
| `Can't connect to local MySQL server` | `sudo systemctl status mysql`, then `sudo systemctl start mysql` |
| `Connection unexpectedly closed` on email | Outbound port 465 blocked by the router or firewall |
| Email authentication error | App password must be 16 letters, no spaces, with 2-Step Verification on |
| API error | API key in `.env`, and credit in the Claude Console |
| ClamAV missing from the report | `clamscan --version`, then `sudo freshclam` |
