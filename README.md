# Automated and Integrated AI Security Agent

**Author:** Mitchell Sheiry
**Course:** CYBR 498, Dr. Almalag
**Platform:** Ubuntu 26.04 LTS, on-prem homelab (Proxmox)

The AI security agent collects security information from Linux hosts and uses the Anthropic API to turn it into easy-to-read reports. A human reviews every report before it's emailed to managers. The goal is to save security analysts time and help non-technical stakeholders understand their risk.

## How it works

1. `collect.sh` runs on each host (by cron) and gathers:
   - pending updates
   - failed logins and sudo usage since the last scan
   - failed services
   - listening ports, network interfaces, and firewall rules
   - a ClamAV malware scan (weekly only)
2. Each host sends its results to the capstone VM's `incoming/` folder with `scp`.
3. `agent.py` checks each file against the `endpoints` table, redacts usernames and MAC addresses, and sends it to Claude. It then saves one report per host and logs everything in MySQL.
4. `approve.py` is the human-in-the-loop step. The reviewer reads each report, approves or rejects it, can choose to install security updates on approved hosts, and emails the approved reports to managers.

| Report  | When                        | ClamAV |
|---------|-----------------------------|--------|
| initial | once, by hand at deployment | no     |
| nightly | every day, 2:00 AM          | no     |
| weekly  | Sunday, 3:00 AM             | yes    |

## Project structure

```
ai-security-agent/
├── .env                     # api key and db credentials (not in git)
├── .venv/                   # python virtual environment (not in git)
├── week2_database/
│   ├── populate.sql         # creates the tables
│   └── seed_data.sql        # adds the capstone vm as the first endpoint
├── week3_api_scripts/
│   ├── collect.sh           # runs on every host
│   ├── agent.py             # sends scans to claude and saves reports
│   ├── approve.py           # human review, updates, and email
│   └── run.sh               # cron entry point on the capstone vm
├── incoming/                # scans waiting to be processed
├── processed/               # scans already turned into reports
├── rejected/                # scans from hosts not in the endpoints table
└── reports/                 # generated markdown reports
```

## Requirements

- Ubuntu 26.04 LTS ([download](https://ubuntu.com/download/server)), 2 vCPU and 4 GB RAM recommended (ClamAV needs ~1.5 GB)
- Python 3, MySQL Server, ClamAV
- An Anthropic API key from the [Claude Console](https://console.anthropic.com)
- A Gmail account with an app password (for email)

## Setup

### 1. Install packages

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y python3 python3-venv mysql-server git clamav unzip
sudo mysql_secure_installation
sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam
```

### 2. Python environment

```bash
cd ~/ai-security-agent
python3 -m venv .venv
source .venv/bin/activate
pip install anthropic pymysql python-dotenv
```

### 3. Database

```bash
sudo mysql
```
```sql
CREATE DATABASE ai_security_agent;
CREATE USER 'agent_app'@'localhost' IDENTIFIED BY 'your-password';
GRANT ALL PRIVILEGES ON ai_security_agent.* TO 'agent_app'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```
```bash
mysql -u agent_app -p < week2_database/populate.sql
mysql -u agent_app -p < week2_database/seed_data.sql
```

### 4. Environment file

Create `~/ai-security-agent/.env`:
```
ANTHROPIC_API_KEY=your-key
DB_USER=agent_app
DB_PASSWORD=your-password
DB_NAME=ai_security_agent
REVIEWER_EMAIL=your-email-in-security_analysts
GMAIL_USER=
GMAIL_APP_PASSWORD=
```
Then lock it down:
```bash
chmod 600 .env
```

### 5. Folders

```bash
mkdir -p incoming processed rejected reports
chmod 700 incoming processed rejected reports
chmod +x week3_api_scripts/*.sh
```

### 6. Initial report

```bash
sudo ~/ai-security-agent/week3_api_scripts/run.sh initial
sudo tail -n 20 /var/log/ai-agent.log
```

### 7. Schedule

```bash
sudo crontab -e
```
```
0 2 * * * /home/capstone/ai-security-agent/week3_api_scripts/run.sh nightly
0 3 * * 0 /home/capstone/ai-security-agent/week3_api_scripts/run.sh weekly
```

## Reviewing reports

```bash
sudo ~/ai-security-agent/.venv/bin/python ~/ai-security-agent/week3_api_scripts/approve.py
```

Each report moves through these statuses: `pending_review` → `approved` / `rejected` → `sent`.

## Adding a host

1. Add it to the database. The hostname must match what `hostname` prints on that machine:
   ```sql
   INSERT INTO endpoints (ip_address, hostname, os_version) VALUES ('192.168.x.x', 'hostname', 'Ubuntu 24.04');
   ```
2. On the new host, install the script and create a key:
   ```bash
   sudo mkdir -p /opt/ai-agent
   sudo cp collect.sh /opt/ai-agent/ && sudo chmod 700 /opt/ai-agent/collect.sh
   sudo apt install -y clamav
   sudo ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ""
   ```
3. Add the host's public key to `~/.ssh/authorized_keys` on the capstone VM, with `restrict ` in front of it so the key can only copy files.
4. Run the initial scan on the host, then schedule it:
   ```bash
   sudo /opt/ai-agent/collect.sh initial
   sudo crontab -e
   ```
   ```
   30 1 * * * /opt/ai-agent/collect.sh nightly
   0 1 * * 0 /opt/ai-agent/collect.sh weekly
   ```
5. Optional: to let `approve.py` install updates, create an `aiagent` user on the host with SSH key access. Its only sudo permission should be `/usr/bin/unattended-upgrade`.

## Security

- The API key and database password live only in `.env` (`chmod 600`), which is excluded from git.
- Usernames and MAC addresses are redacted before anything is sent to the API. IP redaction can be turned on with `redact_ips = True` in `agent.py`.
- Raw scans and reports are root-only (`chmod 600`).
- Only hosts in the `endpoints` table get reports. Anything else goes to `rejected/`.
- Each run sends at most 60,000 characters per host to the API, to keep costs predictable.
- Nothing changes on a host unless a reviewer approves it in `approve.py`.

## Testing

To test whether ClamAV findings make it into the report, put the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) (a harmless file every antivirus flags as malware) in `/tmp` and run a weekly scan:
```bash
sudo ~/ai-security-agent/week3_api_scripts/run.sh weekly
```
The report should flag it.

## Troubleshooting

| Problem | Check |
|---------|-------|
| No report created | `sudo tail /var/log/ai-agent.log` |
| Host's scan lands in `rejected/` | Its hostname isn't in the `endpoints` table |
| `send failed` on a host | SSH key isn't in the capstone VM's `authorized_keys` |
| API error | API key in `.env`, and credit in the Claude Console |
| Database error | `DB_` values in `.env`, and `sudo systemctl status mysql` |
