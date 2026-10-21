import glob
import os
import re
import shutil
from datetime import datetime

import anthropic
import pymysql
from dotenv import load_dotenv

project = "/home/capstone/ai-security-agent"
load_dotenv(os.path.join(project, ".env"))

incoming = os.path.join(project, "incoming")
processed = os.path.join(project, "processed")
rejected = os.path.join(project, "rejected")
report_dir = os.path.join(project, "reports")

model = "claude-haiku-4-5-20251001"
max_chars = 60000
redact_ips = False

schedules = {
    "initial": "manual",
    "nightly": "30 1 * * *",
    "weekly": "0 1 * * 0",
}

system_prompt = """You are a security analyst writing a report about one Linux host for a small business.
You will get raw output from the host: pending updates, failed logins, sudo usage, failed services,
open ports, network interfaces, firewall rules, and on weekly reports a ClamAV malware scan.

Write the report in markdown with exactly these sections:
## Host: <hostname>
### Summary
3 to 5 sentences in plain English for a manager with no technical background.
### Risk Level
One word (Low, Medium, High, or Critical) and one sentence explaining why.
### Findings
Each finding with what it is, why it matters, and the evidence from the data.
### Recommended Actions
Numbered, most important first, with the exact command to fix it when there is one.
### Notes for Reviewer
Anything you are unsure about that a human should double check.

Only report what is in the data. If a section of the data is empty, say nothing was found.
Do not guess or invent findings. ClamAV showing "skipped, weekly only" is normal.
Values like [user], [mac], and [ip] were redacted on purpose."""


def keep_root(match):
    if match.group(2) == "root":
        return match.group(0)
    return match.group(1) + "[user]"


def redact(text):
    text = re.sub(r"\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b", "[mac]", text, flags=re.I)
    text = re.sub(r"/home/[^/\s:]+", "/home/[user]", text)
    text = re.sub(r"(for (?:invalid user )?)(\S+)(?= from)", keep_root, text)
    text = re.sub(r"(USER=|[Uu]ser )(\S+)", keep_root, text)
    text = re.sub(r"(sudo(?:\[\d+\])?:\s+)(\S+)(?=\s+:)", keep_root, text)
    if redact_ips:
        text = re.sub(r"\b(?!0\.0\.0\.0\b)(?!127\.)\d{1,3}(\.\d{1,3}){3}\b", "[ip]", text)
    return text


def get_db():
    return pymysql.connect(
        unix_socket="/var/run/mysqld/mysqld.sock",
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        autocommit=True,
    )


def get_endpoint(cur, hostname):
    cur.execute("SELECT endpoint_id FROM endpoints WHERE hostname = %s", (hostname,))
    row = cur.fetchone()
    return row[0] if row else None


def get_script_id(cur, endpoint_id, report_type):
    cur.execute(
        "SELECT script_id FROM scripts WHERE endpoint_id = %s AND script_type = %s",
        (endpoint_id, report_type),
    )
    row = cur.fetchone()
    if row:
        return row[0]
    # first time this host sends this type
    cur.execute(
        "INSERT INTO scripts (endpoint_id, script_name, script_type, schedule) VALUES (%s, %s, %s, %s)",
        (endpoint_id, "collect.sh", report_type, schedules[report_type]),
    )
    return cur.lastrowid


def ask_claude(hostname, report_type, scan_text):
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model=model,
        max_tokens=2000,
        system=system_prompt,
        messages=[{"role": "user", "content": f"host: {hostname}\nreport type: {report_type}\n\n{scan_text}"}],
    )
    return response.content[0].text


def main():
    for folder in (processed, rejected, report_dir):
        os.makedirs(folder, mode=0o700, exist_ok=True)

    files = sorted(glob.glob(os.path.join(incoming, "scan_*.txt")))
    if not files:
        print(f"{datetime.now()} nothing in incoming")
        return

    db = get_db()
    cur = db.cursor()

    for path in files:
        name = os.path.basename(path)
        match = re.match(r"scan_(initial|nightly|weekly)_(.+)_(\d{8}_\d{6})\.txt$", name)
        if not match:
            print(f"{datetime.now()} bad file name {name}")
            shutil.move(path, os.path.join(rejected, name))
            continue

        report_type, hostname = match.group(1), match.group(2)

        # only hosts in the endpoints table get scanned
        endpoint_id = get_endpoint(cur, hostname)
        if endpoint_id is None:
            print(f"{datetime.now()} {hostname} not in endpoints, rejected")
            shutil.move(path, os.path.join(rejected, name))
            continue

        script_id = get_script_id(cur, endpoint_id, report_type)

        with open(path) as f:
            scan_text = redact(f.read())[:max_chars]

        now = datetime.now()
        try:
            report = ask_claude(hostname, report_type, scan_text)
            status = "success"
        except anthropic.APIError as e:
            report = None
            status = "failed"
            print(f"{now} api error on {hostname}: {e}")

        cur.execute(
            "INSERT INTO anthropic_api (script_id, requested_at, api_status) VALUES (%s, %s, %s)",
            (script_id, now, status),
        )
        request_id = cur.lastrowid

        # leave it in incoming so it retries next run
        if report is None:
            continue

        cur.execute(
            "INSERT INTO email_reporting (request_id, report_type, generated_at, email_status) "
            "VALUES (%s, %s, %s, %s)",
            (request_id, report_type, now, "pending_review"),
        )
        report_id = cur.lastrowid

        report_file = os.path.join(report_dir, f"report_{report_id}_{report_type}_{hostname}_{now:%Y%m%d_%H%M}.md")
        with open(report_file, "w") as f:
            f.write(report)
        os.chmod(report_file, 0o600)

        shutil.move(path, os.path.join(processed, name))
        print(f"{now} saved {report_file}")

    db.close()


if __name__ == "__main__":
    main()
