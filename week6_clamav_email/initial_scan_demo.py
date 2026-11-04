import glob
import os
import re
import smtplib
import ssl
import subprocess
import sys
import time
from datetime import datetime
from email.message import EmailMessage

import anthropic
import pymysql
from dotenv import load_dotenv

project = "/home/capstone/ai-security-agent"
load_dotenv(os.path.join(project, ".env"))

model = "claude-haiku-4-5-20251001"
max_chars = 60000
report_dir = os.path.join(project, "reports")
marker = "===MANAGER SUMMARY==="
report_types = ("initial", "nightly", "weekly")

clamav = "clamscan -r -i --max-filesize=50M --max-scansize=100M /home /root /tmp /var/tmp"

system_prompt = f"""You are a security analyst writing a security report about one Linux server for a small business.
The report type is initial, nightly, or weekly. You will get raw command output: system info, pending updates,
failed logins, failed services, listening ports, firewall status, and a ClamAV malware scan.

Write TWO reports, separated by a line containing exactly {marker}

PART 1 is the technical report for the security analysts, in markdown with exactly these sections:
## Summary
3 to 5 sentences.
## Risk Level
One word (Low, Medium, High, or Critical) and one sentence explaining why.
## Findings
Each finding with what it is, why it matters, and the evidence from the data.
## Malware Scan (ClamAV)
Files scanned, infected files found, and each infected file with its detection name. Say clearly if nothing was found.
If the scan was skipped because this is a nightly report, say that in one line.
## Recommended Actions
Numbered, most important first, with the exact commands when there are any.
## Notes for Reviewer
Anything you are unsure about that a human should double check.

PART 2 is the summary for managers and employees with no technical background, under 200 words:
- One sentence with the overall risk level in plain English.
- 3 to 5 bullet points of the most important issues, in plain words.
- One sentence on what the security team is doing next.
- One plain-English sentence on the virus scan result, like "A virus scan found no harmful files" or "A virus scan found 2 suspicious files that the security team is reviewing." Do not name ClamAV, file paths, or detection names. Those details go to the security analysts only. If the scan was skipped on a nightly report, leave this sentence out.
No commands, file paths, IP addresses, port numbers, package versions, or jargon in PART 2.

Rules for both parts:
- Only report what is in the data. If a section is empty or shows nothing wrong, say so. Never guess or invent findings.
- This server is a virtual machine. Firmware or BIOS dates from QEMU, SeaBIOS, or another hypervisor are placeholders
  set by the virtualization software, not real firmware age. Do not report them as outdated firmware.
- When recommending firewall commands, always allow SSH before enabling the firewall so the admin is not locked out,
  in this order: ufw allow OpenSSH, ufw default deny incoming, ufw default allow outgoing, ufw enable.
- Never recommend commands that delete data, disable security tools, or open new ports.
- If ClamAV found infected files, recommend quarantining them for review, not deleting them.
- If ClamAV is not installed or the scan failed, say so in Notes for Reviewer.
- Values like [user] and [mac] were redacted on purpose. Do not try to guess them."""


def get_checks(report_type):
    # weekly looks back 7 days, the rest look back 24 hours
    since = "7 days ago" if report_type == "weekly" else "24 hours ago"
    return {
        "system": "hostnamectl",
        "upgradable packages": "apt list --upgradable 2>/dev/null",
        f"failed logins (since {since})": f"journalctl -u ssh --since '{since}' --no-pager | grep -iE 'failed|invalid' | tail -n 50",
        "failed services": "systemctl --failed --no-pager",
        "listening ports": "ss -tulnp",
        "firewall": "ufw status verbose",
        # clamav is slow so nightly skips it
        "malware scan (clamav)": "echo 'skipped on nightly reports, runs on initial and weekly'" if report_type == "nightly" else clamav,
    }


def run_checks(report_type):
    output = f"=== report type: {report_type} ===\n"
    for name, command in get_checks(report_type).items():
        print(f"checking {name}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=1800)
        output += f"=== {name} ===\n{result.stdout}{result.stderr}\n"
    return output


def get_users():
    # real login users from passwd
    users = []
    with open("/etc/passwd") as f:
        for line in f:
            parts = line.split(":")
            if len(parts) > 2 and parts[2].isdigit() and 1000 <= int(parts[2]) < 65534:
                users.append(parts[0])
    return users


def redact(text):
    text = re.sub(r"\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b", "[mac]", text, flags=re.I)
    text = re.sub(r"/home/[^/\s:]+", "/home/[user]", text)
    text = re.sub(r"(for (?:invalid user )?)(\S+)(?= from)", lambda m: m.group(0) if m.group(2) == "root" else m.group(1) + "[user]", text)
    for user in get_users():
        text = re.sub(rf"\b{re.escape(user)}\b", "[user]", text)
    return text


def scrub_summary(summary):
    # plain english scan result is fine, technical clamav details stay with analysts
    keep = []
    for line in summary.splitlines():
        if re.search(r"clamav|clamscan", line, re.I):
            continue
        if re.search(r"(^|\s)/\S+", line) or re.search(r"\b[A-Z][a-z]+\.[A-Z][A-Za-z]+\.\S+", line):
            continue
        keep.append(line)
    return "\n".join(keep).strip()


def split_report(text):
    # part 1 for analysts, part 2 for everyone
    if marker not in text:
        return text.strip(), None
    technical, summary = text.split(marker, 1)
    return technical.strip(), scrub_summary(summary)


def get_emails(query):
    try:
        db = pymysql.connect(
            unix_socket="/var/run/mysqld/mysqld.sock",
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
        )
        with db.cursor() as cur:
            cur.execute(query)
            emails = [row[0] for row in cur.fetchall()]
        db.close()
        return emails
    except pymysql.MySQLError as e:
        print(f"database error: {e}")
        return []


def save_file(name, text):
    os.makedirs(report_dir, mode=0o700, exist_ok=True)
    os.chmod(report_dir, 0o700)
    path = os.path.join(report_dir, f"{name}_{datetime.now():%Y%m%d_%H%M}.md")
    # only the owner can read it
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


def send_email(subject, body, recipients):
    user = os.getenv("GMAIL_USER")
    password = os.getenv("GMAIL_APP_PASSWORD")
    if not user or not password:
        print("no gmail settings in .env, skipping email")
        return False
    if not recipients:
        print(f"no recipients for '{subject}', skipping")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = user
    # bcc so recipients cant see each other
    msg["Bcc"] = ", ".join(recipients)
    msg.set_content(body)

    # encrypted from the start, certificate checked
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=30) as smtp:
            smtp.login(user, password)
            smtp.send_message(msg)
        print(f"sent '{subject}' to {len(recipients)} recipient(s)")
        return True
    except (smtplib.SMTPException, OSError) as e:
        print(f"email failed, report is still saved: {e}")
        return False


def get_everyone():
    analysts = get_emails("SELECT staff_email FROM security_analysts")
    managers = get_emails("SELECT manager_email FROM managers_higher_ups")
    return sorted(set(analysts + managers))


def send_summary(path):
    # report type is in the file name
    report_type = os.path.basename(path).split("_")[2]
    with open(path) as f:
        summary = f.read()
    sent = send_email(f"{report_type.capitalize()} Security Summary - {datetime.now():%B %d, %Y}", summary, get_everyone())
    if sent:
        os.rename(path, path.replace("pending_summary_", "sent_summary_"))
    return sent


def review_pending():
    # analyst approves summaries the cron jobs made
    pending = sorted(glob.glob(os.path.join(report_dir, "pending_summary_*.md")))
    if not pending:
        print("no summaries waiting for review")
        return
    for path in pending:
        with open(path) as f:
            print(f"\n===== {os.path.basename(path)} =====\n\n{f.read()}")
        answer = input("\nsend to everyone? (y = send, n = reject, s = skip): ").strip().lower()
        if answer == "y":
            send_summary(path)
        elif answer == "n":
            os.rename(path, path.replace("pending_summary_", "rejected_summary_"))
            print("rejected")


def main():
    if os.geteuid() != 0:
        print("run with sudo so it can read the logs")
        return

    mode = sys.argv[1] if len(sys.argv) > 1 else "initial"
    interactive = sys.stdin.isatty()

    if mode == "send-summary":
        if not interactive:
            print("send-summary needs a person at the keyboard")
            return
        review_pending()
        return
    if mode not in report_types:
        print("usage: initial_scan_demo.py [initial|nightly|weekly|send-summary]")
        return
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("no ANTHROPIC_API_KEY in .env")
        return

    print(f"starting {mode} scan at {datetime.now():%Y-%m-%d %H:%M}\n")
    scan = redact(run_checks(mode))[:max_chars]

    print("\nsending to claude...")
    start = time.time()
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    try:
        response = client.messages.create(
            model=model,
            max_tokens=3500,
            system=system_prompt,
            messages=[{"role": "user", "content": scan}],
        )
    except anthropic.APIError as e:
        print(f"api error: {e}")
        return
    print(f"got report in {time.time() - start:.1f} seconds\n")

    technical, summary = split_report(response.content[0].text)
    date = f"{datetime.now():%B %d, %Y}"

    print("===== TECHNICAL REPORT (analysts) =====\n")
    print(technical)
    print(f"\nsaved to {save_file(f'technical_report_{mode}', technical)}")

    pending = None
    if summary:
        print("\n===== SUMMARY (everyone) =====\n")
        print(summary)
        pending = save_file(f"pending_summary_{mode}", summary)
        print(f"\nsaved to {pending}")
    else:
        print("\nno summary came back, only the analysts will get an email")

    analysts = get_emails("SELECT staff_email FROM security_analysts")
    subject = f"[Security Analysts] {mode.capitalize()} Technical Security Report - {date}"

    if not interactive:
        # cron run, analysts review the technical report themselves
        send_email(subject, technical, analysts)
        if pending:
            print("summary is waiting for an analyst to approve it with send-summary")
        return

    # human in the loop, nothing goes out without a yes
    if input(f"\nemail the technical report to {len(analysts)} analyst(s)? (y/n): ").strip().lower() == "y":
        send_email(subject, technical, analysts)
    if pending and input("email the summary to all analysts and managers? (y/n): ").strip().lower() == "y":
        send_summary(pending)


if __name__ == "__main__":
    main()
