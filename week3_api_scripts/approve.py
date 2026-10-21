import glob
import os
import smtplib
import subprocess
from datetime import datetime
from email.message import EmailMessage

import pymysql
from dotenv import load_dotenv

project = "/home/capstone/ai-security-agent"
load_dotenv(os.path.join(project, ".env"))
report_dir = os.path.join(project, "reports")


def get_db():
    return pymysql.connect(
        unix_socket="/var/run/mysqld/mysqld.sock",
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        autocommit=True,
    )


def get_reviewer(cur):
    cur.execute("SELECT staff_id FROM security_analysts WHERE staff_email = %s", (os.getenv("REVIEWER_EMAIL"),))
    row = cur.fetchone()
    if row is None:
        raise SystemExit("REVIEWER_EMAIL in .env is not in security_analysts")
    return row[0]


def list_pending(cur):
    cur.execute(
        "SELECT r.report_id, r.report_type, r.generated_at, e.hostname, e.ip_address "
        "FROM email_reporting r "
        "JOIN anthropic_api a ON r.request_id = a.request_id "
        "JOIN scripts s ON a.script_id = s.script_id "
        "JOIN endpoints e ON s.endpoint_id = e.endpoint_id "
        "WHERE r.email_status = 'pending_review' "
        "ORDER BY r.report_id"
    )
    return cur.fetchall()


def find_report_file(report_id):
    files = glob.glob(os.path.join(report_dir, f"report_{report_id}_*.md"))
    return files[0] if files else None


def set_status(cur, report_id, status, reviewer):
    cur.execute(
        "UPDATE email_reporting SET email_status = %s, reviewed_by = %s WHERE report_id = %s",
        (status, reviewer, report_id),
    )


def patch_host(hostname, ip):
    print(f"installing security updates on {hostname}...")
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", f"aiagent@{ip}", "sudo unattended-upgrade -v"],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if result.returncode == 0:
        print(f"{hostname} updated")
    else:
        print(f"{hostname} failed: {result.stderr.strip()}")


def send_email(cur, approved):
    gmail_user = os.getenv("GMAIL_USER")
    gmail_pass = os.getenv("GMAIL_APP_PASSWORD")
    if not gmail_user or not gmail_pass:
        print("no gmail settings in .env, skipping email")
        return

    cur.execute("SELECT manager_id, manager_email FROM managers_higher_ups")
    managers = cur.fetchall()
    if not managers:
        print("no managers in the database, skipping email")
        return

    msg = EmailMessage()
    msg["Subject"] = f"Security Report - {datetime.now():%B %d, %Y}"
    msg["From"] = gmail_user
    msg["To"] = ", ".join(email for _, email in managers)
    msg.set_content("\n\n---\n\n".join(r["text"] for r in approved))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(gmail_user, gmail_pass)
        smtp.send_message(msg)

    for r in approved:
        for manager_id, _ in managers:
            cur.execute(
                "INSERT INTO report_recipients (report_id, manager_id) VALUES (%s, %s)",
                (r["id"], manager_id),
            )
        cur.execute("UPDATE email_reporting SET email_status = 'sent' WHERE report_id = %s", (r["id"],))

    print(f"emailed {len(approved)} report(s) to {len(managers)} manager(s)")


def main():
    db = get_db()
    cur = db.cursor()

    pending = list_pending(cur)
    if not pending:
        print("no reports waiting for review")
        return

    reviewer = get_reviewer(cur)
    approved = []

    for report_id, report_type, generated_at, hostname, ip in pending:
        path = find_report_file(report_id)
        if path is None:
            print(f"report {report_id} file missing, skipping")
            continue

        print(f"\nreport {report_id} | {hostname} | {report_type} | {generated_at}")
        input("press enter to read it (q to close)...")
        subprocess.run(["less", path])

        answer = input("approve? (y = yes, n = reject, s = skip, q = quit): ").strip().lower()
        if answer == "q":
            break
        if answer == "y":
            set_status(cur, report_id, "approved", reviewer)
            with open(path) as f:
                approved.append({"id": report_id, "host": hostname, "ip": ip, "text": f.read()})
        elif answer == "n":
            set_status(cur, report_id, "rejected", reviewer)

    if not approved:
        print("nothing approved")
        db.close()
        return

    # one entry per host
    hosts = {r["host"]: r["ip"] for r in approved}
    answer = input(f"\ninstall security updates on {', '.join(hosts)}? (y/n): ").strip().lower()
    if answer == "y":
        for hostname, ip in hosts.items():
            patch_host(hostname, ip)

    send_email(cur, approved)
    db.close()


if __name__ == "__main__":
    main()
