import os
import re
import subprocess
import time
from datetime import datetime

import anthropic
from dotenv import load_dotenv

project = "/home/capstone/ai-security-agent"
load_dotenv(os.path.join(project, ".env"))

model = "claude-haiku-4-5-20251001"

checks = {
    "system": "hostnamectl",
    "upgradable packages": "apt list --upgradable 2>/dev/null",
    "failed logins (24h)": "journalctl -u ssh --since '24 hours ago' --no-pager | grep -iE 'failed|invalid' | tail -n 30",
    "failed services": "systemctl --failed --no-pager",
    "listening ports": "ss -tulnp",
    "firewall": "ufw status verbose",
}

system_prompt = """You are a security analyst writing an initial security report for a small business.
Write it in markdown with these sections: Summary (plain English for a manager),
Risk Level (Low, Medium, High, or Critical), Findings, Recommended Actions (with commands),
and Notes for Reviewer. Only report what is in the data and do not invent findings.
Values like [user] and [mac] were redacted on purpose."""


def run_checks():
    output = ""
    for name, command in checks.items():
        print(f"checking {name}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output += f"=== {name} ===\n{result.stdout}{result.stderr}\n"
    return output


def redact(text):
    text = re.sub(r"\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b", "[mac]", text, flags=re.I)
    text = re.sub(r"(for (?:invalid user )?)(\S+)(?= from)", r"\1[user]", text)
    return text


def main():
    if os.geteuid() != 0:
        print("run with sudo so it can read the logs")
        return

    print("starting initial scan\n")
    scan = redact(run_checks())

    print("\nsending to claude...")
    start = time.time()
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model=model,
        max_tokens=2000,
        system=system_prompt,
        messages=[{"role": "user", "content": scan}],
    )
    report = response.content[0].text
    print(f"got report in {time.time() - start:.1f} seconds\n")

    print(report)

    report_file = os.path.join(project, f"initial_demo_{datetime.now():%Y%m%d_%H%M}.md")
    with open(report_file, "w") as f:
        f.write(report)
    print(f"\nsaved to {report_file}")


if __name__ == "__main__":
    main()
