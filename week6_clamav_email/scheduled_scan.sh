#!/bin/bash
# runs the scan from cron

type=${1:-nightly}
project=/home/capstone/ai-security-agent
log=/var/log/ai-agent.log

# new files only readable by root
umask 077

# dont let two scans run at once
exec 9>/var/lock/ai-agent.lock
if ! flock -n 9; then
    echo "$(date) $type skipped, another scan is running" >> $log
    exit 0
fi

echo "$(date) starting $type" >> $log
$project/.venv/bin/python $project/week6_clamav_email/initial_scan_demo.py $type >> $log 2>&1 < /dev/null
echo "$(date) done $type" >> $log
