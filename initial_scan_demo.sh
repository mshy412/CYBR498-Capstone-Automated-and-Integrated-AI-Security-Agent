#!/bin/bash
# runs the initial scan demo once

project=/home/capstone/ai-security-agent
log=$project/initial_demo.log
done_file=$project/.initial_done

# only run the first time
if [ -f $done_file ]; then
    echo "initial scan already ran, delete $done_file to run again"
    exit 0
fi

# wait for network on boot
sleep 30

echo "$(date) updating package list" >> $log
apt-get update -qq >> $log 2>&1

echo "$(date) running initial scan" >> $log
$project/.venv/bin/python $project/initial_scan_demo.py >> $log 2>&1

if [ $? -eq 0 ]; then
    touch $done_file
    echo "$(date) done" >> $log
else
    echo "$(date) failed, will try again next boot" >> $log
fi
