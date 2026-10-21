#!/bin/bash
# runs the local scan then the agent

type=${1:-nightly}
project=/home/capstone/ai-security-agent
log=/var/log/ai-agent.log

echo "$(date) starting $type" >> $log
$project/week3_api_scripts/collect.sh $type >> $log 2>&1
$project/.venv/bin/python $project/week3_api_scripts/agent.py >> $log 2>&1
echo "$(date) done $type" >> $log
