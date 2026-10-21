#!/bin/bash
# collects security info and sends it to the agent vm

type=${1:-nightly}
agent_host=192.168.30.194
agent_user=capstone
agent_dir=/home/capstone/ai-security-agent/incoming

state=/var/lib/ai-agent
mkdir -p $state/scans
chmod 700 $state

# look back to the last scan of this type
if [ -f $state/last_scan_$type ]; then
    since=$(cat $state/last_scan_$type)
else
    since=$(date -d "7 days ago" "+%Y-%m-%d %H:%M:%S")
fi
now=$(date "+%Y-%m-%d %H:%M:%S")

host=$(hostname)
out=$state/scans/scan_${type}_${host}_$(date +%Y%m%d_%H%M%S).txt

has() {
    command -v $1 > /dev/null 2>&1
}

{
echo "=== host: $host ==="
echo "=== report type: $type ==="
echo "=== window: $since to $now ==="

echo "=== system ==="
if has hostnamectl; then
    hostnamectl
else
    uname -a
    cat /etc/issue
fi

echo "=== upgradable packages ==="
apt-get update -qq > /dev/null 2>&1
if has apt; then
    apt list --upgradable 2>/dev/null
else
    apt-get -s upgrade | grep "^Inst"
fi

echo "=== failed logins ==="
if has journalctl; then
    journalctl -u ssh -u sshd --since "$since" --no-pager 2>/dev/null | grep -iE "failed|invalid" | tail -n 50
else
    grep -iE "failed|invalid" /var/log/auth.log | tail -n 50
fi

echo "=== sudo usage ==="
if has journalctl; then
    journalctl _COMM=sudo --since "$since" --no-pager 2>/dev/null | tail -n 50
else
    grep sudo /var/log/auth.log | tail -n 50
fi

echo "=== failed services ==="
if has systemctl; then
    systemctl --failed --no-pager
fi

echo "=== listening ports ==="
if has ss; then
    ss -tulnp
else
    netstat -tulnp
fi

echo "=== interfaces ==="
ip -brief a 2>/dev/null || ip a 2>/dev/null || ifconfig

echo "=== firewall ==="
if has ufw; then
    ufw status verbose
else
    iptables -S
fi

echo "=== clamav ==="
if [ "$type" = "weekly" ]; then
    if has clamscan; then
        clamscan -r -i --max-filesize=50M --max-scansize=100M /home /root /tmp /var/tmp /opt /srv /etc
    else
        echo "clamav not installed"
    fi
else
    echo "skipped, weekly only"
fi
} > $out 2>&1

chmod 600 $out

# agent vm copies locally, other hosts use scp
if hostname -I 2>/dev/null | grep -qw "$agent_host"; then
    cp $out $agent_dir/
else
    scp -q -o BatchMode=yes $out $agent_user@$agent_host:$agent_dir/
fi

if [ $? -eq 0 ]; then
    echo "$now" > $state/last_scan_$type
    echo "sent $out"
else
    echo "send failed, kept $out"
    exit 1
fi
