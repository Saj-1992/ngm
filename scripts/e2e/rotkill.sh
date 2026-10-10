#!/bin/sh
# Interrupt `ngm vault rotate` with SIGKILL at a chosen point, by PID (no pattern match).
# $1 = point: "keyfile" (right after the new key file appears) or "rewrap" (after the staged row exists)
NGM=/opt/ngm/current/ngm
cur=$($NGM vault status | sed -n 's/active KEK version: //p')
next=$((cur + 1))
$NGM vault rotate >/tmp/rot.log 2>&1 &
pid=$!
i=0
while [ $i -lt 2000 ]; do
  if [ "$1" = "keyfile" ] && [ -f /etc/ngm/keys/kek-$next.key ]; then break; fi
  if [ "$1" = "rewrap" ] && $NGM vault status 2>/dev/null | grep -q "v$next  staged"; then break; fi
  i=$((i + 1)); sleep 0.002
done
kill -9 $pid 2>/dev/null && echo "killed pid $pid at point=$1 (next=v$next)" || echo "rotate already finished before kill"
sleep 1
echo "--- state after kill"
$NGM vault status
ls /etc/ngm/keys
systemctl is-active ngm-api ngm-ops ngm-monitor | tr '\n' ' '; echo
echo "--- resume"
$NGM vault rotate; echo "exit=$?"
sleep 2
$NGM vault status
systemctl is-active ngm-api ngm-ops ngm-monitor | tr '\n' ' '; echo
$NGM doctor | grep -i vault
