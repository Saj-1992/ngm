#!/bin/sh
# Arms a one-shot SIGKILL of ngm-helper at an exact point inside nginx.activate.
# Anchored full-cmdline match (pgrep -f "^...$") so this script never matches itself.
# $1 = test | reload
case "$1" in
  test) pat='(/usr/sbin/)?nginx -t' ;;
  reload) pat='/usr/bin/systemctl reload nginx.service' ;;
  *) echo "usage: killpoint.sh test|reload"; exit 2 ;;
esac
i=0
while [ $i -lt 300000 ]; do
  if pgrep -f "^$pat$" >/dev/null; then
    systemctl kill -s KILL ngm-helper
    echo "$(date +%T.%N) killed ngm-helper during: $pat" >> /tmp/killpoint.log
    exit 0
  fi
  i=$((i + 1))
done
echo "$(date +%T.%N) point never reached: $pat" >> /tmp/killpoint.log
