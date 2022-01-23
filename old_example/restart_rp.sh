#!/bin/zsh
cd openid_relying_party || exit
pkill -9 -f "rp.py"
cd auto || exit
rm *.log
sleep 1
nohup python3 rp.py conf.json > expl.log 2>&1 &
cd ../explicit
nohup python3 rp.py conf_fed_auto.yaml > auto.log 2>&1 &
cd ..
