#!/bin/zsh
cd flask_op || exit
pkill -9 -f "flask_op/server.py"
rm *.log
nohup python3 server.py conf_fed.yaml >op.log 2>&1 &
cd ..
