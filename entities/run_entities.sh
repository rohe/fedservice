cd flask_rp || exit
rm *.log
nohup python3 server.py conf_fed.yaml > expl.log 2>&1 &
nohup python3 server.py conf_fed_auto.yaml > auto.log 2>&1 &
cd ../flask_op || exit
rm *.log
nohup python3 server.py conf.yaml > op.log 2>&1 &
cd ../flask_signing_service || exit
rm *.log
nohup python3 srv.py cnf.yaml > srv.log 2>&1 &
cd ..