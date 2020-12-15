cd flask_rp || exit
rm *.log
nohup python3 local_rp.py conf_fed.yaml > expl.log 2>&1 &
nohup python3 local_rp.py conf_fed_auto.yaml > auto.log 2>&1 &
cd ../flask_op || exit
rm *.log
nohup python3 local_op.py conf_fed.yaml > op.log 2>&1 &
cd ../flask_signing_service || exit
rm *.log
nohup python3 local_sigsrv.py conf.yaml > srv.log 2>&1 &
cd ..