cd flask_op || exit
rm *.log
nohup python3 server.py conf_fed.yaml > op.log 2>&1 &
cd ../flask_signing_service || exit
rm *.log
nohup python3 server.py conf.yaml > srv.log 2>&1 &
cd ..