cd flask_signing_service || exit
pkill -9 -f "flask_signing_service/server.py"
rm *.log
nohup python3 server.py conf.yaml > srv.log 2>&1 &
cd ..
