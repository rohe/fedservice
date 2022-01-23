cd signing_service || exit
pkill -9 -f "signing_service/sign_serv.py"
rm *.log
nohup python3 sign_serv.py conf.json > srv.log 2>&1 &
cd ..
