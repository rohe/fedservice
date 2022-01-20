cd op || exit
rm *.log
echo "OP"
nohup python3 op.py conf.json > op.log 2>&1 &
cd ../rp || exit
cd auto || exit
rm *.log
echo "AUTO"
nohup python3 rp.py conf.json > rp.log 2>&1 &
cd ../explicit || exit
rm *.log
echo "EXPLICIT"
nohup python3 rp.py conf.json > rp.log 2>&1 &
cd ../../signing_service || exit
rm *.log
echo "SIGN SERV"
nohup python3 sign_serv.py conf.json > srv.log 2>&1 &
cd ..