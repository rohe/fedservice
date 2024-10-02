# The TA
./entity.py trust_anchor &
./get_info.py -k -t https://127.0.0.1:7003 > trust_anchor.json
sleep 2

# The OP

./entity.py op &
./add_info.py -s trust_anchor.json -t op/trust_anchors
echo "https://127.0.0.1:7003" >> op/authority_hints

./get_info.py -k -s https://127.0.0.1:4004 > tmp.json
sleep 2
./add_info.py -s tmp.json -t trust_anchor/subordinates

# The RP

./entity.py rp_explicit &
./add_info.py -s trust_anchor.json -t rp_explicit/trust_anchors
echo "https://127.0.0.1:7003" >> rp_explicit/authority_hints

./get_info.py -k -s https://127.0.0.1:4002 > tmp.json
sleep 2
./add_info.py -s tmp.json -t trust_anchor/subordinates
