#!/usr/bin/env bash
# Trust Anchor
./entity.py trust_anchor &
sleep 2

./get_info.py -k -t https://127.0.0.1:7003 > trust_anchor.json

# Trust Mark Issuer
./add_info.py -s trust_anchor.json -t trust_mark_issuer/trust_anchors
rm -r trust_mark_issuer/authority_hints
echo -e "https://127.0.0.1:7003" >> trust_mark_issuer/authority_hints

./entity.py trust_mark_issuer &
sleep 2

./get_info.py -k -s https://127.0.0.1:6000 > tmp.json
./add_info.py -s tmp.json -t trust_anchor/subordinates
./issuer.py trust_mark_issuer > tmp.json
./add_info.py -s tmp.json -t trust_anchor/trust_mark_issuers

# Wallet Provider
./add_info.py -s trust_anchor.json -t wallet_provider/trust_anchors
rm -r wallet_provider/authority_hints
echo -e "https://127.0.0.1:7003" >> wallet_provider/authority_hints

./entity.py wallet_provider &
sleep 2

./get_info.py -k -s https://127.0.0.1:5001 > tmp.json
./add_info.py -s tmp.json -t trust_anchor/subordinates

# Query Server
./add_info.py -s trust_anchor.json -t query_server/trust_anchors
rm -r query_server/authority_hints
echo -e "https://127.0.0.1:7003" >> query_server/authority_hints

./entity.py query_server &
sleep 2

./get_info.py -k -s https://127.0.0.1:6005 > tmp.json
./add_info.py -s tmp.json -t trust_anchor/subordinates

# PID Issuer
./add_info.py -s trust_anchor.json -t pid_issuer/trust_anchors
rm -r pid_issuer/authority_hints
echo -e "https://127.0.0.1:7003" >> pid_issuer/authority_hints

./entity.py pid_issuer &
sleep 2

./get_info.py -k -s https://127.0.0.1:6001 > tmp.json
./add_info.py -s tmp.json -t trust_anchor/subordinates



