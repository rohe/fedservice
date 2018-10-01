#!/usr/bin/env bash

./create_entity_statement.py -j feide_jwks.json -k ntnu_jwks.json -m feide_ntnu.json -i https://feide.no -s https://ntnu.no > feide_ntnu.jws
./create_entity_statement.py -j ntnu_jwks.json -k foodle_jwks.json -m ntnu_foodle.json -a ntnu_authorities.json -i https://ntnu.no -s https://foodle.uninett.no > ntnu_foodle.jws
./create_entity_statement.py -j foodle_jwks.json -k foodle_jwks.json -m foodle_foodle.json -a foodle_authorities.json -i https://foodle.uninett.no -s https://foodle.uninett.no > foodle_foodle.jws
