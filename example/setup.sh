#!/usr/bin/env bash

./set_trust_anchor.py RPA SEID SWAMID
./set_trust_anchor.py RPE SEID SWAMID
./set_trust_anchor.py OP SEID SWAMID
./set_trust_anchor.py LU SEID SWAMID
./set_trust_anchor.py UMU SEID SWAMID

./add_subordinate.py -s RPA LU
./add_subordinate.py -s RPE LU
./add_subordinate.py -s OP UMU
./add_subordinate.py -s UMU SEID
./add_subordinate.py -s UMU SWAMID
./add_subordinate.py -s LU SEID
./add_subordinate.py -s LU SWAMID
