#!/usr/bin/env bash
./register.py feide.no federation_entity lu.se
./register.py feide.no federation_entity umu.se
./register.py swamid.se federation_entity lu.se
./register.py swamid.se federation_entity umu.se
./register.py lu.se openid_relying_party auto
./register.py lu.se openid_relying_party explicit
./register.py umu.se openid_provider umu
