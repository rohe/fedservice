#!/bin/zsh

./entity.py swamid entities/https%3A%2F%2F127.0.0.1%3A7001.json -v ta_views &>swamid.log &
./entity.py seid entities/https%3A%2F%2F127.0.0.1%3A7002.json -v ta_views &> seid.log &