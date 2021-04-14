#!/usr/bin/env python3

import sys, json, yaml

with open(sys.argv[1]) as f:
    print(yaml.safe_dump(json.load(f), default_flow_style=False))