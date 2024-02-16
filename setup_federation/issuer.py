#!/usr/bin/env python3
import json
import sys

from idpyoidc.util import load_config_file

if __name__ == "__main__":
    dir_name = sys.argv[1]

    cnf = load_config_file(f"{dir_name}/conf.json")
    _ids = list(cnf["entity"]["entity_type"]["trust_mark_entity"]["kwargs"]["trust_mark_specification"].keys())

    print(json.dumps({cnf["entity"]["entity_id"]: _ids}))