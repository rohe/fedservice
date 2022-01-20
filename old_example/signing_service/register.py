#!/usr/bin/env python3
import os
import sys
from urllib.parse import quote_plus

from cryptojwt.key_jar import init_key_jar
from fedservice.configure import DEFAULT_FED_FILE_ATTRIBUTE_NAMES
from oidcmsg.configure import Configuration
from oidcmsg.configure import create_from_config_file

from fedservice.configure import FedEntityConfiguration
from fedservice.configure import FedOpConfiguration
from fedservice.configure import FedRPConfiguration

dir_path = os.path.dirname(os.path.realpath(__file__))

CNF_MAP = {
    "openid_provider": FedOpConfiguration,
    "openid_relying_party": FedRPConfiguration,
    "federation_entity": FedEntityConfiguration
}

ATTR_MAP = {
    "openid_provider": "op",
    "openid_relying_party": "rp"
}


def get_subject_conf(entity_type, id):
    if entity_type in ["openid_provider", "openid_relying_party"]:
        head, tail = os.path.split(dir_path)
        _path = os.path.join(head, entity_type, id)
        e_cnf = {
            "class": CNF_MAP[entity_type],
            "attr": ATTR_MAP[entity_type]
        }
        if entity_type == "openid_provider":
            e_cnf["path"] = ["op", "server_info"]

        _conf = create_from_config_file(Configuration,
                                        entity_conf=[e_cnf],
                                        filename=os.path.join(_path, "conf.json"),
                                        base_path=_path)
        ent_conf = _conf[ATTR_MAP[entity_type]]

        keys_args = {k: v for k, v in ent_conf["federation"]["keys"].items() if k != "uri_path"}
        _keyjar = init_key_jar(**keys_args)

        _entity_id = ent_conf["federation"].get("entity_id")
        if _entity_id.endswith("/{}"):  # allow tenant ID
            _entity_id = _entity_id[:-3]
        d_path = os.path.join("authorities", i_am, entity_type, quote_plus(_entity_id))
        if os.path.isdir(d_path):
            pass
        else:
            os.makedirs(d_path)
        file_path = os.path.join(d_path, "jwks.json")
        return file_path, _keyjar
    else:
        _path = os.path.join(dir_path, entity_type, id)
        _conf = create_from_config_file(FedEntityConfiguration,
                                        filename=os.path.join(_path, "conf.json"),
                                        file_attributes=DEFAULT_FED_FILE_ATTRIBUTE_NAMES,
                                        base_path=_path)
        keys_args = {k: v for k, v in _conf["keys"].items() if k != "uri_path"}
        _keyjar = init_key_jar(**keys_args)
        d_path = os.path.join("authorities", i_am, id)
        if os.path.isdir(d_path):
            pass
        else:
            os.makedirs(d_path)
        file_path = os.path.join(d_path, "jwks.json")

        return file_path, _keyjar


if __name__ == "__main__":
    i_am = sys.argv[1]
    entity_type = sys.argv[2]
    _id = sys.argv[3]

    print(f"registering '{_id}' of type '{entity_type}' to superior: '{i_am}'")
    file_path, _keyjar = get_subject_conf(entity_type, _id)

    print(file_path)
    # what do I need to register ?
    # entity_id/-s and jwks

    with open(file_path, "w") as fp:
        fp.write(_keyjar.export_jwks_as_json())
