#!/usr/bin/env python3
import json
import os
import sys
from urllib.parse import quote_plus

from cryptojwt.key_jar import init_key_jar
from fedservice.configure import FedSigServConfiguration

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


def get_subject_info(ta):
    _path = os.path.join(dir_path, "signing_service", "federation_entity", ta)
    _conf = create_from_config_file(FedEntityConfiguration,
                                    filename=os.path.join(_path, "conf.json"),
                                    file_attributes=DEFAULT_FED_FILE_ATTRIBUTE_NAMES,
                                    base_path=_path)
    keys_args = {k: v for k, v in _conf["keys"].items() if k != "uri_path"}
    _keyjar = init_key_jar(**keys_args)

    return _keyjar


if __name__ == "__main__":
    config_file = "signing_service/conf.json"

    _config = create_from_config_file(Configuration,
                                      entity_conf=[{
                                          'class': FedSigServConfiguration,
                                          'attr': 'sigsrv'
                                      }],
                                      filename=config_file)

    _pattern = _config.sigsrv.server_info["kwargs"]["entity_id_pattern"]

    res = {}
    for ta in sys.argv[1:]:
        _keyjar = get_subject_info(ta)
        entity_id = _pattern.format(ta)
        res[entity_id] = _keyjar.export_jwks()

    print(json.dumps(res, indent=2, sort_keys=True))