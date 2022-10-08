import logging

from idpyoidc.server import build_endpoints

# from fedservice.entity_statement.collect import Collector
# from fedservice.entity_statement.collect import tree2chains
# from fedservice.entity_statement.create import create_entity_statement
# from fedservice.entity_statement.policy import apply_policy
# from fedservice.entity_statement.policy import combine_policy
# from fedservice.entity_statement.policy import gather_policies
# from fedservice.utils import load_json

__author__ = 'Roland Hedberg'
__version__ = '3.2.0'

logger = logging.getLogger(__name__)


def do_endpoints(conf, server_get):
    endpoints = build_endpoints(conf["endpoint"], server_get=server_get, issuer=conf["entity_id"])

    _cap = conf.get("capabilities", {})

    for endpoint, endpoint_instance in endpoints.items():
        if endpoint_instance.endpoint_info:
            for key, val in endpoint_instance.endpoint_info.items():
                if key not in _cap:
                    _cap[key] = val

    return endpoints
