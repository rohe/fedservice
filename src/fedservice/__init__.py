import json
import logging
from typing import Any
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from oidcmsg.configure import Configuration
from oidcop.endpoint_context import EndpointContext
from oidcop.exception import ConfigurationError
from oidcop.util import build_endpoints

from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.collect import branch2lists
from fedservice.entity_statement.create import create_entity_statement
from fedservice.entity_statement.policy import apply_policy
from fedservice.entity_statement.policy import combine_policy
from fedservice.entity_statement.policy import gather_policies
from fedservice.entity_statement.verify import eval_chain
from fedservice.entity_statement.verify import eval_policy_chain
from fedservice.utils import load_json

__author__ = 'Roland Hedberg'
__version__ = '3.0.0'

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


class FederationEndpointContext(EndpointContext):
    parameter = EndpointContext.parameter.copy()
    parameter.update({
        "entity_type": "",
        "opponent_entity_type": "",
        "registration_type": "",
        "default_lifetime": 0,
        "trusted_roots": {},
        "collector": Collector,
        "authority_hints": [],
        "tr_priority": [],
        "trust_marks": []
    })

    def __init__(self,
                 config: Union[dict, Configuration],
                 server_get: Callable,
                 keyjar: Optional[KeyJar] = None,
                 cwd: Optional[str] = "",
                 cookie_handler: Optional[Any] = None,
                 httpc: Optional[Any] = None,
                 entity_id: str = "",
                 trusted_roots: List[str] = None,
                 authority_hints: List[str] = None,
                 default_lifetime: int = 86400,
                 priority: List[str] = None,
                 entity_type: str = '',
                 opponent_entity_type: str = '',
                 registration_type: str = '',
                 trust_marks: List[str] = None):

        EndpointContext.__init__(self,
                                 conf=config,
                                 server_get=server_get,
                                 keyjar=keyjar,
                                 cwd=cwd,
                                 cookie_handler=cookie_handler,
                                 httpc=httpc
                                 )

        self.config = config
        self.entity_id = entity_id or config.get("entity_id")

        self.entity_type = entity_type or config.get("entity_type")
        self.opponent_entity_type = opponent_entity_type or config.get("opponent_entity_type", "")
        self.registration_type = registration_type or config.get("registration_type", "")
        self.default_lifetime = default_lifetime or config.get("default_lifetime", 0)
        self.trust_marks = trust_marks or config.get("trust_marks", [])
        self.trusted_roots = trusted_roots or json.loads(open(config["trusted_roots"]).read())

        for iss, jwks in self.trusted_roots.items():
            self.keyjar.import_jwks(jwks, iss)

        if authority_hints is not None:
            self.authority_hints = authority_hints
        elif "authority_hints" in config:
            self.authority_hints = json.loads(open(config["authority_hints"]).read())
        else:
            raise ConfigurationError("Missing authority_hints specification")

        if priority:
            self.tr_priority = priority
        elif 'priority' in config:
            self.tr_priority = config["priority"]
        else:
            self.tr_priority = sorted(set(trusted_roots.keys()))


