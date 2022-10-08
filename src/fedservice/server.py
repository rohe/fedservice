import json
import logging
import os

from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt import KeyJar
from idpyoidc.configure import Configuration
from idpyoidc.context import OidcContext
from idpyoidc.impexp import ImpExp
from idpyoidc.server import build_endpoints
from idpyoidc.server import client_auth_setup
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server import init_service

logger = logging.getLogger(__name__)


class Collection(object):
    def __init__(self, conf):
        self._db = {}
        for id, spec in conf.items():
            self._db[id] = init_service(spec)

    def add(self, id: str, tminfo: dict):
        self._db[id].add(tminfo)

    def find(self, id: str, sub: str, iat: Optional[int] = 0) -> bool:
        return self._db[id].find(sub, iat)


class FileDB(object):
    def __init__(self, **kwargs):
        self.config = kwargs
        for id, file_name in self.config.items():
            if not os.path.exists(file_name):
                # Only need to touch it
                fp = open(file_name, "w")
                fp.close()

    def add(self, id, tm_info):
        # adds a line with info about a trust mark info to the end of a file
        with open(self.config[id], "a") as fp:
            fp.write(json.dumps(tm_info) + '\n')

    def _match(self, id, sub, iat, tmi):
        if id == tmi["id"]:
            if sub == tmi["sub"]:
                if iat:
                    if iat == tmi['iat']:
                        return True
                else:
                    return True
        return False

    def find(self, id: str, sub: str, iat: Optional[int] = 0):
        with open(self.config[id], "r") as fp:
            for line in reversed(list(fp)):
                _tmi = json.loads(line.rstrip())
                if self._match(id, sub, iat, _tmi):
                    return True
        return False

    def __contains__(self, item):
        return item in self.config


class SimpleDB(object):
    def __init__(self, ids):
        self._db = {id: {} for id in ids}

    def add(self, id, tm_info):
        self._db[id][tm_info["sub"]] = tm_info

    def find(self, id, sub: str, iat: Optional[int] = 0) -> bool:
        _tmi = self._db[id].get(sub)
        if _tmi:
            if iat:
                if iat == _tmi["iat"]:
                    return True
            else:
                return True

        return False


class Server(ImpExp):
    parameter = {"endpoint": [Endpoint], "endpoint_context": EndpointContext}

    def __init__(
            self,
            superior_get: Callable,
            config: Optional[Union[dict, Configuration]] = None,
            keyjar: Optional[KeyJar] = None,
            entity_id: Optional[str] = "",
            endpoint: Optional[dict] = None,
            context: Optional[OidcContext] = None
    ):
        ImpExp.__init__(self)
        if config is None:
            config = {}

        self.superior_get = superior_get

        self.conf = config
        self.entity_id = entity_id or superior_get("context").entity_id

        if context:
            self.endpoint_context = context
        else:
            self.endpoint_context = OidcContext(keyjar=keyjar, config=config,
                                                entity_id=self.entity_id)

        if endpoint is None:
            endpoint = config.get("endpoint")

        self.endpoint = build_endpoints(endpoint, server_get=self.server_get, issuer=self.entity_id)

        # self.endpoint_context.do_add_on(endpoints=self.endpoint)

        self.setup_client_authn_methods()
        for endpoint_name, _ in self.endpoint.items():
            self.endpoint[endpoint_name].server_get = self.server_get

    def server_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
        if _func:
            return _func(*arg)
        return None

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_context(self, *arg):
        return self.endpoint_context

    def get_entity(self, *args):
        return self

    def get_attribute(self, attr, *args):
        val = getattr(self, attr)
        if val:
            return val
        else:
            return self.superior_get('attribute', attr)

    def setup_client_authn_methods(self):
        self.endpoint_context.client_authn_method = client_auth_setup(
            self.server_get, self.conf.get("client_authn_methods")
        )

# class Server(server.Server):
#     def __init__(self,
#                  conf: Union[dict, FedOpConfiguration],
#                  keyjar: Optional[KeyJar] = None,
#                  cwd: Optional[str] = "",
#                  cookie_handler: Optional[Any] = None,
#                  httpc: Optional[Any] = None
#                  ):
#         server.Server.__init__(self, conf=conf, keyjar=keyjar, cwd=cwd,
#                                cookie_handler=cookie_handler, httpc=httpc)
#
#         fed_conf = conf["federation"]
#         federation_entity = FederationEntity(httpc=httpc, config=fed_conf)
#
#         self.server_get("context").federation_entity = federation_entity
