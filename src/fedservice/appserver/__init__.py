import logging
from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.utils import importer
from idpyoidc.configure import Base
from idpyoidc.node import topmost_unit
from idpyoidc.server import ASConfiguration
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server import OPConfiguration
from idpyoidc.server import allow_refresh_token
from idpyoidc.server import authz
from idpyoidc.server import build_endpoints
from idpyoidc.server.endpoint_context import init_service
from idpyoidc.server.user_authn.authn_context import populate_authn_broker
from idpyoidc.server.util import execute

from fedservice.entity.claims import OPClaims
from fedservice.server import ServerUnit

logger = logging.getLogger(__name__)


def do_endpoints(conf, upstream_get):
    _endpoints = conf.get("endpoint")
    if _endpoints:
        return build_endpoints(_endpoints, upstream_get=upstream_get, issuer=conf["issuer"])
    else:
        return {}


class ServerEntity(ServerUnit):
    name = 'openid_provider'
    parameter = {"endpoint": [Endpoint], "context": EndpointContext}

    def __init__(
            self,
            config: Optional[Union[dict, OPConfiguration, ASConfiguration]] = None,
            upstream_get: Optional[Callable] = None,
            keyjar: Optional[KeyJar] = None,
            cwd: Optional[str] = "",
            cookie_handler: Optional[Any] = None,
            httpc: Optional[Any] = None,
            httpc_params: Optional[dict] = None,
            entity_id: Optional[str] = "",
            key_conf: Optional[dict] = None,
            server_type: Optional[str] = "",
            entity_type: Optional[str] = ''
    ):
        if config is None:
            config = {}

        self.server_type = server_type or config.get("server_type", "")
        if not self.server_type:
            if entity_type == "oauth_authorization_server":
                self.server_type = "oauth2"
            elif entity_type == "openid_provider":
                self.server_type = "oidc"

        if self.server_type == "oauth2":
            self.name = "oauth_authorization_server"

        ServerUnit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                            httpc_params=httpc_params, entity_id=entity_id, key_conf=key_conf,
                            config=config)

        if not isinstance(config, Base):
            config['issuer'] = entity_id
            config['base_url'] = entity_id
            if self.server_type == "oauth2":
                config = ASConfiguration(config)
            else:
                config = OPConfiguration(config)

        if self.server_type == "oidc" and not isinstance(config, OPConfiguration):
            raise ValueError("Server type and configuration type does not match")
        elif self.server_type == "oauth2" and not isinstance(config, ASConfiguration):
            raise ValueError("Server type and configuration type does not match")

        self.config = config

        self.endpoint = do_endpoints(config, self.unit_get)

        self.context = EndpointContext(
            conf=config,
            upstream_get=self.unit_get,
            cwd=cwd,
            cookie_handler=cookie_handler,
            httpc=httpc,
            claims_class=OPClaims(),
            keyjar=self.keyjar
        )

        _token_endp = self.endpoint.get("token")
        if _token_endp:
            _token_endp.allow_refresh = allow_refresh_token(self.context)

        self.context.claims_interface = init_service(
            config["claims_interface"], self.unit_get
        )

        _per_conf = config.get("persistence", None)
        if _per_conf:
            _storage = execute(_per_conf["kwargs"]["storage"])
            _class = _per_conf["class"]
            kwargs = {"storage": _storage, "upstream_get": self.unit_get}
            if isinstance(_class, str):
                self.persistence = importer(_class)(**kwargs)
            else:
                self.persistence = _per_conf["class"](**kwargs)

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_context(self, *arg):
        return self.context

    def get_server(self, *args):
        return self

    def get_metadata(self, entity_type="", *args):
        if not entity_type:
            entity_type = self.name
        _claims = self.get_context().claims
        metadata = _claims.get_server_metadata(endpoint=self.endpoint.values())
        # remove these from the metadata
        for item in ["jwks", "jwks_uri", "signed_jwks_uri"]:
            try:
                del metadata[item]
            except KeyError:
                pass
        # collect endpoints
        return {entity_type: metadata}

    def pick_guise(self, entity_type: Optional[str] = "", *args):
        if not entity_type:
            entity_type = self.name
        _root = topmost_unit(self)
        _guise = _root.get(entity_type, None)
        if _guise is None:
            logger.error(f"Could not find guise '{entity_type}'")
            logger.info(f"Available guises: {list(_root.keys())}")
        return _guise

    def get_guise(self):
        return self.name

    def setup_authz(self):
        authz_spec = self.config.get("authz")
        if authz_spec:
            return init_service(authz_spec, self.unit_get)
        else:
            return authz.Implicit(self.unit_get)

    def setup_authentication(self, target):
        _conf = self.config.get("authentication")
        if _conf:
            target.authn_broker = populate_authn_broker(
                _conf, self.unit_get, target.template_handler
            )
        else:
            target.authn_broker = {}

        target.endpoint_to_authn_method = {}
        for method in target.authn_broker:
            try:
                target.endpoint_to_authn_method[method.action] = method
            except AttributeError:
                pass
