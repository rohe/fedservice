from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.configure import Base
from idpyoidc.server import ASConfiguration
from idpyoidc.server import Endpoint
from idpyoidc.server import EndpointContext
from idpyoidc.server import OPConfiguration
from idpyoidc.server import allow_refresh_token
from idpyoidc.server import authz
from idpyoidc.server import build_endpoints
from idpyoidc.server import client_auth_setup
from idpyoidc.server import create_session_manager
from idpyoidc.server import get_provider_capabilities
from idpyoidc.server import init_service
from idpyoidc.server import init_user_info
from idpyoidc.server import populate_authn_broker

from fedservice.server import ServerUnit


def do_endpoints(conf, upstream_get):
    _endpoints = conf.get("endpoint")
    if _endpoints:
        return build_endpoints(_endpoints, upstream_get=upstream_get, issuer=conf["issuer"])
    else:
        return {}


class ServerEntity(ServerUnit):
    name = 'openid-provider'
    parameter = {"endpoint": [Endpoint], "endpoint_context": EndpointContext}

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
            key_conf: Optional[dict] = None
    ):
        ServerUnit.__init__(self, upstream_get=upstream_get, keyjar=keyjar, httpc=httpc,
                            httpc_params=httpc_params, entity_id=entity_id, key_conf=key_conf)
        if config is None:
            config = {}

        if not isinstance(config, Base):
            config['issuer'] = entity_id
            config['base_url'] = entity_id
            config = OPConfiguration(config)

        self.config = config
        self.endpoint_context = EndpointContext(
            conf=config,
            upstream_get=self.server_get,
            keyjar=keyjar,
            cwd=cwd,
            cookie_handler=cookie_handler,
            httpc=httpc,
        )
        self.endpoint_context.authz = self.setup_authz()

        self.setup_authentication(self.endpoint_context)

        self.endpoint = do_endpoints(config, self.server_get)
        _cap = get_provider_capabilities(config, self.endpoint)

        self.endpoint_context.provider_info = self.endpoint_context.create_providerinfo(_cap)
        self.endpoint_context.do_add_on(endpoints=self.endpoint)

        self.endpoint_context.session_manager = create_session_manager(
            self.server_get,
            self.endpoint_context.th_args,
            sub_func=self.endpoint_context._sub_func,
            conf=config,
        )
        self.endpoint_context.do_userinfo()
        # Must be done after userinfo
        self.setup_login_hint_lookup()
        self.endpoint_context.set_remember_token()

        self.setup_client_authn_methods()
        for endpoint_name, _ in self.endpoint.items():
            self.endpoint[endpoint_name].upstream_get = self.unit_get

        _token_endp = self.endpoint.get("token")
        if _token_endp:
            _token_endp.allow_refresh = allow_refresh_token(self.endpoint_context)

        self.endpoint_context.claims_interface = init_service(
            config["claims_interface"], self.upstream_get
        )

        _id_token_handler = self.endpoint_context.session_manager.token_handler.handler.get(
            "id_token"
        )
        if _id_token_handler:
            self.endpoint_context.provider_info.update(_id_token_handler.provider_info)

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

    def get_server(self, *args):
        return self

    def get_metadata(self, *args):
        return {'openid_provider': self.endpoint_context.provider_info}

    def setup_authz(self):
        authz_spec = self.config.get("authz")
        if authz_spec:
            return init_service(authz_spec, self.server_get)
        else:
            return authz.Implicit(self.server_get)

    def setup_authentication(self, target):
        _conf = self.config.get("authentication")
        if _conf:
            target.authn_broker = populate_authn_broker(
                _conf, self.server_get, target.template_handler
            )
        else:
            target.authn_broker = {}

        target.endpoint_to_authn_method = {}
        for method in target.authn_broker:
            try:
                target.endpoint_to_authn_method[method.action] = method
            except AttributeError:
                pass

    def setup_login_hint_lookup(self):
        _conf = self.config.get("login_hint_lookup")
        if _conf:
            _userinfo = None
            _kwargs = _conf.get("kwargs")
            if _kwargs:
                _userinfo_conf = _kwargs.get("userinfo")
                if _userinfo_conf:
                    _userinfo = init_user_info(_userinfo_conf, self.endpoint_context.cwd)

            if _userinfo is None:
                _userinfo = self.endpoint_context.userinfo

            self.endpoint_context.login_hint_lookup = init_service(_conf)
            self.endpoint_context.login_hint_lookup.userinfo = _userinfo

    def setup_client_authn_methods(self):
        self.endpoint_context.client_authn_method = client_auth_setup(
            self.server_get, self.config.get("client_authn_methods")
        )
