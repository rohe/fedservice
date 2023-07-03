import logging
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt.key_jar import KeyJar
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.configure import Configuration
from idpyoidc.client.service import init_services
from idpyoidc.client.service_context import CLI_REG_MAP
from idpyoidc.client.service_context import PROVIDER_INFO_MAP
from idpyoidc.node import ClientUnit

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_SERVICES
from fedservice.entity import FederationContext

logger = logging.getLogger(__name__)


class FederationServiceContext(FederationContext):

    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 upstream_get: Callable = None,
                 keyjar: Optional[KeyJar] = None,
                 priority: Optional[List[str]] = None,
                 trust_marks: Optional[List[str]] = None,
                 trusted_roots: Optional[dict] = None,
                 metadata: Optional[dict] = None,
                 ):

        if config is None:
            config = {}

        FederationContext.__init__(self,
                                   config=config,
                                   entity_id=entity_id,
                                   upstream_get=upstream_get,
                                   keyjar=keyjar,
                                   metadata=metadata,
                                   trust_marks=trust_marks,
                                   tr_priority=priority
                                   )

        self.trust_mark_issuer = None
        self.signed_trust_marks = []

        _key_jar = self.upstream_get("attribute", "keyjar")
        for iss, jwks in self.trusted_roots.items():
            _key_jar.import_jwks(jwks, iss)

    def _get_crypt(self, typ, attr):
        _item_typ = CLI_REG_MAP.get(typ)
        _alg = ''
        if _item_typ:
            _alg = self.claims.get_usage(_item_typ[attr])
            if not _alg:
                _alg = self.claims.get_preference(_item_typ[attr])

        _provider_info = {}
        if not _alg and _provider_info:
            _item_typ = PROVIDER_INFO_MAP.get(typ)
            if _item_typ:
                _alg = _provider_info.get(_item_typ[attr])

        return _alg

    def get_sign_alg(self, typ):
        """

        :param typ: ['id_token', 'userinfo', 'request_object']
        :return: signing algorithm
        """
        return self._get_crypt(typ, 'sign')

    def get_enc_alg_enc(self, typ):
        """

        :param typ:
        :return:
        """

        res = {}
        for attr in ["enc", "alg"]:
            res[attr] = self._get_crypt(typ, attr)

        return res

    def get_keyjar(self):
        val = getattr(self, 'keyjar', None)
        if not val:
            return self.upstream_get('attribute', 'keyjar')
        else:
            return val

    def get_client_id(self):
        return self.claims.get_usage("client_id")


class FederationClientEntity(ClientUnit):

    def __init__(
            self,
            upstream_get: Callable = None,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            metadata: Optional[dict] = None,
            trust_marks: Optional[list] = None,
            priority: Optional[list] = None
    ):
        """

        :param keyjar: A py:class:`idpyoidc.key_jar.KeyJar` instance
        :param config: Configuration information passed on to the
            :py:class:`idpyoidc.client.service_context.ServiceContext`
            initialization
        :param httpc: A HTTP client to use
        :param services: A list of service definitions
        :param jwks_uri: A jwks_uri
        :param httpc_params: HTTP request arguments
        :return: Client instance
        """

        ClientUnit.__init__(self, upstream_get=upstream_get, httpc=httpc,
                            keyjar=keyjar, httpc_params=httpc_params,
                            config=config)

        _srvs = services or DEFAULT_FEDERATION_ENTITY_SERVICES

        self.service = init_services(service_definitions=_srvs, upstream_get=self.unit_get)

        self.context = FederationServiceContext(config=config,
                                                upstream_get=self.unit_get,
                                                metadata=metadata,
                                                trust_marks=trust_marks,
                                                priority=priority)

        self.setup_client_authn_methods(config)

    def get_attribute(self, attr, *args):
        val = getattr(self, attr)
        if val:
            return val
        else:
            return self.upstream_get('attribute', attr)

    def get_service(self, service_name, *arg):
        try:
            return self.service[service_name]
        except KeyError:
            return None

    def get_service_names(self, *args):
        return set(self.service.keys())

    def get_services(self, *args):
        return self.service.values()

    def get_context(self, *args):
        return self.context

    def setup_client_authn_methods(self, config):
        if config and "client_authn_methods" in config:
            self.context.client_authn_methods = client_auth_setup(
                config.get("client_authn_methods")
            )
        else:
            self.context.client_authn_methods = {}

    def set_client_id(self, client_id):
        self.context.client_id = client_id

    def get_context_attribute(self, attr, **args):
        _val = getattr(self.context, attr)
        if not _val:
            return self.upstream_get('context_attribute', attr)
