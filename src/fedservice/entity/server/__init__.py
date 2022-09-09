# Server specific defaults and a basic Server class
import json
import logging
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.utils import importer
from idpyoidc.configure import Configuration
from idpyoidc.impexp import ImpExp
from idpyoidc.server.client_authn import client_auth_setup
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.endpoint import Endpoint
from idpyoidc.server.endpoint_context import EndpointContext
from idpyoidc.server.util import build_endpoints

from fedservice.entity import FederationContext
from fedservice.entity_statement.create import create_entity_statement

logger = logging.getLogger(__name__)


def create_self_signed_trust_marks(spec, **kwargs):
    if isinstance(spec["function"], str):
        _func = importer(spec["function"])
    else:
        _func = spec["function"]

    res = []
    for id, content in spec["kwargs"].items():
        _args = kwargs.copy()
        _args.update(content)
        res.append(_func(id=id, sub=id, **_args))
    return res


class FederationServerContext(FederationContext):
    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 entity_get: Callable = None,
                 keyjar: Optional[KeyJar] = None,
                 authority_hints: Optional[Union[List[str], str]] = None,
                 default_lifetime: Optional[int] = 86400,
                 trust_marks: Optional[List[str]] = None
                 ):
        FederationContext.__init__(self,
                                   config=config,
                                   entity_id=entity_id,
                                   entity_get=entity_get,
                                   keyjar=keyjar)

        self.default_lifetime = default_lifetime or config.get("default_lifetime", 0)

        if authority_hints is not None:
            self.authority_hints = authority_hints
        else:
            _hints = config.get("authority_hints")
            if _hints is None:
                self.authority_hints = []
            elif isinstance(_hints, str):
                self.authority_hints = json.loads(open(_hints).read())
            else:
                self.authority_hints = _hints

        _sstm = config.get("self_signed_trust_marks")
        if _sstm:
            self.signed_trust_marks = create_self_signed_trust_marks(entity_id=self.entity_id,
                                                                     keyjar=self.keyjar,
                                                                     spec=_sstm)

        self.trust_marks = trust_marks

    def create_entity_statement(self, iss, sub, key_jar=None, metadata=None, metadata_policy=None,
                                authority_hints=None, lifetime=0, jwks=None, **kwargs):
        if jwks:
            kwargs["jwks"] = jwks
        else:
            if "keys" in kwargs:
                kwargs["jwks"] = {'keys': kwargs["keys"]}
                del kwargs["keys"]

        key_jar = key_jar or self.keyjar

        if not authority_hints:
            authority_hints = self.authority_hints
        if not lifetime:
            lifetime = self.default_lifetime

        return create_entity_statement(iss, sub, key_jar=key_jar, metadata=metadata,
                                       metadata_policy=metadata_policy,
                                       authority_hints=authority_hints, lifetime=lifetime, **kwargs)

    def make_configuration_statement(self):
        _metadata = self.entity_get("metadata")
        kwargs = {}
        if self.authority_hints:
            kwargs["authority_hints"] = self.authority_hints
        if self.trust_marks:
            kwargs["trust_marks"] = self.trust_marks
        if self.signed_trust_marks:
            if "trust_marks" in kwargs:
                kwargs["trust_marks"].extend(self.signed_trust_marks)
            else:
                kwargs["trust_marks"] = self.signed_trust_marks

        return self.create_entity_statement(iss=self.entity_id, sub=self.entity_id,
                                            metadata=_metadata, **kwargs)


class FederationEntityServer(ImpExp):
    parameter = {"endpoint": [Endpoint], "endpoint_context": EndpointContext}

    def __init__(
            self,
            config: Optional[Union[dict, OPConfiguration, ASConfiguration]] = None,
            keyjar: Optional[KeyJar] = None,
            entity_id: Optional[str] = "",
            endpoint: Optional[dict] = None,
    ):
        ImpExp.__init__(self)
        if config is None:
            config = {}

        self.conf = config
        if not entity_id:
            entity_id = config.get("entity_id")

        self.endpoint_context = FederationServerContext(
            config=config,
            entity_get=self.entity_get,
            keyjar=keyjar,
            entity_id=entity_id
        )

        self.endpoint = build_endpoints(endpoint, entity_get=entity_get, issuer=entity_id)

        # self.endpoint_context.do_add_on(endpoints=self.endpoint)

        self.setup_client_authn_methods()
        for endpoint_name, _ in self.endpoint.items():
            self.endpoint[endpoint_name].server_get = self.entity_get

    def entity_get(self, what, *arg):
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

    def get_endpoint_context(self, *arg):
        return self.endpoint_context

    def setup_client_authn_methods(self):
        self.endpoint_context.client_authn_method = client_auth_setup(
            self.entity_get, self.conf.get("client_authn_methods")
        )
