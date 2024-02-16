import json
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.configure import Configuration
from idpyoidc.impexp import ImpExp

from fedservice.entity.claims import FederationEntityClaims
from fedservice.entity_statement.create import create_entity_statement


def entity_type(metadata):
    # assuming there is only one type apart from federation_entity and trust_mark_issuer
    return set(metadata.keys()).difference({'federation_entity', 'trust_mark_issuer'}).pop()


class FederationContext(ImpExp):
    parameter = ImpExp.parameter.copy()
    parameter.update({
        "default_lifetime": 0,
        "authority_hints": [],
        "tr_priority": [],
        "trust_mark_issuer": None,
        "trust_mark_owners": None,
        "signed_trust_marks": [],
        "trust_marks": [],
    })

    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 upstream_get: Callable = None,
                 default_lifetime: Optional[int] = 86400,
                 priority: Optional[list] = None,
                 trust_marks: Optional[list] = None,
                 trusted_roots: Optional[dict] = None,
                 authority_hints: Optional[list] = None,
                 keyjar: Optional[KeyJar] = None,
                 preference: Optional[dict] = None,
                 **kwargs
                 ):

        ImpExp.__init__(self)

        if config is None:
            config = {}

        self.config = config
        self.upstream_get = upstream_get
        self.entity_id = entity_id or config.get("entity_id",
                                                 self.upstream_get("attribute", "entity_id"))
        self.default_lifetime = default_lifetime or config.get("default_lifetime", 0)
        self.trust_marks = trust_marks or config.get('trust_marks')
        # self.issuer = self.entity_id

        self.claims = FederationEntityClaims(prefer=preference)

        if trusted_roots:
            _trusted_roots = trusted_roots
        else:
            _trusted_roots = config.get("trusted_roots")

        if _trusted_roots is None:
            # Must be trust anchor then
            self.trusted_roots = {}
        elif isinstance(_trusted_roots, str):
            self.trusted_roots = json.loads(open(_trusted_roots).read())
        else:
            self.trusted_roots = _trusted_roots

        if priority:
            self.tr_priority = priority
        elif 'priority' in config:
            self.tr_priority = config["priority"]
        else:
            self.tr_priority = sorted(set(self.trusted_roots.keys()))

        if authority_hints:
            if isinstance(authority_hints, str):  # Allow it to be a file name
                self.authority_hints = json.loads(open(authority_hints).read())
            else:
                self.authority_hints = authority_hints
        else:
            self.authority_hints = []

        for param, default in self.parameter.items():
            _val = kwargs.get(param)
            if _val is not None:
                setattr(self, param, _val)
            else:
                try:
                    getattr(self, param)
                except AttributeError:
                    setattr(self, param, default)

        if preference:
            config['preference'] = preference
        _keyjar = self.claims.load_conf(config, supports=self.supports(), keyjar=keyjar)

        if self.upstream_get:
            _unit = self.upstream_get('unit')
            _unit.keyjar = _keyjar
        else:
            self.keyjar = _keyjar

        self.setup_client_authn_methods()

        # For backward compatibility
        self.kid = {"sig": {}, "enc": {}}

    def supports(self):
        res = {}
        if self.upstream_get:
            _services = self.upstream_get('services')
            if _services:
                for service in _services:
                    res.update(service.supports())

            _endpoints = self.upstream_get('endpoints')
            if _endpoints:
                for name, endp in _endpoints.items():
                    res.update(endp.supports())

        res.update(self.claims.supports())
        return res

    def setup_client_authn_methods(self):
        self.client_authn_methods = client_auth_setup(self.config.get("client_authn_methods"))

    def create_entity_statement(self, iss, sub, key_jar=None, metadata=None, metadata_policy=None,
                                authority_hints=None, lifetime=0, jwks=None, **kwargs):
        if jwks:
            kwargs["jwks"] = jwks
        else:
            if "keys" in kwargs:
                kwargs["jwks"] = {'keys': kwargs["keys"]}
                del kwargs["keys"]

        key_jar = key_jar or self.upstream_get("attribute", "keyjar")

        if not authority_hints:
            authority_hints = self.authority_hints
        if not lifetime:
            lifetime = self.default_lifetime

        if self.trust_marks:
            kwargs["trust_marks"] = self.trust_marks

        return create_entity_statement(iss, sub, key_jar=key_jar, metadata=metadata,
                                       metadata_policy=metadata_policy,
                                       authority_hints=authority_hints, lifetime=lifetime, **kwargs)


class FederationServerContext(FederationContext):

    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 upstream_get: Callable = None,
                 preference: Optional[dict] = None,
                 trust_marks: Optional[List[str]] = None,
                 authority_hints: Optional[list] = None,
                 ):
        FederationContext.__init__(self,
                                   config=config,
                                   entity_id=entity_id,
                                   upstream_get=upstream_get,
                                   preference=preference,
                                   authority_hints=authority_hints,
                                   )

        _sstm = config.get("self_signed_trust_marks")
        if _sstm:
            _keyjar = upstream_get('attribute', "keyjar")
            self.signed_trust_marks = self.create_entity_statement(iss=self.entity_id,
                                                                   sub=self.entity_id,
                                                                   keyjar=_keyjar,
                                                                   trust_marks=_sstm)

        self.trust_marks = trust_marks
        self.jti_db = {}
