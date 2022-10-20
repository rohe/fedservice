import json
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt.utils import importer
from idpyoidc.configure import Configuration
from idpyoidc.impexp import ImpExp

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
        "signed_trust_marks": [],
        "trust_marks": []
    })

    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 upstream_get: Callable = None,
                 default_lifetime: Optional[int] = 86400,
                 metadata: Optional[dict] = None,
                 tr_priority: Optional[list] = None,
                 **kwargs
                 ):
        ImpExp.__init__(self)

        if config is None:
            config = {}

        self.config = config
        self.upstream_get = upstream_get
        self.entity_id = entity_id or config.get("entity_id")
        self.default_lifetime = default_lifetime or config.get("default_lifetime", 0)
        self.tr_priority = tr_priority or config.get("trust_root_priority", [])

        if metadata:
            _hints = metadata.get("authority_hints")
            if _hints is None:
                self.authority_hints = []
            elif isinstance(_hints, str):
                self.authority_hints = json.loads(open(_hints).read())
            else:
                self.authority_hints = _hints
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

        return create_entity_statement(iss, sub, key_jar=key_jar, metadata=metadata,
                                       metadata_policy=metadata_policy,
                                       authority_hints=authority_hints, lifetime=lifetime, **kwargs)


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
                 upstream_get: Callable = None,
                 metadata: Optional[dict] = None,
                 trust_marks: Optional[List[str]] = None,
                 ):
        FederationContext.__init__(self,
                                   config=config,
                                   entity_id=entity_id,
                                   upstream_get=upstream_get,
                                   metadata=metadata
                                   )
        if metadata is None:
            metadata = {}

        self.metadata = {k: v for k, v in metadata.items() if k != 'authority_hints'}

        _sstm = config.get("self_signed_trust_marks")
        _keyjar = upstream_get('attribute', "keyjar")
        if _sstm:
            self.signed_trust_marks = create_self_signed_trust_marks(entity_id=self.entity_id,
                                                                     keyjar=_keyjar,
                                                                     spec=_sstm)

        self.trust_marks = trust_marks

    def make_configuration_statement(self):
        _metadata = self.upstream_get("metadata")
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
