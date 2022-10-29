import json
import os
from typing import Callable
from typing import Optional

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.server import init_service

from fedservice.entity import FederationEntity


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

    def __init__(self):
        self._db = {}

    def add(self, id, tm_info):
        if id in self._db:
            self._db[id][tm_info["sub"]] = tm_info
        else:
            self._db[id] = {tm_info["sub"]: tm_info}

    def find(self, id, sub: str, iat: Optional[int] = 0) -> bool:
        _tmi = self._db[id].get(sub)
        if _tmi:
            if iat:
                if iat == _tmi["iat"]:
                    return True
            else:
                return True

        return False

    def keys(self):
        return self._db.keys()

    def __getitem__(self, item):
        return self._db[item]


def create_trust_mark(keyjar, entity_id, **kwargs):
    packer = JWT(key_jar=keyjar, iss=entity_id)
    return packer.pack(payload=kwargs)


class TrustMarkIssuer(FederationEntity):
    name = 'trust_mark_issuer'

    def __init__(self,
                 upstream_get: Optional[Callable] = None,
                 entity_id: str = "",
                 keyjar: Optional[KeyJar] = None,
                 key_conf: Optional[dict] = None,
                 client: Optional[dict] = None,
                 server: Optional[dict] = None,
                 function: Optional[dict] = None,
                 httpc: Optional[object] = None,
                 httpc_params: Optional[dict] = None,
                 metadata: Optional[dict] = None,
                 trust_marks: Optional[dict] = None,
                 trust_mark_db: Optional[object] = None,
                 authority_hints: Optional[list] = None,
                 **kwargs
                 ):

        FederationEntity.__init__(
            self,
            upstream_get=upstream_get,
            entity_id=entity_id,
            keyjar=keyjar,
            key_conf=key_conf,
            client=client,
            server=server,
            function=function,
            httpc=httpc,
            httpc_params=httpc_params,
            metadata=metadata,
            authority_hints=authority_hints
        )

        if upstream_get:  # Not to have keys on my own if there is a superior
            self.keyjar = None

        self.trust_marks = trust_marks or {}

        self.tm_lifetime = {}
        for id, tm in self.trust_marks.items():
            if "lifetime" in tm:
                self.tm_lifetime[id] = tm["lifetime"]
                del tm["lifetime"]

        if trust_mark_db:
            self.issued = init_service(trust_mark_db)
        else:
            self.issued = SimpleDB()

    def create_trust_mark(self, id, sub):
        _now = utc_time_sans_frac()
        _add = {'iat': _now, 'id': id, 'sub': sub}
        lifetime = self.tm_lifetime.get(id)
        if lifetime:
            _add['exp'] = _now + lifetime

        content = self.trust_marks[id].copy()
        content.update(_add)
        self.issued.add(id, content)

        _entity_id = self.get_attribute('entity_id')
        _keyjar = self.get_attribute('keyjar')

        packer = JWT(key_jar=_keyjar, iss=_entity_id)
        return packer.pack(payload=content)

    def self_signed_trust_mark(self, **kwargs):
        _entity_id = self.get_attribute('entity_id')
        _keyjar = self.get_attribute('keyjar')

        packer = JWT(key_jar=_keyjar, iss=_entity_id)
        if 'sub' not in kwargs:
            kwargs['sub'] = _entity_id
        return packer.pack(payload=kwargs)

    def get_metadata(self):
        # federation_status_endpoint
        metadata = {}
        for key, item in self.server.endpoint.items():
            if key in ["status"]:
                metadata[f"federation_{key}_endpoint"] = item.full_path
        return {"trust_mark_issuer": metadata}
