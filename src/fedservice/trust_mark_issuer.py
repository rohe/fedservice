import json
import os
from typing import Callable
from typing import Optional

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.node import create_keyjar
from idpyoidc.server import init_service

from fedservice.message import TrustMark


class FileDB(object):

    def __init__(self, **kwargs):
        self.config = kwargs
        for entity_id, file_name in self.config.items():
            if not os.path.exists(file_name):
                # Only need to touch it
                fp = open(file_name, "w")
                fp.close()

    def add(self, tm_info: dict):
        entity_id = tm_info['id']
        # adds a line with info about a trust mark info to the end of a file
        with open(self.config[entity_id], "a") as fp:
            fp.write(json.dumps(tm_info) + '\n')

    def _match(self, sub, iat, tmi):
        if sub == tmi["sub"]:
            if iat:
                if iat == tmi['iat']:
                    return True
            else:
                return True
        return False

    def find(self, entity_id: str, sub: str, iat: Optional[int] = 0):
        with open(self.config[entity_id], "r") as fp:
            for line in reversed(list(fp)):
                _tmi = json.loads(line.rstrip())
                if self._match(sub, iat, _tmi):
                    return True
        return False

    def __contains__(self, item):
        return item in self.config

    def id_keys(self):
        return self.config.keys()

    def dumps(self):
        res = {}
        for entity_id in self.config.keys():
            res[entity_id] = []
            with open(self.config[entity_id], "r") as fp:
                for line in list(fp):
                    res[entity_id].append(line.rstrip())
        return res

    def loads(self, str):
        res = json.loads(str)
        for entity_id in self.config.keys():
            with open(self.config[entity_id], "a") as fp:
                for tm_info in res[entity_id]:
                    fp.write(tm_info + '\n')


class SimpleDB(object):

    def __init__(self):
        self._db = {}

    def add(self, tm_info: dict):
        if tm_info['id'] in self._db:
            self._db[tm_info['id']].append({tm_info['sub']: tm_info})
        else:
            self._db[tm_info['id']] = {tm_info["sub"]: tm_info}

    def find(self, entity_id, sub: str, iat: Optional[int] = 0) -> bool:
        _tmi = self._db[entity_id].get(sub)
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

    def dumps(self):
        return json.dumps(self._db)

    def loads(self, info):
        self._db = json.loads(info)


def create_trust_mark(keyjar, entity_id, **kwargs):
    packer = JWT(key_jar=keyjar, iss=entity_id)
    return packer.pack(payload=kwargs)


class TrustMarkIssuer(object):
    name = 'trust_mark_issuer'

    def __init__(self,
                 entity_id: str = "",
                 keyjar: Optional[KeyJar] = None,
                 key_conf: Optional[dict] = None,
                 upstream_get: Optional[Callable] = None,
                 trust_mark_specification: Optional[dict] = None,
                 trust_mark_db: Optional[dict] = None,
                 **kwargs
                 ):

        self.entity_id = entity_id
        self.upstream_get = upstream_get

        if keyjar or key_conf:
            self.keyjar = create_keyjar(keyjar, key_conf=key_conf, id=entity_id)
        else:
            self.keyjar = None

        self.trust_mark_specification = trust_mark_specification or {}

        self.tm_lifetime = {}
        for entity_id, tm in self.trust_mark_specification.items():
            if "lifetime" in tm:
                self.tm_lifetime[entity_id] = tm["lifetime"]
                del tm["lifetime"]

        if trust_mark_db:
            self.issued = init_service(trust_mark_db)
        else:
            self.issued = SimpleDB()

    def create_trust_mark(self, entity_id, sub):
        _now = utc_time_sans_frac()
        _add = {'iat': _now, 'id': entity_id, 'sub': sub}
        lifetime = self.tm_lifetime.get(entity_id)
        if lifetime:
            _add['exp'] = _now + lifetime

        if entity_id not in self.trust_mark_specification:
            raise ValueError('Unknown trust mark ID')

        content = self.trust_mark_specification[entity_id].copy()
        content.update(_add)
        self.issued.add(content)

        packer = JWT(key_jar=self.upstream_get('attribute', 'keyjar'),
                     iss=self.upstream_get('attribute', 'entity_id'))
        return packer.pack(payload=content)

    def dump_trust_marks(self):
        return self.issued.dumps()

    def load_trust_marks(self, marks):
        return self.issued.loads(marks)

    def unpack_trust_mark(self, token, entity_id: Optional[str] = ""):
        keyjar = self.upstream_get('attribute', 'keyjar')
        _jwt = JWT(key_jar=keyjar, msg_cls=TrustMark, allowed_sign_algs=["RS256"])
        _tm = _jwt.unpack(token)

        if entity_id:
            _tm.verify(entity_id=entity_id)
        else:
            _tm.verify()

        return _tm

    def self_signed_trust_mark(self, **kwargs):
        _entity_id = self.upstream_get("attribute", 'entity_id')
        _keyjar = self.upstream_get('attribute', 'keyjar')

        packer = JWT(key_jar=_keyjar, iss=_entity_id)
        if 'sub' not in kwargs:
            kwargs['sub'] = _entity_id
        return packer.pack(payload=kwargs)

    def find(self, entity_id, sub: str, iat: Optional[int] = 0) -> bool:
        return self.issued.find(entity_id=entity_id, sub=sub, iat=iat)
