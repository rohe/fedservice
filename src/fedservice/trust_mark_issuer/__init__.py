import json
import os
from typing import Any
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg.configure import Configuration
from oidcop.endpoint_context import init_service

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


def create_trust_mark(content, keyjar, entity_id):
    packer = JWT(key_jar=keyjar, iss=entity_id)
    return packer.pack(payload=content)


class TrustMarkIssuer(FederationEntity):
    def __init__(self,
                 entity_id: str = "",
                 config: Optional[Union[dict, Configuration]] = None,
                 httpc: Optional[Any] = None,
                 cwd: Optional[str] = ''):

        FederationEntity.__init__(self, entity_id=entity_id, config=config, httpc=httpc, cwd=cwd)
        self.trust_marks = config.get("trust_marks")
        _db_conf = config.get("trust_mark_db")
        self.issued = init_service(_db_conf)

        self.tm_lifetime = {}
        for id, tm in self.trust_marks.items():
            if "lifetime" in tm:
                self.tm_lifetime[id] = tm["lifetime"]
                del tm["lifetime"]

    def create_trust_mark(self, id, sub):
        _now = utc_time_sans_frac()
        _add = {'iat': _now, 'id': id, 'sub': sub}
        lifetime = self.tm_lifetime.get(id)
        if lifetime:
            _add['exp'] = _now + lifetime

        content = self.trust_marks[id].copy()
        content.update(_add)
        self.issued.add(id, content)
        _ctx = self.server_get("context")
        packer = JWT(key_jar=_ctx.keyjar, iss=_ctx.entity_id)
        return packer.pack(payload=content)


#     "self_signed_trust_marks": {
#         "function": "fedservice.trust_mark_issuer.self_signed_trust_marks",
#         "kwargs": {
#             "trust_marks": {
#                 "https://openid.net/certification/op": {
#                     "mark": ("http://openid.net/wordpress-content/uploads/2016/05/"
#                              "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg"),
#                     "ref": ("https://openid.net/wordpress-content/uploads/2015/09/"
#                             "RolandHedberg-pyoidc-0.7.7-Basic-26-Sept-2015.zip")
#                 }
#             }
#         }
#     }
def self_signed_trust_mark(entity_id, keyjar, **kwargs):
    packer = JWT(key_jar=keyjar, iss=entity_id)
    return packer.pack(payload=kwargs)
