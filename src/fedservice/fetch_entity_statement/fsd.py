import json
import logging
import os
import re
from typing import Optional
from urllib.parse import quote_plus
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from cryptojwt import JWT
from cryptojwt.key_jar import init_key_jar
from oidcmsg.configure import create_from_config_file

from fedservice.configure import DEFAULT_FED_FILE_ATTRIBUTE_NAMES
from fedservice.configure import FedEntityConfiguration
from fedservice.exception import UnknownEntity
from fedservice.fetch_entity_statement import FetchEntityStatement

logger = logging.getLogger(__name__)


def read_info(dir, sub, typ='metadata'):
    file_name = os.path.join(dir, sub, "{}.json".format(typ))
    if os.path.isfile(file_name):
        return json.loads(open(file_name).read())
    else:
        return None


def create_regex(pattern):
    return pattern.replace('{}', '([a-zA-Z0-9_.]+)')


class FSFetchEntityStatementMulti(object):
    def __init__(self, base_path, entity_id_pattern="https://{}", federation_entities="", **kwargs):
        self.lifetime = kwargs["lifetime"]
        self.entity_id_pattern = create_regex(entity_id_pattern)
        self.signer = {}
        for iss in os.listdir(federation_entities):
            _signer = FetchEntityStatement(iss, entity_id_pattern)
            _signer.fe_base_path = os.path.join(base_path, federation_entities, iss)
            _signer.auth_base_path = os.path.join(base_path, kwargs["authorities"], iss)
            cargs = {k: kwargs[k] for k in ['domain', 'port'] if k in kwargs}
            _conf = create_from_config_file(FedEntityConfiguration,
                                            filename=os.path.join(_signer.fe_base_path,
                                                                  "conf.json"),
                                            file_attributes=DEFAULT_FED_FILE_ATTRIBUTE_NAMES,
                                            base_path=_signer.fe_base_path,
                                            **cargs)
            _conf.entity_type = "federation_entity"
            _signer.federation_api_endpoint = kwargs["federation_api_endpoint"].format(
                domain=kwargs["domain"], port=kwargs["port"])
            _signer.conf = _conf
            keys_args = {k: v for k, v in _conf["keys"].items() if k != "uri_path"}
            keys_args["issuer_id"] = _signer.make_entity_id(iss)
            _signer.keyjar = init_key_jar(**keys_args)

            if 'url_prefix' in kwargs:
                self.url_prefix = kwargs['url_prefix']
            self.signer[iss] = _signer

    def gather_info(self, entity, id: str, entity_id: str) -> dict:
        data = {"metadata": {"federation_entity": entity.conf.metadata}}

        data["metadata"]["federation_entity"].update({
            "federation_api_endpoint": entity.federation_api_endpoint.format(id)})

        if entity.conf._authority_hints:
            data["authority_hints"] = entity.conf._authority_hints
        data["jwks"] = entity.keyjar.export_jwks(issuer_id=entity_id)
        return data

    def _entity_statement(self, dir_path) -> Optional[dict]:
        data = {}
        # get policy
        head, tail = os.path.split(dir_path)
        for _root in [dir_path, head]:
            _file = os.path.join(_root, "conf.json")
            if os.path.isfile(_file):
                with open(_file, "r") as fp:
                    data = json.loads(fp.read())
                    break
        # get jwks
        _file = os.path.join(dir_path, "jwks.json")
        with open(_file, "r") as fp:
            _jwks = json.loads(fp.read())
            data["jwks"] = _jwks

        return data

    def get_entity_info(self, base_path, entity_id) -> Optional[str]:
        p = urlsplit(entity_id, allow_fragments=False)
        _url_path = p.path
        if not _url_path:
            _pp = [""]
        else:
            _pp = _url_path.split('/')

        for i in range(len(_pp)):
            path = "/".join(_pp[:i])

            _id = quote_plus(urlunsplit((p.scheme, p.netloc, path, None, None)))
            for typ in ["openid_relying_party", "openid_provider", "federation_entity"]:
                _path = os.path.join(base_path, typ, _id)
                if os.path.isdir(_path):
                    return self._entity_statement(os.path.join(base_path, typ, _id))
        return None

    def make_entity_statement(self, iss, key_jar, **data):
        packer = JWT(key_jar=key_jar, iss=iss, lifetime=self.lifetime)
        packer.with_jti = True
        return packer.pack(payload=data)

    def create_entity_statement(self, iss: str, sub: Optional[str] = "") -> str:
        _match = re.match(self.entity_id_pattern, iss)
        if _match:
            iss_id = iss
            iss = _match.group(1)
        else:
            iss_id = ""

        _signer = self.signer[iss]
        if not iss_id:
            iss_id = _signer.make_entity_id(iss)
        logger.debug('Statement Issuer ID: %s', iss_id)

        if sub == "":
            sub = iss
            sub_id = iss_id
        else:
            _match = re.match(self.entity_id_pattern, sub)
            if _match:
                sub_id = sub
                sub = _match.group(1)
            else:
                if sub.startswith("https://"):
                    sub_id = sub
                else:
                    sub_id = _signer.make_entity_id(sub)

        logger.debug('Subject ID: %s', sub_id)

        if iss_id == sub_id:  # Self signed entity statement
            logger.debug("Self signed entity statement")
            data = self.gather_info(_signer, iss, iss_id)
            data["sub"] = iss_id
            logger.debug("Entity statement: %s", data)
            entity_statement = self.make_entity_statement(iss_id, _signer.keyjar, **data)
        else:  # entity statement on subordinate
            logger.debug("Entity statement on subordinate")
            # Is sub an entity I manage ?
            try:
                _subject = self.signer[sub]
            except KeyError:  # No, a registered entity
                logger.debug("External entity")
                data = self.get_entity_info(_signer.auth_base_path, sub_id)
            else:
                logger.debug("Managed entity")
                data = self.gather_info(_subject, sub, sub_id)

            if data:
                # Add authority hints
                data["authority_hints"] = _signer.conf._authority_hints
                data["sub"] = sub_id
                logger.debug("Entity statement: %s", data)
                entity_statement = self.make_entity_statement(iss_id, _signer.keyjar, **data)
            else:
                raise UnknownEntity(sub)

        return entity_statement
