import json
from typing import Dict
from typing import List
from typing import Optional

from oidcmsg.configure import Base
from oidcmsg.configure import DEFAULT_DIR_ATTRIBUTE_NAMES
from oidcmsg.configure import set_domain_and_port
from oidcop.configure import OPConfiguration
from oidcrp.configure import RPConfiguration

URIS = [
    "redirect_uris", 'post_logout_redirect_uris', 'frontchannel_logout_uri',
    'backchannel_logout_uri', 'issuer', 'base_url', "entity_id_pattern", "url_prefix"]

DEFAULT_FED_FILE_ATTRIBUTE_NAMES = ['server_key', 'server_cert', 'filename', 'template_dir',
                                    'private_path', 'public_path', 'db_file', 'authority_hints',
                                    'trusted_roots']

DEFAULT_FED_CONFIG = {
    "keys": {
        "private_path": "private/fed_keys.json",
        "key_defs": [
            {
                "type": "RSA",
                "use": [
                    "sig"
                ]
            },
            {
                "type": "EC",
                "crv": "P-256",
                "use": [
                    "sig"
                ]
            }
        ],
        "public_path": "static/fed_keys.json",
        "read_only": False
    },
    "endpoint": {
        "fetch": {
            "path": "fetch",
            "class": 'fedservice.entity.fetch.Fetch',
            "kwargs": {"client_authn_method": None},
        }
    },
    "authority_hints": "authority_hints.json",
    "trusted_roots": "trusted_roots.json"
}


class FedEntityConfiguration(Base):
    uris = ["entity_id"]

    def __init__(self,
                 conf: Dict,
                 entity_conf: Optional[List[dict]] = None,
                 base_path: str = '',
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 dir_attributes: Optional[List[str]] = None,
                 ):
        file_attributes = file_attributes or DEFAULT_FED_FILE_ATTRIBUTE_NAMES
        dir_attributes = dir_attributes or DEFAULT_DIR_ATTRIBUTE_NAMES

        Base.__init__(self, conf=conf, base_path=base_path, file_attributes=file_attributes,
                      dir_attributes=dir_attributes, domain=domain, port=port)

        self.entity_id = conf.get("entity_id")
        self.key_conf = conf.get("keys")
        self.priority = conf.get("priority", [])
        self.entity_type = conf.get("entity_type", "")
        self.opponent_entity_type = conf.get("opponent_entity_type", "")
        self.registration_type = conf.get("registration_type", "")
        self.endpoint = conf.get("endpoint", DEFAULT_FED_CONFIG["endpoint"])

        self._authority_hints = conf.get("authority_hints")
        if isinstance(self._authority_hints, str):
            self.authority_hints = json.loads(open(self._authority_hints).read())
        else:
            self.authority_hints = self._authority_hints

        self._trusted_roots = conf.get("trusted_roots")
        if isinstance(self._trusted_roots, str):
            self.trusted_roots = json.loads(open(self._trusted_roots).read())
        else:
            self.trusted_roots = self._trusted_roots

        self.metadata = conf.get("metadata")


class FedOpConfiguration(OPConfiguration):
    """ Provider configuration """

    def __init__(self,
                 conf: Dict,
                 entity_conf: Optional[List[dict]] = None,
                 base_path: Optional[str] = '',
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 file_attributes: Optional[List[str]] = None,
                 dir_attributes: Optional[List[str]] = None,
                 ):
        file_attributes = file_attributes or DEFAULT_FED_FILE_ATTRIBUTE_NAMES
        dir_attributes = dir_attributes or DEFAULT_DIR_ATTRIBUTE_NAMES

        OPConfiguration.__init__(self, conf, base_path=base_path,
                                 file_attributes=file_attributes,
                                 domain=domain, port=port,
                                 dir_attributes=dir_attributes)

        self.federation = FedEntityConfiguration(conf["federation"], base_path=base_path,
                                                 domain=domain, port=port,
                                                 file_attributes=self._file_attributes,
                                                 dir_attributes=self._dir_attributes)


class FedRPConfiguration(RPConfiguration):
    """RP Configuration"""

    def __init__(self,
                 conf: Dict,
                 entity_conf: Optional[List[dict]] = None,
                 base_path: Optional[str] = "",
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 dir_attributes: Optional[List[str]] = None,
                 ) -> None:
        if file_attributes is None:
            file_attributes = DEFAULT_FED_FILE_ATTRIBUTE_NAMES

        RPConfiguration.__init__(self, conf=conf, base_path=base_path,
                                 file_attributes=file_attributes, domain=domain, port=port,
                                 dir_attributes=dir_attributes)

        self.federation = FedEntityConfiguration(conf["federation"], base_path=base_path,
                                                 domain=domain, port=port,
                                                 file_attributes=file_attributes,
                                                 dir_attributes=dir_attributes)


DEFAULT_FILE_ATTRIBUTE_NAMES = ['server_key', 'server_cert', 'filename',
                                'private_path', 'public_path', 'base_path']


class FedSigServConfiguration(Base):
    def __init__(self,
                 conf: dict,
                 base_path: Optional[str] = "",
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 dir_attributes: Optional[List[str]] = None,
                 ):
        self._file_attributes = file_attributes or DEFAULT_FED_FILE_ATTRIBUTE_NAMES
        self._dir_attributes = dir_attributes or DEFAULT_DIR_ATTRIBUTE_NAMES

        Base.__init__(self, conf=conf, base_path=base_path, file_attributes=self._file_attributes,
                      dir_attributes=self._dir_attributes)

        set_domain_and_port(conf, ["entity_id_pattern", 'url_prefix'], domain, port)

        self.server_info = conf["server_info"]
