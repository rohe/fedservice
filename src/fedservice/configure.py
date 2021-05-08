from typing import Dict
from typing import List
from typing import Optional

from oidcop.configure import OPConfiguration
from oidcrp.configure import Base
from oidcrp.configure import RPConfiguration
from oidcrp.configure import add_base_path
from oidcrp.configure import set_domain_and_port

URIS = [
    "redirect_uris", 'post_logout_redirect_uris', 'frontchannel_logout_uri',
    'backchannel_logout_uri', 'issuer', 'base_url', "entity_id_pattern", "url_prefix"]

DEFAULT_FILE_ATTRIBUTE_NAMES = ['server_key', 'server_cert', 'filename', 'template_dir',
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
    "authority_hints": "authority_hints.json",
    "trusted_roots": "trusted_roots.json"
}


class FedEntityConfiguration(Base):
    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0
                 ):
        Base.__init__(self, conf, base_path, file_attributes)

        self.entity_id = ""
        self.keys = None
        self.authority_hints = ""
        self.trusted_roots = ""
        self.priority = {}
        self.entity_type = ""
        self.opponent_entity_type = ""
        self.registration_type = ""

        for key in self.__dict__.keys():
            _val = conf.get(key)
            if not _val and key in DEFAULT_FED_CONFIG:
                _val = DEFAULT_FED_CONFIG[key]
            if not _val:
                continue

            if key in ["entity_id"]:
                if '{domain}' in _val:
                    setattr(self, key, _val.format(domain=domain, port=port))
                else:
                    setattr(self, key, _val)
            else:
                setattr(self, key, _val)


class FedOpConfiguration(OPConfiguration):
    """ Provider configuration """

    def __init__(self,
                 conf: Dict,
                 entity_conf: Optional[List[dict]] = None,
                 base_path: Optional[str] = '',
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 file_attributes: Optional[List[str]] = None,
                 ):
        if file_attributes is None:
            file_attributes = DEFAULT_FILE_ATTRIBUTE_NAMES

        OPConfiguration.__init__(self, conf, base_path=base_path, file_attributes=file_attributes,
                                 domain=domain, port=port)

        self.federation = FedEntityConfiguration(conf["federation"], base_path=base_path,
                                                 domain=domain, port=port,
                                                 file_attributes=file_attributes)


class FedRPConfiguration(RPConfiguration):
    """RP Configuration"""

    def __init__(self,
                 conf: Dict,
                 entity_conf: Optional[List[dict]] = None,
                 base_path: Optional[str] = "",
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0
                 ) -> None:
        if file_attributes is None:
            file_attributes = DEFAULT_FILE_ATTRIBUTE_NAMES

        RPConfiguration.__init__(self, conf=conf, base_path=base_path,
                                 file_attributes=file_attributes, domain=domain, port=port)

        self.federation = FedEntityConfiguration(conf["federation"], base_path=base_path,
                                                 domain=domain, port=port,
                                                 file_attributes=file_attributes)


DEFAULT_FILE_ATTRIBUTE_NAMES = ['server_key', 'server_cert', 'filename',
                                'private_path', 'public_path', 'base_path']


class FedSigServConfiguration(Base):
    def __init__(self,
                 conf: dict,
                 base_path: Optional[str] = "",
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0):
        Base.__init__(self, conf=conf, base_path=base_path, file_attributes=file_attributes)

        if file_attributes is None:
            file_attributes = DEFAULT_FILE_ATTRIBUTE_NAMES

        add_base_path(conf, base_path, file_attributes)
        set_domain_and_port(conf, ["entity_id_pattern", 'url_prefix'], domain, port)

        self.server_info = conf["server_info"]
        # self.key_defs = conf["keydefs"]
        # self.httpc_params = conf.get("httpc_params", {"verify_ssl": True})
