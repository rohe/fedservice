import logging

import oidcrp

logger = logging.getLogger(__name__)


class RPHandler(oidcrp.RPHandler):
    def __init__(self, base_url='', hash_seed="", keyjar=None, verify_ssl=True,
                 services=None, service_factory=None, client_configs=None,
                 client_authn_factory=None, client_cls=None,
                 state_db=None, http_lib=None, federation_entity=None,
                 module_dirs=None, **kwargs):
        oidcrp.RPHandler.__init__(self, base_url, hash_seed, keyjar, verify_ssl,
                                  services, service_factory, client_configs,
                                  client_authn_factory, client_cls, state_db,
                                  http_lib, module_dirs, **kwargs)

        self.federation_entity = federation_entity

    def init_client(self, issuer):
        client = oidcrp.RPHandler.init_client(self, issuer)
        client.service_context.federation_entity = self.federation_entity
        return client
