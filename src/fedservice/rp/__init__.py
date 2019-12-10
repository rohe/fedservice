import logging

import oidcrp

logger = logging.getLogger(__name__)


class RPHandler(oidcrp.RPHandler):
    def __init__(self, base_url='', hash_seed="", keyjar=None, verify_ssl=True,
                 services=None, service_factory=None, client_configs=None,
                 client_authn_factory=None, client_cls=None,
                 state_db=None, federation_entity=None, **kwargs):
        oidcrp.RPHandler.__init__(self, base_url=base_url, hash_seed=hash_seed, keyjar=keyjar,
                                  verify_ssl=verify_ssl, services=services,
                                  service_factory=service_factory, client_configs=client_configs,
                                  client_authn_factory=client_authn_factory, client_cls=client_cls,
                                  state_db=state_db, **kwargs)

        self.federation_entity = federation_entity

    def init_client(self, issuer):
        client = oidcrp.RPHandler.init_client(self, issuer)
        client.service_context.federation_entity = self.federation_entity
        return client
