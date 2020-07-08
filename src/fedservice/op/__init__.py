from oidcendpoint import endpoint_context

from fedservice import create_federation_entity


class EndpointContext(endpoint_context.EndpointContext):
    def __init__(self, conf, keyjar=None, cwd='', cookie_dealer=None, federation_entity=None):
        endpoint_context.EndpointContext.__init__(
            self, conf, keyjar=keyjar, cwd=cwd, cookie_dealer=cookie_dealer)

        self.federation_entity = federation_entity


class FederationEndpointContext(endpoint_context.EndpointContext):
    def __init__(self, conf, keyjar=None, cwd='', cookie_dealer=None):
        endpoint_context.EndpointContext.__init__(
            self, conf, keyjar=keyjar, cwd=cwd, cookie_dealer=cookie_dealer)

        _fed_conf = conf.get('federation')
        _fed_conf["entity_id"] = self.issuer

        federation_entity = create_federation_entity(cwd=cwd, **_fed_conf)
        federation_entity.keyjar.httpc_params = self.httpc_params

        self.federation_entity = federation_entity
