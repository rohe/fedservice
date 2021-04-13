from urllib.parse import urlparse

from oidcop import endpoint_context
from oidcop.util import get_http_params

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


def init_oidc_op_endpoints(config, folder):
    _server_info_config = config.op['server_info']
    _server_info_config['issuer'] = _server_info_config.get('issuer').format(
        domain=config.domain, port=config.port)

    _fed_conf = _server_info_config.get('federation')
    _fed_conf["entity_id"] = config.base_url
    if 'httpc_params' not in _fed_conf:
        _fed_conf['httpc_params'] = get_http_params(_server_info_config.get(
            "httpc_params"))

    federation_entity = create_federation_entity(cwd=folder, **_fed_conf)

    endpoint_context = EndpointContext(_server_info_config, cwd=folder,
                                       federation_entity=federation_entity)

    for endp in endpoint_context.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split('/')
        if _vpath[0] == '':
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

    return endpoint_context
