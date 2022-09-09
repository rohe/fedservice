from idpyoidc.message import oauth2
from idpyoidc.server import Endpoint

from fedservice.message import EntityStatement


class EntityConfiguration(Endpoint):
    request_cls = oauth2.Message
    response_cls = EntityStatement
    request_format = ""
    response_format = "jwt"
    name = "entity_configuration"
    endpoint_name = "entity_configuration"
    default_capabilities = None
    provider_info_attributes = None
    auth_method_attribute = ""

    def __init__(self, server_get, **kwargs):
        Endpoint.__init__(self, server_get=server_get, **kwargs)

    def process_request(self, request=None, **kwargs):
        pi = self.get_provider_info_attributes()
        return {"response_args": pi}

