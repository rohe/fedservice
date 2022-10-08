from cryptojwt.jwt import JWT
from fedservice.entity_statement.create import create_entity_statement
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
        _server = self.server_get("server")
        _entity_id = _server.superior_get('attribute', 'entity_id')
        _entity = _server.superior_get('node')
        if _entity.superior_get:
            _metadata = _entity.superior_get("metadata")
        else:
            _metadata = _entity.get_metadata()
        _ec = create_entity_statement(iss=_entity_id,
                                      sub=_entity_id,
                                      key_jar=_entity.superior_get('attribute', "keyjar"),
                                      metadata=_metadata,
                                      authority_hints=_server.endpoint_context.authority_hints)
        return {"response": _ec}
