from typing import Optional
from typing import Union

from idpyoidc.message import Message

from fedservice.entity_statement.create import create_entity_statement
from idpyoidc.message import oauth2
from idpyoidc.server import Endpoint

from fedservice.message import EntityStatement


class EntityConfiguration(Endpoint):
    request_cls = oauth2.Message
    response_cls = EntityStatement
    request_format = ""
    response_format = "jose"
    response_placement = "body"
    response_content_type = "application/entity-statement+jwt; charset=utf-8"
    name = "entity_configuration"
    endpoint_name = ""
    default_capabilities = None
    provider_info_attributes = None
    auth_method_attribute = ""

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get=upstream_get, **kwargs)

    def process_request(self, request=None, **kwargs):
        _server = self.upstream_get("unit")
        _entity = _server.upstream_get('unit')
        _entity_id = _entity.get_attribute('entity_id')
        if _entity.upstream_get:
            _metadata = _entity.upstream_get("metadata")
        else:
            _metadata = _entity.get_metadata()
        if _entity.context.trust_marks:
            args = {"trust_marks": _entity.context.trust_marks}
        else:
            args = {}
        _ec = create_entity_statement(iss=_entity_id,
                                      sub=_entity_id,
                                      key_jar=_entity.get_attribute('keyjar'),
                                      metadata=_metadata,
                                      authority_hints=_server.upstream_get('authority_hints'),
                                      **args
                                      )
        return {"response": _ec}

    def response_info(
        self,
        response_args: Optional[dict] = None,
        request: Optional[Union[Message, dict]] = None,
        error: Optional[str] = "",
        **kwargs
    ) -> dict:
        if "response" in kwargs:
            return kwargs["response"]
