import logging

from idpyoidc.message import oidc
from idpyoidc.server.endpoint import Endpoint

from fedservice.entity_statement.create import create_entity_statement
from fedservice.exception import UnknownEntity
from fedservice.message import EntityStatement

logger = logging.getLogger(__name__)


class Fetch(Endpoint):
    request_cls = oidc.Message
    response_cls = EntityStatement
    response_format = 'jws'
    name = "fetch"

    def __init__(self, upstream_get, **kwargs):
        Endpoint.__init__(self, upstream_get=upstream_get, **kwargs)
        self.post_construct.append(self.create_entity_statement)

    def get_policy(self, entity_id):
        pass

    def process_request(self, request=None, **kwargs):
        _context = self.upstream_get("context")
        _issuer = request.get("iss")
        if not _issuer:
            _issuer = self.upstream_get('attribute','entity_id')

        _sub = request.get("sub")
        _keyjar = self.upstream_get('attribute', 'keyjar')
        if not _sub or _sub == _issuer:
            _server = self.upstream_get("server")
            _entity = _server.upstream_get('unit')
            _metadata = _entity.get_metadata()
            _es = create_entity_statement(iss=_entity.context.entity_id,
                                          sub=_entity.context.entity_id,
                                          key_jar=_keyjar,
                                          metadata=_metadata,
                                          authority_hints=self.upstream_get('authority_hints'))
        else:
            _server = self.upstream_get("unit")
            # Contains jwks and possibly entity type and authority_hints
            _response = _server.subordinate.get(_sub)
            if not _response:
                raise UnknownEntity(_sub)

            if not 'authority_hints' in _response:
                _response["authority_hints"] = [_issuer]

            _policy = _server.policy.get(_sub)
            if not _policy:  # No entity specific policy
                if 'entity_types' in _response:
                    _entity_types = _response['entity_types']
                    _response = {k: v for k, v in _response.items() if k != 'entity_types'}
                    _policy = {'metadata': {}, 'metadata_policy': {}}
                    for entity_type in _entity_types:
                        _et_policy = _server.policy.get(entity_type)
                        if not _et_policy:
                            continue
                        for _typ in ['metadata', 'metadata_policy']:
                            if _typ in _et_policy:
                                try:
                                    _policy[_typ].update({entity_type: _et_policy[_typ]})
                                except KeyError:
                                    _policy[_typ] = {entity_type: _et_policy[_typ]}

                    if _policy == {'metadata': {}, 'metadata_policy': {}}:  # Nothing has changed
                        _policy = None

            if _policy:
                _response.update(_policy)

            _es = create_entity_statement(iss=_issuer,
                                          sub=_sub,
                                          key_jar=_keyjar,
                                          **_response
                                          )
        return {"response": _es}

    def create_entity_statement(self, request_args, request=None, **kwargs):
        """
        Create a self signed entity statement

        :param request_args:
        :param request:
        :param kwargs:
        :return:
        """

        _context = self.upstream_get("context")
        _payload = request_args.to_dict()
        _sub = request.get("sub")
        if not _sub:
            _sub = _context.entity_id

        return _context.create_entity_statement(iss=_context.entity_id, sub=_sub, **_payload)
