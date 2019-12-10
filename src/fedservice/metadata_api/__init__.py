from urllib.parse import unquote_plus
from urllib.parse import urlparse

from cryptojwt import KeyJar
from fedservice.entity_statement.create import create_entity_statement


class EntityStatementAPI:
    def __init__(self, iss, entity_id_pattern):
        self.iss = iss
        self.keyjar = KeyJar()
        self.entity_id_pattern = entity_id_pattern
        self.url_prefix = ''
        self.base_path = ""

    def gather_info(self, sub):
        raise NotImplementedError()

    def load_jwks(self, sup, sub, sub_id):
        raise NotImplementedError()

    def make_entity_id(self, netloc):
        return self.entity_id_pattern.format(netloc)

    def create_entity_statement(self, sub):
        _info = self.gather_info(sub)
        if sub.startswith("https"):
            return create_entity_statement(self.make_entity_id(self.iss), unquote_plus(sub),
                                           self.keyjar, **_info)

        return create_entity_statement(self.make_entity_id(self.iss), self.make_entity_id(sub),
                                       self.keyjar, **_info)


