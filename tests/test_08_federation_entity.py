import json
import os

from idpyoidc.configure import Configuration
from idpyoidc.util import instantiate

from fedservice.entity import FederationEntity
from fedservice.entity.server.fetch import Fetch

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

ENTITY_ID = "https://example.com/"
jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()
ANCHOR = {'https://feide.no': json.loads(jwks)}


class Foo():
    def __int__(self, config=None):
        self.config = Configuration(config)
        # OidcContext.__init__(self, config, keyjar, entity_id=config.conf.get("entity_id", ""))

        self.object = {entity_type: instantiate(args['class'], **args["kwargs"]) for
                       entity_type, args in config.items()}


def test_entity():
    config = {
        "federation_entity": {
            'class': FederationEntity,
            'kwargs': {
                "endpoint": {
                    "fetch": {
                        "path": "fetch",
                        "class": Fetch,
                        "kwargs": {"client_authn_method": None},
                    }
                },
                "entity_id": ENTITY_ID,
                "keys": {"uri_path": "static/fed_jwks.json", "key_defs": KEYDEFS},
                "trusted_roots": ANCHOR,
                "authority_hints": ['https://ntnu.no']
            }
        },
        "contacts": "operations@example.com"
    }
    entity = Foo()

    entity_configuration = entity.object["federation_entity"].construct_entity_configuration()
    assert entity_configuration
