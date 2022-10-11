from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import FEDERATION_ENTITY_FUNCTIONS
from fedservice.defaults import FEDERATION_ENTITY_SERVICES
from fedservice.server import Collection

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class FederationEntityBuilder():
    def __init__(self, entity_id, metadata):
        self.conf = {
            "entity_id": entity_id,
            "key_conf": {"key_defs": KEYDEFS},
            "metadata": metadata
        }

    def add_services(self, **services):
        # services are used to send request to endpoints

        if not services:
            services = FEDERATION_ENTITY_SERVICES

        self.conf['client'] = {
            'class': 'fedservice.entity.client.FederationEntityClient',
            'kwargs': {
                "services": services
            }
        }

    def add_endpoints(self, **endpoints):
        # endpoints are accessible to services. Accepts requests and returns responses.
        if not endpoints:
            endpoints = DEFAULT_FEDERATION_ENTITY_ENDPOINTS

        self.conf['server'] = {
            'class': 'fedservice.entity.server.FederationEntityServer',
            'kwargs': {
                'metadata': {},
                'endpoint': endpoints
            }
        }

    def add_functions(self, **functions):
        # functions perform higher level service (like trust chain collection) based on the
        # available services.
        if not functions:
            functions = FEDERATION_ENTITY_FUNCTIONS

        self.conf['function'] = {
            'class': 'fedservice.node.Collection',
            'kwargs': {
                'functions': functions
            }
        }
