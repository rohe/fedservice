from typing import Optional

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import FEDERATION_ENTITY_FUNCTIONS
from fedservice.defaults import FEDERATION_ENTITY_SERVICES
from fedservice.entity.server.status import TrustMarkStatus

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class FederationEntityBuilder():
    def __init__(self,
                 entity_id: Optional[str] = '',
                 metadata: Optional[dict] = None,
                 key_conf: Optional[dict] = None):
        if key_conf is None:
            key_conf = {"key_defs": KEYDEFS}

        self.conf = {
            "entity_id": entity_id,
            "key_conf": key_conf,
            "metadata": metadata
        }

    def add_services(self, metadata: Optional[dict] = None, **services):
        # services are used to send request to endpoints

        if not services:
            services = FEDERATION_ENTITY_SERVICES
        if metadata is None:
            metadata = {}

        self.conf['client'] = {
            'class': 'fedservice.entity.client.FederationEntityClient',
            'kwargs': {
                'metadata': metadata,
                "services": services
            }
        }

    def add_endpoints(self, metadata: Optional[dict] = None, **endpoints):
        # endpoints are accessible to services. Accepts requests and returns responses.
        if not endpoints:
            endpoints = DEFAULT_FEDERATION_ENTITY_ENDPOINTS
        if metadata is None:
            metadata = {}

        self.conf['server'] = {
            'class': 'fedservice.entity.server.FederationEntityServer',
            'kwargs': {
                'metadata': metadata,
                'endpoint': endpoints
            }
        }

    def add_functions(self, metadata: Optional[dict] = None, **functions):
        # functions perform higher level service (like trust chain collection) based on the
        # available services.
        if not functions:
            functions = FEDERATION_ENTITY_FUNCTIONS
        if metadata is None:
            metadata = {}

        self.conf['function'] = {
            'class': 'fedservice.node.Collection',
            'kwargs': {
                'metadata': metadata,
                'functions': functions
            }
        }

    def set_attr(self, section, what):
        self.conf[section]['kwargs'].update(what)


class TrustMarkIssuerBuilder():
    def __init__(self,
                 entity_id: Optional[str] = '',
                 metadata: Optional[dict] = None,
                 key_conf: Optional[dict] = None,
                 trust_marks: Optional[dict] = None
                 ):
        if key_conf is None:
            key_conf = {"key_defs": KEYDEFS}
        if trust_marks is None:
            trust_marks = {}

        self.conf = {
            "entity_id": entity_id,
            "key_conf": key_conf,
            "metadata": metadata,
            "trust_marks": trust_marks
        }

    def add_endpoints(self, metadata: Optional[dict] = None, **endpoints):
        # endpoints are accessible to services. Accepts requests and returns responses.
        if not endpoints:
            endpoints = {
                "trust_mark_status": {
                    'path': 'status',
                    'class': 'fedservice.entity.server.status.TrustMarkStatus',
                    'kwargs': {}
                }
            }
        if metadata is None:
            metadata = {}

        self.conf['server'] = {
            'class': 'fedservice.entity.server.FederationEntityServer',
            'kwargs': {
                'metadata': metadata,
                'endpoint': endpoints
            }
        }
