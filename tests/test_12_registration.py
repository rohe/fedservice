import json
import os
from urllib.parse import parse_qs, urlparse

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from oic.utils.authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.endpoint_context import EndpointContext
from oidcservice.service_context import ServiceContext
from oidcservice.state_interface import InMemoryStateDataBase, State

from fedservice import Collector, FederationEntity
from fedservice.entity_statement.collect import Issuer
from fedservice.op.service import ProviderConfiguration, Registration
from fedservice.rp.service import FedProviderInfoDiscovery, \
    FedRegistrationRequest
from .utils import build_path

BASE_PATH = os.path.abspath(os.path.dirname(__file__))

BASE_URL = 'https://127.0.0.1:6000'
ROOT_DIR = os.path.join(BASE_PATH, 'fedA')
KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
RECEIVER = 'https://example.org/op'


class DummyCollector(Collector):
    def __init__(self, httpd=None, trusted_roots=None, root_dir='.',
                 base_url=''):
        Collector.__init__(self, httpd, trusted_roots=trusted_roots)
        self.root_dir = root_dir
        self.base_url = base_url

    def collect_entity_statements(self, response):
        _jwt = factory(response)
        if _jwt:
            entity_statement = _jwt.jwt.payload()
        else:
            return None

        node = Issuer(response)

        for authority, roots in entity_statement['authority_hints'].items():
            node.superior.append(
                build_path(self.root_dir, self.base_url, authority,
                           sub=entity_statement['iss']))

        return node


class MockResponse():
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class Publisher(object):
    def __init__(self, directory):
        self.dir = directory

    def __call__(self, method, url, **kwargs):
        p = urlparse(url)
        _qs = parse_qs(p.query)
        pt = urlparse(_qs['sub'][0])
        _jws = open(os.path.join(self.dir, p.netloc, pt.netloc)).read().strip()

        return MockResponse(200, '["{}"]'.format(_jws),
                            headers={'content-type': "application/jws"})


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        entity_id = 'https://127.0.0.1:6000/com/rp'
        service_context = ServiceContext(issuer=entity_id)
        trusted_roots = json.loads(
            open(os.path.join(BASE_PATH, 'trust_roots_wt.json')).read())

        key_jar = build_keyjar(KEYSPEC, owner=entity_id)
        self.rp_federation_entity = FederationEntity(
            key_jar=key_jar, id=entity_id, trusted_roots=trusted_roots,
            authority_hints={
                'https://127.0.0.1:6000/com/a': ['https://127.0.0.1:6000/fed']
            },
            entity_type='openid_client', opponent_entity_type='openid_provider'
        )

        self.rp_federation_entity.collector = DummyCollector(
            trusted_roots=trusted_roots,
            root_dir=ROOT_DIR, base_url=BASE_URL)

        service_context.federation_entity = self.rp_federation_entity
        db = InMemoryStateDataBase()
        db.set('state', State(iss='Issuer').to_json())
        self.service = {
            'discovery': FedProviderInfoDiscovery(service_context,
                                                  state_db=db),
            'registration': FedRegistrationRequest(service_context,
                                                   state_db=db)
        }

        op_entity_id = "https://127.0.0.1:6000/org/op"
        conf = {
            "issuer": op_entity_id,
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {},
            "authentication": [{
                'acr': INTERNETPROTOCOLPASSWORD,
                'name': 'NoAuthn',
                'kwargs': {'user': 'diana'}
            }],
            'template_dir': 'template'
        }
        endpoint_context = EndpointContext(conf, keyjar=build_keyjar(KEYSPEC))
        self.endpoint = Registration(endpoint_context)

        # === Federation stuff =======
        trusted_roots = json.loads(
            open(os.path.join(BASE_PATH, 'trust_roots_wt.json')).read())
        key_jar = build_keyjar(KEYSPEC, owner=op_entity_id)

        federation_entity = FederationEntity(
            op_entity_id, key_jar=key_jar, trusted_roots=trusted_roots,
            authority_hints={}, entity_type='openid_client',
            httpd=Publisher(os.path.join(BASE_PATH, 'data')),
             opponent_entity_type='openid_provider')

        federation_entity.collector = DummyCollector(
            httpd=Publisher(os.path.join(BASE_PATH, 'data')),
            trusted_roots=trusted_roots,
            root_dir=ROOT_DIR, base_url=BASE_URL)

        self.fedent = federation_entity
        self.endpoint.endpoint_context.federation_entity = federation_entity

    def test_request(self):
        # construct the client registration request
        req_args = {'entity_id': self.rp_federation_entity.id}
        self.rp_federation_entity.proposed_authority_hints = {
            'https://127.0.0.1:6000/com/a': ['https://127.0.0.1:6000/fed']
        }
        self.service['registration'].service_context.provider_info[
            'registration'] = "https://127.0.0.1:6000/org/op/fedreg"
        jws = self.service['registration'].construct(request_args=req_args)
        assert jws

        # construct the information needed to send the request
        _info = self.service['registration'].get_request_parameters(
            request_body_type="jose", method="POST")

        res = self.endpoint.process_request(_info['body'])
        assert res
