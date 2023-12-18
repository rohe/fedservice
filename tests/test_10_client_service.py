import os
from urllib.parse import urlparse

import pytest
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OAUTH2_SERVICES

from fedservice.appclient import ClientEntity
from fedservice.defaults import DEFAULT_OAUTH2_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.join(BASE_PATH, 'base_data')

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

LEAF_ID = 'https://foodle.uninett.no'
TA_ID = "https://ta.example.org"


class TestRpService(object):

    @pytest.fixture(autouse=True)
    def client_service_setup(self):
        TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]
        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            endpoints=TA_ENDPOINTS
        )

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        oauth2_service = DEFAULT_OAUTH2_SERVICES.copy()
        oauth2_service.update(DEFAULT_OAUTH2_FED_SERVICES)

        self.client = make_federation_combo(
            LEAF_ID,
            preference={
                "organization_name": "Foodle",
                "homepage_uri": "https://foodle.uninett.no",
                "contacts": "operations@foodle.uninett.no"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID],
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=ANCHOR,
            entity_type={
                "oauth_client": {
                    'class': ClientEntity,
                    'kwargs': {
                        'config': {
                            "issuer": "https://as.example.com/",
                            'entity_id': LEAF_ID,
                            'client_secret': 'a longesh password',
                            'redirect_uris': ['https://example.com/cli/authz_cb'],
                            "keys": {"uri_path": "static/jwks.json", "key_defs": DEFAULT_KEY_DEFS},
                            "preference": {
                                "grant_types_supported": ['authorization_code', 'implicit',
                                                          'refresh_token'],
                                "id_token_signing_alg_values_supported": ["ES256"],
                                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                                "client_registration_types_supported": ['automatic']
                            }
                        },
                        "services": oauth2_service,
                        "client_type": 'oauth2'
                    }
                }
            }
        )

    def test_1(self):
        assert set(self.client.keys()) == {'federation_entity', 'oauth_client'}
        _entity_federation = self.client["federation_entity"]
        # can publish as well as request
        assert _entity_federation.get_endpoint("entity_configuration")
        assert _entity_federation.get_service("entity_configuration")

        assert set(_entity_federation.get_all_endpoints()) == {'entity_configuration'}
        assert set(_entity_federation.get_all_services()) == {'entity_configuration', 'entity_statement', 'list',
                                                              'resolve'}
        for func in ["policy", "trust_chain_collector", "trust_mark_verifier", "verifier"]:
            assert getattr(_entity_federation.function, func)

        _oauth_client = self.client["oauth_client"]
        assert isinstance(_oauth_client, ClientEntity)
        for srv in ["server_metadata", "authorization", "accesstoken", "refresh_token"]:
            assert _oauth_client.get_service(srv)

    def test_discover(self):
        _srv = self.client["federation_entity"].get_service("entity_configuration")
        _info = _srv.get_request_parameters()
        assert set(_info.keys()) == {'method', 'url', 'iss'}
        p = urlparse(_info['url'])
        assert p.scheme == 'https'
        assert p.netloc == 'op.ntnu.no'
        assert p.path == "/.well-known/openid-federation"
#
#     def test_parse_discovery_response(self):
#         _info = self.discovery_service.get_request_parameters()
#         http_response = self.entity.httpc('GET', _info['url'])
#
#         statements = self.discovery_service.parse_response(http_response.text)
#         # there are two Trust Anchors. I only trust one.
#         assert len(statements) == 1
#         statement = statements[0]
#         assert statement.anchor == 'https://feide.no'
#         self.discovery_service.update_service_context(statements)
#         assert set(self.discovery_service.upstream_get("context").prefers().keys()) == {
#             'callback_uris',
#             'client_id',
#             'client_secret',
#             'grant_types_supported',
#             'id_token_encryption_alg_values_supported',
#             'id_token_encryption_enc_values_supported',
#             'id_token_signing_alg_values_supported',
#             'jwks_uri',
#             'redirect_uris',
#             'request_object_encryption_alg_values_supported',
#             'request_object_encryption_enc_values_supported',
#             'token_endpoint_auth_methods_supported',
#             'userinfo_encryption_alg_values_supported',
#             'userinfo_encryption_enc_values_supported'}
#         assert set(
#             [k for k, v in self.discovery_service.upstream_get("context").prefers().items() if v]) == {
#                    'callback_uris',
#                    'client_id',
#                    'client_secret',
#                    'grant_types_supported',
#                    'id_token_signing_alg_values_supported',
#                    'jwks_uri',
#                    'redirect_uris',
#                    'token_endpoint_auth_methods_supported'
#                }
#
#     def test_create_reqistration_request(self):
#         # get the entity statement from the OP
#         _info = self.discovery_service.get_request_parameters(iss='https://op.ntnu.no')
#         http_response = self.entity.httpc('GET', _info['url'])
#
#         # parse the response and collect the trust chains
#         res = self.discovery_service.parse_response(http_response.text)
#
#         self.discovery_service.update_service_context(res)
#
#         # construct the client registration request
#         req_args = {'entity_id': self.entity["federation_entity"].entity_id}
#         jws = self.registration_service.construct(request_args=req_args)
#         assert jws
#
#         _sc = self.registration_service.upstream_get("context")
#         self.registration_service.endpoint = _sc.get('provider_info')[
#             'federation_registration_endpoint']
#
#         # construct the information needed to send the request
#         _info = self.registration_service.get_request_parameters(
#             request_body_type="jose", method="POST")
#
#         assert set(_info.keys()) == {'method', 'url', 'body', 'headers', 'request'}
#         assert _info['method'] == 'POST'
#         assert _info['url'] == 'https://op.ntnu.no/fedreg'
#         assert _info['headers'] == {'Content-Type': 'application/jose'}
#
#         _jws = _info['body']
#         _jwt = factory(_jws)
#         payload = _jwt.jwt.payload()
#         assert set(payload.keys()) == {'trust_marks', 'sub', 'iss', 'metadata', 'jwks', 'exp',
#                                        'iat', 'authority_hints'}
#         assert set(payload['metadata']['openid_relying_party'].keys()) == {
#             'application_type',
#             'default_max_age',
#             'grant_types',
#             'id_token_signed_response_alg',
#             'jwks_uri',
#             'redirect_uris',
#             'response_types',
#             'subject_type',
#             'token_endpoint_auth_method'}
#
#     def test_parse_registration_response(self):
#         # construct the entity statement the OP should return
#         es_api = FSFetchEntityStatement(os.path.join(BASE_PATH, 'base_data'), iss="op.ntnu.no")
#         jws = es_api.create_entity_statement("op.ntnu.no")
#
#         # parse the response and collect the trust chains
#         res = self.discovery_service.parse_response(jws)
#
#         _context = self.registration_service.upstream_get("context")
#         _context.issuer = "https://op.ntnu.no"
#         self.discovery_service.update_service_context(res)
#
#         self.registration_service.endpoint = _context.get('provider_info')[
#             'federation_registration_endpoint']
#
#         combo = topmost_unit(self.registration_service)
#         _fe = combo['federation_entity']
#         # construct the client registration request
#         req_args = {'entity_id': _fe.context.entity_id}
#         jws = self.registration_service.construct(request_args=req_args)
#         assert jws
#
#         # construct the information needed to send the request
#         _info = self.registration_service.get_request_parameters(
#             request_body_type="jose", method="POST")
#
#         # create the request
#         _req_jwt = factory(_info['body'])
#         _fe.context.entity_configuration = _info['body']
#
#         payload = _req_jwt.jwt.payload()
#
#         # The OP as federation entity
#         keyjar = combo.get_attribute('keyjar')
#         # make sure I have the private keys
#         keyjar.import_jwks(
#             es_api.keyjar.export_jwks(True, "https://op.ntnu.no"),
#             "https://op.ntnu.no"
#         )
#
#         chains, _ = collect_trust_chains(_fe, entity_id=payload['iss'],
#                                          signed_entity_configuration=_info['body'])
#
#         trust_chains = verify_trust_chains(_fe, chains, _info['body'])
#         trust_chains = apply_policies(_fe, trust_chains)
#
#         _metadata = trust_chains[0].metadata["openid_relying_party"]
#         _metadata.update({
#             "client_id": {"value": "aaaaaaaaa"},
#             "client_secret": {"value": "bbbbbbbbbb"}
#         })
#
#         # This is the registration response from the OP
#         _jwt = _fe.context.create_entity_statement(
#             'https://op.ntnu.no',
#             'https://foodle.uninett.no',
#             metadata={'openid_relying_party': _metadata},
#             key_jar=OP_KEYJAR,
#             trust_anchor_id=trust_chains[0].anchor)
#
#         # On the RP's side
#         keyjar = self.entity['openid_relying_party'].get_attribute('keyjar')
#         keyjar.import_jwks(
#             es_api.keyjar.export_jwks(issuer_id="https://op.ntnu.no"),
#             "https://op.ntnu.no"
#         )
#         claims = self.registration_service.parse_response(_jwt, request=_info['body'])
#
#         assert set(claims.keys()) == {'application_type',
#                                       'client_id',
#                                       'client_secret',
#                                       'contacts',
#                                       'default_max_age',
#                                       'grant_types',
#                                       'id_token_signed_response_alg',
#                                       'jwks_uri',
#                                       'redirect_uris',
#                                       'response_types',
#                                       'subject_type',
#                                       'token_endpoint_auth_method'}
#
#
# class TestRpServiceAuto(object):
#
#     @pytest.fixture(autouse=True)
#     def rp_service_setup(self):
#         ENT = FederationEntityBuilder(
#             LEAF_ID,
#             preference={
#                 "organization_name": "The leaf operator",
#                 "homepage_uri": "https://leaf.example.com",
#                 "contacts": "operations@leaf.example.com",
#                 "client_registration_types": ['automatic']
#             }
#         )
#         ENT.add_services()
#         ENT.add_functions(**MOD_FUNCTIONS)
#         ENT.add_endpoints(**LEAF_ENDPOINTS)
#
#         oidc_service = DEFAULT_OIDC_SERVICES.copy()
#         oidc_service.update(DEFAULT_OIDC_FED_SERVICES)
#
#         config = {
#             'entity_id': LEAF_ID,
#             'key_conf': {'private_path': FOODLE_JWKS},
#             "federation_entity": {
#                 'class': FederationEntity,
#                 'kwargs': ENT.conf
#             },
#             "openid_relying_party": {
#                 'class': ClientEntity,
#                 'kwargs': {
#                     'config': {
#                         'client_id': LEAF_ID,
#                         'client_secret': 'a longesh password',
#                         'redirect_uris': ['https://example.com/cli/authz_cb'],
#                         "keys": {"uri_path": "static/jwks.json", "key_defs": KEY_DEFS},
#                         "preference": {
#                             "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
#                             "id_token_signed_response_alg": "ES256",
#                             "token_endpoint_auth_method": "client_secret_basic",
#                             "token_endpoint_auth_signing_alg": "ES256"
#                         }
#                     },
#                     "services": oidc_service
#                 }
#             }
#         }
#
#         self.entity = FederationCombo(config=config,
#                                       httpc=FSPublisher(os.path.join(BASE_PATH, 'base_data')))
#
#         self.entity['federation_entity'].function.trust_chain_collector.add_trust_anchor(
#             'https://feide.no', json.loads(jwks))
#         self.entity['federation_entity'].server.get_context().authority_hints = [
#             'https://ntnu.no']
#
#         _context = self.entity['openid_relying_party'].get_context()
#         _context.provider_info = {'token_endpoint': "https://op.example.org"}
#
#     def test_construct_client_assertion(self):
#         token_service = self.entity['openid_relying_party'].get_service('accesstoken')
#         request = AccessTokenRequest()
#         pkj = PrivateKeyJWT()
#         http_args = pkj.construct(request, service=token_service, authn_endpoint='token_endpoint')
#
#         assert http_args == {}
#         _jws = factory(request["client_assertion"])
#         _payload = _jws.jwt.payload()
#         assert "iss" in _payload
#         assert _payload["iss"] == 'https://foodle.uninett.no'
#         assert _payload["sub"] == 'https://foodle.uninett.no'
#         assert request['client_assertion_type'] == JWT_BEARER
