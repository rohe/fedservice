import pytest
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.entity import FederationEntity
from fedservice.rp import ClientEntity

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"
ENTITY_ID = "https://anchor.example.com"
AH_ID = "https://example.com"


class TestClaimsEntity():

    @pytest.fixture(autouse=True)
    def create_entity(self):
        # The Trust Anchor
        ENT = FederationEntityBuilder(
            ENTITY_ID,
            metadata={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_conf={"key_defs": KEYSPEC}
        )
        ENT.add_endpoints()
        ENT.add_functions()
        ENT.add_services()

        self.entity = FederationEntity(**ENT.conf)

    def test_supported(self):
        base_supported = self.entity.get_context().supports()
        assert set(base_supported.keys()) == {'organization_name', 'homepage_uri', 'contacts',
                                              'policy_uri', 'logo_uri'}

        assert self.entity.context.claims.prefer == {
            'organization_name': 'The example federation operator',
            'homepage_uri': 'https://ta.example.com',
            'contacts': 'operations@ta.example.com'}

        assert self.entity.get_endpoint_claims() == {
            'federation_fetch_endpoint': 'https://anchor.example.com/fetch',
            'federation_list_endpoint': 'https://anchor.example.com/list',
            'federation_resolve_endpoint': 'https://anchor.example.com/resolve'}

        assert self.entity.get_metadata() == {
            'federation_entity': {
                'contacts': 'operations@ta.example.com',
                'federation_fetch_endpoint': 'https://anchor.example.com/fetch',
                'federation_list_endpoint': 'https://anchor.example.com/list',
                'federation_resolve_endpoint': 'https://anchor.example.com/resolve',
                'homepage_uri': 'https://ta.example.com',
                'organization_name': 'The example federation operator'}}

        # stored under 2 IDs
        assert len(self.entity.keyjar) == 2
        assert set(self.entity.keyjar.owners()) == {'', 'https://anchor.example.com'}


class TestClaimsFRP():

    @pytest.fixture(autouse=True)
    def create_entity(self):
        # The Trust Anchor
        ENT = FederationEntityBuilder(
            ENTITY_ID,
            metadata={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_conf={"key_defs": KEYSPEC},
            authority_hints=[AH_ID]
        )
        ENT.add_endpoints()
        ENT.add_functions()
        ENT.add_services()

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)

        LEAF_CONFIG = {
            'entity_id': ENTITY_ID,
            # 'key_conf': {"key_defs": KEYSPEC},
            "federation_entity": {
                'class': FederationEntity,
                'kwargs': ENT.conf
            },
            "openid_relying_party": {
                'class': ClientEntity,
                'kwargs': {
                    'config': {
                        'client_id': ENTITY_ID,
                        'client_secret': 'a longesh password',
                        'redirect_uris': ['https://example.com/cli/authz_cb'],
                        "keys": {"uri_path": "static/jwks.json", "key_defs": KEYSPEC},
                        "preference": {
                            "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                            "id_token_signed_response_alg": "ES256",
                            "token_endpoint_auth_method": "client_secret_basic",
                            "token_endpoint_auth_signing_alg": "ES256"
                        }
                    },
                    "services": oidc_service
                }
            }
        }

        self.combo = FederationCombo(LEAF_CONFIG)

    def test(self):
        assert self.combo.get_metadata() == {
            'federation_entity': {'contacts': 'operations@ta.example.com',
                                  'federation_fetch_endpoint': 'https://anchor.example.com/fetch',
                                  'federation_list_endpoint': 'https://anchor.example.com/list',
                                  'federation_resolve_endpoint': 'https://anchor.example.com/resolve',
                                  'homepage_uri': 'https://ta.example.com',
                                  'organization_name': 'The example federation operator'},
            'openid_relying_party': {'application_type': 'web',
                                     'grant_types': ['authorization_code'],
                                     'jwks_uri': 'https://anchor.example.com/static/jwks.json',
                                     'redirect_uris': ['https://example.com/cli/authz_cb'],
                                     'response_types': ['code']}}

        # IN this case the Combo has no keys, The federation entity and the openid relying party has
        # separate keyjars. Same initial key owner IDs in both keyjars.
        assert self.combo.keyjar == None
        for _name, _item in self.combo._part.items():
            assert set(_item.keyjar.owners()) == {'', 'https://anchor.example.com'}

        _resp = self.combo._part['federation_entity'].get_endpoint(
            'entity_configuration').process_request()
        _ec = _resp['response']
        assert _ec
        _jws = factory(_ec)
        _payload = _jws.jwt.payload()
        assert set(_payload.keys()) == {'exp', 'authority_hints', 'sub',
                                        'metadata', 'iss', 'jwks', 'iat'}
