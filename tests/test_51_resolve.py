import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.entity import FederationEntity
from fedservice.entity.function import apply_policies
from fedservice.entity.function import verify_trust_chains
from fedservice.rp import ClientEntity
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages


TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
RESOLVER_ID = "https://resolver.example.org"
IM_ID = "https://intermediate.example.org"

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]

class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #     Federation tree
        #
        #            TA
        #        +---|-------+
        #        |           |
        #        IM      RESOLVER
        #        |
        #        RP

        # TRUST ANCHOR

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

        # intermediate

        self.im = make_federation_entity(
            IM_ID,
            preference={
                "organization_name": "The organization",
                "homepage_uri": "https://example.com",
                "contacts": "operations@example.com"
            },
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID],
            trust_anchors=ANCHOR
        )
        self.ta.server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        ########################################
        # Leaf RP
        ########################################

        oidc_service = DEFAULT_OIDC_SERVICES.copy()
        oidc_service.update(DEFAULT_OIDC_FED_SERVICES)

        self.rp = make_federation_combo(
            entity_id=RP_ID,
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            authority_hints=[IM_ID],
            endpoints=LEAF_ENDPOINTS,
            trust_anchors=ANCHOR,
            additional_conf={
                "openid_relying_party": {
                    'class': ClientEntity,
                    'kwargs': {
                        'config': {
                            'client_id': RP_ID,
                            'client_secret': 'a longesh password',
                            'redirect_uris': ['https://example.com/cli/authz_cb'],
                            "keys": {"uri_path": "static/jwks.json", "key_defs": DEFAULT_KEY_DEFS},
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
        )
        self.im.server.subordinate[RP_ID] = {
            "jwks": self.rp["federation_entity"].keyjar.export_jwks(),
            'authority_hints': [IM_ID]
        }

        # Resolver

        self.resolver = make_federation_entity(
            entity_id=RP_ID,
            key_config={"key_defs": DEFAULT_KEY_DEFS},
            preference={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            authority_hints=[TA_ID],
            endpoints=["entity_configuration", "fetch", "resolve"],
            trust_anchors=ANCHOR
        )

        self.ta.server.subordinate[RESOLVER_ID] = {
            "jwks": self.resolver.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }


    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {RESOLVER_ID, IM_ID}

    def test_resolver(self):
        resolver = self.resolver.server.endpoint["resolve"]

        where_and_what = create_trust_chain_messages(self.rp, self.im, self.ta)

        resolver_query = {'sub': self.rp.entity_id,
                          'anchor': self.ta.entity_id}

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            response = resolver.process_request(resolver_query)

        assert response
        _jws = factory(response["response_args"])
        payload = _jws.jwt.payload()
        assert set(payload.keys()) == {'sub', 'iss', 'iat', 'exp', 'metadata', 'trust_chain',
                                       'jwks'}
        assert set(payload['metadata'].keys()) == {'federation_entity', 'openid_relying_party'}
        assert len(payload['trust_chain']) == 3

        # verify that I get the same result using the return trust chain
        # Since what I got was EC+[ES]* where the last ES is from the Trust Anchor I have to
        # reverse the order.
        payload['trust_chain'].reverse()
        _trust_chains = verify_trust_chains(self.rp, [payload['trust_chain']])
        assert len(_trust_chains) == 1
        assert _trust_chains[0].anchor == self.ta.entity_id
        assert _trust_chains[0].iss_path == [self.rp.entity_id, self.im.entity_id,
                                             self.ta.entity_id]

        _trust_chains = apply_policies(self.rp, _trust_chains)
        assert _trust_chains[0].metadata == payload['metadata']
