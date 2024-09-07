import pytest
import responses
from cryptojwt.jws.jws import factory
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES

from fedservice.appclient import ClientEntity
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINTS
from fedservice.entity.function import apply_policies
from fedservice.entity.function import verify_trust_chains
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages
from tests.build_federation import build_federation

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
IM_ID = "https://intermediate.example.org"

TA_ENDPOINTS = ["list", "fetch", "entity_configuration"]

FEDERATION_CONFIG = {
    TA_ID: {
        "entity_type": "trust_anchor",
        "subordinates": [IM_ID],
        "kwargs": {
            "preference": {
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.org",
                "contacts": "operations@ta.example.org"
            },
            "endpoints": ['entity_configuration', 'list', 'fetch', 'resolve'],
        }
    },
    IM_ID: {
        "entity_type": "intermediate",
        "trust_anchors": [TA_ID],
        "subordinates": [RP_ID],
        "kwargs": {
            "authority_hints": [TA_ID],
        }
    },
    RP_ID: {
        "entity_type": "openid_relying_party",
        "trust_anchors": [TA_ID],
        "kwargs": {
            "authority_hints": [IM_ID],
            "preference": {
                "organization_name": "The example federation RP operator",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            }
        }
    }
}
class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #     Federation tree
        #
        #    TA/RESOLVER
        #        |
        #        IM
        #        |
        #        RP

        federation = build_federation(FEDERATION_CONFIG)
        self.ta = federation[TA_ID]
        self.im = federation[IM_ID]
        self.rp = federation[RP_ID]


    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {IM_ID}

    def test_resolver(self):
        resolver = self.ta.server.endpoint["resolve"]

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

        # verify that I get the same result using the returned trust chain
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
