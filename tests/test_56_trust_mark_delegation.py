from urllib.parse import urlparse

import pytest
import responses
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from fedservice.message import TrustMarkRequest

from fedservice.defaults import LEAF_ENDPOINT
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.build_entity import FederationEntityBuilder
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.entity import FederationEntity
from fedservice.entity.server.status import TrustMarkStatus
from fedservice.trust_mark_issuer import TrustMarkIssuer
from fedservice.utils import statement_is_expired
from tests import create_trust_chain_messages

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()

TA_ID = "https://ta.example.org"
TMI_ID = "https://tmi.example.org"
FE_ID = "https://tmi.example.org"

TRUST_MARK_OWNERS_KEYS = build_keyjar(DEFAULT_KEY_DEFS)
TM_OWNERS_ID = "https://tm_owner.example.org"

SIRTIFI_TRUST_MARK_ID = "https://refeds.org/sirtfi"


@pytest.fixture()
def tm_receiver():
    return "https://op.ntnu.no"


@pytest.fixture()
def trust_mark_delegation(tm_receiver):
    _jwt = JWT(TRUST_MARK_OWNERS_KEYS, iss=TM_OWNERS_ID, sign_alg='RS256')
    return _jwt.pack({'sub': TMI_ID})


class TestTrustMarkDelegation():

    @pytest.fixture(autouse=True)
    def setup(self):
        TA = FederationEntityBuilder(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com",
                "trust_mark_owners": {
                    SIRTIFI_TRUST_MARK_ID: {'jwks': TRUST_MARK_OWNERS_KEYS.export_jwks(),
                                            'sub': TM_OWNERS_ID}
                },
                "trust_mark_issuers": {
                    SIRTIFI_TRUST_MARK_ID: TMI_ID
                }
            },
            key_conf={"key_defs": DEFAULT_KEY_DEFS}
        )
        TA.add_endpoints(None, **TA_ENDPOINTS)

        self.ta = FederationEntity(**TA.conf)

        # The trust mark issuer
        self.tmi = TrustMarkIssuer(trust_mark_specification={})
        # Federation entity with only status endpoint
        TM = FederationEntityBuilder(
            TMI_ID,
            preference={
                "organization_name": "Trust Mark Issuer 'R US"
            },
            key_conf={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID]
        )
        TM.add_endpoints(
            status={
                "path": "status",
                "class": TrustMarkStatus,
                "kwargs": {
                    'trust_mark_issuer': self.tmi
                }
            },
            entity_configuration={
                "path": ".well-known/openid-federation",
                "class": 'fedservice.entity.server.entity_configuration.EntityConfiguration',
                "kwargs": {}
            }
        )
        TM.add_functions()
        TM.add_services()

        self.trust_mark_issuer = FederationEntity(**TM.conf)

        self.ta.server.subordinate[TMI_ID] = {
            "jwks": self.trust_mark_issuer.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        FE = FederationEntityBuilder(
            FE_ID,
            preference={
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            key_conf={"key_defs": DEFAULT_KEY_DEFS},
            authority_hints=[TA_ID]
        )
        FE.add_services()
        FE.add_functions()
        FE.add_endpoints(**LEAF_ENDPOINT)
        FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = {TA_ID: self.ta.keyjar.export_jwks()}

        self.federation_entity = FederationEntity(**FE.conf)

    @pytest.fixture()
    def create_trust_mark(self, trust_mark_delegation, tm_receiver):
        self.tmi.trust_mark_specification[SIRTIFI_TRUST_MARK_ID] = {
            "delegation": trust_mark_delegation}
        return self.tmi.create_trust_mark(SIRTIFI_TRUST_MARK_ID, tm_receiver)

    def test_delegated_trust_mark(self, create_trust_mark):
        _trust_mark = create_trust_mark
        _jwt = factory(_trust_mark)
        assert 'delegation' in _jwt.jwt.payload()
        _delegation = factory(_jwt.jwt.payload()['delegation'])
        assert _delegation.jwt.payload()['iss'] == TM_OWNERS_ID
        assert _jwt.jwt.payload()['iss'] == TMI_ID
        assert _delegation.jwt.payload()['sub'] == TMI_ID

    def test_verify_trust_mark(self, create_trust_mark):
        _trust_mark = create_trust_mark

        # (1) verify signature and that it is still active
        # a) trust chain for trust mark issuer

        where_and_what = create_trust_chain_messages(self.trust_mark_issuer, self.ta)
        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            verified_trust_mark = self.federation_entity.function.trust_mark_verifier(
                trust_mark=_trust_mark, trust_anchor=self.ta.entity_id)

        assert verified_trust_mark

        # The collector hold all the entity statements/configurations that has been seen so far.
        _collector = self.federation_entity.function.trust_chain_collector

        # Ask the trust mark issuer if the trust mark is still valid
        # get the metadata for the issuer. Should be cached
        tm_issuer_metadata = _collector.get_metadata(TMI_ID)

        service = self.federation_entity.get_service('trust_mark_status')
        req = service.get_request_parameters(
            request_args={
                'sub': verified_trust_mark['sub'],
                'id': verified_trust_mark['id']
            },
            fetch_endpoint=tm_issuer_metadata['federation_entity'][
                'federation_trust_mark_status_endpoint']
        )
        p = urlparse(req['url'])
        tmr = TrustMarkRequest().from_urlencoded(p.query)

        # The response from the Trust Mark issuer
        resp = self.trust_mark_issuer.server.endpoint['status'].process_request(tmr.to_dict())
        assert resp == {'response': '{"active": true}'}
