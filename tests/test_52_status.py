import pytest
import responses
from fedservice.trust_mark_issuer import TrustMarkIssuer
from idpyoidc.util import rndstr

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.defaults import TRUST_MARK_ISSUER_ENDPOINTS
from fedservice.entity import FederationEntity
from fedservice.trust_mark_issuer import create_trust_mark
from tests import create_trust_chain_messages
from tests.build_entity import FederationEntityBuilder

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()
del TA_ENDPOINTS["resolve"]

TA_ID = "https://ta.example.org"
RP_ID = "https://rp.example.org"
TRUST_MARK_ISSUER_ID = "https://trust_mark_issuer.example.org"
IM_ID = "https://im.example.org"

TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"


class TestComboCollect(object):

    @pytest.fixture(autouse=True)
    def setup(self):
        #     Federation tree
        #
        #            TA
        #        +---|-------+
        #        |           |
        #        IM      TRUST_MARK_ISSUER
        #        |
        #        RP

        ########################################
        # Trust Anchor
        ########################################

        TA = FederationEntityBuilder(
            TA_ID,
            metadata={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_conf={"key_defs": KEYDEFS}
        )
        TA.add_endpoints(None, **TA_ENDPOINTS)

        TA.conf['server']['kwargs']['endpoint']['status']['kwargs'][
            'trust_mark_issuer'] = {
            'class': TrustMarkIssuer,
            'kwargs': {
                'key_conf': {"key_defs": KEYDEFS}
            }
        }

        self.ta = FederationEntity(**TA.conf)

        ANCHOR = {TA_ID: self.ta.keyjar.export_jwks()}

        ########################################
        # intermediate
        ########################################

        INT = FederationEntityBuilder(
            IM_ID,
            metadata={
                "organization_name": "The organization",
                "homepage_uri": "https://example.com",
                "contacts": "operations@example.com"
            },
            key_conf={"key_defs": KEYDEFS},
            authority_hints=[TA_ID]
        )
        INT.add_services()
        INT.add_functions()
        INT.add_endpoints()

        # Intermediate
        self.im = FederationEntity(**INT.conf)

        ########################################
        # Leaf RP
        ########################################

        RP_FE = FederationEntityBuilder(
            RP_ID,
            metadata={
                "organization_name": "The RP",
                "homepage_uri": "https://rp.example.com",
                "contacts": "operations@rp.example.com"
            },
            key_conf={"key_defs": KEYDEFS},
            authority_hints=[TA_ID]
        )
        RP_FE.add_services()
        RP_FE.add_functions()
        RP_FE.add_endpoints(**LEAF_ENDPOINT)
        RP_FE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
            'trust_anchors'] = ANCHOR

        self.rp = FederationEntity(**RP_FE.conf)

        ########################################
        # Trust Mark Issuer
        ########################################

        TMI = FederationEntityBuilder(
            entity_id=TRUST_MARK_ISSUER_ID,
            key_conf={'key_defs': KEYDEFS},
            metadata={
                "organization_name": "The Trust Mark Issuer",
                "homepage_uri": "https://tmi.example.com",
                "contacts": "operations@tmi.example.com"
            },
            authority_hints=[TA_ID]
        )
        # default endpoint = status
        _endpoints = TRUST_MARK_ISSUER_ENDPOINTS
        _endpoints['status']['kwargs']['trust_marks'] = {
            TM_ID: {"ref": "https://refeds.org/sirtfi"}}
        TMI.add_endpoints(**TRUST_MARK_ISSUER_ENDPOINTS)
        TMI.conf['server']['kwargs']['endpoint']['status']['kwargs'][
            'trust_mark_issuer'] = {
            'class': TrustMarkIssuer,
            'kwargs': {
                'key_conf': {"key_defs": KEYDEFS}
            }
        }

        self.tmi = FederationEntity(**TMI.conf)

        self.ta.server.subordinate[IM_ID] = {
            "jwks": self.im.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }
        self.ta.server.subordinate[TRUST_MARK_ISSUER_ID] = {
            "jwks": self.tmi.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        self.im.server.subordinate[RP_ID] = {
            "jwks": self.rp.keyjar.export_jwks(),
            'authority_hints': [IM_ID]
        }

    def test_setup(self):
        assert self.ta
        assert self.ta.server
        assert set(self.ta.server.subordinate.keys()) == {TRUST_MARK_ISSUER_ID, IM_ID}

    def test_trust_mark_verifier(self):
        where_and_what = create_trust_chain_messages(self.tmi, self.ta)

        _trust_mark = create_trust_mark(entity_id=self.tmi.entity_id,
                                        keyjar=self.tmi.get_attribute('keyjar'),
                                        id=rndstr(),
                                        sub=self.rp.entity_id,
                                        lifetime=3600,
                                        reference='https://refeds.org/sirtfi')

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            verified_trust_mark = self.rp.function.trust_mark_verifier(_trust_mark)

        assert verified_trust_mark
