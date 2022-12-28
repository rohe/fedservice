from urllib.parse import urlparse

from cryptojwt.jws.jws import factory
import pytest
import responses

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.entity import FederationEntity
from fedservice.entity.server.status import TrustMarkStatus
from fedservice.message import TrustMark
from fedservice.message import TrustMarkRequest
from fedservice.trust_mark_issuer import TrustMarkIssuer
from tests import create_trust_chain_messages
from tests.build_entity import FederationEntityBuilder

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"
TA_ID = "https://anchor.example.com"

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()
del TA_ENDPOINTS["resolve"]

TRUST_MARK_ISSUER_ID = "https://entity.example.com"

class TestSignedTrustMark():

    @pytest.fixture(autouse=True)
    def create_entity(self):
        # The Trust Anchor
        TA = FederationEntityBuilder(
            TA_ID,
            metadata={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_conf={"key_defs": KEYSPEC}
        )
        TA.add_endpoints(**TA_ENDPOINTS)
        TA.add_services(trust_mark_status={
            "class": 'fedservice.entity.client.trust_mark_status.TrustMarkStatus',
            "kwargs": {}
        })

        self.ta = FederationEntity(**TA.conf)

        # The trust mark issuer
        self.tmi = TrustMarkIssuer(trust_mark_specification={})
        # Federation entity with only status endpoint
        TM = FederationEntityBuilder(
            TRUST_MARK_ISSUER_ID,
            metadata={
                "organization_name": "Trust Mark Issuer 'R US"
            },
            key_conf={"key_defs": KEYSPEC},
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

        self.entity = FederationEntity(**TM.conf)

        self.ta.server.subordinate[TRUST_MARK_ISSUER_ID] = {
            "jwks": self.entity.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

    def test_create_trust_mark_self_signed(self):
        _endpoint = self.entity.server.get_endpoint('status')
        _issuer = _endpoint.trust_mark_issuer
        _trust_mark = _issuer.self_signed_trust_mark(
            id='https://openid.net/certification',
            logo_uri=("http://openid.net/wordpress-content/uploads/2016/05/"
                      "oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg")
        )

        # Unpack and verify the Trust Mark
        _mark = _issuer.unpack_trust_mark(_trust_mark)

        assert isinstance(_mark, TrustMark)
        assert _mark["id"] == "https://openid.net/certification"
        assert _mark['iss'] == _mark['sub']
        assert _mark['iss'] == self.entity.entity_id
        assert set(_mark.keys()) == {'iss', 'sub', 'iat', 'id', 'logo_uri'}

    def test_create_unpack_trust_3rd_party(self):
        _sub = "https://op.ntnu.no"

        self.tmi.trust_mark_specification["https://refeds.org/sirtfi"] = {}
        _trust_mark = self.tmi.create_trust_mark("https://refeds.org/sirtfi", _sub)

        _mark = self.tmi.unpack_trust_mark(_trust_mark, _sub)

        assert isinstance(_mark, TrustMark)

    def test_process_request(self):
        _sub = "https://op.ntnu.no"
        _endpoint = self.entity.server.endpoint['status']
        _issuer = _endpoint.trust_mark_issuer
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {}
        _trust_mark = self.tmi.create_trust_mark("https://refeds.org/sirtfi", _sub)

        resp = _endpoint.process_request({'trust_mark': _trust_mark})
        assert resp == {'response': '{"active": true}'}

    def test_request_response_mark(self):
        _sub = "https://op.ntnu.no"
        _endpoint = self.entity.server.endpoint['status']
        _issuer = _endpoint.trust_mark_issuer
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {}
        _trust_mark = self.tmi.create_trust_mark("https://refeds.org/sirtfi", _sub)

        _jws = factory(_trust_mark)
        _payload = _jws.jwt.payload()
        resp = self.entity.server.endpoint['status'].process_request(_payload)
        assert resp == {'response': '{"active": true}'}

    def test_request_response_args(self):
        # Create a Trust Mark
        _sub = "https://op.ntnu.no"
        _endpoint = self.entity.server.endpoint['status']
        _issuer = _endpoint.trust_mark_issuer
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {}
        _trust_mark = self.tmi.create_trust_mark("https://refeds.org/sirtfi", _sub)

        # Ask for a verification of the Trust Mark
        _jws = factory(_trust_mark)
        _payload = _jws.jwt.payload()

        tms = self.ta.get_service('trust_mark_status')
        req = tms.get_request_parameters(
            request_args={
                'sub': _payload['sub'],
                'id': _payload['id']
            },
            fetch_endpoint=self.entity.server.endpoint['status'].full_path
        )
        p = urlparse(req['url'])
        tmr = TrustMarkRequest().from_urlencoded(p.query)

        resp = self.entity.server.endpoint['status'].process_request(tmr.to_dict())
        assert resp == {'response': '{"active": true}'}

    def test_trust_mark_verifier(self):
        _endpoint = self.entity.server.endpoint['status']
        _issuer = _endpoint.trust_mark_issuer
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {}

        _trust_mark = _issuer.create_trust_mark(id="https://refeds.org/sirtfi",
                                                sub=self.entity.entity_id,
                                                ref='https://refeds.org/sirtfi')

        where_and_what = create_trust_chain_messages(self.entity, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            verified_trust_mark = self.entity.function.trust_mark_verifier(_trust_mark)

        assert verified_trust_mark
        assert set(verified_trust_mark.keys()) == {'iat','iss','id','sub','ref'}
