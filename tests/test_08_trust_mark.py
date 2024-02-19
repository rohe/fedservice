from urllib.parse import urlparse

import pytest
import responses
from cryptojwt.jws.jws import factory

from fedservice.defaults import INTERMEDIATE_ENDPOINTS
from fedservice.message import TrustMark
from fedservice.message import TrustMarkRequest
from fedservice.utils import make_federation_combo
from fedservice.utils import make_federation_entity
from tests import create_trust_chain_messages

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TM_ID = "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"
TA_ID = "https://anchor.example.com"

TA_ENDPOINTS = INTERMEDIATE_ENDPOINTS.copy()

TRUST_MARK_ISSUER_ID = "https://entity.example.com"


class TestSignedTrustMark():

    @pytest.fixture(autouse=True)
    def create_entity(self):
        # The Trust Anchor
        self.ta = make_federation_entity(
            TA_ID,
            preference={
                "organization_name": "The example federation operator",
                "homepage_uri": "https://ta.example.com",
                "contacts": "operations@ta.example.com"
            },
            key_config={"key_defs": KEYSPEC},
            endpoints=TA_ENDPOINTS,
            services=["trust_mark_status"]
        )

        # Federation entity with only status endpoint
        self.entity = make_federation_combo(
            TRUST_MARK_ISSUER_ID,
            preference={
                "organization_name": "Trust Mark Issuer 'R US"
            },
            key_config={"key_defs": KEYSPEC},
            authority_hints=[TA_ID],
            trust_anchors={TA_ID: self.ta.keyjar.export_jwks()},
            endpoints=["entity_configuration"],
            trust_mark_entity={
                "class": "fedservice.trust_mark_entity.entity.TrustMarkEntity",
                "kwargs": {
                    "trust_mark_specification": {
                        "https://refeds.org/sirtfi": {
                            "lifetime": 2592000
                        }
                    },
                    "trust_mark_db": {
                        "class": "fedservice.trust_mark_entity.FileDB",
                        "kwargs": {
                            "https://refeds.org/sirtfi": "sirtfi",
                        }
                    },
                    "endpoint": {
                        "trust_mark": {
                            "path": "trust_mark",
                            "class": "fedservice.trust_mark_entity.server.trust_mark.TrustMark",
                            "kwargs": {
                                "client_authn_method": [
                                    "private_key_jwt"
                                ],
                                "auth_signing_alg_values": [
                                    "ES256"
                                ]
                            }
                        },
                        "trust_mark_list": {
                            "path": "trust_mark_list",
                            "class": "fedservice.trust_mark_entity.server.trust_mark_list.TrustMarkList",
                            "kwargs": {}
                        },
                        "trust_mark_status": {
                            "path": "trust_mark_status",
                            "class": "fedservice.trust_mark_entity.server.trust_mark_status.TrustMarkStatus",
                            "kwargs": {}
                        }
                    }
                }
            }
        )

        self.ta.server.subordinate[TRUST_MARK_ISSUER_ID] = {
            "jwks": self.entity.keyjar.export_jwks(),
            'authority_hints': [TA_ID]
        }

        #

    def test_create_trust_mark_self_signed(self):
        _endpoint = self.entity.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
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

        _tmi = self.entity.server.trust_mark_entity
        _trust_mark = _tmi.create_trust_mark("https://refeds.org/sirtfi", _sub)

        _mark = _tmi.unpack_trust_mark(_trust_mark, _sub)

        assert isinstance(_mark, TrustMark)

    def test_process_request(self):
        _sub = "https://op.ntnu.no"
        _endpoint = self.entity.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {}
        _trust_mark = _issuer.create_trust_mark("https://refeds.org/sirtfi", _sub)

        resp = _endpoint.process_request({'trust_mark': _trust_mark})
        assert resp == {'response_args': {'active': True}}

    def test_request_response_mark(self):
        _sub = "https://op.ntnu.no"
        _endpoint = self.entity.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _trust_mark = _issuer.create_trust_mark("https://refeds.org/sirtfi", _sub)

        _jws = factory(_trust_mark)
        _payload = _jws.jwt.payload()
        resp = self.entity.get_endpoint('trust_mark_status').process_request(_payload)
        assert resp == {'response_args': {'active': True}}

    def test_request_response_args(self):
        # Create a Trust Mark
        _sub = "https://op.ntnu.no"
        _endpoint = self.entity.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _trust_mark = _issuer.create_trust_mark("https://refeds.org/sirtfi", _sub)

        # Ask for a verification of the Trust Mark
        _jws = factory(_trust_mark)
        _payload = _jws.jwt.payload()

        tms = self.ta.get_service('trust_mark_status')
        req = tms.get_request_parameters(
            request_args={
                'sub': _payload['sub'],
                'id': _payload['id']
            },
            fetch_endpoint=self.entity.get_endpoint('trust_mark_status').full_path
        )
        p = urlparse(req['url'])
        tmr = TrustMarkRequest().from_urlencoded(p.query)

        resp = self.entity.get_endpoint('trust_mark_status').process_request(tmr.to_dict())
        assert resp == {'response_args': {'active': True}}

    def test_trust_mark_verifier(self):
        _endpoint = self.entity.get_endpoint('trust_mark_status')
        _issuer = _endpoint.upstream_get("unit")
        _issuer.trust_mark_specification["https://refeds.org/sirtfi"] = {
            "ref": 'https://refeds.org/sirtfi'
        }

        _trust_mark = _issuer.create_trust_mark(id="https://refeds.org/sirtfi",
                                                sub=self.entity.entity_id)

        where_and_what = create_trust_chain_messages(self.entity, self.ta)

        with responses.RequestsMock() as rsps:
            for _url, _jwks in where_and_what.items():
                rsps.add("GET", _url, body=_jwks,
                         adding_headers={"Content-Type": "application/json"}, status=200)

            verified_trust_mark = self.entity.function.trust_mark_verifier(
                trust_mark=_trust_mark, trust_anchor=self.ta.entity_id)

        assert verified_trust_mark
        assert set(verified_trust_mark.keys()) == {'iat', 'iss', 'id', 'sub', 'ref', 'exp'}

    def test_metadata(self):
        _metadata = self.entity.get_metadata()
        assert len(_metadata["federation_entity"]["jwks"]["keys"]) == 2
