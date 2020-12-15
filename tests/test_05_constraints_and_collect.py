import json
import os

from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
import responses

from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.collect import construct_entity_statement_query
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.entity_statement.constraints import meets_restrictions
from fedservice.entity_statement.verify import verify_trust_chain

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def test_collect():
    jwks = open(os.path.join(BASE_PATH, 'base_data', 'feide.no', 'feide.no', 'jwks.json')).read()

    ANCHOR = {'https://feide.no': json.loads(jwks)}

    KEYJAR = KeyJar()
    KEYJAR.import_jwks_as_json(jwks, 'https://feide.no')

    chain = []
    _collector = Collector(trust_anchors=ANCHOR)
    subject = "foodle.uninett.no"
    with responses.RequestsMock() as rsps:
        _msg = open(os.path.join(BASE_PATH, 'base_data', subject, subject, 'jws')).read()
        rsps.add(rsps.GET, "https://foodle.uninett.no/.well-known/openid-federation", body=_msg)
        # Get the self-signed entity statement from a leaf
        _self_signed = _collector.get_configuration_information("https://foodle.uninett.no")

    chain.append(_self_signed)
    _statement = verify_self_signed_signature(_self_signed)
    assert _statement
    authority = ""

    while authority not in _collector.trusted_anchors:
        authority = _statement['authority_hints'][0]
        netloc = authority[8:]
        with responses.RequestsMock() as rsps:
            _msg = open(os.path.join(BASE_PATH, 'base_data', netloc, netloc, "jws")).read()
            _url = "https://{}/.well-known/openid-federation".format(netloc)
            rsps.add(rsps.GET, _url, body=_msg)
            # Get the self-signed entity statement from an entity
            _self_signed = _collector.get_configuration_information(authority)

        _statement = verify_self_signed_signature(_self_signed)
        assert _statement

        _api_endpoint = _statement['metadata']['federation_entity']['federation_api_endpoint']

        with responses.RequestsMock() as rsps:
            _msg = open(os.path.join(BASE_PATH, 'base_data', netloc, subject, "jws")).read()
            _url = construct_entity_statement_query(_api_endpoint, authority,
                                                    "https://{}".format(subject))
            rsps.add(rsps.GET, _url, body=_msg)
            # Get the self-signed entity statement from an authority about the subject
            _signed_statement = _collector.get_entity_statement(_api_endpoint, authority,
                                                                "https://{}".format(subject))
            chain.append(_signed_statement)
            _jwt = factory(_signed_statement)
            _statement = _jwt.jwt.payload()
            # Make the authority be the subject climbing up the chain.
            subject = _statement['iss'][8:]

    # Now I have the chain should be 3 items in it
    assert len(chain) == 3

    # verify the trust chain
    chain.reverse()
    verified_chain = verify_trust_chain(chain, KEYJAR)
    # The result is the verified statements
    assert len(verified_chain) == 3
    # Check that the constraints are met
    assert meets_restrictions(verified_chain)
