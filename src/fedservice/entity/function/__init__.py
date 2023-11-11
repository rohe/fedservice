import logging
from typing import Callable
from typing import List
from typing import Optional

from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar
from idpyoidc.impexp import ImpExp

from fedservice.entity.utils import get_federation_entity

logger = logging.getLogger(__name__)


def unverified_entity_statement(signed_jwt):
    _jws = factory(signed_jwt)
    return _jws.jwt.payload()


def verify_self_signed_signature(token):
    """
    Verify signature using only keys in the entity statement.
    Will raise exception if signature verification fails.

    :param token: Signed JWT
    :return: Payload of the signed JWT
    """

    payload = unverified_entity_statement(token)
    keyjar = KeyJar()
    keyjar.import_jwks(payload['jwks'], payload['iss'])

    _jwt = JWT(key_jar=keyjar)
    _val = _jwt.unpack(token)
    _val["_jws"] = token
    return _val


def tree2chains(unit):
    res = []
    for issuer, branch in unit.items():
        if branch is None:
            res.append([])
            continue

        (statement, unit) = branch
        if not unit:
            res.append([statement])
            continue

        _lists = tree2chains(unit)
        for l in _lists:
            l.append(statement)

        if not res:
            res = _lists
        else:
            res.extend(_lists)
    return res


def collect_trust_chains(unit,
                         entity_id: str,
                         signed_entity_configuration: Optional[str] = "",
                         stop_at: Optional[str] = "",
                         authority_hints: Optional[list] = None):
    _federation_entity = get_federation_entity(unit)

    _collector = _federation_entity.function.trust_chain_collector

    # Collect the trust chains
    if signed_entity_configuration:
        entity_configuration = verify_self_signed_signature(signed_entity_configuration)
        if authority_hints:
            entity_configuration["authority_hints"] = authority_hints
        tree = _collector.collect_tree(entity_id, entity_configuration, stop_at=stop_at)
    else:
        _collector_response = _collector(entity_id, stop_at=stop_at)
        if _collector_response:
            tree, signed_entity_configuration = _collector_response
        else:
            tree = None

    if tree:
        chains = tree2chains(tree)
        logger.debug("%d chains", len(chains))
        return chains, signed_entity_configuration
    else:
        return [], None


def verify_trust_chains(unit, chains: List[List[str]], *entity_statements):
    #
    _verifier = get_federation_entity(unit).function.verifier

    logger.debug("verify_trust_chains")
    res = []
    for c in chains:
        if entity_statements:
            c.extend(entity_statements)
        trust_chain = _verifier(c)
        if trust_chain:
            res.append(trust_chain)
    return res


def apply_policies(unit, trust_chains):
    """
    Goes through the collected trust chains, verifies them and applies policies.

    :param unit: A Unit instance
    :param trust_chains: List of TrustChain instances
    :return: List of processed TrustChain instances
    """
    _policy_applier = get_federation_entity(unit).function.policy

    res = []
    for trust_chain in trust_chains:
        _policy_applier(trust_chain)
        res.append(trust_chain)
    return res


def get_payload(self_signed_statement):
    _jws = as_unicode(self_signed_statement)
    _jwt = factory(_jws)
    return _jwt.jwt.payload()


class Function(ImpExp):

    def __init__(self, upstream_get: Callable):
        ImpExp.__init__(self)
        self.upstream_get = upstream_get


def get_verified_trust_chains(unit, entity_id):
    chains, leaf_ec = collect_trust_chains(unit, entity_id)
    if len(chains) == 0:
        return []

    trust_chains = verify_trust_chains(unit, chains, leaf_ec)
    trust_chains = apply_policies(unit, trust_chains)
    return trust_chains


def get_entity_endpoint(unit, entity_id, metadata_type, metadata_parameter):
    # get endpoint from the Entity Configuration

    trust_chains = get_verified_trust_chains(unit, entity_id)
    # pick one
    if trust_chains:
        return trust_chains[0].metadata[metadata_type][metadata_parameter]
    else:
        return ""
