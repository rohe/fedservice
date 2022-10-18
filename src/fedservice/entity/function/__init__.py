import logging
from typing import Callable
from typing import List
from typing import Optional

from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory
from idpyoidc.impexp import ImpExp

from fedservice.entity import FederationEntity
from fedservice.entity_statement.collect import verify_self_signed_signature

logger = logging.getLogger(__name__)


def tree2chains(Unit):
    res = []
    for issuer, branch in Unit.items():
        if branch is None:
            res.append([])
            continue

        (statement, Unit) = branch
        if not Unit:
            res.append([statement])
            continue

        _lists = tree2chains(Unit)
        for l in _lists:
            l.append(statement)

        if not res:
            res = _lists
        else:
            res.extend(_lists)
    return res


def collect_trust_chains(Unit,
                         entity_id: str,
                         signed_entity_configuration: Optional[str] = "",
                         stop_at: Optional[str] = "",
                         authority_hints: Optional[list] = None):
    if isinstance(Unit, FederationEntity):
        _federation_entity = Unit
    else:
        _federation_entity = Unit.upstream_get('unit')['federation_entity']

    _collector = _federation_entity.function.trust_chain_collector

    # Collect the trust chains
    if signed_entity_configuration:
        entity_configuration = verify_self_signed_signature(signed_entity_configuration)
        if authority_hints:
            entity_configuration["authority_hints"] = authority_hints
        tree = _collector.collect_tree(entity_id, entity_configuration, stop_at=stop_at)
    else:
        tree, signed_entity_configuration = _collector(entity_id, stop_at=stop_at)

    chains = tree2chains(tree)
    logger.debug("%d chains", len(chains))
    return chains, signed_entity_configuration


def verify_trust_chains(federation_entity, chains: List[List[str]], *entity_statements):
    #
    _verifier = federation_entity.function.verifier
    res = []
    for c in chains:
        if entity_statements:
            c.extend(entity_statements)
        trust_chain = _verifier(c)
        if trust_chain:
            res.append(trust_chain)
    return res


def apply_policies(federation_entity, trust_chains):
    """
    Goes through the collected trust chains, verifies them and applies policies.

    :param federation_entity: A FederationEntity instance
    :param trust_chains: List of TrustChain instances
    :param signed_entity_configuration: An Entity Configuration
    :return: List of processed TrustChain instances
    """
    _policy_applier = federation_entity.function.policy
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
