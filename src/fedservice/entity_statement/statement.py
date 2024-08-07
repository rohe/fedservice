import logging
from typing import Optional

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.impexp import ImpExp

__author__ = 'roland'

logger = logging.getLogger(__name__)


class TrustChain(ImpExp):
    """
    Class in which to store the parsed result from applying metadata policies on a
    metadata statement.
    """

    parameter = {
        "anchor": "",
        "chain": [],
        "combined_policy": {},
        "err": {},
        "exp": 0,
        "iss_path": [],
        "metadata": {},
        "verified_chain": []
    }

    def __init__(self,
                 anchor: Optional[str] = "",
                 chain: Optional[list] = None,
                 combined_policy: Optional[dict] = None,
                 err: Optional[dict] = None,
                 exp: Optional[int] = 0,
                 iss_path: Optional[list] = None,
                 metadata: Optional[dict] = None,
                 verified_chain: Optional[list] = None,
                 ):
        """
        :param anchor: The trust anchor for this trust chain
        :param chain: The trust chain
        :param combined_policy: The combined metadata policy
        :param err: Errors that occured while processing the trust chain
        :param exp: Expiration time
        :param iss_path: The entity identifiers of the entities in the trust chain. The TA last
        :param metadata: The entity metadata
        :param: Verified chain of Entity configurations and Subordinate statements
        """
        ImpExp.__init__(self)
        self.anchor = anchor
        self.iss_path = iss_path or []
        self.err = err or {}
        self.metadata = metadata or {}
        self.exp = exp
        self.verified_chain = verified_chain
        self.combined_policy = {}

    def keys(self):
        return self.metadata.keys()

    def items(self):
        return self.metadata.items()

    def __getitem__(self, item):
        return self.metadata[item]

    def __contains__(self, item):
        return item in self.metadata

    def claims(self):
        """
        The result after flattening the statements
        """
        return self.metadata

    def is_expired(self):
        now = utc_time_sans_frac()
        if self.exp < now:
            logger.debug(f'is_expired: {self.exp} < {now}')
            return True
        else:
            return False

    def export_chain(self):
        """
        Exports the verified chain in such a way that it can be used as value on the
        trust_chain claim in an authorization or explicit registration request.
        :return:
        """
        _chain = self.verified_chain
        _chain.reverse()
        return _chain


def chains2dict(trust_chains: TrustChain) -> dict:
    """
    Converts a list of trust chains to a dictionary with the trust anchors entity_id as key.
    If there are more than one trust chain that has the same trust anchor the one with the
    shortest verified_chain are preferred.

    :param trust_chains: list of TrustChain instances
    :return: dictionary with trust anchor entity ids are keys and TrustChain instances as values
    """
    res = {}
    for trust_chain in trust_chains:
        if trust_chain.anchor in res:
            if len(trust_chain.verified_chain) < len(res[trust_chain.anchor].verified_chain):
                res[trust_chain.anchor] = trust_chain
        else:
            res[trust_chain.anchor] = trust_chain
    return res
