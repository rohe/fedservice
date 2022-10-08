import logging
from typing import List
from typing import Optional

from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac

__author__ = 'roland'

logger = logging.getLogger(__name__)


class TrustChain(object):
    """
    Class in which to store the parsed result from applying metadata policies on a
    metadata statement.
    """

    def __init__(self,
                 exp: int = 0,
                 signing_keys: Optional[List[KeyJar]] = None,
                 verified_chain: Optional[list] = None):
        """
        :param exp: Expiration time
        """
        self.anchor = ""
        self.iss_path = []
        self.err = {}
        self.metadata = {}
        self.exp = exp
        self.signing_keys = signing_keys
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
            logger.debug('is_expired: {} < {}'.format(self.exp, now))
            return True
        else:
            return False


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
