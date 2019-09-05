import logging

from cryptojwt.jwt import utc_time_sans_frac

__author__ = 'roland'

logger = logging.getLogger(__name__)


class Statement(object):
    """
    Class in which to store the parse result from applying metadata policies on a
    metadata statement.
    """

    def __init__(self, exp=0, signing_keys=None, verified_chain=None):
        """
        :param exp: Expiration time
        """
        self.fo = ""
        self.iss_path = []
        self.err = {}
        self.metadata = {}
        self.exp = exp
        self.signing_keys = signing_keys
        self.verified_chain = verified_chain

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

