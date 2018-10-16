import logging
from copy import copy

from cryptojwt.jwt import utc_time_sans_frac

__author__ = 'roland'

logger = logging.getLogger(__name__)


def is_singleton(a):
    if isinstance(a, int) or isinstance(a, str) or isinstance(a, bool):
        return True


def is_lesser(a, b):
    """
    Verify that a is <= then b

    :param a: An item
    :param b: Another item
    :return: True or False
    """

    if type(a) != type(b):
        if isinstance(b, list) and is_singleton(a):
            a = [a]
        else:
            return False

    if isinstance(a, str) and isinstance(b, str):
        return a == b
    elif isinstance(a, bool) and isinstance(b, bool):
        return a == b
    elif isinstance(a, list) and isinstance(b, list):
        for element in a:
            flag = 0
            for e in b:
                if is_lesser(element, e):
                    flag = 1
                    break
            if not flag:
                return False
        return True
    elif isinstance(a, dict) and isinstance(b, dict):
        if is_lesser(list(a.keys()), list(b.keys())):
            for key, val in a.items():
                if not is_lesser(val, b[key]):
                    return False
            return True
        return False
    elif isinstance(a, int) and isinstance(b, int):
        return a <= b
    elif isinstance(a, float) and isinstance(b, float):
        return a <= b

    return False


class Statement(object):
    """
    Class in which to store the parse result from flattening a compounded
    metadata statement.
    """

    def __init__(self, iss='', sup=None, exp=0, signing_keys=None, **kwargs):
        """
        :param iss: Issuer ID
        :param sup: Superior
        :type sup: LessOrEqual instance
        :param exp: Expiration time
        """
        if sup:
            self.fo = sup.fo
        else:
            self.fo = iss

        self.iss = iss
        self.sup = sup
        self.err = {}
        self.le = {}
        self.exp = exp
        self.signing_keys = signing_keys

    def __setitem__(self, key, value):
        self.le[key] = value

    def keys(self):
        return self.le.keys()

    def items(self):
        return self.le.items()

    def __getitem__(self, item):
        return self.le[item]

    def __contains__(self, item):
        return item in self.le

    def sup_items(self):
        """
        Items (key+values) from the superior
        """
        if self.sup:
            return self.sup.le.items()
        else:
            return {}

    def restrict(self, orig, strict=True):
        """
        Apply the less or equal algorithm on the ordered list of metadata
        statements

        :param orig: Start values
        :param strict: Whether the evaluation should be strict, that is return
            an error if a subordinate tries to register something that is
            not less or equal to what the subordinates has said or just
            ignore what the client specifies.
        :return:
        """
        _le = {}
        _err = []
        for k, v in self.sup_items():
            if k in orig:
                if is_lesser(orig[k], v):
                    _le[k] = orig[k]
                else:
                    _err.append(
                        {'claim': k, 'policy': orig[k], 'err': v,
                         'signer': self.iss})
                    if not strict:
                        _le[k] = v
            else:
                _le[k] = v

        for k, v in orig.items():
            if k not in _le:
                _le[k] = v

        self.le = _le
        self.err = _err

        if strict and _err:
            return False
        else:
            return True

    def protected_claims(self):
        """
        Someone in the list of signers has said this information is OK
        """
        if self.sup:
            return self.sup.le

    def unprotected_and_protected_claims(self):
        """
        This is both verified and self asserted information. As expected
        verified information beats self-asserted so if there is both
        self-asserted and verified values for a claim then only the verified
        will be returned.
        """
        if self.sup:
            res = copy(self.le)
            for k, v in self.sup.le.items():
                if k not in self.le:
                    res[k] = v
            return res
        else:
            return self.le

    def is_expired(self):
        now = utc_time_sans_frac()
        if self.exp < now:
            logger.debug('is_expired: {} < {}'.format(self.exp, now))
            return True
        if self.sup:
            return self.sup.is_expired()
        else:
            return False

