import logging

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.impexp import ImpExp

logger = logging.getLogger(__name__)


class ESCache(ImpExp):
    parameter = {
        "_db": {},
        "allowed_delta": 0
    }

    def __init__(self, allowed_delta=300):
        ImpExp.__init__(self)
        self._db = {}
        self.allowed_delta = allowed_delta

    def __setitem__(self, key, value):
        self._db[key] = value

    def __getitem__(self, item):
        try:
            statement = self._db[item]
        except KeyError:
            return None
        else:
            if isinstance(statement, dict):
                # verify that the statement is recent enough
                _now = utc_time_sans_frac()
                if _now < (statement["exp"] - self.allowed_delta):
                    return statement
                else:
                    del self._db[item]
                    return None
            else:
                return statement

    def __delitem__(self, key):
        del self._db[key]

    def keys(self):
        return self._db.keys()

    def __len__(self):
        return len(self._db)

    def __contains__(self, item):
        return item in self._db