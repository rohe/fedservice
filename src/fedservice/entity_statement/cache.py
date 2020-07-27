import logging

from cryptojwt.jwt import utc_time_sans_frac
from oidcendpoint.util import importer

logger = logging.getLogger(__name__)


class ESCache(object):
    def __init__(self, db, allowed_delta=300):
        self._db = db
        self.allowed_delta = allowed_delta

    # def get_db(self, db_conf=None):
    #     if db_conf:
    #         _kwargs = db_conf.get("kwargs", {})
    #         return importer(db_conf["class"])(**_kwargs)
    #     else:
    #         return {}

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

    def __contains__(self, item):
        _val = self[item]
        if _val:
            return True
        else:
            return False

    def keys(self):
        return self._db.keys()

    def __len__(self):
        return len(self._db)
