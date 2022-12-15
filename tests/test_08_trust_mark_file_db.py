import os

from cryptojwt.jwt import utc_time_sans_frac

from fedservice.trust_mark_issuer import FileDB
from fedservice.trust_mark_issuer import SimpleDB

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def test_add_and_find():
    file_name = os.path.join(BASE_PATH, 'sirtfi')
    try:
        os.unlink(file_name)
    except FileNotFoundError:
        pass

    _db = FileDB(**{
        "https://refeds.org/sirtfi": file_name
    })

    _db.add(
        {'id': "https://refeds.org/sirtfi", "sub": "https://example.com",
         'iat': utc_time_sans_frac()}
    )

    res = _db.find("https://refeds.org/sirtfi", sub="https://example.com")
    assert res


def test_dump_load():
    file_name = os.path.join(BASE_PATH, 'sirtfi')
    try:
        os.unlink(file_name)
    except FileNotFoundError:
        pass

    _db = FileDB(**{
        "https://refeds.org/sirtfi": file_name
    })

    _db.add(
        {'id': "https://refeds.org/sirtfi", "sub": "https://example.com",
         'iat': utc_time_sans_frac()}
    )

    _db.add(
        {'id': "https://refeds.org/sirtfi", "sub": "https://example.org",
         'iat': utc_time_sans_frac()}
    )

    _dump = _db.dumps()

    _sdb = SimpleDB()
    _sdb.loads(_dump)

    _dump2 = _sdb.dumps()

    try:
        os.unlink(file_name)
    except FileNotFoundError:
        pass

    _db2 = FileDB(**{"https://refeds.org/sirtfi": file_name})
    _db2.loads(_dump2)

    _dump = _db.dump()
    assert set(_dump.keys()) == {"https://refeds.org/sirtfi"}
    assert len(_dump["https://refeds.org/sirtfi"]) == 2
