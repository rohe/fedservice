from fedservice.le import LessOrEqual


def test_le_init():
    le = LessOrEqual()
    assert le.eval({'foo': 'bar'})


def test_le_string():
    sup = LessOrEqual()
    sup.eval({'foo': 'bar'})
    le = LessOrEqual(sup=sup)
    assert le.eval({'foo': 'bar'})
    assert le.eval({'foo': 'box'}) is False
    assert le.eval({'foo': 'BAR'}) is False


def test_more():
    sup = LessOrEqual()
    sup.eval({'foo': 'bar'})
    le = LessOrEqual(sup=sup)
    assert le.eval({'foo': 'bar', 'fox': 'hound'})
    assert le.protected_claims() == {'foo': 'bar'}
    assert le.unprotected_and_protected_claims() == {'foo': 'bar',
                                                     'fox': 'hound'}


def test_list():
    sup = LessOrEqual()
    sup.eval({'foo': ['bar', 'stol']})
    le = LessOrEqual(sup=sup)
    assert le.eval({'foo': ['bar']})
    assert le.unprotected_and_protected_claims() == {'foo': ['bar']}
