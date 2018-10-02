from fedservice.entity_statement.le import Statement


def test_le_init():
    le = Statement()
    assert le.restrict({'foo': 'bar'})


def test_le_string():
    sup = Statement()
    sup.restrict({'foo': 'bar'})
    le = Statement(sup=sup)
    assert le.restrict({'foo': 'bar'})
    assert le.restrict({'foo': 'box'}) is False
    assert le.restrict({'foo': 'BAR'}) is False


def test_more():
    sup = Statement()
    sup.restrict({'foo': 'bar'})
    le = Statement(sup=sup)
    assert le.restrict({'foo': 'bar', 'fox': 'hound'})
    assert le.protected_claims() == {'foo': 'bar'}
    assert le.unprotected_and_protected_claims() == {'foo': 'bar',
                                                     'fox': 'hound'}


def test_list():
    sup = Statement()
    sup.restrict({'foo': ['bar', 'stol']})
    le = Statement(sup=sup)
    assert le.restrict({'foo': ['bar']})
    assert le.unprotected_and_protected_claims() == {'foo': ['bar']}
