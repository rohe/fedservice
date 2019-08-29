from fedservice.entity_statement.statement import Statement


def test_le_init():
    le = Statement()
    assert le.flatten({'foo': 'bar'})


def test_le_string():
    sup = Statement()
    sup.flatten({'foo': 'bar'})
    le = Statement(sup=sup)
    assert le.flatten({'foo': 'bar'})
    assert le.flatten({'foo': 'box'}) is False
    assert le.flatten({'foo': 'BAR'}) is False


def test_more():
    sup = Statement()
    sup.flatten({'foo': 'bar'})
    le = Statement(sup=sup)
    assert le.flatten({'foo': 'bar', 'fox': 'hound'})
    assert le.claims() == {'foo': 'bar', 'fox': 'hound'}


def test_list():
    sup = Statement()
    sup.flatten({'foo': ['bar', 'stol']})
    le = Statement(sup=sup)
    assert le.flatten({'foo': ['bar']})
    assert le.claims() == {'foo': ['bar']}
