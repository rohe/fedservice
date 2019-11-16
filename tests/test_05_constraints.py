from fedservice.entity_statement.constraints import calculate_path_length
from fedservice.entity_statement.constraints import excluded
from fedservice.entity_statement.constraints import permitted
from fedservice.entity_statement.constraints import update_naming_constraints
from fedservice.message import Constraints
from fedservice.message import NamingConstraints


def test_max_path_length_start():
    current_max_path_length = 0
    max_assigned = False
    constraints = Constraints(max_path_length=1)
    current_max_path_length = calculate_path_length(constraints, current_max_path_length,
                                                    max_assigned)
    assert current_max_path_length == 1


def test_max_path_length_decrease():
    current_max_path_length = 2
    max_assigned = True
    constraints = Constraints(max_path_length=1)
    current_max_path_length = calculate_path_length(constraints, current_max_path_length,
                                                    max_assigned)
    assert current_max_path_length == 1


def test_max_path_length_ignore():
    current_max_path_length = 2
    max_assigned = True
    constraints = Constraints(max_path_length=3)
    current_max_path_length = calculate_path_length(constraints, current_max_path_length,
                                                    max_assigned)
    assert current_max_path_length == 1


def test_max_path_length_no():
    current_max_path_length = 2
    max_assigned = True
    constraints = Constraints()
    current_max_path_length = calculate_path_length(constraints, current_max_path_length,
                                                    max_assigned)
    assert current_max_path_length == 1


def test_naming_constr_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(permitted=["https://.example.com"],
                                            excluded=["https://east.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.com"]
    assert naming_constraints["excluded"] == ["https://east.example.com"]


def test_naming_constr_perm_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(permitted=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.com"]
    assert naming_constraints["excluded"] == []

    # host more specific then domain
    _naming_constraints = NamingConstraints(permitted=["https://foo.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://foo.example.com"]
    assert naming_constraints["excluded"] == []


def test_naming_constr_perm_2():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(permitted=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.com"]
    assert naming_constraints["excluded"] == []

    # adding other domain - not permitted
    _naming_constraints = NamingConstraints(permitted=["https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.com"]
    assert naming_constraints["excluded"] == []


def test_naming_permitted_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }

    # permitted domain
    _naming_constraints = NamingConstraints(permitted=["https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["permitted"] == ["https://.example.org"]
    assert naming_constraints["excluded"] == []

    assert permitted('https://foo.example.org', naming_constraints['permitted']) == True


def test_naming_constr_excl_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(excluded=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com"]
    assert naming_constraints["permitted"] == []

    # host more specific then domain
    _naming_constraints = NamingConstraints(excluded=["https://foo.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://foo.example.com"]
    assert naming_constraints["permitted"] == []


def test_naming_constr_excl_list():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(
        excluded=["https://.example.com", "https://bar.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com", "https://bar.example.org"]
    assert naming_constraints["permitted"] == []

    # host more specific then domain
    _naming_constraints = NamingConstraints(excluded=["https://foo.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://foo.example.com", "https://bar.example.org"]
    assert naming_constraints["permitted"] == []


def test_naming_constr_excl_list_2():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(excluded=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com"]
    assert naming_constraints["permitted"] == []

    # host more specific then domain
    _naming_constraints = NamingConstraints(excluded=["https://foo.example.com",
                                                      "https://bar.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://foo.example.com", "https://bar.example.com"]
    assert naming_constraints["permitted"] == []


def test_naming_constr_excl_list_3():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(excluded=["https://.example.com",
                                                      "https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com", "https://.example.org"]
    assert naming_constraints["permitted"] == []

    # host more specific then domain
    _naming_constraints = NamingConstraints(excluded=["https://foo.example.com",
                                                      "https://bar.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://foo.example.com", "https://bar.example.org"]
    assert naming_constraints["permitted"] == []


def test_naming_constr_excl_2():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }
    _naming_constraints = NamingConstraints(excluded=["https://.example.com"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com"]
    assert naming_constraints["permitted"] == []

    # adding other domain - not permitted
    _naming_constraints = NamingConstraints(excluded=["https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.com"]
    assert naming_constraints["permitted"] == []


def test_naming_excluded_1():
    naming_constraints = {
        "permitted": [],
        "excluded": []
    }

    # permitted domain
    _naming_constraints = NamingConstraints(excluded=["https://.example.org"])
    constraints = Constraints(naming_constraints=_naming_constraints)
    naming_constraints = update_naming_constraints(constraints, naming_constraints)
    assert naming_constraints["excluded"] == ["https://.example.org"]
    assert naming_constraints["permitted"] == []

    assert excluded('https://foo.example.org', naming_constraints['excluded']) == True


def test_meets_restriction():
    pass
