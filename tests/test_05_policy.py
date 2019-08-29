import pytest

from fedservice.entity_statement.policy import PolicyError
from fedservice.entity_statement.policy import combine_claim_policy


def test_policy_subset_of():
    superior = {
        "response_types": {
            "subset_of": ["code", "code token", "code id_token"]
        }}

    child = {
        "response_types": {
            "subset_of": ["code", "code id_token"]
        }
    }

    cp = combine_claim_policy(superior["response_types"], child["response_types"])
    assert list(cp.keys()) == ['subset_of']
    assert set(cp['subset_of']) == {"code", "code id_token"}

    child = {
        "response_types": {
            "subset_of": ["code", "code token", "code id_token", "token", "token id_token"]
        }
    }

    cp = combine_claim_policy(superior["response_types"], child["response_types"])
    assert list(cp.keys()) == ['subset_of']
    assert set(cp['subset_of']) == {"code", "code id_token", "code token"}

    child = {
        "response_types": {
            "subset_of": ["token", "token id_token"]
        }
    }

    with pytest.raises(PolicyError):
        combine_claim_policy(superior["response_types"], child["response_types"])


def test_policy_one_of():
    superior = {
        "response_types": {
            "one_of": ["code", "code token", "code id_token"]
        }}

    child = {
        "response_types": {
            "one_of": ["code", "code id_token"]
        }
    }

    cp = combine_claim_policy(superior["response_types"], child["response_types"])
    assert list(cp.keys()) == ['one_of']
    assert set(cp['one_of']) == {"code", "code id_token"}

    child = {
        "response_types": {
            "one_of": ["code", "code token", "code id_token", "token", "token id_token"]
        }
    }

    cp = combine_claim_policy(superior["response_types"], child["response_types"])
    assert list(cp.keys()) == ['one_of']
    assert set(cp['one_of']) == {"code", "code id_token", "code token"}

    child = {
        "response_types": {
            "one_of": ["token", "token id_token"]
        }
    }

    with pytest.raises(PolicyError):
        combine_claim_policy(superior["response_types"], child["response_types"])


def test_policy_add():
    superior = {
        "contact": {
            "add": "info@superior.example.com"
        }}

    child = {
        "contact": {
            "add": "info@child.example.com"
        }
    }

    cp = combine_claim_policy(superior["contact"], child["contact"])
    assert list(cp.keys()) == ['add']
    assert set(cp['add']) == {"info@superior.example.com", "info@child.example.com"}

    child = {
        "contact": {
            "add": ["info@child.example.com", "dev@child.example.com"]
        }
    }

    cp = combine_claim_policy(superior["contact"], child["contact"])
    assert list(cp.keys()) == ['add']
    assert set(cp['add']) == {"info@superior.example.com", "info@child.example.com",
                              "dev@child.example.com"}


def test_policy_value():
    superior = {"value": "foo"}
    child = {"value": "bar"}

    with pytest.raises(PolicyError):
        combine_claim_policy(superior, child)


def test_policy_add_combinations():
    superior = {
            "add": "info@superior.example.com"
        }

    child = {
        "add": "info@child.example.com",
        "essential": True
    }

    cp = combine_claim_policy(superior, child)
    assert cp

    child = {
        "add": "info@child.example.com",
        "default": "info@child.example.com"
    }

    with pytest.raises(PolicyError):
        combine_claim_policy(superior, child)

    child = {
        "add": "info@child.example.com",
        "default": "info@child.example.com"
    }

    with pytest.raises(PolicyError):
        combine_claim_policy(superior, child)


def test_policy_subset_of_combinations():
    superior = {
            "subset_of": ["code", "code token", "code id_token"]
        }

    child = {
        "subset_of": ["code"],
        "essential": True
    }

    cp = combine_claim_policy(superior, child)
    assert cp

    child = {
        "subset_of": ["code"],
        "default": ["code"]
    }

    cp = combine_claim_policy(superior, child)
    assert cp

    child = {
        "subset_of": ["code"],
        "value": ["code"]
    }

    with pytest.raises(PolicyError):
        combine_claim_policy(superior, child)

    child = {
        "one_of": ["code", "id_token"],
    }

    with pytest.raises(PolicyError):
        combine_claim_policy(superior, child)


def test_policy_essential():
    superior = {"essential": True}
    child = {"essential": True}

    cp = combine_claim_policy(superior, child)
    assert set(cp.keys()) == {'essential'}
    assert cp['essential'] is True

    superior = {"essential": True}
    child = {"essential": False}

    cp = combine_claim_policy(superior, child)
    assert set(cp.keys()) == {'essential'}
    assert cp['essential'] is True

    superior = {"essential": False}
    child = {"essential": True}

    cp = combine_claim_policy(superior, child)
    assert set(cp.keys()) == {'essential'}
    assert cp['essential'] is True

    superior = {"essential": False}
    child = {"essential": False}

    cp = combine_claim_policy(superior, child)
    assert set(cp.keys()) == {'essential'}
    assert cp['essential'] is False


def test_policy_default():
    superior = {"default": "foo"}
    child = {"default": "bar"}

    cp = combine_claim_policy(superior, child)
    assert set(cp.keys()) == {'default'}
    assert cp['default'] is "foo"


def test_policy_default_essential():
    superior = {"default": "foo"}
    child = {"essential": True}

    cp = combine_claim_policy(superior, child)
    assert set(cp.keys()) == {'default', "essential"}
    assert cp['default'] is "foo"
    assert cp['essential'] is True

    superior = {"essential": True}
    child = {"default": "foo"}

    cp = combine_claim_policy(superior, child)
    assert set(cp.keys()) == {'default', "essential"}
    assert cp['default'] is "foo"
    assert cp['essential'] is True
