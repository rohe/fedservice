import pytest

from fedservice.entity_statement.policy import PolicyError
from fedservice.entity_statement.policy import apply_policy
from fedservice.entity_statement.policy import combine_claim_policy
from fedservice.entity_statement.policy import combine_policy

SIMPLE = {
    "SUBSET_OF": [
        {
            "superior": {"subset_of": ['X', 'Y', 'Z']},
            "subordinate": {"subset_of": ['X', 'Y']},
            "result": {"subset_of": ['X', 'Y']}
        },
        {
            "superior": {"subset_of": ['X', 'Y', 'Z']},
            "subordinate": {"subset_of": ['X', 'Y', 'W']},
            "result": {"subset_of": ['X', 'Y']}
        },
        {
            "superior": {"subset_of": ['A', 'X', 'Y', 'Z']},
            "subordinate": {"subset_of": ['X', 'Y', 'W']},
            "result": {"subset_of": ['X', 'Y']}
        },
        {
            "superior": {"subset_of": ['Y', 'Z']},
            "subordinate": {"subset_of": ['X', 'Y']},
            "result": {"subset_of": ['Y']}
        },
        {
            "superior": {"subset_of": ['X', 'Y']},
            "subordinate": {"subset_of": ['Z', 'Y']},
            "result": {"subset_of": ['Y']}
        },
        {
            "superior": {"subset_of": ['X', 'Y']},
            "subordinate": {"subset_of": ['Z', 'W']},
            "result": PolicyError
        }
    ],
    "SUPERSET_OF": [
        {
            "superior": {"superset_of": ['X', 'Y', 'Z']},
            "subordinate": {"superset_of": ['X', 'Y']},
            "result": {"superset_of": ['X', 'Y']}
        },
        {
            "superior": {"superset_of": ['X', 'Y', 'Z']},
            "subordinate": {"superset_of": ['X', 'Y', 'W']},
            "result": {"superset_of": ['X', 'Y']}
        },
        {
            "superior": {"superset_of": ['A', 'X', 'Y', 'Z']},
            "subordinate": {"superset_of": ['X', 'Y', 'W']},
            "result": {"superset_of": ['X', 'Y']}
        },
        {
            "superior": {"superset_of": ['Y', 'Z']},
            "subordinate": {"superset_of": ['X', 'Y']},
            "result": {"superset_of": ['Y']}
        },
        {
            "superior": {"superset_of": ['X', 'Y']},
            "subordinate": {"superset_of": ['Z', 'Y']},
            "result": {"superset_of": ['Y']}
        },
        {
            "superior": {"superset_of": ['X', 'Y']},
            "subordinate": {"superset_of": ['Z', 'W']},
            "result": PolicyError
        }
    ],
    "ONE_OF": [
        {
            "superior": {"one_of": ['X', 'Y', 'Z']},
            "subordinate": {"one_of": ['X', 'Y']},
            "result": {"one_of": ['X', 'Y']}
        },
        {
            "superior": {"one_of": ['X', 'Y', 'Z']},
            "subordinate": {"one_of": ['X', 'Y', 'W']},
            "result": {"one_of": ['X', 'Y']}
        },
        {
            "superior": {"one_of": ['A', 'X', 'Y', 'Z']},
            "subordinate": {"one_of": ['X', 'Y', 'W']},
            "result": {"one_of": ['X', 'Y']}
        },
        {
            "superior": {"one_of": ['Y', 'Z']},
            "subordinate": {"one_of": ['X', 'Y']},
            "result": {"one_of": ['Y']}
        },
        {
            "superior": {"one_of": ['X', 'Y']},
            "subordinate": {"one_of": ['Z', 'Y']},
            "result": {"one_of": ['Y']}
        },
        {
            "superior": {"one_of": ['X', 'Y']},
            "subordinate": {"one_of": ['Z', 'W']},
            "result": PolicyError
        }
    ],
    "ADD": [
        {
            "superior": {"add": "X"},
            "subordinate": {"add": "B"},
            "result": {"add": ["X", "B"]}
        },
        {
            "superior": {"add": "X"},
            "subordinate": {"add": "X"},
            "result": {"add": "X"}
        }
    ],
    "VALUE": [
        {
            "superior": {"value": "X"},
            "subordinate": {"value": "B"},
            "result": PolicyError
        },
        {
            "superior": {"value": "X"},
            "subordinate": {"value": "X"},
            "result": {"value": "X"}
        },
        {
            "superior": {"value": ["X", "Y"]},
            "subordinate": {"value": ["X", "Z"]},
            "result": PolicyError
        }
    ],
    "DEFAULT": [
        {
            "superior": {"default": "X"},
            "subordinate": {"default": "B"},
            "result": PolicyError
        },
        {
            "superior": {"default": ["X", "B"]},
            "subordinate": {"default": ["B", "Y"]},
            "result": PolicyError
        },
        {
            "superior": {"default": "X"},
            "subordinate": {"default": "X"},
            "result": {"default": "X"}
        }
    ],
    "ESSENTIAL": [
        {
            "superior": {"essential": True},
            "subordinate": {"essential": False},
            "result": {"essential": True}
        },
        {
            "superior": {"essential": False},
            "subordinate": {"essential": True},
            "result": {"essential": True}
        },
        {
            "superior": {"essential": True},
            "subordinate": {"essential": True},
            "result": {"essential": True}
        },
        {
            "superior": {"essential": False},
            "subordinate": {"essential": False},
            "result": {"essential": False}
        }
    ]
}

COMPLEX = [
    {
        "superior": {"essential": False},
        "subordinate": {"default": 'A'},
        "result": {"essential": False, "default": 'A'}
    },
    {
        "subordinate": {"essential": False},
        "superior": {"default": 'A'},
        "result": {"essential": True, "default": 'A'}
    },
    {
        "superior": {"essential": False, "default": 'A'},
        "subordinate": {"default": 'A', "essential": True},
        "result": {"essential": True, "default": 'A'}
    },
    {
        "superior": {"essential": False, "default": 'A'},
        "subordinate": {"default": 'B', "essential": True},
        "result": PolicyError
    },
    {
        "superior": {"essential": False},
        "subordinate": {"subset_of": ['B']},
        "result": {"essential": False, "subset_of": ['B']}
    },
    {
        "superior": {"subset_of": ['X', 'Y', 'Z']},
        "subordinate": {"superset_of": ['Y', 'Z']},
        "result": {"subset_of": ['X', 'Y', 'Z'], "superset_of": ['Y', 'Z']}
    },
    {
        "superior": {"subset_of": ['X', 'Y', 'Z']},
        "subordinate": {"superset_of": ['Y', 'A']},
        "result": PolicyError
    },
    {
        "superior": {"subset_of": ['X', 'Y', ]},
        "subordinate": {"superset_of": ['X', 'Y', 'A']},
        "result": PolicyError
    },
    {
        "superior": {"subset_of": ['X', 'Y']},
        "subordinate": {"default": ['X']},
        "result": {"subset_of": ['X', 'Y'], "default": ['X']}
    },
    {
        "superior": {"superset_of": ['X', 'Y']},
        "subordinate": {"default": ['X', 'Y', 'Z']},
        "result": {"superset_of": ['X', 'Y'], "default": ['X', 'Y', 'Z']}
    },
    {
        "superior": {"one_of": ['X', 'Y']},
        "subordinate": {"default": 'X'},
        "result": {"one_of": ['X', 'Y'], "default": 'X'}
    },
    {
        "superior": {"subset_of": ['X', 'Y']},
        "subordinate": {"default": ['X', 'Z']},
        "result": PolicyError
    },
    {
        "superior": {"superset_of": ['X', 'Y']},
        "subordinate": {"default": ['X', 'Z']},
        "result": PolicyError
    },
    {
        "superior": {"one_of": ['X', 'Y']},
        "subordinate": {"default": 'Z'},
        "result": PolicyError
    }
]


def assert_equal(val1, val2):
    assert set(val1.keys()) == set(val2.keys())

    for key, attr in val1.items():
        if isinstance(attr, bool):
            return attr == val2[key]
        elif isinstance(attr, list):
            return set(attr) == set(val2[key])
        else:
            return attr == val2[key]


def test_simple_policy_combinations():
    for typ, _cases in SIMPLE.items():
        for case in _cases:
            if case["result"] in [PolicyError]:
                with pytest.raises(case["result"]):
                    combine_claim_policy(case["superior"], case["subordinate"])
            else:
                cp = combine_claim_policy(case["superior"], case["subordinate"])
                print(case)
                assert assert_equal(cp, case["result"])


def test_complex_policy_combinations():
    for case in COMPLEX:
        if case["result"] in [PolicyError]:
            with pytest.raises(case["result"]):
                combine_claim_policy(case["superior"], case["subordinate"])
        else:
            cp = combine_claim_policy(case["superior"], case["subordinate"])
            print(case)
            assert assert_equal(cp, case["result"])


FED = {
    "scopes": {
        "subset_of": ["openid", "eduperson", "phone"],
        "superset_of": ["openid"],
        "default": ["openid", "eduperson"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384", "ES512"]},
    "contacts": {
        "add": "helpdesk@federation.example.org"},
    "application_type": {"value": "web"}
}

ORG = {
    "scopes": {
        "subset_of": ["openid", "eduperson", "address"],
        "default": ["openid", "eduperson"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384"],
        "default": "ES256"},
    "contacts": {
        "add": "helpdesk@org.example.org"},
}

RES = {
    "scopes": {
        "subset_of": ["openid", "eduperson"],
        "superset_of": ["openid"],
        "default": ["openid", "eduperson"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384"],
        "default": "ES256"},
    "contacts": {
        "add": ["helpdesk@federation.example.org",
                "helpdesk@org.example.org"]},
    "application_type": {
        "value": "web"}
}


def test_combine_policies():
    res = combine_policy(FED, ORG)

    assert set(res.keys()) == set(RES.keys())

    for claim, policy in res.items():
        assert set(policy.keys()) == set(RES[claim].keys())
        assert assert_equal(policy, RES[claim])


RP = {
    "contacts": ["rp_admins@cs.example.com"],
    "redirect_uris": ["https://cs.example.com/rp1"],
    "response_types": ["code"]
}

FED1 = {
    "scopes": {
        "superset_of": ["openid", "eduperson"],
        "default": ["openid", "eduperson"]
    },
    "response_types": {
        "subset_of": ["code", "code id_token"]}
}

ORG1 = {
    "contacts": {
        "add": "helpdesk@example.com"},
    "logo_uri": {
        "one_of": ["https://example.com/logo_small.jpg",
                   "https://example.com/logo_big.jpg"],
        "default": "https://example.com/logo_small.jpg"
    },
    "policy_uri": {
        "value": "https://example.com/policy.html"},
    "tos_uri": {
        "value": "https://example.com/tos.html"}
}

RES1 = {
    "contacts": ["rp_admins@cs.example.com", "helpdesk@example.com"],
    "logo_uri": "https://example.com/logo_small.jpg",
    "policy_uri": "https://example.com/policy.html",
    "tos_uri": "https://example.com/tos.html",
    "scopes": ["openid", "eduperson"],
    "response_types": ["code"],
    "redirect_uris": ["https://cs.example.com/rp1"]
}


def test_apply_policies():
    comb_policy = combine_policy(FED1, ORG1)
    res = apply_policy(RP, comb_policy)

    assert set(res.keys()) == set(RES1.keys())

    for claim, value in res.items():
        if isinstance(value, list):
            if isinstance(RES1[claim], list):
                assert set(value) == set(RES1[claim])
            else:
                assert set(value) == {RES1[claim]}
        else:
            if isinstance(RES1[claim], list):
                assert {value} == set(RES1[claim])
            else:
                assert value == RES1[claim]
