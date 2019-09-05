import pytest

from fedservice.entity_statement.policy import PolicyError
from fedservice.entity_statement.policy import combine_claim_policy

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
        "result": {"essential": False, "default": 'A'}
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
        "subordinate": {"superset_of": ['Y','Z']},
        "result": {"subset_of": ['X', 'Y', 'Z'], "superset_of": ['Y','Z']}
    },
    {
        "superior": {"subset_of": ['X', 'Y', 'Z']},
        "subordinate": {"superset_of": ['Y', 'A']},
        "result": PolicyError
    },
    {
        "superior": {"subset_of": ['X', 'Y',]},
        "subordinate": {"superset_of": ['X', 'Y', 'A']},
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
