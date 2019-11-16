def calculate_path_length(constraints, current_max_path_length, max_assigned):
    try:
        _max_len = constraints['max_path_length']
    except KeyError:
        if max_assigned:
            current_max_path_length -= 1
            return current_max_path_length

        return 0

    if max_assigned:
        new_current = current_max_path_length - 1
        if _max_len < new_current:
            return _max_len
        else:
            return new_current

    return _max_len


def remove_scheme(url):
    if url.startswith('https://'):
        return url[8:]
    elif url.startswith('http://'):
        return url[7:]
    else:
        raise ValueError('Wrong scheme: %s', url)


def more_specific(a, b):
    a_part = remove_scheme(a).split('.')
    b_part = remove_scheme(b).split('.')
    if len(a_part) >= len(b_part):
        a_part.reverse()
        b_part.reverse()
        for _x, _y in zip(a_part, b_part):
            if _x != _y:
                if _y == "":
                    return True
                return False
        return True
    return False


# def add_permitted(new_permitted, permitted):
#     _updated = []
#     for _new in new_permitted:
#         for _old in permitted:
#             if more_specific(_new, _old):
#                 _updated.append(_new)
#             else:
#                 _updated.append(_old)
#     return _updated


def update_specs(new_constraints, old_constraints):
    _updated = []
    _replaced = False
    for _old in old_constraints:
        _replaced = False
        for _new in new_constraints:
            if more_specific(_new, _old):
                _updated.append(_new)
                _replaced = True

        if not _replaced:
            _updated.append(_old)
    return _updated


def add_constraints(new_constraints, naming_constraints):
    for key in ['permitted','excluded']:
        if not naming_constraints[key]:
            if key in new_constraints and new_constraints[key]:
                naming_constraints[key] = new_constraints[key][:]

            continue
        else:
            if not new_constraints[key]:
                continue

        naming_constraints[key] = update_specs(new_constraints[key], naming_constraints[key])

    return naming_constraints


def update_naming_constraints(constraints, naming_constraints):
    try:
        new_constraints = constraints['naming_constraints']
    except KeyError:
        pass
    else:
        naming_constraints = add_constraints(new_constraints, naming_constraints)

    return naming_constraints


def excluded(subject_id, excluded_ids):
    for excl in excluded_ids:
        if more_specific(subject_id, excl):
            return True
    return False


def permitted(subject_id, permitted_id):
    for perm in permitted_id:
        if more_specific(subject_id, perm):
            return True
    return False


def meets_restrictions(trust_chain):
    """
    Verfies that the trust chain fulfills the constraints specified in it.

    :param trust_chain: A sequence of entity statements. The order is such that the leaf's is the
        last. The trust anchor's the first.
    :return: True is the constraints are fulfilled. False otherwise
    """

    current_max_path_length = 0
    max_assigned = False
    naming_constraints = {
        "permitted": None,
        "excluded": None
    }

    for statement in trust_chain[:-1]:  # All but the last
        try:
            _constraints = statement['constraints']
        except KeyError:
            continue

        current_max_path_length = calculate_path_length(_constraints, current_max_path_length,
                                                        max_assigned)

        if current_max_path_length < 0:
            return False

        naming_constraints = update_naming_constraints(_constraints, naming_constraints)

        # if explicitly excluded return False
        if 'excluded' in naming_constraints and naming_constraints['excluded']:
            if excluded(statement['sub'], naming_constraints['excluded']):
                return False

        # If there is a list of permitted it must be in there
        if 'permitted' in naming_constraints and naming_constraints['permitted']:
            if not permitted(statement['sub'], naming_constraints["permitted"]):
                return False

    # Now check the leaf entity
    statement = trust_chain[-1]
    # if explicitly excluded return False
    if 'excluded' in naming_constraints and naming_constraints['excluded']:
        if excluded(statement['sub'], naming_constraints['excluded']):
            return False

    # If there is a list of permitted it must be in there
    if 'permitted' in naming_constraints and naming_constraints['permitted']:
        if not permitted(statement['sub'], naming_constraints["permitted"]):
            return False

    return True
