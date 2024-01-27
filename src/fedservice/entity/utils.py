
def federation_entity(unit):
    if hasattr(unit, "upstream_get"):
        if unit.upstream_get:
            next_unit = unit.upstream_get("unit")
            if next_unit:
                # This is slightly awkward. Can't use isinstance because of circular imports
                if unit.__class__.__name__ == 'FederationEntity':
                    return next_unit
                unit = federation_entity(next_unit)
    else:
        # Unit might be a FederationCombo instance or something equivalent
        if "federation_entity" in unit:
            return unit["federation_entity"]
    return unit


def get_federation_entity(unit):
    # Look both upstream and downstream if necessary
    if unit.__class__.__name__ == 'FederationEntity':
        return unit
    elif unit.upstream_get:
        return get_federation_entity(unit.upstream_get('unit'))
    else:
        _get = getattr(unit, "get", None)
        if _get:
            return _get('federation_entity', None)
        else:
            return None
