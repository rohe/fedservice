from oidcmsg.oidc import RegistrationRequest

from fedservice.entity_statement.statement import Statement
from oidcservice.oidc.service import PROVIDER2PREFERENCE


def translate_configuration(conf):
    """
    Map attributes in a Provider Configuration response into 'equivalent'
    attributes in a client registration request

    :param conf: Attribute,value pairs from a Provider Configuration response
    :return: Attribute,value pairs useful when constructing a Client
        registration requests
    """
    res = {}
    for pro, pref in PROVIDER2PREFERENCE.items():
        try:
            res[pref] = conf[pro]
        except KeyError:
            pass

    return res


def list_to_singleton(args, cls):
    """
    For attributes that are listed as singletons but have values that are
    lists. Replace the list with the first element in the list.

    :param args: The attribute,value pairs as a dictionary
    :param cls: A class instance that can be used to get information about
        the value types for specific attributes.
    :return: A modified attribute,values dictionary
    """
    ci = cls()
    res = {}
    for key,val in args.items():
        if isinstance(val, list):
            try:
                _typ = ci.c_param[key][0]
            except KeyError:
                pass
            else:
                if isinstance(_typ, list):
                    res[key] = val
                else:
                    res[key] = val[0]
        else:
            res[key] = val
    return res


def map_configuration_to_preference(provider_configuration, client_preference):
    """
    Given a provider configuration and client registration attribute
    preferences initiate a ClientRegistration class.

    :param provider_configuration: A ProviderConfigurationResponse
    :param client_preference: An dictionary with client preferences
    :return: A ClientRegistration instance
    """
    _allowed = translate_configuration(provider_configuration)

    _provider = Statement()
    _provider.le = _allowed
    _statem = Statement(sup=_provider)
    _statem.restrict(client_preference)

    args = _statem.unprotected_and_protected_claims()
    args = list_to_singleton(args, RegistrationRequest)
    _cls = RegistrationRequest(**args)
    _cls.weed()
    return _cls.to_dict()
