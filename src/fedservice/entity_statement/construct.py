import logging

from oidcmsg.oidc import RegistrationRequest
from oidcservice.oidc.provider_info_discovery import PROVIDER2PREFERENCE

from fedservice.entity_statement.policy import apply_policy


logger = logging.getLogger(__name__)


def translate_configuration(conf):
    """
    Map a Provider Configuration response into a metadata policy

    :param conf: Attribute,value pairs from a Provider Configuration response
    :return: Attribute,value pairs useful when constructing a Client
        registration requests
    """
    policy = {}
    cls = RegistrationRequest
    for pro, pref in PROVIDER2PREFERENCE.items():
        try:
            _allow = conf[pro]
        except KeyError:
            pass
        else:
            if pref == "scope":
                policy[pref] = {'subset_of': _allow}
            elif isinstance(cls.c_param[pref][0], list):
                policy[pref] = {'subset_of': _allow}
            else:
                policy[pref] = {'one_of': _allow}

    return policy


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
    for key, val in args.items():
        if isinstance(val, list):
            try:
                _typ = ci.c_param[key][0]
            except KeyError:
                res[key] = val
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
    args = apply_policy(client_preference, _allowed)

    return list_to_singleton(args, RegistrationRequest)
