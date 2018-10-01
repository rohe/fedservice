from oidcmsg.message import Message, msg_ser
from oidcmsg.message import SINGLE_REQUIRED_INT
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.oidc import JsonWebToken
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcmsg.oidc import RegistrationResponse
from oidcmsg.oidc import deserialize_from_one_of
from oidcmsg.oidc import dict_deser
from oidcmsg.oidc import msg_ser_json

SINGLE_REQUIRED_DICT = (dict, True, msg_ser_json, dict_deser, False)


def registration_response_deser(val, sformat="json"):
    return deserialize_from_one_of(val, RegistrationResponse, sformat)


def provider_info_deser(val, sformat="json"):
    return deserialize_from_one_of(val, ProviderConfigurationResponse, sformat)


OPTIONAL_CLIENT_METADATA = (Message, False, msg_ser,
                            registration_response_deser, False)
OPTIONAL_PROVIDER_METADATA = (Message, False, msg_ser,
                              provider_info_deser, False)


class Metadata(Message):
    c_param = {
        'openid_client': OPTIONAL_CLIENT_METADATA,
        'openid_provider': OPTIONAL_PROVIDER_METADATA,
    }


def provider_info_deser(val, sformat="json"):
    return deserialize_from_one_of(val, Metadata, sformat)


SINGLE_REQUIRED_METADATA = (Message, True, msg_ser, provider_info_deser, False)


class EntityStatement(JsonWebToken):
    c_param = JsonWebToken.c_param.copy()
    c_param.update({
        "sub": SINGLE_REQUIRED_STRING,
        'iss': SINGLE_REQUIRED_STRING,
        'exp': SINGLE_REQUIRED_INT,
        'iat': SINGLE_REQUIRED_INT,
        'authorityHints': SINGLE_REQUIRED_DICT,
        'metadata': SINGLE_REQUIRED_METADATA
    })
