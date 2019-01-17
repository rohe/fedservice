from oidcservice.oidc.authorization import Authorization


class FedAuthorization(Authorization):
    default_authn_method = 'private_key_jwt'
