from oidcrp.exception import OtherError
from oidcrp.oidc import registration
from oidcrp.oidc.authorization import Authorization


def add_callback_uris(request_args=None, service=None, **kwargs):
    registration.add_callback_uris(request_args=request_args, service=service, **kwargs)
    del request_args['redirect_uris']
    return request_args, {}


class FedAuthorization(Authorization):

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Authorization.__init__(self, client_get=client_get,
                               client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct.insert(0, add_callback_uris)
        self.pre_construct.append(self._automatic_registration)

    def _automatic_registration(self, request_args, post_args=None, **kwargs):
        _context = self.client_get("service_context")
        if post_args is None:
            post_args = {}

        _ams = _context.provider_info.get('client_registration_authn_methods_supported')
        # what if request_param is already set ??
        # What if request_param in not in client_auth ??
        if _ams and 'ar' in _ams:
            if "request_object" in _ams['ar']:
                post_args['request_param'] = "request"
                post_args['recv'] = _context.provider_info["authorization_endpoint"]
                post_args["with_jti"] = True
                post_args["lifetime"] = self.conf.get("request_object_expires_in", 300)
                post_args['issuer'] = _context.federation_entity.get_context().entity_id
            else:
                raise OtherError("Using request object in authentication not supported")
        else:  # no authn methods supported
            # am I already registered ?
            if not _context.registration_response:  # Not registered
                raise OtherError("Can not send an authorization request without being registered"
                                 " and automatic registration not supported")

        client_id = request_args.get('client_id')
        if not client_id:
            request_args['client_id'] = _context.federation_entity.get_context().entity_id

        _context.client_id = client_id
        return request_args, post_args
