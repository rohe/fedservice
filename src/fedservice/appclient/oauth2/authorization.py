from idpyoidc.client.exception import OtherError
from idpyoidc.client.oauth2 import authorization
from idpyoidc.client.oauth2.add_on.jar import construct_request_parameter
from idpyoidc.exception import UnSupported


class Authorization(authorization.Authorization):

    def __init__(self, upstream_get, conf=None):
        authorization.Authorization.__init__(self, upstream_get=upstream_get, conf=conf)
        self.pre_construct.append(self._automatic_registration)
        self.post_construct.append(self.create_request)

    def _use_authorization_endpoint(self, context, post_args, ams, entity_type):
        if 'pushed_authorization' in context.add_on:
            # Turn off pushed auth
            context.add_on['pushed_authorization']['apply'] = False

        if "request_object" in ams['authorization_endpoint']:
            post_args['request_param'] = "request"
            post_args['recv'] = context.get_metadata_claim("authorization_endpoint", [entity_type])
            post_args["with_jti"] = True
            post_args["lifetime"] = self.conf.get("request_object_expires_in", 300)
            post_args['issuer'] = self.upstream_get('attribute', 'entity_id')
        else:
            raise OtherError("Using request object in authentication not supported by OP")

        return post_args

    def _use_pushed_authorization_endpoint(self, context, post_args, ams, entity_type):
        if 'pushed_authorization' not in context.add_on:
            raise UnSupported('Pushed Authorization not supported')
        else:  # Make it happen
            context.add_on['pushed_authorization']['apply'] = True

    def _automatic_registration(self, request_args, post_args=None, **kwargs):
        _context = self.upstream_get("context")
        if post_args is None:
            post_args = {}

        _request_endpoints = _context.config.get('authorization_request_endpoints')
        if not _request_endpoints:
            _request_endpoints = _context.config.conf.get('authorization_request_endpoints')

        # What does the server support
        if self.upstream_get('attribute', "client_type") == 'oidc':
            _entity_type = "openid_provider"
        elif self.upstream_get('attribute', "client_type") == 'oauth2':
            _entity_type = "oauth_authorization_server"
        else:
            raise KeyError("Unknown client_type")

        _ams = _context.get_metadata_claim('request_authentication_methods_supported', [_entity_type])

        # what if request_param is already set ??
        # What if request_param in not in client_auth ??
        if _ams:
            for endpoint in _request_endpoints:
                if endpoint in _ams:
                    _func = getattr(self, f'_use_{endpoint}')
                    post_args = _func(_context, post_args, _ams, _entity_type)
                    break
        else:  # The OP does not support any authn methods
            # am I already registered ?
            if not _context.registration_response:  # Not registered
                raise OtherError("Can not send an authorization request without being registered"
                                 " and automatic registration not supported")

        client_id = request_args.get('client_id')
        if not client_id:
            request_args['client_id'] = self.upstream_get('attribute', 'entity_id')

        return request_args, post_args

    def create_request(self, request_args, **kwargs):
        request_arg = kwargs.get('request_param', "")
        if request_arg == "request":
            service = kwargs.get("service")
            del kwargs["service"]
            _args = {k: request_args[k] for k in self.msg_type().required_parameters() if k in request_args}
            _req = construct_request_parameter(service, request_args, **kwargs)
            _args["request"] = _req
            return _args
        else:
            return request_args
