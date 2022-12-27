import json
import logging
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from cryptojwt.key_jar import KeyJar
from idpyoidc.client.client_auth import client_auth_setup
from idpyoidc.client.configure import Configuration
from idpyoidc.client.service import init_services
from idpyoidc.node import ClientUnit

from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_SERVICES
from fedservice.entity import FederationContext

logger = logging.getLogger(__name__)


class FederationServiceContext(FederationContext):
    def __init__(self,
                 config: Optional[Union[dict, Configuration]] = None,
                 entity_id: str = "",
                 upstream_get: Callable = None,
                 keyjar: Optional[KeyJar] = None,
                 priority: Optional[List[str]] = None,
                 trust_marks: Optional[List[str]] = None,
                 trusted_roots: Optional[dict] = None,
                 metadata: Optional[dict] = None,
                 ):

        if config is None:
            config = {}

        FederationContext.__init__(self,
                                   config=config,
                                   entity_id=entity_id,
                                   upstream_get=upstream_get,
                                   keyjar=keyjar,
                                   metadata=metadata,
                                   trust_marks=trust_marks,
                                   tr_priority=priority
                                   )

        self.trust_mark_issuer = None
        self.signed_trust_marks = []

        _key_jar = self.upstream_get("attribute", "keyjar")
        for iss, jwks in self.trusted_roots.items():
            _key_jar.import_jwks(jwks, iss)


class FederationEntityClient(ClientUnit):
    def __init__(
            self,
            upstream_get: Callable = None,
            keyjar: Optional[KeyJar] = None,
            config: Optional[Union[dict, Configuration]] = None,
            httpc: Optional[Callable] = None,
            httpc_params: Optional[dict] = None,
            services: Optional[dict] = None,
            jwks_uri: Optional[str] = "",
            metadata: Optional[dict] = None,
            trust_marks: Optional[list] = None,
            priority: Optional[list] = None
    ):
        """

        :param keyjar: A py:class:`idpyoidc.key_jar.KeyJar` instance
        :param config: Configuration information passed on to the
            :py:class:`idpyoidc.client.service_context.ServiceContext`
            initialization
        :param httpc: A HTTP client to use
        :param services: A list of service definitions
        :param jwks_uri: A jwks_uri
        :param httpc_params: HTTP request arguments
        :return: Client instance
        """

        ClientUnit.__init__(self, upstream_get=upstream_get, httpc=httpc,
                            keyjar=keyjar, httpc_params=httpc_params,
                            config=config)

        _srvs = services or DEFAULT_FEDERATION_ENTITY_SERVICES

        self._service = init_services(service_definitions=_srvs, upstream_get=self.unit_get)

        self._service_context = FederationServiceContext(config=config,
                                                         upstream_get=self.unit_get,
                                                         metadata=metadata,
                                                         trust_marks=trust_marks,
                                                         priority=priority)

        self.setup_client_authn_methods(config)

    def get_attribute(self, attr, *args):
        val = getattr(self, attr)
        if val:
            return val
        else:
            return self.upstream_get('attribute', attr)

    def get_service(self, service_name, *arg):
        try:
            return self._service[service_name]
        except KeyError:
            return None

    def get_service_names(self, *args):
        return set(self._service.keys())

    def get_services(self, *args):
        return self._service.values()

    def get_context(self, *args):
        return self._service_context

    def setup_client_authn_methods(self, config):
        if config and "client_authn_methods" in config:
            self._service_context.client_authn_method = client_auth_setup(
                config.get("client_authn_methods")
            )
        else:
            self._service_context.client_authn_method = {}

    def set_client_id(self, client_id):
        self._service_context.client_id = client_id

    # def get_response(
    #         self,
    #         service: Service,
    #         url: str,
    #         method: Optional[str] = "GET",
    #         body: Optional[dict] = None,
    #         response_body_type: Optional[str] = "",
    #         headers: Optional[dict] = None,
    #         **kwargs
    # ):
    #     """
    #
    #     :param url:
    #     :param method:
    #     :param body:
    #     :param response_body_type:
    #     :param headers:
    #     :param kwargs:
    #     :return:
    #     """
    #     try:
    #         resp = self.httpc(method, url, data=body, headers=headers)
    #     except Exception as err:
    #         logger.error(f"Exception on request: {err}")
    #         raise
    #
    #     if 300 <= resp.status_code < 400:
    #         return {"http_response": resp}
    #
    #     if resp.status_code < 300:
    #         if "keyjar" not in kwargs:
    #             kwargs["keyjar"] = service.upstream_get("context").keyjar
    #         if not response_body_type:
    #             response_body_type = service.response_body_type
    #
    #         if response_body_type == "html":
    #             return resp.text
    #
    #         if body:
    #             kwargs["request_body"] = body
    #
    #     return self.parse_request_response(service, resp, response_body_type, **kwargs)
    #
    # def service_request(
    #         self,
    #         service: Service,
    #         url: str,
    #         method: Optional[str] = "GET",
    #         body: Optional[dict] = None,
    #         response_body_type: Optional[str] = "",
    #         headers: Optional[dict] = None,
    #         **kwargs
    # ) -> Message:
    #     """
    #     The method that sends the request and handles the response returned.
    #     This assumes that the response arrives in the HTTP response.
    #
    #     :param service: The Service instance
    #     :param url: The URL to which the request should be sent
    #     :param method: Which HTTP method to use
    #     :param body: A message body if any
    #     :param response_body_type: The expected format of the body of the
    #         return message
    #     :param httpc_params: Arguments for the HTTP client
    #     :return: A cls or ResponseMessage instance or the HTTP response
    #         instance if no response body was expected.
    #     """
    #
    #     if headers is None:
    #         headers = {}
    #
    #     logger.debug(REQUEST_INFO.format(url, method, body, headers))
    #
    #     try:
    #         response = service.get_response_ext(
    #             url, method, body, response_body_type, headers, **kwargs
    #         )
    #     except AttributeError:
    #         response = self.get_response(
    #             service, url, method, body, response_body_type, headers, **kwargs
    #         )
    #
    #     if "error" in response:
    #         pass
    #     else:
    #         try:
    #             kwargs["key"] = kwargs["state"]
    #         except KeyError:
    #             pass
    #
    #         service.update_service_context(response, **kwargs)
    #     return response
    #
    # def parse_request_response(self, service, reqresp, response_body_type="", state="",
    #                            **kwargs):
    #     """
    #     Deal with a self.http response. The response are expected to
    #     follow a special pattern, having the attributes:
    #
    #         - headers (list of tuples with headers attributes and their values)
    #         - status_code (integer)
    #         - text (The text version of the response)
    #         - url (The calling URL)
    #
    #     :param service: A :py:class:`idpyoidc.client.service.Service` instance
    #     :param reqresp: The HTTP request response
    #     :param response_body_type: If response in body one of 'json', 'jwt' or
    #         'urlencoded'
    #     :param state: Session identifier
    #     :param kwargs: Extra keyword arguments
    #     :return:
    #     """
    #
    #     # if not response_body_type:
    #     #     response_body_type = self.response_body_type
    #
    #     if reqresp.status_code in SUCCESSFUL:
    #         logger.debug(f'response_body_type: "{response_body_type}"')
    #         _deser_method = get_deserialization_method(reqresp)
    #
    #         if _deser_method != response_body_type:
    #             logger.warning(
    #                 "Not the body type I expected: {} != {}".format(
    #                     _deser_method, response_body_type
    #                 )
    #             )
    #         if _deser_method in ["json", "jwt", "urlencoded"]:
    #             value_type = _deser_method
    #         else:
    #             value_type = response_body_type
    #
    #         logger.debug(f"Successful response: {reqresp.text}")
    #
    #         try:
    #             return service.parse_response(reqresp.text, value_type, state, **kwargs)
    #         except Exception as err:
    #             logger.error(err)
    #             raise
    #     elif reqresp.status_code in [302, 303]:  # redirect
    #         return reqresp
    #     elif reqresp.status_code == 500:
    #         logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
    #         raise ParseError(f"ERROR: Something went wrong: {reqresp.text}")
    #     elif 400 <= reqresp.status_code < 500:
    #         logger.error(
    #             f"Error response ({reqresp.status_code}): {reqresp.text}")
    #         # expecting an error response
    #         _deser_method = get_deserialization_method(reqresp)
    #         if not _deser_method:
    #             _deser_method = "json"
    #
    #         try:
    #             err_resp = service.parse_response(reqresp.text, _deser_method)
    #         except (FormatError, ValueError):
    #             if _deser_method != response_body_type:
    #                 try:
    #                     err_resp = service.parse_response(reqresp.text, response_body_type)
    #                 except (OidcServiceError, FormatError, ValueError):
    #                     raise OidcServiceError(
    #                         "HTTP ERROR: %s [%s] on %s"
    #                         % (reqresp.text, reqresp.status_code, reqresp.url)
    #                     )
    #             else:
    #                 raise OidcServiceError(
    #                     "HTTP ERROR: %s [%s] on %s"
    #                     % (reqresp.text, reqresp.status_code, reqresp.url)
    #                 )
    #         except JSONDecodeError:  # So it's not JSON assume text then
    #             err_resp = {"error": reqresp.text}
    #
    #         err_resp["status_code"] = reqresp.status_code
    #         return err_resp
    #     else:
    #         logger.error(
    #             f"Error response ({reqresp.status_code}): {reqresp.text}")
    #         raise OidcServiceError(
    #             f"HTTP ERROR: {reqresp.text} [{reqresp.status_code}] on {reqresp.url}"
    #         )
