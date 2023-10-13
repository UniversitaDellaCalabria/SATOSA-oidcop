"""
The OpenID Connect frontend module for the satosa proxy
"""
import base64
import logging
import os
from typing import Optional
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import satosa
from idpyoidc.message.oauth2 import ResponseMessage
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationErrorResponse
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oidc import TokenErrorResponse
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.exception import InvalidClient
from idpyoidc.server.exception import NoSuchGrant
from idpyoidc.server.exception import UnAuthorizedClient
from idpyoidc.server.exception import UnknownClient
from idpyoidc.server.oidc.registration import random_client_id
from satosa.context import Context

from .core import ExtendedContext
from .core.persistence import Persistence

try:
    from satosa.context import add_prompt_to_context
except ImportError:
    # TODO: remove after https://github.com/IdentityPython/SATOSA/pull/419 is merged
    def add_prompt_to_context(*args, **kwargs):
        pass
from satosa.frontends.base import FrontendModule
from satosa.internal import InternalData
import satosa.logging_util as lu
from satosa.response import SeeOther

from .core.application import oidcop_application as oidcop_app
from .core.claims import combine_claim_values
from .core.response import JsonResponse

logger = logging.getLogger(__name__)


class OidcOpUtils(Persistence):
    """
    Interoperability class between satosa and oidcop
    """

    def __init__(self):  # pragma: no cover
        Persistence.__init__(self)
        self.jwks_public = {}

    def _parse_request(
            self, endpoint, context: ExtendedContext, http_headers: dict = None
    ):
        """
        Returns a parsed OAuth2/OIDC request,
        used by Authorization, Token, Userinfo and Introspection endpoints views
        """
        http_headers = http_headers or self._get_http_headers(context)
        try:
            parse_req = endpoint.parse_request(
                context.request, http_info=http_headers,
            )
        except (
                InvalidClient,
                UnknownClient,
                UnAuthorizedClient,
                ClientAuthenticationError,
        ) as err:
            logger.error(err)
            response = JsonResponse(
                {"error": "unauthorized_client", "error_description": str(err)},
                status="403",
            )
            return self.send_response(response)
        return parse_req

    def _process_request(self, endpoint, context: Context, parse_req, http_headers):
        """
        Processes an OAuth2/OIDC request
        used by Authorization, Token, Userinfo and Introspection enpoints views
        """
        if isinstance(parse_req, JsonResponse):
            return self.send_response(parse_req)

        # do not handle prompt param by oidc-op, handle it here instead
        prompt_arg = parse_req.pop("prompt", None)
        if prompt_arg:
            add_prompt_to_context(context, " ".join(prompt_arg) if isinstance(prompt_arg,
                                                                              list) else prompt_arg)

        # save ACRs
        acr_values = parse_req.pop("acr_values", None)
        if acr_values:
            acr_values = acr_values if isinstance(acr_values, list) else acr_values.split(" ")
            context.decorate(Context.KEY_AUTHN_CONTEXT_CLASS_REF, acr_values)
            context.state[Context.KEY_AUTHN_CONTEXT_CLASS_REF] = acr_values

        try:
            proc_req = endpoint.process_request(
                parse_req, http_info=http_headers)
            return proc_req
        except Exception as err:  # pragma: no cover
            logger.error(
                f"In endpoint.process_request: {parse_req.__dict__} - {err}")
            response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": "request cannot be processed",
                },
                status="403",
            )
            return self.send_response(response)

    def _log_request(self, context: ExtendedContext, msg: str, level: str = "info"):
        _msg = f"{msg}: {context.request}"
        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(context.state), message=_msg)
        getattr(logger, level)(logline)

    def handle_error(
            self, msg: str = None, excp: Exception = None, status: str = "403"
    ):  # pragma: no cover
        _msg = f'Something went wrong ... {excp or ""}'
        msg = msg or _msg
        logger.error(msg)
        response = JsonResponse(msg, status=status)
        return self.send_response(response)

    def send_response(self, response):
        self._flush_endpoint_context_memory()
        return response


class OidcOpEndpoints(OidcOpUtils):
    """Handles all the oidc endpoint"""

    def jwks_endpoint(self, context: Context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        return JsonResponse(self.jwks_public)

    def provider_info_endpoint(self, context: ExtendedContext):
        """
        Construct the provider configuration information
        served at /.well-known/openid-configuration.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.app.server.endpoint["provider_config"]
        logger.info(f'Request at the "{endpoint.name}" endpoint')
        http_headers = self._get_http_headers(context)

        parse_req = endpoint.parse_request(
            context.request, http_info=http_headers)
        proc_req = endpoint.process_request(parse_req, http_info=http_headers)

        info = endpoint.do_response(request=context.request, **proc_req)
        return JsonResponse(info["response"])

    def _load_cdb(self, context: ExtendedContext, client_id: Optional[str] = None) -> dict:
        """
        gets client_id from local storage and updates the client DB
        """
        _ec = self.app.server.context

        if client_id:
            client_id = client_id
        elif context.request and isinstance(context.request, dict):
            client_id = context.request.get("client_id")
        else:
            _http_info = self._get_http_headers(context)
            client_id = self._get_client_id(_ec.session_manager, context.request, _http_info)

        client_info = {}
        if client_id:
            client_info = self.app.storage.fetch("client_info", client_id)
        else:
            _msg = f"Could not find a client_id!"
            logger.warning(_msg)
            raise InvalidClient(_msg)

        if not client_info:  # pragma: no cover
            _ec.cdb = {}
            _msg = f"Client {client_id} not found!"
            logger.warning(_msg)
            raise InvalidClient(_msg)

        if client_info:
            _ec.cdb = {client_id: client_info}
            logger.debug(
                f"Loaded oidcop client from {self.app.storage}: {client_info}")
        else:  # pragma: no cover
            logger.info(f'Cannot find "{client_id}" in client DB')
            raise UnknownClient(client_id)

        return client_info

    def _load_session(self, parse_req, endpoint, http_headers):
        """
        actions to perform before an endpoint handles a new http request
        """
        self._flush_endpoint_context_memory()
        _ec = self.app.server.context
        client_id = self._get_client_id(_ec.session_manager, parse_req,
                                        {"headers": http_headers})
        self.app.storage.fetch("client_info", client_id)

    def authorization_endpoint(self, context: ExtendedContext):
        """
        OAuth2 / OIDC Authorization endpoint
        Checks client_id and handles the authorization request
        """
        self._log_request(context, "Authorization endpoint request")
        self._load_cdb(context)

        endpoint = self.app.server.endpoint["authorization"]
        self._get_http_headers(context)
        internal_req = self._handle_authn_request(context, endpoint)
        if not isinstance(internal_req, InternalData):  # pragma: no cover
            return self.send_response(internal_req)

        return self.auth_req_callback_func(context, internal_req)

    def token_endpoint(self, context: ExtendedContext):
        """
        Handle token requests (served at /token).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        self._log_request(context, "Token endpoint request")
        endpoint = self.app.server.endpoint["token"]
        http_headers = self._get_http_headers(context)

        try:
            self._load_cdb(context)
        except UnknownClient:
            return self.send_response(
                JsonResponse(
                    {
                        "error": "unauthorized_client",
                        "error_description": "unknown client",
                    }
                )
            )

        raw_request = AccessTokenRequest().from_urlencoded(urlencode(context.request))
        try:
            self._load_session(raw_request, endpoint, http_headers)
        except NoSuchGrant:
            _response = JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Not owner of token",
                },
                status="403",
            )
            return self.send_response(_response)

        # in token endpoint we cannot parse a request without having loaded cdb and session first
        parse_req = self._parse_request(endpoint, context, http_headers=http_headers)

        ec = endpoint.upstream_get("context")
        self._load_claims(ec)
        proc_req = self._process_request(endpoint, context, parse_req, http_headers)
        # flush as soon as possible, otherwise in case of an exception it would be
        # stored in the object ... until a next .load would happen ...
        ec.userinfo.flush()

        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)
        elif isinstance(proc_req, TokenErrorResponse):
            return self.send_response(JsonResponse(proc_req.to_dict(), status="403"))

        # TODO: remove when migrate to idpy-oidc
        # PATCH https://github.com/UniversitaDellaCalabria/SATOSA-oidcop/issues/29
        if isinstance(proc_req["response_args"].get("scope", str), list):
            proc_req["response_args"]["scope"] = " ".join(
                proc_req["response_args"]["scope"]
            )
        # end PATCH

        # better return jwt or jwe here!
        self.store_session_to_db()
        response = JsonResponse(proc_req["response_args"])

        return self.send_response(response)

    def userinfo_endpoint(self, context: ExtendedContext):
        self._log_request(context, "Userinfo endpoint request")
        endpoint = self.app.server.endpoint["userinfo"]
        http_headers = self._get_http_headers(context)

        # everything depends on bearer access token here
        self._load_session({}, endpoint, http_headers)

        # not load the client from the session using the bearer token
        if self.dump_sessions():
            # load cdb from authz bearer token
            try:
                self._load_cdb(context)
            except Exception:
                logger.warning(
                    f"Userinfo endpoint request without any loadable client"
                )
                return self.send_response(
                    JsonResponse(
                        {"error": "invalid_client", "error_description": "<client not found>"},
                        status="403",
                    )
                )
        else:
            logger.warning(
                f"Userinfo endpoint request without any loadable sessions"
            )
            return self.send_response(
                JsonResponse(
                    {"error": "invalid_token", "error_description": "<no loadable session>"},
                    status="403",
                )
            )

        try:
            parse_req = self._parse_request(
                endpoint, context, http_headers=http_headers
            )
        except KeyError:
            return self.send_response(
                JsonResponse(
                    {"error": "invalid_token", "error_description": "<TOKEN>"},
                    status="403",
                )
            )

        ec = endpoint.upstream_get("context")
        self._load_claims(ec)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_headers)
        # flush as soon as possible, otherwise in case of an exception it would be
        # stored in the object ... until a next .load would happen ...
        ec.userinfo.flush()

        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)
        elif "error" in proc_req or "error" in proc_req.get("response_args", {}):
            return self.send_response(
                JsonResponse(
                    proc_req["response_args"]
                    if "response_args" in proc_req
                    else proc_req.to_dict(),
                    status="403",
                )
            )

        # better return jwt or jwe here!
        response = JsonResponse(proc_req["response_args"])

        self.store_session_to_db()
        return self.send_response(response)

    def _load_claims(self, endpoint_context):
        claims = {}
        sman = endpoint_context.session_manager
        for k, v in sman.dump()["db"].items():
            if v[0] == "idpyoidc.server.session.grant.Grant":
                sid = k
                claims = self.app.storage.get_claims_from_sid(sid)
                break
            else:  # pragma: no cover
                continue

        if not claims:
            logger.warning(
                "Can't find any suitable sid/claims from stored session"
            )

        # That's a patchy runtime definition of userinfo db configuration
        endpoint_context.userinfo.load(claims)

    def registration_read_endpoint(self, context: ExtendedContext):
        """
        The Client Configuration Endpoint is an OAuth 2.0 Protected Resource
        that MAY be provisioned by the server for a specific Client to be able
        to view its registered information.

        The Client MUST use its Registration Access Token in all calls
        to this endpoint as an OAuth 2.0 Bearer Token
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        self._log_request(context, "Client Registration Read endpoint request")
        self._load_cdb(context)
        http_headers = self._get_http_headers(context)
        endpoint = self.app.server.endpoint["registration_read"]
        parse_req = self._parse_request(
            endpoint, context, http_headers=http_headers)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_headers)
        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)
        # better return jwt or jwe here!
        response = JsonResponse(proc_req["response_args"].to_dict())
        return self.send_response(response)

    def registration_endpoint(self, context: ExtendedContext):
        """
        Handle the OIDC dynamic client registration.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        self._log_request(context, "Client Registration endpoint request")
        http_headers = self._get_http_headers(context)
        endpoint = self.app.server.endpoint["registration"]
        parse_req = self._parse_request(
            endpoint, context, http_headers=http_headers)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_headers)
        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)
        # store client to storage
        client_data = context.request
        client_data["client_id"] = random_client_id(
            reserved=self.app.storage.get_registered_clients_id()
        )
        self.app.storage.insert_client(client_data)
        return JsonResponse(client_data)

    def introspection_endpoint(self, context: ExtendedContext):
        self._log_request(context, "Token Introspection endpoint request")
        endpoint = self.app.server.endpoint["introspection"]
        http_headers = self._get_http_headers(context)

        self._load_cdb(context)
        self._load_session(context.request, endpoint, http_headers)
        parse_req = self._parse_request(
            endpoint, context, http_headers=http_headers)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_headers)
        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)

        # better return jwt or jwe here!
        response = JsonResponse(proc_req["response_args"].to_dict())

        self._flush_endpoint_context_memory()
        return self.send_response(response)


class OidcOpFrontend(FrontendModule, OidcOpEndpoints):
    """
    OpenID Connect frontend module based on idpy oidcop
    """

    def __init__(
            self, auth_req_callback_func, internal_attributes, conf, base_url, name
    ):
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)
        self.app = oidcop_app(conf)
        # Why not
        # self.config = self.app.server.conf
        self.config = self.app.srv_config
        jwks_public_path = self.config["key_conf"]["public_path"]
        with open(jwks_public_path) as f:
            self.jwks_public = f.read()

        # registered endpoints will be filled by self.register_endpoints
        self.endpoints = None

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        url_map = [
            (v["path"], getattr(self, f"{k}_endpoint"))
            for k, v in self.config.endpoint.items()
        ]

        # add jwks.json webpath
        uri_path = self.config["key_conf"]["uri_path"]
        url_map.append((uri_path, self.jwks_endpoint))

        logger.debug(f"Loaded OIDC Provider endpoints: {url_map}")
        self.endpoints = url_map
        return url_map

    def _handle_authn_request(self, context: ExtendedContext, endpoint):
        """
        Parse and verify the authentication request into an internal request.
        :type context: satosa.context.Context
        :rtype: satosa.internal.InternalData

        :param context: the current context
        :return: the internal request
        """
        self._log_request(context, "OIDC Authorization request from client")

        http_headers = self._get_http_headers(context)
        self._load_cdb(context)
        parse_req = self._parse_request(
            endpoint, context, http_headers=http_headers)
        if isinstance(parse_req, AuthorizationErrorResponse):
            logger.debug(f"{context.request}, {parse_req._dict}")
            return self.send_response(JsonResponse(parse_req._dict))

        self._load_session(parse_req, endpoint, http_headers)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_headers)
        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return proc_req

        try:
            endpoint.do_response(request=context.request, **proc_req)
        except Exception as excp:  # pragma: no cover
            # TODO - something to be done with the help of unit test
            # this should be for humans if auth code flow
            # and JsonResponse for other flows ...
            self.handle_error(excp=excp)

        context.state[self.name] = {"oidc_request": context.request}

        client_id = parse_req.get("client_id")
        _client_conf = endpoint.upstream_get("context").cdb[client_id]
        client_name = _client_conf.get("client_name")
        subject_type = _client_conf.get("subject_type", "pairwise")
        if client_name:
            requester_name = [{"lang": "en", "text": client_name}]
        else:  # pragma: no cover
            requester_name = None

        internal_req = InternalData(
            subject_type=subject_type,
            requester=client_id,
            requester_name=requester_name,
        )

        _claims_supported = self.config["capabilities"]["claims_supported"]

        # TODO - additional filter here?
        # _approved_attributes = self._get_approved_attributes(
        # _claims_supported, authn_req
        # )
        internal_req.attributes = self.converter.to_internal_filter(
            "openid", _claims_supported
        )

        # TODO - have a default backend, otherwise exception here ...
        context.target_backend = self.app.default_target_backend
        context.internal_data = internal_req
        return internal_req

    def handle_authn_request(self, context: ExtendedContext):
        """
        Handle an authentication request and pass it on to the backend.
        :type context: satosa.context.Context
        :rtype: satosa.response.SeeOther

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.app.server.endpoint["authorization"]
        internal_req = self._handle_authn_request(context, endpoint)
        if not isinstance(internal_req, InternalData):
            return self.send_response(internal_req)
        return self.auth_req_callback_func(context, internal_req)

    def _handle_backend_response(self, context: ExtendedContext, internal_resp):
        """
        Called by handle_authn_response, once a backend made its work
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :param internal_resp: satosa internal data
        :type internal_resp: satosa.internal.InternalData
        :return: HTTP response to the client
        """
        http_headers = self._get_http_headers(context)
        oidc_req = context.state[self.name]["oidc_request"]
        endpoint = self.app.server.endpoint["authorization"]
        self._load_cdb(context, client_id=oidc_req["client_id"])

        # not using self._parse_request cause of "Missing required attribute 'response_type'"
        parse_req = AuthorizationRequest().from_urlencoded(urlencode(oidc_req))
        # not really needed here ... because nothing have been dumped before
        # self._load_session(parse_req, endpoint, http_headers)
        proc_req = self._process_request(
            endpoint, context, parse_req, http_headers)

        if isinstance(proc_req, JsonResponse):  # pragma: no cover
            return self.send_response(proc_req)

        client_id = parse_req["client_id"]
        sub = internal_resp.subject_id

        authn_event = create_authn_event(
            uid=sub,
            salt=base64.b64encode(os.urandom(self.app.salt_size)).decode(),
            authn_info=internal_resp.auth_info.auth_class_ref,
            # TODO: authn_time=datetime.fromisoformat(internal_resp.auth_info.timestamp).timestamp(),
        )

        _ec = endpoint.upstream_get("context")
        _token_usage_rules = _ec.authn_broker.get_method_by_id("user")

        session_manager = _ec.session_manager
        client = self.app.storage.fetch("client_info", client_id)
        client_subject_type = client.get("subject_type", "public")
        _session_id = session_manager.create_session(
            authn_event=authn_event,
            auth_req=parse_req,
            user_id=sub,
            client_id=client_id,
            sub_type=client_subject_type,
            token_usage_rules=_token_usage_rules,
        )

        try:
            # _args is a dict that contains:
            #  - idpyoidc.message.oidc.AuthorizationResponse
            #  - session_id
            #  - cookie (only need for logout -> not yet supported by Satosa)
            _args = endpoint.authz_part2(
                user=sub,
                session_id=_session_id,
                request=parse_req,
                authn_event=authn_event,
            )
        except ValueError as excp:  # pragma: no cover
            # TODO - cover with unit test and add some satosa logging ...
            return self.handle_error(excp=excp)
        except Exception as excp:  # pragma: no cover
            return self.handle_error(excp=excp)

        if isinstance(_args, ResponseMessage) and "error" in _args:  # pragma: no cover
            return self.send_response(JsonResponse(_args, status="403"))
        elif isinstance(
                _args.get("response_args"), AuthorizationErrorResponse
        ):  # pragma: no cover
            rargs = _args.get("response_args")
            logger.error(rargs)
            response = JsonResponse(rargs.to_json(), status="403")
            return self.send_response(response)

        info = endpoint.do_response(request=parse_req, **proc_req)
        info_response = info["response"]
        _response_placement = info.get(
            "response_placement", endpoint.response_placement
        )
        if _response_placement == "url":
            data = _args["response_args"].to_dict()
            url_components = urlparse(info_response)
            original_params = parse_qs(url_components.query)
            merged_params = {**original_params, **data}
            updated_query = urlencode(merged_params, doseq=True)
            redirect_url = url_components._replace(query=updated_query).geturl()
            logger.debug(f"Redirect to: {redirect_url}")
            resp = SeeOther(redirect_url)
        else:  # pragma: no cover
            self._flush_endpoint_context_memory()
            raise NotImplementedError()

        # I don't flush in-mem db because it will be flushed by handle_authn_response
        return resp

    def handle_authn_response(self, context: ExtendedContext, internal_resp):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_resp: satosa.internal.InternalData
        :rtype satosa.response.SeeOther
        """
        _claims = self.converter.from_internal(
            "openid", internal_resp.attributes)
        claims = {k: v for k, v in _claims.items() if v}
        combined_claims = dict(
            [i for i in combine_claim_values(claims.items())])

        response = self._handle_backend_response(context, internal_resp)
        # TODO - why should we have to delete it?
        del context.state[self.name]

        # store oidc session with user claims
        client_id= context.request.get("client_id")
        self.store_state(client_id)
        self.store_claims(combined_claims, client_id)
        return self.send_response(response)

    def handle_backend_error(self, exception: Exception):
        """
        See super class satosa.frontends.base.FrontendModule
        :type exception: satosa.exception.SATOSAError
        :rtype: oic.utils.http_util.Response
        """
        auth_req = AuthorizationRequest().from_urlencoded(
            urlencode(exception.state[self.name]["oidc_request"])
        )
        msg = exception.message
        error_resp = AuthorizationErrorResponse(
            error="access_denied",
            error_description=msg,
            # If the client sent us a state parameter, we should reflect it back according to the
            # spec
            **({"state": auth_req["state"]} if "state" in auth_req else {}),
        )
        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(exception.state), message=msg)
        logger.info(logline)
        return SeeOther(
            error_resp.request(
                auth_req["redirect_uri"], auth_req["response_type"] != ["code"]
            )
        )
