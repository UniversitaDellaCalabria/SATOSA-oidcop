import hashlib
import logging
from typing import Optional
from typing import Union

from cryptojwt import JWT
from cryptojwt.exception import BadSignature
from cryptojwt.exception import Invalid
from cryptojwt.exception import IssuerNotFound
from cryptojwt.exception import MissingKey
from cryptojwt.utils import as_bytes
from idpyoidc.message import Message
from idpyoidc.message.oidc import JsonWebToken
from idpyoidc.server.client_authn import basic_authn
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.token import UnknownToken
from idpyoidc.util import sanitize

from . import ExtendedContext

logger = logging.getLogger(__name__)

IGNORED_HEADERS = ["cookie", "user-agent"]


class Persistence(object):

    def __init__(self):
        self.app = None

    def _flush_endpoint_context_memory(self, session_manager=None):
        """
        each OAuth2/OIDC request loads an oidcop session in memory
        this method will simply free the memory from any loaded session
        """
        if not session_manager:
            session_manager = self.app.server.context.session_manager

        session_manager.flush()

    def _deal_with_client_assertion(self, session_manager, token):
        _keyjar = session_manager.upstream_get("attribute", "keyjar")
        _jwt = JWT(_keyjar)
        _jwt.msg_cls = JsonWebToken
        try:
            ca_jwt = _jwt.unpack(token)
        except (Invalid, MissingKey, BadSignature) as err:
            logger.info("%s" % sanitize(err))
            raise ClientAuthenticationError("Could not verify client_assertion.")
        return ca_jwt["iss"]

    def _get_client_id(self,
                       endpoint_context,
                       request: Union[Message, dict],
                       http_info: dict) -> Optional[str]:
        # Figure out which client is concerned
        if "client_id" in request:
            return request["client_id"]

        session_manager = endpoint_context.session_manager

        for param in ["code", "access_token", "refresh_token", "registration_access_token"]:
            if param in request:
                _token_info = session_manager.token_handler.info(request[param])
                sid = _token_info["sid"]
                _path = session_manager.decrypt_branch_id(sid)
                return _path[1]

        if "client_assertion" in request:
            return self._deal_with_client_assertion(session_manager, request["client_assertion"])

        authz = http_info.get("headers", {}).get("authorization", "")
        if authz:

            if "Basic " in authz:
                _info = basic_authn(authz)
                return _info["id"]
            else:
                token = authz.split(" ", 1)[1]
                try:
                    _token_info = session_manager.token_handler.info(token)
                except UnknownToken:
                    _msg = ""
                    logger.error("Someone is using a token I can not parse")
                    raise
                sid = _token_info["sid"]
                _path = session_manager.decrypt_branch_id(sid)
                return _path[1]

        return None

    def _get_client_info(self, client_id, endpoint_context) -> dict:
        client_info = self.app.storage.fetch("client_info", client_id)
        if not client_info:
            return {}

        try:
            keys = endpoint_context.keyjar.get_issuer_keys(client_info["client_id"])
        except IssuerNotFound:
            if "jwks" in client_info:
                endpoint_context.keyjar.import_jwks(client_info["jwks"], client_info["client_id"])
            elif "_jwks" in client_info:
                endpoint_context.keyjar.import_jwks(client_info["_jwks"], client_info["client_id"])
            elif "jwks_uri" in client_info:
                endpoint_context.keyjar.add_url(client_info["client_id"], client_info["jwks_uri"])
        else:
            # TODO
            # here I should check that the keys in the key jar matches the keys in the client info
            pass

        return client_info

    def update_state(self,
                     request: Union[Message, dict],
                     http_info: Optional[dict]) -> str:
        endpoint_context = self.app.server.context
        sman = endpoint_context.session_manager
        # Find the client_id
        client_id = self._get_client_id(endpoint_context=endpoint_context,
                                        request=request,
                                        http_info=http_info)

        _session_info = self.app.storage.fetch(information_type="session_info", key="")
        if _session_info:
            self._flush_endpoint_context_memory(sman)
            sman.load(_session_info)

            # Update session
            _client_session_info = self.app.storage.fetch(information_type="client_session_info",
                                                          key=client_id)
            _session_info["db"] = _client_session_info

            self._flush_endpoint_context_memory(sman)
            sman.load(_session_info)

        # Update local client database
        client_info = self._get_client_info(client_id, endpoint_context)
        if client_info:
            self.app.server.context.cdb = {client_id: client_info}
            return client_id
        else:
            return ""

    def _hash_session_id(self, session_id):
        return hashlib.sha256(as_bytes(session_id)).hexdigest()

    def load_claims(self, session_id):
        # session IDs can be quite large, so I just use the hash
        sid_hash = self._hash_session_id(session_id)
        return self.app.storage.fetch(information_type="claims", key=sid_hash)

    # Now for the store part

    def store_claims(self, claims: dict, session_id: str):
        # session IDs can be quite large, so I just use the hash
        sid_hash = self._hash_session_id(session_id)
        self.app.storage.store(information_type="claims", value=claims, key=sid_hash)

    def get_client_session_info(self, client_id, db, session_manager):
        res = {}
        for key, info in db.items():
            val = session_manager.unpack_branch_key(key)
            if len(val) > 1 and val[1] == client_id:
                res[key] = info
                if val[0] not in res:
                    res[val[0]] = db[val[0]]
        return res

    def store_state(self, client_id):
        sman = self.app.server.context.session_manager
        _session_state = sman.dump()
        _client_session_info = self.get_client_session_info(client_id, _session_state["db"], sman)
        self.app.storage.store(information_type="client_session_info",
                               value=_client_session_info,
                               key=client_id)
        self.app.storage.store(information_type="client_info",
                               value=self.app.server.context.cdb[client_id],
                               key=client_id)
        _session_state["db"] = {}
        self.app.storage.store(information_type="session_info", value=_session_state)

    def _get_http_info(self, context: ExtendedContext):
        """
        aligns parameters for oidcop interoperability needs
        """
        http_info = {"headers": {}}

        if getattr(context, "http_info", None):
            http_info = {
                "headers": {
                    k.lower(): v
                    for k, v in context.http_info.items()
                    if k not in IGNORED_HEADERS
                },
                "method": context.request_method,
                "url": context.request_uri,
            }

        # for token and userinfo endpoint ... but also for authz endpoint if needed
        if getattr(context, "request_authorization", None):
            http_info["headers"].update(
                {"authorization": context.request_authorization}
            )
        return http_info

    def dump_clients(self):  # pragma: no cover
        return self.app.server.context.cdb

    def dump_sessions(self):  # pragma: no cover
        return self.app.server.context.session_manager.dump()
