import json
import os
import shutil

from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS
from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server import user_info
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server.oidc import userinfo
from idpyoidc.server.oidc.authorization import Authorization
from idpyoidc.server.oidc.provider_config import ProviderConfiguration
from idpyoidc.server.oidc.registration import Registration
from idpyoidc.server.oidc.token import Token
from idpyoidc.server.scopes import SCOPE2CLAIMS
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from idpyoidc.server.util import execute
import pytest

from satosa_oidcop.core.persistence import Persistence

CRYPT_CONFIG = {
    "kwargs": {
        "keys": {
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "password"},
                {"type": "OCT", "use": ["enc"], "kid": "salt"},
            ]
        },
        "iterations": 1,
    }
}

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

CAPABILITIES = {
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

AUTH_REQ_2 = AuthorizationRequest(
    client_id="client_2",
    redirect_uri="https://two.example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ_2 = AccessTokenRequest(
    client_id="client_2",
    redirect_uri="https://two.example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))

ISSUER = "https://example.com/"

ENDPOINT_CONTEXT_CONFIG = {
    "issuer": ISSUER,
    "httpc_params": {"verify": False, "timeout": 1},
    "preference": CAPABILITIES,
    # "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
    "token_handler_args": {
        # "jwks_file": "private/token_jwks.json",
        "jwks_def": {"private_file": "private_path/token_jwks.json",
                     "read_only": False,
                     "key_defs": DEFAULT_KEY_DEFS},
        "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
        "token": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            },
        },
        "refresh": {
            "class": "idpyoidc.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "aud": ["https://example.org/appl"],
            },
        },
        "id_token": {"class": "idpyoidc.server.token.id_token.IDToken", "kwargs": {}},
    },
    "endpoint": {
        "provider_config": {
            "path": ".well-known/openid-configuration",
            "class": ProviderConfiguration,
            "kwargs": {},
        },
        "registration": {
            "path": "registration",
            "class": Registration,
            "kwargs": {},
        },
        "authorization": {
            "path": "authorization",
            "class": Authorization,
            "kwargs": {},
        },
        "token": {
            "path": "token",
            "class": Token,
            "kwargs": {
                "client_authn_method": [
                    "client_secret_post",
                    "client_secret_basic",
                    "client_secret_jwt",
                    "private_key_jwt",
                ]
            },
        },
        "userinfo": {
            "path": "userinfo",
            "class": userinfo.UserInfo,
            "kwargs": {
                "claim_types_supported": [
                    "normal",
                    "aggregated",
                    "distributed",
                ],
                "client_authn_method": ["bearer_header"],
                "add_claims_by_scope": True,
            },
        },
    },
    "userinfo": {
        "class": user_info.UserInfo,
        "kwargs": {"db_file": full_path("users.json")},
    },
    # "client_authn": verify_client,
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "idpyoidc.server.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "template_dir": "template",
    "scopes_to_claims": {
        **SCOPE2CLAIMS,
        "research_and_scholarship": [
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "sub",
            "eduperson_scoped_affiliation",
        ],
    },
    "authz": {
        "class": AuthzHandling,
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token",
                        ],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": ["access_token", "refresh_token"],
                    },
                },
                "expires_in": 43200,
            }
        },
    },
    "session_params": SESSION_PARAMS,
}


class Application(object):
    def __init__(self, server, store):
        self.server = server
        self.storage = store


STORE_CONF = {
    "class": "satosa_oidcop.core.storage.file.FilesystemDB",
    "kwargs": {
        "fdir": "storage",
        "key_conv": "idpyoidc.util.Base64",
        "value_conv": "idpyoidc.util.JSON"
    }
}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        try:
            shutil.rmtree("storage")
        except FileNotFoundError:
            pass

        # Both have to use the same key jar
        _keyjar = build_keyjar(DEFAULT_KEY_DEFS)
        _keyjar.import_jwks_as_json(_keyjar.export_jwks_as_json(True, ""), ISSUER)

        self.frontend = {}
        store_1 = execute(STORE_CONF)
        server_1 = Server(
            OPConfiguration(conf=ENDPOINT_CONTEXT_CONFIG, base_path=BASEDIR),
            cwd=BASEDIR,
            keyjar=_keyjar,
        )
        self.frontend[1] = Persistence()
        self.frontend[1].app = Application(server_1, store_1)
        self.frontend[1].app.server.context.cdb = {
            "client_1": {
                "client_secret": "hemligt",
                "redirect_uris": [("https://example.com/cb", None)],
                "client_salt": "salted",
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code", "token", "code id_token", "id_token"],
                "allowed_scopes": [
                    "openid",
                    "profile",
                    "email",
                    "address",
                    "phone",
                    "offline_access",
                    "research_and_scholarship",
                ],
            },
            "client_2": {
                "client_secret": "hemligt_ord",
                "redirect_uris": [("https://two.example.com/cb", None)],
                "client_salt": "salted peanuts",
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code", "code id_token", "id_token"],
                "allowed_scopes": [
                    "openid",
                    "profile",
                    "email",
                    "address",
                    "phone",
                    "offline_access",
                    "research_and_scholarship",
                ]
            }
        }

        store_2 = execute(STORE_CONF)
        server_2 = Server(
            OPConfiguration(conf=ENDPOINT_CONTEXT_CONFIG, base_path=BASEDIR),
            cwd=BASEDIR,
            keyjar=_keyjar,
        )
        self.frontend[2] = Persistence()
        self.frontend[2].app = Application(server_2, store_2)

        self.user_id = "diana"

    def _create_session(self, auth_req, sub_type="public", sector_identifier="", index=1):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id)
        return self.frontend[index].app.server.context.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_code(self, grant, session_id, index=1):
        _server = self.frontend[index].app.server
        _sman = _server.context.session_manager
        # Constructing an authorization code is now done
        _code = grant.mint_token(
            session_id,
            context=_server.context,
            token_class="authorization_code",
            token_handler=_sman.token_handler["authorization_code"]
        )

        _sman.set(_sman.decrypt_session_id(session_id), grant)

        return _code

    def _mint_access_token(self, grant, session_id, token_ref=None, index=1):
        _server = self.frontend[index].app.server
        _sman = _server.context.session_manager
        _session_info = _sman.get_session_info(session_id, client_session_info=True)

        _token = grant.mint_token(
            session_id=session_id,
            context=_server.context,
            token_class="access_token",
            token_handler=_sman.token_handler["access_token"],
            based_on=token_ref,  # Means the token (token_ref) was used to mint this token
        )

        _sman.set([self.user_id, _session_info["client_id"], grant.id], grant)

        return _token

    def test_init(self):
        assert self.frontend[1]
        self.frontend[1].store_state("client_1")
        # frontend.1 has two clients in its cdb
        self.frontend[2].update_state({"client_id": "client_1"}, {})
        # frontend.2 will only have one
        assert len(self.frontend[1].app.server.context.cdb) == 2
        assert len(self.frontend[2].app.server.context.cdb) == 1
        # nothing has really happened yet so nothing differs when it comes to grants issued (zero)

    def test_parse(self):
        session_id = self._create_session(AUTH_REQ, index=1)
        grant = self.frontend[1].app.server.context.authz(session_id, AUTH_REQ)
        # grant, session_id = self._do_grant(AUTH_REQ, index=1)
        code = self._mint_code(grant, session_id, index=1)
        access_token = self._mint_access_token(grant, session_id, code, 1)

        # store state
        self.frontend[1].store_state("client_1")
        # switch to another endpoint context instance
        # action at the userinfo endpoint

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        self.frontend[2].update_state({}, http_info)

        _endpoint = self.frontend[2].app.server.get_endpoint("userinfo")
        _req = _endpoint.parse_request({}, http_info=http_info)
        assert set(_req.keys()) == {'client_id', "access_token"}

    def test_process_request(self):
        session_id = self._create_session(AUTH_REQ, index=1)

        grant = self.frontend[1].app.server.context.authz(session_id, AUTH_REQ)
        # grant, session_id = self._do_grant(AUTH_REQ, index=1)
        code = self._mint_code(grant, session_id, index=1)
        access_token = self._mint_access_token(grant, session_id, code, 1)

        # store state
        self.frontend[1].store_state("client_1")
        # switch to another endpoint context instance
        # action at the userinfo endpoint

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        self.frontend[2].update_state({}, http_info)

        _endpoint = self.frontend[2].app.server.get_endpoint("userinfo")
        _req = _endpoint.parse_request({}, http_info=http_info)
        assert set(_req.keys()) == {'client_id', "access_token"}
        args = _endpoint.process_request(_req)
        assert args

    def test_process_request_not_allowed(self):
        session_id = self._create_session(AUTH_REQ, index=1)
        grant = self.frontend[1].app.server.context.authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, session_id, index=1)
        access_token = self._mint_access_token(grant, session_id, code, 1)

        access_token.expires_at = utc_time_sans_frac() - 60
        _sman = self.frontend[1].app.server.context.session_manager

        _sman.set([self.user_id, AUTH_REQ["client_id"], grant.id], grant)

        self.frontend[1].store_state("client_1")
        # switch to another endpoint context instance
        # action at the userinfo endpoint

        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        self.frontend[2].update_state({}, http_info)

        _endpoint = self.frontend[2].app.server.get_endpoint("userinfo")
        _req = _endpoint.parse_request({}, http_info=http_info)
        args = _endpoint.process_request(_req)
        assert set(args.keys()) == {"error", "error_description"}
        assert args["error"] == "invalid_token"

    def test_do_signed_response(self):
        _endpoint = self.frontend[1].app.server.get_endpoint("userinfo")
        _endpoint.upstream_get("context").cdb["client_1"]["userinfo_signed_response_alg"] = "ES256"

        session_id = self._create_session(AUTH_REQ, index=1)
        grant = _endpoint.upstream_get("context").authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, session_id, index=1)
        access_token = self._mint_access_token(grant, session_id, code, 1)

        self.frontend[1].store_state("client_1")
        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        self.frontend[2].update_state({}, http_info)

        _endpoint = self.frontend[2].app.server.get_endpoint("userinfo")

        _req = _endpoint.parse_request({}, http_info=http_info)
        args = _endpoint.process_request(_req)
        assert args
        res = _endpoint.do_response(request=_req, **args)
        assert res

    def test_custom_scope(self):
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]
        _endpoint = self.frontend[1].app.server.get_endpoint("authorization")
        session_id = self._create_session(_auth_req, index=1)
        grant = _endpoint.upstream_get("context").authz(session_id, _auth_req)

        # 1 -> 2
        self.frontend[1].store_state("client_1")
        self.frontend[2].update_state({"client_id": "client_1"}, {})
        _endpoint = self.frontend[2].app.server.get_endpoint("authorization")

        grant.claims = {
            "userinfo": _endpoint.upstream_get("context").claims_interface.get_claims(
                session_id, scopes=_auth_req["scope"], claims_release_point="userinfo"
            )
        }

        # 2 -> 1
        self.frontend[2].store_state("client_1")
        self.frontend[1].update_state({"client_id": "client_1"}, {})

        _sman = self.frontend[1].app.server.context.session_manager
        _sman.set(_sman.decrypt_session_id(session_id), grant)

        code = self._mint_code(grant, session_id, index=1)
        access_token = self._mint_access_token(grant, session_id, code, 1)

        # 1 -> 2
        self.frontend[1].store_state("client_1")
        http_info = {"headers": {"authorization": "Bearer {}".format(access_token.value)}}
        self.frontend[2].update_state({"client_id": "client_1"}, http_info)

        _endpoint = self.frontend[2].app.server.get_endpoint("userinfo")
        _req = _endpoint.parse_request({}, http_info=http_info)
        args = _endpoint.process_request(_req)
        assert set(args["response_args"].keys()) == {
            "sub",
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "eduperson_scoped_affiliation",
        }

    # def test_sman_db_integrity(self):
    #     """
    #     this test assures that session database remains consistent after
    #         - many consecutives flush
    #         - deletion of key or salt
    #         - some mess with values overwritten runtime
    #     it show that flush and loads method will keep order, anyway.
    #     """
    #     session_id = self._create_session(AUTH_REQ, index=1)
    #     grant = self.endpoint[1].upstream_get("context").authz(session_id, AUTH_REQ)
    #     sman = self.session_manager[1]
    #     session_dump = sman.dump()
    #
    #     # after an exception a database could be inconsistent
    #     # it would be better to always flush database when a new http request come
    #     # and load session from previously loaded sessions
    #     sman.flush()
    #     # yes, two times to simulate those things that happens in real world
    #     sman.flush()
    #
    #     # check that a sman db schema is consistent after a flush
    #     tdump = sman.dump()
    #     for i in ["db", "crypt_config"]:
    #         if i not in tdump:
    #             raise ValueError(f"{i} not found in session dump after a flush!")
    #
    #     # test that key and salt have not been touched after the flush
    #     # they wouldn't change runtime (even if they are randomic).
    #     if session_dump["crypt_config"] != tdump["crypt_config"]:
    #         raise ValueError(
    #             f"Inconsistent Session schema dump after a flush. "
    #             f"'crypt_config' has changed compared to which was configured."
    #         )
    #
    #     # ok, load the session and assert that everything is in the right place
    #     # some mess before doing that
    #     sman.crypt_config = {"password": "ingoalla", "salt": "fantozzi"}
    #
    #     # ok, end of the game, session have been loaded and all the things should finally be
    #     there!
    #     sman.load(session_dump)
    #     for i in "db", "crypt_config":
    #         assert session_dump[i] == sman.dump()[i]
    #
    # def _get_client_session_info(self, client_id, db):
    #     res = {}
    #     for key, info in db.items():
    #         val = self.session_manager[1].unpack_branch_key(key)
    #         if len(val) > 1 and val[1] == client_id:
    #             res[key] = info
    #             if val[0] not in res:
    #                 res[val[0]] = db[val[0]]
    #
    #     return res
    #
    # def test_multiple_sessions(self):
    #     session_id = self._create_session(AUTH_REQ, index=1)
    #     grant = self.endpoint[1].upstream_get("context").authz(session_id, AUTH_REQ)
    #     code = self._mint_code(grant, session_id, index=1)
    #     access_token_1 = self._mint_access_token(grant, session_id, code, 1)
    #
    #     session_id = self._create_session(AUTH_REQ_2, index=1)
    #     grant = self.endpoint[1].upstream_get("context").authz(session_id, AUTH_REQ_2)
    #     code = self._mint_code(grant, session_id, index=1)
    #     access_token_2 = self._mint_access_token(grant, session_id, code, 1)
    #
    #     _session_state = self.session_manager[1].dump()
    #     _orig_db = _session_state["db"]
    #     _client_1_db = self._get_client_session_info('client_1', _orig_db)
    #     _session_state["db"] = _client_1_db
    #
    #     self.session_manager[2].load(
    #         _session_state, init_args={"upstream_get": self.endpoint[2].upstream_get}
    #     )
    #
    #     http_info = {"headers": {"authorization": "Bearer {}".format(access_token_1.value)}}
    #     _req = self.endpoint[2].parse_request({}, http_info=http_info)
    #     args = self.endpoint[2].process_request(_req)
    #     assert args["client_id"] == "client_1"
    #
    #     # this should not work
    #
    #     http_info = {"headers": {"authorization": "Bearer {}".format(access_token_2.value)}}
    #     _req = self.endpoint[2].parse_request({}, http_info=http_info)
    #
    #     assert _req["error"] == "invalid_token"
    #
    #     _token_info = self.session_manager[1].token_handler.info(access_token_2.value)
    #     sid = _token_info.get("sid")
    #     _path = self.session_manager[1].decrypt_branch_id(sid)
    #
    #     _client_db = self._get_client_session_info(_path[1], _orig_db)
    #     _session_state["db"] = _client_db
    #
    #     self.session_manager[2].load(
    #         _session_state, init_args={"upstream_get": self.endpoint[2].upstream_get}
    #     )
    #
    #     http_info = {"headers": {"authorization": "Bearer {}".format(access_token_2.value)}}
    #     _req = self.endpoint[2].parse_request({}, http_info=http_info)
    #     args = self.endpoint[2].process_request(_req)
    #     assert args["client_id"] == "client_2"
