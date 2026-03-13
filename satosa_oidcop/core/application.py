import logging
import os

from idpyoidc.server.configure import OPConfiguration
from idpyoidc.server import Server
from idpyoidc.server.util import importer

from satosa_oidcop.yaml_loader import load_yaml_with_env


folder = os.path.dirname(os.path.realpath(__file__))
logger = logging.getLogger(__name__)


def oidc_provider_init_app(config, name="oidc_op", **kwargs):
    name = name or __name__
    app = type("OidcOpApp", (object,), {"srv_config": config})
    app.server = Server(config, cwd=folder)
    return app


def oidcop_application(conf: dict):
    domain = conf.get("domain")
    server_info = conf["op"]["server_info"]
    # Support server_info as file path (loaded with !ENV support)
    if isinstance(server_info, str):
        server_info = load_yaml_with_env(server_info)
    config = OPConfiguration(conf=server_info, domain=domain)
    app = oidc_provider_init_app(config)

    # app customs
    app.default_target_backend = conf.get("default_target_backend")
    app.salt_size = conf.get("salt_size", 8)

    _strg = conf["storage"]
    app.storage = importer(_strg["class"])(_strg, **_strg["kwargs"])
    return app
