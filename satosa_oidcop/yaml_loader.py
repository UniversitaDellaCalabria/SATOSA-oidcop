"""
YAML config loader with !ENV and !ENVFILE support.

Uses SATOSA's YAML loader to resolve environment variables in config,
consistent with pyeudiw and other SATOSA backends/frontends.
"""
import logging
import os

logger = logging.getLogger(__name__)


def load_yaml_with_env(config_source):
    """
    Load YAML configuration with !ENV and !ENVFILE tag support.

    Environment variables in the YAML are resolved at load time:
    - !ENV VARIABLE_NAME: replaced with os.environ.get("VARIABLE_NAME")
    - !ENVFILE VARIABLE_NAME: replaced with contents of file path in env var

    :param config_source: File path (str) or file-like object or YAML string
    :return: Parsed configuration as dict
    """
    from satosa.yaml import load as yaml_load

    if isinstance(config_source, str):
        if os.path.isfile(config_source):
            with open(config_source, "rt", encoding="utf-8") as f:
                return yaml_load(f.read())
        return yaml_load(config_source)
    elif hasattr(config_source, "read"):
        return yaml_load(config_source.read())
    else:
        raise TypeError(f"config_source must be path, file object or string, got {type(config_source)}")
