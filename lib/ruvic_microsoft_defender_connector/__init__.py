"""Conector Ruvic para Microsoft Defender for Endpoint (alertas, máquinas, aislamiento)."""

from .client import DefenderClient
from .config import ENV_PREFIX, DefenderConfig
from .exceptions import (
    DefenderAuthError,
    DefenderConfigError,
    DefenderConnectorError,
    DefenderDataError,
    DefenderNetworkError,
    DefenderSecurityError,
)
from .logging_utils import setup_logging

__all__ = [
    "ENV_PREFIX",
    "DefenderAuthError",
    "DefenderClient",
    "DefenderConfig",
    "DefenderConfigError",
    "DefenderConnectorError",
    "DefenderDataError",
    "DefenderNetworkError",
    "DefenderSecurityError",
    "setup_logging",
]

__version__ = "1.0.0"
