"""Configuración del conector leída desde variables de entorno.

Convención de la plataforma: cada campo del formulario de configuración
llega como variable de entorno {ENV_PREFIX}{CAMPO} en mayúsculas.
Para este conector el prefijo es RUVIC_MS_DEFENDER_.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ENV_PREFIX = "RUVIC_MS_DEFENDER_"

_DEFAULT_BASE_URL = "https://api.securitycenter.microsoft.com"
_TOKEN_SCOPE = "https://api.securitycenter.microsoft.com/.default"


@dataclass(frozen=True)
class DefenderConfig:
    """Parámetros de conexión a Microsoft Defender for Endpoint."""

    tenant_id: str
    client_id: str
    client_secret: str
    base_url: str = _DEFAULT_BASE_URL
    allow_isolation: bool = False
    timeout: int = 30

    @classmethod
    def from_env(cls) -> "DefenderConfig":
        """Construye la configuración desde las variables RUVIC_MS_DEFENDER_*.

        Raises:
            ValueError: si falta TENANT_ID, CLIENT_ID o CLIENT_SECRET.
        """
        tenant_id = os.environ.get(f"{ENV_PREFIX}TENANT_ID", "").strip()
        client_id = os.environ.get(f"{ENV_PREFIX}CLIENT_ID", "").strip()
        client_secret = os.environ.get(f"{ENV_PREFIX}CLIENT_SECRET", "").strip()

        missing = [
            name for name, val in (
                (f"{ENV_PREFIX}TENANT_ID", tenant_id),
                (f"{ENV_PREFIX}CLIENT_ID", client_id),
                (f"{ENV_PREFIX}CLIENT_SECRET", client_secret),
            ) if not val
        ]
        if missing:
            raise ValueError(
                "Faltan variables de entorno del conector microsoft_defender: "
                + ", ".join(missing)
                + ". Configura el conector en Settings → Conectores."
            )

        base_url = os.environ.get(f"{ENV_PREFIX}BASE_URL", "").strip() or _DEFAULT_BASE_URL
        allow_isolation_raw = os.environ.get(f"{ENV_PREFIX}ALLOW_ISOLATION", "false").strip().lower()

        return cls(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url.rstrip("/"),
            allow_isolation=allow_isolation_raw in ("true", "1", "yes"),
            timeout=int(os.environ.get(f"{ENV_PREFIX}REQUEST_TIMEOUT", "30")),
        )
