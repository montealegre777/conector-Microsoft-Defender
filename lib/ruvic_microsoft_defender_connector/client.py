"""Cliente para gestionar alertas y dispositivos en Microsoft Defender for Endpoint.

Capacidades:
- list_alerts():            listar alertas, con filtro opcional.
- get_machine_info():       consultar el detalle de una máquina.
- set_device_isolation():   aislar o liberar un dispositivo de la red.

Protección de seguridad incorporada: `set_device_isolation` está
**bloqueada por defecto** — es la acción de mayor impacto que expone
este conector (aislar una máquina de la red es una acción real y
disruptiva). Solo se ejecuta si `allow_isolation` está habilitado
explícitamente en la configuración del conector.

Autenticación: Azure AD App Registration (Client Credentials OAuth2).
Las credenciales SIEMPRE provienen de variables de entorno
RUVIC_MS_DEFENDER_* (ver config.DefenderConfig.from_env). Prohibido
hardcodearlas.
"""

from __future__ import annotations

import time
from typing import Any

import requests
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException, Timeout

from .config import DefenderConfig, _TOKEN_SCOPE
from .exceptions import (
    DefenderAuthError,
    DefenderDataError,
    DefenderNetworkError,
    DefenderSecurityError,
)
from .logging_utils import get_logger

_TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


class DefenderClient:
    """Cliente de Microsoft Defender for Endpoint autenticado vía Azure AD.

    Args:
        config: configuración de conexión. Si se omite, se lee de las
            variables de entorno RUVIC_MS_DEFENDER_* (comportamiento
            estándar en el runtime de la plataforma).

    Ejemplo:
        >>> client = DefenderClient()  # lee RUVIC_MS_DEFENDER_* del entorno
        >>> client.list_alerts(max_results=10)
        [{'id': '...', 'severity': 'High', ...}, ...]
    """

    def __init__(self, config: DefenderConfig | None = None) -> None:
        self.config = config or DefenderConfig.from_env()
        self._logger = get_logger()
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------ #
    # Autenticación (Azure AD Client Credentials)
    # ------------------------------------------------------------------ #

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token

        url = _TOKEN_URL_TEMPLATE.format(tenant_id=self.config.tenant_id)
        try:
            resp = requests.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "scope": _TOKEN_SCOPE,
                },
                timeout=self.config.timeout,
            )
        except Timeout as exc:
            raise DefenderNetworkError("Tiempo de espera agotado autenticando con Azure AD.") from exc
        except RequestsConnectionError as exc:
            raise DefenderNetworkError(f"No se pudo conectar a Azure AD: {exc}") from exc
        except RequestException as exc:
            raise DefenderNetworkError(f"Error de red autenticando con Azure AD: {exc}") from exc

        if resp.status_code != 200:
            raise DefenderAuthError(
                f"Azure AD rechazó la autenticación (HTTP {resp.status_code}): {resp.text[:300]}. "
                "Revisa tenant_id, client_id y client_secret."
            )

        payload = resp.json()
        self._token = payload["access_token"]
        self._token_expires_at = time.time() + int(payload.get("expires_in", 3600))
        return self._token

    # ------------------------------------------------------------------ #
    # Peticiones HTTP
    # ------------------------------------------------------------------ #

    def _request(self, method: str, path: str, **extra: Any) -> requests.Response:
        token = self._get_token()
        url = f"{self.config.base_url}{path}"
        headers = extra.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        try:
            return requests.request(method, url, headers=headers, timeout=self.config.timeout, **extra)
        except Timeout as exc:
            raise DefenderNetworkError(f"Tiempo de espera agotado llamando a {path}.") from exc
        except RequestsConnectionError as exc:
            raise DefenderNetworkError(f"No se pudo conectar a {url}: {exc}") from exc
        except RequestException as exc:
            raise DefenderNetworkError(f"Error de red: {exc}") from exc

    def _raise_for_error(self, resp: requests.Response, context: str) -> None:
        try:
            payload = resp.json()
            message = payload.get("error", {}).get("message", resp.text[:300])
        except (ValueError, AttributeError):
            message = resp.text[:300] or "Error desconocido"

        if resp.status_code in (401, 403):
            raise DefenderAuthError(
                f"Permisos insuficientes en {context} (HTTP {resp.status_code}): {message}. "
                "La app necesita los permisos de aplicación 'Alert.Read.All' y "
                "'Machine.Read.All' (y 'Machine.Isolate' si se usa el aislamiento)."
            )
        if resp.status_code == 404:
            raise DefenderDataError(f"No encontrado en {context}: {message}")
        if resp.status_code == 400:
            raise DefenderDataError(f"Solicitud inválida en {context}: {message}")
        raise DefenderDataError(f"Error de Microsoft Defender en {context} (HTTP {resp.status_code}): {message}")

    # ------------------------------------------------------------------ #
    # Ping / prueba de conexión
    # ------------------------------------------------------------------ #

    def ping(self) -> bool:
        """Verifica las credenciales listando 1 alerta (barato)."""
        self.list_alerts(max_results=1)
        self._logger.info("Ping exitoso a Microsoft Defender (%s)", self.config.base_url)
        return True

    # ------------------------------------------------------------------ #
    # Capacidad 1: listar alertas
    # ------------------------------------------------------------------ #

    def list_alerts(self, severity: str | None = None, max_results: int = 50) -> list[dict[str, Any]]:
        """Lista alertas, opcionalmente filtradas por severidad.

        Args:
            severity: filtra por severidad ("Informational", "Low",
                "Medium", "High"). Opcional.
            max_results: máximo de resultados (default 50).

        Returns:
            Lista de dicts con "id", "title", "severity", "status",
            "machine_id", "created_time".

        Ejemplo:
            >>> client.list_alerts(severity="High", max_results=10)
            [{'id': '...', 'title': 'Suspicious activity', ...}, ...]
        """
        params: dict[str, Any] = {"$top": max_results}
        if severity:
            params["$filter"] = f"severity eq '{severity}'"

        resp = self._request("GET", "/api/alerts", params=params)
        if resp.status_code != 200:
            self._raise_for_error(resp, "list_alerts")

        items = resp.json().get("value", [])
        alerts = [
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "severity": item.get("severity"),
                "status": item.get("status"),
                "machine_id": item.get("machineId"),
                "created_time": item.get("alertCreationTime"),
            }
            for item in items
        ]
        self._logger.info("list_alerts: %d resultado(s)", len(alerts))
        return alerts

    # ------------------------------------------------------------------ #
    # Capacidad 2: consultar una máquina
    # ------------------------------------------------------------------ #

    def get_machine_info(self, machine_id: str) -> dict[str, Any]:
        """Consulta el detalle de una máquina.

        Args:
            machine_id: Id de la máquina en Defender.

        Returns:
            Dict con "id", "computer_dns_name", "os_platform",
            "health_status", "risk_score", "last_ip_address".

        Ejemplo:
            >>> client.get_machine_info("a1b2c3...")
            {'id': '...', 'computer_dns_name': 'WKS-001', ...}
        """
        if not machine_id or not machine_id.strip():
            raise DefenderDataError("machine_id no puede estar vacío.")

        resp = self._request("GET", f"/api/machines/{machine_id.strip()}")
        if resp.status_code != 200:
            self._raise_for_error(resp, f"get_machine_info {machine_id}")

        item = resp.json()
        return {
            "id": item.get("id"),
            "computer_dns_name": item.get("computerDnsName"),
            "os_platform": item.get("osPlatform"),
            "health_status": item.get("healthStatus"),
            "risk_score": item.get("riskScore"),
            "last_ip_address": item.get("lastIpAddress"),
        }

    # ------------------------------------------------------------------ #
    # Capacidad 3: aislar / liberar un dispositivo
    # ------------------------------------------------------------------ #

    def set_device_isolation(
        self, machine_id: str, isolate: bool, comment: str = "Aislamiento solicitado vía Ruvic"
    ) -> dict[str, Any]:
        """Aísla (de la red) o libera un dispositivo.

        ⚠️ Esta es la operación de mayor impacto de este conector — aislar
        una máquina de la red es una acción real y disruptiva. Está
        **bloqueada por defecto**: solo se ejecuta si `allow_isolation`
        está habilitado explícitamente en la configuración del conector.

        Args:
            machine_id: Id de la máquina a aislar/liberar.
            isolate: `True` para aislar, `False` para liberar.
            comment: comentario que queda registrado en Defender (requerido
                por la API).

        Returns:
            Dict con "machine_id" y "action" ("isolate" o "unisolate").

        Raises:
            DefenderSecurityError: si `allow_isolation` no está habilitado.

        Ejemplo:
            >>> client.set_device_isolation("a1b2c3...", isolate=True)
            {'machine_id': 'a1b2c3...', 'action': 'isolate', 'success': True}
        """
        if not self.config.allow_isolation:
            raise DefenderSecurityError(
                "El aislamiento de dispositivos está bloqueado por defecto. Para "
                "permitirlo, activa 'allow_isolation' explícitamente en la "
                "configuración del conector — es una acción de alto impacto "
                "(aísla la máquina de la red)."
            )
        if not machine_id or not machine_id.strip():
            raise DefenderDataError("machine_id no puede estar vacío.")

        action = "isolate" if isolate else "unisolate"
        body: dict[str, Any] = {"Comment": comment}
        if isolate:
            body["IsolationType"] = "Full"

        resp = self._request(
            "POST", f"/api/machines/{machine_id.strip()}/{action}", json=body
        )
        if resp.status_code not in (200, 201):
            self._raise_for_error(resp, f"set_device_isolation {machine_id}")

        self._logger.info("Dispositivo %s: accion=%s", machine_id, action)
        return {"machine_id": machine_id, "action": action, "success": True}
