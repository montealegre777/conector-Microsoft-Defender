"""Excepciones propias del conector Microsoft Defender for Endpoint.

Separan los tipos de fallo que el usuario debe distinguir: configuración
inválida, autenticación (Azure AD), red, seguridad (aislamiento
bloqueado si no está habilitado explícitamente), y datos (máquina/alerta
inexistente).
"""


class DefenderConnectorError(Exception):
    """Error base del conector."""


class DefenderConfigError(DefenderConnectorError):
    """Configuración inválida: falta un campo requerido."""


class DefenderAuthError(DefenderConnectorError):
    """Azure AD rechazó la autenticación, o la app no tiene los permisos necesarios."""


class DefenderNetworkError(DefenderConnectorError):
    """No se pudo alcanzar la API de Microsoft Defender (DNS, timeout, red)."""


class DefenderSecurityError(DefenderConnectorError):
    """La operación de aislamiento fue bloqueada porque `allow_isolation`
    no está habilitado explícitamente en la configuración."""


class DefenderDataError(DefenderConnectorError):
    """La operación es válida pero la máquina/alerta no existe, o
    Microsoft Defender rechazó la operación por otra razón."""
