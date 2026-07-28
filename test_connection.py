"""Prueba de conexión estándar del conector microsoft_defender.

Firma estándar Ruvic: def test_connection() -> tuple[bool, str]
- Lee la configuración EXCLUSIVAMENTE de las env vars RUVIC_MS_DEFENDER_*.
- Nunca lanza excepciones; retorna (ok, mensaje).

Ejecutable también como script para pruebas locales:
    python test_connection.py
"""

from __future__ import annotations


def test_connection() -> tuple[bool, str]:
    """Verifica las credenciales listando 1 alerta."""
    try:
        from ruvic_microsoft_defender_connector import (
            DefenderAuthError,
            DefenderClient,
            DefenderDataError,
            DefenderNetworkError,
        )
    except ImportError:
        return (
            False,
            "La librería ruvic-microsoft-defender-connector no está instalada. "
            "Instala con: pip install git+https://github.com/tu-org/"
            "conector-microsoft-defender.git#subdirectory=lib",
        )

    try:
        client = DefenderClient()  # valida config
    except ValueError as exc:
        return False, str(exc)

    try:
        client.ping()
    except DefenderAuthError as exc:
        return False, f"Autenticación fallida: {exc}"
    except DefenderNetworkError as exc:
        return False, f"Error de red: {exc}"
    except DefenderDataError as exc:
        return False, f"Error de datos: {exc}"
    except Exception as exc:  # red de seguridad: jamás propagar
        return False, f"Error inesperado: {exc}"

    return True, f"Conexión exitosa a {client.config.base_url}"


if __name__ == "__main__":
    ok, message = test_connection()
    print(f"{'OK' if ok else 'FALLO'}: {message}")
    raise SystemExit(0 if ok else 1)
