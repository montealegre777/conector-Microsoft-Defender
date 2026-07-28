---
name: microsoft-defender
description: "Usa la librería ruvic_microsoft_defender_connector para gestionar alertas y dispositivos en Microsoft Defender for Endpoint - listar alertas con filtro de severidad opcional (list_alerts), consultar el detalle de una máquina (get_machine_info), y aislar/liberar un dispositivo de la red (set_device_isolation). Úsala cuando el usuario pida revisar alertas de Defender, el estado de un endpoint, o aislar/liberar un dispositivo. El aislamiento está BLOQUEADO por defecto y requiere confirmación del usuario antes de usarse."
triggers:
- microsoft defender
- defender for endpoint
- aislar dispositivo
- alerta defender
---

# Conector Microsoft Defender (ruvic_microsoft_defender_connector)

Librería Python para gestionar alertas y dispositivos en Microsoft Defender for Endpoint, autenticada vía Azure AD (App Registration). Está **preinstalada en el runtime** cuando el conector está configurado (si no, instálala con `pip install git+https://github.com/tu-org/conector-microsoft-defender.git#subdirectory=lib`).

## Regla crítica de credenciales

El código generado **NUNCA hardcodea credenciales**. Siempre se leen de variables de entorno, disponibles cuando el conector `microsoft_defender` está configurado:

| Variable | Contenido |
|----------|-----------|
| `RUVIC_MS_DEFENDER_TENANT_ID` / `..._CLIENT_ID` / `..._CLIENT_SECRET` | Siempre requeridas |
| `RUVIC_MS_DEFENDER_BASE_URL` | (opcional) default `https://api.securitycenter.microsoft.com` |
| `RUVIC_MS_DEFENDER_ALLOW_ISOLATION` | (opcional) `true`/`false`, default `false` |
| `RUVIC_MS_DEFENDER_REQUEST_TIMEOUT` | (opcional) segundos, default `30` |

Si estas variables NO existen, el conector no está configurado: no generes código que lo use; indica al usuario que lo configure en **Settings → Conectores**.

El código generado **NUNCA** usa nombres de variable con segmento de alias (`_DEFAULT_`, `_TEST_`, `_PRODUCCION_`, etc.) — siempre `{ENV_PREFIX}{CAMPO}` tal cual, sin importar cuántas instancias de este conector haya configuradas. Esto aplica salvo que dichos nombres aparezcan explícitamente en una sección autogenerada al final de este skill.

## Conexión (siempre igual)

```python
from ruvic_microsoft_defender_connector import DefenderClient

client = DefenderClient()  # lee RUVIC_MS_DEFENDER_* del entorno automáticamente
```

## Capacidad 1 — Listar alertas

```python
alertas = client.list_alerts(severity="High", max_results=20)
for a in alertas:
    print(f"{a['id']}: {a['title']} ({a['severity']})")
```

## Capacidad 2 — Consultar una máquina

```python
maquina = client.get_machine_info("a1b2c3d4...")
print(f"{maquina['computer_dns_name']}: {maquina['health_status']}")
```

## Capacidad 3 — Aislar/liberar un dispositivo ⚠️

**Esta es la operación de mayor impacto del conector** — aísla una máquina de la red. Está bloqueada por defecto y solo funciona si el admin activó `allow_isolation` explícitamente:

```python
client.set_device_isolation("a1b2c3d4...", isolate=True)   # aislar
client.set_device_isolation("a1b2c3d4...", isolate=False)  # liberar
```

**Antes de llamar a esta función, confirma explícitamente la intención del usuario** — no la ejecutes por una instrucción ambigua. Si la llamada falla con `DefenderSecurityError`, informa que el aislamiento no está habilitado en este conector.

## Manejo de errores

```python
from ruvic_microsoft_defender_connector import (
    DefenderAuthError, DefenderNetworkError, DefenderSecurityError, DefenderDataError,
)

try:
    client.list_alerts()
except DefenderAuthError:
    print("Credenciales inválidas o permisos insuficientes — revisa la configuración del conector")
except DefenderNetworkError:
    print("No se pudo conectar a Microsoft Defender — revisa la red")
except DefenderSecurityError as e:
    print(f"Bloqueado por seguridad: {e}")  # aislamiento no habilitado
except DefenderDataError as e:
    print(f"Error de datos: {e}")  # ej. máquina no encontrada
```

## Buenas prácticas al generar código

1. Lee credenciales SOLO de las variables `RUVIC_MS_DEFENDER_*` (el constructor de `DefenderClient` ya lo hace).
2. Nunca imprimas `RUVIC_MS_DEFENDER_CLIENT_SECRET` en logs ni en la salida.
3. **Siempre confirma con el usuario antes de aislar/liberar un dispositivo** — es una acción real y disruptiva.
4. No intentes eliminar alertas ni gestionar políticas de Defender: este conector no lo soporta.
