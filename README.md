# conector-microsoft-defender

Conector Ruvic para Microsoft Defender for Endpoint: listar alertas, consultar una máquina, y aislar/liberar un dispositivo.

## Capacidades

`list_alerts`, `get_machine_info`, `set_device_isolation`. El aislamiento está **bloqueado por defecto** — requiere `allow_isolation=true` explícito en la configuración.

## Instalación

Requiere **Python ≥ 3.10**.

```bash
pip install git+https://github.com/tu-org/conector-microsoft-defender.git#subdirectory=lib
```

Para desarrollo local (editable, en un venv limpio):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ./lib
```

## Variables de entorno

| Variable | Obligatoria | Descripción |
|----------|-------------|-------------|
| `RUVIC_MS_DEFENDER_TENANT_ID` / `..._CLIENT_ID` / `..._CLIENT_SECRET` | Sí | Credenciales de la App Registration de Azure AD |
| `RUVIC_MS_DEFENDER_BASE_URL` | No | Default `https://api.securitycenter.microsoft.com` |
| `RUVIC_MS_DEFENDER_ALLOW_ISOLATION` | No | `true`/`false`, default `false` |
| `RUVIC_MS_DEFENDER_REQUEST_TIMEOUT` | No | Segundos, default `30` |

## Permisos / prerrequisitos en Azure

1. Registra una app en **Azure Portal → Microsoft Entra ID → App registrations → New registration**.
2. Genera un **Client Secret** (Certificates & secrets) — cópialo de inmediato.
3. En **API permissions → Add a permission → APIs my organization uses**, busca **"WindowsDefenderATP"**.
4. Selecciona **Application permissions** (no delegadas — este conector corre sin usuario interactivo) y agrega: **Alert.Read.All**, **Machine.Read.All**, y solo si vas a permitir aislamiento, **Machine.Isolate**.
5. Haz clic en **"Grant admin consent"** — sin esto, los permisos de aplicación no funcionan.
6. Anota Tenant ID, Client ID (Application ID), y el Client Secret.

## Cómo correr las pruebas locales

Microsoft Defender no tiene una versión local/Docker (es un servicio de Microsoft 365/Azure) — hace falta un tenant real, idealmente uno de prueba (Microsoft ofrece trials de Microsoft 365 Defender).

```bash
export RUVIC_MS_DEFENDER_TENANT_ID=xxxx
export RUVIC_MS_DEFENDER_CLIENT_ID=xxxx
export RUVIC_MS_DEFENDER_CLIENT_SECRET=xxxx

python test_connection.py
python validate_local.py
```

## Limitaciones conocidas

- No elimina alertas ni gestiona políticas de Defender ni exclusiones.
- El aislamiento está bloqueado por defecto — habilítalo solo con necesidad real confirmada.
- No implementa la recolección de paquetes de investigación (investigation package) ni ejecución de scripts remotos.

## Notas de integración

- El paquete pip es `ruvic-microsoft-defender-connector`; el import name es `ruvic_microsoft_defender_connector`.
- Única dependencia externa: `requests`.
- Ver `SKILL.md` para los ejemplos de uso que consume el agente.
