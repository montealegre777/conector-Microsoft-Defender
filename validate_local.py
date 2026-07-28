"""Validación local del conector microsoft_defender: ejercita las 3 capacidades.

Requiere las env vars RUVIC_MS_DEFENDER_* exportadas contra un tenant real
de Microsoft Defender for Endpoint (no existe una versión local/Docker —
es un servicio de Microsoft 365/Azure). Usa un tenant de prueba, no uno
productivo.

El aislamiento (set_device_isolation) NO se ejercita automáticamente
aquí por ser una acción de alto impacto — pruébalo manualmente y con
cuidado.
"""

from ruvic_microsoft_defender_connector import DefenderClient, setup_logging

setup_logging("INFO")
client = DefenderClient()

print("== 1. Listar alertas recientes ==")
alertas = client.list_alerts(max_results=5)
print(f"  {len(alertas)} alerta(s)")
for a in alertas:
    print(f"    {a}")

if alertas and alertas[0].get("machine_id"):
    machine_id = alertas[0]["machine_id"]
    print(f"== 2. Consultar la maquina {machine_id} de la primera alerta ==")
    maquina = client.get_machine_info(machine_id)
    print(f"  {maquina}")
else:
    print("== 2. Se omite (no hay alertas con machine_id para inspeccionar) ==")

print(
    "\n== 3. set_device_isolation NO se ejercita aquí automáticamente ==\n"
    "Es una acción de alto impacto (aísla un dispositivo de la red). Pruébala manualmente:\n\n"
    "  client.set_device_isolation('MACHINE_ID_REAL', isolate=True)\n\n"
    "Requiere ademas que 'allow_isolation' este activo en la configuracion.\n"
)

print("Validación completa.")
