# ================================================================================================================
# fch_dynamic_v0_2.py
# Módulo de Vigilancia Dinámica, Intervención de Usuario e Integridad de Paquetes
# Versión: 0.2.5 (Premium) - Fecha: 2025-12-18
# Autor: Daniel Miñana Montero & Gemini básico
# Descripción:
# Este módulo protege la RAM. Detecta procesos sospechosos, verifica su hash contra
# la base oficial del sistema (dpkg) y consulta una base pedagógica JSON para
# explicar al usuario qué está ocurriendo antes de tomar una acción de bloqueo.
# =================================================================================================================

import os
import hashlib
import psutil
import time
import sys
import csv
import subprocess
import json
import select
from datetime import datetime

# =================================================================================================================
# SECCIÓN 1: CONFIGURACIÓN Y DETECCIÓN DE ENTORNO
# =================================================================================================================

# Rutas estándar según el estándar FHS (Filesystem Hierarchy Standard)
DIR_CRITICOS = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/libexec']
INTERVALO_ESCANEADO = 5 
TIEMPO_DECISION = 15  # Tiempo que damos al usuario para leer la pedagogía

# Archivos de Datos
AHORA_DYN = datetime.now().strftime("%Y%m%d_%H%M%S")
NOMBRE_LOG_DYNAMIC = f"incidencias_ram_{AHORA_DYN}.csv"
BASE_JSON = "base_conocimiento.json"

def detectar_distribucion():
    """ Identifica si estamos en Debian/Ubuntu para usar dpkg. """
    if os.path.exists("/etc/debian_version"):
        return "debian_ubuntu"
    return "base_general"

# =================================================================================================================
# SECCIÓN 2: MOTOR DE INTELIGENCIA Y PEDAGOGÍA
# =================================================================================================================

def cargar_conocimiento():
    """ Carga el diccionario de procesos desde el archivo JSON externo. """
    if os.path.exists(BASE_JSON):
        with open(BASE_JSON, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {"sistemas": {}}

CONOCIMIENTO = cargar_conocimiento()
SISTEMA_ACTUAL = detectar_distribucion()

def obtener_leccion_pedagogica(nombre_proc):
    """ Busca en el JSON qué hace el proceso para enseñárselo al usuario. """
    dict_sistemas = CONOCIMIENTO.get("sistemas", {}).get(SISTEMA_ACTUAL, {})
    return dict_sistemas.get("procesos_standard", {}).get(nombre_proc, "Proceso no catalogado en la base local.")

# =================================================================================================================
# SECCIÓN 3: AUDITORÍA DE INTEGRIDAD (HASH OFICIAL)
# =================================================================================================================

def verificar_integridad_oficial(ruta_exe):
    """ 
    Comprueba si el binario en RAM coincide con el instalado por el sistema.
    Usa 'dpkg -S' para hallar el paquete y 'dpkg --verify' para el hash.
    """
    try:
        # 1. Hallar paquete propietario
        res = subprocess.run(['dpkg', '-S', ruta_exe], capture_output=True, text=True)
        if res.returncode != 0:
            return False, "Binario huérfano (No instalado por gestor oficial)."

        paquete = res.stdout.split(':')[0]
        
        # 2. Verificar si el hash ha cambiado
        verif = subprocess.run(['dpkg', '--verify', paquete], capture_output=True, text=True)
        if ruta_exe in verif.stdout:
            return False, f"¡AVISO! El hash actual NO coincide con el original del paquete {paquete}."
        
        return True, f"Integridad confirmada (Paquete: {paquete})."
    except Exception as e:
        return False, f"Error en auditoría: {e}"

# =================================================================================================================
# SECCIÓN 4: INTERVENCIÓN Y BLOQUEO
# =================================================================================================================

def gestionar_amenaza(pid, nombre, ruta, tipo_alerta):
    """ El punto de decisión. Muestra la información y espera la orden del usuario. """
    leccion = obtener_leccion_pedagogica(nombre)
    integridad_ok, msg_integridad = verificar_integridad_oficial(ruta)

    print(f"\n" + "!"*80)
    print(f"🚨 EVENTO DE SEGURIDAD EN PROCESO: {nombre} (PID: {pid})")
    print(f"📂 RUTA: {ruta}")
    print(f"🔍 ALERTA: {tipo_alerta}")
    print(f"🛠️  INTEGRIDAD: {msg_integridad}")
    print(f"📖 PEDAGOGÍA: {leccion}")
    print("!"*80)
    print(f"\n¿Desea PERMITIR este proceso? (Presione 'p' y Enter / Deje pasar {TIEMPO_DECISION}s para BLOQUEAR): ")

    # Espera interactiva
    rlist, _, _ = select.select([sys.stdin], [], [], TIEMPO_DECISION)
    
    if rlist:
        if sys.stdin.readline().strip().lower() == 'p':
            print(f"✅ USUARIO autorizó el proceso. Continuando vigilancia...")
            registrar_log(pid, nombre, ruta, tipo_alerta, "PERMITIDO_USUARIO")
            return

    # Acción de bloqueo preventivo
    try:
        p = psutil.Process(pid)
        p.terminate()
        print(f"🛑 SEGURIDAD: Proceso {pid} terminado automáticamente.")
        registrar_log(pid, nombre, ruta, tipo_alerta, "BLOQUEADO_PREVENTIVO")
    except Exception as e:
        print(f"⚠️ No se pudo detener el proceso: {e}")

def registrar_log(pid, nombre, ruta, alerta, accion):
    file_exists = os.path.isfile(NOMBRE_LOG_DYNAMIC)
    with open(NOMBRE_LOG_DYNAMIC, mode='a', newline='', encoding='utf-8') as f:
        escritor = csv.writer(f)
        if not file_exists:
            escritor.writerow(['Fecha', 'PID', 'Nombre', 'Ruta', 'Alerta', 'Accion'])
        escritor.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), pid, nombre, ruta, alerta, accion])

# =================================================================================================================
# SECCIÓN 5: BUCLE PRINCIPAL (CENTINELA)
# =================================================================================================================

def iniciar_vigilancia():
    print(f"\n[🛡️ ] VIGILANTE DINÁMICO v0.2.5 - ENTORNO: {SISTEMA_ACTUAL}")
    print(f"[ℹ️ ] Monitorizando cada {INTERVALO_ESCANEADO}s...")
    print("-" * 100)

    try:
        while True:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pinfo = proc.info
                    if not pinfo['exe']: continue

                    # Prueba 1: Existencia en disco (Fileless Malware)
                    if not os.path.exists(pinfo['exe']):
                        gestionar_amenaza(pinfo['pid'], pinfo['name'], pinfo['exe'], "MALWARE_SIN_ARCHIVO")
                        continue

                    # Prueba 2: Ruta no estándar
                    es_seguro = any(pinfo['exe'].startswith(d) for d in DIR_CRITICOS)
                    es_usuario = any(pinfo['exe'].startswith(d) for d in ['/home/', '/usr/lib/'])

                    if not es_seguro and not es_usuario:
                        gestionar_amenaza(pinfo['pid'], pinfo['name'], pinfo['exe'], "RUTA_INHABITUAL")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            time.sleep(INTERVALO_ESCANEADO)
            print(".", end="", flush=True)

    except KeyboardInterrupt:
        print("\n🛑 Centinela desactivado por el usuario.")
        sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("🚨 Error: Ejecuta con sudo.")
        sys.exit(1)
    iniciar_vigilancia()