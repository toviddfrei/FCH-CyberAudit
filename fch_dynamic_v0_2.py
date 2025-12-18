# ================================================================================================================
# fch_dynamic_v0_2.py
# Módulo de Vigilancia Dinámica, Intervención de Usuario, Integridad de Paquetes y Auto-Aprendizaje
# Versión: 0.2.8 (Premium) - Fecha: 2025-12-18
# Autor: Daniel Miñana Montero & Gemini básico
# =================================================================================================================
# DESCRIPCIÓN PEDAGÓGICA:
# Este script actúa como un "Sistema de Prevención de Intrusiones" (IPS) a nivel de proceso.
# 1. MONITORIZA: Escanea la RAM buscando procesos activos.
# 2. AUDITA: Verifica si el binario en disco ha sido alterado comparando su hash con la base oficial (dpkg).
# 3. ENSEÑA: Utiliza una base de datos JSON para explicar al usuario la función de cada proceso.
# 4. APRENDE: Si un proceso es oficial y seguro, lo registra automáticamente para no volver a preguntar.
# 5. PROTEGE: Bloquea procesos sospechosos si el usuario no autoriza su ejecución.
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
# SECCIÓN 1: CONFIGURACIÓN, RUTAS Y DETECCIÓN DE ENTORNO
# Esta sección establece los cimientos. Identifica el sistema operativo para saber qué "lenguaje" (comandos) 
# debe hablar con el gestor de paquetes y define dónde están los archivos de bitácora y conocimiento.
# =================================================================================================================

# Rutas estándar según el Filesystem Hierarchy Standard (FHS). 
# Todo lo que corra fuera de aquí es, por definición, digno de ser inspeccionado.
DIR_CRITICOS = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/libexec']
INTERVALO_ESCANEADO = 5 
TIEMPO_DECISION = 15  # Segundos que el sistema espera una respuesta humana antes de actuar.

# Trazabilidad y almacenamiento de inteligencia local
AHORA_DYN = datetime.now().strftime("%Y%m%d_%H%M%S")
NOMBRE_LOG_DYNAMIC = f"incidencias_ram_{AHORA_DYN}.csv"
BASE_JSON = "base_conocimiento.json"

def detectar_distribucion():
    """ 
    Detecta la 'familia' de la distribución Linux. 
    Esto es crucial porque un sistema Debian usa 'dpkg' mientras que un RedHat usa 'rpm'.
    """
    if os.path.exists("/etc/debian_version"):
        return "debian_ubuntu"
    return "base_general"

SISTEMA_ACTUAL = detectar_distribucion()

# =================================================================================================================
# SECCIÓN 2: MOTOR DE INTELIGENCIA Y GESTIÓN DE LA BASE DE CONOCIMIENTO (JSON)
# Aquí reside la 'memoria' del script. El archivo JSON permite que el script no sea una herramienta muda,
# sino que pueda dar explicaciones pedagógicas sobre los procesos del sistema.
# =================================================================================================================

def cargar_conocimiento():
    """ Lee el archivo JSON. Si no existe, inicializa una estructura básica. """
    if os.path.exists(BASE_JSON):
        try:
            with open(BASE_JSON, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️ Error cargando JSON: {e}")
    return {"sistemas": {SISTEMA_ACTUAL: {"procesos_standard": {}}}}

def guardar_conocimiento(datos):
    """ Escribe la memoria actualizada en el disco para que el aprendizaje sea permanente. """
    try:
        with open(BASE_JSON, 'w', encoding='utf-8') as f:
            json.dump(datos, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ Error al guardar conocimiento: {e}")

CONOCIMIENTO = cargar_conocimiento()

def obtener_explicacion(nombre_proc):
    """ Busca en la base de datos local la descripción pedagógica del proceso. """
    dict_proc = CONOCIMIENTO.get("sistemas", {}).get(SISTEMA_ACTUAL, {}).get("procesos_standard", {})
    return dict_proc.get(nombre_proc, "Proceso no catalogado en la base local.")

def auto_registrar_proceso(nombre, ruta, info_adicional):
    """ 
    Función de aprendizaje: Si un proceso es validado como seguro, se añade al JSON.
    Evita la fatiga del usuario al no preguntar dos veces por lo mismo.
    """
    if SISTEMA_ACTUAL not in CONOCIMIENTO["sistemas"]:
        CONOCIMIENTO["sistemas"][SISTEMA_ACTUAL] = {"procesos_standard": {}}
    
    desc = f"Verificado oficialmente: {info_adicional}. Registrado el {datetime.now()}."
    CONOCIMIENTO["sistemas"][SISTEMA_ACTUAL]["procesos_standard"][nombre] = desc
    guardar_conocimiento(CONOCIMIENTO)
    print(f"📝 APRENDIZAJE: '{nombre}' ha sido añadido a la lista de confianza.")

# =================================================================================================================
# SECCIÓN 3: AUDITORÍA DE INTEGRIDAD (FORENSE DIGITAL)
# Esta es la parte más técnica. El script no confía en el nombre del archivo, sino que le pide al sistema 
# operativo que verifique si el archivo ha sido modificado bit a bit desde su instalación oficial.
# =================================================================================================================

def verificar_integridad_oficial(ruta_exe):
    """ 
    Usa herramientas de bajo nivel (dpkg) para asegurar que el binario es el original.
    Detecta si un malware ha reemplazado un archivo legítimo del sistema.
    """
    try:
        # Buscamos qué paquete instaló este archivo
        res = subprocess.run(['dpkg', '-S', ruta_exe], capture_output=True, text=True)
        if res.returncode != 0:
            return False, "Binario HUÉRFANO (No pertenece a ningún paquete oficial)."

        paquete = res.stdout.split(':')[0]
        
        # Verificamos si el hash (la huella digital) actual coincide con la de fábrica
        verif = subprocess.run(['dpkg', '--verify', paquete], capture_output=True, text=True)
        if ruta_exe in verif.stdout:
            return False, f"¡MODIFICADO! El hash no coincide con el original de {paquete}."
        
        return True, f"Paquete oficial: {paquete}"
    except Exception as e:
        return False, f"Error en auditoría: {e}"

# =================================================================================================================
# SECCIÓN 4: GESTIÓN DE AMENAZAS E INTERVENCIÓN
# El 'tribunal' del script. Aquí se presenta la evidencia al usuario y se decide si el proceso vive o muere.
# Implementa el bloqueo preventivo si no hay respuesta, siguiendo el principio de 'seguridad por defecto'.
# =================================================================================================================

def gestionar_amenaza(pid, nombre, ruta, tipo_alerta):
    """ Muestra la pedagogía y la integridad, y espera la decisión del usuario. """
    leccion = obtener_explicacion(nombre)
    integridad_ok, msg_integ = verificar_integridad_oficial(ruta)

    # AUTO-APRENDIZAJE: Si es oficial y no estaba en el JSON, lo registramos y dejamos pasar.
    if integridad_ok and "no catalogado" in leccion:
        auto_registrar_proceso(nombre, ruta, msg_integ)
        return

    print(f"\n" + "!"*90)
    print(f"🚨 ALERTA DE SEGURIDAD DINÁMICA")
    print(f"   PROCESO: {nombre} (PID: {pid})")
    print(f"   RUTA: {ruta} | ALERTA: {tipo_alerta}")
    print(f"   INTEGRIDAD: {msg_integ}")
    print(f"   PEDAGOGÍA: {leccion}")
    print("!"*90)
    print(f"\nAcción requerida: [P] Permitir y Registrar | [B] Bloquear | [Enter] Ignorar")
    
    rlist, _, _ = select.select([sys.stdin], [], [], TIEMPO_DECISION)
    
    if rlist:
        accion = sys.stdin.readline().strip().lower()
        if accion == 'p':
            auto_registrar_proceso(nombre, ruta, "Autorizado manualmente por usuario")
            registrar_evento(pid, nombre, ruta, tipo_alerta, "PERMITIDO_MANUAL")
            return
        elif accion == 'b':
            bloquear_proceso(pid)
            return

    # Si la integridad falló y no hubo respuesta, bloqueamos por seguridad absoluta.
    if not integridad_ok:
        print(f"⏰ Tiempo agotado. Bloqueando por falta de integridad oficial.")
        bloquear_proceso(pid)

def bloquear_proceso(pid):
    """ Finaliza el proceso de forma inmediata. """
    try:
        p = psutil.Process(pid)
        p.terminate()
        print(f"🛑 BLOQUEADO: El proceso {pid} ha sido finalizado.")
        registrar_evento(pid, "N/A", "N/A", "BLOQUEO_SEGURIDAD", "TERMINADO")
    except Exception as e:
        print(f"⚠️ Error al bloquear: {e}")

def registrar_evento(pid, nombre, ruta, alerta, accion):
    """ Escribe el desenlace en el archivo CSV para auditoría forense posterior. """
    file_exists = os.path.isfile(NOMBRE_LOG_DYNAMIC)
    with open(NOMBRE_LOG_DYNAMIC, mode='a', newline='', encoding='utf-8') as f:
        escritor = csv.writer(f)
        if not file_exists:
            escritor.writerow(['Timestamp', 'PID', 'Nombre', 'Ruta', 'Alerta', 'Accion'])
        escritor.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), pid, nombre, ruta, alerta, accion])

# =================================================================================================================
# SECCIÓN 5: BUCLE DE VIGILANCIA (EL CENTINELA)
# El corazón del script que nunca duerme. Recorre la tabla de procesos de la RAM constantemente.
# =================================================================================================================

def iniciar_centinela():
    print(f"\n" + "█"*90)
    print(f"            MONITOR DE INTEGRIDAD DINÁMICA FCH v0.2.8 - MODO APRENDIZAJE")
    print(f"█" * 90)
    print(f"🛡️  Entorno: {SISTEMA_ACTUAL} | ⏱️  Escaneo: {INTERVALO_ESCANEADO}s")
    
    try:
        while True:
            ahora = datetime.now().strftime("%H:%M:%S")
            print(f"🔍 [{ahora}] Analizando procesos...", end="", flush=True)
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    p = proc.info
                    if not p['exe']: continue

                    # 1. Verificación de existencia (Malware Fileless / Memoria residente)
                    if not os.path.exists(p['exe']):
                        gestionar_amenaza(p['pid'], p['name'], p['exe'], "EJECUCIÓN_SIN_BINARIO")
                        continue

                    # 2. Verificación de Rutas (Zonas Seguras vs Inusuales)
                    esta_en_zona_segura = any(p['exe'].startswith(d) for d in DIR_CRITICOS)
                    es_proceso_usuario = any(p['exe'].startswith(d) for d in ['/home/', '/usr/lib/', '/snap/'])

                    if not esta_en_zona_segura and not es_proceso_usuario:
                        # Si el proceso ya está en el conocimiento como verificado, no saltar alerta
                        if obtener_explicacion(p['name']) == "Proceso no catalogado en la base local.":
                            gestionar_amenaza(p['pid'], p['name'], p['exe'], "RUTA_NO_ESTANDAR")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            print(" [OK]", flush=True)
            time.sleep(INTERVALO_ESCANEADO)

    except KeyboardInterrupt:
        print("\n" + "="*90)
        print("🛑 VIGILANCIA DETENIDA: El sistema queda bajo supervisión estándar del OS.")
        print("="*90)
        sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("🚨 ERROR: Se requieren privilegios de ROOT para auditar la RAM.")
        sys.exit(1)
    iniciar_centinela()