# ================================================================================================================
# fch_dynamic_v0_1.py
# Módulo de Vigilancia Dinámica de Integridad y Detección de Procesos Sospechosos
# Versión: 0.1.1 (Premium) - Fecha: 2025-12-17
# Autor: Daniel Miñana Montero & Gemini básico
# Descripción:
# Este módulo monitoriza la memoria RAM en tiempo real para detectar procesos que se 
# ejecutan desde rutas no autorizadas o que no tienen un binario correspondiente en disco.
# Es el complemento dinámico para la auditoría de archivos fch_v0_1.py.
# Requiere: sudo apt install python3-psutil
# =================================================================================================================

# =================================================================================================================
# SECCIÓN DE IMPORTACIONES
# =================================================================================================================

import os          # El "Cartógrafo": Para validar rutas y existencia de archivos en el sistema.
import hashlib     # El "Notario": Crea firmas digitales SHA-256 para comparar disco vs memoria.
import psutil      # El "Vigilante de Procesos": Permite inspeccionar la RAM y los PIDs activos.
import time        # El "Reloj de Guardia": Gestiona los intervalos entre rondas de inspección.
import sys         # El "Control de Salida": Maneja el cierre del script y errores de entorno.
import csv         # El "Escribano": Registra los eventos sospechosos en un informe forense.
from datetime import datetime # El "Cronómetro": Fecha y hora exacta de cada incidente detectado.

# =================================================================================================================
# SECCIÓN DE CONFIGURACIÓN Y CONSTANTES (EL PERÍMETRO DE SEGURIDAD)
# =================================================================================================================

# Lista de directorios "ZONA SEGURA" donde el sistema operativo guarda sus binarios oficiales.
DIR_CRITICOS = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin']

# Frecuencia de escaneo: Cada 5 segundos ofrece una respuesta rápida para pruebas.
INTERVALO_ESCANEADO = 5 

# Trazabilidad: Nombre del archivo de log para incidencias en RAM
AHORA_DYN = datetime.now().strftime("%Y%m%d_%H%M%S")
NOMBRE_LOG_DYNAMIC = f"incidencias_ram_{AHORA_DYN}.csv"

# =================================================================================================================
# SECCIÓN DE MOTOR DE IDENTIDAD (HASHING)
# =================================================================================================================

def calcular_sha256_forense(ruta_fichero):
    """
    EL ANALISTA DE FIRMAS: Genera una huella digital SHA-256. 
    Permite asegurar que el archivo en disco no ha sido modificado.
    """
    hash_sha256 = hashlib.sha256()
    try:
        # Abrimos en modo binario de lectura (rb)
        with open(ruta_fichero, "rb") as f:
            # Lectura en bloques de 4KB para optimizar el uso de RAM del propio script
            for bloque in iter(lambda: f.read(4096), b""):
                hash_sha256.update(bloque)
        return hash_sha256.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None
    except Exception as e:
        return f"ERROR: {e}"

# =================================================================================================================
# SECCIÓN DE REGISTRO DE INCIDENCIAS (EL LIBRO DE EVENTOS)
# =================================================================================================================

def registrar_evento_sospechoso(pid, nombre, ruta, tipo_alerta):
    """
    EL REGISTRADOR: Escribe cada hallazgo sospechoso en un archivo CSV para su posterior análisis.
    """
    file_exists = os.path.isfile(NOMBRE_LOG_DYNAMIC)
    try:
        with open(NOMBRE_LOG_DYNAMIC, mode='a', newline='', encoding='utf-8') as f:
            escritor = csv.writer(f)
            if not file_exists:
                escritor.writerow(['Timestamp', 'PID', 'Nombre Proceso', 'Ruta Ejecución', 'Tipo de Alerta'])
            
            escritor.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), pid, nombre, ruta, tipo_alerta])
    except Exception as e:
        print(f"🛑 Error al escribir en el log: {e}")

# =================================================================================================================
# SECCIÓN DE VIGILANCIA ACTIVA (EL CORAZÓN DEL MONITOR)
# =================================================================================================================

def iniciar_vigilancia_ram():
    """
    EL CENTINELA: Bucle principal que proporciona feedback visual constante al usuario.
    Comprueba:
    1. Ejecuciones fuera de zonas seguras.
    2. Procesos sin archivo en disco (Fileless Malware).
    """
    print(f"\n[🛡️ ] VIGILANTE DINÁMICO ACTIVADO")
    print(f"[ℹ️ ] Escaneando procesos activos cada {INTERVALO_ESCANEADO} segundos...")
    print(f"[ℹ️ ] Informe de incidencias: {NOMBRE_LOG_DYNAMIC}")
    print("-" * 113)

    try:
        while True:
            ahora_str = datetime.now().strftime("%H:%M:%S")
            print(f"🔍 [{ahora_str}] Iniciando inspección de la RAM...", end="", flush=True)
            
            hallazgos_ronda = 0
            procesos_vistos = 0
            
            # Recorrido de todos los procesos del sistema
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    procesos_vistos += 1
                    pid = proc.info['pid']
                    nombre = proc.info['name']
                    ruta_exe = proc.info['exe']

                    # --- PRUEBA 1: VERIFICAR SI EL ARCHIVO EXISTE EN DISCO ---
                    if ruta_exe:
                        if not os.path.exists(ruta_exe) or "(deleted)" in ruta_exe:
                            print(f"\n🚨 ALERTA CRÍTICA (Fileless): '{nombre}' (PID {pid}) no existe en disco.")
                            registrar_evento_sospechoso(pid, nombre, ruta_exe, "MALWARE_FILELESS")
                            hallazgos_ronda += 1
                            continue

                        # --- PRUEBA 2: VERIFICAR SI ESTÁ EN UNA ZONA SEGURA ---
                        esta_en_zona_segura = any(ruta_exe.startswith(d) for d in DIR_CRITICOS)
                        
                        # Filtramos procesos legítimos de usuario (navegadores, escritorio) para evitar ruido
                        es_proceso_usuario = any(ruta_exe.startswith(d) for d in ['/home/', '/usr/lib/', '/snap/'])

                        if not esta_en_zona_segura and not es_proceso_usuario:
                            print(f"\n⚠️  AVISO (Ruta Inusual): '{nombre}' (PID {pid}) desde {ruta_exe}")
                            registrar_evento_sospechoso(pid, nombre, ruta_exe, "RUTA_NO_ESTANDAR")
                            hallazgos_ronda += 1

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Ignoramos procesos que mueren durante el escaneo
                    continue

            # Feedback final de la ronda para el usuario
            if hallazgos_ronda == 0:
                print(f" [OK] {procesos_vistos} verificados.")
            else:
                print(f" [!] {hallazgos_ronda} INCIDENCIAS DETECTADAS.")

            # Barra de progreso visual para la espera
            for _ in range(INTERVALO_ESCANEADO):
                time.sleep(1)
                print(".", end="", flush=True)
            print()

    except KeyboardInterrupt:
        print("\n" + "="*113)
        print("🛑 MONITOR DETENIDO: El Centinela ha dejado de vigilar.")
        print("="*113)
        sys.exit(0)

# =================================================================================================================
# PUNTO DE ENTRADA DEL MÓDULO
# =================================================================================================================

if __name__ == "__main__":
    # Verificación de identidad obligatoria
    if os.geteuid() != 0:
        print("🚨 ERROR: Este monitor requiere privilegios de SUPERUSUARIO (sudo).")
        sys.exit(1)

    print("\n" + "█"*113)
    print("                      MONITOR DE INTEGRIDAD DINÁMICA FCH v0.2 - VIGILANCIA RAM")
    print("█" * 113)
    
    iniciar_vigilancia_ram()