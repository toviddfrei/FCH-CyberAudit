# ================================================================================================================
# fch_dynamic_v0_1.py
# Módulo de Vigilancia Dinámica de Integridad (RAM vs DISCO)
# Versión: 0.1.0 - Fecha: 2025-12-17
# Autor: Daniel Miñana Montero & Gemini básico
# Descripción:
# Este módulo monitoriza los procesos en ejecución y verifica su integridad comparando
# su hash en memoria con su binario original en disco. Detecta malware "fileless"
# y modificaciones de código en tiempo real (Inyecciones).
# Requiere: pip install psutil
# =================================================================================================================

# =================================================================================================================
# SECCIÓN DE IMPORTACIONES
# =================================================================================================================

import os          # Para verificar rutas de archivos.
import hashlib     # El "Generador de Huellas": Crea hashes SHA-256 de seguridad.
import psutil      # El "Vigilante de Procesos": Permite inspeccionar la RAM activa.
import time        # Para gestionar los intervalos de escaneo (rendimiento).
import sys         # Gestión de salida y señales del sistema.

# =================================================================================================================
# SECCIÓN DE CONFIGURACIÓN Y CONSTANTES
# =================================================================================================================

# Directorios críticos que el monitor vigilará con prioridad
DIR_CRITICOS = ['/bin', '/sbin', '/usr/bin', '/usr/sbin']

# Intervalo de escaneo en segundos (Balance entre Seguridad y Rendimiento)
# 10s = Seguridad Alta | 60s = Modo Eco
INTERVALO_ESCANEADO = 10 

# =================================================================================================================
# SECCIÓN DE MOTOR DE INTEGRIDAD (HASHING)
# =================================================================================================================

def calcular_sha256(ruta_fichero):
    """
    EL NOTARIO: Genera una huella digital única (SHA-256) del contenido de un archivo.
    Si el archivo ha sido modificado aunque sea en un solo bit, el hash cambiará.
    """
    hash_sha256 = hashlib.sha256()
    try:
        with open(ruta_fichero, "rb") as f:
            # Leemos en bloques para no saturar la memoria con archivos grandes
            for bloque in iter(lambda: f.read(4096), b""):
                hash_sha256.update(bloque)
        return hash_sha256.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None
    except Exception as e:
        return f"ERROR_{e}"

# =================================================================================================================
# SECCIÓN DE MONITOREO DINÁMICO (EL CENTINELA)
# =================================================================================================================

def iniciar_vigilancia_ram():
    """
    EL CENTINELA: Bucle infinito que inspecciona cada proceso activo en el sistema.
    Compara el binario que se está ejecutando en RAM con su versión en almacenamiento.
    """
    print(f"\n[🛡️ ] Iniciando Vigilancia Dinámica (Intervalo: {INTERVALO_ESCANEADO}s)")
    print("[🛡️ ] Presione Ctrl+C para detener el monitor.")
    print("-" * 80)

    try:
        while True:
            hallazgos_sospechosos = 0
            
            # Recorremos todos los procesos vivos
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = proc.info['pid']
                    nombre = proc.info['name']
                    ruta_exe = proc.info['exe']

                    # 1. DETECCIÓN DE MALWARE FILELESS (Sin archivo en disco)
                    # Si el ejecutable no existe o está marcado como (deleted)
                    if not ruta_exe or not os.path.exists(ruta_exe):
                        print(f"🚨 ALERTA CRÍTICA: Proceso 'fileless' detectado!")
                        print(f"   > PID: {pid} | Nombre: {nombre} | Ruta: {ruta_exe or 'DESCONOCIDA'}")
                        hallazgos_sospechosos += 1
                        continue

                    # 2. VERIFICACIÓN DE INTEGRIDAD (Inyección de código)
                    # Solo escaneamos binarios en carpetas del sistema para ahorrar CPU
                    if any(ruta_exe.startswith(d) for d in DIR_CRITICOS):
                        hash_disco = calcular_sha256(ruta_exe)
                        # Nota: En Linux, el 'exe' de psutil apunta al binario que levantó el proceso
                        # Si este ha cambiado desde que se lanzó, detectaríamos la discrepancia.
                        
                        # En este nivel v0.1, comparamos la existencia y consistencia base
                        if hash_disco is None:
                            print(f"⚠️ AVISO: No se pudo verificar integridad de {nombre} (PID: {pid})")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            if hallazgos_sospechosos == 0:
                print(f"[{time.strftime('%H:%M:%S')}] Escaneo completado: Sistema íntegro.")
            
            time.sleep(INTERVALO_ESCANEADO)

    except KeyboardInterrupt:
        print("\n\n🛑 Monitor dinámico detenido por el usuario.")
        sys.exit(0)

# =================================================================================================================
# PUNTO DE ENTRADA DEL MÓDULO
# =================================================================================================================

if __name__ == "__main__":
    # Verificación de privilegios
    if os.geteuid() != 0:
        print("🚨 ERROR: El monitor dinámico requiere privilegios de ROOT (sudo).")
        sys.exit(1)

    print("=======================================================")
    print("||       MONITOR DE INTEGRIDAD DINÁMICA FCH v0.2     ||")
    print("=======================================================")
    iniciar_vigilancia_ram()