import os
import csv
from datetime import datetime
import sys
import subprocess
from collections import Counter

# =========================================================================
# === CONFIGURACIÓN CLAVE: ¡ACTUALIZA ESTA RUTA! ===
# La ruta debe apuntar al script shell 'limpieza_fuse.sh' o 'fuse_clean.sh'
# =========================================================================
RUTA_LIMPIEZA_SHELL = "/home/toviddfrei/BAppC/fuse_clean.sh" # Usando el nombre de tu output
# =========================================================================

# Lista global para almacenar los ficheros que root no pudo acceder
ficheros_no_controlables = []

# --- Funciones de Clasificación ---

def clasificar_y_recomendar(error_os):
    """Clasifica el error y devuelve una conclusión y una solución recomendada."""
    
    ruta_fallida = error_os.filename
    error_nombre = type(error_os).__name__
    
    conclusion = "Sin Clasificar (Investigar)"
    solucion = "Investigar la causa del fallo del sistema."
    nivel_riesgo = "MEDIO"

    if error_nombre == 'PermissionError':
        if 'gvfs' in ruta_fallida or 'fuse' in ruta_fallida or '/run/user/' in ruta_fallida or '/run/user' in ruta_fallida:
            conclusion = "Punto de Montaje Virtual (FUSE/GVFS) de usuario."
            solucion = "Este error es ruido de auditoría. Si desea un informe limpio, ejecute `fusermount -u RUTA` como su usuario normal."
            nivel_riesgo = "BAJO"
        elif 'root' in ruta_fallida or 'etc/shadow' in ruta_fallida or 'etc/sudoers' in ruta_fallida:
            conclusion = "Fallo de Permiso inesperado en un archivo clave del sistema (Seguridad Crítica)."
            solucion = "Revisar los permisos con `ls -ld RUTA` y restaurar la propiedad/permisos. **Alto indicio de manipulación o fallo de configuración crítico.**"
            nivel_riesgo = "ALTO"
        else:
            conclusion = "Fallo de Permiso genérico en un directorio/archivo persistente."
            solucion = "Revisar la configuración de permisos (ACLs) del sistema. Posible error de montaje o configuración de seguridad."
            nivel_riesgo = "MEDIO"
            
    elif error_nombre == 'FileNotFoundError':
        if '/proc/' in ruta_fallida or '/sys/' in ruta_fallida:
            conclusion = "Fichero Virtual/Efímero desaparecido (Típico del kernel).\n"
            solucion = "Generalmente seguro de ignorar. El fichero se creó y se eliminó entre el listado y el intento de acceso."
            nivel_riesgo = "BAJO"
        else:
            conclusion = "Enlace Simbólico Roto o Fichero Eliminado de forma inesperada.\n"
            solucion = "Eliminar el enlace roto o investigar la eliminación inesperada del fichero. Puede ser ruido o una limpieza mal hecha."
            nivel_riesgo = "MEDIO"
            
    elif error_nombre == 'OSError':
        conclusion = "Error de Entrada/Salida de bajo nivel (I/O Error) o Fallo de Integridad.\n"
        solucion = "Verificar la integridad del disco (`fsck` si es necesario) y el estado del hardware. **Riesgo crítico de corrupción o fallo de hardware.**"
        nivel_riesgo = "CRÍTICO"

    return conclusion, solucion, nivel_riesgo

def manejar_error_auditoria_clasificada(error_os):
    """Maneja el error, registra la ruta y añade la clasificación."""
    
    ruta_fallida = error_os.filename
    error_nombre = type(error_os).__name__
    
    conclusion, solucion, riesgo = clasificar_y_recomendar(error_os)

    ficheros_no_controlables.append([
        ruta_fallida, 
        error_nombre, 
        str(error_os),
        riesgo,
        conclusion,
        solucion
    ])
    
    print(f"[{riesgo}] Fallo de control en: {ruta_fallida}")


# --- Función de Desmontaje Interactivo y Llamada al Wrapper ---

def preguntar_y_desmontar():
    """Pregunta al usuario si desea ejecutar la limpieza automática a través del wrapper shell."""
    
    # Obtenemos el usuario original que ejecutó 'sudo'
    original_user = os.environ.get('SUDO_USER')
    
    if not original_user:
        print("🚨 ERROR: No se detectó el usuario original (SUDO_USER). No se puede realizar la limpieza de FUSE/GVFS.")
        return

    print("\n-------------------------------------------------------")
    print(f"La limpieza de puntos virtuales FUSE se ejecutará como el usuario: {original_user}")
    respuesta = input("¿Desea intentar la limpieza automática de FUSE/GVFS para evitar ruido? (s/n): ").lower()
    print("-------------------------------------------------------")

    if respuesta == 's' or respuesta == 'si':
        print(f"Lanzando wrapper de limpieza como usuario {original_user} (requiere contexto de sesión)...")
        
        try:
            # === CAMBIO CLAVE: Usamos 'su -' para simular un login shell ===
            comando = ['su', '-', original_user, '-c', RUTA_LIMPIEZA_SHELL]
            
            subprocess.run(
                comando,
                check=False, # No forzamos un error si la limpieza falla (ej. en uso)
                capture_output=False, # Muestra la salida de limpieza directamente
            )
            print("✅ El wrapper de limpieza se ejecutó. Revise los mensajes de Éxito/Fallo.")
            
        except FileNotFoundError:
            print(f"🛑 ERROR: No se encontró el wrapper de limpieza o el comando 'su'. Ejecución omitida.")
        except Exception as e:
            print(f"🛑 ERROR INESPERADO: Fallo al ejecutar el wrapper. {e}")
        
    else:
        print("⏭️ Desmontaje automático omitido por decisión del usuario.")


# --- Funciones de Auditoría y Resumen ---

def generar_resumen_final(contador_total):
    """Genera la conclusión ejecutiva y las recomendaciones basadas en los fallos."""
    
    conteo_riesgos = Counter(item[3] for item in ficheros_no_controlables)
    
    fallos_criticos = conteo_riesgos.get('CRÍTICO', 0)
    fallos_altos = conteo_riesgos.get('ALTO', 0)
    fallos_medios = conteo_riesgos.get('MEDIO', 0)
    fallos_bajos = conteo_riesgos.get('BAJO', 0)

    print("\n=======================================================")
    print("||       CONCLUSIÓN EJECUTIVA DE CIBERSEGURIDAD      ||")
    print("=======================================================")
    
    if fallos_criticos > 0 or fallos_altos > 0 or fallos_medios > 0:
        print(f"🚨 ESTADO: RIESGO DE SEGURIDAD DETECTADO")
        print(f"Fallos: CRÍTICO={fallos_criticos}, ALTO={fallos_altos}, MEDIO={fallos_medios}.")
        print("\nRECOMENDACIÓN URGENTE:")
        print("1. **PRIORIDAD MÁXIMA:** Revisar las entradas marcadas como **CRÍTICO** (I/O Error) y **ALTO** (Archivos de configuración de root).")
        print("2. Investigar fallos MEDIOS (Permisos genéricos o Enlaces rotos) para asegurar la limpieza del sistema.")
        
    else:
        print("✅ ESTADO: CONTROL TOTAL CONFIRMADO")
        if fallos_bajos > 0:
             # Los fallos de /proc/ y /sys/ son normales, no son un problema de seguridad de FUSE.
             # Por eso no los mencionamos en la recomendación urgente.
             print(f"El informe muestra {fallos_bajos} fallos, todos clasificados como de riesgo BAJO, típicos del ruido de auditoría (/proc, /sys).")
        else:
             print("No se encontró ninguna ruta inaccesible, lo que indica un sistema de archivos completamente bajo control.")
        print("\nRECOMENDACIÓN:")
        print("Mantener la auditoría periódica.")

    print(f"\nTotal de archivos analizados: {contador_total}")
    print("=======================================================")

def auditar_control_root_clasificado(directorio_raiz, nombre_archivo_csv="auditoria_control_clasificada.csv"):
    """
    Ejecuta una auditoría con clasificación de fallos. DEBE EJECUTARSE CON SUDO.
    """
    print("--- Auditoría Clasificada de Control Total (Ciberseguridad) ---")
    
    # 0. Verificación de permisos y Pregunta/Desmontaje
    if os.name != 'posix' or os.geteuid() != 0:
        print("🚨 ERROR: Este modo requiere 'sudo' en sistemas Unix/Linux. Por favor, ejecute con 'sudo python3 tu_script.py'")
        sys.exit(1)
        
    preguntar_y_desmontar() # <--- Punto de interacción y limpieza

    contador_total = 0
    global ficheros_no_controlables
    ficheros_no_controlables = [] 

    # 1. Recorrido y Conteo
    print("\n🔍 Iniciando recorrido del sistema de ficheros...")
    try:
        # El conteo total de ficheros recorridos
        contador_total = sum(len(ficheros) for _, _, ficheros in os.walk(directorio_raiz, onerror=manejar_error_auditoria_clasificada))

    except Exception as e:
        print(f"🛑 Error catastrófico durante os.walk: {e}")
        return

    # 2. Escritura del Informe CSV (sin cambios)
    cabecera_fallos = [
        'Ruta Inaccesible', 
        'Tipo de Error', 
        'Detalle del Error',
        'Nivel de Riesgo',
        'Conclusión del Fallo',
        'Solución Recomendada'
    ]
    
    try:
        with open(nombre_archivo_csv, 'w', newline='', encoding='utf-8') as archivo_csv:
            escritor_csv = csv.writer(archivo_csv)
            
            # Escribir metadatos
            escritor_csv.writerow(['Auditoría Ejecutada', datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            escritor_csv.writerow(['Directorio Analizado', directorio_raiz])
            escritor_csv.writerow(['Total Ficheros Rastreables', contador_total])
            escritor_csv.writerow(['Total Rutas No Controlables (Detectadas)', len(ficheros_no_controlables)])
            escritor_csv.writerow([])
            
            # Escribir la lista de ficheros no controlables
            escritor_csv.writerow(['--- INFORME DETALLADO DE FALLOS DE CONTROL ---'])
            escritor_csv.writerow(cabecera_fallos)
            escritor_csv.writerows(ficheros_no_controlables)
            
        print(f"\n✅ Informe detallado guardado en '{nombre_archivo_csv}'")
        
    except Exception as e:
        print(f"Ocurrió un error al escribir el CSV: {e}")
        
    # 3. Generar Conclusión Ejecutiva
    generar_resumen_final(contador_total)


# --- PUNTO DE ENTRADA PRINCIPAL (ASEGURA LA EJECUCIÓN) ---

if __name__ == "__main__":
    # La ruta a auditar (la raíz)
    ruta_a_auditar = "/" 
    
    # Ejecutamos la función principal
    # DEBE ejecutarse con: sudo python3 fch.py
    auditar_control_root_clasificado(ruta_a_auditar)