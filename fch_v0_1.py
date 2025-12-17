# ================================================================================================================
# fch_v0_1.py
# Auditoría Clasificada de Control Total para Sistemas de Archivos con FUSE/GVFS
# Versión: 0.1.1 (Premium) - Fecha: 2025-12-17
# Autor: Daniel Miñana Montero & Gemini básico
# Descripción:
# Este script realiza una auditoría exhaustiva del sistema de archivos para identificar
# rutas inaccesibles debido a permisos o errores de E/S, clasificando cada fallo según
# su gravedad y proporcionando recomendaciones específicas para cada caso.
# Además, ofrece una opción interactiva para desmontar puntos FUSE/GVFS antes de
# iniciar la auditoría, minimizando el ruido en los resultados e integrando protección
# avanzada de informes (permisos 600) y trazabilidad por fecha.
# Requiere ejecución con privilegios de superusuario (sudo).
# =================================================================================================================

# =================================================================================================================
# SECCIÓN DE IMPORTACIONES NECESARIAS
# =================================================================================================================

import os          # El "Paspartú": Permite navegar por las carpetas y examinar los dueños de los archivos.
import csv         # La "Máquina de Actas": Organiza los hallazgos en una tabla profesional (CSV).
from datetime import datetime  # El "Reloj Forense": Registra el momento exacto para el informe y nombres de archivo.
import sys         # El "Freno de Emergencia": Gestiona la salida segura del script y la interacción con el sistema.
import subprocess  # El "Enlace de Radio": Permite ejecutar comandos externos y scripts de limpieza (Shell).
from collections import Counter # El "Ábaco": Facilita el conteo rápido de riesgos para la conclusión ejecutiva.
import pathlib     # El "GPS Inteligente": Localiza rutas y archivos de apoyo de forma dinámica y segura.

# =================================================================================================================
# SECCIÓN DE CONSTANTES Y VARIABLES GLOBALES
# =================================================================================================================

# Define la ruta del script actual (fch_v0_1.py)
BASE_DIR = pathlib.Path(__file__).parent 

# La ruta al wrapper se construye de forma dinámica
RUTA_LIMPIEZA_SHELL = str(BASE_DIR / "fuse_clean_v0_1.sh") 

# MEJORA DE TRAZABILIDAD: Nombre de informe único basado en la fecha y hora de ejecución
# Esto evita que una auditoría nueva sobrescriba los resultados de la anterior.
AHORA = datetime.now().strftime("%Y%m%d_%H%M%S")
NOMBRE_INFORME_CSV = f"auditoria_control_{AHORA}.csv"

# Lista global para almacenar los ficheros que root no pudo acceder
ficheros_no_controlables = [] 

# =================================================================================================================
# SECCIÓN DE FUNCIONES DE CLASIFICACIÓN (DICCIONARIO DE INTELIGENCIA)
# Esta sección contiene la lógica que traduce los errores crípticos del sistema operativo
# a términos comprensibles de ciberseguridad y gestión de riesgos.
# =================================================================================================================

def clasificar_y_recomendar(error_os):
    """
    EL MANUAL DEL INSPECTOR: Clasifica el fallo y devuelve una conclusión y una solución recomendada.
    Esta función actúa como el cerebro del script, analizando la "etiqueta" del error (PermissionError, 
    FileNotFoundError, OSError) para determinar qué acción debe tomar el administrador.
    """
    
    ruta_fallida = error_os.filename
    error_nombre = type(error_os).__name__
    
    conclusion = "Sin Clasificar (Investigar)"
    solucion = "Investigar la causa del fallo del sistema."
    nivel_riesgo = "MEDIO"

    # --- Análisis de Errores de Permiso (Acceso Denegado) ---
    if error_nombre == 'PermissionError':
        if 'gvfs' in ruta_fallida or 'fuse' in ruta_fallida or '/run/user/' in ruta_fallida or '/run/user' in ruta_fallida:
            conclusion = "Punto de Montaje Virtual (FUSE/GVFS) de usuario."
            solucion = "Este error es ruido de auditoría. Si desea un informe limpio, ejecute `fusermount -u RUTA` como su usuario normal."
            nivel_riesgo = "BAJO"
        elif 'root' in ruta_fallida or 'etc/shadow' in ruta_fallida or 'etc/sudoers' in ruta_fallida:
            conclusion = "Fallo de Permiso inesperado en un archivo clave del sistema (Seguridad Crítica)."
            solucion = "Revisar los permisos con `ls -ld RUTA` y restaurar la propiedad/permisos. **Alto indicio de manipulación.**"
            nivel_riesgo = "ALTO"
        else:
            conclusion = "Fallo de Permiso genérico en un directorio/archivo persistente."
            solucion = "Revisar la configuración de permisos (ACLs) del sistema. Posible error de montaje o configuración."
            nivel_riesgo = "MEDIO"
            
    # --- Análisis de Errores de Existencia (Archivos Fantasma) ---
    elif error_nombre == 'FileNotFoundError':
        if '/proc/' in ruta_fallida or '/sys/' in ruta_fallida:
            conclusion = "Fichero Virtual/Efímero desaparecido (Típico del kernel).\n"
            solucion = "Generalmente seguro de ignorar. El fichero se creó y se eliminó entre el listado y el intento de acceso."
            nivel_riesgo = "BAJO"
        else:
            conclusion = "Enlace Simbólico Roto o Fichero Eliminado de forma inesperada.\n"
            solucion = "Eliminar el enlace roto o investigar la eliminación inesperada del fichero. Puede ser ruido."
            nivel_riesgo = "MEDIO"
            
    # --- Análisis de Errores de Bajo Nivel (Fallos de Hardware o Integridad) ---
    elif error_nombre == 'OSError':
        conclusion = "Error de Entrada/Salida de bajo nivel (I/O Error) o Fallo de Integridad.\n"
        solucion = "Verificar la integridad del disco (`fsck` si es necesario) y el estado del hardware. **Riesgo crítico.**"
        nivel_riesgo = "CRÍTICO"

    return conclusion, solucion, nivel_riesgo

# =================================================================================================================
# SECCIÓN DE GESTIÓN DE INCIDENCIAS (EL LIBRO DE NOTAS)
# =================================================================================================================

def manejar_error_auditoria_clasificada(error_os):
    """
    EL CUADERNO DE NOTAS: Maneja el error detectado, registra la ruta y añade la clasificación detallada.
    Esta función se activa automáticamente cada vez que el escáner se encuentra con una puerta cerrada.
    """
    
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

# =================================================================================================================
# SECCIÓN DE INTERACCIÓN Y SANEAMIENTO (EL PROTOCOLO DE LIMPIEZA)
# =================================================================================================================

def preguntar_y_desmontar():
    """
    EL PROTOCOLO DE LIMPIEZA: Pregunta al usuario si desea ejecutar el saneamiento automático.
    Utiliza una técnica de "cambio de contexto" (su -) para asegurar la limpieza correcta.
    """
    
    original_user = os.environ.get('SUDO_USER')
    
    if not original_user:
        print("🚨 ERROR: No se detectó el usuario original (SUDO_USER). Saneamiento omitido.")
        return

    print("\n-------------------------------------------------------")
    print(f"La limpieza de puntos virtuales FUSE se ejecutará como el usuario: {original_user}")
    respuesta = input("¿Desea intentar la limpieza automática de FUSE/GVFS para evitar ruido? (s/n): ").lower()
    print("-------------------------------------------------------")

    if respuesta == 's' or respuesta == 'si':
        # MEJORA DE SEGURIDAD: Validación de existencia antes de la ejecución
        if not os.path.exists(RUTA_LIMPIEZA_SHELL):
            print(f"🛑 ERROR: No se encontró el archivo de limpieza en: {RUTA_LIMPIEZA_SHELL}")
            return

        print(f"Lanzando wrapper de limpieza como usuario {original_user} (requiere contexto de sesión)...")
        
        try:
            comando = ['su', '-', original_user, '-c', RUTA_LIMPIEZA_SHELL]
            subprocess.run(comando, check=False, capture_output=False)
            print("✅ El wrapper de limpieza se ejecutó. Revise los mensajes de Éxito/Fallo.")
            
        except FileNotFoundError:
            print(f"🛑 ERROR: No se encontró el comando 'su'. Ejecución omitida.")
        except Exception as e:
            print(f"🛑 ERROR INESPERADO: Fallo al ejecutar el wrapper. {e}")
        
    else:
        print("⏭️ Desmontaje automático omitido por decisión del usuario.")

# =================================================================================================================
# SECCIÓN DE CONCLUSIÓN EJECUTIVA (EL VEREDICTO DE SEGURIDAD)
# =================================================================================================================

def generar_resumen_final(contador_total):
    """
    LA CONCLUSIÓN EJECUTIVA: Genera el veredicto final y recomendaciones basadas en los niveles de riesgo.
    """
    
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
        print("1. **PRIORIDAD MÁXIMA:** Revisar las entradas marcadas como **CRÍTICO** e **ALTO**.")
        print("2. Investigar fallos MEDIOS para asegurar la limpieza del sistema.")
        
    else:
        print("✅ ESTADO: CONTROL TOTAL CONFIRMADO")
        if fallos_bajos > 0:
             print(f"El informe muestra {fallos_bajos} fallos de riesgo BAJO (ruido normal de /proc, /sys).")
        else:
             print("No se encontró ninguna ruta inaccesible.")
        print("\nRECOMENDACIÓN: Mantener la auditoría periódica.")

    print(f"\nTotal de archivos analizados: {contador_total}")
    print("=======================================================")

# =================================================================================================================
# SECCIÓN DE CONSENTIMIENTO INFORMADO (PROTOCOLO LEGAL Y DE SEGURIDAD)
# =================================================================================================================

def obtener_consentimiento_informado():
    """
    EL CONTRATO DEL AUDITOR: Muestra los términos de responsabilidad y bloquea la ejecución
    si no existe una aceptación activa. Es el primer paso ético de la auditoría.
    """
    print("\n" + "!"*80)
    print("                AVISO DE SEGURIDAD Y RESPONSABILIDAD (fch_v0_1)")
    print("!"*80)
    print("\nUsted está a punto de iniciar una auditoría de CONTROL TOTAL en la raíz ('/').")
    print("\nESTE PROCESO IMPLICA:")
    print(" 1. Análisis profundo de metadatos y permisos en todo el Host.")
    print(" 2. Interacción con el sistema para limpiar ruidos de montaje (FUSE/GVFS).")
    print(" 3. Generación de un informe forense con hallazgos de seguridad.")
    print("\nRESPONSABILIDAD: El uso de los resultados de este informe es responsabilidad")
    print("exclusiva del auditor. El script se proporciona 'tal cual'.")
    print("-" * 80)
    
    confirmacion = input("\n¿Acepta los términos y desea proceder con la auditoría? (S/N): ").upper()
    
    if confirmacion != 'S':
        print("\nAbortando: Ejecución cancelada por el usuario. No se han realizado cambios.")
        sys.exit(0)
    
    print("\n✅ Consentimiento otorgado. Iniciando protocolos...")
    print("-" * 80)

# =================================================================================================================
# SECCIÓN DE OPERACIÓN DE CAMPO (AUDITORÍA PRINCIPAL)
# =================================================================================================================

def auditar_control_root_clasificado(directorio_raiz):
    """
    LA INSPECCIÓN GENERAL: Ejecuta la auditoría integral con clasificación de fallos.
    Coordina todas las fases del proceso asegurando la integridad del informe.
    """
    print("--- Auditoría Clasificada de Control Total (Ciberseguridad) ---")
    
    # --- FASE 0: VERIFICACIÓN DE IDENTIDAD ---
    if os.name != 'posix' or os.geteuid() != 0:
        print("🚨 ERROR: Este modo requiere 'sudo'. Ejecute con 'sudo python3 fch_v0_1.py'")
        sys.exit(1)
    
    # --- FASE 1: CONSENTIMIENTO INFORMADO ---
    obtener_consentimiento_informado()
        
    # --- FASE 2: LIMPIEZA INTERACTIVA ---
    preguntar_y_desmontar() 

    contador_total = 0
    global ficheros_no_controlables
    ficheros_no_controlables = [] 

    # --- FASE 3: RECORRIDO Y CONTEO (EL PASEO) ---
    print("\n🔍 Iniciando recorrido del sistema de ficheros...")
    try:
        contador_total = sum(len(ficheros) for _, _, ficheros in os.walk(directorio_raiz, onerror=manejar_error_auditoria_clasificada))
    except Exception as e:
        print(f"🛑 Error catastrófico durante os.walk: {e}")
        return

    # --- FASE 4: ESCRITURA DEL INFORME (EL ACTA OFICIAL) ---
    cabecera_fallos = ['Ruta Inaccesible', 'Tipo de Error', 'Detalle', 'Riesgo', 'Conclusión', 'Solución']
    
    try:
        # Usamos el NOMBRE_INFORME_CSV dinámico definido en la sección de constantes
        with open(NOMBRE_INFORME_CSV, 'w', newline='', encoding='utf-8') as archivo_csv:
            escritor_csv = csv.writer(archivo_csv)
            
            # Registro de Metadatos Forenses
            escritor_csv.writerow(['Auditoría Ejecutada', datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            escritor_csv.writerow(['Directorio Analizado', directorio_raiz])
            escritor_csv.writerow(['Total Ficheros Rastreables', contador_total])
            escritor_csv.writerow(['Total Rutas No Controlables', len(ficheros_no_controlables)])
            escritor_csv.writerow([])
            
            # Registro Detallado de Incidencias
            escritor_csv.writerow(['--- INFORME DETALLADO DE FALLOS DE CONTROL ---'])
            escritor_csv.writerow(cabecera_fallos)
            escritor_csv.writerows(ficheros_no_controlables)
            
        # MEJORA DE CONFIDENCIALIDAD: Solo Root puede leer el informe generado (chmod 600)
        os.chmod(NOMBRE_INFORME_CSV, 0o600)
        print(f"\n✅ Informe protegido y guardado: '{NOMBRE_INFORME_CSV}'")
        
    except Exception as e:
        print(f"🛑 Error al escribir el CSV: {e}")
        
    # --- FASE 5: GENERACIÓN DEL VEREDICTO FINAL ---
    generar_resumen_final(contador_total)

# =================================================================================================================
# SECCIÓN DE MEJORAS ADICIONALES (PROTECCIÓN DINÁMICA - CONEXIÓN FRONTAL)
# =================================================================================================================

def sugerir_proteccion_dinamica():
    """
    EL PUENTE DINÁMICO: Ofrece al auditor la posibilidad de pasar de una auditoría estática
    a una vigilancia activa en RAM. Se ejecuta en primer plano para total transparencia.
    """
    print("\n" + "="*113)
    print("🛡️  MEJORA DE SEGURIDAD DISPONIBLE: VIGILANCIA EN TIEMPO REAL")
    print("="*113)
    print("Se ha detectado el módulo de monitoreo dinámico 'fch_dynamic_v0_1.py'.")
    print("Este módulo permite vigilar procesos en RAM contra inyecciones de código y malware fileless.")
    
    opcion = input("\n¿Desea iniciar la vigilancia de memoria ahora en esta terminal? (s/n): ").lower()
    
    if opcion == 's' or opcion == 'si':
        print("\n🚀 Transfiriendo control al Monitor Dinámico...")
        print("Pulse [Ctrl+C] en cualquier momento para detener la vigilancia y salir.")
        
        try:
            # CAMBIO ESTRATÉGICO: Usamos subprocess.call para bloquear la terminal actual
            # y mostrar la ejecución del monitor dinámico directamente al usuario.
            import subprocess
            subprocess.call(['sudo', 'python3', 'fch_dynamic_v0_1.py'])
            
        except FileNotFoundError:
            print("\n🛑 ERROR: No se encontró el archivo 'fch_dynamic_v0_1.py' en el directorio.")
        except Exception as e:
            print(f"\n🛑 ERROR INESPERADO al lanzar el monitor: {e}")
    else:
        print("\n⏭️ Vigilancia dinámica omitida. Auditoría finalizada correctamente.")

# =================================================================================================================
# PUNTO DE ENTRADA PRINCIPAL
# =================================================================================================================

if __name__ == "__main__":
    # Iniciamos el proceso oficial de auditoría desde la raíz del Host
    auditar_control_root_clasificado("/")
    # Sugerimos el nuevo módulo tras finalizar la auditoría estática
    sugerir_proteccion_dinamica()