# ================================================================================================================
# fch_v0_1.py
# Auditoría Clasificada de Control Total para Sistemas de Archivos con FUSE/GVFS
# Versión: 0.1.2 (Premium - Suite) - Fecha: 2025-12-18
# Autor: Daniel Miñana Montero & Gemini básico
# Descripción:
# Este script realiza una auditoría exhaustiva del sistema de archivos para identificar
# rutas inaccesibles debido a permisos o errores de E/S, clasificando cada fallo según
# su gravedad y proporcionando recomendaciones específicas para cada caso.
# Además, ofrece una opción interactiva para desmontar puntos FUSE/GVFS antes de
# iniciar la auditoría, minimizando el ruido en los resultados e integrando protección
# avanzada de informes (permisos 600) y trazabilidad por fecha.
# Incluye el PUENTE DE CONEXIÓN a la vigilancia dinámica de RAM v0.2.8.
# Requiere ejecución con privilegios de superusuario (sudo).
# =================================================================================================================

# =================================================================================================================
# SECCIÓN DE IMPORTACIONES NECESARIAS
# =================================================================================================================

import os          # El "Paspartú": Permite navegar por las carpetas y examinar los dueños de los archivos.
import csv         # La "Máquina de Actas": Organiza los hallazgos en una tabla profesional (CSV).
import json        # EL ARCHIVERO: Gestiona la base de conocimiento pedagógica compartida.
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

# Definimos los nombres de los módulos de la suite para la conexión dinámica
MODULO_DINAMICO = "fch_dynamic_v0_2.py"
BASE_CONOCIMIENTO = "base_conocimiento.json"

# MEJORA DE TRAZABILIDAD: Nombre de informe único basado en la fecha y hora de ejecución
AHORA = datetime.now().strftime("%Y%m%d_%H%M%S")
NOMBRE_INFORME_CSV = f"auditoria_control_{AHORA}.csv"

# Lista global para almacenar los ficheros que root no pudo acceder
ficheros_no_controlables = [] 

# =================================================================================================================
# SECCIÓN DE FUNCIONES DE CLASIFICACIÓN (DICCIONARIO DE INTELIGENCIA)
# =================================================================================================================

def clasificar_y_recomendar(error_os):
    """
    EL MANUAL DEL INSPECTOR: Clasifica el fallo y devuelve una conclusión y una solución recomendada.
    Esta función actúa como el cerebro del script, analizando la "etiqueta" del error para determinar 
    qué acción debe tomar el administrador.
    """
    
    ruta_fallida = error_os.filename
    error_nombre = type(error_os).__name__
    
    conclusion = "Sin Clasificar (Investigar)"
    solucion = "Investigar la causa del fallo del sistema."
    nivel_riesgo = "MEDIO"

    # --- Análisis de Errores de Permiso (Acceso Denegado) ---
    if error_nombre == 'PermissionError':
        if any(x in ruta_fallida for x in ['gvfs', 'fuse', '/run/user/']):
            conclusion = "Punto de Montaje Virtual (FUSE/GVFS) de usuario."
            solucion = "Este error es ruido de auditoría. Si desea un informe limpio, ejecute el saneamiento inicial."
            nivel_riesgo = "BAJO"
        elif any(x in ruta_fallida for x in ['root', 'etc/shadow', 'etc/sudoers', 'etc/passwd']):
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
            conclusion = "Fichero Virtual/Efímero desaparecido (Típico del kernel)."
            solucion = "Generalmente seguro de ignorar. El fichero se creó y se eliminó durante el escaneo."
            nivel_riesgo = "BAJO"
        else:
            conclusion = "Enlace Simbólico Roto o Fichero Eliminado de forma inesperada."
            solucion = "Investigar la eliminación inesperada. Si es un enlace roto, puede ser ruido."
            nivel_riesgo = "MEDIO"
            
    # --- Análisis de Errores de Bajo Nivel (Fallos de Hardware o Integridad) ---
    elif error_nombre == 'OSError':
        conclusion = "Error de Entrada/Salida de bajo nivel (I/O Error) o Fallo de Integridad."
        solucion = "Verificar la integridad del disco (`fsck`) y el estado del hardware. **Riesgo crítico.**"
        nivel_riesgo = "CRÍTICO"

    return conclusion, solucion, nivel_riesgo

# =================================================================================================================
# SECCIÓN DE GESTIÓN DE INCIDENCIAS (EL LIBRO DE NOTAS)
# =================================================================================================================

def manejar_error_auditoria_clasificada(error_os):
    """
    EL CUADERNO DE NOTAS: Maneja el error detectado, registra la ruta y añade la clasificación detallada.
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

    if respuesta in ['s', 'si']:
        if not os.path.exists(RUTA_LIMPIEZA_SHELL):
            print(f"🛑 ERROR: No se encontró el archivo de limpieza en: {RUTA_LIMPIEZA_SHELL}")
            return

        print(f"Lanzando wrapper de limpieza como usuario {original_user}...")
        try:
            comando = ['su', '-', original_user, '-c', RUTA_LIMPIEZA_SHELL]
            subprocess.run(comando, check=False)
            print("✅ El wrapper de limpieza se ejecutó satisfactoriamente.")
        except Exception as e:
            print(f"🛑 ERROR INESPERADO: Fallo al ejecutar el wrapper. {e}")
    else:
        print("⏭️ Desmontaje automático omitido por decisión del usuario.")

# =================================================================================================================
# SECCIÓN DE INTEGRACIÓN DE LA SUITE (INTELIGENCIA COMPARTIDA)
# =================================================================================================================

def asegurar_base_inteligencia():
    """
    EL PREPARADOR: Garantiza que la base de datos JSON esté lista para el monitor de RAM.
    Esto permite que ambos scripts compartan el conocimiento pedagógico.
    """
    ruta_json = BASE_DIR / BASE_CONOCIMIENTO
    if not os.path.exists(ruta_json):
        print(f"\n[ℹ️] Inicializando base de conocimiento local: {BASE_CONOCIMIENTO}")
        datos_base = {"sistemas": {"debian_ubuntu": {"procesos_standard": {}}}}
        try:
            with open(ruta_json, 'w', encoding='utf-8') as f:
                json.dump(datos_base, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"🛑 Error al crear archivo de inteligencia: {e}")

# =================================================================================================================
# SECCIÓN DE CONCLUSIÓN EJECUTIVA (EL VEREDICTO DE SEGURIDAD)
# =================================================================================================================

def generar_resumen_final(contador_total):
    """
    LA CONCLUSIÓN EJECUTIVA: Genera el veredicto final basado en los niveles de riesgo.
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
        print("1. **PRIORIDAD MÁXIMA:** Revisar las entradas marcadas como CRÍTICO e ALTO.")
        print("2. Investigar fallos MEDIOS para asegurar la limpieza del sistema.")
    else:
        print("✅ ESTADO: CONTROL TOTAL CONFIRMADO")
        if fallos_bajos > 0:
             print(f"El informe muestra {fallos_bajos} fallos de riesgo BAJO (ruido normal).")
        else:
             print("No se encontró ninguna ruta inaccesible.")
        print("\nRECOMENDACIÓN: Mantener la auditoría periódica.")

    print(f"\nTotal de archivos analizados: {contador_total}")
    print("=======================================================")

# =================================================================================================================
# SECCIÓN DE CONSENTIMIENTO INFORMADO
# =================================================================================================================

def obtener_consentimiento_informado():
    """
    EL CONTRATO DEL AUDITOR: Muestra los términos de responsabilidad.
    """
    print("\n" + "!"*80)
    print("                AVISO DE SEGURIDAD Y RESPONSABILIDAD (fch_v0_1)")
    print("!"*80)
    print("\nUsted está a punto de iniciar una auditoría de CONTROL TOTAL en la raíz ('/').")
    print("\nESTE PROCESO IMPLICA:")
    print(" 1. Análisis profundo de metadatos y permisos en todo el Host.")
    print(" 2. Interacción con el sistema para limpiar ruidos de montaje (FUSE/GVFS).")
    print(" 3. Generación de un informe forense con hallazgos de seguridad.")
    print("-" * 80)
    
    confirmacion = input("\n¿Acepta los términos y desea proceder? (S/N): ").upper()
    if confirmacion != 'S':
        print("\nAbortando: Ejecución cancelada por el usuario.")
        sys.exit(0)
    
    print("\n✅ Consentimiento otorgado. Iniciando protocolos...")
    print("-" * 80)

# =================================================================================================================
# SECCIÓN DE OPERACIÓN DE CAMPO (AUDITORÍA PRINCIPAL)
# =================================================================================================================

def auditar_control_root_clasificado(directorio_raiz):
    """
    LA INSPECCIÓN GENERAL: Coordina todas las fases de la auditoría de archivos.
    """
    if os.name != 'posix' or os.geteuid() != 0:
        print("🚨 ERROR: Este modo requiere 'sudo'. Ejecute con 'sudo python3 fch_v0_1.py'")
        sys.exit(1)
    
    obtener_consentimiento_informado()
    preguntar_y_desmontar() 

    contador_total = 0
    global ficheros_no_controlables
    ficheros_no_controlables = [] 

    print("\n🔍 Iniciando recorrido del sistema de ficheros...")
    try:
        contador_total = sum(len(ficheros) for _, _, ficheros in os.walk(directorio_raiz, onerror=manejar_error_auditoria_clasificada))
    except Exception as e:
        print(f"🛑 Error catastrófico durante os.walk: {e}")
        return

    # --- ESCRITURA DEL INFORME ---
    try:
        with open(NOMBRE_INFORME_CSV, 'w', newline='', encoding='utf-8') as archivo_csv:
            escritor_csv = csv.writer(archivo_csv)
            escritor_csv.writerow(['Auditoría Ejecutada', datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            escritor_csv.writerow(['Total Archivos', contador_total])
            escritor_csv.writerow([])
            escritor_csv.writerow(['Ruta Inaccesible', 'Error', 'Detalle', 'Riesgo', 'Conclusión', 'Solución'])
            escritor_csv.writerows(ficheros_no_controlables)
            
        os.chmod(NOMBRE_INFORME_CSV, 0o600)
        print(f"\n✅ Informe protegido guardado en: '{NOMBRE_INFORME_CSV}'")
    except Exception as e:
        print(f"🛑 Error al escribir el CSV: {e}")
        
    generar_resumen_final(contador_total)

# =================================================================================================================
# SECCIÓN DE MEJORAS ADICIONALES (LA CONEXIÓN DINÁMICA)
# =================================================================================================================

def sugerir_proteccion_dinamica():
    """
    EL PUENTE DINÁMICO: Ofrece al auditor saltar a la vigilancia activa en RAM (v0.2.8).
    """
    print("\n" + "="*113)
    print("🛡️  MEJORA DE SEGURIDAD DISPONIBLE: VIGILANCIA EN TIEMPO REAL (RAM)")
    print("="*113)
    print(f"Módulo: '{MODULO_DINAMICO}' (Versión 0.2.8 - Aprendizaje Activo)")
    print("Este módulo verifica hashes oficiales y permite bloquear procesos sospechosos.")
    
    opcion = input("\n¿Desea iniciar la vigilancia de memoria ahora? (s/n): ").lower()
    
    if opcion in ['s', 'si']:
        asegurar_base_inteligencia() # Aseguramos que el JSON exista antes de lanzar
        print("\n🚀 Transfiriendo control al Monitor Dinámico...")
        
        try:
            # Llamamos al nuevo script v0.2.8
            subprocess.call(['sudo', 'python3', str(BASE_DIR / MODULO_DINAMICO)])
        except FileNotFoundError:
            print(f"\n🛑 ERROR: No se encontró '{MODULO_DINAMICO}' en el directorio.")
        except Exception as e:
            print(f"\n🛑 ERROR INESPERADO al lanzar el monitor: {e}")
    else:
        print("\n⏭️ Vigilancia dinámica omitida. Suite finalizada correctamente.")

# =================================================================================================================
# PUNTO DE ENTRADA PRINCIPAL
# =================================================================================================================

if __name__ == "__main__":
    # 1. Ejecutar auditoría estática del sistema de archivos
    auditar_control_root_clasificado("/")
    # 2. Ofrecer el salto al monitor de RAM evolucionado
    sugerir_proteccion_dinamica()