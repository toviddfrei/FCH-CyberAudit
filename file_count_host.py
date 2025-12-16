import csv
from datetime import datetime
from pathlib import Path

def contar_ficheros_pathlib_y_guardar_csv(directorio_raiz, nombre_archivo_csv="conteo_ficheros_pathlib.csv"):
    """
    Recorre un directorio recursivamente usando pathlib, cuenta el total de ficheros,
    y escribe el resultado en un archivo CSV.
    """
    # Convertir la ruta de entrada a un objeto Path
    ruta_base = Path(directorio_raiz)
    
    # 1. Conteo de ficheros (la parte clave)
    # .rglob('*') busca recursivamente todos los archivos y directorios
    # .is_file() filtra los resultados para contar solo los ficheros
    # sum(1 for ...) es un generador eficiente para contar elementos
    try:
        contador_total = sum(1 for elemento in ruta_base.rglob('*') if elemento.is_file())
    except FileNotFoundError:
        print(f"Error: El directorio '{directorio_raiz}' no existe.")
        return 0
    except Exception as e:
        print(f"Ocurrió un error al contar los ficheros: {e}")
        return 0

    print(f"Total de ficheros encontrados en '{directorio_raiz}' (Pathlib): {contador_total}")
    
    # 2. Preparación y escritura del CSV (idéntica a la versión anterior)
    fecha_ejecucion = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    datos_resultado = [
        ['Fecha de Ejecución', 'Directorio Analizado', 'Total de Ficheros'],
        [fecha_ejecucion, str(ruta_base.resolve()), contador_total] # Usamos str() para guardar la ruta como texto
    ]

    try:
        # 'w' es modo escritura, newline='' evita saltos de línea extra
        with open(nombre_archivo_csv, 'w', newline='', encoding='utf-8') as archivo_csv:
            escritor_csv = csv.writer(archivo_csv)
            escritor_csv.writerows(datos_resultado)
            
        print(f"Resultados guardados exitosamente en '{nombre_archivo_csv}'")
        
    except Exception as e:
        print(f"Ocurrió un error al escribir el CSV: {e}")
        
    return contador_total

# --- Ejemplo de uso ---

# Define la ruta inicial. Usamos '.' para el directorio actual
ruta_a_analizar = Path.cwd() # Path.cwd() es el equivalente de os.getcwd()

total_pathlib = contar_ficheros_pathlib_y_guardar_csv(ruta_a_analizar)