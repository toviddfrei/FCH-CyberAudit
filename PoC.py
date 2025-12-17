import os
import hashlib
import psutil # Necesitarás instalarlo: sudo apt install python3-psutil

def obtener_hash_archivo(ruta):
    """Calcula el SHA-256 de un archivo en disco."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(ruta, "rb") as f:
            for bloque in iter(lambda: f.read(4096), b""):
                hash_sha256.update(bloque)
        return hash_sha256.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def prueba_concepto_memoria(nombre_proceso):
    print(f"--- Iniciando PoC: Verificación de Integridad para {nombre_proceso} ---")
    
    # 1. Localizar el archivo en disco
    ruta_disco = f"/bin/{nombre_proceso}" 
    if not os.path.exists(ruta_disco):
        ruta_disco = f"/usr/bin/{nombre_proceso}"

    hash_disco = obtener_hash_archivo(ruta_disco)
    print(f"[DISCO] Ruta: {ruta_disco}")
    print(f"[DISCO] Hash SHA-256: {hash_disco}")

    # 2. Buscar el proceso en RAM (Simulando el 'sniffer')
    print(f"\n🔍 Buscando '{nombre_proceso}' en la memoria activa...")
    encontrado = False
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        if proc.info['name'] == nombre_proceso:
            encontrado = True
            ruta_ram = proc.info['exe']
            hash_ram = obtener_hash_archivo(ruta_ram)
            
            print(f"[RAM] Detectado PID {proc.info['pid']} ejecutando desde: {ruta_ram}")
            print(f"[RAM] Hash SHA-256: {hash_ram}")
            
            if hash_disco == hash_ram:
                print("\n✅ RESULTADO: INTEGRIDAD CONFIRMADA. El proceso coincide con el disco.")
            else:
                print("\n🚨 ALERTA: DISCREPANCIA DETECTADA. El proceso en RAM no es igual al del disco.")
            break
    
    if not encontrado:
        print(f"\nℹ️ El proceso '{nombre_proceso}' no está en ejecución ahora mismo.")
        print(f"Prueba esto: Abre otra terminal y escribe 'sleep 100', luego ejecuta este script buscando 'sleep'.")

if __name__ == "__main__":
    # Probamos con 'ls' (si lo estás ejecutando rápido) o 'bash' que siempre está activo
    prueba_concepto_memoria("bash")