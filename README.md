# 🛡️ Linux Root Control Audit (FCH)

Este script de auditoría de ciberseguridad verifica el control total del usuario root sobre los archivos persistentes del sistema, eliminando el "ruido" de la auditoría que generan los sistemas de archivos virtuales (FUSE/GVFS) y el kernel (`/proc`).

## 💡 Motivación

La mayoría de los escáneres de archivos reportan fallos de permiso (`[BAJO]`) en rutas como `/run/user/1000/gvfs` o `/proc/PID/fd/`, lo que obscurece la detección de riesgos reales. Este script interactivo limpia los montajes virtuales antes de auditar, permitiendo una conclusión ejecutiva clara y enfocada en riesgos **ALTO** o **CRÍTICO**.

## 🛠️ Requisitos

* Sistema Operativo Linux (Probado en Ubuntu/Debian).
* Python 3.x
* Comandos estándar de sistema: `sudo`, `fusermount`, `su`.
* Un usuario con privilegios de `sudo`.

## 🚀 Uso

1. **Guardar el Wrapper:**
    Guarde el contenido del archivo `limpieza_fuse.sh` (o el nombre que haya elegido) en su ruta de trabajo.

2. **Otorgar Permisos de Ejecución al Wrapper:**

    ```bash
    chmod +x limpieza_fuse.sh
    ```

3. **Actualizar la Ruta en `fch.py`:**
    Asegúrese de que la variable `RUTA_LIMPIEZA_SHELL` dentro de `fch.py` apunte a la ubicación correcta del *wrapper*.

4. **Ejecutar la Auditoría:**

    ```bash
    sudo python3 fch.py
    ```

    El script le preguntará si desea ejecutar la limpieza automática.
