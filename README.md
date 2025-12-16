# Linux Root Control Audit (FCH)

Este proyecto ofrece una herramienta de auditoría de ciberseguridad diseñada para verificar el **control total** del usuario `root` sobre el sistema de archivos de Linux. Su principal objetivo es depurar el informe final eliminando las entradas falsas generadas por archivos del sistema operativo que son inaccesibles por diseño (ruido de auditoría).

## Propósito y Valor Añadido

La mayoría de los escáneres recursivos reportan miles de errores de permiso en directorios virtuales de bajo riesgo como `/run/user/` (FUSE/GVFS) y `/proc/` (kernel). Estos errores de nivel **BAJO** oscurecen la detección de fallos de seguridad críticos.

El script `fch.py` ofrece tres características clave:

1. **Limpieza Interactiva:** Ejecuta el *wrapper* `fuse_clean.sh` con el contexto de sesión adecuado (`su -`) para desmontar automáticamente los sistemas de archivos virtuales de usuario antes de la auditoría.
2. **Clasificación de Riesgos:** Clasifica cada fallo de acceso detectado como **BAJO**, **MEDIO**, **ALTO**, o **CRÍTICO** (I/O Errors).
3. **Conclusión Ejecutiva:** Proporciona un resumen claro, indicando si se detectaron fallos críticos o si el sistema ha mantenido el control total de los archivos persistentes.

## Requisitos del Sistema

* Sistema Operativo: Linux (Distros basadas en Debian/Ubuntu, Red Hat).
* Intérprete: Python 3.x
* Privilegios: Un usuario con acceso a `sudo`.
* Comandos necesarios: `sudo`, `su`, `fusermount`.

## Guía de Uso

Para garantizar la portabilidad y evitar la edición manual de rutas, **se recomienda mantener `fch.py` y `fuse_clean.sh` en el mismo directorio.**

### 1. Preparación de Archivos

Asegúrese de que el script *wrapper* de limpieza tenga los permisos de ejecución:

```bash
chmod +x fuse_cleaner.sh
```

### 2. Ejecución de la Auditoría

Lance el script principal con privilegios de root.

```bash

sudo python3 fch.py
```

El script verificará automáticamente su entorno y ejecutará la auditoría siguiendo esta secuencia:

* **Consentimiento:** El script preguntará si desea ejecutar la limpieza automática de FUSE/GVFS.

* **Limpieza:** Si acepta, se intentará el desmontaje simulando una sesión de inicio de sesión (su - usuario).

* **Auditoría:** Se inicia el recorrido recursivo del sistema de archivos (os.walk('/')).

### 3. Análisis de la Salida

La salida final mostrará una conclusión ejecutiva basada en la clasificación de riesgos.

Ejemplo de Salida (Control Total Confirmado)
Lanzando wrapper de limpieza como usuario (requiere contexto de sesión)...
Iniciando limpieza de montajes virtuales (FUSE/GVFS)...
   [Éxito] Desmontado: /run/user/1000/gvfs
   [Éxito] Desmontado: /run/user/1000/doc
Limpieza de montajes virtuales finalizada.
✅ El wrapper de limpieza se ejecutó. Revise los mensajes de Éxito/Fallo.

🔍 Iniciando recorrido del sistema de ficheros...
[BAJO] Fallo de control en: /proc/6491/task/6491/fd/3
[BAJO] Fallo de control en: /proc/6491/fd/3

...
✅ ESTADO: CONTROL TOTAL CONFIRMADO
El informe muestra 2 fallos, todos clasificados como de riesgo BAJO, típicos del ruido de auditoría (/proc, /sys).
...
Nota sobre Riesgo BAJO:

Los fallos clasificados como BAJO y ubicados en /proc/ o /sys/ son inherentes al funcionamiento del kernel de Linux y pueden ignorarse con seguridad. El objetivo de la auditoría es detectar fallos en ubicaciones críticas o persistentes (riesgo MEDIO, ALTO o CRÍTICO).

## Estructura del Proyecto

* **fch.py:** Script principal de auditoría y clasificación de riesgos.

* **fuse_clean.sh:** Wrapper de shell encargado de desmontar los puntos FUSE/GVFS.

* **auditoria_control_clasificada.csv:** Archivo de informe generado.
