# Linux Root Control Audit (FCH) - v0.1.1 Premium

Este proyecto ofrece una herramienta de auditoría de ciberseguridad diseñada para verificar el CONTROL TOTAL del usuario root sobre el sistema de archivos de Linux. Su principal objetivo es identificar "zonas ciegas" y depurar el informe final eliminando el ruido generado por sistemas de archivos virtuales (FUSE/GVFS).

## Propósito y Valor Añadido

A diferencia de los escáneres recursivos genéricos, el script fch_v0_1.py está diseñado bajo un enfoque de SEGURIDAD PROACTIVA, ofreciendo:

1. Saneamiento de Entorno: Ejecuta el wrapper fuse_clean_v0_1.sh mediante "su -" para desmontar sistemas virtuales antes de la auditoría.
2. Clasificación de Riesgos: Clasifica cada fallo detectado como BAJO, MEDIO, ALTO o CRÍTICO (errores de E/S de hardware).
3. Protocolo Ético: Incluye una fase de Consentimiento Informado obligatorio antes de cualquier acción.
4. Trazabilidad Forense: Generación de informes con nombres dinámicos basados en marca de tiempo (YYYYMMDD_HHMMSS) para evitar la sobrescritura.
5. Privacidad del Informe: Protección automática de resultados mediante permisos "chmod 600" (lectura exclusiva para root).

## Requisitos del Sistema

* Sistema Operativo: Linux (basado en Debian, Ubuntu, RHEL o similares).
* Intérprete: Python 3.x.
* Privilegios: Acceso a sudo.
* Comandos necesarios: sudo, su, fusermount.

## Guía de Uso

Para garantizar la portabilidad, MANTENGA fch_v0_1.py y fuse_clean_v0_1.sh en el mismo directorio.

### 1. Preparación del Entorno

Otorgue permisos de ejecución al script de limpieza:

```bash
$chmod +x fuse_clean_v0_1.sh
```

### 2. Ejecución de la Auditoría

Inicie el proceso con privilegios de superusuario:

```bash
$sudo python3 fch_v0_1.py
```

### 3. Flujo de Trabajo (Workflow)

El script guiará al auditor a través de las siguientes fases:

1. Identidad: Comprobación de privilegios root.
2. Consentimiento: Aceptación explícita de la responsabilidad del auditor.
3. Limpieza: Opción interactiva para desmontar puntos FUSE/GVFS.
4. Escaneo: Recorrido recursivo y clasificación de incidencias en tiempo real.
5. Veredicto: Resumen ejecutivo en consola y generación de acta protegida.

## Análisis de la Salida

La herramienta genera un archivo CSV con la siguiente estructura de nombre:
auditoria_control_YYYYMMDD_HHMMSS.csv

Estructura del Informe:

* Ruta Inaccesible: Ubicación exacta del fallo en el sistema.
* Nivel de Riesgo: Clasificación de severidad (CRÍTICO, ALTO, MEDIO, BAJO).
* Conclusión: Análisis pedagógico del motivo técnico del fallo.
* Solución: Recomendación inmediata para mitigar el riesgo.

## Estructura del Proyecto

* fch_v0_1.py: Motor principal de auditoría y lógica de riesgos.
* fuse_clean_v0_1.sh: Script de soporte para el saneamiento de puntos virtuales.
* auditoria_control_*.csv: Informes generados (protegidos con permisos restrictivos).

--------------------------------------------------------------------------------
Desarrollado como herramienta educativa de control de integridad en sistemas Linux.
