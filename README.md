# **Linux Security & Integrity Suite (FCH) - v0.2.8 Premium**

## **🛡️ Propósito del Proyecto**

**FCH (Filesystem & Control Health)** es una suite de herramientas de ciberseguridad diseñada para el control total de la integridad en sistemas Linux. Ha evolucionado de una auditoría estática de archivos a un sistema híbrido que combina el análisis de disco con la **Vigilancia Inteligente de RAM**.

Esta suite ayuda a los administradores a identificar "zonas ciegas" y detectar malware persistente o volátil mediante la verificación cruzada de firmas oficiales del sistema.

## **🚀 Valor Añadido de la Suite**

A diferencia de los escáneres genéricos, la FCH Suite ofrece un enfoque de **Seguridad Pedagógica**:

1. **Auditoría Estática Clasificada (v0.1.2):** Escaneo profundo de permisos con clasificación de riesgos (BAJO a CRÍTICO) y saneamiento automático de puntos virtuales (FUSE/GVFS).  
2. **Monitor Dinámico de RAM (v0.2.8):** Vigilancia de procesos en tiempo real con detección de inyecciones y ejecución sin binarios en disco.  
3. **Motor de Integridad Oficial:** Auditoría automática de hashes contra la base de datos del gestor de paquetes (dpkg) para confirmar la legitimidad de los binarios.  
4. **Auto-Aprendizaje Pedagógico:** Uso de una base de conocimiento en formato **JSON** que el sistema alimenta automáticamente tras verificar procesos seguros, explicando al usuario qué hace cada proceso.  
5. **Trazabilidad Forense:** Informes protegidos con chmod 600 y logs detallados en CSV con marcas de tiempo.

## **📁 Estructura del Proyecto**

* fch_v0_1.py: **Módulo Suite Principal**. Orquestador de la auditoría de archivos y lanzador del monitor RAM.  
* fch_dynamic_v0_2.py: **Monitor Dinámico de Procesos**. El "cerebro" que vigila la RAM y verifica hashes oficiales.  
* base_conocimiento.json: **Base de Inteligencia**. Almacena la pedagogía y procesos de confianza (se genera automáticamente).  
* fuse_clean_v0_1.sh: **Script de Saneamiento**. Limpia montajes virtuales para eliminar ruido en los informes.

## **🛠️ Requisitos e Instalación**

* **SO:** Linux (Debian, Ubuntu, Kali Linux).  
* **Dependencias:** Python 3.x, python3-psutil.  
* **Privilegios:** Ejecución obligatoria con sudo.

```Bash

# Clonar y preparar  
$ git clone https://github.com/tu-usuario/fch-security-suite.git  
$ cd fch-security-suite  
$ chmod +x fuse_clean_v0_1.sh

```

## **📖 Guía de Uso**

### **1. Iniciar la Auditoría Completa**

Ejecute el script base para un escaneo total del sistema:

```Bash

# Ejecutar
$ sudo python3 fch_v0_1.py

```

### **2. Flujo de Trabajo (Workflow)**

1. **Consentimiento:** Aceptación de términos legales y de responsabilidad.  
2. **Saneamiento FUSE:** Limpieza interactiva de puntos de montaje de usuario.  
3. **Escaneo de Disco:** Clasificación pedagógica de errores de acceso.  
4. **Veredicto Ejecutivo:** Resumen de salud del sistema de archivos.  
5. **Vigilancia RAM:** Transición opcional al monitor dinámico con auto-aprendizaje.

## **📊 Análisis de la Salida (Reports)**

La suite genera informes técnicos detallados:

* auditoria_control_*.csv: Detalla rutas inaccesibles, nivel de riesgo y recomendación de mitigación.  
* incidencias_ram_*.csv: Registra bloqueos de procesos sospechosos o autorizaciones de usuario.

## **👨‍💻 Perfil del Proyecto**

Desarrollado como una herramienta educativa y profesional para la gestión de integridad. Este proyecto demuestra la capacidad de integrar lógica de bajo nivel de Linux con estructuras de datos dinámicas (JSON) para la toma de decisiones en ciberseguridad.
