# **GUÍA INTEGRAL: DOCUMENTACIÓN TÉCNICA, SEGURIDAD Y FAQ (v0.2.8)**

## **1. FILOSOFÍA Y OBJETIVO DEL SISTEMA**

Este sistema ha sido diseñado para verificar el **"Control Total"** del administrador (ROOT) sobre el Host, evolucionando de una auditoría estática a una vigilancia dinámica. En Linux, root es el superusuario que debe tener acceso a todo; si la suite detecta rutas inaccesibles o procesos sin firma oficial, los cataloga como "zonas ciegas" o anomalías de integridad.

Estas anomalías pueden originarse por:

* Errores técnicos o de configuración administrativa.  
* Fallos físicos de hardware (Errores de E/S).  
* Técnicas de ocultación, persistencia de software no autorizado o malware volátil en RAM.

## **2. ARQUITECTURA TÉCNICA (El Maletín de Herramientas)**

Para garantizar transparencia y seguridad, la suite utiliza librerías estándar y especializadas:

* **os / pathlib**: Navegación y localización precisa de archivos en el sistema.  
* **subprocess**: Ejecución del saneamiento externo (fuse\_clean.sh) y consulta al motor dpkg.  
* **psutil**: Monitorización quirúrgica de la tabla de procesos en tiempo real.  
* **json**: Gestión del "Cerebro Pedagógico" o base de conocimiento compartida.  
* **csv / datetime**: Generación de actas forenses con trazabilidad temporal exacta.

## **3. PROTOCOLO DE INTERVENCIÓN: LIMPIEZA DE RUIDO (FUSE/GVFS)**

Los sistemas modernos proyectan "carpetas virtuales" (FUSE/GVFS) que no son archivos reales. Si no se desmontan antes de la auditoría:

* El informe se contamina con "falsos positivos" o ruido innecesario.  
* El script pierde eficiencia intentando acceder a rutas efímeras de usuario.

**Seguridad del Saneamiento**: El script fuse\_clean.sh es seguro; utiliza su \- para actuar bajo la identidad del usuario original y no compromete datos reales, solo desconecta montajes temporales.

## **4. MATRIZ DE CLASIFICACIÓN Y JERARQUÍA DE RIESGOS**

El sistema utiliza una lógica de semáforo para priorizar la respuesta del auditor:

* 🔴 **CRÍTICO**: Fallos de Entrada/Salida (I/O) en disco o procesos con Hash oficial modificado.  
  * *Acción*: Verificar hardware (fsck), restaurar backups o investigar compromiso de sistema.  
* 🟠 **ALTO**: Bloqueos en archivos clave (shadow, sudoers) o procesos en rutas no estándar (ej. /tmp).  
  * *Acción*: Restaurar permisos urgentemente e investigar el origen del proceso detectado.  
* 🟡 **MEDIO**: Permisos genéricos mal configurados o enlaces simbólicos rotos.  
  * *Acción*: Reconfiguración de permisos estándar y limpieza administrativa.  
* 🔵 **BAJO**: Errores en rutas virtuales (/proc, /sys).  
  * *Acción*: Ignorar; es comportamiento esperado del Kernel.

## **5. SECCIÓN DE PREGUNTAS FRECUENTES (FAQ)**

**¿Por qué usar un archivo JSON local?**
Para garantizar portabilidad y autonomía. Permite que la suite aprenda y funcione sin depender de bases de datos externas o configuraciones complejas.

**¿Cómo se verifica la legitimidad de un proceso?**  
La suite consulta la base de datos de dpkg para realizar una verificación cruzada de firmas y hashes del binario en ejecución. Si el binario ha sido alterado, se dispara una alerta de integridad.

**¿Qué es un "Binario Huérfano"?**
Es un proceso que no pertenece a ningún paquete oficial instalado por el sistema. La suite lo trata como riesgo potencial hasta que el usuario le otorga confianza manual.

**¿El bloqueo de procesos es automático?**  
En el modo de vigilancia, si se detecta una amenaza y el usuario no interviene tras un tiempo prudencial, la suite aplica un protocolo "Fail-Safe" de bloqueo preventivo para proteger el host.
