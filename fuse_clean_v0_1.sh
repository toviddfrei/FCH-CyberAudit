#!/bin/bash
# Script para desmontar montajes FUSE/GVFS como el usuario propietario.

echo "Iniciando limpieza de montajes virtuales (FUSE/GVFS)..."

# Usamos $UID para obtener el UID del usuario que ejecuta el script (el usuario original, gracias a 'su -')
GVFS_PATH="/run/user/${UID}/gvfs"
DOC_PATH="/run/user/${UID}/doc"

if [ -d "$GVFS_PATH" ]; then
    /usr/bin/fusermount -u "$GVFS_PATH" 2>/dev/null 
    if [ $? -eq 0 ]; then
        echo "   [Éxito] Desmontado: $GVFS_PATH"
    else
        echo "   [Fallo] No se pudo desmontar $GVFS_PATH (puede estar en uso, o no existen)."
        echo "           Comprueba manualmente con mount | grep gvfs."
    fi
fi

if [ -d "$DOC_PATH" ]; then
    /usr/bin/fusermount -u "$DOC_PATH" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "   [Éxito] Desmontado: $DOC_PATH"
    else
        echo "   [Fallo] No se pudo desmontar $DOC_PATH (puede estar en uso, o no existen)."
        echo "           Comprueba manualmente con mount | grep doc."
    fi
fi

echo "Limpieza de montajes virtuales finalizada."
exit 0