#!/bin/sh

ORIGIN= "/ruta/del/origen"
DEST = "usuario@ip::backup/"
LAST_COMP_COPY = "/ruta/ultima/completa"
LAST_DIFF_COPY = "/ruta/ultima/diferencial"
LAST_INC_COPY = "/ruta/ultima/incremental"
INC_DAYS = 7
DIFF_DAYS = 21
COMP_DAYS = 31


copia_completa() {
    rsync -avz "$ORIGIN" "$DEST"
    cp -al "$LAST_COMP_COPY" "$LAST_INC_COPY"
}

copia_incremental() {
    rsync -avz --link-dest="$LAST_COMP_COPY" "$ORIGIN" "$DEST"
}

copia_diferencial() {
    rsync -avz --compare-dest="$LAST_COMP_COPY" "$ORIGIN" "$DEST"
    cp -al "$LAST_DIFF_COPY" "$LAST_COMP_COPY"
}

FECHA_ACTUAL = $(date +%Y%m%d)

if [ "$FECHA_ACTUAL" == "$(date +%Y%m%d)"]; then
    copia_completa
    exit 0
fi

if [ "$FECHA_ACTUAL" == "$(date +%Y%m%d -d "$DIFF_DAYS days ago")"]; then
    copia_diferencial
    exit 0
fi

if [ "$FECHA_ACTUAL" == "$(date +%Y%m%d -d "$DIFF_DAYS days ago")"]; then
    contador_incrementales = $(ls -1 /ruta/incrementales/ | wc -1)
    if [ "$contador_incrementales" -ge 3 ]; then
        copia_diferencial
        exit 0
    else
        copia_incremental
        exit 0
    fi
fi






