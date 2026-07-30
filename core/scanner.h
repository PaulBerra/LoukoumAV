// Point d'entrée scan fichier/dossier


#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include "detection/heuristic.h"

typedef enum {
    FILE_TYPE_UKNW,
    FILE_TYPE_PE,
    FILE_TYPE_PDF,
    FILE_TYPE_ZIP,
    FILE_TYPE_ELF,
    FILE_TYPE_DOC,
    FILE_TYPE_7ZIP,
    FILE_TYPE_JPEG,
    FILE_TYPE_PNG
} FileType;

FileType DetectFileType(uint8_t *data, size_t size);

int Scanner_ScanFile(const char* filePath, ScanResult *result);

#endif