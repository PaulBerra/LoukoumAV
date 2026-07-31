// Intégration libyara

#ifndef YARA_ENGINE_H
#define YARA_ENGINE_H

#include <yara/libyara.h>

#include "detection/heuristic.h"

int YARA_ScanBuffer(uint8_t *data, size_t size, const char *rulesPath, ScanResult *result);


#endif