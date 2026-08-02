// Point d'entrée scan fichier/dossier


#ifndef AMSI_CLIENT_H
#define AMSI_CLIENT_H

#include <stdint.h>
#include <amsi.h>
#include "detection/heuristic.h"


int AMSIClient_Scan(uint8_t *data, size_t size, const char *filename, ScanResult *result);

#endif