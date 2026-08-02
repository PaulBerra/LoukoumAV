#ifndef MITRE_H
#define MITRE_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>s


typedef struct {
    char technique[16];
    int severity;
} MitreSeverity;

typedef struct {
    MitreSeverity entries[512];
    int count;
} MitreMap;


#ifdef __cplusplus 
extern "C" {
#endif

void ExtractMitreTechnique(const char *path, char *out, size_t outSize);
int Mitre_LoadFromCSV(const char *path, MitreMap *out);
int Mitre_GetSeverity(const MitreMap *map, const char *technique);

#ifdef __cplusplus
}
#endif

#endif