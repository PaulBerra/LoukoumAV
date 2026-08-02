
#include "mitre.h"

int Mitre_LoadFromCSV(const char *path, MitreMap *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    
    out->count = 0;
    char line[1024];
    
    while (fgets(line, sizeof(line), f)) {
        if (out->count >= 512) break;
        
        char *technique = strtok(line, ",");
        char *severityStr = strtok(NULL, ",");
        
        if (technique && severityStr) {
            MitreSeverity *entry = &out->entries[out->count];
            strncpy(entry->technique, technique, 15);
            entry->severity = atoi(severityStr);
            out->count++;
        }
    }
    
    fclose(f);
    return 0;
}

int Mitre_GetSeverity(const MitreMap *map, const char *technique) {
    for (int i = 0; i < map->count; i++) {
        if (strcmp(map->entries[i].technique, technique) == 0) {
            return map->entries[i].severity;
        }
    }
    return 70; // Not found
}

void ExtractMitreTechnique(const char *path, char *out, size_t outSize) {
    const char *t = strstr(path, "T");
    while (t) {
        // Vérifie que ce qui suit est bien un TID (T + digits)
        if (t[1] >= '0' && t[1] <= '9') {
            size_t i = 0;
            out[i++] = 'T';
            const char *p = t + 1;
            while (*p >= '0' && *p <= '9' && i < outSize - 1) {
                out[i++] = *p++;
            }
            out[i] = '\0';
            return;
        }
        t = strstr(t + 1, "T");
    }
    out[0] = '\0';
}
