// Orchestrateur des analyses

#include "engine.h"
#include "utils/config.h"
#include <stdio.h>

int Engine_ProcessEvent(const Event *event) {
    FILE *f = fopen(SERVICE_LOGFILE, "a");
    if (f) { 
        fprintf(f, "ENGINE: type=%d pid=%lu details=%s\n", 
                event->type, event->pid, event->details); 
        fclose(f); 
    }
    return 0;
}