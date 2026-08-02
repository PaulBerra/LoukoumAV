// Orchestrateur des analyses

#include "engine.h"
#include "detection/rules_parser.h"
#include "utils/config.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    Event history[MAX_HISTORY];
    int count;
    CRITICAL_SECTION lock;
} EngineState;

static EngineState g_state = {0};
static SysmonRules g_rules = {0};
static int g_rulesLoaded = 0;


int Engine_ProcessEvent(const Event *event) {
    // Charger les règles au premier appel
    if (!g_rulesLoaded) {
        if (Rules_LoadFromFile(SYSMON_RULES_PATH, &g_rules) == 0) {
            g_rulesLoaded = 1;
            FILE *f = fopen(SERVICE_LOGFILE, "a");
            if (f) { fprintf(f, "ENGINE: loaded %d rules\n", g_rules.ruleCount); fclose(f); }
        }
    }
    
    // Traiter les process starts
    if (event->type == EVENT_PROCESS_START) {
        // Pour l'instant on n'a que le chemin dans details, pas le parent
        // On passera "" pour parent
        int ruleIdx = Rules_MatchProcessCreate(&g_rules, "", event->details);
        
        if (ruleIdx >= 0) {
            FILE *f = fopen(SERVICE_LOGFILE, "a");
            if (f) { 
                fprintf(f, "ALERT: rule matched '%s' pid=%lu\n",
                        g_rules.rules[ruleIdx].groupName, event->pid);
                fclose(f); 
            }
        }
    }
    
    return 0;
}