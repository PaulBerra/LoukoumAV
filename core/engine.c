// Orchestrateur des analyses

#include "engine.h"
#include "detection/rules_parser.h"
#include "monitor/dynamic_scoring.h"
#include "utils/config.h"
#include "core/scanner.h"

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

        // Scan statique du binaire
        ScanResult sr = {0};
        int staticScore = Scanner_ScanFile(event->details, &sr);
        if (staticScore > 0) {
            Scoring_AddPoints(event->pid, staticScore, -1);
        }

        int totalScore = Scoring_GetScore(event->pid);
        if (totalScore > ALERT_THRESHOLD) {
            FILE *f = fopen(SERVICE_LOGFILE, "a");
            if (f) { 
                // pour l'instant on log ici
                fprintf(f, "!!! HIGH THREAT: pid=%lu score=%d image=%s\n", 
                        event->pid, totalScore, event->details); 
                fclose(f); 
            }
        }


        // Match des règles Sysmon sur les métadonnées de création du processus
        // Chaque règle qui matche ajoute sa severity au score cumulé du PID
        EventField fields[] = {
            {"ParentImage", event->parentImage},
            {"Image", event->details}
        };

        int ruleIdx = Rules_MatchEvent(&g_rules, RULE_PROCESS_CREATE, fields, 2);
        
        if (ruleIdx >= 0) {
            int severity = g_rules.rules[ruleIdx].severity;

            Scoring_AddPoints(event->pid, severity, ruleIdx);
            int currentScore = Scoring_GetScore(event->pid);

            FILE *f = fopen(SERVICE_LOGFILE, "a");
            if (f) { 
                fprintf(f, "ALERT: rule matched '%s' pid=%lu score=%d\n",
                        g_rules.rules[ruleIdx].groupName, event->pid, currentScore);
                fclose(f); 
            }
        }
    }
    
    if (event->type == EVENT_PROCESS_STOP) {
        Scoring_Remove(event->pid);
    }


    return 0;
}