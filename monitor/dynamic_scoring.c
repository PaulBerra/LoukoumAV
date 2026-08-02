#include "dynamic_scoring.h"
#include <string.h>

#define MAX_PROCESSES 512

static ProcessScore g_processes[MAX_PROCESSES] = {0};
static int g_active[MAX_PROCESSES] = {0};

ProcessScore* Scoring_GetOrCreate(DWORD pid) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (g_active[i] && g_processes[i].pid == pid) {
            return &g_processes[i];
        }
    }

    // Find an available slot
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (!g_active[i]) {
            g_active[i] = 1;
            g_processes[i].pid = pid;
            g_processes[i].score = 0;
            g_processes[i].matchedRuleCount = 0;
            return &g_processes[i];
        }
    }

    return NULL;
}



void Scoring_AddPoints(DWORD pid, int severity, int ruleIdx) {
    ProcessScore *ps = Scoring_GetOrCreate(pid);
    if (!ps) return;

    ps->score += severity;
    if (ps->matchedRuleCount < 16) {
        ps->matchedRules[ps->matchedRuleCount++] = ruleIdx;
    }
}

int Scoring_GetScore(DWORD pid) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (g_active[i] && g_processes[i].pid == pid) {
            return g_processes[i].score;
        }
    }
    return 0;
}

void Scoring_Remove(DWORD pid) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (g_active[i] && g_processes[i].pid == pid) {
            g_active[i] = 0;
            memset(&g_processes[i], 0, sizeof(ProcessScore));
            return;
        }
    }
}