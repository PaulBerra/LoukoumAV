#include <windows.h>
#include <stdint.h>

typedef struct {
    DWORD pid;
    char imagePath[MAX_PATH];
    DWORD parentPid;
    int score;
    int matchedRules[16];
    int matchedRuleCount;
    uint64_t firstSeen;
    uint64_t lastActivity;
} ProcessScore;

// Ajoute ou récupère l'entrée pour un PID
ProcessScore* Scoring_GetOrCreate(DWORD pid);

// Ajoute des points à un processus + trace la règle
void Scoring_AddPoints(DWORD pid, int severity, int ruleIdx);

// Récupère le score actuel
int Scoring_GetScore(DWORD pid);

// Supprime un processus terminé
void Scoring_Remove(DWORD pid);