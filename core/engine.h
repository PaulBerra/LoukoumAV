// Orchestrateur des analyses

// core/engine.h
#ifndef ENGINE_H
#define ENGINE_H

#include <stdint.h>
#include <windows.h>

#define MAX_HISTORY 256

typedef enum {
    EVENT_PROCESS_START,
    EVENT_PROCESS_STOP,
    EVENT_FILE_WRITE,
    EVENT_MEMORY_RWX,
    EVENT_NETWORK_CONNECT,
    // à étendre
} EventType;

typedef struct {
    EventType type;
    DWORD pid;
    DWORD parentPid;
    uint64_t timestamp;
    char details[512];  // chemin fichier, IP, etc.
} Event;

typedef struct {
    Event history[MAX_HISTORY];
    int count;
    CRITICAL_SECTION lock;  // thread-safety
} EngineState;

static EngineState g_state = {0};

int Engine_ProcessEvent(const Event *event);

#endif