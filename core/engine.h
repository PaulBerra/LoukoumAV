// engine.h
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
} EventType;

typedef struct {
    EventType type;
    DWORD pid;
    DWORD parentPid;
    uint64_t timestamp;
    char details[512];
} Event;

int Engine_ProcessEvent(const Event *event);

#endif