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
    EVENT_REMOTE_THREAD,
    EVENT_PROCESS_INJECT,
} EventType;

typedef struct {
    EventType type;
    DWORD pid;
    DWORD parentPid;
    uint64_t timestamp;
    char details[512];
    char parentImage[MAX_PATH];
} Event;


#ifdef __cplusplus
extern "C" {
#endif

int Engine_ProcessEvent(const Event *event);

#ifdef __cplusplus
}
#endif

#endif