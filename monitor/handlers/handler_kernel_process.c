#include "handler_kernel_process.h"
#include "core/engine.h"
#include "core/scanner.h"

void Handler_KernelProcess(PEVENT_RECORD event) {
    // Seulement les events "Process Start"
    if (event->EventHeader.EventDescriptor.Id != 1) return;
    
    // Extraire le PID
    DWORD pid = *(DWORD*)event->UserData;
    
    // Ouvrir le processus pour son chemin
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return;
    
    WCHAR exePath[MAX_PATH];
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, exePath, &size)) {
        CloseHandle(hProcess);
        return;
    }
    CloseHandle(hProcess);
    
    // Construire l'Event générique
    Event evt = {0};
    evt.type = EVENT_PROCESS_START;
    evt.pid = pid;
    GetSystemTimeAsFileTime((FILETIME*)&evt.timestamp);
    WideCharToMultiByte(CP_ACP, 0, exePath, -1, evt.details, sizeof(evt.details), NULL, NULL);
    
    // Envoyer à l'engine (qui décidera de scanner ou pas)
    Engine_ProcessEvent(&evt);
}