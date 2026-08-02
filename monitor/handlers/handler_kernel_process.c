#include "handler_kernel_process.h"
#include "core/engine.h"
#include "core/scanner.h"

void Handler_KernelProcess(PEVENT_RECORD event) {
    // Seulement les events "Process Start"
    if (event->EventHeader.EventDescriptor.Id != 1) return;
    
    // Extraire le PID & PPID
    DWORD pid = *(DWORD*)event->UserData;
    DWORD parentPid = *(DWORD*)((BYTE*)event->UserData + 20);

    // Ouvrir le processus 
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return;
    
    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    WCHAR parentPath[MAX_PATH] = L"";
    if (hParent) {
        DWORD psize = MAX_PATH;
        QueryFullProcessImageNameW(hParent, 0, parentPath, &psize);
        CloseHandle(hParent);
    }


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
    evt.parentPid = parentPid;

    GetSystemTimeAsFileTime((FILETIME*)&evt.timestamp);

    WideCharToMultiByte(CP_ACP, 0, exePath, -1, evt.details, sizeof(evt.details), NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, parentPath, -1, evt.parentImage, sizeof(evt.parentImage), NULL, NULL);


    // Envoyer à l'engine (qui décidera de scanner ou pas)
    Engine_ProcessEvent(&evt);
}