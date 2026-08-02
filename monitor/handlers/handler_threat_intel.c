#include "handler_threat_intel.h"

void Handler_ThreatIntel(PEVENT_RECORD event) {
    if (event->EventHeader.EventDescriptor.Id != 1) return;
    
    uint32_t pid = 0;
    uint32_t parentPid = 0;
    char imagePath[MAX_PATH] = {0};
    char parentImagePath[MAX_PATH] = {0};

    Etw_GetPropertyUInt32(event, L"ProcessID", &pid);
    Etw_GetPropertyUInt32(event, L"ParentProcessID", &parentPid);
    Etw_GetPropertyString(event, L"ImageName", imagePath, sizeof(imagePath));
    
    // Essaye d'obtenir le nom du parent directement depuis l'event
    if (Etw_GetPropertyString(event, L"ParentImageName", parentImagePath, sizeof(parentImagePath)) != 0) {
        // ouverture du parent car pas dans l'event
        HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
        if (hParent) {
            WCHAR parentPathW[MAX_PATH];
            DWORD psize = MAX_PATH;
            if (QueryFullProcessImageNameW(hParent, 0, parentPathW, &psize)) {
                WideCharToMultiByte(CP_ACP, 0, parentPathW, -1, parentImagePath, sizeof(parentImagePath), NULL, NULL);
            }
            CloseHandle(hParent);
        }
    }
    
    Event evt = {0};
    evt.type = EVENT_PROCESS_START;
    evt.pid = pid;
    evt.parentPid = parentPid;
    GetSystemTimeAsFileTime((FILETIME*)&evt.timestamp);
    
    strncpy(evt.details, imagePath, sizeof(evt.details) - 1);
    strncpy(evt.parentImage, parentImagePath, sizeof(evt.parentImage) - 1);
    
    Engine_ProcessEvent(&evt);
}