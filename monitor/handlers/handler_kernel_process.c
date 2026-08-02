// handler_kernel_process.c
#include "handler_kernel_process.h"


void Handler_KernelProcess(PEVENT_RECORD event) {
    //if (event->UserDataLength < 60) return;
    if (event->EventHeader.EventDescriptor.Id == 1) {
    // Log pour identifier
    FILE *f = fopen(SERVICE_LOGFILE, "a");
    if (f) { 
        fprintf(f, "PROCESS EVENT: id=%d userDataLen=%d\n", 
                event->EventHeader.EventDescriptor.Id,
                event->UserDataLength); 
        fclose(f); 
    }
    DWORD pid = *(DWORD*)event->UserData;


    FILE *f2 = fopen(SERVICE_LOGFILE, "a");
    if (f2) { fprintf(f2, "  extracted PID=%lu\n", pid); fclose(f2); }


    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        DWORD err = GetLastError();
        FILE *f3 = fopen(SERVICE_LOGFILE, "a");
        if (f3) { fprintf(f3, "  OpenProcess failed err=%lu\n", err); fclose(f3); }
        return;
    }
    
    WCHAR exePath[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, exePath, &size)) {
        // Convertir wide → ansi
        char exePathA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, exePath, -1, exePathA, MAX_PATH, NULL, NULL);
        
        // Scanner
        ScanResult result = {0};
        int score = Scanner_ScanFile(exePathA, &result);
        
        FILE *f = fopen(SERVICE_LOGFILE, "a");
        if (f) { 
            fprintf(f, "SCAN: %s → score=%d\n", exePathA, score);
            if (score > 50) fprintf(f, "  ⚠ ALERT\n");
            fclose(f); 
        }
    }
    
    CloseHandle(hProcess);
}
}