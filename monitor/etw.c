// etw router
#include "etw.h"
#include "handlers/handler_kernel_process.h"
#include <stdio.h>
#include "core/service.h"

static const GUID ProviderKernelProcess = 
    { 0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16} };

static const GUID ProviderThreatIntelligence = 
    { 0xF4E1897C, 0xBB5D, 0x5668, {0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44} };

static TRACEHANDLE g_sessionHandle = 0;
static EVENT_TRACE_PROPERTIES *g_pSessionProperties = NULL;
static WCHAR g_sessionName[] = L"LoukoumETWsession";
static ENABLE_TRACE_PARAMETERS g_enableParameters;

// gestion des retries pour le provider ThreatIntel
static HANDLE g_tiRetryThread = NULL;
static volatile int g_tiEnabled = 0;

static HANDLE g_etwRetryThread = NULL;
static volatile int g_etwEnabled = 0;

static void WINAPI EtwEventCallback(PEVENT_RECORD event) {

    // Dispatch selon le provider GUID
    if (IsEqualGUID(&event->EventHeader.ProviderId, &ProviderKernelProcess)) {
        Handler_KernelProcess(event);
    }
    // else if pour les autres handlers plus tard
}


static DWORD WINAPI EtwTiRetryThread(LPVOID param) {
    while (!g_tiEnabled) {
        DWORD wait = WaitForSingleObject(g_serviceStopEvent, 5 * 60 * 1000);
        if (wait == WAIT_OBJECT_0) return 0;  // service stopped
        
        ULONG status = EnableTraceEx2(g_sessionHandle,
            &ProviderThreatIntelligence,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            0xFFFFFFFFFFFFFFFF,
            0, 0, NULL);
        
        if (status == ERROR_SUCCESS) {
            g_tiEnabled = 1;
            FILE *f = fopen(SERVICE_LOGFILE, "a");
            if (f) { fprintf(f, "ETW_TI: enabled after retry\n"); fclose(f); }
        }
    }
    return 0;
}

static DWORD WINAPI EtwRetryThread(LPVOID param) {
    while (!g_etwEnabled) {
        
        DWORD wait = WaitForSingleObject(g_serviceStopEvent, 5 * 60 * 1000);
        if (wait == WAIT_OBJECT_0) return 0;  // service stopped

        ULONG status = EnableTraceEx2(g_sessionHandle, 
            &ProviderKernelProcess, 
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, 
            TRACE_LEVEL_VERBOSE,
            0xFFFFFFFFFFFFFFFF,
            0,
            0,
            NULL
        );

        if (status == ERROR_SUCCESS) {
            g_etwEnabled = 1;
            FILE *f = fopen(SERVICE_LOGFILE, "a");
            if (f) { fprintf(f, "ETW: enabled after retry\n"); fclose(f); }
        }
    }
    return 0;
}


int ETW_Start(void){
    FILE *f;
    f = fopen(SERVICE_LOGFILE, "a"); if (f) { fprintf(f, "ETW_Start: entered\n"); fclose(f); }

    ULONG status;
    size_t bufferSize;

    bufferSize = sizeof(EVENT_TRACE_PROPERTIES) +
                 (wcslen(g_sessionName) + 1) * sizeof(WCHAR) +
                 (MAX_PATH * sizeof(WCHAR));

    // Allocate memory for session properties
    g_pSessionProperties = (EVENT_TRACE_PROPERTIES *)malloc(bufferSize);
    if (!g_pSessionProperties) {
        printf(L"Memory allocation failed.\n");
        return 1;
    }
    ZeroMemory(g_pSessionProperties, bufferSize);

    // Fill EVENT_TRACE_PROPERTIES
    g_pSessionProperties->Wnode.BufferSize = (ULONG)bufferSize;
    g_pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_pSessionProperties->Wnode.ClientContext = 1; // QPC clock resolution
    g_pSessionProperties->Wnode.Guid = GUID_NULL;  // Let ETW assign a GUID
    g_pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_pSessionProperties->MaximumFileSize = 0; // No file size limit
    g_pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    g_pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) +
                                            (wcslen(g_sessionName) + 1) * sizeof(WCHAR);

    memcpy((char*)g_pSessionProperties + g_pSessionProperties->LoggerNameOffset, g_sessionName, (wcslen(g_sessionName) + 1) * sizeof(WCHAR));

    f = fopen(SERVICE_LOGFILE, "a"); if (f) { fprintf(f, "ETW_Start: StartTraceW status=%lu\n", status); fclose(f); }

    status = StartTraceW(&g_sessionHandle, g_sessionName, g_pSessionProperties);                                        
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ALREADY_EXISTS) {
            printf(L"Session '%s' already exists.\n", g_sessionName);
        } else {
            printf(L"StartTraceW failed with error: %lu\n", status);
        }
        free(g_pSessionProperties);
        return 1;
    }
    printf(L"ETW session '%s' started successfully.\n", g_sessionName);

    status = EnableTraceEx2(g_sessionHandle, 
        &ProviderKernelProcess, 
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, 
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,
        0,
        0,
        NULL
    );
    f = fopen(SERVICE_LOGFILE, "a"); if (f) { fprintf(f, "ETW_Start: EnableTraceEx2 status=%lu\n", status); fclose(f); }

    if (status == ERROR_SUCCESS) {
        g_etwEnabled = 1;
    } else {
        fprintf(f, "EnableTraceEx2 for ETW failed with error: %lu\n", status);
        // Start a retry thread for ETW provider
        g_etwRetryThread = CreateThread(NULL, 0, EtwRetryThread, NULL, 0, NULL);
        if (!g_etwRetryThread) {
            fprintf(f, "Failed to create retry thread for ETW provider.\n");
        }
    }

    status = EnableTraceEx2(g_sessionHandle,
        &ProviderThreatIntelligence,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,
        0, 0, NULL);
    f = fopen(SERVICE_LOGFILE, "a"); if (f) { fprintf(f, "ETW_TI_Start: EnableTraceEx2 status=%lu\n", status); fclose(f); }

    if (status == ERROR_SUCCESS) {
        g_tiEnabled = 1;
        fprintf(f, "EnableTraceEx2 for Threat Intelligence ETW failed with error: %lu\n", status);
    } else {
        // Start a retry thread for ThreatIntel provider
        g_tiRetryThread = CreateThread(NULL, 0, EtwTiRetryThread, NULL, 0, NULL);
        if (!g_tiRetryThread) {
            fprintf(f, "Failed to create retry thread for ThreatIntel provider.\n");
        }
    }








    EVENT_TRACE_LOGFILEW logFile = {0};
    logFile.LoggerName = g_sessionName;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EtwEventCallback;

    TRACEHANDLE consumer = OpenTraceW(&logFile);
    f = fopen(SERVICE_LOGFILE, "a"); if (f) { fprintf(f, "ETW_Start: OpenTraceW handle=%llu\n", (unsigned long long)consumer); fclose(f); }

    status = ProcessTrace(&consumer, 1, NULL, NULL);  // bloque jusqu'à Stop
    f = fopen(SERVICE_LOGFILE, "a"); if (f) { fprintf(f, "ETW_Start: ProcessTrace returned status=%lu\n", status); fclose(f); }

    return 0;
}
int ETW_Stop(void){
    FILE *f = fopen(SERVICE_LOGFILE, "a"); 
    if (f) { fprintf(f, "ETW_Stop called\n"); fclose(f); }

    int status = ControlTraceW(g_sessionHandle, g_sessionName, g_pSessionProperties, EVENT_TRACE_CONTROL_STOP);

    f = fopen(SERVICE_LOGFILE, "a"); 
    if (f) { fprintf(f, "ControlTraceW returned: %lu\n", status); fclose(f); }

    if (status != ERROR_SUCCESS) {
        printf(L"ControlTraceW (stop) failed with error: %lu\n", status);
    } else {
        printf(L"ETW session '%s' stopped successfully.\n", g_sessionName);
    }

    free(g_pSessionProperties);
    return 0;
}