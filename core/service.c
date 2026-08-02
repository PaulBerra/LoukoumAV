#include "service.h"
#include <stdio.h>
#include <windows.h>
#include "monitor/etw.h"
#include "utils/config.h"


int Service_Install(void){
    SC_HANDLE hSCManager = OpenSCManagerW(
        NULL,   //local
        NULL,   //SA db
        SC_MANAGER_ALL_ACCESS // tous les droits
    );

    if (hSCManager == NULL) {
        DWORD err = GetLastError();
        fprintf(stderr,"OpenSCManagerW failed. Error: %lu\n", err);
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "Access denied. Try running as Administrator.\n");
        }
        return 1;
    }
    fprintf(stdout, "Successfully opened Service Control Manager.\n");

    // Create the service
    SC_HANDLE hService = CreateServiceW(
        hSCManager,               // SCM database handle
        SERVICE_NAME,         // Internal service name
        SERVICE_DISPLAY_NAME,     // Display name
        SERVICE_ALL_ACCESS,       // Desired access
        SERVICE_WIN32_OWN_PROCESS,// Service type
        SERVICE_DEMAND_START,     // Start type (boot) // prod = SERVICE_AUTO_START; debug = SERVICE_DEMAND_START
        SERVICE_ERROR_NORMAL,     // Error control type
        SERVICE_PATH, // Path to service binary
        NULL,                     // No load ordering group
        NULL,                     // No tag identifier
        NULL,                     // No dependencies
        NULL,                     // LocalSystem account
        NULL                      // No password
    );

    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            fprintf(stderr, "Service already exists.\n");
        } else {
            fprintf(stderr, "CreateService failed (%lu)\n", err);
        }
        CloseServiceHandle(hSCManager);
        return 1;
    }

    fprintf(stdout, "Service created successfully.\n");

    // Close handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return 0;
}

int Service_Uninstall(void) {
        SC_HANDLE hSCManager = OpenSCManagerW(
        NULL,   //local
        NULL,   //SA db
        SC_MANAGER_ALL_ACCESS // tous les droits
    );

    if (hSCManager == NULL) {
        DWORD err = GetLastError();
        fprintf(stderr,"OpenSCManagerW failed. Error: %lu\n", err);
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "Access denied. Try running as Administrator.\n");
        }
        return 1;
    }
    fprintf(stdout, "Successfully opened Service Control Manager.\n");

    
    SC_HANDLE hService = OpenServiceW(
        hSCManager,              // Handle to SCM
        SERVICE_NAME,             // Name of the service
        DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS     // Desired access rights
    );

    if (hService == NULL) {
        wprintf(L"OpenServiceW failed. Error: %lu\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return 1;
    }

    // try shut down the service
    SERVICE_STATUS status;
    if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        fprintf(stdout, "Stopping service...\n");
        Sleep(1000); // Give it a moment to stop
    }

    // Delete the service
    int success = DeleteService(hService);
    if (!success) {
        printf("DeleteService failed. Error: %lu\n", GetLastError());
    } else {
        printf("Service marked for deletion.\n");
    }

    // Close handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return 0;
}

/*             Gestion du RUN du service            */
static SERVICE_STATUS g_serviceStatus;
static SERVICE_STATUS_HANDLE g_serviceStatusHandle;
static HANDLE g_serviceStopEvent = NULL;

void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
        case SERVICE_CONTROL_STOP:
            g_serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
            SetEvent(g_serviceStopEvent);  // débloque ServiceMain
            break;
    }
}

static DWORD WINAPI EtwThread(LPVOID param) {
    FILE *f = fopen(SERVICE_LOGFILE, "a");
    if (f) { fprintf(f, "EtwThread started\n"); fclose(f); }
    ETW_Start();  // bloque jusqu'à la fin
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPWSTR *argv) {
    FILE *f = fopen(SERVICE_LOGFILE, "a");
    if (f) { fprintf(f, "ServiceMain called\n"); fclose(f); }
    g_serviceStatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    
    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
    
    // Créer l'event de stop
    g_serviceStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    
    // Signaler qu'on tourne
    g_serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
    
    // lancer un thread ETW
    HANDLE hEtwThread = CreateThread(NULL, 0, EtwThread, NULL, 0, NULL);
    
    // Attendre le signal de stop
    WaitForSingleObject(g_serviceStopEvent, INFINITE);
    
    ETW_Stop();
    WaitForSingleObject(hEtwThread, 5000);  // attend max 5s la fin du thread
    CloseHandle(hEtwThread);

    // Nettoyer et sortir
    g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
}

int Service_Run(void) {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { SERVICE_NAME, ServiceMain },
        { NULL, NULL }
    };
    
    StartServiceCtrlDispatcherW(serviceTable);
    return 0;
}