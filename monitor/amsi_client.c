// Sous traitement a amsi pour un check systematique par tous les AV disponibles

#include "amsi_client.h"
#include <stdio.h>

int AMSIClient_Scan(uint8_t *data, size_t size, const char *filename, ScanResult *result) {
    HAMSICONTEXT context;
    HAMSISESSION session;
    AMSI_RESULT resultAmsi;
    HRESULT hr;

    // Init AMSI
    hr = AmsiInitialize(L"LoukoumAV", &context);
    if (FAILED(hr)) {
    switch (hr) {
        case E_NOINTERFACE:
            fprintf(stderr, "AMSI: aucun provider disponible\n");
            break;
        case E_ACCESSDENIED:
            fprintf(stderr, "AMSI: accès refusé\n");
            break;
        case E_OUTOFMEMORY:
            fprintf(stderr, "AMSI: mémoire insuffisante\n");
            break;
        default:
            fprintf(stderr, "AMSI indisponible (HRESULT: 0x%08X)\n", hr);
    }
        return 1;
    }
    
    fprintf(stdout, "AMSI successfully initialized\n");
    // Ouvrir session
    hr = AmsiOpenSession(context, &session);
    if (FAILED(hr)) {
        AmsiUninitialize(context);
        return 1;
    }

    // Scanner
    hr = AmsiScanBuffer(context, data, (ULONG)size, L"filename", session, &resultAmsi);
    if (FAILED(hr)) {
        AmsiCloseSession(context, session);
        AmsiUninitialize(context);
        return 1;
    }

    // Stocker le résultat
    if (AmsiResultIsMalware(resultAmsi)) {
        result->amsiDetected = resultAmsi;
    }

    // Cleanup
    AmsiCloseSession(context, session);
    AmsiUninitialize(context);
    return 0;
}
