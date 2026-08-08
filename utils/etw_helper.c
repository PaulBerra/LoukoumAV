#include "etw_helper.h"


int Etw_GetPropertyUInt32(PEVENT_RECORD event, LPCWSTR propertyName, uint32_t *out) {
    PROPERTY_DATA_DESCRIPTOR desc = {0};
    desc.PropertyName = (ULONGLONG)propertyName;
    desc.ArrayIndex = ULONG_MAX;
    
    ULONG size = 0;
    if (TdhGetPropertySize(event, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS) return -1;
    if (size != sizeof(uint32_t)) return -1;
    
    if (TdhGetProperty(event, 0, NULL, 1, &desc, size, (PBYTE)out) != ERROR_SUCCESS) return -1;
    return 0;
}

int Etw_GetPropertyString(PEVENT_RECORD event, LPCWSTR propertyName, char *out, size_t outSize) {
    PROPERTY_DATA_DESCRIPTOR desc = {0};
    desc.PropertyName = (ULONGLONG)propertyName;
    desc.ArrayIndex = ULONG_MAX;
    
    ULONG size = 0;
    if (TdhGetPropertySize(event, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS) return -1;
    
    // Allouer temporairement pour le WCHAR*
    WCHAR *tmp = (WCHAR*)malloc(size);
    if (!tmp) return -1;
    
    if (TdhGetProperty(event, 0, NULL, 1, &desc, size, (PBYTE)tmp) != ERROR_SUCCESS) {
        free(tmp);
        return -1;
    }
    
    // Convertir wide → ansi
    WideCharToMultiByte(CP_ACP, 0, tmp, -1, out, (int)outSize, NULL, NULL);
    free(tmp);
    return 0;
}

int psh_GetScriptBlockDetails(PEVENT_RECORD event, char *out, size_t outSize) {
    if (!out || outSize == 0) return -1;
    out[0] = '\0';

    // Validation : l'ID 4104 correspond au Script Block Logging
    if (event->EventHeader.EventDescriptor.Id != 4104) {
        return -1;
    }

    char path[MAX_PATH] = {0};
    Etw_GetPropertyString(event, L"Path", path, sizeof(path));

    if (path[0] != '\0') {
        char scriptBuffer[8192] = {0}; 
        
        if (Etw_GetPropertyString(event, L"ScriptBlockText", scriptBuffer, sizeof(scriptBuffer)) == 0) {
            snprintf(out, outSize, "[File: %s]\n%s", path, scriptBuffer);
            return 0;
        }
    } else {
        // Exécution en mémoire (dropper, Invoke-Expression, etc.) : écriture directe
        return Etw_GetPropertyString(event, L"ScriptBlockText", out, outSize);
    }

    return -1;
}