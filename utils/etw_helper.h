// Extrait un champ nommé d'un event ETW

#ifndef ETW_HELPER_H
#define ETW_HELPER_H

#include <windows.h>
#include <evntcons.h>
#include <stdint.h>
#include <tdh.h>

// Retourne 0 si succès, -1 sinon
int Etw_GetPropertyUInt32(PEVENT_RECORD event, LPCWSTR propertyName, uint32_t *out);
int Etw_GetPropertyString(PEVENT_RECORD event, LPCWSTR propertyName, char *out, size_t outSize);


#endif

