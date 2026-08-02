// Point d'entrée scan fichier/dossier
#ifndef HANDLER_THREAT_INTEL_H
#define HANDLER_THREAT_INTEL_H

#include <windows.h>
#include <evntcons.h>
#include <stdio.h>

#include "utils/config.h"
#include "core/scanner.h"
#include "utils/etw_helper.h"
#include "core/engine.h"

void Handler_ThreatIntel(PEVENT_RECORD event);

#endif

