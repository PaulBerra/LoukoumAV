// Point d'entrée scan fichier/dossier


#ifndef ETW_H
#define ETW_H

#include <stdint.h>
#include <amsi.h>
#include <guiddef.h>
#include <evntcons.h>
#include <objbase.h>
#include <stdio.h>

#include "utils/config.h"
#include "handlers/handler_kernel_process.h"
#include "handlers/handler_threat_intel.h"
#include "handlers/handler_powershell.h"

#include "core/service.h"

int ETW_Start(void);
int ETW_Stop(void);

#endif