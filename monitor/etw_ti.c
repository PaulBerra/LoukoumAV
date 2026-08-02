// Point d'entrée scan fichier/dossier avec ETW-TI
#ifndef ETW_TI_H
#define ETW_TI_H

#include <stdint.h>
#include <amsi.h>
#include <guiddef.h>
#include <evntcons.h>
#include <objbase.h>

#include "utils/config.h"

int ETW_TI_Start(void);
int ETW_TI_Stop(void);

#endif