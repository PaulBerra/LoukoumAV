// Point d'entrée scan fichier/dossier


#ifndef ETW_H
#define ETW_H

#include <stdint.h>
#include <amsi.h>
#include <guiddef.h>
#include <evntcons.h>
#include <objbase.h>

#include "utils/config.h"

int ETW_Start(void);
int ETW_Stop(void);

#endif