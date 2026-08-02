// Point d'entrée scan fichier/dossier
#ifndef HANDLER_KERNEL_PROCESS_H
#define HANDLER_KERNEL_PROCESS_H

#include <windows.h>
#include <evntcons.h>
#include <stdio.h>

#include "utils/config.h"
#include "core/scanner.h"
void Handler_KernelProcess(PEVENT_RECORD event);

#endif

