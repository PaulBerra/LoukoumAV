// core/service.h
#ifndef SERVICE_H
#define SERVICE_H

#include "utils/config.h"

extern HANDLE g_serviceStopEvent;

int Service_Install(void);
int Service_Uninstall(void);
int Service_Run(void);  // appelé par le SCM

#endif