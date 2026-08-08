#ifndef HANDLER_POWERSHELL_H
#define HANDLER_POWERSHELL_H

#include <windows.h>
#include <evntcons.h>
#include <stdio.h>
#include "utils/config.h"
#include "utils/etw_helper.h"

void Handler_PowerShell(PEVENT_RECORD event);

#endif