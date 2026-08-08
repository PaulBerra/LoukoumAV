// Fichier de config (JSON/INI)

#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>

#define ALERT_THRESHOLD 60
#define ENTROPY_THRESHOLD 7.1
#define CSV_PATH "C:\\Antivirus_loukoum\\rules\\signatures\\hashes.csv"
#define RULEPATH "C:\\Antivirus_loukoum\\rules\\yara\\rules.yar"
#define MAX_SCORE 70
#define SERVICE_PATH L"\"C:\\Antivirus_loukoum\\build\\Release\\loukoumav.exe\" run"
#define SERVICE_NAME L"LoukoumAV"
#define SERVICE_DISPLAY_NAME L"Loukoum AntiVirus"
#define SERVICE_LOGFILE "C:\\Antivirus_loukoum\\service.log"
#define RULES_DIR "C:\\Antivirus_loukoum\\rules\\sysmon\\"
#define MITRE_CSV_PATH "C:\\Antivirus_loukoum\\rules\\sysmon\\mitre_severity.csv"
#define MAX_RULES 8192
#define POWERSHELL_SCRIPTLOGGING_LOGFILE "C:\\Antivirus_loukoum\\service_powershell.log"
#define MAX_SCRIPT_SIZE 32768

static const char *SUSPICIOUS_IMPORTS[] = {
    "VirtualAlloc", "VirtualProtect",
    "WriteProcessMemory", "CreateRemoteThread",
    "LoadLibrary", "GetProcAddress",
    NULL
};

static const char *PATTERNS[] = {
    "http://", "https://",
    "cmd.exe", "powershell",
    "HKEY_", "%%APPDATA%%",
    NULL
};

#endif