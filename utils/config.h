// Fichier de config (JSON/INI)

#ifndef CONFIG_H
#define CONFIG_H

#define ALERT_THRESHOLD 60
#define ENTROPY_THRESHOLD 7.1
#define CSV_PATH "rules\\signatures\\hashes.csv"
#define MAX_SCORE 70
#endif

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