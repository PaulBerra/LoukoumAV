#ifndef RULES_PARSER_H
#define RULES_PARSER_H

#include "mitre.h"
#include "utils/config.h"

typedef enum {
    RULE_PROCESS_CREATE,
    RULE_FILE_CREATE_TIME,
    RULE_NETWORK_CONNECT,
    RULE_PROCESS_TERMINATE,
    RULE_DRIVER_LOAD,
    RULE_IMAGE_LOAD,
    RULE_CREATE_REMOTE_THREAD,
    RULE_RAW_ACCESS_READ,
    RULE_PROCESS_ACCESS,
    RULE_FILE_CREATE,
    RULE_REGISTRY_EVENT,
    RULE_FILE_CREATE_STREAM_HASH,
    RULE_PIPE_EVENT,
    RULE_WMI_EVENT,
    RULE_DNS_QUERY,
    RULE_FILE_DELETE,
    RULE_CLIPBOARD_CHANGE,
    RULE_PROCESS_TAMPERING,
    RULE_FILE_DELETE_DETECTED,
    RULE_FILE_EXECUTABLE_DETECTED,
} RuleType;

typedef struct {
    char field[64];      // "ParentImage", "Image", etc.
    char condition[32];  // "end with", "contains", "is"
    char value[512];     // "winword.exe"
} RuleCondition;


typedef struct {
    RuleType type;
    char groupName[128];
    RuleCondition conditions[16];
    int conditionCount;
    int onMatch;  // 1 = include, 0 = exclude
    int severity; // 
} SysmonRule;

typedef struct {
    SysmonRule rules[MAX_RULES];
    int ruleCount;
} SysmonRules;

typedef struct {
    const char *name;
    const char *value;
} EventField;





typedef struct {
    const char *xmlName;
    RuleType type;
} SysmonEventType;





// API C
#ifdef __cplusplus
extern "C" {
#endif

extern const SysmonEventType SYSMON_EVENT_TYPES[];
extern const int SYSMON_EVENT_TYPES_COUNT;

int Rules_LoadFromDirectory(const char *dirPath, SysmonRules *out, const MitreMap *mitre);
int Rules_MatchEvent(const SysmonRules *rules, RuleType type,const EventField *fields, int fieldCount);

int Mitre_LoadFromCSV(const char *path, MitreMap *out);
int Mitre_GetSeverity(const MitreMap *map, const char *technique);

#ifdef __cplusplus
}
#endif

#endif