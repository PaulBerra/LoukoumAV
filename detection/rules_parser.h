// rules_parser.h
typedef enum {
    RULE_PROCESS_CREATE,
    RULE_FILE_CREATE,
    RULE_NETWORK_CONNECT,
    // ...
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
    SysmonRule rules[256];
    int ruleCount;
} SysmonRules;

typedef struct {
    const char *name;
    const char *value;
} EventField;



// API C
#ifdef __cplusplus
extern "C" {
#endif

int Rules_LoadFromFile(const char *path, SysmonRules *out);
int Rules_MatchEvent(const SysmonRules *rules, RuleType type,const EventField *fields, int fieldCount);

#ifdef __cplusplus
}
#endif