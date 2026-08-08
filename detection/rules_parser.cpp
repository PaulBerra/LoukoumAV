#include <tinyxml2.h>
#include <string.h>
#include <stdio.h>

#include "rules_parser.h"
#include "utils/etw_helper.h"
#include "monitor/handlers/handler_threat_intel.c"
#include "detection/mitre.h"

extern "C" const SysmonEventType SYSMON_EVENT_TYPES[] = {
    {"ProcessCreate", RULE_PROCESS_CREATE},
    {"FileCreateTime", RULE_FILE_CREATE_TIME},
    {"NetworkConnect", RULE_NETWORK_CONNECT},
    {"ProcessTerminate", RULE_PROCESS_TERMINATE},
    {"DriverLoad", RULE_DRIVER_LOAD},
    {"ImageLoad", RULE_IMAGE_LOAD},
    {"CreateRemoteThread", RULE_CREATE_REMOTE_THREAD},
    {"RawAccessRead", RULE_RAW_ACCESS_READ},
    {"ProcessAccess", RULE_PROCESS_ACCESS},
    {"FileCreate", RULE_FILE_CREATE},
    {"RegistryEvent", RULE_REGISTRY_EVENT},
    {"FileCreateStreamHash", RULE_FILE_CREATE_STREAM_HASH},
    {"PipeEvent", RULE_PIPE_EVENT},
    {"WmiEvent", RULE_WMI_EVENT},
    {"DnsQuery", RULE_DNS_QUERY},
    {"FileDelete", RULE_FILE_DELETE},
    {"ClipboardChange", RULE_CLIPBOARD_CHANGE},
    {"ProcessTampering", RULE_PROCESS_TAMPERING},
    {"FileDeleteDetected", RULE_FILE_DELETE_DETECTED},
    {"FileExecutableDetected", RULE_FILE_EXECUTABLE_DETECTED},
};
extern "C" const int SYSMON_EVENT_TYPES_COUNT = sizeof(SYSMON_EVENT_TYPES) / sizeof(SYSMON_EVENT_TYPES[0]);

static int LoadSingleFile(const char *path, SysmonRules *out, const MitreMap *mitre) {
    tinyxml2::XMLDocument doc;
    if (doc.LoadFile(path) != tinyxml2::XML_SUCCESS) {
        return -1;
    }
    
    tinyxml2::XMLElement *sysmon = doc.FirstChildElement("Sysmon");
    if (!sysmon) return -1;
    
    tinyxml2::XMLElement *filtering = sysmon->FirstChildElement("EventFiltering");
    if (!filtering) return -1;
    
    // Extraction de la technique MITRE depuis le nom de fichier (une fois par fichier)
    char technique[16];
    ExtractMitreTechnique(path, technique, sizeof(technique));
    int severity = Mitre_GetSeverity(mitre, technique);
    
    // Parcourir chaque RuleGroup
    for (tinyxml2::XMLElement *group = filtering->FirstChildElement("RuleGroup"); 
         group != nullptr; 
         group = group->NextSiblingElement("RuleGroup")) {
        
        const char *groupName = group->Attribute("name");
        
        // Parcourir chaque type d'event Sysmon supporté
        for (int t = 0; t < SYSMON_EVENT_TYPES_COUNT; t++) {
            const char *xmlName = SYSMON_EVENT_TYPES[t].xmlName;
            RuleType ruleType = SYSMON_EVENT_TYPES[t].type;
            
            for (tinyxml2::XMLElement *evt = group->FirstChildElement(xmlName);
                 evt != nullptr;
                 evt = evt->NextSiblingElement(xmlName)) {
                
                const char *onMatch = evt->Attribute("onmatch");
                int onMatchInt = (onMatch && strcmp(onMatch, "include") == 0) ? 1 : 0;
                
                // Parcourir chaque <Rule> dans l'event
                for (tinyxml2::XMLElement *ruleElem = evt->FirstChildElement("Rule");
                     ruleElem != nullptr;
                     ruleElem = ruleElem->NextSiblingElement("Rule")) {
                    
                    if (out->ruleCount >= MAX_RULES) return 0;
                    
                    SysmonRule *rule = &out->rules[out->ruleCount];
                    rule->type = ruleType;
                    strncpy(rule->groupName, groupName ? groupName : "", 127);
                    rule->severity = severity;
                    rule->onMatch = onMatchInt;
                    rule->conditionCount = 0;
                    
                    for (tinyxml2::XMLElement *cond = ruleElem->FirstChildElement();
                         cond != nullptr;
                         cond = cond->NextSiblingElement()) {
                        
                        if (rule->conditionCount >= 16) break;
                        
                        RuleCondition *rc = &rule->conditions[rule->conditionCount];
                        strncpy(rc->field, cond->Name(), 63);
                        
                        const char *conditionAttr = cond->Attribute("condition");
                        strncpy(rc->condition, conditionAttr ? conditionAttr : "is", 31);
                        
                        const char *value = cond->GetText();
                        strncpy(rc->value, value ? value : "", 511);
                        
                        rule->conditionCount++;
                    }
                    
                    out->ruleCount++;
                }
            }
        }
    }
    
    return 0;
}

extern "C" int Rules_LoadFromDirectory(const char *dirPath, SysmonRules *out, const MitreMap *mitre) {
    // Construire le pattern de recherche : "dirPath\*"
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*", dirPath);
    
    WIN32_FIND_DATAA data;
    HANDLE hFind = FindFirstFileA(pattern, &data);
    if (hFind == INVALID_HANDLE_VALUE) return -1;
    
    do {
        // Ignorer les entrées "." et ".."
        if (strcmp(data.cFileName, ".") == 0 || strcmp(data.cFileName, "..") == 0) {
            continue;
        }
        
        // Construire le chemin complet
        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", dirPath, data.cFileName);
        
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Sous-dossier : récursion
            static MitreMap g_mitre = {0};
            Mitre_LoadFromCSV(MITRE_CSV_PATH, &g_mitre);
            Rules_LoadFromDirectory(fullPath, out, mitre);
        } else {
            // Fichier : vérifier l'extension .xml
            size_t len = strlen(data.cFileName);
            if (len > 4 && _stricmp(data.cFileName + len - 4, ".xml") == 0) {
                LoadSingleFile(fullPath, out, mitre);
            }
        }
    } while (FindNextFileA(hFind, &data));
    
    FindClose(hFind);
    return 0;
}

extern "C" int Rules_MatchEvent(const SysmonRules *rules, RuleType type, const EventField *fields, int fieldCount) {
    for (int i = 0; i < rules->ruleCount; i++) {
        const SysmonRule *rule = &rules->rules[i];
        if (rule->type != type) continue;
        
        int allConditionsMatch = 1;
        
        for (int j = 0; j < rule->conditionCount; j++) {
            const RuleCondition *cond = &rule->conditions[j];
            const char *target = NULL;
            
            // Chercher le champ dans le tableau
            for (int k = 0; k < fieldCount; k++) {
                if (strcmp(cond->field, fields[k].name) == 0) {
                    target = fields[k].value;
                    break;
                }
            }
            
            if (!target) { allConditionsMatch = 0; break; }
            
            int matches = 0;
            if (strcmp(cond->condition, "is") == 0) {
                matches = (_stricmp(target, cond->value) == 0);
            } else if (strcmp(cond->condition, "end with") == 0) {
                size_t tlen = strlen(target);
                size_t vlen = strlen(cond->value);
                matches = (tlen >= vlen && _stricmp(target + tlen - vlen, cond->value) == 0);
            } else if (strcmp(cond->condition, "contains") == 0) {
                matches = (strstr(target, cond->value) != NULL);
            }
            
            if (!matches) { allConditionsMatch = 0; break; }
        }
        
        if (allConditionsMatch) return i;
    }
    return -1;
}
