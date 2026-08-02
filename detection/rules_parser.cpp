#include <tinyxml2.h>
#include <string.h>
#include <stdio.h>

#include "rules_parser.h"
#include "utils/etw_helper.h"


extern "C" int Rules_LoadFromFile(const char *path, SysmonRules *out) {
    tinyxml2::XMLDocument doc; // conflict with msxml.h for windows.h
    if (doc.LoadFile(path) != tinyxml2::XML_SUCCESS) {
        return -1;
    }
    
    out->ruleCount = 0;
    
    tinyxml2::XMLElement *sysmon = doc.FirstChildElement("Sysmon");
    if (!sysmon) return -1;
    
    tinyxml2::XMLElement *filtering = sysmon->FirstChildElement("EventFiltering");
    if (!filtering) return -1;
    
    // Parcourir chaque RuleGroup
    for (tinyxml2::XMLElement *group = filtering->FirstChildElement("RuleGroup"); 
         group != nullptr; 
         group = group->NextSiblingElement("RuleGroup")) {
        
        const char *groupName = group->Attribute("name");
        
        // Parcourir chaque ProcessCreate dans le groupe
        for (tinyxml2::XMLElement *pc = group->FirstChildElement("ProcessCreate"); 
             pc != nullptr; 
             pc = pc->NextSiblingElement("ProcessCreate")) {
            
            if (out->ruleCount >= 256) return 0;
            
            SysmonRule *rule = &out->rules[out->ruleCount];
            rule->type = RULE_PROCESS_CREATE;
            strncpy(rule->groupName, groupName ? groupName : "", 127);
            
            const char *onMatch = pc->Attribute("onmatch");
            rule->onMatch = (onMatch && strcmp(onMatch, "include") == 0) ? 1 : 0;
            rule->conditionCount = 0;
            
            // Parcourir chaque enfant (ParentImage, Image, CommandLine, etc.)
            for (tinyxml2::XMLElement *cond = pc->FirstChildElement(); 
                 cond != nullptr; 
                 cond = cond->NextSiblingElement()) {
                
                if (rule->conditionCount >= 16) break;
                
                RuleCondition *rc = &rule->conditions[rule->conditionCount];
                strncpy(rc->field, cond->Name(), 63);
                
                const char *conditionAttr = cond->Attribute("condition");
                strncpy(rc->condition, conditionAttr ? conditionAttr : "is", 31);
                
                const char *value = cond->GetText();
                strncpy(rc->value, value ? value : "", 511);
                
                const char *sevAttr = group->Attribute("severity");
                rule->severity = sevAttr ? atoi(sevAttr) : 50;

                rule->conditionCount++;
            }
            
            out->ruleCount++;
        }
    }
    
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