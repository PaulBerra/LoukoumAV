// Intégration libyara
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <yara.h>
#include "detection/heuristic.h"

static int YaraCallback(YR_SCAN_CONTEXT *context, int message, void *message_data, void *user_data) {
    //printf("DEBUG YARA callback: message=%d\n", message);
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        //printf("DEBUG YARA: MATCH!\n");
        ScanResult *result = (ScanResult*)user_data;
        YR_RULE *rule = (YR_RULE*)message_data;

        if (result->yaraMatchCount < 16) {
            strncpy(result->yaraMatches[result->yaraMatchCount], rule->identifier, 127);
            result->yaraMatchCount++;
        }
    }
    return CALLBACK_CONTINUE;
}

int YARA_ScanBuffer(uint8_t *data, size_t size, const char *rulesPath, ScanResult *result) {
    int success = yr_initialize();
    if (success != 0) {
        printf("Error initializing yara");
        return -1;
    }
    YR_COMPILER *compiler = NULL;
    success = yr_compiler_create(&compiler);
    if (success != 0) {
        return -1;
    }

    FILE* file = fopen(rulesPath, "r");
    if (!file) {
        perror("Error opening CSV file");
        return -1;
    }

    success = yr_compiler_add_file(compiler, file, NULL, rulesPath);
    if (success != 0) {
        yr_compiler_destroy(compiler);
        fclose(file);
        yr_finalize();
        return -1;
    }

    YR_RULES *rules = NULL;
    success = yr_compiler_get_rules(compiler, &rules);
    if (success != 0) {
        printf("YARA : No rules found %s", rulesPath);
        return -1;
    }

    YR_SCANNER *scanner = NULL;
    success = yr_scanner_create(rules, &scanner);
    if (success != 0) {
        return -1;
    }

    yr_scanner_set_callback(scanner, YaraCallback, result);

    success = yr_scanner_scan_mem(scanner, data, size);
    if (success != 0) {
        return -1;
    }

    yr_scanner_destroy(scanner);
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    fclose(file);
    yr_finalize();

    return 0;

}