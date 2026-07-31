// Extraction de chaînes suspectes
#include <stdint.h>
#include "strings_extract.h"
#include <stdio.h>
#include <ctype.h>
#include "utils/config.h"


/*
typedef struct {
    char **strings;      // dynamic strings array
    int count;           // matching strings count
    int capacity;        // allocated capacity
} StringsResult;
*/


StringsResult* StringsResult_Init() {
    StringsResult *stringResultPtr = (StringsResult *)malloc(sizeof(StringsResult));
    if (!stringResultPtr) return NULL;

    stringResultPtr->count = 0;
    stringResultPtr->capacity = 128;

    stringResultPtr->strings = malloc(128 * sizeof(char*));    
    if (!stringResultPtr->strings) {
        free(stringResultPtr);
        return NULL; 
    }
    return stringResultPtr;
}

int ExtractStrings(uint8_t *data, size_t size, StringsResult *result) {
    if (data == NULL) {
        printf("Erreur : buffer NULL.\n");
        return -1;
    }

    size_t start = 0;
    size_t len = 0;
    char potentialMatch[]  = "";
    for (size_t i = 0; i < size; i++) {
        if (isprint(data[i])) {
            if (len == 0) start = i;
            len++;
        } else {
            if (len >= 4) {
                int matched = 0;

                char *candidate = malloc(len + 1);
                if (!candidate) return -1;
                candidate[len] = '\0';
                memcpy(candidate, data + start, len);
                for (int j = 0; PATTERNS[j] != NULL; j++) {

                    if (strstr(candidate, PATTERNS[j]) != NULL) {
                        
                        if (result->count >= result->capacity) {
                            // Resize the array if needed
                            result->capacity *= 2;
                            char **tmp = realloc(result->strings, result->capacity * sizeof(char*));
                            if (!tmp) { free(candidate); return -1; }
                            result->strings = tmp;
                        }
                        
                        result->strings[result->count] = candidate;
                        result->count++;
                        matched = 1;
                        break;
                    }
                }
                if (!matched) free(candidate);
            }
            len = 0;
        }
    }
    return 0;
}