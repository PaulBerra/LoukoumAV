// Extraction de chaînes suspectes

#ifndef STRING_EXTRACT_H
#define STRING_EXTRACT_H

#include <stdint.h>

typedef struct {
    char **strings;      // dynamic strings array
    int count;           // matching strings count
    int capacity;        // allocated capacity
} StringsResult;

// init struct
StringsResult* StringsResult_Init();

int ExtractStrings(uint8_t *data, size_t size, StringsResult *result);

#endif