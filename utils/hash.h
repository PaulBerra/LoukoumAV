// MD5 / SHA256

#ifndef HASH_H
#define HASH_H

#include <stdint.h>


int ReadFileBytes(const char* filename, uint8_t **buffer, size_t *bufferSize);
int ComputeHash(uint8_t *data, size_t dataSize, const char* hashType, uint8_t *outBuffer, size_t outBufferSize);

#endif
