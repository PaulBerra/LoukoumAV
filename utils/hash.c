// MD5 / SHA256
#include "hash.h"
#include <stdlib.h>
#include <stdio.h>
#include <mbedtls/sha256.h>

int ComputeHash(uint8_t *ptableau, size_t tableauSize, const char* hashType, uint8_t *outHashBuffer, size_t outHashSize) {
    uint8_t hash[32]; // SHA256 produces a 32-byte hash
    int success = mbedtls_sha256(ptableau, tableauSize, hash, 0); // 0 for SHA-256
    if (success != 0) {
        return -1;
    }

    for (int i = 0; i < 32; i++) { // ecris le hash dans outHashBuffer
        sprintf(outHashBuffer + i*2, "%02x", hash[i]);
    }
    return 0;
}

int ReadFileBytes(const char* filename, uint8_t **buffer, size_t* bufferSize) {

    FILE* file = NULL;
    file = fopen(filename, "rb");

    if (!file) {
        perror("Error opening file");
        return -1;
    }

    // aller a la fin du fichier
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    *bufferSize = (size_t)fileSize;

    //allouer un buffer pour lire le fichier
    *buffer = (uint8_t*)malloc(*bufferSize);
    if (*buffer == NULL) {
        perror("Error allocating memory");
        fclose(file);
        return -1;
    }

    size_t itemRead = fread(*buffer, sizeof(uint8_t), *bufferSize, file);
    if (itemRead != *bufferSize) {
        perror("Error reading from file");
        fclose(file);
        free(*buffer);
        *buffer = NULL;
        return -1;
    }
    
    fclose(file);
    return 0;
}
