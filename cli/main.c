// Interface ligne de commande

#include <stdio.h>
#include <stdlib.h>
#include "utils/hash.h"

int main(int argc, char *argv[]) {
    // Vérification du nombre d'arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filePath = argv[1];
    printf("Processing file: %s\n", filePath);


    uint8_t *fileData = NULL;
    size_t fileSize = 0;

    if (ReadFileBytes(filePath, &fileData, &fileSize) != 0) {
        fprintf(stderr, "Failed to read file: %s\n", filePath);
        return EXIT_FAILURE;
    }

    uint8_t hashOutput[65] = {0}; // 64 characters for SHA256 in hex + null terminator
    
    if (ComputeHash(fileData, fileSize, "SHA256", hashOutput, sizeof(hashOutput)) != 0) {
        fprintf(stderr, "Failed to compute hash for file: %s\n", filePath);
        free(fileData);
        return EXIT_FAILURE;
    }

    printf("SHA256 Hash: %s\n", hashOutput);

    free(fileData);

    return EXIT_SUCCESS;
}