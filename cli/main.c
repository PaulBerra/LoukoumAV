// Interface ligne de commande
// cl.exe cli/main.c utils/hash.c analysis/static/signature.c /I"." /I"C:\vcpkg\installed\x64-windows-static\include" /link C:\vcpkg\installed\x64-windows-static\lib\mbedcrypto.lib
#include <stdio.h>
#include <stdlib.h>
#include "utils/hash.h"
#include "analysis/static/signature.h"

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

    if (PE_IsValid(fileData, fileSize) != 0) {
        fprintf(stderr, "Invalid PE file: %s\n", filePath);
        free(fileData);
        return EXIT_FAILURE;
    }
    printf("Valid PE file: %s\n", filePath);

    if (PE_ParseSections(fileData, fileSize) != 0) {
        fprintf(stderr, "Failed to parse PE sections for file: %s\n", filePath);
        free(fileData);
        return EXIT_FAILURE;
    }
    printf("PE sections parsed successfully for file: %s\n", filePath);





    uint8_t hashOutput[65] = {0}; // 64 characters for SHA256 in hex + null terminator
    
    if (ComputeHash(fileData, fileSize, "SHA256", hashOutput, sizeof(hashOutput)) != 0) {
        fprintf(stderr, "Failed to compute hash for file: %s\n", filePath);
        free(fileData);
        return EXIT_FAILURE;
    }

    printf("SHA256 Hash en cours de traitement: %s\n file: %s \n", hashOutput, filePath);

    SignatureEntry *signatures = NULL;
    int signatureCount = 0;

    if (loadCSV("rules\\signatures\\hashes.csv", &signatures, &signatureCount) != 0) {
        fprintf(stderr, "Failed to load signatures\n");
        free(fileData);
        return EXIT_FAILURE;
    }

    const SignatureEntry *match = lookupHash((const char*)hashOutput, signatures, signatureCount);
    if (match != NULL) {
        printf("Malware detected: %s\n",match->malwareName);
    } else {
        printf("No malware detected for file: %s\n", filePath);
    }

    free(fileData);
    free(signatures);

    return EXIT_SUCCESS;
}