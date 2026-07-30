// Interface ligne de commande
// cl.exe cli/main.c utils/hash.c analysis/static/signature.c /I"." /I"C:\vcpkg\installed\x64-windows-static\include" /link C:\vcpkg\installed\x64-windows-static\lib\mbedcrypto.lib
#include <stdio.h>
#include <stdlib.h>
#include "utils/hash.h"
#include "analysis/static/signature.h"
#include "detection/heuristic.h"
#include "utils/config.h"



int main(int argc, char *argv[]) {
    // Vérification du nombre d'arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filePath = argv[1];
    printf("Processing file: %s\n", filePath);

    ScanResult result = {0};


    uint8_t *fileData = NULL;
    size_t fileSize = 0;

    if (ReadFileBytes(filePath, &fileData, &fileSize) != 0) {
        fprintf(stderr, "Failed to read file: %s\n", filePath);
        return EXIT_FAILURE;
    }

    if (PE_IsValid(fileData, fileSize) != 0) { // et que c'est un exe
        fprintf(stderr, "Invalid PE file: %s\n", filePath);
        free(fileData);
        return EXIT_FAILURE;
    }
    printf("Valid PE file: %s\n", filePath);

    if (PE_ParseSections(fileData, fileSize, &result) != 0) {
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

    if (loadCSV(CSV_PATH, &signatures, &signatureCount) != 0) {
        fprintf(stderr, "Failed to load signatures\n");
        free(fileData);
        return EXIT_FAILURE;
    }

    result.signatureMatch = lookupHash((const char*)hashOutput, signatures, signatureCount) ? 1 : 0;

    int score = computeScore(&result);


    if (score > 70) {
        printf("\n\n\nVerdict : \n");
        printf("Malware detected in %s\n", filePath);
    }
    else {
        printf("\n\n\nVerdict : \n");
        printf("%s look clean.\n", filePath);
    }

    free(fileData);
    free(signatures);

    return EXIT_SUCCESS;
}