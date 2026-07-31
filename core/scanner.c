// Point d'entrée scan fichier/dossier
#include <stdint.h>
#include <windows.h>
#include <stdio.h>

#include "scanner.h"
#include "detection/heuristic.h"
#include "analysis/static/signature.h"
#include "detection/heuristic.h"
#include "utils/hash.h"
#include "utils/config.h"
#include "detection/heuristic.h"

FileType DetectFileType(uint8_t *data, size_t size) {

    /*
    Identifies the type of a file by inspecting its magic bytes.
    Inputs  : data - pointer to the file buffer
              size - size of the buffer in bytes
    Outputs : FileType enum value (FILE_TYPE_PE, FILE_TYPE_PDF, etc.)
              FILE_TYPE_UKNW if the type cannot be determined
    Actions : checks the first 4 bytes against known magic numbers
              and returns the corresponding file type
    */

    if (size < 4 ) return FILE_TYPE_UKNW;

    if (data[0] == 'M' && data[1] == 'Z')                          return FILE_TYPE_PE;
    if (data[0] == '%' && data[1] == 'P')                          return FILE_TYPE_PDF;
    if (data[0] == 'P' && data[1] == 'K')                          return FILE_TYPE_ZIP;
    if (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L')      return FILE_TYPE_ELF;
    if (data[0] == 0xD0 && data[1] == 0xCF)                        return FILE_TYPE_DOC;
    if (data[0] == 0x37 && data[1] == 0x7A)                        return FILE_TYPE_7ZIP;
    if (data[0] == 0xFF && data[1] == 0xD8)                        return FILE_TYPE_JPEG;
    if (data[0] == 0x89 && data[1] == 'P' && data[2] == 'N')      return FILE_TYPE_PNG;

    return FILE_TYPE_UKNW;

}


int Scanner_ScanFile(const char* filePath, ScanResult *result) {

    /*
    Orchestrates the full scan pipeline for a given file.
    Inputs  : filePath - path to the file to scan
            result   - pointer to a ScanResult struct to fill
    Outputs : cumulative threat score (0 = clean, 100+ = likely malware)
            -1 on error
    Actions : reads file into memory, computes SHA256 hash, checks signature DB,
            detects file type, routes to appropriate parsers (PE sections, imports),
            computes and returns heuristic score
    */

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

    printf("SHA256 Hash en cours de traitement: %s\n file: %s \n", hashOutput, filePath);

    SignatureEntry *signatures = NULL;
    int signatureCount = 0;

    if (loadCSV(CSV_PATH, &signatures, &signatureCount) != 0) {
        fprintf(stderr, "Failed to load signatures\n");
        free(fileData);
        return EXIT_FAILURE;
    }
    result->signatureMatch = lookupHash((const char*)hashOutput, signatures, signatureCount) ? 1 : 0;


    FileType file = DetectFileType(fileData, fileSize);
    switch (file) {
        case FILE_TYPE_PE:
            if (PE_IsValid(fileData, fileSize) != 0) {
                free(fileData);
                free(signatures);
                return -1;
            }
            if (PE_ParseSections(fileData, fileSize, result) != 0) {
                free(fileData);
                free(signatures);
                return -1;
            }
            if (PE_ParseImports(fileData, fileSize, result) != 0) {
                free(fileData);
                free(signatures);
                return -1;
            }
            break;
        case FILE_TYPE_PDF:

            break;
        case FILE_TYPE_ZIP:

            break;
        case FILE_TYPE_ELF:

            break;
        case FILE_TYPE_DOC:

            break;
        case FILE_TYPE_7ZIP:

            break;
        case FILE_TYPE_JPEG:

            break;
        case FILE_TYPE_PNG:

            break;
        case FILE_TYPE_UKNW:

            break;
        default:
            break;
    }

    int score = computeScore(result);

    free(fileData);
    free(signatures);

    return score;
}