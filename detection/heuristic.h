// Moteur heuristique + scoring

#ifndef HEURISTIC_H
#define HEURISTIC_H

#include <stdint.h>

typedef struct ScanResult {

    /*
    Stores the results of a file scan across all analysis modules.
    Passed by pointer to each analysis function which fills in its relevant fields.
    Final score is computed by computeScore().
    */

    double entropy;
    int suspiciousImports;
    int suspiciousSections;
    int invalidPEHeader;
    int signatureMatch;
    char detectedImports[32][64];
    int detectedImportCount;
    char yaraMatches[16][128];
    int yaraMatchCount;
    int amsiDetected;
} ScanResult;

int computeScore(const ScanResult *result);

#endif