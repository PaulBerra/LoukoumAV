// Moteur heuristique + scoring

#ifndef HEURISTIC_H
#define HEURISTIC_H

#include <stdint.h>

typedef struct ScanResult {
    double entropy;
    int suspiciousImports;
    int suspiciousSections;
    int invalidPEHeader;
    int signatureMatch;
} ScanResult;

int computeScore(const ScanResult *result);

#endif