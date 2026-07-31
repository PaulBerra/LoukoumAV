// Génération des rapports / logs
#ifndef REPORT_H
#define REPORT_H

#include "detection/heuristic.h"

int Report_Generate(const char *filePath, const ScanResult *result, int score, const char *outputPath);

#endif