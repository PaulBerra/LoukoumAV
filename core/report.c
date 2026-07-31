// Génération des rapports / logs
#include <stdio.h>
#include "report.h"

int Report_Generate(const char *filePath, const ScanResult *result, int score, const char *outputPath) {
    FILE *f = fopen(outputPath, "w");
    if (!f) return -1;

    fprintf(f, "{\n");
    fprintf(f, "  \"file\": \"%s\",\n", filePath);
    fprintf(f, "  \"score\": %d,\n", score);
    fprintf(f, "  \"entropy_max\": %.4f,\n", result->entropy);
    fprintf(f, "  \"signature_match\": %s,\n", result->signatureMatch ? "true" : "false");

    fprintf(f, "  \"yara_matches\": [");
    for (int i = 0; i < result->yaraMatchCount; i++) {
        fprintf(f, "\"%s\"%s", result->yaraMatches[i], (i < result->yaraMatchCount - 1) ? ", " : "");
    }
    fprintf(f, "],\n");

    fprintf(f, "  \"suspicious_imports\": [");
    for (int i = 0; i < result->detectedImportCount; i++) {
        fprintf(f, "\"%s\"%s", result->detectedImports[i], (i < result->detectedImportCount - 1) ? ", " : "");
    }
    fprintf(f, "]\n");

    fprintf(f, "}\n");

    fclose(f);
    return 0;
}