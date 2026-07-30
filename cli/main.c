// Interface ligne de commande
// cl.exe cli/main.c utils/hash.c analysis/static/signature.c /I"." /I"C:\vcpkg\installed\x64-windows-static\include" /link C:\vcpkg\installed\x64-windows-static\lib\mbedcrypto.lib
#include <stdio.h>
#include <stdlib.h>
#include "utils/hash.h"
#include "analysis/static/signature.h"
#include "detection/heuristic.h"
#include "utils/config.h"
#include "core/scanner.h"


int main(int argc, char *argv[]) {
    /*
    Entry point of the antivirus CLI.
    Inputs  : argc - number of command line arguments
            argv - array of command line argument strings
            argv[1] - path to the file to scan
    Outputs : EXIT_SUCCESS if scan completed
            EXIT_FAILURE if arguments are missing or scan failed
    Actions : validates arguments, calls Scanner_ScanFile,
            displays threat score and verdict to stdout
    */

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filePath = argv[1];
    printf("Processing file: %s\n", filePath);

    ScanResult result = {0};

    int score = Scanner_ScanFile(filePath, &result);

    if (score > 70) {
        printf("malware !!\n dangerosité estimée : %d%%\n", score);
    } else if (score > 50) {
        printf("potentiel malware !!\n dangerosité estimée : %d%%\n", score);
    } else {
        printf("fichier propre\n dangerosité estimée : %d%%\n", score);
    }

    return EXIT_SUCCESS;
}