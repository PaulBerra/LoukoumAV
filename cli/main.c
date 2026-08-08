// Interface ligne de commande
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils/hash.h"
#include "analysis/static/signature.h"
#include "detection/heuristic.h"
#include "utils/config.h"
#include "core/scanner.h"
#include "core/report.h"
#include "core/service.h"
#include "utils/logger.h"

int main(int argc, char *argv[]) {
    /*
    Entry point of the antivirus CLI.
    Commands :
        scan <filepath>  - scan a single file (CLI mode)
        install          - register the AV as a Windows service
        uninstall        - remove the Windows service
        run              - internal command called by the SCM
    */

    LogLevel min_level = LOG_LEVEL_INFO;
    int v_count = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] == 'v') {
            int valid = 1;
            for (int j = 1; argv[i][j] != '\0'; j++) {
                if (argv[i][j] != 'v') {
                    valid = 0;
                    break;
                }
            }
            if (valid) {
                v_count += (int)strlen(argv[i]) - 1;
            }
        } else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
            min_level = LOG_LEVEL_WARN;
        }
    }

    if (v_count == 1) {
        min_level = LOG_LEVEL_DEBUG;
    } else if (v_count >= 2) {
        min_level = LOG_LEVEL_TRACE;
    }

    if (logger_init(SERVICE_LOGFILE, min_level) != 0) {
        fprintf(stderr, "Critical Error : Can't initialize logger.\n");
        return EXIT_FAILURE;
    }

    if (argc < 2 || (strcmp(argv[1], "scan") != 0
              && strcmp(argv[1], "install") != 0
              && strcmp(argv[1], "uninstall") != 0
              && strcmp(argv[1], "run") != 0))
    {
        fprintf(stderr, "Invalid command.\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s scan <filepath>\n", argv[0]);
        fprintf(stderr, "  %s install\n", argv[0]);
        fprintf(stderr, "  %s uninstall\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "install") == 0) {
        return Service_Install();
    }

    if (strcmp(argv[1], "uninstall") == 0) {
        return Service_Uninstall();
    }

    if (strcmp(argv[1], "run") == 0) {
        return Service_Run();
    }

    if (strcmp(argv[1], "scan") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s scan <filepath>\n", argv[0]);
            return EXIT_FAILURE;
        }

        const char *filePath = argv[2];
        printf("Processing file: %s\n", filePath);

        ScanResult result = {0};
        int score = Scanner_ScanFile(filePath, &result);

        if (score > 70) {
            printf("malware !!\n dangerosite estimee : %d%%\n", score);
        } else if (score > 50) {
            printf("potentiel malware !!\n dangerosite estimee : %d%%\n", score);
        } else {
            printf("fichier propre\n dangerosite estimee : %d%%\n", score);
        }

        printf("Generation du rapport...\n");
        Report_Generate(filePath, &result, score, "report.json");

        return EXIT_SUCCESS;
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    logger_close();
    return EXIT_FAILURE;
}