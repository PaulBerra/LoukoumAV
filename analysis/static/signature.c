// Comparaison hash (MD5/SHA256)

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    /* 
    
    Structure pour stocker une signature 
    Structure to store a signature 
    
    hash: SHA256 hash of the malware file in hexadecimal format + null terminator
    malwareName: Name of the malware associated with the hash

    */

    char hash[65];  
    char malwareName[128];
} SignatureEntry;

int loadCSV(const char* filename, SignatureEntry** entries, int* entryCount) {
    /* 

    Charge les signatures à partir d'un fichier CSV
    Load signatures from a CSV file 

    */

    int capacity = 100; // capacité initiale du tableau
    int count = 0; // nombre d'entrées actuellement dans le tableau
    char line[256]; // buffer pour lire les lignes du fichier CSV

    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Error opening CSV file");
        return -1;
    }

    // alloue tableau de signatures, securité pour realloc
    SignatureEntry* tmp = realloc(*entries, capacity * sizeof(SignatureEntry));
    if (!tmp) { free(*entries); fclose(file); return -1;}
    *entries = tmp;

    if (!(*entries)) {
        perror("Error allocating memory");
        fclose(file);
        return -1;
    }

        while (fgets(line, sizeof(line), file) != NULL) {
            if (count >= capacity) {
                // Resize the array if needed
                capacity *= 2;
                *entries = (SignatureEntry*)realloc(*entries, capacity * sizeof(SignatureEntry));
                if (!(*entries)) {
                    perror("Error reallocating memory");
                    fclose(file);
                    return -1;
                }
            }

        // Parse the line to extract hash and malware name
        char* token = strtok(line, ",");
        if (token != NULL) {
            strncpy((*entries)[count].hash, token, sizeof((*entries)[count].hash) - 1);
            (*entries)[count].hash[sizeof((*entries)[count].hash) - 1] = '\0'; // null-terminate
        }

        token = strtok(NULL, ",");
        if (token != NULL) {
            strncpy((*entries)[count].malwareName, token, sizeof((*entries)[count].malwareName) - 1);
            (*entries)[count].malwareName[sizeof((*entries)[count].malwareName) - 1] = '\0'; // null-terminate
        }
            count++;
        }

    *entryCount = count;

    fclose(file);

    return 0;
}

const SignatureEntry* lookupHash(const char* hash, const SignatureEntry* entries, int entryCount) {

    /* 

    Compare la signature du fichier scanné a celles de la base de données 
    Compare the hash of the scanned file with those in the database 
    
    */

    for (int i = 0; i < entryCount; i++) {
        if (strcmp(hash, entries[i].hash) == 0) {
            return &entries[i];
        }
    }
    return NULL;
}
