// Comparaison hash (MD5/SHA256)
#ifndef SIGNATURE_H
#define SIGNATURE_H

typedef struct {
    char hash[65];      // SHA256 hex + \0
    char malwareName[128];  // nom du malware
} SignatureEntry;

int loadCSV(const char* filename, SignatureEntry** entries, int* entryCount);

const SignatureEntry* lookupHash(const char* hash, const SignatureEntry* entries, int entryCount);

#endif
