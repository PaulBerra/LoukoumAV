// Comparaison hash (MD5/SHA256)
#ifndef SIGNATURE_H
#define SIGNATURE_H

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

int loadCSV(const char* filename, SignatureEntry** entries, int* entryCount);

const SignatureEntry* lookupHash(const char* hash, const SignatureEntry* entries, int entryCount);

#endif
