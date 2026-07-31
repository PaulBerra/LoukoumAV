// Parsing PE header, entropie, imports
#include <windows.h>
#include <stdint.h>
#include <math.h>
#include "detection/heuristic.h"
#include <windows.h>
#include "utils/config.h"


static uint32_t  RvaToOffset(uint32_t rva, IMAGE_SECTION_HEADER *sections, int numSections) {
    for (int i = 0; i < numSections; i++)
        if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + sections[i].SizeOfRawData) {
            uint32_t offset = rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
            return offset;
        }
    return -1;
}

// Valider le header PE (MZ + PE\0\0)
int PE_IsValid(uint8_t *data, size_t size) {
    /*
    
    Parse le PE header pour vérifier si le fichier est un exécutable valide.
    Parse the PE header to check if the file is a valid executable.

    */
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER*)data;
    if (dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) {
        return -1;
    }

    IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS*)(data + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return -1;
    }
    return 0;
}

// Extraire les noms des sections + leur entropie -> scanResult
int PE_ParseSections(uint8_t *data, size_t size, ScanResult *result){

    /*
    
    Parse la table des sections du PE header pour extraire les noms des sections et calculer leur entropie.
    Parse the section table of the PE header to extract section names and calculate their entropy.

    */
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER*)data;
    if (dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) {
        return -1;
    }

    IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS*)(data + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return -1;
    }

    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        char sectionName[9] = {0};
        memcpy(sectionName, sections[i].Name, 8);

        if (sections[i].PointerToRawData + sections[i].SizeOfRawData > size) {
            continue;
        }
        unsigned long OffsetInFile = sections[i].PointerToRawData;
        unsigned long SizeOfRawData = sections[i].SizeOfRawData;

        int freq[256] = {0};
        for (int j = 0; j < SizeOfRawData; j++) {
            freq[data[OffsetInFile + j]]++;
        }

        double entropy = 0.0;
        for (int j = 0; j < 256; j++) {
            if (freq[j] > 0) {
                double p = (double)freq[j] / SizeOfRawData;
                entropy -= p * log2(p);
            }
        }
        if (entropy > result->entropy) {
            result->entropy = entropy;
        }
        printf("Section: %s, Entropy: %.4f\n", sectionName, entropy);
    }
    return 0;
}

// Extraire les imports
int PE_ParseImports(uint8_t *data, size_t size, ScanResult *result) {

    /*
    Parses the import table of a PE file and detects suspicious API calls.
    Inputs  : data   - pointer to the file buffer
            size   - size of the buffer in bytes
            result - pointer to a ScanResult struct to fill
    Outputs : 0 on success, -1 on error
    Actions : iterates over IMAGE_IMPORT_DESCRIPTOR entries,
            resolves DLL and function names via RVA-to-offset conversion,
            compares each import against a list of suspicious API calls,
            stores matches in result->detectedImports and increments
            result->detectedImportCount
    */
   
    //printf("DEBUG: entering PE_ParseImports\n");
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER*)data;
    if (dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) {
        return -1;
    }

    IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS*)(data + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return -1;
    }

    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(ntHeaders);

    uint32_t importOffset  = RvaToOffset(importDir.VirtualAddress, sections, ntHeaders->FileHeader.NumberOfSections);
    //printf("DEBUG: importOffset = %u\n", importOffset);
    if (importOffset == -1) {
        return -1;
    }
    IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(data + importOffset);
    
    
    while(importDesc->Name != 0) {
        uint32_t nameOffset  = RvaToOffset(importDesc->Name, sections, ntHeaders->FileHeader.NumberOfSections);
        //printf("DEBUG: nameOffset = %u\n", nameOffset);

        char *dllName = (char*)(data + nameOffset);
        //printf("DEBUG: DLL loop, name RVA = %u\n", importDesc->Name);

        uint32_t thunkOffset = RvaToOffset(importDesc->OriginalFirstThunk, sections, ntHeaders->FileHeader.NumberOfSections);
        //printf("DEBUG: thunkOffset = %u\n", thunkOffset);
        if (thunkOffset == -1) {
                importDesc++;
                continue;  // passe à la DLL suivante au lieu de crash
        }
        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA*)(data + thunkOffset);
        
        while (thunk->u1.AddressOfData != 0) {
            //printf("DEBUG: thunk AddressOfData = %llu\n", thunk->u1.AddressOfData);
            // accéder au nom de la fonction
            uint32_t funcOffset = RvaToOffset(thunk->u1.AddressOfData, sections, ntHeaders->FileHeader.NumberOfSections);
            IMAGE_IMPORT_BY_NAME *funcName = (IMAGE_IMPORT_BY_NAME*)(data + funcOffset);
            //printf("  -> %s\n", funcName->Name);

            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // import par ordinal, on skip
                thunk++;
                continue;
            }

            for (int i=0; SUSPICIOUS_IMPORTS[i] != NULL; i++) {
                if (strcmp(funcName->Name, SUSPICIOUS_IMPORTS[i]) == 0) {
                    //printf(" \n\n\nSupicious import detected : %s", funcName->Name);
                    if (result->detectedImportCount < 32) {
                        strncpy(result->detectedImports[result->detectedImportCount], funcName->Name, 63);
                        result->detectedImports[result->detectedImportCount][63] = '\0';
                        result->detectedImportCount++;
                        }
                    }
            }
            thunk++;
        }
        importDesc++;
    }
    //printf("DEBUG: end of PE_ParseImports\n");
    return 0;
}


