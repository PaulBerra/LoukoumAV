// Parsing PE header, entropie, imports
#include <windows.h>
#include <stdint.h>
#include <math.h>



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

// Extraire les noms des sections + leur entropie
int PE_ParseSections(uint8_t *data, size_t size){

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
        printf("Section: %s, Entropy: %.4f\n", sectionName, entropy);
    }
    return 0;
}

// Extraire les imports
int PE_ParseImports(uint8_t *data, size_t size);
