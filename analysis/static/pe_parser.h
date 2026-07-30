// Parsing PE header, entropie, imports
#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <stdint.h>


// Valider le header PE (MZ + PE\0\0)
int PE_IsValid(uint8_t *data, size_t size);

// Extraire les noms des sections + leur entropie
int PE_ParseSections(uint8_t *data, size_t size);

// Extraire les imports
int PE_ParseImports(uint8_t *data, size_t size);

#endif