#include "handler_powershell.h"



void Handler_PowerShell(PEVENT_RECORD event) {
    // Buffer pour stocker le contenu réel du script récupéré
    char scriptBuffer[MAX_SCRIPT_SIZE] = {0}; 
    
    // Appel avec un buffer valide pour extraire les données
    int status = psh_GetScriptBlockDetails(event, scriptBuffer, sizeof(scriptBuffer));
    
    FILE *f = fopen(POWERSHELL_SCRIPTLOGGING_LOGFILE, "a");
    if (f) { 
        if (status == 0) {
            // Succès : C'est un Event 4104 et le texte a été extrait
            fprintf(f, "PS EVENT: id=%d\n%s\n", event->EventHeader.EventDescriptor.Id, scriptBuffer); 
            fprintf(f, "----------------------------------------\n");
        } else {
            // Échec ou événement non pertinent (ex: ID différent de 4104)
            fprintf(f, "PS EVENT: id=%d\nScript detail: not available\n", event->EventHeader.EventDescriptor.Id); 
            fprintf(f, "----------------------------------------\n");
        }
        fclose(f); 
    }
}