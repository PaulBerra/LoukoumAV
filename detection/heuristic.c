// Moteur heuristique + scoring
#include "heuristic.h"

int computeScore(const ScanResult *result) {
    /*
    Computes a threat score based on the collected scan results.
    Inputs  : pointer to a filled ScanResult struct
    Outputs : integer score (0 = clean, 100+ = likely malware)
    Actions : weights each indicator and returns the cumulative score
            - signature match : +100
            - suspicious imports (1-3) : +60
            - suspicious imports (>3)  : +100
            - suspicious sections (>2) : +40
            - high entropy (>= 7.1)    : +30
    */
   
    int score = 0;

    if (result->signatureMatch > 0) {
        score = score + 100;
    }

    //if (result->invalidPEHeader) //inutile on a un exit failure si pas ok 

    if (result->suspiciousImports > 1 && result->suspiciousImports <= 3){
        score = score + 60;
    }
    if (result->suspiciousImports > 3 ) {
        score = score + 100;
    }

    if (result->suspiciousSections > 2) {
        score = score + 40;
    }

    if (result->entropy >= 7.1) {
        score = score + 30;
    }
    return score;
}