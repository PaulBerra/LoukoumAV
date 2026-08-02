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

    if (result->suspiciousSections > 2) {
        score = score + 40;
    }

    if (result->entropy >= 7.1) {
        score = score + 30;
    }

    if (result->detectedImportCount > 0 && result->detectedImportCount <= 2) {
        score += 15;
    }

    if (result->detectedImportCount > 2 &&  result->detectedImportCount < 4) {
        score = score + 50;
    }

    if (result->detectedImportCount > 5 ) {
        score = score + 100;
    }

    if (result->yaraMatchCount > 0) {
    score += 30 * result->yaraMatchCount;
    }

    if (result->amsiDetected >= 32768) score += 100;  // detected
    else if (result->amsiDetected >= 16384) score += 40;  // blocked by admin


    return score;
}