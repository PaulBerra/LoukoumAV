// Moteur heuristique + scoring
#include "heuristic.h"

int computeScore(const ScanResult *result) {

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