rule TestRule {
    strings:
        $s1 = "MZ"
        $s2 = "This program"
    condition:
        all of them
}