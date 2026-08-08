# LoukoumAV

A small educativ project to understand how an AV work.

<img width="2816" height="1536" alt="logo" src="https://github.com/user-attachments/assets/994f77d8-c577-4f31-bd69-b24847a5fc98" />

## Features

**Scan statique (CLI)**
- SHA256 lookup contre une base CSV de hashes
- Analyse PE (validation, entropie des sections, imports suspects)
- Détection de chaînes suspectes (URLs, cmd, registry)
- Règles YARA
- Second avis via AMSI (Defender)
- Rapport JSON

**Monitoring temps réel (service Windows)**
- Consumer ETW pour capturer les créations de processus
- Moteur de règles au format Sysmon XML
- Scoring dynamique par processus (accumulation au fil du temps)

**Provider AMSI (DLL COM)**
- Enregistré comme provider AMSI (non-signé, donc non appelé par Windows)

## Architecture

```
cli/main.c Point d'entrée (scan / install / uninstall / run)

core/
 scanner.c Pipeline de scan statique d'un fichier
 engine.c Orchestrateur des événements runtime
 service.c Service Windows (install, run, stop)
 report.c Génération rapport JSON

analysis/static/
 signature.c Lookup hash CSV
 pe_parser.c Parsing PE, entropie, imports
 strings_extract.c Extraction chaînes suspectes
 yara_engine.c Intégration libyara

detection/
 heuristic.c Scoring statique (fichier)
 rules_parser.cpp Parser XML Sysmon (tinyxml2)

monitor/
 etw.c Consumer ETW
 amsi.c Provider AMSI (DLL)
 amsi_client.c Client AMSI
 dynamic_scoring.c Scoring runtime par PID
 handlers/
  handler_kernel_process.c

utils/
 hash.c SHA256 via mbedTLS
 config.h Chemins, seuils, patterns
```


## Build

```
cd build
cmake ..
cmake --build . --config Release
```

Dépendances (vcpkg) : mbedtls, yara, cjson, tinyxml2.

```
# Installation de vcpkg
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat

# Installation des dépendances
C:\vcpkg\vcpkg install mbedtls:x64-windows-static
C:\vcpkg\vcpkg install yara:x64-windows-static
C:\vcpkg\vcpkg install cjson:x64-windows-static
C:\vcpkg\vcpkg install tinyxml2:x64-windows-static
C:\vcpkg\vcpkg install pthread:x64-windows-static
```

## Usage

```
loukoumav.exe scan <fichier> # scan CLI
loukoumav.exe install # enregistre le service (admin)
loukoumav.exe uninstall # supprime le service (admin)
Start-Service LoukoumAV # démarre le monitoring
```

## Fichiers de règles

- `rules/signatures/hashes.csv` — hashes malveillants connus
- `rules/yara/rules.yar` — règles YARA
- `rules/sysmon/rules.xml` — règles composites Sysmon

## TODO

```
# TODO

## Améliorations moteur ETW
- [ ] Récupérer le ParentProcess pour matcher les règles Sysmon "winword.exe → powershell.exe"
- [ ] Ignorer les processus système signés Microsoft pour réduire le bruit
- [ ] Gérer les OpenProcess qui échouent (retry, fallback PROCESS_QUERY_INFORMATION)

## Handlers ETW supplémentaires
- [ ] handler_file.c (créations/modifications de fichiers)
- [ ] handler_network.c (connexions sortantes)
- [ ] handler_registry.c (modifications registre)

## Corrélation temporelle
- [ ] Utiliser g_state.history pour les règles séquentielles
- [ ] Règles composites type "PROCESS_START + MEMORY_RWX + CREATE_REMOTE_THREAD en 5s"
- [ ] Fenêtre temporelle configurable par règle

## Actions sur alerte
- [ ] Kill du processus au-dessus d'un seuil
- [ ] Quarantaine du binaire
- [ ] Notification (event log Windows, webhook)

## Règles
- [ ] Charger de vraies règles publiques (SwiftOnSecurity, Olaf Hartong)
- [ ] Support des conditions Sysmon manquantes (regex, wildcards, image path)
- [ ] Groupement OR/AND

## Provider AMSI
- [ ] Implémenter la logique Scan complète (brancher Scanner_ScanFile)

## Divers
- [ ] Retirer les logs debug de production
- [ ] Chemin d'installation propre (Program Files, pas C:\Antivirus_loukoum)
- [ ] Script d'installation MSI
- [ ] Tests unitaires
- [ ] Mode verbose CLI
```

run debug (not for you | DEV ) : 

```
cls; del service.log; cd build; cmake --build . --config Release; cd ..; C:\Antivirus_loukoum\build\Release\loukoumav.exe uninstall; sleep(5); C:\Antivirus_loukoum\build\Release\loukoumav.exe install; sleep(5); Start-Service LoukoumAV
```
