# A small educativ project to understand how an AV work.

compil (internal note) : cl.exe cli/main.c utils/hash.c analysis/static/signature.c analysis/static/pe_parser.c detection/heuristic.c core/scanner.c /I"." /I"C:\vcpkg\installed\x64-windows-static\include" /D_WIN64 /link C:\vcpkg\installed\x64-windows-static\lib\mbedcrypto.lib