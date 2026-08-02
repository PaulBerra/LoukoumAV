cmake_minimum_required(VERSION 3.15)
project(LoukoumAV C)

set(CMAKE_C_STANDARD 11)
set(VCPKG_ROOT "C:/vcpkg/installed/x64-windows-static")

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${VCPKG_ROOT}/include
)

add_executable(loukoumav
    cli/main.c
    utils/hash.c
    analysis/static/signature.c
    analysis/static/pe_parser.c
    analysis/static/yara_engine.c
    analysis/static/strings_extract.c
    detection/heuristic.c
    core/scanner.c
    core/report.c
    monitor/amsi.c
    monitor/amsi_client.c
    monitor/etw.c
    monitor/handlers/handler_kernel_process.c
    core/service.c
)

target_link_libraries(loukoumav
    ${VCPKG_ROOT}/lib/mbedcrypto.lib
    ${VCPKG_ROOT}/lib/libyara.lib
    ${VCPKG_ROOT}/lib/libcrypto.lib
    ${VCPKG_ROOT}/lib/libssl.lib
    crypt32
    ws2_32
    advapi32
    user32
    amsi
)

target_compile_definitions(loukoumav PRIVATE _WIN64)