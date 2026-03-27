cmake_minimum_required(VERSION 3.16)
project(nos_like VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)          # gnu11 — DPDK uses GNU extensions

# ── Build type default ────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

# ── Output directory ──────────────────────────────────────────────────────────
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ─────────────────────────────────────────────────────────────────────────────
# 1.  Find DPDK via pkg-config
#
#     DPDK ships no CMake config file — pkg-config is the official method.
#     DPDK's cflags include a force-include flag:
#         -include rte_config.h
#     cmake's target_compile_options() passes this through unchanged.
# ─────────────────────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# pkg_check_modules gives us:
#   DPDK_CFLAGS        — compiler flags (includes -include rte_config.h)
#   DPDK_LDFLAGS       — linker flags
#   DPDK_INCLUDE_DIRS  — header directories
#   DPDK_LIBRARIES     — library names for target_link_libraries

# Create an INTERFACE target so all targets share the same DPDK settings
add_library(dpdk_iface INTERFACE)
target_include_directories(dpdk_iface INTERFACE ${DPDK_INCLUDE_DIRS})
target_compile_options(dpdk_iface    INTERFACE ${DPDK_CFLAGS_OTHER})
# Pass the force-include and other misc flags that pkg-config puts in CFLAGS
# but NOT in CFLAGS_OTHER (i.e., the -include rte_config.h flag).
# We do this by splitting DPDK_CFLAGS into include dirs (handled above)
# and everything else:
foreach(_flag ${DPDK_CFLAGS})
    if(NOT _flag MATCHES "^-I")
        target_compile_options(dpdk_iface INTERFACE ${_flag})
    endif()
endforeach()
target_link_libraries(dpdk_iface INTERFACE ${DPDK_LDFLAGS} ${DPDK_LIBRARIES})

# ─────────────────────────────────────────────────────────────────────────────
# 2.  Find intel-ipsec-mb
#
#     No pkg-config file — use find_library + find_path.
#     The header is intel-ipsec-mb.h; the library is libIPSec_MB.
# ─────────────────────────────────────────────────────────────────────────────
find_path(IPSECMB_INCLUDE_DIR
    NAMES intel-ipsec-mb.h
    PATHS /usr/include /usr/local/include
    REQUIRED)

find_library(IPSECMB_LIBRARY
    NAMES IPSec_MB
    PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/local/lib
    REQUIRED)

message(STATUS "intel-ipsec-mb header : ${IPSECMB_INCLUDE_DIR}")
message(STATUS "intel-ipsec-mb library: ${IPSECMB_LIBRARY}")

add_library(ipsecmb_iface INTERFACE)
target_include_directories(ipsecmb_iface INTERFACE ${IPSECMB_INCLUDE_DIR})
target_link_libraries(ipsecmb_iface      INTERFACE ${IPSECMB_LIBRARY})

# ─────────────────────────────────────────────────────────────────────────────
# 3.  Common compiler flags
# ─────────────────────────────────────────────────────────────────────────────
add_compile_options(-Wall -Wextra)

# ─────────────────────────────────────────────────────────────────────────────
# 4.  Common include path (our own headers)
# ─────────────────────────────────────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/include)

# ─────────────────────────────────────────────────────────────────────────────
# 5.  Source groups
# ─────────────────────────────────────────────────────────────────────────────
set(COMMON_SRC
    src/nos_init.c
    src/nos_pipeline.c
    src/nos_threads.c
    src/nos_crypto.c
    src/nos_control.c
    src/nos_stats.c
)

# ─────────────────────────────────────────────────────────────────────────────
# 6.  Targets
# ─────────────────────────────────────────────────────────────────────────────

# ── 6a. Main dataplane binary ─────────────────────────────────────────────────
add_executable(nos_dataplane
    ${COMMON_SRC}
    src/nos_main.c
)
target_link_libraries(nos_dataplane PRIVATE dpdk_iface ipsecmb_iface)

# ── 6b. EAL-based integration tests ──────────────────────────────────────────
#    Requires a host with /sys/devices/system/cpu/cpuN/topology/core_id
add_executable(nos_test
    ${COMMON_SRC}
    src/nos_test.c
)
target_link_libraries(nos_test PRIVATE dpdk_iface ipsecmb_iface)

# ── 6c. Standalone logic tests (no EAL — runs anywhere) ──────────────────────
add_executable(nos_logic_test
    src/nos_logic_test.c
)
target_link_libraries(nos_logic_test PRIVATE ipsecmb_iface)

# ── 6d. AES-256-GCM ISA detection + crypto correctness test ──────────────────
add_executable(test_ipsec_mb
    src/test_ipsec_mb.c
)
target_link_libraries(test_ipsec_mb PRIVATE ipsecmb_iface)

# ─────────────────────────────────────────────────────────────────────────────
# 7.  CTest integration
#     cmake --build . --target test  (or: ctest --output-on-failure)
#     Runs the two standalone tests that need no NIC or hugepages.
# ─────────────────────────────────────────────────────────────────────────────
enable_testing()

add_test(NAME crypto_isa_test
    COMMAND test_ipsec_mb
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_test(NAME logic_test
    COMMAND nos_logic_test
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ─────────────────────────────────────────────────────────────────────────────
# 8.  Print summary
# ─────────────────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "── NOS-like DPDK Data Plane ─────────────────────")
message(STATUS "  Build type   : ${CMAKE_BUILD_TYPE}")
message(STATUS "  DPDK version : ${DPDK_VERSION}")
message(STATUS "  Targets      : nos_dataplane  nos_test")
message(STATUS "                 nos_logic_test test_ipsec_mb")
message(STATUS "  Tests (ctest): crypto_isa_test  logic_test")
message(STATUS "─────────────────────────────────────────────────")
message(STATUS "")
