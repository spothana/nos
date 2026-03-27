# NOS handling L1, L2 and L3 using DPDK

A DPDK-based SD-WAN data plane implemention: poller/worker threading, single-pass 
packet pipeline, AES-256-GCM IPSec via intel-ipsec-mb, BFD-driven WAN path selection, and
multi-tenancy foundations.

---

## Prerequisites

```bash
# Ubuntu 22.04 / 24.04
sudo apt-get install build-essential cmake pkg-config \
    dpdk libdpdk-dev dpdk-dev \
    libipsec-mb-dev
```

If cmake is not available via apt, install it with pip:

```bash
pip3 install cmake
```

---

## Build

```bash
# Configure (out-of-source build)
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Compile all targets in parallel
cmake --build build --parallel

# Run tests (no NIC or hugepages needed)
ctest --test-dir build --output-on-failure
```

Targets produced in `build/bin/`:

| Binary | Description |
|---|---|
| `nos_dataplane` | Full SD-WAN data plane (needs DPDK NIC or `--vdev`) |
| `nos_test` | EAL-based integration tests (needs host with full sysfs) |
| `nos_logic_test` | Standalone logic tests — no EAL, runs anywhere |
| `test_ipsec_mb` | AES-256-GCM ISA detection + crypto correctness |

### Other cmake build types

```bash
cmake -S . -B build_debug   -DCMAKE_BUILD_TYPE=Debug
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release
```

---

## Running

```bash
# No NIC needed — standalone tests:
./build/bin/nos_logic_test      # 40/40: session, AppID, FIB, WAN, NAT, BFD, crypto
./build/bin/test_ipsec_mb       #  9/9:  AES-256-GCM ISA detection

# Or via ctest:
ctest --test-dir build --output-on-failure -V

# EAL integration tests (requires host with /sys topology files):
sudo ./build/bin/nos_test --no-huge --no-pci -l 0,1

# Full dataplane with null vdev (no physical NIC):
sudo ./build/bin/nos_dataplane --no-huge -l 0,1,2,3 \
  --vdev net_null0 --vdev net_null1 \
  --vdev crypto_ipsec_mb

# Full dataplane with real NIC (bind with dpdk-devbind first):
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0
sudo ./build/bin/nos_dataplane -l 0,1,2,3 \
  -a 0000:01:00.0 --vdev crypto_ipsec_mb
```

---

## Architecture

```
┌──────────── Control Plane (nos_control.c) ──────────────┐
│  BFD rte_timer → wan[i].rtt_us / loss_ppm (EMA α=0.25)  │
│  nos_ctrl_add_route / add_nat / add_wan_circuit          │
└───────────────────────┬─────────────────────────────────┘
                        │  rte_lpm_add, rte_hash writes
┌────── Single-Pass Data Plane (nos_pipeline.c) ──────────┐
│  session lookup → AppID/DPI → NAT → WAN select →        │
│  IPSec encrypt → L3 forward                             │
│  packet parsed once; metadata flows between stages      │
└───────────┬────────────────────────┬────────────────────┘
            │                        │
     ┌──────┴──────┐          ┌──────┴──────┐
     │  Pollers    │          │   Workers   │
     │ rte_eth_rx  │  RSS     │  process_   │
     │ _burst()    │ ──────→  │  burst()    │
     │ 100% poll   │  rings   │ per-flow    │
     └──────┬──────┘          └──────┬──────┘
            └────────────────────────┘
                    DPDK PMDs
              (ixgbe / i40e / ice / virtio)
```

### Crypto acceleration stack

```
nos_ipsec_encrypt()
    │
    ├── PATH B (if --vdev crypto_ipsec_mb or crypto_qat):
    │     rte_cryptodev_enqueue_burst()  ← PMD abstraction
    │     rte_cryptodev_dequeue_burst()  ← async for QAT
    │
    └── PATH A (fallback — always available):
          IMB_AES256_GCM_ENC() direct call
          └── init_mb_mgr_auto() selects ISA at startup:
                AVX-512 + VAES  →  by32 (~0.5 cycles/byte)
                AVX2            →  by16
                SSE + AES-NI    →  by8  (~1.0 cycle/byte)
```

---

## CMakeLists.txt design notes

**DPDK discovery** uses `find_package(PkgConfig)` + `pkg_check_modules(DPDK REQUIRED libdpdk)`.
DPDK ships no native CMake config file — pkg-config is the official upstream method.
The `DPDK_CFLAGS` list includes `-include rte_config.h` (a force-include flag);
the CMakeLists.txt iterates over all flags and passes non-`-I` entries via
`target_compile_options()` so the force-include is preserved correctly.

**intel-ipsec-mb discovery** uses `find_library(IPSec_MB)` + `find_path(intel-ipsec-mb.h)`
since that library ships no pkg-config file.

Both are wrapped in `INTERFACE` targets (`dpdk_iface`, `ipsecmb_iface`) so
each executable only calls `target_link_libraries(... PRIVATE dpdk_iface ipsecmb_iface)`.

**CTest** registers `crypto_isa_test` and `logic_test` — the two binaries that
need no NIC or hugepages. The EAL-dependent `nos_test` is built but not
registered as a ctest target because it requires `/sys` CPU topology files
that may not be present in containers or CI environments.

---

## File inventory

```
CMakeLists.txt         cmake build — DPDK via pkg-config, ipsec-mb via find_library

include/
  nos.h                Core types: session, WAN circuit, IPSec SA, lcore ctx
  nos_crypto.h         Crypto engine: IMB_MGR, gcm_key_data, cryptodev pools

src/
  nos_init.c           EAL init, port RSS config, session hash, LPM FIB, rings
  nos_pipeline.c       Single-pass pipeline + WAN path selection
  nos_threads.c        Poller loop (RX→RSS dispatch) + worker loop
  nos_crypto.c         AES-256-GCM: intel-ipsec-mb direct + DPDK cryptodev
  nos_control.c        BFD timers, EMA RTT, control plane API
  nos_stats.c          Per-lcore counters, port stats, session occupancy
  nos_main.c           Entry point — wires all subsystems, launches threads
  nos_ipsec.c          Placeholder (real implementation in nos_crypto.c)
  nos_test.c           EAL-based integration tests
  nos_logic_test.c     Standalone logic tests — no EAL dependency
  test_ipsec_mb.c      AES-256-GCM ISA detection and correctness test
```

---

## Test results

```
ctest 2/2 passed
  crypto_isa_test:  9/9  — AVX-512+VAES confirmed, GCM-by32
  logic_test:      40/40 — session, AppID, FIB, WAN, NAT, BFD, crypto
```

### Bug caught by tests

`nos_select_wan_path()` initialised `best=0` without checking if circuit 0
was active. On failover, VoIP traffic could be pinned to a downed circuit
whose stale RTT still won all comparisons. Fixed: scan for first active
circuit as baseline before the selection loop.
