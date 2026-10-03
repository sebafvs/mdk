
# MDK

Malware Developer Kit. A small library of pieces you can use to build Windows loaders with less code.

Every loader ends up writing the same things: process and thread control, memory read and write, indirect syscalls, hardware breakpoint hooking, HWBP-based AMSI and ETW bypass, module stomping, PPID spoofing, IAT camouflage, process and thread discovery, and injection primitives (classic, section-map, APC, thread hijack). MDK ships each of these as a small static library. A loader picks the ones it needs and links them into one Windows executable.

Example loaders live in the [`loaders/`](https://github.com/purpleranges/loaders) submodule.

## Setup

### Prerequisites

- Linux host with `x86_64-w64-mingw32-gcc` and `x86_64-w64-mingw32-windres` (mingw-w64 cross-toolchain)
- CMake 3.20 or newer
- Ninja
- Target: Windows x64

### Build

```bash
git clone --recurse-submodules https://github.com/sebafvs/mdk.git
cd mdk

cmake -B build -G Ninja \
    -DCMAKE_SYSTEM_NAME=Windows \
    -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
    -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres
ninja -C build
```

All example loaders land under `build/loaders/<name>/<name>.exe`. See the [`loaders/`](https://github.com/purpleranges/loaders) submodule for how to use each one.

## Options

Build-time CMake variables:

| Variable    | Default | Purpose                                                                                                                    |
| ----------- | ------- | -------------------------------------------------------------------------------------------------------------------------- |
| `MDK_DEBUG` | `OFF`   | Compile-time flag that enables verbose stage logging via `mdk/dbg.h`. When off, format strings are absent from the binary. |

## Using MDK

Add a new folder under `loaders/`, drop a `main.c` and a one-line `CMakeLists.txt` inside it, and include whichever MDK headers you need. Every function MDK exposes lives behind a header in `include/mdk/`.

For inspiration, look at the [example loaders](https://github.com/purpleranges/loaders).

## Layout

The source tree follows the MITRE ATT&CK tactics.

```
include/mdk/     Public API headers, one per pillar
src/core/        Core primitives: memory, thread, process, pe, payload
src/evasion/     Defense Evasion: dfr, iat, syscalls, spawn, hwbp, amsi, etw, encode
src/execution/   Execution: classic, stomp, section, apc, hijack
src/discovery/   Discovery: enum_process, enum_thread, env
src/staging/     Resource Development: staging
loaders/         Submodule pointing at purpleranges/loaders
```

Each pillar compiles as a separate static library. A loader links only the libraries it uses. See `CMakeLists.txt` for the full dependency graph.

## Documentation

Per-pillar and per-function reference at [sebafvs.com/mdk](https://sebafvs.com/mdk).

The website is not complete yet. Until it is, the code itself is the reference. Headers in `include/mdk/` are the quickest way to see the API.

## Credits
  
MDK builds on prior public work in the offensive Windows tradecraft community.
See [NOTICE.md](./NOTICE.md) for the full per-pillar attribution list.


## License

MIT. See [LICENSE](./LICENSE).

## Disclaimer

This tool was developed for authorised security research and adversary simulation. Use it only against systems you own or have explicit written permission to test. The author accepts no liability for misuse. Nothing in this repository is intended as an attack against any production system, third party, or individual.

Detection artefacts (Sigma rules, YARA rules, EDR queries) derived from analysing this tool are welcome. Contributions that improve detection alongside the offensive capability are encouraged.