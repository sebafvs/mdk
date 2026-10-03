# Notices & Attribution

MDK is written by [@sebafvs](https://github.com/sebafvs). The techniques it implements are drawn from public offensive-security research. This file credits each source. MDK's own code is an independent reimplementation, not a copy.

If any author sees their work represented incorrectly, please open an issue.

---

## Summary

| MDK component | Technique inherited from | Upstream reference |
|---|---|---|
| `src/evasion/syscalls.c` | SysWhispers2 SSN-by-VA-sort method | [klezVirus/SysWhispers3](https://github.com/klezVirus/SysWhispers3) |
| `src/evasion/hwbp.c` | HWBP descriptor list + VEH dispatch + DR fanout | [rad9800/hwbp4mw](https://github.com/rad9800/hwbp4mw) |
| `src/evasion/amsi.c`, `src/evasion/etw.c` | HWBP-based AMSI + ETW bypass | [TheEnergyStory/PatchlessEtwAndAmsiBypass](https://github.com/TheEnergyStory/PatchlessEtwAndAmsiBypass), [Praetorian: ETW TI and Hardware Breakpoints](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/) |
| `src/execution/stomp.c` | Phantom DLL Hollowing (SEC_IMAGE + entry-point overwrite) | [Forrest Orr writeup](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing), [forrest-orr/phantom-dll-hollower-poc](https://github.com/forrest-orr/phantom-dll-hollower-poc) |
| `src/execution/apc.c` | Early Bird APC via DEBUG_PROCESS | [Cyberbit disclosure (2018)](https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/) |

---

## Author's contribution

MDK's own code (`src/`, `include/`, `loaders/common.{h,c}`, `scripts/`) is written by [@sebafvs](https://github.com/sebafvs) and licensed MIT per [LICENSE](./LICENSE).

## Corrections

If you are one of the authors above and would prefer different phrasing, additional detail, or want a reference removed, please open an issue.
