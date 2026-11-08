# Third-Party Components

## Project code

The Tamarin models, the `protocol/` C++ implementation, the `simulation/ns3-uavma-module/` module, benchmark sources, scenario configurations and scripts in this repository accompany the paper. No `LICENSE` file is included because the intended license for this code has not been confirmed by the authors; public availability does not grant a license.

## External dependencies

| Component | Version | License | Use in this repository |
| --- | --- | --- | --- |
| ns-3 | 3.45 | GPL-2.0-or-later | Network simulator; `simulation/patches/` contains the interoperability patches |
| IoD-Sim | 4.1.0 | GPL-2.0 | UAV simulation framework hosting the `contrib/uavma` module |
| 5G-LENA (`nr`) | `5g-lena-v4.1.y` | upstream license | Module required by the IoD-Sim build configuration |
| sgp4 | upstream | upstream license | Fetched by the IoD-Sim `leo` module via CMake `FetchContent` |
| OpenSSL | 3.6.4 | Apache-2.0 | Protocol core, ns-3 module and benchmarks |
| SQLite3 | system | public domain | Protocol state persistence |
| Stanford PBC / GMP | GMP 6.3.0 | upstream licenses | Pairing benchmarks |
| herumi/mcl | upstream | upstream license | Extended BLS12-381 benchmarks |
| Tamarin Prover / Maude | upstream | upstream licenses | Discharging the lemmas in `tamarin/` |

Upstream source trees and compiled binaries are not redistributed here; see `docs/ENVIRONMENT.md` for the build tree. Patches in `simulation/patches/` are modifications to the corresponding ns-3 tree and do not change its license. The `uavma` module is additive and does not modify frozen upstream versions.

## Comparison scheme

`simulation/ns3-uavma-module/bi/` is an implementation of the Bi et al. scheme written for the comparison experiments in the paper, mapped onto the same simulation topology and measurement ledger. It is not a copy of a third-party codebase. Values quoted in the paper from other published studies are literature references rather than outputs of this code.
