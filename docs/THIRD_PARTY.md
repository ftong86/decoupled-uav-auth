# Third-party components and licensing

## Own code

The Tamarin models, the `protocol/` C++ implementation, the `simulation/ns3-uavma-module/` custom module, the benchmark sources, the scenario configs and the scripts in this repository are the experimental implementation accompanying the paper. **No LICENSE file is provided** because ownership and the intended license have not been confirmed by all authors. The repository being publicly readable does not grant a license. Contact the authors before redistributing or reusing this code. The included `CITATION.cff` is a citation request only.

## External dependencies (not redistributed here)

| Component | Version used | License | How it is referenced |
| --- | --- | --- | --- |
| ns-3 | 3.45 | GPL-2.0-or-later | Required build tree; eleven interoperability patches are included in `simulation/patches/`. |
| IoD-Sim | 4.1.0 | GPL-2.0 (upstream `LICENSE`) | Required simulation framework; the project adds a `contrib/uavma` module. |
| 5G-LENA (`nr`) | `5g-lena-v4.1.y` | Upstream `LICENSE` / `LICENSES` in the nr module | LTE/NR module used by the scenarios. |
| sgp4 (`dnwrnr/sgp4`) | commit `d176906…` | Upstream license | Fetched by IoD-Sim's `leo` module via CMake `FetchContent`. |
| OpenSSL | paper: 3.6.4; release environment: 3.5.5 | Apache-2.0 (OpenSSL 3.x) | Linked by the protocol core, ns-3 module and benchmarks. |
| SQLite3 | 3.46.1 in release environment | Public domain | Linked by `src/state_store.cpp`. |
| Stanford PBC, GMP, herumi/mcl | paper: GMP 6.3.0 | Upstream licenses | Optional benchmark targets. |
| Tamarin prover + Maude | not installed in release environment | Upstream licenses | External tool used to discharge the lemmas in `tamarin/`. |

Patches in `simulation/patches/` are modifications intended to be applied to the corresponding upstream ns-3 tree; they do not change the upstream license. The custom `uavma` module is additive: it does not modify frozen upstream versions of ns-3, IoD-Sim or 5G-LENA.

## Comparison scheme

`simulation/ns3-uavma-module/bi/` is an original re-implementation, written for this experiment, of the Bi et al. scheme used as a comparison baseline in the paper. It is mapped onto the same simulation topology and measurement ledger so the two protocols can be compared fairly. It is not a copy of a third-party codebase. Where the paper reports values quoted from other published studies, those are literature references, not outputs of this repository.

## Excluded material

No upstream source archives, compiled binaries, virtual environments, SSH keys, cloud credentials, generated datasets, proofs screenshots, figures, logs or statistical/plotting scripts are included. See `README.md` §6 for the experimental scope statement.
