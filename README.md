# Decoupled Authentication for UAV Handover and Edge Service Migration Without Clock Synchronization

Official experimental **source code** repository for the paper

> *Decoupled Authentication for UAV Handover and Edge Service Migration Without Clock Synchronization*

This repository contains the Tamarin formal-verification models, the C++ authentication protocol implementation, the ns-3 / IoD-Sim simulation sources, the cryptographic micro-benchmarks, the comparison-protocol implementation, and the configurations and scripts needed to build and run them.

---

## 1. Overview

The protocol decouples two logically independent mobility procedures:

* **G domain** — communication handover authentication between a UAV and a ground/access target.
* **E domain** — edge service migration authentication between a UAV and an edge service target.

Key mechanisms implemented here:

* Independent authorization and **epoch** management per domain; no timestamp-based freshness check and therefore **no clock synchronization** requirement.
* **M0 / M1 / M2 / M3** message flow with mutual authentication, ECDH session-key agreement, HMAC/HKDF derivation and ECDSA signatures.
* **PUF-derived, evolving signing credentials** (`RootProvider`, state-key evolution) — a software simulation of a physical unclonable function, counted symbolically rather than timed as a hardware operation.
* **State commitment**, a committed state `S^C` and a pending state `Pi`, with crash-restart persistence via SQLite.
* **M2Recover / M3Recover** recovery branches for message loss, plus cached retransmission handling.
* **Cross-domain isolation**: G and E maintain separate roots, pseudonyms, certificates, sessions and state stores.

---

## 2. Repository Structure

| Path | Contents |
| --- | --- |
| `tamarin/` | Five `.spthy` models (normal authentication, message-loss recovery, dual-domain execution, post-session compromise, bounded state handoff) and the verification driver. |
| `protocol/` | Standalone C++17 reference implementation of the protocol core (`src/`, `include/uavma/`), experiment drivers (`src/e1_main.cpp`, `src/e3_main.cpp`, `src/formal_main.cpp`), Linux-native transport, unit tests (`tests/`), build file (`Makefile`), run scripts (`scripts/`), protocol-to-paper mapping (`docs/`) and the ns-3 module sync sources (`ns3/uavma/`). |
| `simulation/` | The custom ns-3 contrib module `ns3-uavma-module/` (protocol engine, measurement ledger, A3-event policy, cell partition, CPU model, and the **Bi et al. comparison scheme** under `bi/`) plus `patches/` (11 upstream ns-3 interoperability patches and 2 project patches). |
| `benchmarks/` | `openssl-suite/` (OpenSSL + PBC primitive timing) and `primitives/` (extended primitive suite: SHA-256, ECDSA, EC operations, HMAC, HKDF, RSA, pairing/BLS12-381, BLS/PBC). |
| `configs/scenarios/` | IoD-Sim scenario JSON files for LTE handover, P vs A_JOINT paired runs, G-only/E-only injection and M3-loss testing. |
| `scripts/` | ns-3 scene generator and the single-run / batch experiment drivers. |
| `docs/` | Environment setup, experiment-to-code map and third-party notices. |

The upstream ns-3.45, IoD-Sim 4.1.0, 5G-LENA and sgp4 source trees are **not redistributed**. They are external dependencies described in `docs/ENVIRONMENT.md`; only the patches required to make them interoperate are included.

---

## 3. Requirements

### Paper environment (as reported in the manuscript)

| Component | Version |
| --- | --- |
| C++ standard / compiler | C++17, GCC 15.2.0 |
| OpenSSL | 3.6.4 |
| PBC / GMP | Stanford PBC, GMP 6.3.0 |
| Network simulator | ns-3.45 + IoD-Sim 4.1.0, LTE module, 5G-LENA (`nr`) |
| Formal verifier | `tamarin-prover` with Maude |
| OS | Ubuntu / WSL2 |

### Verified in the environment used to prepare this release

Ubuntu under WSL2: **GCC 15.2.0**, **OpenSSL 3.5.5**, SQLite 3.46.1 (`libsqlite3-dev`), CMake 4.2.3, GNU Make 4.4.1, Python 3.14.4, `libssl-dev`. The standalone C++ protocol core and its unit tests build and run in this environment (see `docs/EXPERIMENTS.md`).

**Differences and missing tools, stated explicitly:** OpenSSL in this environment is 3.5.5, not 3.6.4; `tamarin-prover`, Maude, Stanford PBC, GMP and herumi/mcl were **not installed**, so the Tamarin models and the PBC/mcl-dependent benchmark targets were not executed here; the ns-3 / IoD-Sim tree was **not** rebuilt during release preparation. No version claim in this README should be read as a verification result.

Additional build dependencies: `libssl-dev`, `libsqlite3-dev`, `pkg-config`, `cmake >= 3.16`, and for `benchmarks/primitives/` Stanford PBC, GMP and herumi/mcl (BLS12-381).

---

## 4. Build Instructions

```bash
# 4.1 Standalone C++ protocol core and unit tests
cd protocol
make                       # builds build/auth_preflight and build/uavma_formal
make formal                 # additionally builds uavma_e1, uavma_e3 and the C++ tests
make test                   # runs the cryptographic smoke preflight
bash scripts/check_environment.sh
```

```bash
# 4.2 OpenSSL / PBC primitive micro-benchmarks
cd benchmarks/openssl-suite
make                        # builds bench_openssl (OpenSSL only)
make pairing param          # optional: requires PBC + GMP; builds bench_pairing,
                            # gen_typea_param and generates typea_256_1536.param
```

```bash
# 4.3 Extended primitive benchmark suite (PBC + GMP + mcl + OpenSSL)
cd benchmarks/primitives
bash run.sh                 # configures with CMake, builds, runs once, writes results/
# or: MCL_ROOT=/path/to/built/mcl bash run.sh
```

```bash
# 4.4 ns-3 / IoD-Sim
# Follow docs/ENVIRONMENT.md to assemble ns-3.45 + IoD-Sim 4.1.0 + 5G-LENA,
# apply simulation/patches/*.patch, and copy simulation/ns3-uavma-module/ to
# ns3/contrib/uavma/  (or run protocol/ns3/uavma/sync_ns3_module.sh).
cd <your-IoD-Sim>/ns3
./ns3 configure -d debug --enable-modules=iodsim,nr,point-to-point-layout,uavma
./ns3 build -j4
```

---

## 5. Running Experiments

### 5.1 Tamarin formal verification (paper Section VI-C, Fig. 4)

```bash
cd tamarin
bash run_all.sh --dry-run              # list models/lemmas without proving
bash run_all.sh                        # prove all five models
bash run_all.sh --model 03             # prove only the dual-domain model
bash run_all.sh --timeout 600 --heap 4000M --threads 1
```

`run_all.sh` / `run_all.py` invoke `tamarin-prover` per lemma and write logs, a summary and HTML result pages into a timestamped local `results/` directory. Those outputs are local only and git-ignored.

### 5.2 Cryptographic benchmarks (paper Tables II and III)

```bash
cd benchmarks/openssl-suite && bash run_all.sh
cd benchmarks/primitives && bash run_many.sh 10
```

Both measure **real wall-clock execution time** with `std::chrono::steady_clock` over repeated samples. The full-procedure cost profile used by the ns-3 CPU model is produced by `protocol/src/e1_main.cpp`, not by a paper-value table. Some comparison values reported in the paper come from other published works cited there; those are external literature values, not locally measured data, and this repository does not include the derived cost tables or the scripts that combine measured primitives with operation counts.

### 5.3 Protocol-core experiments (S2 / E1 / E3)

Run from `protocol/`. Each script creates a new `<repo>/results/formal/<RUN_ID>/` or `<repo>/results/preflight/<RUN_ID>/` directory and refuses to overwrite an existing run.

```bash
bash scripts/run_s2.sh     # protocol core, recovery, persistence, service, multi-process nodes (S2)
bash scripts/run_e1.sh     # Linux-native handler cost and full-transaction calibration (E1 / S3)
bash scripts/run_e3.sh     # E3a clock-independence grid + E3b M2/M3 loss-recovery matrix (S4)
```

The `e3a` grid sweeps a controlled clock offset `Delta_clk/W` in [-1.5, 1.5] and network delay `Dnet/W` in [0, 0.5] with a 500 ms reference window, comparing `P` (proposed) against `A-Time` (timestamp/window baseline). `e3b` compares `P` against `A-Retry` (recovery-branch ablation). The code uses these internal variant names; the paper's C0/C1 clock configurations correspond to the zero-offset and offset/drift cases of this controlled grid, and the background-load dimension is provided by the ns-3 scenarios.

### 5.4 ns-3 / IoD-Sim mobility and comparison experiments (paper Sections VII-C, VII-D, VII-E)

```bash
# Generate a scene set (HO12 natural LTE A3-RSRP handover, HO3 controlled E-only event),
# for P and A_JOINT variants:
python3 scripts/make_scenes.py \
  --template configs/scenarios/PNET_r03_reference.json \
  --root ./scenes --runs 3 --events HO12,HO3 --variants P,A_JOINT

# Run one generated scene from inside the IoD-Sim ns-3 build tree:
IODSIM_ROOT=/path/to/IoD_Sim \
  bash scripts/run_one.sh /abs/path/to/scene.json /abs/path/to/run_dir 3

# Or drive a batch job list:
bash scripts/run_batch.sh joblist.txt 6
```

Scenario JSON files in `configs/scenarios/`:

| File | Use |
| --- | --- |
| `e2_lte_ho_protocol.json` | Baseline LTE A3-RSRP handover scenario. |
| `PNET_r03_reference.json` | Three-cell natural-handover reference template. |
| `E2_frozen_ho3_pair_p.json` | Controlled E-only (HO3) minimal template. |
| `e2_pair_p.json` | Proposed scheme (`P`) paired run. |
| `e2_pair_a_joint.json` | Joint/comparison trigger policy (`A_JOINT`) paired run. |
| `e2_m3_loss_test_p.json` | M3 message-loss test. |

G-only / E-only / G+E events are classified by `protocol/ns3/uavma/model/uavma-event-policy.h` and `simulation/ns3-uavma-module/model/uavma-cell-partition.h`; the ns-3 application (`uavma-ns3-transport.cc`) records A3-event-to-authentication-completion latency, CPU load and wire-message counts. The Bi et al. comparison protocol is implemented in `simulation/ns3-uavma-module/bi/`. M2/M3 loss, `M2Recover` and `M3Recover` are implemented in `protocol/src/protocol_core.cpp` and exercised by `protocol/tests/test_recovery.cpp` and `src/e3_main.cpp`.

**Concurrency experiment (paper Fig. 8):** the ns-3 module supports overlapping authentication sessions, but the concrete parameterised scenario (150 UAVs, 3 eNBs, 25/50/100/150 requests per 20 ms, Ours vs Ours-NS) is **not present in this source snapshot**. No command is provided for it and no result is claimed. The N-scaling launchers and their generated scenes remain in the private working archive and are not part of this release.

---

## 6. Experimental Scope

**This repository provides the experimental source code and necessary configurations. Raw experimental datasets, generated results, statistical post-processing scripts, and plotting scripts are not included.**

Experiment programs create their own outputs locally at run time (for example `results/`, `results_<timestamp>/`, `scenes/`, `simulation_output/`). All such outputs are ignored by Git. No CSV/TSV datasets, PCAP traces, logs, proof screenshots, figure files or derived statistics tables are distributed. The repository does not contain a `results/`, `analysis/`, `figures/`, `plots/` or `data/` publication directory.

---

## 7. Citation

The paper is currently a manuscript; **no DOI, volume, pages or publication venue have been confirmed**, so none are given here. See `CITATION.cff` for a machine-readable reference with the author list.

```bibtex
@misc{decoupled_uav_auth,
  title  = {Decoupled Authentication for UAV Handover and Edge Service Migration Without Clock Synchronization},
  author = {Wang, Linfei and Fang, Wenbo and Zhang, Jianhua and Zhang, Min and
            He, Junjiang and Mo, Daijian and Su, Yanming and Zhang, Linlin},
  year   = {2026},
  note   = {Manuscript; associated experimental source code},
  url    = {https://github.com/ftong86/decoupled-uav-auth}
}
```

---

## 8. License

No `LICENSE` file is included. Ownership and the intended license for the project's own code have not been confirmed by all authors, so no license is asserted here and none should be inferred from the repository being public. Please contact the authors before redistributing.

Third-party components are **not relicensed**: ns-3 and IoD-Sim are GPL-2.0, 5G-LENA (`nr`) carries its own upstream license, and the included patches apply to those upstream trees. See `docs/THIRD_PARTY.md` for provenance. The benchmark code also links against OpenSSL, Stanford PBC, GMP and herumi/mcl, each under its own license.
