# Paper experiments → source code map and verification status

Statuses below are **actual results from the environment used to prepare this release** (WSL2 Ubuntu, GCC 15.2.0, OpenSSL 3.5.5, SQLite 3.46.1, Python 3.14.4; no Tamarin/Maude, no PBC/GMP/mcl, no ns-3 build tree). Nothing here is inferred or claimed without being executed.

| Paper experiment | Source path(s) | Verified status |
| --- | --- | --- |
| Tamarin normal authentication (Fig. 4a) | `tamarin/01_normal_G.spthy` | `bash run_all.sh --dry-run` succeeds; 7 lemmas discovered. **Not proved**: `tamarin-prover`/Maude not installed. |
| Tamarin message-loss recovery (Fig. 4b) | `tamarin/02_recovery_G.spthy` | dry-run OK, 8 lemmas. **Not proved**. |
| Tamarin dual-domain / cross-domain isolation (Fig. 4c) | `tamarin/03_dual_domain.spthy` | dry-run OK, 9 lemmas. **Not proved**. |
| Tamarin post-session compromise (Fig. 4d) | `tamarin/04_compromise.spthy` | dry-run OK, 3 lemmas. **Not proved**. |
| Tamarin bounded state handoff (Fig. 4e) | `tamarin/05_state_handoff_G_bounded.spthy` | dry-run OK, 14 lemmas. **Not proved**. |
| Cryptographic primitives benchmark (Tables II/III) | `benchmarks/openssl-suite/bench_openssl.cpp`, `bench_pairing.c`, `gen_typea_param.c`, `Makefile`; `benchmarks/primitives/crypto_bench*.cpp`, `CMakeLists.txt` | `make` + `bash run_all.sh` **executed**: OpenSSL timing program wrote 24 primitive timing series. Pairing/PBC, GMP and mcl targets **not built** (dependencies absent). Extended suite: static/CMake review only. |
| E1 handler calibration / full-procedure cost | `protocol/src/e1_main.cpp`, `protocol/scripts/run_e1.sh` | **Executed** (`E1_REPEATS=10`): exit 0, `E1 LINUX NATIVE PASS`. |
| Protocol core, G/E state machines, persistence, service (S2) | `protocol/src/protocol_core.cpp`, `state_store.cpp`, `service_core.cpp`, `harness.cpp`; `protocol/tests/*.cpp` | **Compiled and all 10 C++ test binaries pass** (`make run-unit-tests`, exit 0); `bash scripts/run_s2.sh` executed, all five cases PASS. |
| G-only / E-only / G+E classification | `simulation/ns3-uavma-module/model/uavma-event-policy.h`, `uavma-cell-partition.h`, `protocol/ns3/uavma/model/` mirrors; `protocol/tests/test_uavma_event_policy.cpp` | Header-only unit tests **PASS**. ns-3 simulation itself **not rebuilt** in this environment. |
| Joint migration / comparative authentication (incl. Bi et al.) | `simulation/ns3-uavma-module/model/uavma-ns3-transport.cc`, `bi/core/*`, `bi/model/*`, `model/uavma-p4-cpu-model.h`, `model/uavma-measurement-ledger.h` | **Static review only** (CMake source list, headers, patches). Requires the external ns-3.45 + IoD-Sim 4.1.0 + 5G-LENA build tree; not rebuilt here. |
| A3 event → authentication completion latency, CPU and wire-message accounting | `simulation/ns3-uavma-module/model/uavma-ns3-transport.cc`, `model/uavma-measurement-ledger.h`, `configs/scenarios/e2_pair_p.json`, `e2_pair_a_joint.json` | Static review; scenario JSONs parse successfully. ns-3 run **not performed**. |
| Clock offset / drift grid (C0/C1, background load) | `protocol/src/e3_main.cpp` (E3a), `protocol/scripts/run_e3.sh` | **Executed**: 1364 grid points, `P` accepted 682/682, `A-Time` accepted 452/682, 0 window mismatches; `E3 e3a PASS`. |
| M2/M3 loss, `M2Recover`, `M3Recover`, state commit | `protocol/src/protocol_core.cpp`, `protocol/tests/test_recovery.cpp`, `protocol/src/e3_main.cpp` (E3b), `configs/scenarios/e2_m3_loss_test_p.json` | **Executed**: `test_recovery` PASS; `run_e3.sh` E3b fault matrix complete, `E3 e3b PASS`. |
| Concurrent authentication (150 UAV / 3 eNB / 25–150 req per 20 ms, Ours vs Ours-NS) | `simulation/ns3-uavma-module/model/uavma-ns3-transport.cc` supports overlapping sessions | **Parameterised concurrency scenario not present in this snapshot.** No source file implements the 150-UAV/20 ms request matrix; no command and no result are claimed. |

## Other checks performed

* All six `configs/scenarios/*.json` files parse as valid JSON; personal absolute output paths were replaced with relative `./results/...` paths, protocol/crypto/radio parameters untouched.
* All shell scripts pass `bash -n`; all Python files pass `py_compile`; `scripts/make_scenes.py --help` and `tamarin/run_all.py --dry-run` execute. A full HO3/P scene generation run from `configs/scenarios/PNET_r03_reference.json` was executed and produced a valid `scene.json` + `SCENE_MANIFEST.json` with no absolute development-host paths.
* `simulation/ns3-uavma-module/CMakeLists.txt` references only files present in this repository (checked against the file list); the eleven upstream patches and two project patches are present as text.
* No CSV/TSV/JSONL/PCAP/database/log/image/archive/private-key files exist in the release tree.

## Known gaps (stated, not filled)

* Literal paper labels `Ours`, `Ours-NS`, `C0`, `C1` are not used as identifiers in the code. The implementation uses internal variant names `P` (proposed), `A_JOINT` (joint trigger policy), `A-Time` (timestamp/window baseline) and `A-Retry` (recovery ablation); the mapping to paper labels is described in `README.md` and `protocol/docs/protocol_mapping.md`.
* A physical PUF is not present: `RootProvider::puf_eval()` is a symbolic, counted evaluation.
* The B-MES external baseline was never executed in the original project (`BLOCKED_SOURCE`); it is not implemented here.
* Derived cost tables, statistical post-processing and all figure generation are intentionally outside this release.
