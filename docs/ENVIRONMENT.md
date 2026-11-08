# Environment Setup and Usage

## 1. Requirements

The experimental environment reported in the paper is:

| Component | Specification |
| --- | --- |
| Language | C++17 |
| Compiler | GCC 15.2.0 |
| OpenSSL | 3.6.4 |
| GMP | 6.3.0 |
| Pairing library | Stanford PBC |
| Network simulator | ns-3.45 |
| UAV simulation framework | IoD-Sim 4.1.0 |
| Network technology | LTE |
| Formal verification | Tamarin Prover (with Maude) |
| Operating system | Ubuntu Linux / WSL2 |

The code additionally links against SQLite3 and uses CMake, Python 3 and `pkg-config`. `benchmarks/primitives/` requires herumi/mcl, and `tamarin/` requires `tamarin-prover` with its Maude backend.

Install the build dependencies on Ubuntu Linux or WSL2:

```bash
sudo apt update
sudo apt install -y build-essential g++ cmake make git python3 pkg-config \
                    libssl-dev libsqlite3-dev libgmp-dev libpbc-dev \
                    libxml2-dev libgsl-dev libeigen3-dev libfmt-dev \
                    libarchive-dev sqlite3
```

For `benchmarks/primitives/`, build [herumi/mcl](https://github.com/herumi/mcl) and set `MCL_ROOT` to that tree. Third-party components and their licenses are listed in `docs/THIRD_PARTY.md`.

## 2. Protocol Core, Verification and Benchmarks

From the repository root (see the README files in each directory for details):

```bash
# C++17 protocol core (protocol/)
( cd protocol && make && make test && make run-unit-tests )
( cd protocol && bash scripts/run_s2.sh )
( cd protocol && bash scripts/run_e1.sh )
( cd protocol && bash scripts/run_e3.sh )

# Tamarin models (tamarin/)
( cd tamarin && bash run_all.sh --dry-run )
( cd tamarin && bash run_all.sh )

# Cryptographic benchmarks (benchmarks/)
( cd benchmarks/openssl-suite && make && bash run_all.sh )
( cd benchmarks/primitives && bash run.sh )
```

`benchmarks/openssl-suite` also provides `make pairing param` for the PBC/GMP pairing targets, and `benchmarks/primitives/run_many.sh <N>` repeats the extended suite. Experiment programs write their outputs locally at run time; these outputs are ignored by Git.

### Standalone protocol experiment programs

Three additional C++17 programs under `protocol/` exercise the state machine, the clock-independence grid and the M2/M3 loss-recovery behaviour without the ns-3 build tree. They link only against OpenSSL `libcrypto`.

```bash
# State-machine mechanism prototype (01)
( cd protocol/prototype_validation && cmake -S . -B build && cmake --build build -j )
./protocol/prototype_validation/build/prototype_validation_v2 100 500 1000

# Clock-independence ASR/FRR grid (05)
( cd protocol/clock_independence && cmake -S . -B build && cmake --build build -j )
./protocol/clock_independence/build/clock_experiment

# Message-loss / state-recovery programs (06)
( cd protocol/state_recovery && \
    for s in state_recovery_experiment state_recovery_benchmark state_recovery_random_loss; do \
      g++ -std=c++17 -O2 -Wall -o "$s" "$s.cpp" -lcrypto; done )
```

Argument definitions are in `protocol/prototype_validation/README.md` and `protocol/clock_independence/README.md`. Generated CSV outputs are written into the working directory at run time and are excluded from Git.

## 3. ns-3 / IoD-Sim Build Tree

The network experiments require an external build tree assembled from upstream sources, which are not redistributed here. `simulation/patches/` contains the interoperability patches applied to them.

| Component | Version | Source |
| --- | --- | --- |
| ns-3 | 3.45 | official ns-3.45 release tarball |
| IoD-Sim | 4.1.0 | upstream IoD-Sim repository |
| 5G-LENA (`nr`) | `5g-lena-v4.1.y` | https://gitlab.com/cttc-lena/nr.git |
| sgp4 | upstream commit | fetched by the IoD-Sim `leo` module via CMake `FetchContent` |

The `uavma` module links against ns-3 `core`, `network`, `internet`, `mobility`, `applications` and `lte` (see `simulation/ns3-uavma-module/CMakeLists.txt`). The `nr`, `iodsim` and `point-to-point-layout` modules are required by the IoD-Sim build configuration used by these scenarios. If `FetchContent` cannot retrieve sgp4, supply a local checkout at configure time:

```bash
./ns3 configure ... -- -DFETCHCONTENT_SOURCE_DIR_SGP4=/absolute/path/to/sgp4-src
```

## 4. Assemble the Build Tree

```
IoD_Sim/
├── leo/                  (IoD-Sim LEO module)
├── src/                  (IoD-Sim main sources)
├── scenario/             (scenario runner)
├── tools/                (upstream patches)
└── ns3/                  <- ns-3.45 unpacked here
    └── contrib/
        ├── leo -> ../../leo
        ├── nr/           (5G-LENA)
        └── uavma/        <- simulation/ns3-uavma-module/
```

Initialise the ns-3 tree as a Git snapshot so the patches can be applied, then add the custom module:

```bash
cd IoD_Sim/ns3
git init && git add -A && git commit -m "ns-3.45 baseline"
git am /path/to/repo/simulation/patches/00{01..11}-*.patch
mkdir -p contrib/uavma
cp -a /path/to/repo/simulation/ns3-uavma-module/. contrib/uavma/
./ns3 configure -d debug --enable-modules=iodsim,nr,point-to-point-layout,uavma
./ns3 build -j4
```

`protocol/ns3/uavma/sync_ns3_module.sh` performs the module copy and the `scenario` link wiring in one step; set `IODSIM_ROOT` to the `IoD_Sim` directory before running it.

## 5. Running a Scenario

```bash
cd IoD_Sim/ns3
./ns3 run "scenario --config=/path/to/repo/configs/scenarios/e2_pair_p.json --RngSeed=33 --RngRun=3"
```

From the repository root, scene generation and individual runs can also be driven with:

```bash
python3 scripts/make_scenes.py \
  --template configs/scenarios/PNET_r03_reference.json \
  --root ./scenes --runs 3 --events HO12,HO3 --variants P,A_JOINT

IODSIM_ROOT=/path/to/IoD_Sim \
  bash scripts/run_one.sh /abs/path/to/scene.json /abs/path/to/run_dir 3
```

## 6. Multi-UAV / Concurrent Authentication Scenes

The E5 overlay in `simulation/e5/` extends the `uavma` module with a node-wide CPU pool shared by all target applications. Copy `simulation/e5/model/` into `<IoD-Sim>/ns3/contrib/uavma/model/`, add `uavma-e5-cpu-pool.h` to `public_headers` (or use `simulation/e5/CMakeLists.txt`), apply the two patches in `simulation/e5/patches/` to `IoD_Sim/src/main.cc`, then reconfigure and rebuild the ns-3 tree.

```bash
python3 scripts/e5/make_e5_v2_scenes.py \
  --p-template configs/scenarios/e2_pair_p.json \
  --joint-template configs/scenarios/e2_pair_a_joint.json \
  --out-root ./scenes/e5 --n 150 --layout fixed --rng-seed 33 --rng-run 3

python3 scripts/e5/make_e5_scenes.py \
  --p-template configs/scenarios/e2_pair_p.json \
  --joint-template configs/scenarios/e2_pair_a_joint.json \
  --out-root ./scenes/e5-v1 --n 150 --rng-seed 33 --rng-run 3
```

`--layout fixed` keeps a single three-cell LTE corridor (N UEs / 3 eNBs); `--layout scaled` builds `ceil(N / uavs-per-cluster)` corridors of three eNBs each. `make_e5_v2_p_only.py` generates the P-only variant. Run the resulting `scene.json` files with `scripts/run_one.sh` or `scripts/run_batch.sh` as shown in section 5. Generated scenes and simulator outputs are written locally and excluded from Git.

### N=500 formal seeds and the E5 V2 overlay installer

`scripts/e5/e5b_n500_formal4.py` and `scripts/e5/e5b_n500_durable_autowaves.py` are the drivers for the four-seed N=500 P-only runs. `scripts/e5/install_e5_v2.py` installs the E5 V2 source overlay; it defaults to a dry run and `--apply` is permitted only on an independent copied source tree.

These drivers were written for the ECS build tree and keep its absolute layout constants (`/data/e5b`, `/home/wang/uav-e5-v2-build/IoD_Sim`). Recreate that layout, or supply the corresponding paths, before invoking them. The batch evidence validator referenced by `e5b_n500_formal4.py` is a run-time analysis component and is not distributed with this source-only repository; configure its path externally. No private keys or credentials are included in this repository.

Scenario ledgers, state databases and traces are written locally by the simulator and are excluded from this repository. See `docs/EXPERIMENTS.md` for the mapping between paper experiments and source directories.
