# Environment and build setup

This document describes how to reproduce the **environment** used for the ns-3 / IoD-Sim experiments. It is derived from the provenance records of the original working project. No upstream source tarball, compiled tree, virtual environment or dataset is redistributed here.

## 1. Toolchain

Ubuntu (native or WSL2). The paper reports C++17 / GCC 15.2.0, OpenSSL 3.6.4, GMP 6.3.0 and Stanford PBC. The environment used to prepare this release had GCC 15.2.0 and OpenSSL 3.5.5, i.e. **OpenSSL differs** from the paper; no attempt was made to claim otherwise.

```bash
sudo apt update
sudo apt install -y build-essential g++ cmake make git python3 pkg-config \
                    libssl-dev libsqlite3-dev libgmp-dev libpbc-dev \
                    libxml2-dev libgsl-dev libeigen3-dev libfmt-dev \
                    libarchive-dev sqlite3
```

For `benchmarks/primitives/` a built [herumi/mcl](https://github.com/herumi/mcl) tree is required; set `MCL_ROOT` to it. For the Tamarin models, install `tamarin-prover` and its Maude backend (not available in the release-preparation environment).

## 2. Upstream components (obtain separately)

| Component | Version / revision | Provenance recorded by the project |
| --- | --- | --- |
| ns-3 | 3.45 official tarball, `ns-3.45/VERSION` = `3.45`, 4293 archive entries | SHA256 `a09a909a1794d9f1fb131dbcfa1f58ed82c56402602510f7bb9a442d727460b8` |
| IoD-Sim | 4.1.0, upstream commit `d40e35bdee245cac64e3df2bc647dd01d0a51f3a` | archive SHA256 `24c8d2860aa311cbef3f0a76a5ac4e35f988cd6562f77abe38a5d8a46984697f` |
| 5G-LENA (`nr`) | branch `5g-lena-v4.1.y`, commit `5606a4e96b3a0bdbe7a5ecb9bbda10d69da3a7a8` | `https://gitlab.com/cttc-lena/nr.git` |
| sgp4 | commit `d176906dbfaf8361eee1f83bd1dc1bacc6582798` | `https://github.com/dnwrnr/sgp4` (tarball SHA256 `5b2dc0a642bc91988f1b6dd3a7243695f4c3f5dfcdf95f80a136927a645bee75`) |

The IoD-Sim `leo/` module fetches sgp4 with CMake `FetchContent`. Where GitHub access is unavailable, download the commit tarball and point CMake at it without modifying upstream files:

```bash
./ns3 configure ... -- -DFETCHCONTENT_SOURCE_DIR_SGP4=/absolute/path/to/sgp4-src
```

IoD-Sim's `tools/prepare-ns3.sh` normally checks out ns-3.45 from GitLab; the original project used the official release tarball instead and verified the version string plus clean application of all eleven patches.

## 3. Assemble the build tree

```
IoD_Sim/
├── leo/                 (IoD-Sim LEO module)
├── src/                 (IoD-Sim main sources)
├── scenario/            (scenario JSON files)
├── tools/*.patch
└── ns3/                 <- ns-3.45 unpacked here
    ├── src/iodsim -> ../../src     (created by patch 0001)
    └── contrib/
        ├── leo -> ../../leo        (upstream symlink)
        └── nr/                     (5G-LENA)
```

Steps:

```bash
# 1. Unpack ns-3.45 into IoD_Sim/ns3 and initialise a git snapshot so patches apply.
cd IoD_Sim/ns3
git init && git add -A && git commit -m "ns-3.45 baseline"

# 2. Apply the eleven interoperability patches supplied in this repository.
git am /path/to/decoupled-uav-auth/simulation/patches/0001-*.patch \
       /path/to/decoupled-uav-auth/simulation/patches/0002-*.patch \
       ... \
       /path/to/decoupled-uav-auth/simulation/patches/0011-*.patch

# 3. Place the custom module.
cp -a /path/to/decoupled-uav-auth/simulation/ns3-uavma-module/. ns3/contrib/uavma/
#    (or run protocol/ns3/uavma/sync_ns3_module.sh with IODSIM_ROOT set)

# 4. Configure, build.
./ns3 configure -d debug --enable-modules=iodsim,nr,point-to-point-layout,uavma
./ns3 build -j4
```

`sync_ns3_module.sh` additionally copies the standalone protocol core into `contrib/uavma/core/` and idempotently adds `${libuavma}` to the `scenario` target's link libraries.

> Python 3.14 note: ns-3.45's `ns3` launcher may need the newer `ns3` script from ns-3-dev commit `30eb4168f63ee7263a046d5851ce99913e84d42a` to avoid a Python 3.14 crash. The original project applied that workaround; it is not bundled here.

## 4. Running a scenario

```bash
cd IoD_Sim/ns3
./ns3 run "scenario --config=/path/to/configs/scenarios/e2_pair_p.json --RngSeed=33 --RngRun=3"
```

Outputs (CSV ledgers, SQLite state databases, PCAPs, logs, `simulation_output/`) are produced locally by the simulator and are ignored by Git. They are not part of this repository.

## 5. What is deliberately absent

* Complete upstream ns-3 / IoD-Sim / 5G-LENA / sgp4 source trees, their build directories and `.venv` environments.
* Experimental data, result archives, proof screenshots, figures and their generating scripts.
* Cloud-server paths and credentials. All absolute paths in the published scripts and configs were replaced by relative paths or environment variables (`IODSIM_ROOT`, `IODSIM_NS3_DIR`, `E2_WIN_ROOT`, `E2_WSL_ROOT`, `MCL_ROOT`).
