# Multi-UAV Scene Generators

These generators build the multi-UAV LTE scenes used for the scalability and concurrent authentication experiments. Each starts from the single-UAV `P` / `A_JOINT` templates in `configs/scenarios/` and creates N genuine drone nodes, N protocol-state-isolated target applications on one infrastructure node, and a shared modeled CPU pool.

| Script | Purpose |
| --- | --- |
| `make_e5_scenes.py` | N drones on one three-cell LTE corridor with simultaneous authentication starts |
| `make_e5_v2_scenes.py` | V2 generator: `--layout fixed` keeps a single three-cell corridor (N UEs / 3 eNBs); `--layout scaled` builds `ceil(N / uavs-per-cluster)` corridors of three eNBs each |
| `make_e5_v2_p_only.py` | P-only variant of the V2 generator |

Common arguments: `--p-template`, `--joint-template`, `--out-root`, `--n`, `--rng-seed`, `--rng-run`. The V2 generator additionally accepts `--layout`, `--uavs-per-cluster`, `--site-spacing-m`, `--spread-y-m` and `--background-traffic`.

```bash
python3 scripts/e5/make_e5_v2_scenes.py \
  --p-template configs/scenarios/e2_pair_p.json \
  --joint-template configs/scenarios/e2_pair_a_joint.json \
  --out-root ./scenes/e5 --n 150 --layout fixed --rng-seed 33 --rng-run 3
```

Generated scenes and simulator outputs are written locally and ignored by Git. Run a generated scene with `scripts/run_one.sh` or `scripts/run_batch.sh` (`run_job.sh` is the single-job worker used by the batch driver). The ns-3 module overlay required by these scenes is in `simulation/e5/`; build and execution commands are listed in `docs/ENVIRONMENT.md`.

The 150-UAV concurrent-authentication experiments do not use separately named scene files: the same generators produce them with `--n 150` and the layout/background-traffic arguments above, and the batch drivers dispatch them. The shared modeled CPU pool used by all target applications is implemented in `simulation/e5/model/`.

## Additional E5 drivers

| Script | Purpose |
| --- | --- |
| `e5b_n500_formal4.py` | Four independently registered P-only formal seeds (N=500) in two waves |
| `e5b_n500_durable_autowaves.py` | Durable reboot-safe worker for the four-seed batch |
| `install_e5_v2.py` | SHA-guarded E5 V2 source overlay installer (dry run by default) |

These three scripts retain the absolute ECS build-tree paths they were written for; see the "N=500 formal seeds" section of `docs/ENVIRONMENT.md` before running them. The run-time evidence validator they reference is not part of this source-only repository and must be supplied externally.
