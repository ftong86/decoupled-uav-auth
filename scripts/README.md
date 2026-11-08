# Experiment Drivers

| Script | Purpose |
| --- | --- |
| `make_scenes.py` | Generates HO12 (natural LTE A3-RSRP handover) and HO3 (controlled E-only) scenes for `P` and `A_JOINT` from a template |
| `run_one.sh` | Runs one IoD-Sim scene: `./ns3 run scenario --no-build -- --config=<scene> --RngSeed=33 --RngRun=<r>` |
| `run_job.sh` | One batch job with a free-space guard and a unique output directory |
| `run_batch.sh` | Parallel driver over a job list: `run_batch.sh <joblist.txt> [workers] [start] [end]` |
| `e5/` | Multi-UAV / concurrent authentication scene generators (`--n`, `--layout`, `--uavs-per-cluster`); see `e5/README.md` |

Set `IODSIM_ROOT` to your IoD-Sim checkout (`IODSIM_NS3_DIR` overrides its `ns3` directory) before running the ns-3 drivers.

```bash
python3 scripts/make_scenes.py \
  --template configs/scenarios/PNET_r03_reference.json \
  --root ./scenes --runs 3 --events HO12,HO3 --variants P,A_JOINT

IODSIM_ROOT=/path/to/IoD_Sim \
  bash scripts/run_one.sh /abs/path/to/scene.json /abs/path/to/run_dir 3
```

Generated scenes and run outputs are written locally and ignored by Git.
