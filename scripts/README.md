# Experiment drivers

| Script | Purpose |
| --- | --- |
| `make_scenes.py` | Generates HO12 (natural LTE A3-RSRP handover) and HO3 (controlled E-only) scenes for `P` and `A_JOINT` variants from a template, without touching any protocol field or cost table. |
| `run_one.sh` | Runs one IoD-Sim scene: `./ns3 run scenario --no-build -- --config=<scene> --RngSeed=33 --RngRun=<r>`. |
| `run_job.sh` | One formal batch job with a free-space guard; writes a unique output directory, never deletes prior runs. |
| `run_batch.sh` | Parallel driver over a job list: `run_batch.sh <joblist.txt> [workers] [start] [end]`. |

Absolute paths from the development machine were replaced with `IODSIM_ROOT` / `IODSIM_NS3_DIR` / `E2_WIN_ROOT` / `E2_WSL_ROOT` environment variables and with paths derived from the script location. Set `IODSIM_ROOT` to your IoD-Sim checkout before running.

```bash
python3 scripts/make_scenes.py \
  --template configs/scenarios/PNET_r03_reference.json \
  --root ./scenes --runs 3 --events HO12,HO3 --variants P,A_JOINT

IODSIM_ROOT=/path/to/IoD_Sim \
  bash scripts/run_one.sh /abs/path/to/scene.json /abs/path/to/run_dir 3
```

Generated scenes and run outputs are local and git-ignored.
