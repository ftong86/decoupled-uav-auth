# Tamarin Models

Five self-contained `.spthy` models for the formal security verification in the paper (Section VI-C, Fig. 4). No additional shared definition file is required.

| Model | File | Property family | Lemmas |
| --- | --- | --- | ---: |
| 01 | `01_normal_G.spthy` | Normal G-domain authentication and session-key secrecy/authentication | 7 |
| 02 | `02_recovery_G.spthy` | M2/M3 message loss and recovery | 8 |
| 03 | `03_dual_domain.spthy` | G/E binding, independent execution, state commit through M3 | 9 |
| 04 | `04_compromise.spthy` | Credential disclosure after session completion | 3 |
| 05 | `05_state_handoff_G_bounded.spthy` | Competing authorizations, successive handoffs and post-recovery commit order | 14 |

## Requirements

`tamarin-prover` with its Maude backend, Python 3 and Bash. A dry run does not require the prover.

## Commands

```bash
bash run_all.sh --dry-run                    # list models and lemmas, no proof
bash run_all.sh                              # prove every lemma of all five models
bash run_all.sh --model 03                   # prove only the dual-domain model
bash run_all.sh --timeout 600 --heap 4000M --threads 1
tamarin-prover 03_dual_domain.spthy --prove=<lemma>   # direct single-lemma invocation
```

`run_all.py` discovers the lemmas in each model, invokes the prover once per lemma and writes the verifier's raw output to a timestamped local `results/<run-id>/` directory together with `proof_lines.txt`. These verification artefacts are ignored by Git and are not distributed.
