# Tamarin models (paper Section VI-C, Fig. 4)

Five final `.spthy` models used for the formal security verification in the paper.

| Model | File | Property family | Defined lemmas |
| --- | --- | --- | ---: |
| 01 | `01_normal_G.spthy` | Normal G-domain authentication and session-key secrecy/authentication | 7 |
| 02 | `02_recovery_G.spthy` | M2/M3 message loss and recovery | 8 |
| 03 | `03_dual_domain.spthy` | G/E binding, independent execution, state commit through M3 | 9 |
| 04 | `04_compromise.spthy` | Credential disclosure after session completion | 3 |
| 05 | `05_state_handoff_G_bounded.spthy` | Competing authorizations, successive handoffs, post-recovery commit order (bounded) | 14 |

The models are self-contained `.spthy` files; no additional shared definition file is required.

## Requirements

`tamarin-prover` (with its Maude backend), `python3` (standard library only) and `bash`. A dry run does not need the prover.

## Commands

```bash
bash run_all.sh --dry-run                    # list models and lemmas, no proof
bash run_all.sh                              # prove every lemma of all five models
bash run_all.sh --model 03                   # prove only the dual-domain model
bash run_all.sh --timeout 600 --heap 4000M --threads 1
tamarin-prover 03_dual_domain.spthy --prove=<lemma>   # direct single-lemma invocation
```

`run_all.py` discovers lemmas from each model, invokes the prover once per lemma and records the verifier's raw stdout. Every invocation creates a fresh timestamped `results/<run-id>/` directory containing logs, `verification_summary.txt`, `results.csv` and HTML summary pages. These are verification artefacts, are git-ignored, and are **not** published.

The 41 defined lemmas are not a claim that all 41 were proved: the true status is whatever the verifier prints on the machine that runs it. This release does not include any stored proof output or screenshot.
