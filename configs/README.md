# Scenario Configurations

IoD-Sim JSON scene files used as input to the ns-3 `scenario` executable (`--config=<file>`) or as the `--template` argument of `scripts/make_scenes.py`. They are input configurations, not experimental results.

| File | Purpose |
| --- | --- |
| `scenarios/e2_lte_ho_protocol.json` | LTE A3-RSRP handover baseline |
| `scenarios/PNET_r03_reference.json` | Three-cell natural-handover reference template |
| `scenarios/E2_frozen_ho3_pair_p.json` | Controlled HO3 (E-only) template |
| `scenarios/e2_pair_p.json` | Paired run for the proposed scheme (`P`) |
| `scenarios/e2_pair_a_joint.json` | Paired run for the joint trigger policy (`A_JOINT`) |
| `scenarios/e2_m3_loss_test_p.json` | M3 loss and state-recovery scene |

`resultsPath` and the state and log paths point into a local `./results/` tree created at run time and ignored by Git. Clock-offset and message-loss variants are generated in code by `protocol/src/e3_main.cpp` and `scripts/make_scenes.py`.
