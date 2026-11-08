# Scenario configurations

IoD-Sim JSON scene files. These are input configurations, not experimental results. All output/log/state paths inside them were rewritten to relative `./results/...` locations so they can be used on any machine; the protocol, crypto, radio and mobility parameters are unchanged.

| File | Purpose |
| --- | --- |
| `scenarios/e2_lte_ho_protocol.json` | LTE A3-RSRP handover baseline used by the G-domain / handover experiments. |
| `scenarios/PNET_r03_reference.json` | Three-cell natural-handover reference template used by `scripts/make_scenes.py`. |
| `scenarios/E2_frozen_ho3_pair_p.json` | Controlled HO3 (E-only) minimal template. |
| `scenarios/e2_pair_p.json` | Formal paired run for the proposed scheme (`P`). |
| `scenarios/e2_pair_a_joint.json` | Formal paired run for the joint trigger policy (`A_JOINT`). |
| `scenarios/e2_m3_loss_test_p.json` | M3 loss / state-recovery test scene. |

Use them with the ns-3 `scenario` executable (`--config=<file>`), or as the `--template` argument of `scripts/make_scenes.py`. `resultsPath` and all state/log paths point into a local `./results/` tree that the simulation creates at run time; that tree is git-ignored.

No clock-configuration file named C0/C1 exists in this snapshot: the controlled clock-offset grid is generated in code by `protocol/src/e3_main.cpp` (E3a) rather than read from a JSON file. No concurrency scenario (150 UAV / 3 eNB / 25–150 requests per 20 ms) exists in this snapshot.
