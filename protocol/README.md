# C++17 protocol core and Linux-native experiments

Standalone implementation of the decoupled authentication protocol, independent of ns-3. It compiles with `g++ -std=c++17` against OpenSSL (`libcrypto`) and SQLite3.

## Layout

| Path | Purpose |
| --- | --- |
| `include/uavma/` | Protocol headers: byte encoding, crypto, state, sessions, persistence, transport, harness, experiment driver, service core. |
| `src/crypto.cpp` | SHA-256, HMAC-SHA256, HKDF-Extract/Expand, ECDSA P-256, ECDH P-256, hash-to-scalar, operation counters. |
| `src/protocol_core.cpp` | M0/M1/M2/M3 state machines, `normal` / `cached-retry` / `M2Recover` / `M3Recover` branches, epoch freshness, dual-domain isolation, state invariants. |
| `src/root_provider.cpp` | Symbolic PUF evaluation and domain-root derivation. |
| `src/state_store.cpp` | SQLite persistence at the three commit points and crash-restart recovery. |
| `src/harness.cpp`, `src/experiment_driver.cpp` | Controlled transaction preparation, timing and measurement ledgers. |
| `src/e1_main.cpp` | E1/S3: primitive micro-benchmarks, pure handler cost, full transaction latency. |
| `src/e3_main.cpp` | E3a clock-independence grid (`P` vs `A-Time`) and E3b M2/M3 loss-recovery matrix (`P` vs `A-Retry`). |
| `src/formal_main.cpp` | S2 multi-process node exercise. |
| `src/core.cpp` | Standalone cryptographic preflight (`auth_preflight`). |
| `tests/` | C++ unit tests for protocol core, recovery, persistence, service, transport, event policy, cell partition, CPU model and measurement ledger. |
| `scripts/` | `check_environment.sh`, `run_s2.sh`, `run_e1.sh`, `run_e3.sh`. |
| `ns3/uavma/` | ns-3 module sources and `sync_ns3_module.sh` for wiring them into an IoD-Sim build tree. |
| `docs/protocol_mapping.md` | Mapping from paper equations / messages to concrete functions. |

`src/` and `include/uavma/` are also copied verbatim into `simulation/ns3-uavma-module/core/` so the ns-3 module and the standalone build remain independently buildable.

## Build and test

```bash
make                  # auth_preflight + uavma_formal
make formal            # + uavma_e1, uavma_e3 and C++ test binaries
make test              # cryptographic smoke preflight
bash scripts/check_environment.sh
```

Header-only ns-3 policy tests can be compiled directly, e.g.:

```bash
g++ -std=c++17 -Iinclude -Ins3/uavma/model tests/test_uavma_event_policy.cpp -o /tmp/t_event && /tmp/t_event
```

## Experiment scripts

Each script writes into a fresh `<repository-root>/results/formal/<RUN_ID>/` directory and refuses to overwrite an existing run. `RUN_ID` can be set in the environment. Outputs are git-ignored.

```bash
bash scripts/run_s2.sh   # S2: protocol core, recovery, persistence, service, nodes
bash scripts/run_e1.sh   # E1/S3: Linux-native cost and handler calibration
bash scripts/run_e3.sh   # E3a + E3b: clock grid and loss-recovery matrix
```

## Honest boundaries

* `RootProvider::puf_eval()` counts PUF evaluations symbolically; it is not a physical PUF timing measurement.
* `A-Time` and `A-Retry` are comparison/ablation variants, not additional implementations of the proposed scheme.
* The standalone core runs transactions in one process; paper-level network latency figures come from the ns-3 module in `simulation/`.
