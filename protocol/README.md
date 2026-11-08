# C++17 Protocol Core

Standalone implementation of the decoupled authentication protocol, built with `g++ -std=c++17` against OpenSSL (`libcrypto`) and SQLite3. It does not depend on ns-3.

## Layout

| Path | Purpose |
| --- | --- |
| `include/uavma/` | Protocol headers: encoding, crypto, state, sessions, persistence, transport, harness and experiment driver |
| `src/crypto.cpp` | SHA-256, HMAC-SHA256, HKDF, ECDSA P-256, ECDH P-256 and operation counters |
| `src/protocol_core.cpp` | M0–M3 state machines, epoch freshness, normal / cached-retry / M2Recover / M3Recover branches, dual-domain isolation |
| `src/root_provider.cpp` | Symbolic PUF evaluation and domain-root derivation |
| `src/state_store.cpp` | SQLite persistence at the three commit points and crash-restart recovery |
| `src/e1_main.cpp` | Handler-cost calibration and full-transaction timing |
| `src/e3_main.cpp` | Clock-independence grid (`P` vs `A-Time`) and M2/M3 loss-recovery matrix (`P` vs `A-Retry`) |
| `src/formal_main.cpp`, `src/experiment_driver.cpp`, `src/harness.cpp` | Controlled transaction preparation and multi-process node exercise |
| `src/core.cpp` | Cryptographic preflight (`auth_preflight`) |
| `tests/` | Unit tests for the protocol core, recovery, persistence, service, transport and ns-3 policy headers |
| `scripts/` | Environment check and the S2 / E1 / E3 experiment drivers |
| `ns3/uavma/` | ns-3 module sources and the sync script for wiring them into an IoD-Sim build tree |
| `docs/protocol_mapping.md` | Mapping from paper messages and equations to concrete functions |

`src/` and `include/uavma/` are also copied into `simulation/ns3-uavma-module/core/` so the standalone build and the ns-3 module are each self-contained.

## Build and Test

```bash
make                       # auth_preflight + uavma_formal
make test                  # cryptographic preflight
make run-unit-tests        # build and run all C++ unit tests
bash scripts/check_environment.sh
```

## Experiment Scripts

```bash
bash scripts/run_s2.sh     # protocol core, recovery, persistence, service
bash scripts/run_e1.sh     # handler-cost calibration
bash scripts/run_e3.sh     # clock-offset grid and loss-recovery matrix
```

Each script creates a new run directory under `results/`; outputs are local and ignored by Git.

## Implementation Notes

* `RootProvider::puf_eval()` evaluates the PUF symbolically; it is not a physical PUF timing measurement.
* `A-Time` and `A-Retry` are comparison and ablation variants, not alternative implementations of the proposed scheme.
* The standalone core executes transactions within one process; network-level latency is measured by the ns-3 module in `simulation/`.
