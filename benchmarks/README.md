# Cryptographic benchmarks (paper Tables II and III)

All benchmark executables measure **real execution time** using `std::chrono::steady_clock` over repeated samples; they do not read pre-computed paper values.

| Directory | Sources | What is timed |
| --- | --- | --- |
| `openssl-suite/` | `bench_openssl.cpp`, `bench_pairing.c`, `gen_typea_param.c` | SHA-256, HMAC, HKDF, ECDSA P-256 sign/verify, ECDH, RSA, PBC Type-A pairing and related operations. |
| `primitives/` | `crypto_bench.cpp`, `crypto_bench_pbc128.cpp`, `crypto_bench_mvno.cpp`, `crypto_bench_cross_domain_mec_bls12381.cpp` | Extended primitive suite including elliptic-curve operations, BLS12-381 (herumi/mcl), 128-bit pairing baseline, RSA/modular exponentiation and cross-domain/MEC primitives. |

## Build / run

```bash
cd openssl-suite && make && bash run_all.sh
# optional PBC/GMP pairing targets:
cd openssl-suite && make pairing param && bash run_all.sh

cd primitives && bash run.sh                  # one repetition
cd primitives && MCL_ROOT=/path/to/mcl bash run_many.sh 10   # ten repetitions
```

`openssl-suite/Makefile` uses `pkg-config` for OpenSSL and `-lpbc -lgmp` for the optional pairing target; override `PBC_CFLAGS` / `PBC_LIBS` if PBC is installed outside the default paths. `primitives/CMakeLists.txt` requires OpenSSL, PBC, GMP and herumi/mcl (`MCL_ROOT` or system paths).

Outputs (`results_<timestamp>/`, `results/`, `build*`, `params/a_160_512.param` when generated) are local only and git-ignored.

## Scope

The drivers in this repository build and execute the timing programs and record raw samples. The statistical summarisation, operation-count cost substitution and any plotting/table-generation programs used to derive the published tables are deliberately **not** included. Some comparison values in the paper are taken from cited external literature rather than measured locally; those are literature values, not outputs of this code.
