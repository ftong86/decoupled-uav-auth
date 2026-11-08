# Cryptographic Benchmarks

The benchmark programs measure execution time with `std::chrono::steady_clock` over repeated samples.

| Directory | Sources | Timed operations |
| --- | --- | --- |
| `openssl-suite/` | `bench_openssl.cpp`, `bench_pairing.c`, `gen_typea_param.c` | SHA-256, HMAC, HKDF, ECDSA P-256, ECDH, RSA, PBC Type-A pairing |
| `primitives/` | `crypto_bench.cpp`, `crypto_bench_pbc128.cpp`, `crypto_bench_mvno.cpp`, `crypto_bench_cross_domain_mec_bls12381.cpp` | Elliptic-curve operations, BLS12-381 (herumi/mcl), 128-bit pairing, RSA and cross-domain/MEC primitives |

## Build and Run

From `benchmarks/`:

```bash
cd openssl-suite && make && bash run_all.sh
cd openssl-suite && make pairing param             # PBC/GMP pairing targets
cd primitives && bash run.sh                      # one repetition
cd primitives && MCL_ROOT=/path/to/mcl bash run_many.sh 10
```

`openssl-suite/Makefile` uses `pkg-config` for OpenSSL and `-lpbc -lgmp` for the optional pairing target; override `PBC_CFLAGS` / `PBC_LIBS` when PBC is installed outside the default paths. `primitives/CMakeLists.txt` requires OpenSSL, PBC, GMP and herumi/mcl (`MCL_ROOT` or system paths).

Raw timing samples are written locally and ignored by Git. Values quoted in the paper from other published studies are literature references rather than outputs of this code.
