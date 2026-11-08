# Protocol-to-Code Mapping

This document maps the notation used in the paper to the functions in `protocol/`.

## Common Definitions

| Paper notation | Function | File |
| --- | --- | --- |
| `Enc(x1..xn)` — injective encoding with 4-byte length prefixes | `enc()`, `enc_vec()`, `append_enc()` | `include/uavma/bytes.h` |
| `Hash(tag; x1..xn) = H(Enc(tag, x1..xn))` | `hash_tag()` | `src/crypto.cpp` |
| `KDF(k; tag, x1..xn) = HMAC(k, Enc(tag, x1..xn))` | `kdf()` | `src/crypto.cpp` |
| `H2S(.)` — hash to scalar | `scalar_from_hash()` | `src/crypto.cpp` |
| `PUFEval_U(chi_U) -> kappa_U` | `RootProvider::puf_eval()` (symbolic evaluation) | `src/root_provider.cpp` |
| `kappa_d = KDF(kappa_U; DOMAINROOT, d)` | `RootProvider::domain_root()` | `src/root_provider.cpp` |
| `Cert_Td = (d, ID, PK^LT, sigma_cert)` | `CaCore::issue_cert()` / `verify_cert()` | `src/protocol_core.cpp` |
| `PID_d = Hash(PID; d, eta_d)` | `derive_pid()` | `src/protocol_core.cpp` |

## Message Flow

| Message | Generation | Processing |
| --- | --- | --- |
| `Authz^U_d`, `Authz^S_d` | `MobilityManager::authorize()`, `authz_u()`, `authz_s()` | `prepare_authorization()` in `src/harness.cpp` |
| `Transfer_d = {d, PID, ID_Td, e_d, S^C, Pi}` | `SourceCore::build_transfer()` | `TargetCore::accept_transfer()` |
| `M0 = {d, SID, X_T, Cert, PreAuth}` | `TargetCore::create_session()` | `UavCore::handle_m0()` |
| `M1 = {SID, rho^B, X_U, PK^N, sigma_U}` | `UavCore::build_m1()` | `TargetCore::handle_m1()` |
| `M2 = {SID, tau_T}` | `TargetCore::handle_m1()` | `UavCore::handle_m2()` |
| `M3 = {SID, tau_C}` | `UavCore::handle_m2()` | `TargetCore::handle_m3()` |

`M1` derives the next credential (`CV^N`, `sk^N`, `rho^N`, `delta_pend`) and signs the transcript with the evolved key. `M2` completes ECDH agreement and derives `K^cf`, `K^cm` and `K^s` through HKDF before computing `tau_T`. `M3` carries `tau_C` and triggers the atomic state commit.

## Persistence Points

| Moment | Location |
| --- | --- |
| Before sending M2 | `TargetCore::handle_m1()`: `save_pending()` and `save_session()` |
| Before sending M3 | `UavCore::handle_m2()`: `save_uav()` |
| After verifying M3 | `TargetCore::handle_m3()`: `save_committed()` and `save_pending(nullopt)` |

`World::crash_restart()` rebuilds the roles from the store with `UavCore::restore_from_store()` and `TargetCore::restore_from_store()`.

## Branches and Invariants

| Branch | Condition | Semantics |
| --- | --- | --- |
| `normal` | `pi_ == nullopt && rho_base == S^C.rho` | Ordinary transaction |
| `cached-retry` | `s.m2_sent` and the received M1 equals the cached bytes | Retransmission within one session; no new PUF evaluation or signature |
| `M2Recover` | `pi_ != nullopt && rho_base == S^C.rho` | Replaces the pending state without advancing `S^C` |
| `M3Recover` | `pi_ != nullopt && rho_base == Pi.next.rho` | Commits the previously activated pending state, then creates a new one |

`invariants_hold(su, sc, pi)` enforces `Pi.base.rho == S^C.rho` and `Pi.next.v == S^C.v + 1`. Rejected transactions (old epoch, expired session, unknown SID, inadmissible base rho, invalid state signature) leave `S^C`, `Pi` and the session state unchanged. `OpCounters` in `include/uavma/crypto.h` records hash, MAC, hash-to-scalar, sign, verify, ECDH and PUF operations, and `ByteAccount` records body and encoded message sizes.
