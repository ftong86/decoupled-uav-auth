// UAV-Mobility-Auth formal core: cryptographic primitives.
// Implements the primitives named by the paper:
//   Hash(tag; x1..xn) = H(Enc(tag, x1..xn))                       (Eq.1)
//   KDF(k; tag, x1..xn) = HMAC-SHA256(k, Enc(tag, x1..xn))        (Eq.1)
//   ECDSA P-256 sign/verify, ECDH P-256, HKDF-Extract/Expand, H2S (hash-to-scalar)
// Every primitive call increments an instrumented counter so that the S0
// operation ledger can be re-checked against real execution in S2/S3.
#ifndef UAVMA_CRYPTO_H
#define UAVMA_CRYPTO_H

#include <cstdint>
#include <string>
#include <vector>

#include "uavma/bytes.h"

namespace uavma {

// Instrumented primitive counters. Mapping to paper symbols is recorded in the
// output metadata (Th/Tsg/Tsv/Thm/Th2s/Tpuf); raw counts are kept separate so no
// mapping assumption can silently distort the ledger comparison.
struct OpCounters {
  uint64_t hash = 0;      // SHA-256 calls                    -> Th
  uint64_t mac = 0;       // HMAC-SHA256 calls (KDF/MAC)      -> Thm
  uint64_t sign = 0;      // ECDSA signatures                 -> Tsg
  uint64_t verify = 0;    // ECDSA verifications              -> Tsv
  uint64_t h2s = 0;       // hash-to-scalar (state key deriv.)-> Th2s
  uint64_t ecdh = 0;      // ECDH shared secret computations
  uint64_t puf = 0;       // root-provider evaluations         -> Tpuf (symbolic cost)
  uint64_t pts_mul = 0;   // EC point multiplications (public key derivation)
  void reset() { *this = OpCounters{}; }
  OpCounters operator-(const OpCounters& o) const {
    OpCounters r;
    r.hash = hash - o.hash;
    r.mac = mac - o.mac;
    r.sign = sign - o.sign;
    r.verify = verify - o.verify;
    r.h2s = h2s - o.h2s;
    r.ecdh = ecdh - o.ecdh;
    r.puf = puf - o.puf;
    r.pts_mul = pts_mul - o.pts_mul;
    return r;
  }
};

OpCounters& counters();
void reset_counters();

Bytes sha256(const Bytes& b);
Bytes hash_tag(const std::string& tag, const std::vector<Bytes>& xs);  // Eq.(1)
Bytes hmac_sha256(const Bytes& key, const Bytes& b);
Bytes kdf(const Bytes& key, const std::string& tag, const std::vector<Bytes>& xs);  // Eq.(1)
Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm);
Bytes hkdf_expand(const Bytes& prk, const Bytes& info);
Bytes random_bytes(size_t n);

// P-256 group helpers. Public keys use 33-byte compressed points.
Bytes scalar_from_hash(const Bytes& h);          // H2S
Bytes pubkey_from_scalar(const Bytes& sk);       // sk * P
Bytes ecdh_shared(const Bytes& sk, const Bytes& peer_pk_compressed);
Bytes ecdsa_sign(const Bytes& sk, const Bytes& digest);   // raw r||s, 64 bytes
bool ecdsa_verify(const Bytes& pk_compressed, const Bytes& digest, const Bytes& sig);
Bytes compress_point(const void* ec_point);      // internal helper, declared for tests

}  // namespace uavma

#endif
