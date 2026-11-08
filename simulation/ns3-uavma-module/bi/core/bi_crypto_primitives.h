// SPDX-License-Identifier: MIT
// Bi[11] section IV cryptographic building blocks, NOT the complete protocol.
// OpenSSL EC secp256k1. SHA-256 of compressed point is an explicit encoding
// convention for integration testing; its exact mapping to Bi's H[point] notation
// must be declared in the final reproducibility specification.
#pragma once

#include <openssl/evp.h>
#include <openssl/bn.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace e2b {
using Bytes = std::vector<std::uint8_t>;
using Digest32 = std::array<std::uint8_t, 32>;

class EcKey final {
 public:
  static EcKey Generate();
  static EcKey ImportPublic(const Bytes& encoded);
  EcKey(EcKey&&) noexcept = default;
  EcKey& operator=(EcKey&&) noexcept = default;
  EcKey(const EcKey&) = delete;
  EcKey& operator=(const EcKey&) = delete;

  Bytes PublicPoint() const;
  Bytes SignSha256(const Bytes& message) const;
  bool VerifySha256(const Bytes& message, const Bytes& signature) const;
  bool HasPrivateKey() const;
  // Returns private scalar only for implementation of Bi's (r+Sk) derivation.
  // Do not serialize or log this value.
  std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> PrivateScalar() const;
 private:
  explicit EcKey(EVP_PKEY* pkey);
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key_;
};

struct BiEphemeral final {
  BiEphemeral();
  BiEphemeral(BiEphemeral&&) noexcept = default;
  BiEphemeral& operator=(BiEphemeral&&) noexcept = default;
  BiEphemeral(const BiEphemeral&) = delete;
  BiEphemeral& operator=(const BiEphemeral&) = delete;
  static BiEphemeral Generate();
  Bytes point;
  std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> scalar;
};

// Bi[11] formula: H[(r_own + Sk_own) (R_peer + Pk_peer)]
// Peer computes H[(r_peer + Sk_peer) (R_own + Pk_own)].
Digest32 EvolveDomainKey(const EcKey& own, const BiEphemeral& ephemeral,
                         const Bytes& peerPublicPoint, const Bytes& peerEphemeralPoint);
Digest32 Sha256(const Bytes& data);
} // namespace e2b
