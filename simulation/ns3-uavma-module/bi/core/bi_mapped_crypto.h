// SPDX-License-Identifier: MIT
#pragma once
#include "bi_crypto_primitives.h"
#include "bi_fields.h"
#include <map>
#include <memory>
#include <string>
namespace e2b {
// This is explicitly an authenticated ECIES/AEAD implementation mapping the
// paper's generic ElGamal ciphertext and symmetric encryption notation.
// It is NOT a byte-for-byte reproduction of the unspecified ElGamal encoding.
Bytes SealEcies(const Bytes& recipientPublic, const Bytes& plain, const Bytes& aad);
Bytes OpenEcies(const EcKey& recipient, const Bytes& sealed, const Bytes& aad);
Bytes SealAesGcm(const Bytes& key32,const Bytes& plain,const Bytes& aad);
Bytes OpenAesGcm(const Bytes& key32,const Bytes& sealed,const Bytes& aad);
Bytes EstablishedKey(const std::string& seed,const std::string& domain);

// Independent registration domains. Public keys are published in this
// experiment's trusted pre-registration setup. CA issuance itself is outside
// the measured handover, as it is outside Bi's handover phase in the paper.
enum class Identity { UE_G, UE_E, S_GNB, T_GNB, S_MEH, T_MEH };
class Identities {
 public:
  const EcKey& Private(Identity id);
  Bytes Public(Identity id);
 private:
  std::map<Identity,EcKey> identities_;
};
} // namespace e2b
