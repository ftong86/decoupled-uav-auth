// UAV-Mobility-Auth formal core: root provider (software-stable root).
// The paper requires a PUF-assisted state signing credential: kappa_U = PUFEval(chi_U),
// kappa_d = KDF(kappa_U; DOMAINROOT, d). This module models a *software-stable* root.
// It is NEVER claimed to be a physical PUF: Tpuf stays symbolic (see docs/operation_ledger.md).
#ifndef UAVMA_ROOT_PROVIDER_H
#define UAVMA_ROOT_PROVIDER_H

#include <cstdint>

#include "uavma/bytes.h"

namespace uavma {

class RootProvider {
 public:
  explicit RootProvider(Bytes seed, Bytes challenge = text("fixed-challenge"));

  // One evaluation = one logical PUFEval. Called once per NEW M1 construction.
  Bytes puf_eval();
  // kappa_d = KDF(kappa_U; DOMAINROOT, d); does not re-invoke PUFEval.
  Bytes domain_root(char d);
  // Deterministic re-derivation used only to assert root stability.
  Bytes puf_eval_uncounted() const;

  uint64_t puf_calls() const { return puf_calls_; }

 private:
  Bytes seed_;
  Bytes challenge_;
  Bytes root_;
  Bytes last_kappa_;
  uint64_t puf_calls_ = 0;
};

}  // namespace uavma

#endif
