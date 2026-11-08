// UAV-Mobility-Auth formal core: root provider implementation.
#include "uavma/root_provider.h"

#include "uavma/crypto.h"

namespace uavma {

RootProvider::RootProvider(Bytes seed, Bytes challenge)
    : seed_(std::move(seed)), challenge_(std::move(challenge)) {
  last_kappa_ = kdf(seed_, "SOFTWARE_PUF", {challenge_});
}

Bytes RootProvider::puf_eval() {
  ++puf_calls_;
  ++counters().puf;
  last_kappa_ = kdf(seed_, "SOFTWARE_PUF", {challenge_});
  return last_kappa_;
}

Bytes RootProvider::puf_eval_uncounted() const {
  return kdf(seed_, "SOFTWARE_PUF", {challenge_});
}

Bytes RootProvider::domain_root(char d) {
  return kdf(last_kappa_, "DOMAINROOT", {text(std::string(1, d))});
}

}  // namespace uavma
