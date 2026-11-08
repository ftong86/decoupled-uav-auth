// E5-only simulation CPU resource model.  Not part of cryptographic protocol.
// Dedicated TARGET application per UAV retains protocol state, but all such
// apps on the same ns-3 infrastructure Node must share modeled CPU lanes.
#ifndef UAVMA_E5_CPU_POOL_H
#define UAVMA_E5_CPU_POOL_H
#include "uavma-p4-cpu-model.h"
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <tuple>

namespace uavma_ns3 {
class E5SharedNodeCpuPool {
 public:
  static E5SharedNodeCpuPool& Instance() {
    static E5SharedNodeCpuPool pool;
    return pool;
  }
  CpuReservation Reserve(uint32_t nodeId, const std::string& mode,
                         int64_t nowNs, char domain, int64_t serviceNs) {
    auto it = pools_.find(nodeId);
    if (it == pools_.end()) {
      it = pools_.emplace(std::piecewise_construct,
          std::forward_as_tuple(nodeId), std::forward_as_tuple(mode)).first;
    } else if (it->second.Mode() != mode) {
      throw std::invalid_argument("E5 shared node CPU mode mismatch");
    }
    return it->second.Reserve(nowNs, domain, serviceNs);
  }
  // Only for independent unit tests, not mid-simulation; each ns-3 scenario
  // should run in a fresh process, as in the E2/E4 formal runner.
  void ResetForTest() { pools_.clear(); }
 private:
  E5SharedNodeCpuPool() = default;
  std::map<uint32_t, CpuQueueModel> pools_;
};
}  // namespace uavma_ns3
#endif
