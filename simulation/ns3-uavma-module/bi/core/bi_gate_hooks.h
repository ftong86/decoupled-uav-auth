// SPDX-License-Identifier: GPL-2.0-only
// Forwarding interface between a real A3 opportunity and the registered
// Bi source-gNB application. This does NOT authorize a handover.
#pragma once

#include <cstdint>

namespace ns3 {
class UavmaBiGatedA3HandoverAlgorithm;
}

namespace e2b {
class BiGateHooks final {
public:
  // Returns the correlation id owned by BiGateBridge.
  // Throws if the source-gNB controller is not registered (fail closed).
  static std::uint64_t Notify(
      ns3::UavmaBiGatedA3HandoverAlgorithm* algorithm,
      std::uint64_t localToken,
      std::uint16_t rnti,
      std::uint16_t targetCell);
};
} // namespace e2b
