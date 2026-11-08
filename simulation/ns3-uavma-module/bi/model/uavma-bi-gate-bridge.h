// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <cstdint>
#include <functional>
#include <string>

namespace ns3 {
class UavmaBiGatedA3HandoverAlgorithm;
// Simulation instrumentation, not an on-wire Bi message. Its sole purpose is to
// relay an *actual* LTE A3 decision to the already-registered source-gNB proxy.
class BiGateBridge final {
 public:
  using OnOpportunity = std::function<void(std::uint64_t,std::uint16_t)>;
  static void SetController(OnOpportunity cb);
  static std::uint64_t Open(UavmaBiGatedA3HandoverAlgorithm* algorithm,
                            std::uint16_t rnti,std::uint16_t target,std::uint64_t localToken);
  static bool Approve(std::uint64_t correlation,std::uint16_t target,bool authenticated);
  static void OnTimeout(std::uint64_t correlation);
  static void RecordP(std::uint16_t rnti,std::uint16_t target,std::uint64_t nowNs);
  static void ExportPObservations(const std::string& filename);
  static void Reset();
};
} // namespace ns3
