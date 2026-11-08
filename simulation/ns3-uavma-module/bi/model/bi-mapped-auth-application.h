// SPDX-License-Identifier: GPL-2.0-only
// LTE/IP protocol-behavior mapping of Bi [11], NOT native 5G RACH signalling.
#pragma once
#include "bi_protocol_engine.h"
#include "ns3/application.h"
#include "ns3/socket.h"
#include "ns3/ipv4-address.h"
#include <cstdint>
#include <map>
#include <memory>
#include <string>

namespace ns3 {
class BiMappedAuthApplication final : public Application {
 public:
  static TypeId GetTypeId();
  BiMappedAuthApplication() = default;
  ~BiMappedAuthApplication() override = default;
 protected:
  void StartApplication() override;
  void StopApplication() override;
 private:
  void HandleRecv(Ptr<Socket> socket);
  void ConnectUeRrc();
  void OnRrcStart(std::uint64_t imsi,std::uint16_t cell,std::uint16_t rnti,std::uint16_t target);
  void OnRrcEnd(std::uint64_t imsi,std::uint16_t cell,std::uint16_t rnti);
  std::uint64_t currentHandoverCorr_=0;
  void OnDecision(std::uint64_t correlation, std::uint16_t target);
  void Dispatch(const e2b::EngineResult& result);
  void DispatchAfterCpu(e2b::EngineResult result, std::uint64_t corr,
                        std::uint64_t receivedAt, const std::string& operation);
  void ScheduleOutput(e2b::EngineResult result, std::uint64_t corr,
                      std::uint64_t receivedAt,const std::string& operation,
                      std::uint64_t hostDurationUs);
  std::uint64_t CpuServiceUs(const std::string& operation) const;
  void ParseProfile();
  e2b::Role Role() const;
  Ipv4Address DetermineOwnIp() const;

  Ptr<Socket> socket_;
  std::unique_ptr<e2b::BiProtocolEngine> engine_;
  std::map<std::string,std::uint64_t> serviceProfileUs_;
  std::map<std::uint64_t,std::uint16_t> targets_;
  std::uint64_t cpuAvailableNs_=0;
  std::uint32_t sequence_=0;
  std::string roleName_="S_GNB";
  std::string seedTag_="E2B_BI_REGISTRATION";
  std::string outputDir_;
  std::string cpuProfilePath_;
  std::uint16_t port_=9300;
  bool started_=false;
};
} // namespace ns3
