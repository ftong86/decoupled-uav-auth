// SPDX-License-Identifier: GPL-2.0-only
#include "uavma-bi-gate-bridge.h"
#include "bi_gate_hooks.h"
#include "uavma-bi-gated-a3.h"
#include <map>
#include <filesystem>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <utility>

namespace ns3 {
namespace {
struct Entry { UavmaBiGatedA3HandoverAlgorithm* algorithm; std::uint16_t rnti,target;
               std::uint64_t localToken; };
std::map<std::uint64_t,Entry> awaiting;
std::uint64_t nextCorrelation=0;
struct PRow { std::uint16_t rnti,target;std::uint64_t time; };
std::vector<PRow> pObservations;
BiGateBridge::OnOpportunity controller;
}
void BiGateBridge::SetController(OnOpportunity cb) { controller=std::move(cb); }
std::uint64_t BiGateBridge::Open(UavmaBiGatedA3HandoverAlgorithm* algorithm,
                                std::uint16_t rnti,std::uint16_t target,std::uint64_t token) {
  if(!algorithm || !rnti || !target || !token || !controller)
    throw std::logic_error("Bi A3 decision lacks a registered source gNB controller");
  const auto id=++nextCorrelation;
  awaiting.emplace(id,Entry{algorithm,rnti,target,token});
  controller(id,target);
  return id;
}
bool BiGateBridge::Approve(std::uint64_t id,std::uint16_t target,bool authenticated) {
  auto it=awaiting.find(id);
  if(it==awaiting.end() || it->second.target!=target) return false;
  const auto entry=it->second;
  awaiting.erase(it);
  return entry.algorithm->OnPreparationResult(entry.rnti,entry.target,
                                              entry.localToken,authenticated);
}
void BiGateBridge::OnTimeout(std::uint64_t id) { awaiting.erase(id); }
void BiGateBridge::RecordP(std::uint16_t rnti,std::uint16_t target,std::uint64_t nowNs) {
  pObservations.push_back({rnti,target,nowNs});
}
void BiGateBridge::ExportPObservations(const std::string& filename) {
  if(std::filesystem::exists(filename))throw std::runtime_error("refuse overwrite P observation CSV");
  std::ofstream f(filename);
  if(!f)throw std::runtime_error("cannot create P observation CSV");
  f<<"rnti,target_cell,pre_command_opportunity_ns\n";
  for(const auto& row:pObservations)f<<row.rnti<<','<<row.target<<','<<row.time<<'\n';
}
void BiGateBridge::Reset() { awaiting.clear(); controller={};nextCorrelation=0;pObservations.clear(); }
} // namespace ns3

namespace e2b {
// The A3 algorithm calls this only after selecting a genuine target cell.
// Open() requires a registered Bi controller and invokes its real protocol
// Begin() path through BiMappedAuthApplication::OnDecision().
std::uint64_t BiGateHooks::Notify(
    ns3::UavmaBiGatedA3HandoverAlgorithm* algorithm,
    std::uint64_t localToken,
    std::uint16_t rnti,
    std::uint16_t targetCell) {
  return ns3::BiGateBridge::Open(algorithm, rnti, targetCell, localToken);
}
} // namespace e2b

