// SPDX-License-Identifier: GPL-2.0-only
#include "uavma-bi-gated-a3.h"
#include "uavma-bi-gate-bridge.h"
#include "bi_gate_hooks.h"

#include "ns3/abort.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/lte-common.h"
#include "ns3/simulator.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/uinteger.h"

#include <algorithm>

namespace ns3 {
NS_LOG_COMPONENT_DEFINE("UavmaBiGatedA3HandoverAlgorithm");
NS_OBJECT_ENSURE_REGISTERED(UavmaBiGatedA3HandoverAlgorithm);

TypeId UavmaBiGatedA3HandoverAlgorithm::GetTypeId() {
  static TypeId tid = TypeId("ns3::UavmaBiGatedA3HandoverAlgorithm")
    .SetParent<LteHandoverAlgorithm>()
    .SetGroupName("Lte")
    .AddConstructor<UavmaBiGatedA3HandoverAlgorithm>()
    .AddAttribute("Hysteresis", "A3 hysteresis (dB)", DoubleValue(3.0),
      MakeDoubleAccessor(&UavmaBiGatedA3HandoverAlgorithm::m_hysteresisDb),
      MakeDoubleChecker<std::uint8_t>(0.0, 15.0))
    .AddAttribute("TimeToTrigger", "A3 time to trigger", TimeValue(MilliSeconds(256)),
      MakeTimeAccessor(&UavmaBiGatedA3HandoverAlgorithm::m_timeToTrigger),
      MakeTimeChecker())
    .AddAttribute("ObserveOnly", "P control: record opportunity and pass A3 decision immediately",
      BooleanValue(false),
      MakeBooleanAccessor(&UavmaBiGatedA3HandoverAlgorithm::m_observeOnly),
      MakeBooleanChecker())
    .AddAttribute("GateTargetCellId", "Gate only the common G/E target cell",
      UintegerValue(3),
      MakeUintegerAccessor(&UavmaBiGatedA3HandoverAlgorithm::m_gateTargetCellId),
      MakeUintegerChecker<std::uint16_t>(1))
    .AddAttribute("PreparationTimeout", "Maximum wait for genuine verified Bi preparation",
      TimeValue(Seconds(2)),
      MakeTimeAccessor(&UavmaBiGatedA3HandoverAlgorithm::m_preparationTimeout),
      MakeTimeChecker())
    .AddTraceSource("PreparationOpportunity", "A3 selected target, prior to TriggerHandover",
      MakeTraceSourceAccessor(&UavmaBiGatedA3HandoverAlgorithm::m_prepOpportunity),
      "ns3::TracedCallback::Uint64Uint16Uint16")
    .AddTraceSource("PreparationOutcome", "Verified, failed, or timed-out Bi preparation",
      MakeTraceSourceAccessor(&UavmaBiGatedA3HandoverAlgorithm::m_prepOutcome),
      "ns3::TracedCallback::Uint64Uint16Uint16Uint8");
  return tid;
}

UavmaBiGatedA3HandoverAlgorithm::UavmaBiGatedA3HandoverAlgorithm() {
  m_provider = new MemberLteHandoverManagementSapProvider<UavmaBiGatedA3HandoverAlgorithm>(this);
}
UavmaBiGatedA3HandoverAlgorithm::~UavmaBiGatedA3HandoverAlgorithm() = default;
void UavmaBiGatedA3HandoverAlgorithm::SetLteHandoverManagementSapUser(
    LteHandoverManagementSapUser* user) { m_user = user; }
LteHandoverManagementSapProvider*
UavmaBiGatedA3HandoverAlgorithm::GetLteHandoverManagementSapProvider() {
  return m_provider;
}

void UavmaBiGatedA3HandoverAlgorithm::DoInitialize() {
  NS_ABORT_MSG_IF(!m_user, "LTE handover SAP user is missing");
  NS_ABORT_MSG_IF(m_preparationTimeout <= Time(0), "Bi preparation timeout must be positive");
  LteRrcSap::ReportConfigEutra cfg;
  cfg.eventId = LteRrcSap::ReportConfigEutra::EVENT_A3;
  cfg.a3Offset = 0;
  cfg.hysteresis = EutranMeasurementMapping::ActualHysteresis2IeValue(m_hysteresisDb);
  cfg.timeToTrigger = m_timeToTrigger.GetMilliSeconds();
  cfg.reportOnLeave = false;
  cfg.triggerQuantity = LteRrcSap::ReportConfigEutra::RSRP;
  cfg.reportInterval = LteRrcSap::ReportConfigEutra::MS1024;
  m_measIds = m_user->AddUeMeasReportConfigForHandover(cfg);
  LteHandoverAlgorithm::DoInitialize();
}

void UavmaBiGatedA3HandoverAlgorithm::DoReportUeMeas(
    std::uint16_t rnti, LteRrcSap::MeasResults results) {
  if (std::find(m_measIds.begin(), m_measIds.end(), results.measId) == m_measIds.end()) {
    return;
  }
  if (!results.haveMeasResultNeighCells || results.measResultListEutra.empty()) {
    return;
  }
  std::uint16_t targetCell = 0;
  std::uint8_t strongest = 0;
  for (const auto& neighbour : results.measResultListEutra) {
    if (neighbour.haveRsrpResult && neighbour.rsrpResult > strongest &&
        neighbour.physCellId != 0) {
      targetCell = neighbour.physCellId;
      strongest = neighbour.rsrpResult;
    }
  }
  if (!targetCell) return;
  if (m_observeOnly || targetCell != m_gateTargetCellId) {
    NS_LOG_INFO("E2B_GATE_DIRECT_OR_NONCOMPARISON rnti=" << rnti << " target=" << targetCell);
    m_prepOpportunity(0, rnti, targetCell); // token 0 identifies non-gated P
    if (m_observeOnly) BiGateBridge::RecordP(rnti,targetCell,
              static_cast<std::uint64_t>(Simulator::Now().GetNanoSeconds()));
    m_user->TriggerHandover(rnti, targetCell);
    return;
  }
  auto decision = m_gate.Start(rnti, targetCell, Simulator::Now().GetNanoSeconds(),
                               m_preparationTimeout.GetNanoSeconds());
  if (!decision.NewOpportunity()) return;
  auto old = m_timeouts.find(rnti);
  if (old != m_timeouts.end()) old->second.Cancel();
  m_timeouts[rnti] = Simulator::Schedule(m_preparationTimeout,
                &UavmaBiGatedA3HandoverAlgorithm::OnGateTimeout, this,
                rnti, decision.request.token);
  NS_LOG_INFO("E2B_GATE_BI_HOLD token=" << decision.request.token
               << " rnti=" << rnti << " target=" << targetCell);
  m_prepOpportunity(decision.request.token, rnti, targetCell);
  // Callback only starts real Bi socket traffic. It never directly authorizes.
  // If the Bi application is missing, the gate times out CLOSED.
  const std::uint64_t correlation =
      e2b::BiGateHooks::Notify(this, decision.request.token, rnti, targetCell);
  NS_ABORT_MSG_IF(correlation == 0, "Bi preparation did not return a valid correlation");
  m_correlations[rnti] = correlation;
  // Intentionally NO TriggerHandover here.
}

bool UavmaBiGatedA3HandoverAlgorithm::OnPreparationResult(
    std::uint16_t rnti, std::uint16_t targetCell, std::uint64_t token, bool verified) {
  if (m_observeOnly) return false;
  const auto answer = m_gate.Authorize(rnti, targetCell, token,
                                       Simulator::Now().GetNanoSeconds(), verified);
  if (answer.code == e2b::GateCode::Stale) return false;
  m_correlations.erase(rnti);
  auto old = m_timeouts.find(rnti);
  if (old != m_timeouts.end()) { old->second.Cancel(); m_timeouts.erase(old); }
  if (!answer.MayTriggerHandover()) {
    if (answer.code == e2b::GateCode::Rejected || answer.code == e2b::GateCode::Expired) {
      m_prepOutcome(token, rnti, targetCell, 2);
    }
    return false;
  }
  NS_LOG_INFO("E2B_GATE_BI_VERIFIED_RELEASE token=" << token
               << " rnti=" << rnti << " target=" << targetCell);
  m_prepOutcome(token, rnti, targetCell, 1);
  NS_ABORT_MSG_IF(!m_user, "LTE SAP user disposed before Bi preparation completion");
  m_user->TriggerHandover(rnti, targetCell);
  return true;
}

void UavmaBiGatedA3HandoverAlgorithm::OnGateTimeout(std::uint16_t rnti,
                                                       std::uint64_t token) {
  const auto answer = m_gate.Timeout(rnti, token, Simulator::Now().GetNanoSeconds());
  if (answer.code == e2b::GateCode::Expired) {
    m_timeouts.erase(rnti);
    auto cor=m_correlations.find(rnti);
    if(cor!=m_correlations.end()) { BiGateBridge::OnTimeout(cor->second); m_correlations.erase(cor); }
    NS_LOG_INFO("E2B_GATE_BI_TIMEOUT token=" << token << " rnti=" << rnti);
    m_prepOutcome(token, rnti, answer.request.target, 3);
  }
}
void UavmaBiGatedA3HandoverAlgorithm::DoDispose() {
  for (auto& kv : m_timeouts) kv.second.Cancel();
  m_timeouts.clear();
  m_gate.Clear();
  for(auto& item:m_correlations) BiGateBridge::OnTimeout(item.second);
  m_correlations.clear();
  m_user = nullptr;
  delete m_provider;
  m_provider = nullptr;
  LteHandoverAlgorithm::DoDispose();
}
} // namespace ns3
