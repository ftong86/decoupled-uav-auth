// SPDX-License-Identifier: GPL-2.0-only
// Independently authored ns-3.45 LTE A3 adapter, based on the ns-3 A3-RSRP
// handover algorithm API (B. Herman, 2013). E2-B DEVELOPMENT ONLY.
#pragma once

#include "bi_gate_state.h"

#include "ns3/event-id.h"
#include "ns3/lte-handover-algorithm.h"
#include "ns3/lte-handover-management-sap.h"
#include "ns3/nstime.h"
#include "ns3/traced-callback.h"

#include <cstdint>
#include <map>
#include <vector>

namespace ns3 {

// This REPLACES (does not wrap) the standard A3 handover algorithm in a Bi
// development scene. TriggerHandover is called only after verified preparation.
// It does NOT implement Bi authentication; that remains a separate application.
class UavmaBiGatedA3HandoverAlgorithm final : public LteHandoverAlgorithm {
 public:
  static TypeId GetTypeId();
  UavmaBiGatedA3HandoverAlgorithm();
  ~UavmaBiGatedA3HandoverAlgorithm() override;

  void SetLteHandoverManagementSapUser(LteHandoverManagementSapUser* user) override;
  LteHandoverManagementSapProvider* GetLteHandoverManagementSapProvider() override;

  // Called by the externally validated Bi preparation engine, for this source
  // eNB's algorithm instance. A forged/stale token NEVER releases handover.
  // NOTE: verified is NOT established here. The real Bi verifier must supply it.
  bool OnPreparationResult(std::uint16_t rnti, std::uint16_t targetCell,
                           std::uint64_t token, bool verified);

  // SAP member provider needs access to DoReportUeMeas.
  friend class MemberLteHandoverManagementSapProvider<UavmaBiGatedA3HandoverAlgorithm>;

 protected:
  void DoInitialize() override;
  void DoDispose() override;
  void DoReportUeMeas(std::uint16_t rnti, LteRrcSap::MeasResults results) override;

 private:
  void OnGateTimeout(std::uint16_t rnti, std::uint64_t token);
  std::vector<std::uint8_t> m_measIds;
  double m_hysteresisDb = 3.0;
  Time m_timeToTrigger = MilliSeconds(256);
  Time m_preparationTimeout = Seconds(2);
  std::uint16_t m_gateTargetCellId = 3; // Only the common G/E handover is a Bi trial.
  bool m_observeOnly = false;  // P control: identical A3, immediate TriggerHandover
  LteHandoverManagementSapUser* m_user = nullptr;
  LteHandoverManagementSapProvider* m_provider = nullptr;
  e2b::GateState m_gate;
  std::map<std::uint16_t, EventId> m_timeouts;
  std::map<std::uint16_t, std::uint64_t> m_correlations;

  // (token,rnti,target) fires inside decision, BEFORE any Handover Command.
  TracedCallback<std::uint64_t, std::uint16_t, std::uint16_t> m_prepOpportunity;
  // (token,rnti,target,outcome) outcome: 1=verified release,2=failed,3=timeout.
  TracedCallback<std::uint64_t, std::uint16_t, std::uint16_t, std::uint8_t> m_prepOutcome;
};

} // namespace ns3
