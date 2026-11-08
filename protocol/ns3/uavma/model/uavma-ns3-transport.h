// UAV-Mobility-Auth S6: ns-3 transport backend.
//
// Purpose: carry the REAL, already-validated S2 protocol core (uavma::UavCore /
// uavma::TargetCore, canonical Enc framing) inside an ns-3.45 simulation so that
// UAV and infrastructure nodes exchange genuinely serialized AuthzU / M0 / M1 /
// M2 / M3 messages over real ns-3 sockets on top of the verified LTE A3-RSRP
// handover substrate.
//
// Hard rules honoured here:
//   * protocol_core is REUSED, never rewritten, never weakened: the epoch check in
//     UavCore::handle_m0 (m.epoch == authorized_epoch) is fed from the real AuthzU
//     message sent by the Mobility Manager, not from M0 itself.
//   * G and E domains stay independent (separate CA / MM / state / sessions).
//   * no protocol field, message or formula is modified; no byte is added to any
//     protocol message for measurement purposes (see UavmaRegistry below).
//   * four latency classes are recorded separately and never mixed.
#ifndef UAVMA_NS3_TRANSPORT_H
#define UAVMA_NS3_TRANSPORT_H

#include <ns3/address.h>
#include <ns3/application.h>
#include <ns3/event-id.h>
#include <ns3/ipv4-address.h>
#include <ns3/ptr.h>
#include <ns3/socket.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "uavma-cell-partition.h"
#include "uavma-measurement-ledger.h"
#include "uavma-p4-cpu-model.h"
#include "uavma/crypto.h"
#include "uavma/experiment_driver.h"
#include "uavma/linux_transport.h"
#include "uavma/protocol_core.h"
#include "uavma/root_provider.h"
#include "uavma/state_store.h"

namespace ns3 {

// ---------------------------------------------------------------------------
// Process-wide measurement registry.
//
// The whole ns-3 simulation runs in ONE process with ONE simulator clock, so a
// simulated timestamp recorded by the sender is directly comparable with one
// recorded by the receiver. This registry exists ONLY so that the receiver can
// recover an unambiguous sender attempt and compute one-way transport delay
// WITHOUT changing the protocol. If multiple identical attempts are pending,
// their physical identity cannot be inferred and the transport metric is N/A.
// ---------------------------------------------------------------------------
struct UavmaIoEvent {
  int64_t simNs = 0;
  bool recv = false;  // false = sent, true = received
  bool retrans = false;
  std::string sid;
  std::string msg;
};

class UavmaRegistry {
 public:
  static UavmaRegistry& Instance();

  void Reset();

  void RecordSend(const std::string& key, int64_t simNs);
  // Returns false for lost/ambiguous attempts; transport delay must be N/A.
  bool MatchRecvSend(const std::string& key, int64_t recvNs, int64_t& sendNs);
  void RecordWireSend(const std::string& sid, size_t framedBytes);
  uavma_ns3::WireUsage WireUsageFor(const std::string& sid) const;

  void AddCpuUs(const std::string& sid, double cpuUs);
  double CpuUs(const std::string& sid) const;
  void AddCalibratedCpu(const std::string& sid, int64_t serviceNs, int64_t queueNs);
  std::pair<int64_t, int64_t> CalibratedCpu(const std::string& sid) const;

  // Number of on-wire retransmission attempts, separately from transport delay.
  void AddRetrans(const std::string& key);
  uint32_t Retrans(const std::string& key) const;

  void AddCounters(const std::string& sid, const uavma::OpCounters& d);
  uavma::OpCounters Counters(const std::string& sid) const;

  void RecordIo(const UavmaIoEvent& e);
  const std::vector<UavmaIoEvent>& IoEvents() const { return io_; }

  void AddHandover(int64_t startNs, int64_t endNs, uint16_t targetCellId);
  const std::vector<std::array<int64_t, 3>>& Handovers() const { return hos_; }

 private:
  UavmaRegistry() = default;
  uavma_ns3::MeasurementLedger measurement_;
  std::map<std::string, double> cpu_;
  std::map<std::string, std::pair<int64_t, int64_t>> calibrated_;
  std::map<std::string, uint32_t> retrans_;
  std::map<std::string, uavma::OpCounters> cnt_;
  std::vector<UavmaIoEvent> io_;
  std::vector<std::array<int64_t, 3>> hos_;  // {startNs, endNs, targetCellId}
};

// ---------------------------------------------------------------------------
// One protocol transaction (one domain) as observed end to end.
// ---------------------------------------------------------------------------
struct UavmaTxRecord {
  uint64_t id = 0;
  char domain = 'G';
  std::string eventType;  // G_only | E_only | GE
  std::string variant;    // P | A_JOINT
  std::string trigger;    // natural_handover | controlled_injection
  std::string sid;
  std::string targetId;   // configured target, never synthesize a physical migration
  uint64_t epoch = 0;
  bool committed = false;
  std::string branch;
  std::string reason;
  int64_t tTriggerNs = 0; // infrastructure learned of the mobility event
  int64_t tStartNs = 0;   // M0 emitted (infrastructure side)
  int64_t tCommitNs = 0;  // M3 committed (infrastructure side)
  double cpuUs = 0.0;     // real host handler time, kept separate
  int64_t calibratedServiceNs = 0; // E1 modeled handler service, not host time
  int64_t calibratedQueueNs = 0; // E1 modeled CPU lane waiting
  std::string cpuResourceMode = "UNCALIBRATED";
  std::string e1ProfileSha256;
  uint32_t committedV = 0;
  uint64_t puf = 0, sign = 0, verify = 0, mac = 0, hash = 0, ecdh = 0;
  size_t bodyUl = 0, bodyDl = 0, bodyInf = 0, bodyMm = 0, framed = 0;
  size_t nMsg = 0;  // attempted on-wire UDP authentication datagrams, including retries
};

// Per-message transport record (one row per delivered protocol message).
struct UavmaMsgRecord {
  uint64_t txId = 0;
  char domain = 'G';
  std::string eventType;
  std::string trigger;
  std::string msg;  // AuthzU / M0 / M1 / M2 / M3
  std::string dir;  // UL (UAV->infra) or DL (infra->UAV)
  int64_t sendNs = 0;
  int64_t recvNs = 0;
  double transportMs = 0.0;
  double handlerCpuUs = 0.0;
  size_t framedBytes = 0;
  bool delivered = true;
  uint32_t retrans = 0;  // retransmissions before this delivery
};

// CSV / JSONL evidence writers. Files are created fresh; nothing is overwritten.
class UavmaMetrics {
 public:
  bool Open(const std::string& prefix);
  void Msg(const UavmaMsgRecord& m);
  void Tx(const UavmaTxRecord& t);
  void Handover(int idx, int64_t startNs, int64_t endNs, uint16_t cellId, double protoGapMs,
                int inWindowSent, int inWindowDelivered);
  // Full send/receive event dump: lets a lost datagram be distinguished from a
  // datagram that was never emitted. Evidence for failure localisation.
  void IoEvents(const std::vector<UavmaIoEvent>& ev);
  void UavState(const std::string& sid, char dom, uint32_t v, int64_t simNs);
  void CpuSchedule(const std::string& role, const std::string& sid, char dom,
                   const std::string& stage, const uavma_ns3::CpuReservation& plan,
                   const std::string& cpuMode, const std::string& profileSha);
  void Close();
  const std::string& Dir() const { return dir_; }

 private:
  std::string dir_;
  std::ofstream fMsg_, fTx_, fHo_, fSt_, fIo_, fCpu_;
};

// ---------------------------------------------------------------------------
// Per-domain role bundle.
// ---------------------------------------------------------------------------
struct UavmaDomainWorld {
  uavma::Domain d = uavma::Domain::G;
  std::string targetId;
  uavma::Bytes seed;
  std::unique_ptr<uavma::RootProvider> root;
  std::unique_ptr<uavma::CaCore> ca;
  std::unique_ptr<uavma::MobilityManager> mm;  // infrastructure side only
  std::unique_ptr<uavma::TargetCore> target;   // infrastructure side only
  std::unique_ptr<uavma::SourceCore> src;      // infrastructure side only
  std::unique_ptr<uavma::UavCore> uav;         // UAV side only
  uint64_t authorizedEpoch = 0;                // UAV side: learned from AuthzU
  bool authorized = false;
};

// ---------------------------------------------------------------------------
// The ns-3 application. One instance per node; Role selects UAV or infrastructure.
// ---------------------------------------------------------------------------
class UavmaAuthApplication : public Application {
 public:
  static TypeId GetTypeId();
  UavmaAuthApplication();
  ~UavmaAuthApplication() override;

  // Trigger channel (simulation plumbing, NOT protocol traffic). Used only to
  // (a) let the infrastructure learn the UAV's address at attach, and
  // (b) let the UAV report that a real LTE handover just completed so that the
  //     G-domain transaction is triggered by a genuinely occurring network event.
  // These frames are never counted in any protocol latency and carry no protocol field.
  static const uint8_t kTriggerAttach = 0x01;
  static const uint8_t kTriggerHandover = 0x02;

 protected:
  void DoDispose() override;

 private:
  void StartApplication() override;
  void StopApplication() override;

  void SetupSockets();
  void HandleRead(Ptr<Socket> socket);
  void HandleTriggerRead(Ptr<Socket> socket);
  void ConnectHandoverTraces();

  // UAV side handlers
  void OnAuthzU(const uavma::AuthzUMsg& m, char dom);
  void OnM0(const uavma::M0Msg& m, char dom);
  void OnM2(const uavma::M2Msg& m, char dom);

  // Infrastructure side handlers
  void OnM1(uint64_t txId, char dom, const uavma::M1Msg& m);
  void OnM3(uint64_t txId, char dom, const uavma::M3Msg& m);

  void BeginTransaction(char dom, const std::string& eventType, const std::string& trigger,
                        int64_t triggerNs, const uavma_ns3::CpuReservation& preparation);
  uavma_ns3::CpuReservation ReserveCpu(char dom, const std::vector<std::string>& stages,
                                      const std::string& sid);
  void LogCpu(const std::string& sid, char dom, const std::vector<std::string>& stages,
              const uavma_ns3::CpuReservation& planned);
  void BeginMobilityEvent(int eventKind, const std::string& trigger);

  int64_t SendProtocol(const uavma::Bytes& framed, const std::string& msg, const std::string& sid,
                       char dom, const std::string& dir, const std::string& altKey = "",
                       bool isRetrans = false);
  void SendTrigger(uint8_t type);
  void SendHandoverTrigger(std::uint16_t fromCell, std::uint16_t toCell);
  bool ApplyPartitionDecision(const uavma_ns3::PartitionDecision& plan);
  bool HasUnresolvedAuthentication() const;
  void RecordRecvCommon(UavmaMsgRecord& r, const std::string& sid, const std::string& key);

  UavmaDomainWorld& World(char dom);

  void OnHandoverStart(uint64_t imsi, uint16_t cellId, uint16_t rnti, uint16_t targetCellId);
  void OnHandoverEndOk(uint64_t imsi, uint16_t cellId, uint16_t rnti);

  void SchedulePeriodic();
  void PeriodicTick();
  void FinalizeTransactions();

  // ---- bounded retransmission (application-level ARQ).
  // Retransmissions reuse the cached protocol message, so they take the protocol's
  // cached-retry path: no additional PUFEval, no additional signature.
  void OnUavM1Rto(std::string sid);
  void OnInfraM0Rto(std::string sid);
  void OnInfraM2Rto(std::string sid);

  // ---- attributes
  std::string m_role;     // "UAV" or "TARGET"
  std::string m_variantName = "P";  // P | A_JOINT; trigger policy only
  bool m_testDropFirstM3 = false;  // preflight-only fault injection
  bool m_testM3DropInjected = false;
  std::string m_domains;  // "G", "E" or "GE"
  std::string m_peerIp;
  uint16_t m_peerPort = 9000;
  uint16_t m_localPort = 9000;
  uint16_t m_triggerPort = 9001;
  std::string m_seedTag = "uavma-s6";
  std::string m_gTargetId = "GS_T1";
  std::string m_eTargetId = "ES_T1";
  std::string m_cellToEdgeText;  // empty = unchanged legacy technical experiments
  uint16_t m_initialCellId = 0;  // mandatory if CellToEdgeMap configured
  std::string m_outputPrefix = "uavma-e2";
  std::string m_storePath;  // empty -> no durable store
  bool m_verbose = false;
  double m_ePeriodSec = 0.0;
  double m_eStartSec = 10.0;
  double m_geInjectSec = -1.0;
  bool m_triggerGOnHandover = true;
  std::string m_e1HandlerCosts; // canonical 12-entry E1 handler table, from verified JSON
  std::string m_e1ProfileSha256; // SHA256 of original E1 cost_profile.json
  std::string m_cpuResourceMode = "PER_DOMAIN"; // or SHARED; equal between variants

  // ---- runtime
  bool m_isUav = false;
  bool m_running = false;
  bool m_cpuCalibrated = false;
  std::map<std::string, double> m_e1Costs;
  uavma_ns3::CpuQueueModel m_cpuQueue;
  bool m_hasG = true;
  bool m_hasE = false;
  bool m_partitionEnabled = false;
  uint16_t m_currentCellId = 0;
  uavma_ns3::CellToEdge m_cellToEdge;
  Ptr<Socket> m_socket;
  Ptr<Socket> m_triggerSocket;
  Ipv4Address m_peerFullAddr;
  bool m_peerKnown = false;
  UavmaDomainWorld m_g;
  UavmaDomainWorld m_e;
  std::unique_ptr<uavma::StateStore> m_store;
  std::unique_ptr<uavma::EventLog> m_log;
  uavma::VariantConfig m_variant;

  std::map<uint64_t, UavmaTxRecord> m_tx;
  uint64_t m_nextTxId = 1;
  std::map<std::string, uint64_t> m_sidToTx;  // sid -> tx id (infrastructure)
  std::map<std::string, char> m_sidDomain;    // sid -> domain  (infrastructure)
  std::map<std::string, char> m_uavSidDomain;  // sid -> domain  (UAV)
  struct UavSess {
    char dom = 'G';
    int m1Sent = 0;
    bool gotM2 = false;  // only after a valid M2 was authenticated
    uavma::Bytes acceptedM2Tau;  // authenticated tag for cached-M3 replay
    int64_t m3CachedStartNs = -1;
    uint32_t m3ReplayCount = 0;
    EventId rto;
  };
  struct InfraSess {
    char dom = 'G';
    uint64_t txId = 0;
    int m0Sent = 0;
    int m2Sent = 0;
    bool gotM1 = false;
    bool gotM3 = false;
    EventId rto;
  };
  std::map<std::string, UavSess> m_uavSess;
  std::map<std::string, InfraSess> m_infraSess;
  std::map<std::string, uavma::Bytes> m_frames;  // "sid|msg" -> framed bytes for retransmit
  double m_rtoMs = 250.0;
  uint32_t m_maxRetrans = 3;
  int64_t m_hoStartNs = -1;
  int64_t m_hoEndNs = -1;
  uint16_t m_hoTargetCell = 0;
  uint16_t m_hoSourceCell = 0;
  int m_hoCount = 0;
  EventId m_periodicEvent;
  UavmaMetrics m_metrics;
};

}  // namespace ns3

#endif  // UAVMA_NS3_TRANSPORT_H
