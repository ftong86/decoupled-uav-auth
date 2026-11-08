// UAV-Mobility-Auth S6: ns-3 transport backend (implementation).
//
// Latency classes recorded here are kept strictly separate:
//   (a) transport      : one-way sim delay for unambiguous send/receive pairs only;
//                        ambiguous retransmissions use -1 (not a measured delay).
//   (b) handler        : REAL host CPU time spent inside protocol_core (steady_clock).
//                        ns-3 simulated time does not advance during computation, so a
//                        real clock is the only correct instrument for this class.
//   (c) auth completion: simulated time from M0 emission to M3 commit (network inclusive);
//                        the CPU-only sum is recorded as a separate column.
//   (d) interruption   : handover window from LteUeRrc traces + protocol delivery gap.
#include "uavma-ns3-transport.h"
#include "uavma-event-policy.h"

#include <ns3/boolean.h>
#include <ns3/double.h>
#include <ns3/inet-socket-address.h>
#include <ns3/log.h>
#include <ns3/lte-ue-net-device.h>
#include <ns3/lte-ue-rrc.h>
#include <ns3/node.h>
#include <ns3/nstime.h>
#include <ns3/packet.h>
#include <ns3/simulator.h>
#include <ns3/string.h>
#include <ns3/uinteger.h>
#include <ns3/udp-socket-factory.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <openssl/crypto.h>
#include <sys/stat.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("UavmaAuthApplication");
NS_OBJECT_ENSURE_REGISTERED(UavmaAuthApplication);

namespace {
int64_t SimNs() {
  return Simulator::Now().GetNanoSeconds();
}
double CpuUs() {
  return std::chrono::duration<double, std::micro>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
std::string S(double v) {
  char b[64];
  std::snprintf(b, sizeof(b), "%.6f", v);
  return std::string(b);
}
std::string I(long long v) {
  return std::to_string(v);
}
uavma::Bytes ShaSeedTag(const std::string& tag, char dom) {
  return uavma::sha256(uavma::text("uavma-s6-" + tag + "-" + std::string(1, dom)));
}
void EnsureDir(const std::string& d) {
  if (d.empty()) return;
  std::string acc;
  for (size_t i = 0; i < d.size(); ++i) {
    if (d[i] == '/') {
      if (!acc.empty()) ::mkdir(acc.c_str(), 0755);
    }
    acc.push_back(d[i]);
  }
  if (!acc.empty()) ::mkdir(acc.c_str(), 0755);
}
}  // namespace

// ---------------------------------------------------------------------------
// UavmaRegistry
// ---------------------------------------------------------------------------
UavmaRegistry& UavmaRegistry::Instance() {
  static UavmaRegistry r;
  return r;
}
void UavmaRegistry::Reset() {
  measurement_.Reset();
  cpu_.clear();
  calibrated_.clear();
  retrans_.clear();
  cnt_.clear();
  io_.clear();
  hos_.clear();
}
void UavmaRegistry::RecordSend(const std::string& key, int64_t simNs) {
  measurement_.NoteSend(key, simNs);
}
bool UavmaRegistry::MatchRecvSend(const std::string& key, int64_t recvNs,
                                  int64_t& sendNs) {
  return measurement_.MatchReceive(key, recvNs, sendNs);
}
void UavmaRegistry::RecordWireSend(const std::string& sid, size_t framedBytes) {
  measurement_.NoteWireSend(sid, framedBytes);
}
uavma_ns3::WireUsage UavmaRegistry::WireUsageFor(const std::string& sid) const {
  return measurement_.Usage(sid);
}
void UavmaRegistry::AddCpuUs(const std::string& sid, double us) {
  cpu_[sid] += us;
}
double UavmaRegistry::CpuUs(const std::string& sid) const {
  auto it = cpu_.find(sid);
  return it == cpu_.end() ? 0.0 : it->second;
}
void UavmaRegistry::AddCalibratedCpu(const std::string& sid, int64_t serviceNs, int64_t queueNs) {
  auto& total = calibrated_[sid];
  total.first += serviceNs;
  total.second += queueNs;
}
std::pair<int64_t, int64_t> UavmaRegistry::CalibratedCpu(const std::string& sid) const {
  auto it = calibrated_.find(sid);
  return it == calibrated_.end() ? std::make_pair(int64_t(0), int64_t(0)) : it->second;
}
void UavmaRegistry::AddRetrans(const std::string& key) {
  retrans_[key] += 1;
}
uint32_t UavmaRegistry::Retrans(const std::string& key) const {
  auto it = retrans_.find(key);
  return it == retrans_.end() ? 0u : it->second;
}
void UavmaRegistry::AddCounters(const std::string& sid, const uavma::OpCounters& d) {
  uavma::OpCounters& c = cnt_[sid];
  c.hash += d.hash;
  c.mac += d.mac;
  c.sign += d.sign;
  c.verify += d.verify;
  c.h2s += d.h2s;
  c.ecdh += d.ecdh;
  c.puf += d.puf;
  c.pts_mul += d.pts_mul;
}
uavma::OpCounters UavmaRegistry::Counters(const std::string& sid) const {
  auto it = cnt_.find(sid);
  return it == cnt_.end() ? uavma::OpCounters{} : it->second;
}
void UavmaRegistry::RecordIo(const UavmaIoEvent& e) {
  io_.push_back(e);
}
void UavmaRegistry::AddHandover(int64_t startNs, int64_t endNs, uint16_t targetCellId) {
  hos_.push_back({startNs, endNs, static_cast<int64_t>(targetCellId)});
}

// ---------------------------------------------------------------------------
// UavmaMetrics
// ---------------------------------------------------------------------------
bool UavmaMetrics::Open(const std::string& prefix) {
  dir_ = prefix;
  // Historical traces are immutable: never silently truncate an existing run.
  for (const auto& name : {"uavma_auth_completion.csv", "uavma_transport_metrics.csv",
                           "uavma_handover.csv", "uavma_uav_state.csv",
                           "uavma_io_events.csv", "uavma_cpu_schedule.csv", "uavma_events.jsonl"}) {
    struct stat prior{};
    if (::stat((dir_ + "/" + name).c_str(), &prior) == 0)
      throw std::runtime_error("UAVMA refuses to overwrite existing run: " + dir_);
  }
  fMsg_.open(dir_ + "/uavma_transport_metrics.csv", std::ios::out | std::ios::trunc);
  fTx_.open(dir_ + "/uavma_auth_completion.csv", std::ios::out | std::ios::trunc);
  fHo_.open(dir_ + "/uavma_handover.csv", std::ios::out | std::ios::trunc);
  fSt_.open(dir_ + "/uavma_uav_state.csv", std::ios::out | std::ios::trunc);
  fIo_.open(dir_ + "/uavma_io_events.csv", std::ios::out | std::ios::trunc);
  fCpu_.open(dir_ + "/uavma_cpu_schedule.csv", std::ios::out | std::ios::trunc);
  fMsg_ << "tx_id,domain,event_type,trigger,msg,dir,send_sim_ms,recv_sim_ms,"
           "transport_sim_ms,handler_cpu_us,framed_bytes,delivered,retrans\n";
  fTx_ << "tx_id,domain,event_type,trigger,variant,sid,target_id,epoch,committed,branch,reason,"
          "t_start_sim_ms,t_commit_sim_ms,auth_complete_sim_ms,auth_complete_cpu_ms,"
          "committed_v,puf,sign,verify,mac,hash,ecdh,body_ul,body_dl,body_inf,body_mm,"
          "framed_total,n_msg,trigger_recv_sim_ms,trigger_to_commit_sim_ms,"
          "calibrated_service_us,calibrated_queue_us,cpu_resource_mode,e1_profile_sha256\n";
  fHo_ << "ho_index,ho_start_sim_ms,ho_end_sim_ms,rrc_window_ms,target_cell_id,"
          "proto_delivery_gap_ms,in_window_sent,in_window_delivered\n";
  fSt_ << "sid,domain,uav_v,t_sim_ms\n";
  fIo_ << "sim_ms,direction,retrans,msg,sid\n";
  fCpu_ << "role,sid,domain,stages,arrival_sim_ms,start_sim_ms,finish_sim_ms,"
           "calibrated_service_us,queue_wait_us,cpu_resource_mode,e1_profile_sha256\n";
  fMsg_.flush();
  fTx_.flush();
  fHo_.flush();
  fSt_.flush();
  fIo_.flush();
  fCpu_.flush();
  return fMsg_.good() && fTx_.good() && fHo_.good() && fSt_.good() && fCpu_.good();
}
void UavmaMetrics::Msg(const UavmaMsgRecord& m) {
  if (!fMsg_.is_open()) return;
  fMsg_ << m.txId << ',' << m.domain << ',' << m.eventType << ',' << m.trigger << ',' << m.msg
        << ',' << m.dir << ',' << S(m.sendNs / 1e6) << ',' << S(m.recvNs / 1e6) << ','
        << S(m.transportMs) << ',' << S(m.handlerCpuUs) << ',' << m.framedBytes << ','
        << (m.delivered ? 1 : 0) << ',' << m.retrans << '\n';
  fMsg_.flush();
}
void UavmaMetrics::Tx(const UavmaTxRecord& t) {
  if (!fTx_.is_open()) return;
  double simMs = t.committed ? (t.tCommitNs - t.tStartNs) / 1e6 : -1.0;
  double triggerMs = t.committed ? (t.tCommitNs - t.tTriggerNs) / 1e6 : -1.0;
  fTx_ << t.id << ',' << t.domain << ',' << t.eventType << ',' << t.trigger << ','
       << t.variant << ',' << t.sid << ',' << t.targetId << ','
       << t.epoch << ',' << (t.committed ? 1 : 0) << ',' << t.branch << ',' << t.reason << ','
       << S(t.tStartNs / 1e6) << ',' << S(t.tCommitNs / 1e6) << ',' << S(simMs) << ','
       << S(t.cpuUs / 1000.0) << ',' << t.committedV << ',' << t.puf << ',' << t.sign << ',' << t.verify
       << ',' << t.mac << ',' << t.hash << ',' << t.ecdh << ',' << t.bodyUl << ',' << t.bodyDl
       << ',' << t.bodyInf << ',' << t.bodyMm << ',' << t.framed << ',' << t.nMsg
       << ',' << S(t.tTriggerNs / 1e6) << ',' << S(triggerMs)
       << ',' << S(t.cpuResourceMode == "UNCALIBRATED" ? -1.0 : t.calibratedServiceNs / 1000.0)
       << ',' << S(t.cpuResourceMode == "UNCALIBRATED" ? -1.0 : t.calibratedQueueNs / 1000.0)
       << ',' << t.cpuResourceMode << ',' << t.e1ProfileSha256 << '\n';
  fTx_.flush();
}
void UavmaMetrics::Handover(int idx, int64_t startNs, int64_t endNs, uint16_t cellId,
                            double protoGapMs, int inWindowSent, int inWindowDelivered) {
  if (!fHo_.is_open()) return;
  fHo_ << idx << ',' << S(startNs / 1e6) << ',' << S(endNs / 1e6) << ','
       << S((endNs - startNs) / 1e6) << ',' << cellId << ',' << S(protoGapMs) << ',' << inWindowSent
       << ',' << inWindowDelivered << '\n';
  fHo_.flush();
}
void UavmaMetrics::UavState(const std::string& sid, char dom, uint32_t v, int64_t simNs) {
  if (!fSt_.is_open()) return;
  fSt_ << sid << ',' << dom << ',' << v << ',' << S(simNs / 1e6) << '\n';
  fSt_.flush();
}
void UavmaMetrics::IoEvents(const std::vector<UavmaIoEvent>& ev) {
  if (!fIo_.is_open()) return;
  for (const auto& e : ev) {
    fIo_ << S(e.simNs / 1e6) << ',' << (e.recv ? "RECV" : "SEND") << ',' << (e.retrans ? "R" : "-")
         << ',' << e.msg << ',' << e.sid << '\n';
  }
  fIo_.flush();
}
void UavmaMetrics::CpuSchedule(const std::string& role, const std::string& sid, char dom,
                               const std::string& stages, const uavma_ns3::CpuReservation& plan,
                               const std::string& mode, const std::string& sha) {
  if (!fCpu_.is_open()) return;
  fCpu_ << role << ',' << sid << ',' << dom << ',' << stages
        << ',' << S(plan.arrivalNs / 1e6) << ',' << S(plan.startNs / 1e6)
        << ',' << S(plan.finishNs / 1e6) << ',' << S(plan.serviceNs / 1000.0)
        << ',' << S(plan.queueNs / 1000.0) << ',' << mode << ',' << sha << '\n';
  fCpu_.flush();
}
void UavmaMetrics::Close() {
  if (fMsg_.is_open()) fMsg_.close();
  if (fTx_.is_open()) fTx_.close();
  if (fHo_.is_open()) fHo_.close();
  if (fSt_.is_open()) fSt_.close();
  if (fIo_.is_open()) fIo_.close();
  if (fCpu_.is_open()) fCpu_.close();
}

// ---------------------------------------------------------------------------
// TypeId
// ---------------------------------------------------------------------------
TypeId UavmaAuthApplication::GetTypeId() {
  static TypeId tid =
      TypeId("ns3::UavmaAuthApplication")
          .SetParent<Application>()
          .SetGroupName("Applications")
          .AddConstructor<UavmaAuthApplication>()
          .AddAttribute("Role", "UAV or TARGET (infrastructure: MM + source + target).",
                        StringValue("UAV"), MakeStringAccessor(&UavmaAuthApplication::m_role),
                        MakeStringChecker())
          .AddAttribute("Domains", "Which domains this instance serves: G, E or GE.",
                        StringValue("GE"), MakeStringAccessor(&UavmaAuthApplication::m_domains),
                        MakeStringChecker())
          .AddAttribute("Variant", "Trigger policy: P or A_JOINT (both domains share resources).",
                        StringValue("P"), MakeStringAccessor(&UavmaAuthApplication::m_variantName),
                        MakeStringChecker())
          .AddAttribute("TestDropFirstM3", "TEST/PREFLIGHT ONLY: intentionally drop exactly one UAV M3; false by default.",
                        BooleanValue(false), MakeBooleanAccessor(&UavmaAuthApplication::m_testDropFirstM3),
                        MakeBooleanChecker())
          .AddAttribute("PeerIp", "Peer IPv4 address (UAV: infrastructure address).",
                        StringValue("200.0.0.1"),
                        MakeStringAccessor(&UavmaAuthApplication::m_peerIp), MakeStringChecker())
          .AddAttribute("PeerPort", "Peer UDP port for protocol messages.", UintegerValue(9000),
                        MakeUintegerAccessor(&UavmaAuthApplication::m_peerPort),
                        MakeUintegerChecker<uint16_t>())
          .AddAttribute("LocalPort", "Local UDP port for protocol messages.", UintegerValue(9000),
                        MakeUintegerAccessor(&UavmaAuthApplication::m_localPort),
                        MakeUintegerChecker<uint16_t>())
          .AddAttribute("TriggerPort", "Local UDP port for the simulation trigger channel.",
                        UintegerValue(9001),
                        MakeUintegerAccessor(&UavmaAuthApplication::m_triggerPort),
                        MakeUintegerChecker<uint16_t>())
          .AddAttribute("SeedTag", "Seed tag for deterministic long-term configuration.",
                        StringValue("uavma-s6"),
                        MakeStringAccessor(&UavmaAuthApplication::m_seedTag), MakeStringChecker())
          .AddAttribute("GTargetId", "G-domain target identifier (e.g. GS_T1).",
                        StringValue("GS_T1"),
                        MakeStringAccessor(&UavmaAuthApplication::m_gTargetId),
                        MakeStringChecker())
          .AddAttribute("ETargetId", "E-domain target identifier (e.g. ES_T1).",
                        StringValue("ES_T1"),
                        MakeStringAccessor(&UavmaAuthApplication::m_eTargetId),
                        MakeStringChecker())
          .AddAttribute("CellToEdgeMap", "Fixed logical LTE-cell-to-edge-server partition; e.g. 1:ES_T1,2:ES_T2. "
                        "Empty preserves legacy experiment trigger semantics; no E4 service migration.",
                        StringValue(""), MakeStringAccessor(&UavmaAuthApplication::m_cellToEdgeText),
                        MakeStringChecker())
          .AddAttribute("InitialCellId", "Initial observed LTE serving cell; mandatory in partition mode.",
                        UintegerValue(0), MakeUintegerAccessor(&UavmaAuthApplication::m_initialCellId),
                        MakeUintegerChecker<uint16_t>())
          .AddAttribute("OutputPrefix", "Directory for CSV / JSONL evidence.",
                        StringValue("uavma-e2"),
                        MakeStringAccessor(&UavmaAuthApplication::m_outputPrefix),
                        MakeStringChecker())
          .AddAttribute("StorePath", "SQLite durable-state path (empty disables persistence).",
                        StringValue(""), MakeStringAccessor(&UavmaAuthApplication::m_storePath),
                        MakeStringChecker())
          .AddAttribute("Verbose", "Log per-message detail.", BooleanValue(false),
                        MakeBooleanAccessor(&UavmaAuthApplication::m_verbose),
                        MakeBooleanChecker())
          .AddAttribute("EPeriodSec",
                        "Controlled E-only injection period in simulated seconds (0 disables).",
                        DoubleValue(0.0), MakeDoubleAccessor(&UavmaAuthApplication::m_ePeriodSec),
                        MakeDoubleChecker<double>())
          .AddAttribute("EStartSec", "First controlled E-only injection time (simulated s).",
                        DoubleValue(10.0), MakeDoubleAccessor(&UavmaAuthApplication::m_eStartSec),
                        MakeDoubleChecker<double>())
          .AddAttribute("GeInjectSec",
                        "Controlled GE injection time (simulated s, negative disables).",
                        DoubleValue(-1.0),
                        MakeDoubleAccessor(&UavmaAuthApplication::m_geInjectSec),
                        MakeDoubleChecker<double>())
          .AddAttribute("TriggerGOnHandover",
                        "Start the G-domain transaction when a real LTE handover completes.",
                        BooleanValue(true),
                        MakeBooleanAccessor(&UavmaAuthApplication::m_triggerGOnHandover),
                        MakeBooleanChecker())
          .AddAttribute("E1HandlerCostsUs", "Validated 12-stage E1 measured handler costs, encoded as name=mean_us;...; empty disables calibrated processing.",
                        StringValue(""), MakeStringAccessor(&UavmaAuthApplication::m_e1HandlerCosts),
                        MakeStringChecker())
          .AddAttribute("E1ProfileSha256", "SHA256 provenance of the original E1 cost_profile.json.",
                        StringValue(""), MakeStringAccessor(&UavmaAuthApplication::m_e1ProfileSha256),
                        MakeStringChecker())
          .AddAttribute("CpuResourceMode", "CPU resource capacity: independent G/E lanes or a single shared lane, identical for P/A.",
                        StringValue("PER_DOMAIN"), MakeStringAccessor(&UavmaAuthApplication::m_cpuResourceMode),
                        MakeStringChecker())
          .AddAttribute("RtoMs", "Retransmission timeout in simulated milliseconds.",
                        DoubleValue(250.0), MakeDoubleAccessor(&UavmaAuthApplication::m_rtoMs),
                        MakeDoubleChecker<double>())
          .AddAttribute("MaxRetrans", "Maximum retransmissions per protocol message.",
                        UintegerValue(3),
                        MakeUintegerAccessor(&UavmaAuthApplication::m_maxRetrans),
                        MakeUintegerChecker<uint32_t>());
  return tid;
}

UavmaAuthApplication::UavmaAuthApplication() {}
UavmaAuthApplication::~UavmaAuthApplication() {}

// Out-of-class definitions: these constants are bound by Simulator::Schedule, which
// odr-uses them, so a definition is required even though they are initialised inline.
const uint8_t UavmaAuthApplication::kTriggerAttach;
const uint8_t UavmaAuthApplication::kTriggerHandover;

void UavmaAuthApplication::DoDispose() {
  m_socket = nullptr;
  m_triggerSocket = nullptr;
  Application::DoDispose();
}

// ---------------------------------------------------------------------------
// start / stop
// ---------------------------------------------------------------------------
void UavmaAuthApplication::StartApplication() {
  m_isUav = (m_role == "UAV" || m_role == "Uav" || m_role == "uav");
  m_hasG = m_domains.find('G') != std::string::npos;
  m_hasE = m_domains.find('E') != std::string::npos;
  uavma_ns3::Variant checkedVariant;
  if (!uavma_ns3::ParseVariant(m_variantName, &checkedVariant))
    throw std::invalid_argument("UAVMA Variant must be P or A_JOINT");
  if (m_hasE && m_hasG && m_eTargetId == m_gTargetId)
    throw std::invalid_argument("UAVMA G/E target IDs must differ for AuthzU demultiplexing");
  if (checkedVariant == uavma_ns3::Variant::AJoint && (!m_hasG || !m_hasE))
    throw std::invalid_argument("UAVMA A_JOINT requires both G and E domains");
  m_variant.joint_trigger = (checkedVariant == uavma_ns3::Variant::AJoint);
  m_variant.id = m_variantName;
  m_cpuQueue.SetMode(m_cpuResourceMode);
  m_cpuCalibrated = !m_e1HandlerCosts.empty();
  if (m_cpuCalibrated) {
    if (m_e1ProfileSha256.size() != 64 ||
        !std::all_of(m_e1ProfileSha256.begin(), m_e1ProfileSha256.end(),
                     [](unsigned char c){ return std::isxdigit(c) != 0; }))
      throw std::invalid_argument("E1ProfileSha256 must be the original 64-hex digest");
    m_e1Costs = uavma_ns3::ParseE1CostProfile(m_e1HandlerCosts);
  } else if (!m_e1ProfileSha256.empty()) {
    throw std::invalid_argument("E1 profile digest provided without calibrated handler costs");
  }
  m_running = true;

  m_partitionEnabled = !m_cellToEdgeText.empty();
  if (m_partitionEnabled) {
    if (!m_isUav && (!m_hasG || !m_hasE))
      throw std::invalid_argument("partition model requires both G and E domain actors");
    if (!m_hasG || !m_hasE || !m_triggerGOnHandover)
      throw std::invalid_argument("partition model requires GE and real LTE handover tracing");
    if (m_ePeriodSec > 0.0 || m_geInjectSec > 0.0)
      throw std::invalid_argument("controlled E/GE injection is prohibited in natural partition mode");
    m_cellToEdge = uavma_ns3::ParseCellToEdge(m_cellToEdgeText);
    if (m_initialCellId == 0 || !m_cellToEdge.count(m_initialCellId))
      throw std::invalid_argument("initial serving LTE cell missing from CellToEdgeMap");
    for (const auto& entry : m_cellToEdge) {
      if (entry.second == uavma_ns3::GTargetForCell(entry.first))
        throw std::invalid_argument("G and E target IDs collide in partition model");
    }
    if (m_gTargetId != uavma_ns3::GTargetForCell(m_initialCellId) ||
        m_eTargetId != m_cellToEdge.at(m_initialCellId))
      throw std::invalid_argument("initial G/E target attributes must match InitialCellId mapping");
    m_currentCellId = m_initialCellId;
  }

  const std::string dir = m_outputPrefix + (m_isUav ? "_uav" : "_infra");
  EnsureDir(m_outputPrefix);
  EnsureDir(dir);
  m_metrics.Open(dir);
  m_log = std::make_unique<uavma::EventLog>(dir + "/uavma_events.jsonl", false);
  if (!m_storePath.empty()) {
    struct stat oldState{};
    if (::stat(m_storePath.c_str(), &oldState) == 0)
      throw std::runtime_error("UAVMA refuses to reuse prior run's SQLite store: " + m_storePath);
    m_store = std::make_unique<uavma::StateStore>(m_storePath);
  }

  auto initDomain = [&](UavmaDomainWorld& w, char dom) {
    w.d = (dom == 'E') ? uavma::Domain::E : uavma::Domain::G;
    w.targetId = (dom == 'E') ? m_eTargetId : m_gTargetId;
    w.seed = ShaSeedTag(m_seedTag, dom);
    w.root = std::make_unique<uavma::RootProvider>(w.seed);
    w.ca = std::make_unique<uavma::CaCore>(w.d, w.seed);
    if (m_isUav) {
      w.uav = std::make_unique<uavma::UavCore>(w.d, w.seed, m_variant, *w.root, m_store.get(),
                                               m_log.get());
    } else {
      w.mm = std::make_unique<uavma::MobilityManager>(w.d, w.seed);
      uavma::Bytes dr = w.root->domain_root(uavma::domain_char(w.d));
      w.target = std::make_unique<uavma::TargetCore>(w.d, w.targetId,
                                                    w.ca->target_lt_sk(w.targetId), dr, w.seed,
                                                    m_variant, m_store.get(), m_log.get());
      w.target->set_cert_sig(w.ca->issue_cert(w.targetId, w.ca->target_lt_pk(w.targetId)));
      w.src = std::make_unique<uavma::SourceCore>(w.d, w.target->pid());
    }
  };
  if (m_hasG) initDomain(m_g, 'G');
  if (m_hasE) initDomain(m_e, 'E');

  SetupSockets();

  if (m_isUav) {
    ConnectHandoverTraces();
    // Simulation plumbing: let the infrastructure learn the UAV address so it can emit
    // M0 later. Not a protocol message; never counted in any latency class.
    Simulator::Schedule(Seconds(0.5), &UavmaAuthApplication::SendTrigger, this, kTriggerAttach);
  } else {
    SchedulePeriodic();
  }
  if (m_log) {
    m_log->event("app_start", {{"role", m_isUav ? "UAV" : "INFRA"},
                               {"domains", m_domains},
                               {"variant", m_variantName},
                               {"test_drop_first_m3", m_testDropFirstM3 ? "true" : "false"},
                               {"node", I(GetNode()->GetId())},
                               {"t_sim_ms", S(SimNs() / 1e6)}});
    m_log->event("e1_cpu_model_configured", {
      {"calibrated", m_cpuCalibrated ? "true" : "false"},
      {"profile_sha256", m_e1ProfileSha256},
      {"resource_mode", m_cpuResourceMode},
      {"measurement_type", m_cpuCalibrated ? "ns3_calibrated_linux_pure_handler_E1" : "network_only"}});
    if (m_partitionEnabled)
      m_log->event("fixed_partition_configured", {
          {"cell_to_edge_map", m_cellToEdgeText},
          {"initial_cell_id", I(m_currentCellId)},
          {"logical_edge_assignment_only", "true"}});
  }
}

void UavmaAuthApplication::StopApplication() {
  m_running = false;
  if (m_periodicEvent.IsPending()) Simulator::Cancel(m_periodicEvent);
  if (!m_isUav) {
    FinalizeTransactions();
  } else {
    // Full send/receive dump (distinguishes "never emitted" from "lost in flight").
    m_metrics.IoEvents(UavmaRegistry::Instance().IoEvents());
    // Interruption class (d): handover window + protocol-observed delivery gap.
    const auto& ho = UavmaRegistry::Instance().Handovers();
    const auto& io = UavmaRegistry::Instance().IoEvents();
    for (size_t i = 0; i < ho.size(); ++i) {
      int64_t sNs = ho[i][0], eNs = ho[i][1];
      int64_t lastRecvBefore = -1, firstRecvAfter = -1;
      int inSent = 0, inDelivered = 0;
      for (const auto& e : io) {
        if (!e.recv && e.simNs >= sNs && e.simNs <= eNs) {
          ++inSent;
          bool got = false;
          for (const auto& r : io) {
            if (r.recv && r.simNs > e.simNs && r.sid == e.sid && r.msg == e.msg) {
              got = true;
              break;
            }
          }
          if (got) ++inDelivered;
        }
        if (e.recv) {
          if (e.simNs <= sNs) lastRecvBefore = e.simNs;
          if (e.simNs >= eNs && firstRecvAfter < 0) firstRecvAfter = e.simNs;
        }
      }
      double gap = -1.0;
      if (lastRecvBefore >= 0 && firstRecvAfter >= 0) gap = (firstRecvAfter - lastRecvBefore) / 1e6;
      m_metrics.Handover(static_cast<int>(i), sNs, eNs, static_cast<uint16_t>(ho[i][2]), gap,
                         inSent, inDelivered);
    }
  }
  m_metrics.Close();
  if (m_log) m_log->close();
}

void UavmaAuthApplication::SetupSockets() {
  m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
  m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_localPort));
  m_socket->SetRecvCallback(MakeCallback(&UavmaAuthApplication::HandleRead, this));

  m_triggerSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
  m_triggerSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_triggerPort));
  m_triggerSocket->SetRecvCallback(MakeCallback(&UavmaAuthApplication::HandleTriggerRead, this));
}

void UavmaAuthApplication::ConnectHandoverTraces() {
  Ptr<Node> node = GetNode();
  for (uint32_t i = 0; i < node->GetNDevices(); ++i) {
    Ptr<LteUeNetDevice> ueDev = DynamicCast<LteUeNetDevice>(node->GetDevice(i));
    if (!ueDev) continue;
    Ptr<LteUeRrc> rrc = ueDev->GetRrc();
    if (!rrc) continue;
    rrc->TraceConnectWithoutContext("HandoverStart",
                                    MakeCallback(&UavmaAuthApplication::OnHandoverStart, this));
    rrc->TraceConnectWithoutContext("HandoverEndOk",
                                    MakeCallback(&UavmaAuthApplication::OnHandoverEndOk, this));
  }
}

// ---------------------------------------------------------------------------
// handover traces (UAV side)
// ---------------------------------------------------------------------------
void UavmaAuthApplication::OnHandoverStart(uint64_t imsi, uint16_t cellId, uint16_t rnti,
                                           uint16_t targetCellId) {
  (void)rnti;
  m_hoStartNs = SimNs();
  m_hoTargetCell = targetCellId;
  m_hoSourceCell = cellId;
  if (m_log) {
    m_log->event("handover_start", {{"imsi", I(static_cast<long long>(imsi))},
                                    {"cell_id", I(cellId)},
                                    {"target_cell_id", I(targetCellId)},
                                    {"t_sim_ms", S(m_hoStartNs / 1e6)}});
  }
}

void UavmaAuthApplication::OnHandoverEndOk(uint64_t imsi, uint16_t cellId, uint16_t rnti) {
  (void)rnti;
  m_hoEndNs = SimNs();
  if (m_hoStartNs < 0) {
    if (m_log) m_log->event("handover_unpaired_end_rejected", {{"cell_id", I(cellId)}});
    return;
  }
  UavmaRegistry::Instance().AddHandover(m_hoStartNs, m_hoEndNs, m_hoTargetCell);
  if (m_log) {
    m_log->event("handover_end_ok", {{"imsi", I(static_cast<long long>(imsi))},
                                     {"cell_id", I(cellId)},
                                     {"target_cell_id", I(m_hoTargetCell)},
                                     {"t_sim_ms", S(m_hoEndNs / 1e6)},
                                     {"rrc_window_ms", S((m_hoEndNs - m_hoStartNs) / 1e6)}});
  }
  ++m_hoCount;
  m_hoStartNs = -1;
  if (!m_triggerGOnHandover) return;
  if (!m_partitionEnabled) {
    SendTrigger(kTriggerHandover);
    return;
  }
  if (cellId != m_hoTargetCell || m_hoSourceCell != m_currentCellId) {
    if (m_log) m_log->event("partition_handover_rejected", {{"reason", "rrc_cell_or_source_mismatch"},
        {"source_cell_id", I(m_hoSourceCell)}, {"target_cell_id", I(cellId)},
        {"expected_current_cell_id", I(m_currentCellId)}});
    return;
  }
  try {
    const auto d = uavma_ns3::DecideHandover(m_cellToEdge, m_hoSourceCell, cellId);
    if (!ApplyPartitionDecision(d)) return;
    SendHandoverTrigger(m_hoSourceCell, cellId);
  } catch (const std::invalid_argument& ex) {
    if (m_log) m_log->event("partition_handover_rejected", {{"reason", ex.what()},
                  {"source_cell_id", I(m_hoSourceCell)}, {"target_cell_id", I(cellId)}});
  }
}

// ---------------------------------------------------------------------------
// trigger channel
// ---------------------------------------------------------------------------
void UavmaAuthApplication::SendTrigger(uint8_t type) {
  if (!m_triggerSocket) return;
  Address to;
  if (m_peerKnown) {
    to = InetSocketAddress(m_peerFullAddr, m_triggerPort);
  } else if (!m_peerIp.empty()) {
    to = InetSocketAddress(Ipv4Address(m_peerIp.c_str()), m_triggerPort);
  } else {
    return;
  }
  uint8_t buf[9];
  buf[0] = type;
  int64_t t = SimNs();
  for (int i = 0; i < 8; ++i) buf[1 + i] = static_cast<uint8_t>((t >> (8 * i)) & 0xff);
  Ptr<Packet> p = Create<Packet>(buf, 9);
  m_triggerSocket->SendTo(p, 0, to);
}

// Private ns-3 testbed metadata ONLY (type + 8-byte simulator time + 2-byte
// source cell + 2-byte target cell). This is not an authentication message,
// does not add a protocol round-trip and is excluded from byte accounting.
void UavmaAuthApplication::SendHandoverTrigger(std::uint16_t fromCell, std::uint16_t toCell) {
  if (!m_triggerSocket) return;
  Address to = m_peerKnown ? InetSocketAddress(m_peerFullAddr, m_triggerPort)
                           : InetSocketAddress(Ipv4Address(m_peerIp.c_str()), m_triggerPort);
  uint8_t buf[13] = {0};
  buf[0] = kTriggerHandover;
  const auto t = static_cast<std::uint64_t>(SimNs());
  for (int i = 0; i < 8; ++i) buf[1 + i] = static_cast<uint8_t>((t >> (8 * i)) & 0xff);
  buf[9] = static_cast<uint8_t>(fromCell & 0xffu);
  buf[10] = static_cast<uint8_t>((fromCell >> 8) & 0xffu);
  buf[11] = static_cast<uint8_t>(toCell & 0xffu);
  buf[12] = static_cast<uint8_t>((toCell >> 8) & 0xffu);
  m_triggerSocket->SendTo(Create<Packet>(buf, sizeof(buf)), 0, to);
}

bool UavmaAuthApplication::HasUnresolvedAuthentication() const {
  for (const auto& entry : m_infraSess) {
    if (!entry.second.gotM3) return true;
  }
  return false;
}

bool UavmaAuthApplication::ApplyPartitionDecision(const uavma_ns3::PartitionDecision& d) {
  if (!m_partitionEnabled || d.sourceCell != m_currentCellId ||
      m_eTargetId != d.sourceEdge) {
    if (m_log) m_log->event("partition_handover_rejected", {
      {"reason", "current_partition_state_mismatch"}, {"current_cell", I(m_currentCellId)}});
    return false;
  }
  if (!m_isUav && HasUnresolvedAuthentication()) {
    if (m_log) m_log->event("partition_handover_rejected", {
      {"reason", "unresolved_domain_authentication"},
      {"source_cell_id", I(d.sourceCell)}, {"target_cell_id", I(d.targetCell)}});
    return false;
  }
  // Both roles deterministically select the SAME cryptographic target IDs from
  // an immutable deployment mapping and a real completed LTE A3 handover.
  // No E-only event is synthesized; this represents logical service assignment,
  // NOT physical application state migration (which belongs to E4).
  m_currentCellId = d.targetCell;
  m_gTargetId = d.targetG;
  m_eTargetId = d.targetEdge;
  m_g.targetId = d.targetG;
  m_e.targetId = d.targetEdge;
  if (m_log) m_log->event("natural_partition_event", {
    {"source_cell_id", I(d.sourceCell)}, {"target_cell_id", I(d.targetCell)},
    {"source_edge_id", d.sourceEdge}, {"target_edge_id", d.targetEdge},
    {"g_target_id", d.targetG}, {"event_type", uavma_ns3::EventName(d.event)},
    {"edge_changed", d.edgeChanged ? "true" : "false"},
    {"logical_assignment_only", "true"}, {"t_sim_ms", S(SimNs() / 1e6)}});
  return true;
}

void UavmaAuthApplication::HandleTriggerRead(Ptr<Socket> socket) {
  Address from;
  while (Ptr<Packet> p = socket->RecvFrom(from)) {
    const auto packetSize = p->GetSize();
    if (packetSize < 9 || packetSize > 13) continue;
    uint8_t buf[13] = {0};
    p->CopyData(buf, packetSize);
    if (buf[0] == kTriggerAttach && packetSize == 9) {
      m_peerKnown = true;
      m_peerFullAddr = InetSocketAddress::ConvertFrom(from).GetIpv4();
      continue;
    }
    if (m_isUav || buf[0] != kTriggerHandover ||
        packetSize != (m_partitionEnabled ? 13u : 9u)) {
      if (m_log) m_log->event("handover_trigger_rejected", {{"reason", "unexpected_control_size_or_type"}});
      continue;
    }
    std::uint64_t t = 0;
    for (int i = 0; i < 8; ++i) t |= static_cast<std::uint64_t>(buf[1 + i]) << (8 * i);
    if (!m_partitionEnabled) {
      if (m_log) m_log->event("handover_trigger_received", {
          {"ho_end_sim_ms", S(static_cast<double>(t) / 1e6)},
          {"now_sim_ms", S(SimNs() / 1e6)}});
      if (m_hasG) BeginMobilityEvent(static_cast<int>(uavma_ns3::Event::GOnly), "natural_handover");
      continue;
    }
    const uint16_t source = static_cast<uint16_t>(buf[9] | (static_cast<uint16_t>(buf[10]) << 8));
    const uint16_t target = static_cast<uint16_t>(buf[11] | (static_cast<uint16_t>(buf[12]) << 8));
    if (source != m_currentCellId || HasUnresolvedAuthentication()) {
      if (m_log) m_log->event("handover_trigger_rejected", {
         {"reason", "replayed_out_of_order_or_unresolved"},
         {"source_cell_id", I(source)}, {"target_cell_id", I(target)}});
      continue;
    }
    try {
      const auto d = uavma_ns3::DecideHandover(m_cellToEdge, source, target);
      if (!ApplyPartitionDecision(d)) continue;
      m_peerKnown = true;
      m_peerFullAddr = InetSocketAddress::ConvertFrom(from).GetIpv4();
      if (m_log) m_log->event("handover_trigger_received", {
          {"ho_end_sim_ms", S(static_cast<double>(t) / 1e6)},
          {"now_sim_ms", S(SimNs() / 1e6)},
          {"source_cell_id", I(source)}, {"target_cell_id", I(target)},
          {"event_type", uavma_ns3::EventName(d.event)}});
      BeginMobilityEvent(static_cast<int>(d.event), "natural_handover");
    } catch (const std::invalid_argument& ex) {
      if (m_log) m_log->event("handover_trigger_rejected", {{"reason", ex.what()},
           {"source_cell_id", I(source)}, {"target_cell_id", I(target)}});
    }
  }
}

// ---------------------------------------------------------------------------
// protocol receive
// ---------------------------------------------------------------------------
void UavmaAuthApplication::HandleRead(Ptr<Socket> socket) {
  Address from;
  while (Ptr<Packet> p = socket->RecvFrom(from)) {
    uint32_t sz = p->GetSize();
    if (sz == 0) continue;
    uavma::Bytes buf(sz);
    p->CopyData(buf.data(), sz);
    m_peerKnown = true;
    m_peerFullAddr = InetSocketAddress::ConvertFrom(from).GetIpv4();

    size_t off = 0;
    uavma::MsgKind kind;
    uavma::Bytes payload;
    if (!uavma::Framing::decode(buf, off, kind, payload)) continue;
    size_t o = 0;
    switch (kind) {
      case uavma::MsgKind::AuthzU: {
        uavma::AuthzUMsg m = uavma::AuthzUMsg::from_bytes(payload, o);
        const char dom = uavma_ns3::MatchTargetDomain(
            m.target, m_gTargetId, m_eTargetId, m_hasG, m_hasE);
        if (!dom) {
          if (m_log) m_log->event("authz_u_rejected", {{"reason", "unknown_or_ambiguous_target"},
                                                           {"target", m.target}});
          break;
        }
        OnAuthzU(m, dom);
        break;
      }
      case uavma::MsgKind::M0: {
        uavma::M0Msg m = uavma::M0Msg::from_bytes(payload, o);
        const char dom = uavma::domain_char(m.d);
        const std::string sid = uavma::hex(m.sid);
        if (!m_cpuCalibrated || m_uavSess.count(sid)) {
          OnM0(m, dom);
        } else {
          const auto slot = ReserveCpu(dom, {"uav_handle_M0", "uav_build_M1"}, sid);
          Simulator::Schedule(NanoSeconds(slot.delayNs), [this, m, dom]() {
            if (m_running) OnM0(m, dom);
          });
        }
        break;
      }
      case uavma::MsgKind::M1: {
        uavma::M1Msg m = uavma::M1Msg::from_bytes(payload, o);
        const std::string sid = uavma::hex(m.sid);
        auto it = m_sidToTx.find(sid);
        if (it == m_sidToTx.end()) break;
        const char dom = m_sidDomain[sid];
        if (!m_cpuCalibrated || m_tx[it->second].committed) {
          OnM1(it->second, dom, m);
        } else {
          const uint64_t txId = it->second;
          const auto slot = ReserveCpu(dom, {"target_handle_M1"}, sid);
          Simulator::Schedule(NanoSeconds(slot.delayNs), [this, m, dom, txId]() {
            if (m_running) OnM1(txId, dom, m);
          });
        }
        break;
      }
      case uavma::MsgKind::M2: {
        uavma::M2Msg m = uavma::M2Msg::from_bytes(payload, o);
        const std::string sid = uavma::hex(m.sid);
        auto it = m_uavSidDomain.find(sid);
        if (it == m_uavSidDomain.end()) break;
        const char dom = it->second;
        auto session = m_uavSess.find(sid);
        if (!m_cpuCalibrated || (session != m_uavSess.end() && session->second.gotM2)) {
          OnM2(m, dom); // duplicate M2 uses cached-M3 path, no repeated handler charge
        } else {
          const auto slot = ReserveCpu(dom, {"uav_handle_M2"}, sid);
          Simulator::Schedule(NanoSeconds(slot.delayNs), [this, m, dom]() {
            if (m_running) OnM2(m, dom);
          });
        }
        break;
      }
      case uavma::MsgKind::M3: {
        uavma::M3Msg m = uavma::M3Msg::from_bytes(payload, o);
        const std::string sid = uavma::hex(m.sid);
        auto it = m_sidToTx.find(sid);
        if (it == m_sidToTx.end()) break;
        const char dom = m_sidDomain[sid];
        if (!m_cpuCalibrated || m_tx[it->second].committed) {
          OnM3(it->second, dom, m);
        } else {
          const uint64_t txId = it->second;
          const auto slot = ReserveCpu(dom, {"target_handle_M3"}, sid);
          Simulator::Schedule(NanoSeconds(slot.delayNs), [this, m, dom, txId]() {
            if (m_running) OnM3(txId, dom, m);
          });
        }
        break;
      }
      default:
        break;
    }
  }  // drain all pending protocol datagrams; especially simultaneous G/E traffic
}

// ---------------------------------------------------------------------------
// UAV side handlers
// ---------------------------------------------------------------------------
void UavmaAuthApplication::OnAuthzU(const uavma::AuthzUMsg& m, char dom) {
  UavmaDomainWorld& w = World(dom);
  if (m.target != w.targetId || (w.authorized && m.epoch < w.authorizedEpoch)) {
    if (m_log) m_log->event("authz_u_rejected", {{"domain", std::string(1, dom)},
                                                 {"reason", "wrong_target_or_stale_epoch"}});
    return;
  }
  w.authorizedEpoch = m.epoch;
  w.authorized = true;
  UavmaMsgRecord r;
  r.domain = dom;
  r.msg = "AuthzU";
  r.dir = "DL";
  r.framedBytes = m.account().encoded + uavma::kFrameHeaderBytes;
  RecordRecvCommon(r, "", uavma_ns3::AuthzKey(dom, m.epoch));
  if (m_log) {
    m_log->event("authz_u_received", {{"domain", std::string(1, dom)},
                                      {"target", m.target},
                                      {"epoch", I(static_cast<long long>(m.epoch))},
                                      {"t_sim_ms", S(SimNs() / 1e6)}});
  }
}

void UavmaAuthApplication::OnM0(const uavma::M0Msg& m, char dom) {
  UavmaDomainWorld& w = World(dom);
  const std::string sid = uavma::hex(m.sid);
  // Duplicate-M0 suppression: a retransmitted M0 for a session the UAV already owns must
  // NOT be re-processed, otherwise handle_m0 would reset the session and build_m1 would
  // spend a second PUFEval, breaking the protocol's "one PUFEval per authorization"
  // property. The message is still recorded as delivered.
  if (m_uavSess.find(sid) != m_uavSess.end()) {
    UavmaMsgRecord rd;
    rd.domain = dom;
    rd.msg = "M0";
    rd.dir = "DL";
    rd.framedBytes = m.account().encoded + uavma::kFrameHeaderBytes;
    rd.retrans = UavmaRegistry::Instance().Retrans(sid + "|M0");
    RecordRecvCommon(rd, sid, sid + "|M0");
    return;
  }
  double t0 = CpuUs();
  uavma::OpCounters before = uavma::counters();
  std::string err;
  bool ok = w.authorized && w.uav->handle_m0(m, w.ca->ca_pk(), w.authorizedEpoch, &err);
  double cpu = CpuUs() - t0;
  uavma::OpCounters d = uavma::counters() - before;
  UavmaRegistry::Instance().AddCpuUs(sid, cpu);
  UavmaRegistry::Instance().AddCounters(sid, d);

  UavmaMsgRecord r;
  r.domain = dom;
  r.msg = "M0";
  r.dir = "DL";
  r.framedBytes = m.account().encoded + uavma::kFrameHeaderBytes;
  r.handlerCpuUs = cpu;
  m_uavSidDomain[sid] = dom;
  RecordRecvCommon(r, sid, sid + "|M0");

  if (!ok) {
    if (m_log) m_log->event("m0_rejected", {{"sid", sid}, {"reason", err}});
    return;
  }
  t0 = CpuUs();
  before = uavma::counters();
  uavma::M1Msg m1 = w.uav->build_m1(0);
  cpu = CpuUs() - t0;
  d = uavma::counters() - before;
  UavmaRegistry::Instance().AddCpuUs(sid, cpu);
  UavmaRegistry::Instance().AddCounters(sid, d);
  SendProtocol(uavma::Framing::encode(uavma::MsgKind::M1, m1.to_bytes()), "M1", sid, dom, "UL");
  // ARQ: if M2 does not arrive, the cached M1 is resent (protocol cached-retry path:
  // no new PUFEval, no new signature).
  UavSess& s = m_uavSess[sid];
  s.dom = dom;
  s.m1Sent = 1;
  s.gotM2 = false;
  s.rto = Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(m_rtoMs)),
                              &UavmaAuthApplication::OnUavM1Rto, this, sid);
}

void UavmaAuthApplication::OnM2(const uavma::M2Msg& m, char dom) {
  UavmaDomainWorld& w = World(dom);
  const std::string sid = uavma::hex(m.sid);
  auto sit = m_uavSess.find(sid);
  UavmaMsgRecord r;
  r.domain = dom;
  r.msg = "M2";
  r.dir = "DL";
  r.framedBytes = m.account().encoded + uavma::kFrameHeaderBytes;

  // A repeat of a previously authenticated M2 is the paper's cached-retry
  // signal for retransmitting the EXACT stored M3 (no new state transition).
  // Do not pass it to UavCore::handle_m2 again: active_ intentionally rejects
  // duplicate activation. Compare against the MAC already verified on first M2.
  if (sit != m_uavSess.end() && sit->second.gotM2) {
    const auto& original = sit->second.acceptedM2Tau;
    const bool sameTag = !original.empty() && original.size() == m.tau.size() &&
                         CRYPTO_memcmp(original.data(), m.tau.data(), m.tau.size()) == 0;
    const bool liveSession = w.uav->active() && w.uav->session().sid == sid &&
                             w.uav->session().epoch == w.authorizedEpoch;
    RecordRecvCommon(r, sid, sid + "|M2");
    auto cached = m_frames.find(sid + "|M3");
    const bool withinRetryWindow = uavma_ns3::AllowCachedM3Replay(
        SimNs(), sit->second.m3CachedStartNs, m_rtoMs,
        sit->second.m3ReplayCount, m_maxRetrans);
    if (sameTag && liveSession && withinRetryWindow && cached != m_frames.end()) {
      ++sit->second.m3ReplayCount;
      SendProtocol(cached->second, "M3", sid, dom, "UL", "", true);
      if (m_log) m_log->event("m3_cached_replay", {{"sid", sid}, {"domain", std::string(1, dom)}});
    } else if (m_log) {
      m_log->event("duplicate_m2_rejected", {{"sid", sid},
                                               {"reason", "wrong_mac_or_stale_session_or_retry_bound"}});
    }
    return;
  }

  double t0 = CpuUs();
  uavma::OpCounters before = uavma::counters();
  std::string err;
  bool ok = w.uav->handle_m2(m, &err);
  double cpu = CpuUs() - t0;
  uavma::OpCounters d = uavma::counters() - before;
  UavmaRegistry::Instance().AddCpuUs(sid, cpu);
  UavmaRegistry::Instance().AddCounters(sid, d);
  r.handlerCpuUs = cpu;
  RecordRecvCommon(r, sid, sid + "|M2");
  if (!ok) {
    if (m_log) m_log->event("m2_rejected", {{"sid", sid}, {"reason", err}});
    return;  // Invalid M2 MUST NOT cancel the M1 retry timer.
  }
  if (sit != m_uavSess.end()) {
    sit->second.gotM2 = true;
    sit->second.acceptedM2Tau = m.tau;
    sit->second.m3CachedStartNs = SimNs();
    sit->second.m3ReplayCount = 0;
    if (sit->second.rto.IsPending()) Simulator::Cancel(sit->second.rto);
  }

  t0 = CpuUs();
  before = uavma::counters();
  uavma::M3Msg m3 = w.uav->m3();
  cpu = CpuUs() - t0;
  d = uavma::counters() - before;
  UavmaRegistry::Instance().AddCpuUs(sid, cpu);
  UavmaRegistry::Instance().AddCounters(sid, d);
  SendProtocol(uavma::Framing::encode(uavma::MsgKind::M3, m3.to_bytes()), "M3", sid, dom, "UL");
  m_metrics.UavState(sid, dom, w.uav->su().v, SimNs());
}

// ---------------------------------------------------------------------------
// infrastructure side handlers
// ---------------------------------------------------------------------------
void UavmaAuthApplication::OnM1(uint64_t txId, char dom, const uavma::M1Msg& m) {
  UavmaDomainWorld& w = World(dom);
  UavmaTxRecord& t = m_tx[txId];
  const std::string sid = uavma::hex(m.sid);
  if (t.committed) {  // An old M1 must not restart M2 ARQ after successful commit.
    UavmaMsgRecord r;
    r.txId = txId; r.domain = dom; r.eventType = t.eventType; r.trigger = t.trigger;
    r.msg = "M1"; r.dir = "UL";
    r.framedBytes = m.account().encoded + uavma::kFrameHeaderBytes;
    RecordRecvCommon(r, sid, sid + "|M1");
    return;
  }
  double t0 = CpuUs();
  uavma::OpCounters before = uavma::counters();
  std::string err;
  uavma::M1Outcome oc = w.target->handle_m1(m, t.epoch, uavma::now_mono_ms(), 0, &err);
  double cpu = CpuUs() - t0;
  uavma::OpCounters d = uavma::counters() - before;
  UavmaRegistry::Instance().AddCpuUs(sid, cpu);
  UavmaRegistry::Instance().AddCounters(sid, d);

  UavmaMsgRecord r;
  r.txId = txId;
  r.domain = dom;
  r.eventType = t.eventType;
  r.trigger = t.trigger;
  r.msg = "M1";
  r.dir = "UL";
  r.framedBytes = m.account().encoded + uavma::kFrameHeaderBytes;
  r.handlerCpuUs = cpu;
  RecordRecvCommon(r, sid, sid + "|M1");
  t.bodyUl += m.account().body;

  if (!oc.ok) {
    t.reason = "M1 rejected: " + oc.reason;
    t.branch = uavma::branch_str(oc.branch);
    return;
  }
  t.reason.clear();
  t.branch = uavma::branch_str(oc.branch);
  uavma::M2Msg m2 = w.target->m2();
  t.bodyDl += m2.account().body;
  SendProtocol(uavma::Framing::encode(uavma::MsgKind::M2, m2.to_bytes()), "M2", sid, dom, "DL");
  InfraSess& s = m_infraSess[sid];
  s.dom = dom;
  s.txId = txId;
  s.gotM1 = true;
  s.gotM3 = false;
  s.m2Sent = 1;
  if (s.rto.IsPending()) Simulator::Cancel(s.rto);
  s.rto = Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(m_rtoMs)),
                              &UavmaAuthApplication::OnInfraM2Rto, this, sid);
}

void UavmaAuthApplication::OnM3(uint64_t txId, char dom, const uavma::M3Msg& m) {
  UavmaDomainWorld& w = World(dom);
  UavmaTxRecord& t = m_tx[txId];
  const std::string sid = uavma::hex(m.sid);
  if (t.committed) {  // Duplicate M3 is recorded, not committed or rejected twice.
    UavmaMsgRecord r;
    r.txId = txId; r.domain = dom; r.eventType = t.eventType; r.trigger = t.trigger;
    r.msg = "M3"; r.dir = "UL";
    r.framedBytes = m.account().encoded + uavma::kFrameHeaderBytes;
    RecordRecvCommon(r, sid, sid + "|M3");
    return;
  }
  auto sit = m_infraSess.find(sid);
  double t0 = CpuUs();
  uavma::OpCounters before = uavma::counters();
  std::string err;
  bool ok = w.target->handle_m3(m, t.epoch, uavma::now_mono_ms(), &err);
  double cpu = CpuUs() - t0;
  uavma::OpCounters d = uavma::counters() - before;
  UavmaRegistry::Instance().AddCpuUs(sid, cpu);
  UavmaRegistry::Instance().AddCounters(sid, d);

  UavmaMsgRecord r;
  r.txId = txId;
  r.domain = dom;
  r.eventType = t.eventType;
  r.trigger = t.trigger;
  r.msg = "M3";
  r.dir = "UL";
  r.framedBytes = m.account().encoded + uavma::kFrameHeaderBytes;
  r.handlerCpuUs = cpu;
  RecordRecvCommon(r, sid, sid + "|M3");
  t.bodyUl += m.account().body;

  t.cpuUs = UavmaRegistry::Instance().CpuUs(sid);
  const auto calibrated_cpu_pair = UavmaRegistry::Instance().CalibratedCpu(sid);
  t.calibratedServiceNs = calibrated_cpu_pair.first;
  t.calibratedQueueNs = calibrated_cpu_pair.second;
  const auto wire = UavmaRegistry::Instance().WireUsageFor(sid);
  t.framed = wire.bytes;
  t.nMsg = wire.datagrams;
  uavma::OpCounters acc = UavmaRegistry::Instance().Counters(sid);
  t.puf = acc.puf;
  t.sign = acc.sign;
  t.verify = acc.verify;
  t.mac = acc.mac;
  t.hash = acc.hash;
  t.ecdh = acc.ecdh;
  if (!ok) {
    t.reason = "M3 rejected: " + err;
    return;  // Do not finalize a transaction that can still recover via ARQ.
  }
  if (sit != m_infraSess.end()) {
    sit->second.gotM3 = true;
    if (sit->second.rto.IsPending()) Simulator::Cancel(sit->second.rto);
  }
  t.reason.clear();
  t.tCommitNs = SimNs();
  t.committed = true;
  t.committedV = w.target->sc().v;
  m_metrics.Tx(t);
  if (m_log) {
    m_log->event("commit", {{"domain", std::string(1, dom)},
                            {"sid", sid},
                            {"committed_v", I(t.committedV)},
                            {"t_sim_ms", S(SimNs() / 1e6)}});
  }
}

uavma_ns3::CpuReservation UavmaAuthApplication::ReserveCpu(
    char dom, const std::vector<std::string>& stages, const std::string& sid) {
  const int64_t now = SimNs();
  if (!m_cpuCalibrated) return {now, now, now, 0, 0, 0};
  const int64_t service = uavma_ns3::HandlerServiceNs(m_e1Costs, dom, stages);
  const auto slot = m_cpuQueue.Reserve(now, dom, service);
  if (!sid.empty()) LogCpu(sid, dom, stages, slot);
  return slot;
}
void UavmaAuthApplication::LogCpu(
    const std::string& sid, char dom, const std::vector<std::string>& stages,
    const uavma_ns3::CpuReservation& slot) {
  if (!m_cpuCalibrated) return;
  std::string text;
  for (const auto& stage : stages) {
    if (!text.empty()) text += "+";
    text += stage + "_" + dom;
  }
  UavmaRegistry::Instance().AddCalibratedCpu(sid, slot.serviceNs, slot.queueNs);
  m_metrics.CpuSchedule(m_isUav ? "UAV" : "INFRA", sid, dom, text, slot,
                        m_cpuResourceMode, m_e1ProfileSha256);
}

// ---------------------------------------------------------------------------
// One real mobility event; P and A_JOINT observe the SAME event and targets.
// Sequential C++ calls here execute at the SAME ns-3 simulation timestamp;
// neither variant is assigned an artificial per-domain serialization delay.
// ---------------------------------------------------------------------------
void UavmaAuthApplication::BeginMobilityEvent(int eventKind, const std::string& trigger) {
  const auto event = static_cast<uavma_ns3::Event>(eventKind);
  const auto variant = m_variant.joint_trigger ? uavma_ns3::Variant::AJoint
                                               : uavma_ns3::Variant::P;
  const auto plan = uavma_ns3::Select(variant, event);
  const std::string label = uavma_ns3::EventName(event);
  const int64_t triggerNs = SimNs();
  const auto begin = [this, label, trigger, triggerNs](char dom) {
    if (!m_cpuCalibrated) {
      BeginTransaction(dom, label, trigger, triggerNs, {});
      return;
    }
    // The E1 target_create_session cost is before M0 emission. Reserve it on
    // the same node's capacity as M1/M3; no artificially serialized GE paths.
    const auto slot = ReserveCpu(dom, {"target_create_session_M0"}, "");
    Simulator::Schedule(NanoSeconds(slot.delayNs), [this, dom, label, trigger, triggerNs, slot]() {
      if (m_running) BeginTransaction(dom, label, trigger, triggerNs, slot);
    });
  };
  if (plan.g && m_hasG) begin('G');
  if (plan.e && m_hasE) begin('E');
}

// ---------------------------------------------------------------------------
// infrastructure: begin a transaction
// ---------------------------------------------------------------------------
void UavmaAuthApplication::BeginTransaction(char dom, const std::string& eventType,
                                            const std::string& trigger, int64_t triggerNs,
                                            const uavma_ns3::CpuReservation& preparation) {
  if (!m_peerKnown) return;
  UavmaDomainWorld& w = World(dom);
  uint64_t epoch = w.mm->authorize(w.targetId);
  uavma::AuthzUMsg au = w.mm->authz_u();
  uavma::AuthzSMsg as = w.mm->authz_s(w.target->pid());

  // When the physical LTE target cell or mapped edge target CHANGES, take the
  // committed/pending state from the OLD target. The existing protected
  // Transfer process carries it into a NEW target core with its own CA-issued
  // certificate and long-term identity; no protocol-core field is altered.
  w.src->set_committed(w.target->sc());
  w.src->set_pending(w.target->pi() ? std::optional<uavma::Pending>(*w.target->pi())
                                    : std::nullopt);
  uavma::TransferMsg tr = w.src->build_transfer(w.targetId, epoch);
  if (w.target->id() != w.targetId) {
    const std::string previousTarget = w.target->id();
    auto next = std::make_unique<uavma::TargetCore>(
       w.d, w.targetId, w.ca->target_lt_sk(w.targetId),
       w.root->domain_root(uavma::domain_char(w.d)), w.seed,
       m_variant, m_store.get(), m_log.get());
    next->set_cert_sig(w.ca->issue_cert(w.targetId, w.ca->target_lt_pk(w.targetId)));
    w.target = std::move(next);
    if (m_log) m_log->event("logical_target_context_transfer", {
        {"domain", std::string(1, dom)}, {"source_target", previousTarget},
        {"target", w.targetId}, {"base_v", I(tr.sc.v)},
        {"logical_assignment_only", "true"}});
  }
  w.target->accept_transfer(tr);
  uavma::M0Msg m0 = w.target->create_session(w.target->pid(), w.targetId, epoch);
  const std::string sid = uavma::hex(m0.sid);
  if (m_cpuCalibrated) LogCpu(sid, dom, {"target_create_session_M0"}, preparation);

  UavmaTxRecord t;
  t.id = m_nextTxId++;
  t.tTriggerNs = triggerNs;
  t.cpuResourceMode = m_cpuCalibrated ? m_cpuResourceMode : "UNCALIBRATED";
  t.e1ProfileSha256 = m_e1ProfileSha256;
  t.domain = dom;
  t.eventType = eventType;
  t.trigger = trigger;
  t.variant = m_variantName;
  t.sid = sid;
  t.targetId = w.targetId;
  t.epoch = epoch;
  t.bodyMm = au.account().body + as.account().body;
  t.bodyInf = tr.account().body;
  t.bodyDl = m0.account().body;
  m_tx[t.id] = t;
  m_sidToTx[sid] = t.id;
  m_sidDomain[sid] = dom;

  // AuthzU is a real protocol message (MM -> U) carrying the epoch the UAV must check
  // in handle_m0. It is transmitted, not assumed. Its lookup key uses the epoch because
  // the UAV does not know the SID before M0 arrives.
  SendProtocol(uavma::Framing::encode(uavma::MsgKind::AuthzU, au.to_bytes()), "AuthzU", sid, dom,
               "DL", uavma_ns3::AuthzKey(dom, epoch));
  m_tx[t.id].tStartNs = SimNs();
  SendProtocol(uavma::Framing::encode(uavma::MsgKind::M0, m0.to_bytes()), "M0", sid, dom, "DL");
  InfraSess& s = m_infraSess[sid];
  s.dom = dom;
  s.txId = t.id;
  s.gotM1 = false;
  s.gotM3 = false;
  s.m0Sent = 1;
  s.m2Sent = 0;
  s.rto = Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(m_rtoMs)),
                              &UavmaAuthApplication::OnInfraM0Rto, this, sid);
}

// ---------------------------------------------------------------------------
// send / record plumbing
// ---------------------------------------------------------------------------
int64_t UavmaAuthApplication::SendProtocol(const uavma::Bytes& framed, const std::string& msg,
                                           const std::string& sid, char dom, const std::string& dir,
                                           const std::string& altKey, bool isRetrans) {
  (void)dom;
  (void)dir;
  Address to = m_peerKnown ? InetSocketAddress(m_peerFullAddr, m_peerPort)
                           : InetSocketAddress(Ipv4Address(m_peerIp.c_str()), m_peerPort);
  // Deliberate fault injection is disabled by default and strictly for a
  // separately labeled D-6 preflight. The serialized M3 still gets cached,
  // so the first correctly replayed M2 can request an identical M3 retransmit.
  const bool injectLoss = m_testDropFirstM3 && m_isUav && msg == "M3" &&
                          !isRetrans && !m_testM3DropInjected;
  if (injectLoss) {
    m_testM3DropInjected = true;
    if (m_log) m_log->event("controlled_m3_loss_injected", { {"sid", sid},
                              {"domain", std::string(1, dom)}, {"test_only", "true"},
                              {"t_sim_ms", S(SimNs() / 1e6)} });
  }
  int rc = 0;
  if (!injectLoss) {
    Ptr<Packet> p = Create<Packet>(framed.data(), static_cast<uint32_t>(framed.size()));
    rc = m_socket->SendTo(p, 0, to);
  }
  if (rc < 0 && m_log) {
    m_log->event("send_failed", {{"msg", msg},
                                 {"sid", sid},
                                 {"retrans", I(isRetrans ? 1 : 0)},
                                 {"bytes", I(static_cast<long long>(framed.size()))},
                                 {"t_sim_ms", S(SimNs() / 1e6)}});
  }
  int64_t t = SimNs();
  m_frames[sid + "|" + msg] = framed;  // cache even when deliberately dropped
  const bool onWire = !injectLoss && rc >= 0;
  if (onWire) {
    const auto key = sid + "|" + msg;
    // Every on-wire attempt gets its own timestamp. Match with a receive only
    // when there is exactly one outstanding candidate for this session/message.
    if (isRetrans) {
      UavmaRegistry::Instance().AddRetrans(key);
      if (!altKey.empty()) UavmaRegistry::Instance().AddRetrans(altKey);
    }
    UavmaRegistry::Instance().RecordSend(key, t);
    if (!altKey.empty()) UavmaRegistry::Instance().RecordSend(altKey, t);
    UavmaRegistry::Instance().RecordWireSend(sid, framed.size());
    UavmaIoEvent e;
    e.simNs = t;
    e.recv = false;
    e.retrans = isRetrans;
    e.sid = sid;
    e.msg = msg;
    UavmaRegistry::Instance().RecordIo(e);
  }
  return t;
}

void UavmaAuthApplication::RecordRecvCommon(UavmaMsgRecord& r, const std::string& sid,
                                            const std::string& key) {
  int64_t sendNs = 0;
  r.recvNs = SimNs();
  const bool have = UavmaRegistry::Instance().MatchRecvSend(key, r.recvNs, sendNs);
  r.sendNs = have ? sendNs : 0;
  // Missing or ambiguous attempt: -1 is NOT a measured one-way transit time.
  r.transportMs = have ? (r.recvNs - sendNs) / 1e6 : -1.0;
  r.retrans = UavmaRegistry::Instance().Retrans(
      uavma_ns3::RetransmissionLookupKey(sid, r.msg, key));
  UavmaIoEvent e;
  e.simNs = r.recvNs;
  e.recv = true;
  e.sid = sid;
  e.msg = r.msg;
  UavmaRegistry::Instance().RecordIo(e);
  auto it = m_sidToTx.find(sid);
  if (it != m_sidToTx.end()) {
    r.txId = it->second;
    r.eventType = m_tx[it->second].eventType;
    r.trigger = m_tx[it->second].trigger;
  }
  m_metrics.Msg(r);
}

UavmaDomainWorld& UavmaAuthApplication::World(char dom) {
  return (dom == 'E') ? m_e : m_g;
}

void UavmaAuthApplication::SchedulePeriodic() {
  if (m_ePeriodSec > 0 && m_hasE) {
    m_periodicEvent =
        Simulator::Schedule(Seconds(m_eStartSec), &UavmaAuthApplication::PeriodicTick, this);
  }
  if (m_geInjectSec > 0 && m_hasG && m_hasE) {
    Simulator::Schedule(Seconds(m_geInjectSec), &UavmaAuthApplication::BeginMobilityEvent,
                        this, static_cast<int>(uavma_ns3::Event::GE),
                        std::string("controlled_injection"));
  }
}

void UavmaAuthApplication::PeriodicTick() {
  if (m_hasE) BeginMobilityEvent(static_cast<int>(uavma_ns3::Event::EOnly), "controlled_injection");
  m_periodicEvent =
      Simulator::Schedule(Seconds(m_ePeriodSec), &UavmaAuthApplication::PeriodicTick, this);
}

// ---------------------------------------------------------------------------
// bounded retransmission (application-level ARQ)
//
// Retransmissions resend the EXACT bytes already produced by protocol_core, so the
// protocol takes its defined cached-retry path: no additional PUFEval, no additional
// signature. Retries are counted separately. Transport delay is reported only
// when a received copy can be matched to exactly one outstanding send attempt.
// ---------------------------------------------------------------------------
void UavmaAuthApplication::OnUavM1Rto(std::string sid) {
  auto it = m_uavSess.find(sid);
  if (it == m_uavSess.end() || it->second.gotM2) return;
  if (static_cast<uint32_t>(it->second.m1Sent) > m_maxRetrans) return;
  auto f = m_frames.find(sid + "|M1");
  if (f == m_frames.end()) return;
  uavma::Bytes fb = f->second;
  SendProtocol(fb, "M1", sid, it->second.dom, "UL", "", true);
  it->second.m1Sent++;
  it->second.rto = Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(m_rtoMs)),
                                       &UavmaAuthApplication::OnUavM1Rto, this, sid);
}

void UavmaAuthApplication::OnInfraM0Rto(std::string sid) {
  auto it = m_infraSess.find(sid);
  if (it == m_infraSess.end() || it->second.gotM1) return;
  if (static_cast<uint32_t>(it->second.m0Sent) > m_maxRetrans) return;
  auto fa = m_frames.find(sid + "|AuthzU");
  auto fm = m_frames.find(sid + "|M0");
  if (fa == m_frames.end() || fm == m_frames.end()) return;
  uavma::Bytes ba = fa->second, bm = fm->second;
  const auto txIt = m_tx.find(it->second.txId);
  const std::string authzKey = txIt == m_tx.end() ? "" :
      uavma_ns3::AuthzKey(it->second.dom, txIt->second.epoch);
  SendProtocol(ba, "AuthzU", sid, it->second.dom, "DL", authzKey, true);
  SendProtocol(bm, "M0", sid, it->second.dom, "DL", "", true);
  it->second.m0Sent++;
  it->second.rto = Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(m_rtoMs)),
                                       &UavmaAuthApplication::OnInfraM0Rto, this, sid);
}

void UavmaAuthApplication::OnInfraM2Rto(std::string sid) {
  auto it = m_infraSess.find(sid);
  if (it == m_infraSess.end() || it->second.gotM3) return;
  if (static_cast<uint32_t>(it->second.m2Sent) > m_maxRetrans) return;
  auto f = m_frames.find(sid + "|M2");
  if (f == m_frames.end()) return;
  uavma::Bytes fb = f->second;
  SendProtocol(fb, "M2", sid, it->second.dom, "DL", "", true);
  it->second.m2Sent++;
  it->second.rto = Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(m_rtoMs)),
                                       &UavmaAuthApplication::OnInfraM2Rto, this, sid);
}

void UavmaAuthApplication::FinalizeTransactions() {
  for (auto& kv : m_tx) {
    UavmaTxRecord& t = kv.second;
    if (!t.committed && t.tCommitNs == 0) {
      t.cpuUs = UavmaRegistry::Instance().CpuUs(t.sid);
      const auto wire = UavmaRegistry::Instance().WireUsageFor(t.sid);
      t.framed = wire.bytes;
      t.nMsg = wire.datagrams;
      if (t.reason.empty()) t.reason = "not committed before stop";
      m_metrics.Tx(t);
    }
  }
}

}  // namespace ns3
