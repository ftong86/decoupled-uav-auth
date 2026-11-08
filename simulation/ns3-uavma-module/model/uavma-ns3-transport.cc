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
#include <ns3/ipv4-interface-address.h>
#include <ns3/ipv4.h>
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
#include <sstream>
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
Ipv4Address ParseSiteMapIpv4(const std::string& s) {
  // Strict dotted-quad parse (no ns-3 assert on malformed scene input).
  unsigned parts[4] = {0, 0, 0, 0};
  size_t idx = 0;
  for (int part = 0; part < 4; ++part) {
    unsigned value = 0;
    size_t digits = 0;
    while (idx < s.size() && s[idx] >= '0' && s[idx] <= '9') {
      value = value * 10u + static_cast<unsigned>(s[idx] - '0');
      ++idx;
      ++digits;
      if (value > 255u) throw std::invalid_argument("SiteMap IPv4 octet out of range");
    }
    if (digits == 0 || digits > 3) throw std::invalid_argument("SiteMap IPv4 octet malformed");
    parts[part] = value;
    if (part < 3) {
      if (idx >= s.size() || s[idx] != '.')
        throw std::invalid_argument("SiteMap IPv4 must be dotted quad");
      ++idx;
    }
  }
  if (idx != s.size()) throw std::invalid_argument("SiteMap IPv4 has trailing characters");
  return Ipv4Address((static_cast<uint32_t>(parts[0]) << 24) |
                     (static_cast<uint32_t>(parts[1]) << 16) |
                     (static_cast<uint32_t>(parts[2]) << 8) |
                     static_cast<uint32_t>(parts[3]));
}

// ns-3.45 Ipv4Address exposes no ToString(); EventLog fields are strings.
std::string PnetIpStr(const Ipv4Address& a) {
  std::ostringstream os;
  a.Print(os);
  return os.str();
}

std::map<std::string, Ipv4Address> ParseSiteMap(const std::string& encoded) {
  // "GS_CELL_1=200.0.0.2,ES_T1=200.0.0.5" — immutable deployment mapping, same
  // epistemic status as CellToEdgeMap: it places logical identities on physical
  // remote nodes; it is not a protocol message and carries no protocol field.
  if (encoded.empty()) throw std::invalid_argument("empty SiteMap");
  std::map<std::string, Ipv4Address> map;
  size_t start = 0;
  while (start < encoded.size()) {
    const size_t comma = encoded.find(',', start);
    const size_t end = comma == std::string::npos ? encoded.size() : comma;
    const std::string entry = encoded.substr(start, end - start);
    const size_t eq = entry.find('=');
    if (eq == std::string::npos || eq == 0 || eq + 1 >= entry.size() ||
        entry.find('=', eq + 1) != std::string::npos)
      throw std::invalid_argument("SiteMap entries must be TARGET=IP");
    const std::string id = entry.substr(0, eq);
    if (!uavma_ns3::ValidEdgeId(id)) throw std::invalid_argument("invalid SiteMap target identity");
    if (!map.emplace(id, ParseSiteMapIpv4(entry.substr(eq + 1))).second)
      throw std::invalid_argument("duplicate SiteMap target identity");
    if (comma == std::string::npos) break;
    start = comma + 1;
    if (start == encoded.size()) throw std::invalid_argument("trailing SiteMap comma");
  }
  return map;
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
// E2-DISTRIBUTED (M4/D5): per-(transaction scope, message) emission ledger. Keyed by
// "<wireKey>|<msg>" so that a retransmission lands in the SAME bucket as its first
// emission. firstBytes therefore reconstructs a retransmission-free authentication;
// totalBytes is everything actually put on the wire.
void UavmaRegistry::RecordEmission(const std::string& key, size_t bytes, bool retrans) {
  EmissionStat& s = emis_[key];
  if (s.count == 0) s.firstBytes = bytes;
  s.totalBytes += bytes;
  if (retrans) s.retransBytes += bytes;
  s.count += 1;
}
UavmaRegistry::EmissionStat UavmaRegistry::Emission(const std::string& key) const {
  const auto it = emis_.find(key);
  return it == emis_.end() ? EmissionStat{} : it->second;
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
                           "uavma_io_events.csv", "uavma_cpu_schedule.csv", "uavma_events.jsonl",
                           "uavma_send_ledger.csv"}) {
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
  fLed_.open(dir_ + "/uavma_send_ledger.csv", std::ios::out | std::ios::trunc);
  fMsg_ << "tx_id,domain,event_type,trigger,msg,dir,send_sim_ms,recv_sim_ms,"
           "transport_sim_ms,handler_cpu_us,framed_bytes,delivered,retrans\n";
  fTx_ << "tx_id,domain,event_type,trigger,variant,sid,target_id,epoch,committed,branch,reason,"
          "t_start_sim_ms,t_commit_sim_ms,auth_complete_sim_ms,auth_complete_cpu_ms,"
          "committed_v,puf,sign,verify,mac,hash,ecdh,body_ul,body_dl,body_inf,body_mm,"
          "framed_total,n_msg,trigger_recv_sim_ms,trigger_to_commit_sim_ms,"
          "calibrated_service_us,calibrated_queue_us,cpu_resource_mode,e1_profile_sha256,"
          "infra_framed_total,infra_msg,"
          "normal_auth_bytes,full_sent_auth_bytes,ul_auth_bytes,dl_auth_bytes,"
          "infra_auth_bytes,total_auth_bytes,coord_bytes,app_retrans_bytes,"
          "migration,intra_site_transfer,counterfactual_infra_bytes\n";
  fHo_ << "ho_index,ho_start_sim_ms,ho_end_sim_ms,rrc_window_ms,target_cell_id,"
          "proto_delivery_gap_ms,in_window_sent,in_window_delivered\n";
  fSt_ << "sid,domain,uav_v,t_sim_ms\n";
  fIo_ << "sim_ms,direction,retrans,msg,sid,bytes,dom,key\n";
  fLed_ << "sim_ms,node,role,event,msg,dom,sid,tx_id,key,src_ip,src_port,dst_ip,dst_port,"
           "port_class,dir,framed_bytes,on_wire,send_rc,retrans\n";
  fCpu_ << "role,sid,domain,stages,arrival_sim_ms,start_sim_ms,finish_sim_ms,"
           "calibrated_service_us,queue_wait_us,cpu_resource_mode,e1_profile_sha256\n";
  fMsg_.flush();
  fTx_.flush();
  fHo_.flush();
  fSt_.flush();
  fIo_.flush();
  fCpu_.flush();
  return fMsg_.good() && fTx_.good() && fHo_.good() && fSt_.good() && fCpu_.good() &&
         fLed_.good();
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
       << ',' << t.cpuResourceMode << ',' << t.e1ProfileSha256 << ','
       << t.infraFramed << ',' << t.infraMsg << ','
       << t.normalAuthBytes << ',' << t.fullSentAuthBytes << ',' << t.ulAuthBytes << ','
       << t.dlAuthBytes << ',' << t.infraAuthBytes << ','
       << (t.ulAuthBytes + t.dlAuthBytes + t.infraAuthBytes) << ',' << t.coordBytes << ','
       << t.appRetransBytes << ',' << (t.migration ? 1 : 0) << ','
       << (t.intraSiteTransfer ? 1 : 0) << ',' << t.counterfactualInfraBytes << '\n';
  fTx_.flush();
}
// E2-DISTRIBUTED (M4): one row per real UDP emission attempt, written by the SENDER.
// This is the primary evidence that reported bytes were actually transmitted.
void UavmaMetrics::Ledger(const UavmaIoEvent& e) {
  if (!fLed_.is_open()) return;
  fLed_ << S(e.simNs / 1e6) << ',' << e.nodeId << ',' << e.role << ','
        << (e.recv ? "RECV" : "SEND") << ',' << e.msg << ',' << e.dom << ',' << e.sid << ','
        << e.txId << ',' << e.key << ',' << e.srcIp << ',' << e.srcPort << ',' << e.dstIp << ','
        << e.dstPort << ',' << e.portClass << ',' << e.dir << ',' << e.bytes << ','
        << (e.onWire ? 1 : 0) << ',' << e.sendRc << ',' << (e.retrans ? "R" : "-") << '\n';
  fLed_.flush();
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
         << ',' << e.msg << ',' << e.sid << ',' << e.bytes << ',' << e.dom << ',' << e.key
         << '\n';
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
  if (fLed_.is_open()) fLed_.close();
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
          .AddAttribute("Role", "UAV | MM | SITE | TARGET (legacy single-node infrastructure: "
                        "MM + source + target).",
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
          .AddAttribute("SiteMap", "P-NET infrastructure roles: TARGET=IP,... static deployment "
                        "map of logical target identities onto physical remote nodes.",
                        StringValue(""), MakeStringAccessor(&UavmaAuthApplication::m_siteMapText),
                        MakeStringChecker())
          .AddAttribute("HostTargets", "P-NET SITE role: the single target identity hosted by "
                        "this node.",
                        StringValue(""), MakeStringAccessor(&UavmaAuthApplication::m_hostTargets),
                        MakeStringChecker())
          .AddAttribute("InfraPort", "P-NET infrastructure-to-infrastructure UDP port.",
                        UintegerValue(9002),
                        MakeUintegerAccessor(&UavmaAuthApplication::m_infraPort),
                        MakeUintegerChecker<uint16_t>())
          .AddAttribute("RtoMs", "Retransmission timeout in simulated milliseconds.",
                        DoubleValue(250.0), MakeDoubleAccessor(&UavmaAuthApplication::m_rtoMs),
                        MakeDoubleChecker<double>())
          .AddAttribute("MaxRetrans", "Maximum retransmissions per protocol message.",
                        UintegerValue(3),
                        MakeUintegerAccessor(&UavmaAuthApplication::m_maxRetrans),
                        MakeUintegerChecker<uint32_t>())
          // ---- E2-DISTRIBUTED -------------------------------------------------
          .AddAttribute("AllowForcedSameSiteReauth",
                        "E2-DISTRIBUTED (M2): let a NON-migrating domain REALLY re-authenticate "
                        "(real MM::authorize, real AuthzU, real AuthzS on the wire) instead of "
                        "skipping it. State is re-installed on the SAME site and no Transfer "
                        "datagram is fabricated. Off by default, so P and all legacy runs are "
                        "bit-identical.",
                        BooleanValue(false),
                        MakeBooleanAccessor(&UavmaAuthApplication::m_allowForcedSameSiteReauth),
                        MakeBooleanChecker())
          .AddAttribute("Ho3AtSec",
                        "E2-DISTRIBUTED (HO3): simulated time (s) of ONE controlled E-only "
                        "logical target change. The G target and the LTE serving cell do not "
                        "change and no RRC handover is triggered; negative disables the probe.",
                        DoubleValue(-1.0),
                        MakeDoubleAccessor(&UavmaAuthApplication::m_ho3AtSec),
                        MakeDoubleChecker<double>())
          .AddAttribute("Ho3ObserveSec",
                        "E2-DISTRIBUTED (HO3): observation window (s) after the E-only change.",
                        DoubleValue(1.0),
                        MakeDoubleAccessor(&UavmaAuthApplication::m_ho3ObserveSec),
                        MakeDoubleChecker<double>())
          .AddAttribute("Ho3NewETarget",
                        "E2-DISTRIBUTED (HO3): new logical E-domain target identifier "
                        "(e.g. ES_T2); empty disables the probe.",
                        StringValue(""),
                        MakeStringAccessor(&UavmaAuthApplication::m_ho3NewETarget),
                        MakeStringChecker());
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
  m_infraSocket = nullptr;
  Application::DoDispose();
}

// ---------------------------------------------------------------------------
// start / stop
// ---------------------------------------------------------------------------
void UavmaAuthApplication::StartApplication() {
  m_isUav = (m_role == "UAV" || m_role == "Uav" || m_role == "uav");
  m_isMm = (m_role == "MM" || m_role == "mm");
  m_isSite = (m_role == "SITE" || m_role == "Site" || m_role == "site");
  m_hasG = m_domains.find('G') != std::string::npos;
  m_hasE = m_domains.find('E') != std::string::npos;
  uavma_ns3::Variant checkedVariant;
  if (!uavma_ns3::ParseVariant(m_variantName, &checkedVariant))
    throw std::invalid_argument("UAVMA Variant must be P or A_JOINT");
  if (m_hasE && m_hasG && m_eTargetId == m_gTargetId)
    throw std::invalid_argument("UAVMA G/E target IDs must differ for AuthzU demultiplexing");
  // E2-DISTRIBUTED: a P-NET SITE hosts at most ONE target per domain (enforced by
  // HostTargets), so it structurally cannot serve both. The variant is a trigger
  // policy and is only ever evaluated by the role that dispatches an event (the UAV
  // in the legacy deployment, the MM in P-NET); a site never calls Select().
  // Requiring both domains here made A_JOINT undeployable on split infrastructure.
  // The requirement is therefore scoped to the roles that actually evaluate it.
  // No protocol field, message or security check is affected.
  if (checkedVariant == uavma_ns3::Variant::AJoint && (!m_hasG || !m_hasE) && !m_isSite)
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

  // ---- P-NET role validation (infrastructure split for communication-caliber unification).
  if (m_isMm || m_isSite) {
    if (m_siteMapText.empty())
      throw std::invalid_argument("P-NET MM/SITE roles require SiteMap");
    m_siteMap = ParseSiteMap(m_siteMapText);
  }
  if (m_isMm) {
    if (!m_hasG || !m_hasE)
      throw std::invalid_argument("P-NET MM requires both G and E domains");
    if (!m_partitionEnabled)
      throw std::invalid_argument("P-NET MM requires CellToEdgeMap partition mode");
  }
  if (m_isSite) {
    if (m_partitionEnabled)
      throw std::invalid_argument("P-NET SITE must not configure CellToEdgeMap");
    if (m_hostTargets.empty())
      throw std::invalid_argument("P-NET SITE requires HostTargets");
    // "G:GS_CELL_3,E:ES_T1": at most one hosted target per active domain. A node may
    // host one G and one E target (distinct logical entities, never message peers).
    bool hasG = false, hasE = false;
    size_t start = 0;
    while (start < m_hostTargets.size()) {
      const size_t comma = m_hostTargets.find(',', start);
      const size_t end = comma == std::string::npos ? m_hostTargets.size() : comma;
      const std::string entry = m_hostTargets.substr(start, end - start);
      const size_t colon = entry.find(':');
      if (colon != 1) throw std::invalid_argument("HostTargets entries must be D:TARGET");
      const char d = entry[0];
      if (d != 'G' && d != 'E')
        throw std::invalid_argument("HostTargets domain tag must be G or E");
      const std::string id = entry.substr(2);
      if (id.empty() || !m_siteMap.count(id))
        throw std::invalid_argument("P-NET SITE host target missing from SiteMap");
      if (d == 'G') {
        if (hasG) throw std::invalid_argument("P-NET SITE hosts one G target at most");
        hasG = true;
        m_gTargetId = id;
      } else {
        if (hasE) throw std::invalid_argument("P-NET SITE hosts one E target at most");
        hasE = true;
        m_eTargetId = id;
      }
      if (comma == std::string::npos) break;
      start = comma + 1;
      if (start == m_hostTargets.size())
        throw std::invalid_argument("trailing HostTargets comma");
    }
    if (hasG != m_hasG || hasE != m_hasE)
      throw std::invalid_argument("P-NET SITE Domains attribute must match HostTargets");
    m_hostTarget = m_hostTargets;  // diagnostics only
  }

  std::string siteSuffix;
  if (m_isSite) {
    siteSuffix = m_hostTargets;
    for (char& c : siteSuffix)
      if (c == ':' || c == ',') c = '_';
  }
  const std::string dir = m_outputPrefix + (m_isUav ? "_uav" : m_isMm ? "_mm"
                                        : m_isSite ? "_site_" + siteSuffix : "_infra");
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
    } else if (m_isMm) {
      // P-NET: the MM hosts only the MobilityManager (plus the deterministic CA/root).
      // The domain pseudonym is re-derivable on any node from the shared SeedTag.
      w.mm = std::make_unique<uavma::MobilityManager>(w.d, w.seed);
      w.pid = uavma::derive_pid(w.d, w.root->domain_root(uavma::domain_char(w.d)));
    } else if (m_isSite) {
      // P-NET: one site hosts exactly one target core, rebuilt deterministically from
      // the shared SeedTag (same keys, same initial state as the legacy single node).
      uavma::Bytes dr = w.root->domain_root(uavma::domain_char(w.d));
      w.target = std::make_unique<uavma::TargetCore>(w.d, w.targetId,
                                                    w.ca->target_lt_sk(w.targetId), dr, w.seed,
                                                    m_variant, m_store.get(), m_log.get());
      w.target->set_cert_sig(w.ca->issue_cert(w.targetId, w.ca->target_lt_pk(w.targetId)));
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
  if (m_isMm || m_isSite) SetupInfraSocket();

  if (m_isUav) {
    ConnectHandoverTraces();
    // Simulation plumbing: let the infrastructure learn the UAV address so it can emit
    // M0 later. Not a protocol message; never counted in any latency class.
    Simulator::Schedule(Seconds(0.5), &UavmaAuthApplication::SendTrigger, this, kTriggerAttach);
  } else {
    SchedulePeriodic();
  }
  if (m_log) {
    m_log->event("app_start", {{"role", m_isUav ? "UAV" : m_isMm ? "MM"
                                        : m_isSite ? "SITE" : "INFRA"},
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
  // E2-DISTRIBUTED (HO3): one controlled E-only logical target change, scheduled at
  // the same absolute simulated time on the UAV and on the MM. Only the MM dispatches
  // the production authentication flow; the UAV only mirrors the logical E target so
  // that AuthzU demultiplexing and the epoch check stay consistent.
  InstallHo3Probe();
}

void UavmaAuthApplication::StopApplication() {
  m_running = false;
  if (m_periodicEvent.IsPending()) Simulator::Cancel(m_periodicEvent);
  if (m_ho3ProbeEvent.IsPending()) Simulator::Cancel(m_ho3ProbeEvent);
  for (auto& kv : m_mmAuthzRto)
    if (kv.second.IsPending()) Simulator::Cancel(kv.second);
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

// P-NET: infrastructure-to-infrastructure protocol channel (AuthzS / Transfer).
void UavmaAuthApplication::SetupInfraSocket() {
  m_infraSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
  m_infraSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_infraPort));
  m_infraSocket->SetRecvCallback(MakeCallback(&UavmaAuthApplication::HandleInfraRead, this));
}

// P-NET plumbing: the MM distributes the UAV's address (learned from the attach
// trigger) to every site so any site can emit M0 without inventing a route.
void UavmaAuthApplication::BroadcastPeerInfo() {
  if (!m_triggerSocket || !m_peerKnown) return;
  uint8_t buf[13] = {0};
  buf[0] = kTriggerPeerInfo;
  const int64_t t = SimNs();
  for (int i = 0; i < 8; ++i) buf[1 + i] = static_cast<uint8_t>((t >> (8 * i)) & 0xff);
  const uint32_t ip = m_peerFullAddr.Get();
  for (int i = 0; i < 4; ++i) buf[9 + i] = static_cast<uint8_t>((ip >> (8 * i)) & 0xff);
  for (const auto& entry : m_siteMap) {
    const Address to = InetSocketAddress(entry.second, m_triggerPort);
    const int rc = m_triggerSocket->SendTo(Create<Packet>(buf, sizeof(buf)), 0, to);
    RecordCoordSend("peer_info", sizeof(buf), 'G', to, rc);
  }
  if (m_log)
    m_log->event("peer_info_broadcast", {{"uav_ip", PnetIpStr(m_peerFullAddr)},
                                         {"sites", I(static_cast<long long>(m_siteMap.size()))},
                                         {"t_sim_ms", S(SimNs() / 1e6)}});
}

// P-NET plumbing: relay the mobility-event timestamp and kind to the involved sites
// BEFORE any AuthzS leaves the MM, so every site records the same event time (the
// CSMA backbone preserves per-source ordering). Never counted in any metric.
void UavmaAuthApplication::RelayEventInfo(int64_t eventNs, int eventKind,
                                          const std::vector<Ipv4Address>& sites) {
  if (!m_triggerSocket || sites.empty()) return;
  uint8_t buf[10] = {0};
  buf[0] = kTriggerEventInfo;
  for (int i = 0; i < 8; ++i)
    buf[1 + i] = static_cast<uint8_t>((static_cast<uint64_t>(eventNs) >> (8 * i)) & 0xff);
  buf[9] = static_cast<uint8_t>(eventKind);
  for (const auto& ip : sites) {
    const Address to = InetSocketAddress(ip, m_triggerPort);
    const int rc = m_triggerSocket->SendTo(Create<Packet>(buf, sizeof(buf)), 0, to);
    RecordCoordSend("event_info", sizeof(buf), 'G', to, rc);
  }
  if (m_log)
    m_log->event("event_info_relayed", {{"event_ns", I(eventNs)},
                                        {"event_kind", I(eventKind)},
                                        {"sites", I(static_cast<long long>(sites.size()))},
                                        {"t_sim_ms", S(SimNs() / 1e6)}});
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
  const int rc = m_triggerSocket->SendTo(p, 0, to);
  RecordCoordSend("attach_trigger", 9, 'G', to, rc);
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
  const int rc = m_triggerSocket->SendTo(Create<Packet>(buf, sizeof(buf)), 0, to);
  RecordCoordSend("handover_trigger", sizeof(buf), 'G', to, rc);
}

bool UavmaAuthApplication::HasUnresolvedAuthentication() const {
  for (const auto& entry : m_infraSess) {
    if (!entry.second.gotM3) return true;
  }
  return false;
}

// E2-DISTRIBUTED (M1): per-domain view used by the infrastructure message handlers.
// A_JOINT authorizes G and E for the same event, so at the moment one domain's AuthzS
// arrives the other domain's transaction is legitimately still open. The node-global
// test rejected the SECOND domain's authorization even though its own domain was idle,
// which silently dropped A_JOINT transactions. Scoping the test to the domain restores
// the intended concurrency while keeping every per-domain check (an open transaction
// of the SAME domain still blocks).
bool UavmaAuthApplication::HasUnresolvedAuthentication(char dom) const {
  for (const auto& entry : m_infraSess) {
    if (entry.second.dom != dom) continue;
    if (!entry.second.gotM3) return true;
  }
  return false;
}

std::string UavmaAuthApplication::RoleName() const {
  return m_isUav ? "UAV" : m_isMm ? "MM" : m_isSite ? "SITE" : "INFRA";
}

// Best-effort own IPv4: the first non-loopback address of the first IPv4 interface.
std::string UavmaAuthApplication::OwnIpv4() const {
  Ptr<Node> node = GetNode();
  if (!node) return "";
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  if (!ipv4) return "";
  for (uint32_t i = 1; i < ipv4->GetNInterfaces(); ++i) {
    for (uint32_t j = 0; j < ipv4->GetNAddresses(i); ++j) {
      const Ipv4InterfaceAddress a = ipv4->GetAddress(i, j);
      if (a.GetLocal() != Ipv4Address::GetLoopback()) return PnetIpStr(a.GetLocal());
    }
  }
  return "";
}

// E2-DISTRIBUTED (M4): sender-side evidence for one emission attempt. Every field is
// taken from the actual Socket::SendTo call, so the ledger can be used to reconstruct
// the reported byte totals independently of the CSV aggregates.
void UavmaAuthApplication::RecordLedger(UavmaIoEvent& e, bool alsoRegistry) {
  e.nodeId = GetNode()->GetId();
  e.role = RoleName();
  if (e.srcIp.empty()) e.srcIp = OwnIpv4();
  // The io-events dump keeps its original meaning (on-wire protocol attempts only);
  // the ledger is the complete sender record, including dropped or failed attempts.
  if (alsoRegistry && e.onWire) UavmaRegistry::Instance().RecordIo(e);
  m_metrics.Ledger(e);
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
  // E2-DISTRIBUTED (HO3): the reserved name must describe the mechanism that
  // really produced the decision. A controlled probe injection is NOT a natural
  // A3-driven event, so it is logged under a different event name; otherwise the
  // evidence trail would falsely show a natural handover in the HO3 scene.
  if (m_log) m_log->event(m_ho3Injecting ? "ho3_controlled_partition_event"
                                         : "natural_partition_event", {
    {"source_cell_id", I(d.sourceCell)}, {"target_cell_id", I(d.targetCell)},
    {"source_edge_id", d.sourceEdge}, {"target_edge_id", d.targetEdge},
    {"g_target_id", d.targetG}, {"event_type", uavma_ns3::EventName(d.event)},
    {"edge_changed", d.edgeChanged ? "true" : "false"},
    {"trigger", m_ho3Injecting ? "controlled_injection" : "natural_a3_handover"},
    {"logical_assignment_only", "true"}, {"t_sim_ms", S(SimNs() / 1e6)}});
  return true;
}

// ---------------------------------------------------------------------------
// E2-DISTRIBUTED (HO3): one controlled E-only logical target change.
//
// Same mechanism as the frozen E2 HO3 probe, adapted to the split P-NET roles:
//   * the UAV mirrors the logical E target through ApplyPartitionDecision(), the same
//     commit the natural A3 handover path uses, so AuthzU demultiplexing and the epoch
//     check stay consistent;
//   * the MM relays the event time to the involved sites and then calls
//     BeginMobilityEventMm(), the production authorization dispatch, so AuthzU and
//     AuthzS are really transmitted;
//   * the G target and the LTE serving cell do NOT change, no RRC handover is
//     triggered, and no G handover is fabricated. Under A_JOINT the existing Select()
//     policy expands the E-only event to both domains; the G domain is then
//     re-authenticated at its ORIGINAL site by the forced same-site path.
// ---------------------------------------------------------------------------
void UavmaAuthApplication::InstallHo3Probe() {
  if (m_ho3AtSec < 0.0 || m_ho3NewETarget.empty()) return;  // probe disabled
  if (!m_hasE) throw std::invalid_argument("HO3 probe requires the E domain");
  if (!m_partitionEnabled)
    throw std::invalid_argument("HO3 probe requires CellToEdgeMap partition mode");
  if (m_ho3NewETarget == m_eTargetId)
    throw std::invalid_argument("HO3 new E target must differ from the current E target");
  if (!(m_ho3ObserveSec > 0.0))
    throw std::invalid_argument("HO3 observation window must be positive");
  if (m_ho3ProbeInstalled) return;
  m_ho3ProbeInstalled = true;
  if (m_log)
    m_log->event("ho3_probe_configured", {{"role", RoleName()},
                                          {"at_sec", S(m_ho3AtSec)},
                                          {"observe_sec", S(m_ho3ObserveSec)},
                                          {"from_e_target", m_eTargetId},
                                          {"to_e_target", m_ho3NewETarget},
                                          {"g_target_id", m_gTargetId},
                                          {"cell_id", I(m_currentCellId)},
                                          {"variant", m_variantName},
                                          {"mechanism", "ho3_probe_controlled_injection"}});
  m_ho3ProbeEvent = Simulator::Schedule(Seconds(m_ho3AtSec),
                                        &UavmaAuthApplication::Ho3Fire, this);
}

void UavmaAuthApplication::Ho3Fire() {
  if (!m_running) return;
  uavma_ns3::PartitionDecision d;
  d.event = uavma_ns3::Event::EOnly;
  d.sourceCell = m_currentCellId;   // unchanged: NO LTE cell switch
  d.targetCell = m_currentCellId;
  d.sourceEdge = m_eTargetId;       // ES_T1
  d.targetEdge = m_ho3NewETarget;   // ES_T2
  d.targetG = m_gTargetId;          // GS_CELL_1, the ORIGINAL G site
  d.edgeChanged = true;
  if (m_isUav) {
    m_ho3Injecting = true;
    const bool committed = ApplyPartitionDecision(d);
    m_ho3Injecting = false;
    if (committed && m_log)
      m_log->event("ho3_e_target_view_sync", {
          {"domain", "E"}, {"e_target", m_eTargetId},
          {"g_target_id", m_gTargetId}, {"cell_id", I(m_currentCellId)},
          {"mechanism", "ho3_probe_controlled_injection"},
          {"logical_assignment_only", "true"},
          {"t_sim_ms", S(SimNs() / 1e6)}});
    return;
  }
  if (!m_isMm) return;  // SITE roles only react to AuthzS / event info
  const auto plan = uavma_ns3::Select(
      m_variant.joint_trigger ? uavma_ns3::Variant::AJoint : uavma_ns3::Variant::P, d.event);
  std::vector<Ipv4Address> sites;
  const auto addSite = [&](const std::string& id) {
    const auto it = m_siteMap.find(id);
    if (it == m_siteMap.end())
      throw std::invalid_argument("SiteMap missing deployment entry: " + id);
    if (std::find(sites.begin(), sites.end(), it->second) == sites.end())
      sites.push_back(it->second);
  };
  if (plan.g && m_hasG) {
    addSite(uavma_ns3::GTargetForCell(d.sourceCell));
    addSite(d.targetG);
  }
  if (plan.e && m_hasE) {
    addSite(d.sourceEdge);
    addSite(d.targetEdge);
  }
  const int64_t eventNs = SimNs();
  RelayEventInfo(eventNs, static_cast<int>(d.event), sites);
  if (m_log)
    m_log->event("ho3_e_change", {
        {"domain", "E"}, {"from", d.sourceEdge}, {"to", d.targetEdge},
        {"g_target_id", d.targetG}, {"cell_id", I(m_currentCellId)},
        {"trigger", "controlled_injection"},
        {"mechanism", "ho3_probe"},
        {"g_switch", "false"},
        {"a_joint_policy", m_variant.joint_trigger ? "existing_select_expands_eonly_to_ge"
                                                   : "not_applicable"},
        {"logical_assignment_only", "true"},
        {"t_sim_ms", S(SimNs() / 1e6)}});
  BeginMobilityEventMm(static_cast<int>(d.event), d, eventNs);
}

void UavmaAuthApplication::HandleTriggerRead(Ptr<Socket> socket) {
  Address from;
  while (Ptr<Packet> p = socket->RecvFrom(from)) {
    const auto packetSize = p->GetSize();
    if (packetSize < 9 || packetSize > 14) continue;
    uint8_t buf[14] = {0};
    p->CopyData(buf, packetSize);
    if (buf[0] == kTriggerPeerInfo && packetSize == 13) {
      // P-NET plumbing: MM -> site, carries the UAV address learned at attach.
      if (m_isSite) {
        uint32_t ip = 0;
        for (int i = 0; i < 4; ++i) ip |= static_cast<uint32_t>(buf[9 + i]) << (8 * i);
        m_peerKnown = true;
        m_peerFullAddr = Ipv4Address(ip);
        if (m_log) m_log->event("peer_info_received", {{"uav_ip", PnetIpStr(m_peerFullAddr)},
                                                       {"t_sim_ms", S(SimNs() / 1e6)}});
      }
      continue;
    }
    if (buf[0] == kTriggerEventInfo && packetSize == 10) {
      // P-NET plumbing: MM -> involved sites, carries the mobility-event time/kind.
      if (m_isSite) {
        std::uint64_t t = 0;
        for (int i = 0; i < 8; ++i) t |= static_cast<std::uint64_t>(buf[1 + i]) << (8 * i);
        m_triggerRecvNs = static_cast<int64_t>(t);
        m_eventKind = buf[9];
        if (m_log) m_log->event("event_info_received", {{"event_ns", I(m_triggerRecvNs)},
                                                        {"event_kind", I(m_eventKind)},
                                                        {"t_sim_ms", S(SimNs() / 1e6)}});
      }
      continue;
    }
    if (buf[0] == kTriggerAttach && packetSize == 9) {
      m_peerKnown = true;
      m_peerFullAddr = InetSocketAddress::ConvertFrom(from).GetIpv4();
      if (m_isMm) BroadcastPeerInfo();
      continue;
    }
    if (m_isSite) continue;  // sites act only on the two P-NET plumbing frames above
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
      if (m_isMm) {
        // P-NET: relay the event time/kind to the involved sites BEFORE any AuthzS
        // leaves, then authorize per domain (AuthzU -> UAV, AuthzS -> source site).
        std::vector<Ipv4Address> sites;
        const auto plan = uavma_ns3::Select(
            m_variant.joint_trigger ? uavma_ns3::Variant::AJoint : uavma_ns3::Variant::P, d.event);
        const auto addSite = [&](const std::string& id) {
          const auto it = m_siteMap.find(id);
          if (it == m_siteMap.end())
            throw std::invalid_argument("SiteMap missing deployment entry: " + id);
          if (std::find(sites.begin(), sites.end(), it->second) == sites.end())
            sites.push_back(it->second);
        };
        if (plan.g && m_hasG) {
          addSite(uavma_ns3::GTargetForCell(d.sourceCell));
          addSite(d.targetG);
        }
        if (plan.e && m_hasE) {
          addSite(d.sourceEdge);
          addSite(d.targetEdge);
        }
        RelayEventInfo(static_cast<int64_t>(t), static_cast<int>(d.event), sites);
        BeginMobilityEventMm(static_cast<int>(d.event), d, static_cast<int64_t>(t));
      } else {
        BeginMobilityEvent(static_cast<int>(d.event), "natural_handover");
      }
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
    // P-NET: only AuthzU (always sent by the MM) defines the UAV's trigger peer.
    // M0/M2 come from the per-transaction target site and must NOT overwrite it;
    // M1/M3 replies use the per-sid peer map. Single-node formal runs had one
    // infrastructure peer for everything, so the unconditional refresh was safe
    // there and is wrong after the split.
    {
      size_t off0 = 0;
      uavma::MsgKind kind0;
      uavma::Bytes payload0;
      const bool decoded0 = uavma::Framing::decode(buf, off0, kind0, payload0);
      if (!m_isUav || (decoded0 && kind0 == uavma::MsgKind::AuthzU)) {
        m_peerKnown = true;
        m_peerFullAddr = InetSocketAddress::ConvertFrom(from).GetIpv4();
      }
    }

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
          OnM0(m, dom, from);
        } else {
          const auto slot = ReserveCpu(dom, {"uav_handle_M0", "uav_build_M1"}, sid);
          Simulator::Schedule(NanoSeconds(slot.delayNs), [this, m, dom, from]() {
            if (m_running) OnM0(m, dom, from);
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

void UavmaAuthApplication::OnM0(const uavma::M0Msg& m, char dom, const Address& from) {
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
  // P-NET: M0 may arrive from any site; remember the per-sid peer so M1/M3 return to
  // the exact site that owns this session (G and E sessions can live on different
  // sites once the infrastructure is split). AuthzU never updates this mapping.
  m_sidPeer[sid] = from;
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
  // [FIX item-1] Reject a first-receive M2 whose UAV session epoch does not match the
  // currently authorized epoch. OnAuthzU installs a newer epoch (e2) WITHOUT resetting
  // the UAV's durable session, so a stale-but-valid M2 from a superseded epoch (e1) could
  // otherwise be accepted here (before e2's M0/M1 overwrite the session), reactivating the
  // old candidate state and emitting a spurious M3.
  if (w.uav->session().epoch != w.authorizedEpoch) {
    if (m_log)
      m_log->event("m2_rejected", {{"sid", sid},
                                   {"reason", "epoch_mismatch_first_receive"},
                                   {"session_epoch", I(static_cast<long long>(w.uav->session().epoch))},
                                   {"authorized_epoch", I(static_cast<long long>(w.authorizedEpoch))}});
    return;  // no UAV state change, no M3
  }
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

// ---------------------------------------------------------------------------
// E2-DISTRIBUTED (M4 / D5): unified byte accounting for ONE transaction.
//
// Every number is read back from the per-message emission ledger, which the sender
// filled from the real Socket::SendTo calls. Nothing here estimates or hard-codes a
// message length:
//   * normal_auth_bytes  - one retransmission-free pass (each message counted ONCE);
//   * full_sent_auth_bytes - every auth UDP payload actually put on the wire, ARQ included;
//   * ul/dl/infra        - split by the real direction of each message;
//   * app_retrans_bytes  - application-layer retransmission payload only.
// If a message was never successfully sent, its contribution is 0 and a completed
// "normal" figure is therefore never fabricated.
// ---------------------------------------------------------------------------
void UavmaAuthApplication::FillAccounting(UavmaTxRecord& t) {
  const std::string domTag = std::string(1, t.domain);
  const std::string authzKey = uavma_ns3::AuthzKey(t.domain, t.epoch);
  const std::string infraKey = "INFRA|" + domTag + "|" + std::to_string(t.epoch);
  auto& reg = UavmaRegistry::Instance();
  const std::pair<std::string, std::string> msgs[] = {
      {authzKey, "AuthzU"}, {infraKey, "AuthzS"}, {infraKey, "Transfer"},
      {t.sid, "M0"},        {t.sid, "M1"},        {t.sid, "M2"}, {t.sid, "M3"}};
  size_t normal = 0, full = 0, ul = 0, dl = 0, infra = 0, retrans = 0;
  for (const auto& km : msgs) {
    const auto s = reg.Emission(km.first + "|" + km.second);
    if (s.count == 0) continue;  // never sent: contributes nothing, never invented
    normal += s.firstBytes;
    full += s.totalBytes;
    retrans += s.retransBytes;
    if (km.second == "M1" || km.second == "M3") ul += s.totalBytes;
    else if (km.second == "AuthzS" || km.second == "Transfer") infra += s.totalBytes;
    else dl += s.totalBytes;
  }
  t.normalAuthBytes = normal;
  t.fullSentAuthBytes = full;
  t.ulAuthBytes = ul;
  t.dlAuthBytes = dl;
  t.infraAuthBytes = infra;
  t.appRetransBytes = retrans;
  if (t.coordBytes == 0) t.coordBytes = m_coordBytes;
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
  // P-NET: AuthzU is emitted by the MM under the domain+epoch alias; add its ACTUAL
  // sent bytes so framed_total keeps the formal UE-facing meaning (AuthzU+M0+M1+M2+M3).
  const auto authzU = UavmaRegistry::Instance().WireUsageFor(uavma_ns3::AuthzKey(dom, t.epoch));
  t.framed += authzU.bytes;
  t.nMsg += authzU.datagrams;
  // P-NET: infrastructure-to-infrastructure datagrams (AuthzS + Transfer) actually
  // sent for this transaction, recorded by the MM and the source site under one key.
  const auto infra = UavmaRegistry::Instance().WireUsageFor("INFRA|" + std::string(1, dom) +
                                                            "|" + std::to_string(t.epoch));
  t.infraFramed = infra.bytes;
  t.infraMsg = infra.datagrams;
  FillAccounting(t);
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
                                           const std::string& altKey, bool isRetrans,
                                           const std::string& wireKey) {
  (void)dir;
  Address to;
  const auto peerIt = m_sidPeer.find(sid);
  if (peerIt != m_sidPeer.end()) {
    to = peerIt->second;  // P-NET: return to the site that owns this session
  } else {
    to = m_peerKnown ? InetSocketAddress(m_peerFullAddr, m_peerPort)
                     : InetSocketAddress(Ipv4Address(m_peerIp.c_str()), m_peerPort);
  }
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
    UavmaRegistry::Instance().RecordWireSend(wireKey.empty() ? sid : wireKey, framed.size());
  }
  // ---- E2-DISTRIBUTED (M4): per-datagram sender evidence + emission ledger ----
  {
    const std::string wireKeyUsed = !wireKey.empty() ? wireKey : (!altKey.empty() ? altKey : sid);
    UavmaIoEvent e;
    e.simNs = t;
    e.recv = false;
    e.retrans = isRetrans;
    e.sid = sid;
    e.msg = msg;
    e.bytes = framed.size();
    e.dom = dom;
    e.key = wireKeyUsed.empty() ? (sid + "|" + msg) : wireKeyUsed;
    e.dir = dir.empty() ? std::string("DL") : dir;
    e.portClass = m_localPort;
    e.onWire = onWire;
    e.sendRc = rc;
    if (!sid.empty()) {
      const auto txIt = m_sidToTx.find(sid);
      if (txIt != m_sidToTx.end()) e.txId = txIt->second;
    }
    if (InetSocketAddress::IsMatchingType(to)) {
      e.dstIp = PnetIpStr(InetSocketAddress::ConvertFrom(to).GetIpv4());
      e.dstPort = InetSocketAddress::ConvertFrom(to).GetPort();
    }
    e.srcPort = m_localPort;
    RecordLedger(e);
    if (onWire) UavmaRegistry::Instance().RecordEmission(e.key + "|" + msg, framed.size(), isRetrans);
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
  e.bytes = r.framedBytes;
  e.dom = r.domain;
  e.key = key;
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
      const auto authzU = UavmaRegistry::Instance().WireUsageFor(
          uavma_ns3::AuthzKey(t.domain, t.epoch));
      t.framed += authzU.bytes;
      t.nMsg += authzU.datagrams;
      const auto infra = UavmaRegistry::Instance().WireUsageFor(
          "INFRA|" + std::string(1, t.domain) + "|" + std::to_string(t.epoch));
      t.infraFramed = infra.bytes;
      t.infraMsg = infra.datagrams;
      FillAccounting(t);
      if (t.reason.empty()) t.reason = "not committed before stop";
      m_metrics.Tx(t);
    }
  }
}

// ---------------------------------------------------------------------------
// P-NET infrastructure: real UDP exchange of the paper's MM->Src (AuthzS) and
// Src->T (Transfer) messages on the infrastructure-to-infrastructure port.
// ---------------------------------------------------------------------------
int64_t UavmaAuthApplication::SendInfraProtocol(const uavma::Bytes& framed, const std::string& msg,
                                                const std::string& matchKey,
                                                const std::string& wireKey, char dom,
                                                const Address& to) {
  Ptr<Packet> p = Create<Packet>(framed.data(), static_cast<uint32_t>(framed.size()));
  const int rc = m_infraSocket->SendTo(p, 0, to);
  if (rc < 0 && m_log) {
    m_log->event("send_failed", {{"msg", msg},
                                 {"bytes", I(static_cast<long long>(framed.size()))},
                                 {"t_sim_ms", S(SimNs() / 1e6)}});
  }
  const int64_t t = SimNs();
  m_frames[matchKey] = framed;  // cache for the (bounded) retransmission path
  if (rc >= 0) {
    UavmaRegistry::Instance().RecordSend(matchKey, t);
    UavmaRegistry::Instance().RecordWireSend(wireKey, framed.size());
  }
  // ---- E2-DISTRIBUTED (M4): per-datagram sender evidence + emission ledger ----
  {
    UavmaIoEvent e;
    e.simNs = t;
    e.recv = false;
    e.retrans = false;
    e.msg = msg;
    e.bytes = framed.size();
    e.dom = dom;
    e.key = wireKey;
    e.dir = "INFRA";
    e.portClass = m_infraPort;
    e.onWire = rc >= 0;
    e.sendRc = rc;
    if (InetSocketAddress::IsMatchingType(to)) {
      e.dstIp = PnetIpStr(InetSocketAddress::ConvertFrom(to).GetIpv4());
      e.dstPort = InetSocketAddress::ConvertFrom(to).GetPort();
    }
    e.srcPort = m_infraPort;
    RecordLedger(e);
    if (rc >= 0) UavmaRegistry::Instance().RecordEmission(wireKey + "|" + msg, framed.size(), false);
  }
  return t;
}

// E2-DISTRIBUTED (M4): the port-9001 channel carries ONLY simulator plumbing
// (attach / handover trigger / peer info / event info). It is recorded so that the
// "coordination bytes" of a run can be reported, and it is never folded into any
// authentication byte total.
void UavmaAuthApplication::RecordCoordSend(const std::string& msg, size_t bytes, char dom,
                                           const Address& to, int rc) {
  if (rc < 0) return;  // a failed coordination datagram carries no bytes
  m_coordBytes += bytes;
  UavmaIoEvent e;
  e.simNs = SimNs();
  e.recv = false;
  e.msg = msg;
  e.bytes = bytes;
  e.dom = dom;
  e.key = "COORD";
  e.dir = "COORD";
  e.portClass = m_triggerPort;
  e.onWire = true;
  e.sendRc = rc;
  if (InetSocketAddress::IsMatchingType(to)) {
    e.dstIp = PnetIpStr(InetSocketAddress::ConvertFrom(to).GetIpv4());
    e.dstPort = InetSocketAddress::ConvertFrom(to).GetPort();
  }
  e.srcPort = m_triggerPort;
  RecordLedger(e, false);  // coordination traffic never enters the protocol io dump
}

void UavmaAuthApplication::HandleInfraRead(Ptr<Socket> socket) {
  Address from;
  while (Ptr<Packet> p = socket->RecvFrom(from)) {
    const uint32_t sz = p->GetSize();
    if (sz == 0) continue;
    uavma::Bytes buf(sz);
    p->CopyData(buf.data(), sz);
    size_t off = 0;
    uavma::MsgKind kind;
    uavma::Bytes payload;
    if (!uavma::Framing::decode(buf, off, kind, payload)) continue;
    size_t o = 0;
    if (kind == uavma::MsgKind::AuthzS) {
      if (!m_isSite) {
        if (m_log) m_log->event("infra_msg_rejected", {{"reason", "authz_s_on_non_site"}});
        continue;
      }
      const uavma::AuthzSMsg m = uavma::AuthzSMsg::from_bytes(payload, o);
      OnAuthzS(m, sz);
    } else if (kind == uavma::MsgKind::Transfer) {
      if (!m_isSite) {
        if (m_log) m_log->event("infra_msg_rejected", {{"reason", "transfer_on_non_site"}});
        continue;
      }
      const uavma::TransferMsg m = uavma::TransferMsg::from_bytes(payload, o);
      const char dom = uavma::domain_char(m.d);
      UavmaDomainWorld& w = World(dom);
      if (!w.target || m.target != w.target->id()) {
        if (m_log) m_log->event("transfer_rejected", {{"reason", "unhosted_target_or_domain"},
                                                       {"target", m.target}});
        continue;
      }
      OnTransfer(m, dom, sz);
    } else {
      if (m_log) m_log->event("infra_msg_rejected", {{"reason", "unexpected_kind"}});
    }
  }
}

// Source site: MM -> Src authorization arrived; emit the paper's Transfer for real.
void UavmaAuthApplication::OnAuthzS(const uavma::AuthzSMsg& m, size_t framedBytes) {
  // The domain pseudonym is domain-specific, so it disambiguates which of this
  // node's hosted target cores the authorization belongs to.
  char dom = 0;
  if (m_hasG && m_g.target && m.pid == m_g.target->pid())
    dom = 'G';
  else if (m_hasE && m_e.target && m.pid == m_e.target->pid())
    dom = 'E';
  if (dom == 0) {
    if (m_log) m_log->event("authz_s_rejected", {{"reason", "pid_domain_unresolved"}});
    return;
  }
  UavmaDomainWorld& w = World(dom);
  const std::string domTag = std::string(1, dom) + "|" + std::to_string(m.epoch);
  UavmaMsgRecord r;
  r.domain = dom;
  r.msg = "AuthzS";
  r.dir = "INFRA";
  r.framedBytes = framedBytes;
  RecordRecvCommon(r, "", "AuthzS|" + domTag);
  if (m.pid != w.target->pid()) {
    if (m_log) m_log->event("authz_s_rejected", {{"domain", std::string(1, dom)},
                                                  {"reason", "pid_mismatch"}});
    return;
  }
  const auto dstIt = m_siteMap.find(m.target);
  // E2-DISTRIBUTED (M1): only THIS domain's open transaction blocks this domain.
  if (HasUnresolvedAuthentication(dom)) {
    if (m_log) m_log->event("authz_s_rejected", {{"domain", std::string(1, dom)},
                                                 {"reason", "unresolved_domain_authentication"}});
    return;
  }
  if (dstIt == m_siteMap.end()) {
    if (m_log) m_log->event("authz_s_rejected", {{"domain", std::string(1, dom)},
                                                 {"reason", "unroutable_target"},
                                                 {"target", m.target}});
    return;
  }
  // E2-DISTRIBUTED (M2/M3): this node ALREADY hosts the authorized target, i.e. the
  // domain does not migrate. A_JOINT still requires the domain to authenticate, so the
  // state is re-installed here, in-site, with NO Transfer datagram on the wire.
  if (m.target == w.target->id()) {
    BeginSameSiteReinstall(dom, m);
    return;
  }
  // Build the Transfer from THIS node's committed/pending state exactly as the legacy
  // single-node path did, then really serialize and send it to the target site.
  uavma::SourceCore src(w.d, w.target->pid());
  src.set_committed(w.target->sc());
  src.set_pending(w.target->pi() ? std::optional<uavma::Pending>(*w.target->pi()) : std::nullopt);
  const uavma::TransferMsg tr = src.build_transfer(m.target, m.epoch);
  const Address to = InetSocketAddress(dstIt->second, m_infraPort);
  // E2-DISTRIBUTED (M3): a REAL cross-site Transfer; its bytes are counted normally.
  m_intraSiteTransfer[dom] = false;
  m_counterfactualInfra[dom] = 0;
  SendInfraProtocol(uavma::Framing::encode(uavma::MsgKind::Transfer, tr.to_bytes()), "Transfer",
                    "Transfer|" + domTag, "INFRA|" + domTag, dom, to);
  if (m_log) m_log->event("transfer_sent", {{"domain", std::string(1, dom)},
                                            {"target", m.target},
                                            {"epoch", I(static_cast<long long>(m.epoch))},
                                            {"base_v", I(tr.sc.v)},
                                            {"has_pi", tr.has_pi ? "true" : "false"},
                                            {"site", PnetIpStr(dstIt->second)},
                                            {"t_sim_ms", S(SimNs() / 1e6)}});
}

// ---------------------------------------------------------------------------
// E2-DISTRIBUTED (M2 + M3): forced re-authentication of a NON-migrating domain.
//
// A_JOINT's Select() returns {G,E} for every event, including events where only one
// domain actually changes target. For the domain that does NOT migrate, the paper's
// semantics still require a fresh authentication, so this path REALLY runs:
//   * the MM has already advanced the epoch and really sent AuthzU (9000) + AuthzS (9002);
//   * this node really builds the protocol Transfer with the same SourceCore encoding;
//   * the state is really re-installed through TargetCore::accept_transfer, with the
//     SAME target_create_session_M0 CPU cost reserved as in the cross-site path.
// What does NOT happen: no target core is created, no cell/target switch occurs, no
// handover is fabricated, and NO Transfer datagram is emitted (the state never leaves
// the node). The bytes such a datagram WOULD have used are derived from the real
// encoding and recorded as a counterfactual, never as sent bytes.
// ---------------------------------------------------------------------------
void UavmaAuthApplication::BeginSameSiteReinstall(char dom, const uavma::AuthzSMsg& m) {
  UavmaDomainWorld& w = World(dom);
  if (m_log)
    m_log->event("forced_same_site_reauth", {{"domain", std::string(1, dom)},
                                             {"target", m.target},
                                             {"epoch", I(static_cast<long long>(m.epoch))},
                                             {"migration", "false"},
                                             {"mechanism", "a_joint_non_migrating_domain"},
                                             {"t_sim_ms", S(SimNs() / 1e6)}});
  if (m_triggerRecvNs < 0) {
    if (m_log) m_log->event("same_site_reauth_rejected", {{"domain", std::string(1, dom)},
                                                          {"reason", "event_info_not_received"}});
    return;
  }
  // Identical construction to the cross-site path, so the counterfactual size is a
  // DERIVED quantity: the real serialization result, not a hard-coded constant.
  uavma::SourceCore src(w.d, w.target->pid());
  src.set_committed(w.target->sc());
  src.set_pending(w.target->pi() ? std::optional<uavma::Pending>(*w.target->pi()) : std::nullopt);
  const uavma::TransferMsg tr = src.build_transfer(m.target, m.epoch);
  const size_t wouldBe = uavma::Framing::encode(uavma::MsgKind::Transfer, tr.to_bytes()).size();
  m_intraSiteTransfer[dom] = true;
  m_counterfactualInfra[dom] = wouldBe;
  if (m_log)
    m_log->event("intra_site_transfer_installed", {
        {"domain", std::string(1, dom)}, {"target", m.target},
        {"epoch", I(static_cast<long long>(m.epoch))},
        {"counterfactual_infra_bytes", I(static_cast<long long>(wouldBe))},
        {"wire_bytes_sent", I(0)},
        {"derivation", "framing_encode_of_real_transfer_not_hardcoded"},
        {"t_sim_ms", S(SimNs() / 1e6)}});
  w.target->accept_transfer(tr);
  if (!m_cpuCalibrated) {
    SiteCreateSession(tr, dom, {});
    return;
  }
  // The in-site computation cost is NOT omitted even though nothing is transmitted.
  const auto slot = ReserveCpu(dom, {"target_create_session_M0"}, "");
  Simulator::Schedule(NanoSeconds(slot.delayNs), [this, tr, dom, slot]() {
    if (m_running) SiteCreateSession(tr, dom, slot);
  });
}

// Target site: the paper's Src -> T Transfer arrived; install state, open session, emit M0.
void UavmaAuthApplication::OnTransfer(const uavma::TransferMsg& m, char dom, size_t framedBytes) {
  UavmaDomainWorld& w = World(dom);
  const std::string domTag = std::string(1, dom) + "|" + std::to_string(m.epoch);
  UavmaMsgRecord r;
  r.domain = dom;
  r.msg = "Transfer";
  r.dir = "INFRA";
  r.framedBytes = framedBytes;
  RecordRecvCommon(r, "", "Transfer|" + domTag);
  if (m.target != w.target->id() || m.pid != w.target->pid()) {
    if (m_log) m_log->event("transfer_rejected", {{"domain", std::string(1, dom)},
                                                   {"reason", "wrong_target_or_pid"},
                                                   {"target", m.target}});
    return;
  }
  // E2-DISTRIBUTED (M1): only THIS domain's open transaction blocks this domain.
  if (HasUnresolvedAuthentication(dom)) {
    if (m_log) m_log->event("transfer_rejected", {{"domain", std::string(1, dom)},
                                                  {"reason", "unresolved_domain_authentication"}});
    return;
  }
  if (m_triggerRecvNs < 0) {
    if (m_log) m_log->event("transfer_rejected", {{"domain", std::string(1, dom)},
                                                  {"reason", "event_info_not_received"}});
    return;
  }
  // A cross-site Transfer really arrived, so the state installation is NOT in-site.
  m_intraSiteTransfer[dom] = false;
  m_counterfactualInfra[dom] = 0;
  // Install the transferred committed/pending state exactly like the legacy path.
  w.target->accept_transfer(m);
  if (!m_cpuCalibrated) {
    SiteCreateSession(m, dom, {});
    return;
  }
  // The E1 target_create_session_M0 cost is reserved on THIS node's lane before M0.
  const auto slot = ReserveCpu(dom, {"target_create_session_M0"}, "");
  Simulator::Schedule(NanoSeconds(slot.delayNs), [this, m, dom, slot]() {
    if (m_running) SiteCreateSession(m, dom, slot);
  });
}

void UavmaAuthApplication::SiteCreateSession(const uavma::TransferMsg& t, char dom,
                                             const uavma_ns3::CpuReservation& preparation) {
  UavmaDomainWorld& w = World(dom);
  const uavma::M0Msg m0 = w.target->create_session(t.pid, t.target, t.epoch);
  const std::string sid = uavma::hex(m0.sid);
  if (m_cpuCalibrated) LogCpu(sid, dom, {"target_create_session_M0"}, preparation);
  // bodyMm / bodyInf are recomputed here from the actually received messages; the
  // values are byte-identical to the legacy single-node accounting.
  uavma::AuthzUMsg au;
  au.target = t.target;
  au.epoch = t.epoch;
  uavma::AuthzSMsg as;
  as.pid = t.pid;
  as.target = t.target;
  as.epoch = t.epoch;
  UavmaTxRecord tx;
  tx.id = m_nextTxId++;
  tx.tTriggerNs = m_triggerRecvNs;
  tx.cpuResourceMode = m_cpuCalibrated ? m_cpuResourceMode : "UNCALIBRATED";
  tx.e1ProfileSha256 = m_e1ProfileSha256;
  tx.domain = dom;
  tx.eventType = uavma_ns3::EventName(static_cast<uavma_ns3::Event>(m_eventKind));
  tx.trigger = "natural_handover";
  tx.variant = m_variantName;
  tx.sid = sid;
  tx.targetId = t.target;
  tx.epoch = t.epoch;
  tx.bodyMm = au.account().body + as.account().body;
  tx.bodyInf = t.account().body;
  tx.bodyDl = m0.account().body;
  // E2-DISTRIBUTED (M3): record HOW this transaction's state was installed.
  const auto intraIt = m_intraSiteTransfer.find(dom);
  tx.migration = !(intraIt != m_intraSiteTransfer.end() && intraIt->second);
  tx.intraSiteTransfer = !tx.migration;
  const auto cfIt = m_counterfactualInfra.find(dom);
  tx.counterfactualInfraBytes = cfIt == m_counterfactualInfra.end() ? 0 : cfIt->second;
  tx.coordBytes = m_coordBytes;
  m_tx[tx.id] = tx;
  m_sidToTx[sid] = tx.id;
  m_sidDomain[sid] = dom;
  m_tx[tx.id].tStartNs = SimNs();
  SendProtocol(uavma::Framing::encode(uavma::MsgKind::M0, m0.to_bytes()), "M0", sid, dom, "DL");
  InfraSess& s = m_infraSess[sid];
  s.dom = dom;
  s.txId = tx.id;
  s.gotM1 = false;
  s.gotM3 = false;
  s.m0Sent = 1;
  s.m2Sent = 0;
  s.rto = Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(m_rtoMs)),
                              &UavmaAuthApplication::OnInfraM0Rto, this, sid);
  if (m_log) m_log->event("session_prepared_pnet", {
      {"domain", std::string(1, dom)}, {"sid", sid}, {"target", t.target},
      {"epoch", I(static_cast<long long>(t.epoch))}, {"t_sim_ms", S(SimNs() / 1e6)}});
}

// MM side of one real mobility event: authorize per triggered domain, emit AuthzU to
// the UAV and AuthzS to the source site. No target core exists here; the M0 path
// belongs to the target site (SiteCreateSession).
void UavmaAuthApplication::BeginMobilityEventMm(int eventKind, const uavma_ns3::PartitionDecision& d,
                                                int64_t eventNs) {
  (void)eventNs;
  const auto event = static_cast<uavma_ns3::Event>(eventKind);
  const auto variant = m_variant.joint_trigger ? uavma_ns3::Variant::AJoint
                                               : uavma_ns3::Variant::P;
  const auto plan = uavma_ns3::Select(variant, event);
  const auto begin = [this, d](char dom) {
    UavmaDomainWorld& w = World(dom);
    const std::string newTarget = (dom == 'G') ? d.targetG : d.targetEdge;
    const std::string srcTarget =
        (dom == 'G') ? uavma_ns3::GTargetForCell(d.sourceCell) : d.sourceEdge;
    const auto srcIt = m_siteMap.find(srcTarget);
    const auto dstIt = m_siteMap.find(newTarget);
    // E2-DISTRIBUTED (M2): a domain whose target does NOT change is skipped unless the
    // run explicitly asks for the forced same-site re-authentication that A_JOINT's
    // policy implies. Both variants keep the same authorization state machine.
    const bool nonMigrating = (srcTarget == newTarget);
    if (srcIt == m_siteMap.end() || dstIt == m_siteMap.end()) {
      if (m_log) m_log->event("pnet_authorize_rejected", {
          {"domain", std::string(1, dom)}, {"reason", "unroutable_site_pair"},
          {"source_target", srcTarget}, {"target", newTarget}});
      return;
    }
    if (nonMigrating && !(m_allowForcedSameSiteReauth && m_variant.joint_trigger)) {
      if (m_log) m_log->event("pnet_authorize_rejected", {
          {"domain", std::string(1, dom)}, {"reason", "non_migrating_domain_not_selected"},
          {"source_target", srcTarget}, {"target", newTarget},
          {"variant", m_variantName}});
      return;
    }
    if (nonMigrating && m_log)
      m_log->event("forced_same_site_reauth_authorized", {
          {"domain", std::string(1, dom)}, {"target", newTarget},
          {"migration", "false"}, {"variant", m_variantName},
          {"site", PnetIpStr(srcIt->second)},
          {"authz_s_will_be_sent", "true"}, {"t_sim_ms", S(SimNs() / 1e6)}});
    const uint64_t epoch = w.mm->authorize(newTarget);
    const uavma::AuthzUMsg au = w.mm->authz_u();
    const uavma::AuthzSMsg as = w.mm->authz_s(w.pid);
    const std::string authzKey = uavma_ns3::AuthzKey(dom, epoch);
    const std::string domTag = std::string(1, dom) + "|" + std::to_string(epoch);
    // AuthzU (MM -> U): identical message and encoding to the formal single-node run.
    const uavma::Bytes auFramed = uavma::Framing::encode(uavma::MsgKind::AuthzU, au.to_bytes());
    SendProtocol(auFramed, "AuthzU", "", dom, "DL", authzKey, false, authzKey);
    // AuthzU is sent exactly once per transaction, as in the formal single-node
    // protocol; its only retransmission path is the target site's M0-RTO recovery
    // (requires a genuinely lost M1). No standalone MM timer exists upstream.
    // AuthzS (MM -> Src): the paper's MM->Src message, now really on the wire.
    const Address to = InetSocketAddress(srcIt->second, m_infraPort);
    SendInfraProtocol(uavma::Framing::encode(uavma::MsgKind::AuthzS, as.to_bytes()), "AuthzS",
                      "AuthzS|" + domTag, "INFRA|" + domTag, dom, to);
    if (m_log) m_log->event("pnet_authorized", {
        {"domain", std::string(1, dom)}, {"epoch", I(static_cast<long long>(epoch))},
        {"source_target", srcTarget}, {"target", newTarget},
        {"migration", nonMigrating ? "false" : "true"},
        {"source_site", PnetIpStr(srcIt->second)}, {"t_sim_ms", S(SimNs() / 1e6)}});
  };
  if (plan.g && m_hasG) begin('G');
  if (plan.e && m_hasE) begin('E');
}

// MM-side bounded AuthzU retransmission (mirrors the infra ARQ contract: cached
// bytes, bounded attempts, no new PUFEval or signature).
void UavmaAuthApplication::OnMmAuthzRto(std::string key) {
  if (!m_running) return;
  const auto frameIt = m_mmAuthz.find(key);
  if (frameIt == m_mmAuthz.end()) return;
  const uint32_t sent = m_mmAuthzSent[key];
  if (sent > m_maxRetrans) return;
  const char dom = key.size() > 7 ? key[7] : 'G';
  SendProtocol(frameIt->second, "AuthzU", "", dom, "DL", key, true, key);
  m_mmAuthzSent[key] = sent + 1;
  m_mmAuthzRto[key] = Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(m_rtoMs)),
                                          &UavmaAuthApplication::OnMmAuthzRto, this, key);
}

}  // namespace ns3
