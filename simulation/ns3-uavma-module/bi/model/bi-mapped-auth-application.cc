// SPDX-License-Identifier: GPL-2.0-only
#include "bi-mapped-auth-application.h"
#include "uavma-bi-gate-bridge.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4.h"
#include "ns3/lte-ue-net-device.h"
#include "ns3/lte-ue-rrc.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/ipv4-address.h"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/type-id.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <stdexcept>
#include <utility>
#include <vector>

namespace ns3 {
NS_LOG_COMPONENT_DEFINE("BiMappedAuthApplication");
NS_OBJECT_ENSURE_REGISTERED(BiMappedAuthApplication);
namespace {
using R=e2b::Role;
struct Endpoint { Ipv4Address ip;std::uint16_t port; };
struct Metric {
  std::uint64_t correlation=0,ns=0;
  std::string actor,event,detail;
  std::uint64_t bytes=0,hostUs=0,serviceUs=0,queueUs=0;
};
std::map<R,Endpoint> directory;
e2b::Identities identities;
std::vector<Metric> measurements;
std::map<std::uint64_t,std::uint64_t> opportunity,prepReady,completed,rrcStart,rrcEnd;
std::map<std::uint64_t,std::uint16_t> targetCell;
void Record(std::uint64_t corr,const std::string& actor,const std::string& event,
            const std::string& detail="",std::uint64_t bytes=0,
            std::uint64_t host=0,std::uint64_t service=0,std::uint64_t queue=0) {
  measurements.push_back({corr,static_cast<std::uint64_t>(Simulator::Now().GetNanoSeconds()),
                          actor,event,detail,bytes,host,service,queue});
}
R ParseRole(const std::string& value) {
  if(value=="UE")return R::UE;
  if(value=="S_GNB")return R::SourceGnb;
  if(value=="T_GNB")return R::TargetGnb;
  if(value=="S_MEH")return R::SourceMeh;
  if(value=="T_MEH")return R::TargetMeh;
  throw std::invalid_argument("unknown Bi role: "+value);
}
R ExpectedSender(e2b::BiMsg m) {
  using M=e2b::BiMsg;
  switch(m) {
    case M::PrepStart: case M::PrepM2: case M::PrepForwardM3:
    case M::ExecCommand: return R::SourceGnb;
    case M::PrepM1: case M::PrepC1: case M::PrepContext: return R::SourceMeh;
    case M::PrepForwardM1: case M::PrepM4: case M::ExecForwardM5:
    case M::ExecAck12: return R::TargetGnb;
    case M::PrepM3: case M::PrepContextAck: case M::ExecAck1: return R::TargetMeh;
    case M::ExecM5M6: return R::UE;
    default: throw std::invalid_argument("unsupported Bi frame sender in E2-B");
  }
}
void WriteAggregate(const std::string& path) {
  std::filesystem::create_directories(path);
  const auto log=path+"/bi_message_events.csv";
  const auto summary=path+"/bi_transactions.csv";
  if(std::filesystem::exists(log)||std::filesystem::exists(summary))
    throw std::runtime_error("refusing overwrite of previous Bi run");
  std::ofstream eventOut(log);
  eventOut<<"correlation,sim_ns,role,event,detail,framed_bytes,host_cpu_us,modeled_service_us,modeled_queue_us\n";
  for(const auto& m:measurements)
    eventOut<<m.correlation<<','<<m.ns<<','<<m.actor<<','<<m.event<<','<<m.detail<<','
            <<m.bytes<<','<<m.hostUs<<','<<m.serviceUs<<','<<m.queueUs<<'\n';
  std::ofstream tx(summary);
  tx<<"correlation,opportunity_ns,preparation_ready_ns,dual_ack_ready_ns,rrc_start_ns,rrc_end_ns,prep_ms,total_auth_ms,post_ho_auth_wait_ms,completed,framed_sent_bytes,modeled_service_us,host_cpu_us\n";
  for(const auto& [id,start]:opportunity) {
    std::uint64_t ready=prepReady.count(id)?prepReady.at(id):0;
    std::uint64_t end=completed.count(id)?completed.at(id):0;
    std::uint64_t framed=0,cpu=0,host=0;
    for(const auto& m:measurements) if(m.correlation==id) {
      if(m.event=="SEND")framed+=m.bytes;
      cpu+=m.serviceUs;host+=m.hostUs;
    }
    const auto hoBegin=rrcStart.count(id)?rrcStart.at(id):0;
    const auto hoFinish=rrcEnd.count(id)?rrcEnd.at(id):0;
    tx<<id<<','<<start<<','<<ready<<','<<end<<','<<hoBegin<<','<<hoFinish<<',';
    if(ready>=start&&ready)tx<<std::fixed<<std::setprecision(6)<<static_cast<double>(ready-start)/1e6;
    tx<<',';
    if(end>=start&&end)tx<<std::fixed<<std::setprecision(6)<<static_cast<double>(end-start)/1e6;
    tx<<',';
    if(hoBegin && hoFinish && end) {
      auto endAuthorization=std::max(hoFinish,end);
      tx<<std::fixed<<std::setprecision(6)<<static_cast<double>(endAuthorization-hoBegin)/1e6;
    }
    tx<<','<<(end?1:0)<<','<<framed<<','<<cpu<<','<<host<<'\n';
  }
}
} // namespace

TypeId BiMappedAuthApplication::GetTypeId() {
  static TypeId tid=TypeId("ns3::BiMappedAuthApplication")
    .SetParent<Application>().SetGroupName("Applications")
    .AddConstructor<BiMappedAuthApplication>()
    .AddAttribute("Role","Bi participant, UE/S_GNB/T_GNB/S_MEH/T_MEH",
                  StringValue("S_GNB"),MakeStringAccessor(&BiMappedAuthApplication::roleName_),MakeStringChecker())
    .AddAttribute("SeedTag","Pre-registered long-term session state for mapped Bi",
                  StringValue("E2B_BI_REGISTRATION"),MakeStringAccessor(&BiMappedAuthApplication::seedTag_),MakeStringChecker())
    .AddAttribute("Port","Real UDP port for all Bi actors",UintegerValue(9300),
                  MakeUintegerAccessor(&BiMappedAuthApplication::port_),MakeUintegerChecker<std::uint16_t>())
    .AddAttribute("OutputDirectory","New experiment output; source gNB writes after its StopTime",
                  StringValue(""),MakeStringAccessor(&BiMappedAuthApplication::outputDir_),MakeStringChecker())
    .AddAttribute("CpuProfilePath","Measured Bi role/step mean CPU service (CSV)",
                  StringValue(""),MakeStringAccessor(&BiMappedAuthApplication::cpuProfilePath_),MakeStringChecker());
  return tid;
}
e2b::Role BiMappedAuthApplication::Role() const { return ParseRole(roleName_); }
Ipv4Address BiMappedAuthApplication::DetermineOwnIp() const {
  Ptr<Ipv4> ipv4=GetNode()->GetObject<Ipv4>();
  if(!ipv4)throw std::runtime_error("Bi actor has no IPv4 stack");
  for(std::uint32_t i=1;i<ipv4->GetNInterfaces();++i)
    for(std::uint32_t j=0;j<ipv4->GetNAddresses(i);++j) {
      const auto addr=ipv4->GetAddress(i,j).GetLocal();
      if(addr!=Ipv4Address("0.0.0.0") && addr!=Ipv4Address("127.0.0.1"))return addr;
    }
  throw std::runtime_error("Bi actor has no reachable IPv4 interface");
}
void BiMappedAuthApplication::ParseProfile() {
  if(cpuProfilePath_.empty())throw std::runtime_error("Bi calibrated CPU profile missing; do not run without baseline");
  std::ifstream input(cpuProfilePath_);
  if(!input)throw std::runtime_error("Bi CPU profile not readable: "+cpuProfilePath_);
  std::string line;std::getline(input,line);
  if(line!="role,operation,mean_us,n")throw std::runtime_error("Bi invalid calibration CSV header");
  while(std::getline(input,line)) {
    const auto comma1=line.find(','),comma2=line.find(',',comma1+1),comma3=line.find(',',comma2+1);
    if(comma1==std::string::npos||comma2==std::string::npos||comma3==std::string::npos)
      throw std::runtime_error("invalid Bi calibration row");
    if(line.substr(0,comma1)!=roleName_) continue;
    auto name=line.substr(comma1+1,comma2-comma1-1);
    double mean=std::stod(line.substr(comma2+1,comma3-comma2-1));
    int repeats=std::stoi(line.substr(comma3+1));
    if(!std::isfinite(mean)||mean<=0||repeats<10)throw std::runtime_error("unverified Bi CPU calibration");
    serviceProfileUs_[name]=static_cast<std::uint64_t>(std::ceil(mean));
  }
  if(serviceProfileUs_.empty())throw std::runtime_error("Bi calibration no entries for role "+roleName_);
}
std::uint64_t BiMappedAuthApplication::CpuServiceUs(const std::string& operation) const {
  auto p=serviceProfileUs_.find(operation);
  if(p==serviceProfileUs_.end())throw std::runtime_error("Bi CPU profile missing "+roleName_+"/"+operation);
  return p->second;
}
void BiMappedAuthApplication::StartApplication() {
  if(started_)throw std::logic_error("Bi actor already started");
  if(roleName_=="P_A3_OBSERVER") {
    if(outputDir_.empty())throw std::runtime_error("P observer output dir not configured");
    started_=true;return;
  }
  ParseProfile();
  engine_=std::make_unique<e2b::BiProtocolEngine>(Role(),identities,seedTag_);
  socket_=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
  if(socket_->Bind(InetSocketAddress(Ipv4Address::GetAny(),port_))!=0)
    throw std::runtime_error("Bi UDP bind failed");
  socket_->SetRecvCallback(MakeCallback(&BiMappedAuthApplication::HandleRecv,this));
  if(!directory.emplace(Role(),Endpoint{DetermineOwnIp(),port_}).second)
    throw std::runtime_error("duplicate Bi role application");
  started_=true;
  if(Role()==R::UE)ConnectUeRrc();
  if(Role()==R::SourceGnb) {
    if(outputDir_.empty())throw std::runtime_error("Bi output dir must not be empty");
    BiGateBridge::SetController([this](std::uint64_t correlation,std::uint16_t target) {
      this->OnDecision(correlation,target);
    });
  }
  Record(0,roleName_,"START");
}
void BiMappedAuthApplication::StopApplication() {
  if(roleName_=="P_A3_OBSERVER") {
    std::filesystem::create_directories(outputDir_);
    BiGateBridge::ExportPObservations(outputDir_+"/p_a3_opportunities.csv");
    started_=false;return;
  }
  Record(0,roleName_,"STOP");
  if(Role()==R::SourceGnb) {
    BiGateBridge::SetController({});
    WriteAggregate(outputDir_);
  }
  if(socket_) {socket_->Close(); socket_=nullptr;}
  directory.erase(Role());
  engine_.reset();started_=false;
}
void BiMappedAuthApplication::OnDecision(std::uint64_t correlation,std::uint16_t target) {
  const auto now=static_cast<std::uint64_t>(Simulator::Now().GetNanoSeconds());
  if(!engine_ || !correlation || !target) throw std::runtime_error("invalid Bi A3 opportunity");
  if(!opportunity.emplace(correlation,now).second)throw std::logic_error("duplicate Bi opportunity");
  targets_[correlation]=target;
  targetCell[correlation]=target;
  Record(correlation,roleName_,"A3_OPPORTUNITY",std::to_string(target));
  const auto started=std::chrono::steady_clock::now();
  auto result=engine_->Begin(correlation,target,now);
  const auto ended=std::chrono::steady_clock::now();
  const auto host=std::max<std::uint64_t>(1,
     std::chrono::duration_cast<std::chrono::microseconds>(ended-started).count());
  ScheduleOutput(std::move(result),correlation,now,"BI_BEGIN",host);
}
void BiMappedAuthApplication::HandleRecv(Ptr<Socket> socket) {
  Address address;
  while(auto packet=socket->RecvFrom(address)) {
    auto n=packet->GetSize();
    if(n==0)continue;
    std::vector<std::uint8_t> input(n);
    packet->CopyData(input.data(),input.size());
    const auto now=static_cast<std::uint64_t>(Simulator::Now().GetNanoSeconds());
    try {
      auto frame=e2b::BiWire::Decode(input);
      const auto expected=ExpectedSender(frame.type);
      auto it=directory.find(expected);
      if(it==directory.end() || !InetSocketAddress::IsMatchingType(address) ||
         InetSocketAddress::ConvertFrom(address).GetIpv4()!=it->second.ip)
        throw std::runtime_error("Bi sender endpoint mismatch");
      Record(frame.correlation,roleName_,"RECV",std::to_string(static_cast<int>(frame.type)),n);
      auto started=std::chrono::steady_clock::now();
      auto result=engine_->Handle(frame,now);
      auto ended=std::chrono::steady_clock::now();
      const auto host=std::max<std::uint64_t>(1,
         std::chrono::duration_cast<std::chrono::microseconds>(ended-started).count());
      ScheduleOutput(std::move(result),frame.correlation,now,
                     "RX_"+std::to_string(static_cast<int>(frame.type)),host);
    } catch(const std::exception& e) {
      Record(0,roleName_,"REJECT",e.what());
      NS_LOG_WARN("Rejected Bi message at " << roleName_ << ": " << e.what());
    }
  }
}
void BiMappedAuthApplication::ScheduleOutput(e2b::EngineResult result,std::uint64_t corr,
                              std::uint64_t receivedAt,const std::string& operation,
                              std::uint64_t hostUs) {
  const auto now=static_cast<std::uint64_t>(Simulator::Now().GetNanoSeconds());
  const auto requested=CpuServiceUs(operation);
  const auto start=std::max(now,cpuAvailableNs_);
  const auto available=start+requested*1000;
  if(available>static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
    throw std::overflow_error("Bi CPU modeled timestamp overflow");
  cpuAvailableNs_=available;
  const auto queueUs=(start-now)/1000;
  Record(corr,roleName_,"CPU",operation,0,hostUs,requested,queueUs);
  Simulator::Schedule(NanoSeconds(available-now),
      &BiMappedAuthApplication::DispatchAfterCpu,this,std::move(result),corr,receivedAt,operation);
}
void BiMappedAuthApplication::DispatchAfterCpu(e2b::EngineResult result,
             std::uint64_t corr,std::uint64_t,const std::string&) {
  if(!started_)return;
  if(Role()==R::SourceGnb && result.prepared_and_verified) {
    auto target=targets_.find(corr);
    if(target==targets_.end() || !BiGateBridge::Approve(corr,target->second,true))
      throw std::runtime_error("Bi prepared-but-no-valid-LTE-gate; cannot release handover");
    prepReady[corr]=static_cast<std::uint64_t>(Simulator::Now().GetNanoSeconds());
    Record(corr,roleName_,"PREPARATION_VERIFIED",std::to_string(target->second));
  }
  Dispatch(result);
  // Strict terminal milestone: UE has verified both domain ACKs AND the
  // profiled RX_12 computation has finished. No synthetic MappedReady is sent.
  if(Role()==R::UE && engine_->Completed(corr)) {
    if(!completed.count(corr)) {
      completed[corr]=static_cast<std::uint64_t>(Simulator::Now().GetNanoSeconds());
      Record(corr,roleName_,"DUAL_ACK_VERIFIED");
    }
  }
}
void BiMappedAuthApplication::Dispatch(const e2b::EngineResult& result) {
  for(const auto& outbound:result.send) {
    auto found=directory.find(outbound.to);
    if(found==directory.end())throw std::runtime_error("Bi peer not installed or started");
    e2b::BiFrame frame=outbound.frame;
    frame.sequence=++sequence_;
    auto bytes=e2b::BiWire::Encode(frame);
    auto packet=Create<Packet>(bytes.data(),bytes.size());
    int sent=socket_->SendTo(packet,0,InetSocketAddress(found->second.ip,found->second.port));
    if(sent!=static_cast<int>(bytes.size()))
      throw std::runtime_error("Bi UDP packet was not accepted by socket");
    Record(frame.correlation,roleName_,"SEND",std::to_string(static_cast<int>(frame.type)),bytes.size());
  }
}
} // namespace ns3

namespace ns3 {
void BiMappedAuthApplication::ConnectUeRrc() {
  auto node=GetNode();
  for(std::uint32_t i=0;i<node->GetNDevices();++i) {
    auto device=DynamicCast<LteUeNetDevice>(node->GetDevice(i));
    if(!device || !device->GetRrc()) continue;
    device->GetRrc()->TraceConnectWithoutContext("HandoverStart",
                              MakeCallback(&BiMappedAuthApplication::OnRrcStart,this));
    device->GetRrc()->TraceConnectWithoutContext("HandoverEndOk",
                              MakeCallback(&BiMappedAuthApplication::OnRrcEnd,this));
  }
}
void BiMappedAuthApplication::OnRrcStart(std::uint64_t,std::uint16_t,
                                         std::uint16_t,std::uint16_t target) {
  const auto now=static_cast<std::uint64_t>(Simulator::Now().GetNanoSeconds());
  currentHandoverCorr_=0;
  for(const auto& pair:opportunity) {
    if(targetCell[pair.first]==target && !rrcStart.count(pair.first)) {
      currentHandoverCorr_=pair.first;break;
    }
  }
  if(currentHandoverCorr_)rrcStart[currentHandoverCorr_]=now;
  Record(currentHandoverCorr_,roleName_,"RRC_START",std::to_string(target));
}
void BiMappedAuthApplication::OnRrcEnd(std::uint64_t,std::uint16_t cell,std::uint16_t) {
  const auto now=static_cast<std::uint64_t>(Simulator::Now().GetNanoSeconds());
  if(currentHandoverCorr_)rrcEnd[currentHandoverCorr_]=now;
  Record(currentHandoverCorr_,roleName_,"RRC_END",std::to_string(cell));
  currentHandoverCorr_=0;
}
} // namespace ns3
