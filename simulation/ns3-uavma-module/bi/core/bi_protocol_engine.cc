// SPDX-License-Identifier: MIT
#include "bi_protocol_engine.h"
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace e2b {
namespace {
namespace K {
constexpr FieldId Target=1,Time=2,R1=3,C1=4,Sig1=5,H1=6,N1=7,Sig2=8,H2=9,
  M1=10,N2=11,R2=12,C2=13,Sig4=14,SigTargetMeh=15,H3=16,
  RtMeh=17,T4=18,M3=19,Sig3=20,SigTargetGnb=21,H4=22,NtGnb=23,
  Context=24,C1Enc=25,C2Enc=26,H1Exec=27,Re=28,SigUeE=29,
  H2Exec=30,Rg=31,SigUeG=32,H3Exec=33,M5=34,Ack1=35,Ack2=36,
  Tag=38,T3=39,Extra=40;
}
void Require(bool good, const char* message) {
  if(!good) throw std::invalid_argument(message);
}
void Sign(Fields& f,FieldId sig, const std::string& stage,std::uint64_t corr,const EcKey& k) {
  f.Put(sig,k.SignSha256(SignedText(stage,corr,f,sig)));
}
void Verify(const Fields& f,FieldId sig,const std::string& stage,std::uint64_t corr,
            Identities& ids,Identity id) {
  const auto key=EcKey::ImportPublic(ids.Public(id));
  Require(key.VerifySha256(SignedText(stage,corr,f,sig),f.Get(sig)),"Bi signature verification failed");
}
void HashPut(Fields& f,FieldId dest,const std::string& label,std::uint64_t corr,
             const Bytes& key={}) {
  f.Put(dest, TaggedHash(label,corr,f.Encode(),key));
}
void Send(EngineResult& o,Role to,BiMsg type,std::uint64_t corr,const Fields& f) {
  BiFrame packet;packet.type=type;packet.correlation=corr;packet.payload=f.Encode();
  o.send.push_back({to,std::move(packet)});
}
Fields MakeTarget(uint16_t target,std::uint64_t now) {
  Fields f;f.PutU64(K::Target,target);f.PutU64(K::Time,now);return f;
}
void CheckTarget(const Fields& f, const BiSession& s) {
  Require(f.GetU64(K::Target)==s.targetCell,"Bi target cell differs from pending handover");
}
void Stage(BiSession& s,int expected,int next) {
  Require(s.stage==expected,"Bi unexpected/replayed stage");s.stage=next;
}
void VerifyTargetSig(Identities& identities,Identity id,const Bytes& point,
                     std::uint16_t cell,std::uint64_t stamp,const Bytes& sig) {
  Fields f=MakeTarget(cell,stamp);f.Put(K::Extra,point);f.Put(K::SigTargetMeh,sig);
  const auto k=EcKey::ImportPublic(identities.Public(id));
  Require(k.VerifySha256(SignedText("BI_TARGET_EPHEMERAL",0,f,K::SigTargetMeh),sig),
          "Bi target ephemeral signature failed");
}
Bytes SignTarget(const EcKey& key,const Bytes& point,uint16_t cell,std::uint64_t stamp) {
  Fields f=MakeTarget(cell,stamp);f.Put(K::Extra,point);
  return key.SignSha256(SignedText("BI_TARGET_EPHEMERAL",0,f,K::SigTargetMeh));
}
} // namespace

std::string RoleName(Role r) {
  switch(r) {
    case Role::UE: return "UE";
    case Role::SourceGnb: return "S_GNB";
    case Role::TargetGnb: return "T_GNB";
    case Role::SourceMeh: return "S_MEH";
    case Role::TargetMeh: return "T_MEH";
  }
  throw std::invalid_argument("Bi unknown actor");
}
BiProtocolEngine::BiProtocolEngine(Role role, Identities& ids,std::string seed)
    : role_(role),identities_(ids),seed_(std::move(seed)) {
  Require(!seed_.empty(),"Bi pre-established registration seed is required");
}
Identity BiProtocolEngine::IdentityFor(Role role) {
  switch(role) {
    case Role::UE: return Identity::UE_G;
    case Role::SourceGnb: return Identity::S_GNB;
    case Role::TargetGnb: return Identity::T_GNB;
    case Role::SourceMeh: return Identity::S_MEH;
    case Role::TargetMeh: return Identity::T_MEH;
  }
  throw std::invalid_argument("Bi actor missing identity");
}
const EcKey& BiProtocolEngine::Key() const { return identities_.Private(IdentityFor(role_)); }
Bytes BiProtocolEngine::OldKey(char domain) const {
  Require(domain=='G'||domain=='E',"invalid Bi registration domain");
  return EstablishedKey(seed_,std::string(1,domain));
}
bool BiProtocolEngine::Completed(uint64_t corr) const {
  auto it=sessions_.find(corr);return it!=sessions_.end()&&it->second.completion;
}
uint16_t BiProtocolEngine::Target(uint64_t corr) const {
  auto it=sessions_.find(corr);return it==sessions_.end()?0:it->second.targetCell;
}
EngineResult BiProtocolEngine::Begin(uint64_t corr,uint16_t cell,uint64_t ns) {
  Require(role_==Role::SourceGnb && corr && cell && ns>0,"Bi only source gNB begins handover");
  Require(!sessions_.count(corr),"duplicate Bi handover correlation");
  auto& s=sessions_[corr];s.targetCell=cell;s.openedNs=ns;s.stage=1;
  Fields f=MakeTarget(cell,ns);
  EngineResult r;Send(r,Role::SourceMeh,BiMsg::PrepStart,corr,f);return r;
}
EngineResult BiProtocolEngine::Handle(const BiFrame& f,uint64_t nowNs) {
  Require(f.correlation>0 && nowNs>0,"invalid Bi message correlation/time");
  const Fields fields=Fields::Decode(f.payload);
  const auto target=fields.GetU64(K::Target);
  Require(target>0&&target<=65535,"Bi invalid target");
  auto it=sessions_.find(f.correlation);
  if(it==sessions_.end()) {
    bool first=(role_==Role::SourceMeh&&f.type==BiMsg::PrepStart) ||
      (role_==Role::TargetGnb&&f.type==BiMsg::PrepM2) ||
      (role_==Role::TargetMeh&&f.type==BiMsg::PrepForwardM1) ||
      (role_==Role::UE&&f.type==BiMsg::ExecCommand);
    Require(first,"Bi message without established corresponding session");
    it=sessions_.try_emplace(f.correlation).first;
    it->second.targetCell=static_cast<uint16_t>(target);
    it->second.openedNs=nowNs;
  }
  CheckTarget(fields,it->second);
  return Process(it->second,f,nowNs);
}
EngineResult BiProtocolEngine::Process(BiSession& s,const BiFrame& frame,uint64_t now) {
  auto corr=frame.correlation;
  const Fields f=Fields::Decode(frame.payload);
  EngineResult o;
  const auto tm=identities_.Public(Identity::T_MEH);
  const auto tg=identities_.Public(Identity::T_GNB);
  switch(role_) {
  case Role::SourceMeh:
    if(frame.type==BiMsg::PrepStart) {
      Stage(s,0,1);
      s.ownFirst=BiEphemeral::Generate();
      Fields m=MakeTarget(s.targetCell,now);
      m.Put(K::R1,s.ownFirst.point);
      m.Put(K::C1,SealEcies(tm,DomainDigest("MESREQ",corr,{}),DomainDigest("M1",corr,{})));
      HashPut(m,K::H1,"M1_INTEGRITY",corr);
      Sign(m,K::Sig1,"M1",corr,Key());
      s.messageM1=m.Encode();
      Send(o,Role::SourceGnb,BiMsg::PrepM1,corr,m);
    } else if(frame.type==BiMsg::PrepForwardM3) {
      Stage(s,1,2);
      Verify(f,K::Sig4,"M3",corr,identities_,Identity::T_MEH);
      s.peerR2=f.Get(K::R2);s.targetRtMeh=f.Get(K::RtMeh);
      s.targetTimeMeh=f.GetU64(K::T4);s.sigTargetMeh=f.Get(K::SigTargetMeh);
      VerifyTargetSig(identities_,Identity::T_MEH,s.targetRtMeh,s.targetCell,
                      s.targetTimeMeh,s.sigTargetMeh);
      const auto unused=OpenEcies(Key(),f.Get(K::C2),DomainDigest("M3",corr,{}));
      Require(!unused.empty(),"empty decrypted M3");
      s.serviceKey=AsBytes(EvolveDomainKey(Key(),s.ownFirst,
                       identities_.Public(Identity::T_MEH),s.peerR2));
      Fields check=MakeTarget(s.targetCell,f.GetU64(K::Time));
      check.Put(K::R2,s.peerR2);check.Put(K::RtMeh,s.targetRtMeh);check.Put(K::C2,f.Get(K::C2));
      Require(EqualSecret(f.Get(K::H3),TaggedHash("M3_MIGRATION",corr,check.Encode(),s.serviceKey)),
              "Bi migration-channel confirmation failed");
      Fields context=MakeTarget(s.targetCell,now);
      context.Put(K::Context,SealAesGcm(s.serviceKey,DomainDigest("MEH_CONTEXT",corr,{}),
                                         DomainDigest("CONTEXT",corr,{})));
      Send(o,Role::TargetMeh,BiMsg::PrepContext,corr,context);
    } else if(frame.type==BiMsg::PrepContextAck) {
      Stage(s,2,3);
      Require(EqualSecret(f.Get(K::Tag),TaggedHash("CONTEXT_CONFIRMED",corr,{},s.serviceKey)),
              "Bi migration context ACK failed");
      Fields inner=MakeTarget(s.targetCell,s.targetTimeMeh);
      inner.Put(K::RtMeh,s.targetRtMeh);inner.Put(K::SigTargetMeh,s.sigTargetMeh);
      Fields envelope=MakeTarget(s.targetCell,now);
      envelope.Put(K::C1Enc,SealAesGcm(OldKey('E'),inner.Encode(),DomainDigest("C1",corr,{})));
      Send(o,Role::SourceGnb,BiMsg::PrepC1,corr,envelope);
    } else throw std::invalid_argument("unexpected S-MEH message");
    break;
  case Role::SourceGnb:
    if(frame.type==BiMsg::PrepM1) {
      Stage(s,1,2);
      Verify(f,K::Sig1,"M1",corr,identities_,Identity::S_MEH);
      Fields h=MakeTarget(s.targetCell,f.GetU64(K::Time));h.Put(K::R1,f.Get(K::R1));h.Put(K::C1,f.Get(K::C1));
      Require(EqualSecret(f.Get(K::H1),TaggedHash("M1_INTEGRITY",corr,h.Encode())),"M1 integrity");
      s.messageM1=f.Encode();
      s.ownFirst=BiEphemeral::Generate();
      Fields m=MakeTarget(s.targetCell,now);m.Put(K::M1,s.messageM1);m.Put(K::N1,s.ownFirst.point);
      HashPut(m,K::H2,"M2_INTEGRITY",corr);Sign(m,K::Sig2,"M2",corr,Key());
      Send(o,Role::TargetGnb,BiMsg::PrepM2,corr,m);
    } else if(frame.type==BiMsg::PrepM4) {
      Stage(s,2,3);
      Verify(f,K::Sig3,"M4",corr,identities_,Identity::T_GNB);
      s.peerN2=f.Get(K::N2);s.targetNtGnb=f.Get(K::NtGnb);
      s.targetTimeGnb=f.GetU64(K::T3);s.sigTargetGnb=f.Get(K::SigTargetGnb);
      VerifyTargetSig(identities_,Identity::T_GNB,s.targetNtGnb,s.targetCell,
                      s.targetTimeGnb,s.sigTargetGnb);
      s.gatewayKey=AsBytes(EvolveDomainKey(Key(),s.ownFirst,tg,s.peerN2));
      Fields cm=MakeTarget(s.targetCell,f.GetU64(K::Time));
      cm.Put(K::N2,s.peerN2);cm.Put(K::NtGnb,s.targetNtGnb);cm.Put(K::M3,f.Get(K::M3));
      Require(EqualSecret(f.Get(K::H4),TaggedHash("M4_G2G",corr,cm.Encode(),s.gatewayKey)),
              "Bi gNB inter-domain key confirmation failed");
      Fields toSm=Fields::Decode(f.Get(K::M3));
      Send(o,Role::SourceMeh,BiMsg::PrepForwardM3,corr,toSm);
    } else if(frame.type==BiMsg::PrepC1) {
      Stage(s,3,4);
      Fields in=MakeTarget(s.targetCell,s.targetTimeGnb);
      in.Put(K::NtGnb,s.targetNtGnb);in.Put(K::SigTargetGnb,s.sigTargetGnb);
      Fields m=MakeTarget(s.targetCell,now);
      m.Put(K::C1Enc,f.Get(K::C1Enc));
      m.Put(K::C2Enc,SealAesGcm(OldKey('G'),in.Encode(),DomainDigest("C2",corr,{})));
      HashPut(m,K::H1Exec,"EXEC_CMD",corr,Concat(OldKey('G'),OldKey('E')));
      o.prepared_and_verified=true; // preparation complete; release LTE A3 before execution packet
      Send(o,Role::UE,BiMsg::ExecCommand,corr,m);
    } else throw std::invalid_argument("unexpected S-gNB message");
    break;
  case Role::TargetGnb:
    if(frame.type==BiMsg::PrepM2) {
      Stage(s,0,1);
      Verify(f,K::Sig2,"M2",corr,identities_,Identity::S_GNB);
      Fields h=MakeTarget(s.targetCell,f.GetU64(K::Time));h.Put(K::M1,f.Get(K::M1));h.Put(K::N1,f.Get(K::N1));
      Require(EqualSecret(f.Get(K::H2),TaggedHash("M2_INTEGRITY",corr,h.Encode())),"M2 integrity");
      auto m1=Fields::Decode(f.Get(K::M1));Verify(m1,K::Sig1,"M1",corr,identities_,Identity::S_MEH);
      s.peerN1=f.Get(K::N1);s.messageM1=f.Get(K::M1);
      s.ownFirst=BiEphemeral::Generate();s.ownSecond=BiEphemeral::Generate();
      s.gatewayKey=AsBytes(EvolveDomainKey(Key(),s.ownFirst,
                             identities_.Public(Identity::S_GNB),s.peerN1));
      s.targetNtGnb=s.ownSecond.point;s.targetTimeGnb=now;
      s.sigTargetGnb=SignTarget(Key(),s.targetNtGnb,s.targetCell,now);
      Fields fw=MakeTarget(s.targetCell,now);fw.Put(K::M1,s.messageM1);
      Send(o,Role::TargetMeh,BiMsg::PrepForwardM1,corr,fw);
    } else if(frame.type==BiMsg::PrepM3) {
      Stage(s,1,2);
      Verify(f,K::Sig4,"M3",corr,identities_,Identity::T_MEH);
      Fields m=MakeTarget(s.targetCell,now);
      m.Put(K::M3,f.Encode());m.Put(K::N2,s.ownFirst.point);
      m.Put(K::NtGnb,s.targetNtGnb);m.PutU64(K::T3,s.targetTimeGnb);
      m.Put(K::SigTargetGnb,s.sigTargetGnb);
      Fields keyed=MakeTarget(s.targetCell,now);
      keyed.Put(K::N2,s.ownFirst.point);keyed.Put(K::NtGnb,s.targetNtGnb);keyed.Put(K::M3,f.Encode());
      m.Put(K::H4,TaggedHash("M4_G2G",corr,keyed.Encode(),s.gatewayKey));
      Sign(m,K::Sig3,"M4",corr,Key());
      Send(o,Role::SourceGnb,BiMsg::PrepM4,corr,m);
    } else if(frame.type==BiMsg::ExecM5M6) {
      Stage(s,2,3);
      Verify(f,K::SigUeG,"UE_M6",corr,identities_,Identity::UE_G);
      s.savedM5=f.Get(K::M5);
      s.gatewayKey=AsBytes(EvolveDomainKey(Key(),s.ownSecond,
                   identities_.Public(Identity::UE_G),f.Get(K::Rg)));
      Fields verify=MakeTarget(s.targetCell,f.GetU64(K::Time));
      verify.Put(K::M5,s.savedM5);verify.Put(K::Rg,f.Get(K::Rg));
      Require(EqualSecret(f.Get(K::H3Exec),TaggedHash("UE_M6_HASH",corr,verify.Encode(),s.gatewayKey)),
              "gNB updated handover key H3 mismatch");
      Fields m=MakeTarget(s.targetCell,now);m.Put(K::M5,s.savedM5);
      Send(o,Role::TargetMeh,BiMsg::ExecForwardM5,corr,m);
    } else if(frame.type==BiMsg::ExecAck1) {
      Stage(s,3,4);
      Fields a=MakeTarget(s.targetCell,now);
      a.Put(K::Ack1,f.Get(K::Ack1));
      a.Put(K::Ack2,SealAesGcm(s.gatewayKey,DomainDigest("ACK_GNB",corr,{}),
                               DomainDigest("ACK_G",corr,{})));
      Send(o,Role::UE,BiMsg::ExecAck12,corr,a);
      s.completion=true;
    } else throw std::invalid_argument("unexpected T-gNB message");
    break;
  case Role::TargetMeh:
    if(frame.type==BiMsg::PrepForwardM1) {
      Stage(s,0,1);
      const auto m1=Fields::Decode(f.Get(K::M1));
      Verify(m1,K::Sig1,"M1",corr,identities_,Identity::S_MEH);
      const auto request=OpenEcies(Key(),m1.Get(K::C1),DomainDigest("M1",corr,{}));
      Require(EqualSecret(request,DomainDigest("MESREQ",corr,{})),"Bi encrypted MES request invalid");
      s.peerR1=m1.Get(K::R1);
      s.ownFirst=BiEphemeral::Generate();s.ownSecond=BiEphemeral::Generate();
      s.serviceKey=AsBytes(EvolveDomainKey(Key(),s.ownFirst,
                          identities_.Public(Identity::S_MEH),s.peerR1));
      s.targetRtMeh=s.ownSecond.point;s.targetTimeMeh=now;
      s.sigTargetMeh=SignTarget(Key(),s.targetRtMeh,s.targetCell,now);
      Fields m=MakeTarget(s.targetCell,now);
      m.Put(K::R2,s.ownFirst.point);m.Put(K::RtMeh,s.targetRtMeh);
      m.PutU64(K::T4,now);m.Put(K::SigTargetMeh,s.sigTargetMeh);
      m.Put(K::C2,SealEcies(identities_.Public(Identity::S_MEH),
                           DomainDigest("MEH_CONTEXT_REPLY",corr,{}),DomainDigest("M3",corr,{})));
      Fields keyed=MakeTarget(s.targetCell,now);
      keyed.Put(K::R2,s.ownFirst.point);keyed.Put(K::RtMeh,s.targetRtMeh);keyed.Put(K::C2,m.Get(K::C2));
      m.Put(K::H3,TaggedHash("M3_MIGRATION",corr,keyed.Encode(),s.serviceKey));
      Sign(m,K::Sig4,"M3",corr,Key());
      Send(o,Role::TargetGnb,BiMsg::PrepM3,corr,m);
    } else if(frame.type==BiMsg::PrepContext) {
      Stage(s,1,2);
      auto plain=OpenAesGcm(s.serviceKey,f.Get(K::Context),DomainDigest("CONTEXT",corr,{}));
      Require(EqualSecret(plain,DomainDigest("MEH_CONTEXT",corr,{})),"migration context invalid");
      Fields ack=MakeTarget(s.targetCell,now);
      ack.Put(K::Tag,TaggedHash("CONTEXT_CONFIRMED",corr,{},s.serviceKey));
      Send(o,Role::SourceMeh,BiMsg::PrepContextAck,corr,ack);
    } else if(frame.type==BiMsg::ExecForwardM5) {
      Stage(s,2,3);
      Fields m5=Fields::Decode(f.Get(K::M5));
      Verify(m5,K::SigUeE,"UE_M5",corr,identities_,Identity::UE_E);
      s.serviceKey=AsBytes(EvolveDomainKey(Key(),s.ownSecond,
                          identities_.Public(Identity::UE_E),m5.Get(K::Re)));
      Fields check=MakeTarget(s.targetCell,m5.GetU64(K::Time));check.Put(K::Re,m5.Get(K::Re));
      Require(EqualSecret(m5.Get(K::H2Exec),TaggedHash("UE_M5_HASH",corr,check.Encode(),s.serviceKey)),
              "MEH updated handover key H2 mismatch");
      Fields ack=MakeTarget(s.targetCell,now);
      ack.Put(K::Ack1,SealAesGcm(s.serviceKey,DomainDigest("ACK_MEH",corr,{}),
                                  DomainDigest("ACK_E",corr,{})));
      Send(o,Role::TargetGnb,BiMsg::ExecAck1,corr,ack);
      s.completion=true;
    } else throw std::invalid_argument("unexpected T-MEH message");
    break;
  case Role::UE:
    if(frame.type==BiMsg::ExecCommand) {
      Stage(s,0,1);
      Fields chk=MakeTarget(s.targetCell,f.GetU64(K::Time));
      chk.Put(K::C1Enc,f.Get(K::C1Enc));chk.Put(K::C2Enc,f.Get(K::C2Enc));
      Require(EqualSecret(f.Get(K::H1Exec),TaggedHash("EXEC_CMD",corr,chk.Encode(),
                    Concat(OldKey('G'),OldKey('E')))),"Bi execute command H1 mismatch");
      const Fields e=Fields::Decode(OpenAesGcm(OldKey('E'),f.Get(K::C1Enc),DomainDigest("C1",corr,{})));
      const Fields g=Fields::Decode(OpenAesGcm(OldKey('G'),f.Get(K::C2Enc),DomainDigest("C2",corr,{})));
      CheckTarget(e,s);CheckTarget(g,s);
      s.targetRtMeh=e.Get(K::RtMeh);s.targetNtGnb=g.Get(K::NtGnb);
      VerifyTargetSig(identities_,Identity::T_MEH,s.targetRtMeh,s.targetCell,
                      e.GetU64(K::Time),e.Get(K::SigTargetMeh));
      VerifyTargetSig(identities_,Identity::T_GNB,s.targetNtGnb,s.targetCell,
                      g.GetU64(K::Time),g.Get(K::SigTargetGnb));
      s.ownFirst=BiEphemeral::Generate();s.ownSecond=BiEphemeral::Generate();
      s.serviceKey=AsBytes(EvolveDomainKey(identities_.Private(Identity::UE_E),s.ownFirst,
                                            tm,s.targetRtMeh));
      s.gatewayKey=AsBytes(EvolveDomainKey(identities_.Private(Identity::UE_G),s.ownSecond,
                                            tg,s.targetNtGnb));
      Fields m5=MakeTarget(s.targetCell,now);m5.Put(K::Re,s.ownFirst.point);
      HashPut(m5,K::H2Exec,"UE_M5_HASH",corr,s.serviceKey);
      Sign(m5,K::SigUeE,"UE_M5",corr,identities_.Private(Identity::UE_E));
      Fields m6=MakeTarget(s.targetCell,now);m6.Put(K::M5,m5.Encode());m6.Put(K::Rg,s.ownSecond.point);
      HashPut(m6,K::H3Exec,"UE_M6_HASH",corr,s.gatewayKey);
      Sign(m6,K::SigUeG,"UE_M6",corr,identities_.Private(Identity::UE_G));
      Send(o,Role::TargetGnb,BiMsg::ExecM5M6,corr,m6);
    } else if(frame.type==BiMsg::ExecAck12) {
      Stage(s,1,2);
      const auto a=OpenAesGcm(s.serviceKey,f.Get(K::Ack1),DomainDigest("ACK_E",corr,{}));
      const auto b=OpenAesGcm(s.gatewayKey,f.Get(K::Ack2),DomainDigest("ACK_G",corr,{}));
      Require(EqualSecret(a,DomainDigest("ACK_MEH",corr,{})) &&
              EqualSecret(b,DomainDigest("ACK_GNB",corr,{})),"Bi dual-track ACK invalid");
      // Both independently keyed ACKs were verified at the UE.
      // Do not add a source-gNB confirmation absent from the mapped Bi exchange.
      s.completion=true;
    } else throw std::invalid_argument("unexpected UE message");
    break;
  }
  return o;
}
} // namespace e2b
