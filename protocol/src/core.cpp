// UAV-Mobility-Auth PRE-FLIGHT cryptographic reference core, v0.1.
// Implements Section V signature, ECDH, HMAC, state candidate, epoch & loss recovery
// inside one process. This is NOT the Linux socket or IoD-Sim/ns-3 transport backend.
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>

using B = std::vector<unsigned char>;
using namespace std::string_literals;
void require(bool v, const std::string& msg) { if (!v) throw std::runtime_error(msg); }
B text(const std::string& s){return B(s.begin(), s.end());}
B nbytes(unsigned n){return B{(unsigned char)(n>>24),(unsigned char)(n>>16),(unsigned char)(n>>8),(unsigned char)n};}
B encode(std::initializer_list<B> xs) {
  B b; for (auto &x:xs){auto n=nbytes((unsigned)x.size()); b.insert(b.end(),n.begin(),n.end());b.insert(b.end(),x.begin(),x.end());}return b;
}
B sha(const B& b){B o(SHA256_DIGEST_LENGTH); SHA256(b.data(),b.size(),o.data());return o;}
B H(const std::string& tag,std::initializer_list<B> x){B b=encode({text(tag)});for(const auto& a:x){auto n=nbytes((unsigned)a.size());b.insert(b.end(),n.begin(),n.end());b.insert(b.end(),a.begin(),a.end());}return sha(b);}
B mac(const B& key, const B& b){B o(EVP_MAX_MD_SIZE);unsigned n=0; require(HMAC(EVP_sha256(),key.data(),(int)key.size(),b.data(),b.size(),o.data(),&n)!=nullptr,"HMAC failed");o.resize(n);return o;}
B K(const B& key,const std::string& tag,std::initializer_list<B> args){B b=encode({text(tag)});for(const auto& a:args){auto n=nbytes((unsigned)a.size());b.insert(b.end(),n.begin(),n.end());b.insert(b.end(),a.begin(),a.end());}return mac(key,b);}
B rnd(unsigned len){B b(len);require(RAND_bytes(b.data(),(int)len)==1,"RAND_bytes failed");return b;}
std::string hex(const B& b){static const char* hs="0123456789abcdef";std::string s;for(auto v:b){s+=hs[v>>4];s+=hs[v&15];}return s;}
using Key=std::unique_ptr<EC_KEY,decltype(&EC_KEY_free)>;
using Point=std::unique_ptr<EC_POINT,decltype(&EC_POINT_free)>;
using Bn=std::unique_ptr<BIGNUM,decltype(&BN_free)>;
using Ctx=std::unique_ptr<BN_CTX,decltype(&BN_CTX_free)>;
EC_GROUP* grp(){static EC_GROUP* g=[](){EC_GROUP* x=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);require(x!=nullptr,"curve");return x;}();return g;}
B scalar(const B& h){Ctx ctx(BN_CTX_new(),BN_CTX_free); Bn bn(BN_bin2bn(h.data(),(int)h.size(),nullptr),BN_free), order(BN_new(),BN_free);require(ctx&&bn&&order,"bn alloc");require(EC_GROUP_get_order(grp(),order.get(),ctx.get())==1,"group order");require(BN_mod(bn.get(),bn.get(),order.get(),ctx.get())==1,"scalar mod");if(BN_is_zero(bn.get())) require(BN_one(bn.get())==1,"one");B out(32);require(BN_bn2binpad(bn.get(),out.data(),32)==32,"binpad");return out;}
Key from_sk(const B& raw){Key k(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),EC_KEY_free);Bn sk(BN_bin2bn(raw.data(),(int)raw.size(),nullptr),BN_free);Ctx ctx(BN_CTX_new(),BN_CTX_free);Point p(EC_POINT_new(grp()),EC_POINT_free);require(k&&sk&&ctx&&p,"key allocation");require(EC_POINT_mul(grp(),p.get(),sk.get(),nullptr,nullptr,ctx.get())==1,"point mul");require(EC_KEY_set_private_key(k.get(),sk.get())==1&&EC_KEY_set_public_key(k.get(),p.get())==1,"key init");return k;}
Key from_pub(const B& raw){Key k(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),EC_KEY_free);Ctx ctx(BN_CTX_new(),BN_CTX_free);Point p(EC_POINT_new(grp()),EC_POINT_free);require(k&&ctx&&p,"public alloc");require(EC_POINT_oct2point(grp(),p.get(),raw.data(),raw.size(),ctx.get())==1,"bad EC point");require(EC_KEY_set_public_key(k.get(),p.get())==1,"public set");return k;}
B pub(const EC_KEY* k){Ctx ctx(BN_CTX_new(),BN_CTX_free);const EC_POINT* p=EC_KEY_get0_public_key(k);size_t len=EC_POINT_point2oct(grp(),p,POINT_CONVERSION_COMPRESSED,nullptr,0,ctx.get());require(len==33,"invalid compressed pub");B out(len);require(EC_POINT_point2oct(grp(),p,POINT_CONVERSION_COMPRESSED,out.data(),out.size(),ctx.get())==len,"point2oct");return out;}
B sign(const B& sk, const B& digest){auto key=from_sk(sk);std::unique_ptr<ECDSA_SIG,decltype(&ECDSA_SIG_free)> sig(ECDSA_do_sign(digest.data(),(int)digest.size(),key.get()),ECDSA_SIG_free);require(sig!=nullptr,"ECDSA sign");const BIGNUM *r,*s;ECDSA_SIG_get0(sig.get(),&r,&s);B ret(64);require(BN_bn2binpad(r,ret.data(),32)==32&&BN_bn2binpad(s,ret.data()+32,32)==32,"ECDSA raw64");return ret;}
bool verify(const B& pk,const B& digest,const B& sig){if(sig.size()!=64)return false;auto key=from_pub(pk);std::unique_ptr<ECDSA_SIG,decltype(&ECDSA_SIG_free)> es(ECDSA_SIG_new(),ECDSA_SIG_free);Bn r(BN_bin2bn(sig.data(),32,nullptr),BN_free),s(BN_bin2bn(sig.data()+32,32,nullptr),BN_free);require(es&&r&&s,"sig allocation");require(ECDSA_SIG_set0(es.get(),r.release(),s.release())==1,"set sig");return ECDSA_do_verify(digest.data(),(int)digest.size(),es.get(),key.get())==1;}
B dh(const B& sk,const B& pk){auto a=from_sk(sk),b=from_pub(pk);B z(32);int n=ECDH_compute_key(z.data(),(int)z.size(),EC_KEY_get0_public_key(b.get()),a.get(),nullptr);require(n==32,"ECDH failed");return z;}
B hkdf_extract(const B& salt, const B& ikm){return mac(salt,ikm);}
B hkdf_expand(const B& prk,const B& info){B x=info;x.push_back(1);return mac(prk,x);}

struct State{unsigned v{};B cv,pk,rho;};
bool same(const State&a,const State&b){return a.v==b.v&&a.cv==b.cv&&a.pk==b.pk&&a.rho==b.rho;}
struct Pending{State base,next;B delta,sid;unsigned epoch=0;};
struct M0{char d;B sid,xt,cert_pk,cert_sig,preauth;unsigned epoch;std::string target;B signed_wall_ts;};
struct M1{B sid,rho_base,xu,pk_next,sig;};
struct M2{B sid,tag;};
struct M3{B sid,tag;};
unsigned wire_m0(const M0&m){return (unsigned)(1 + m.sid.size()+m.xt.size()+m.cert_pk.size()+m.cert_sig.size()+m.preauth.size()+m.signed_wall_ts.size());}
unsigned wire_m1(const M1&m){return (unsigned)(m.sid.size()+m.rho_base.size()+m.xu.size()+m.pk_next.size()+m.sig.size());}
unsigned wire_m2(const M2&m){return (unsigned)(m.sid.size()+m.tag.size());}
unsigned wire_m3(const M3&m){return (unsigned)(m.sid.size()+m.tag.size());}
struct Tx{M0 m0;M1 m1;M2 m2;M3 m3;B xt_sk,xu_sk,tctx,th1,th2,kcf,kcm,ks;State base,next;B delta;bool m1_done=false,m2_done=false,m3_done=false,expired=false,committed=false;int m2_send_count=0,m3_send_count=0;};

class Domain {
  char domain_; B seed_, pu_root_, dr_, pid_, ca_sk_; std::map<std::string,B> target_sk_;
  State sc_,su_;std::map<std::string,B> target_cert_pk_,target_cert_sig_;std::unique_ptr<Pending> pending_; unsigned epoch_=0, puf_calls_=0, signs_=0,commits_=0;
  std::map<std::string,std::unique_ptr<Tx>> sessions_; std::string active_sid_;
  B state_key(const State& s)const{return scalar(K(dr_,"AUTHKEY",{text(std::string(1,domain_)),pid_,nbytes(s.v),s.cv}));}
  B staterho(const State& s)const{return H("STATE",{text(std::string(1,domain_)),pid_,nbytes(s.v),s.cv,s.pk});}
  State make_state(const State& base,const B& tctx,const B& xu)const{
    State s;s.v=base.v+1;s.cv=H("NEXT",{base.rho,tctx,xu,nbytes(s.v)});auto kk=state_key(s);auto eck=from_sk(kk);s.pk=pub(eck.get());s.rho=staterho(s);return s;
  }
  B tctx(const M0&m)const{return H("TCTX",{text(std::string(1,domain_)),m.sid,pid_,text(m.target),nbytes(m.epoch),m.xt});}
  B pre_hash(const B&t,const B&ts)const{return H("PREAUTH",{t,ts});}
  B th1(const B&t,const B&xu,const B&delta)const{return H("TH1",{H("TH0",{t}),xu,delta});}
  B delta(const State& b,const State& n,const B& t)const{return H("PENDING",{t,b.rho,nbytes(n.v),n.cv,n.pk});}
  std::string key_sid(const B&sid)const{return hex(sid);}
public:
  explicit Domain(char d,B seed):domain_(d),seed_(std::move(seed)) {
    require(d=='G'||d=='E',"domain must G or E"); pu_root_=K(seed_,"SOFTWARE_PUF",{text("fixed-challenge")});dr_=K(pu_root_,"DOMAINROOT",{text(std::string(1,d))});pid_=H("PID",{text(std::string(1,d)),K(dr_,"PIDSEED",{text(std::string(1,d))})});
    sc_.v=0;sc_.cv=sha(encode({seed_,text(std::string(1,d)),text("CV0")}));auto k=from_sk(state_key(sc_));sc_.pk=pub(k.get());sc_.rho=staterho(sc_);su_=sc_;
    ca_sk_=scalar(K(seed_,"CA",{text(std::string(1,d))}));
    for(const auto&s:{"T1","T2","T3","T4"}){
      target_sk_[s]=scalar(K(seed_,"TARGET",{text(std::string(1,d)),text(s)}));
      auto lt=from_sk(target_sk_[s]);target_cert_pk_[s]=pub(lt.get());
      target_cert_sig_[s]=sign(ca_sk_,H("CERT",{text(std::string(1,d)),text(s),target_cert_pk_[s]}));
    }
  }
  char domain()const{return domain_;}
  unsigned epoch()const{return epoch_;}unsigned puf_calls()const{return puf_calls_;}unsigned signs()const{return signs_;}unsigned commits()const{return commits_;}
  const State& sc()const{return sc_;}const State& su()const{return su_;}const Pending* pending()const{return pending_.get();}
  bool consistent()const {if(!pending_)return same(sc_,su_);return same(pending_->base,sc_) && pending_->next.v==sc_.v+1&&(same(su_,sc_)||same(su_,pending_->next));}
  bool finish_consistent()const{return !pending_&&same(sc_,su_);}
  Tx& start(const std::string& target) {
    require(target_sk_.count(target)>0,"unknown target");require(consistent(),"invalid state before new authorized epoch");
    ++epoch_;auto p=std::make_unique<Tx>();p->m0.d=domain_;p->m0.epoch=epoch_;p->m0.target=target;p->m0.sid=rnd(16);
    p->xt_sk=scalar(rnd(32));auto kt=from_sk(p->xt_sk);p->m0.xt=pub(kt.get());p->m0.cert_pk=target_cert_pk_.at(target);
    p->m0.cert_sig=target_cert_sig_.at(target);p->tctx=tctx(p->m0);
    p->m0.signed_wall_ts=B(8,0); // signed creation time fixed at 0 for virtual-clock E3a tests
    p->m0.preauth=sign(target_sk_.at(target),pre_hash(p->tctx,p->m0.signed_wall_ts));
    const std::string id=key_sid(p->m0.sid);sessions_[id]=std::move(p);active_sid_=id;return *sessions_.at(id);
  }
  M1& m1(Tx& t,bool window_enforced=false,int delta_ms=0,int delay_ms=0) {
    require(!t.expired &&t.m0.epoch==epoch_&&key_sid(t.m0.sid)==active_sid_,"stale M0");
    if(t.m1_done)return t.m1;
    auto ca=from_sk(ca_sk_);require(verify(pub(ca.get()),H("CERT",{text(std::string(1,domain_)),text(t.m0.target),t.m0.cert_pk}),t.m0.cert_sig),"bad CA cert");
    require(verify(t.m0.cert_pk,pre_hash(t.tctx,t.m0.signed_wall_ts),t.m0.preauth),"bad preauth");
    if(window_enforced) require(std::abs(delta_ms+delay_ms)<=500,"TIMESTAMP_WINDOW");
    t.base=su_;t.xu_sk=scalar(rnd(32));auto ku=from_sk(t.xu_sk);t.m1.sid=t.m0.sid;t.m1.xu=pub(ku.get());
    ++puf_calls_; // software PUF *model* invocation, NOT physical PUF measurement
    B regenerated=K(seed_,"SOFTWARE_PUF",{text("fixed-challenge")});require(regenerated==pu_root_,"root changed");
    t.next=make_state(t.base,t.tctx,t.m1.xu);t.delta=delta(t.base,t.next,t.tctx);t.th1=th1(t.tctx,t.m1.xu,t.delta);
    t.m1.rho_base=t.base.rho;t.m1.pk_next=t.next.pk;
    t.m1.sig=sign(state_key(t.base),H("UAV-AUTH",{t.th1}));++signs_;
    t.m1_done=true;return t.m1;
  }
  M2& handle_m1(Tx& t,const M1& msg){
    require(t.m0.epoch==epoch_&&key_sid(msg.sid)==active_sid_&&!t.expired,"old SID or epoch");
    if(t.m2_done){require(msg.sig==t.m1.sig&&msg.xu==t.m1.xu&&msg.pk_next==t.m1.pk_next&&msg.rho_base==t.m1.rho_base,"changed duplicate M1");++t.m2_send_count;return t.m2;}
    const State* b=nullptr;int recovery=0;
    if(msg.rho_base==sc_.rho)b=&sc_;
    else if(pending_&&msg.rho_base==pending_->next.rho){b=&pending_->next;recovery=3;}
    else throw std::runtime_error("M1 base rho not current/pending");
    State verified_base=*b;
    State recomputed=make_state(verified_base,t.tctx,msg.xu);B dd=delta(verified_base,recomputed,t.tctx);B tt=th1(t.tctx,msg.xu,dd);
    require(recomputed.pk==msg.pk_next,"M1 candidate mismatch");
    require(verify(b->pk,H("UAV-AUTH",{tt}),msg.sig),"invalid UAV signature");
    // After signature verification ONLY, choose normal/M2Recover/M3Recover.
    if(recovery==3){require(pending_&&same(su_,pending_->next),"M3Recover base not active");sc_=pending_->next;++commits_;pending_.reset();}
    else if(pending_) {require(same(su_,sc_),"M2Recover active unexpectedly advanced");/* discard old candidate */}
    require(same(verified_base,t.base),"unmatched base");
    // We copied verified_base before resetting the pending object (no dangling pointer).
    require(same(t.base,sc_)||same(t.base,su_),"verified base mismatch");
    t.next=recomputed;t.delta=dd;t.th1=tt;
    pending_=std::make_unique<Pending>(Pending{sc_,t.next,dd,msg.sid,t.m0.epoch});
    B z=dh(t.xt_sk,msg.xu);B actx=H("ACTX",{t.tctx,msg.rho_base});B prk=hkdf_extract(actx,z);
    t.kcf=hkdf_expand(prk,H("KCONF",{tt}));t.kcm=hkdf_expand(prk,H("KCOMMIT",{tt}));t.ks=hkdf_expand(prk,H("SESSKEY",{tt}));
    t.m2.sid=msg.sid;t.m2.tag=mac(t.kcf,H("TARGET-CONFIRM",{tt}));t.th2=H("TH2",{tt,t.m2.tag});
    t.m2_done=true;++t.m2_send_count;require(consistent(),"invalid pending after M1");return t.m2;
  }
  M3& handle_m2(Tx&t,const M2& msg){
    require(t.m0.epoch==epoch_&&key_sid(msg.sid)==active_sid_&&!t.expired,"stale M2");
    require(t.m2_done,"M2 before M1");
    if(t.m3_done){require(msg.tag==t.m2.tag,"changed duplicate M2");++t.m3_send_count;return t.m3;}
    B z=dh(t.xu_sk,t.m0.xt);B actx=H("ACTX",{t.tctx,t.base.rho});B prk=hkdf_extract(actx,z);
    B kcf=hkdf_expand(prk,H("KCONF",{t.th1})),kcm=hkdf_expand(prk,H("KCOMMIT",{t.th1}));
    require(kcf==t.kcf&&kcm==t.kcm,"ECDH/KDF not agreeing");
    require(msg.tag==mac(kcf,H("TARGET-CONFIRM",{t.th1})),"invalid M2 MAC");
    B th2=H("TH2",{t.th1,msg.tag});t.m3.sid=msg.sid;t.m3.tag=mac(kcm,H("COMMIT",{th2}));
    su_=t.next;t.m3_done=true;++t.m3_send_count;require(consistent(),"invalid UAV activation");return t.m3;
  }
  bool handle_m3(Tx&t,const M3&msg){
    require(t.m0.epoch==epoch_&&key_sid(msg.sid)==active_sid_&&!t.expired,"stale M3");
    require(t.m2_done&&t.m3_done,"M3 before activation");
    require(msg.tag==mac(t.kcm,H("COMMIT",{t.th2})),"invalid M3 MAC");
    if(t.committed)return false; // cached duplicate, no second state transition
    require(pending_&&pending_->sid==msg.sid&&same(pending_->next,t.next),"unmatched pending on M3");
    sc_=pending_->next;pending_.reset();++commits_;t.committed=true;require(finish_consistent(),"commit inconsistent");return true;
  }
  void expire(Tx&t){t.expired=true;t.kcf.clear();t.kcm.clear();t.ks.clear();/* pending must survive expiry */}
};

struct Csv{
 std::ofstream f;explicit Csv(const std::string& path,const std::string& head){std::filesystem::create_directories(std::filesystem::path(path).parent_path());f.open(path);require(bool(f),"open "+path);f<<head<<'\n';}
};
B seed_for(unsigned i){return sha(encode({text("local-integration-preflight-v1"),nbytes(i)}));}
void finish(Domain& d,Tx&t){d.m1(t);d.handle_m1(t,t.m1);d.handle_m2(t,t.m2);require(d.handle_m3(t,t.m3),"expected commit");require(d.finish_consistent(),"final inconsistent");}

void smoke(){
  Domain d('G',seed_for(1)), e('E',seed_for(1));
  auto& a=d.start("T1");auto& m1=d.m1(a);require(d.puf_calls()==1&&d.signs()==1,"root/sign counters");
  auto& m2=d.handle_m1(a,m1);require(d.pending()&&d.sc().v==0&&d.su().v==0,"M1 pending before M2");
  M1 bad=m1;bad.sig[0]^=1;bool rejected=false;
  try{d.handle_m1(a,bad);}catch(const std::exception&){rejected=true;}
  require(rejected&&d.pending()&&d.sc().v==0,"tampered duplicate M1 must not change state");
  M2 mbad=m2;mbad.tag[0]^=1;rejected=false;try{d.handle_m2(a,mbad);}catch(const std::exception&){rejected=true;}
  require(rejected&&d.su().v==0,"tampered M2 must not activate");
  auto& m3=d.handle_m2(a,m2);require(d.pending()&&d.su().v==1&&d.sc().v==0,"M2 advance UAV only");
  M3 cbad=m3;cbad.tag[0]^=1;rejected=false;try{d.handle_m3(a,cbad);}catch(const std::exception&){rejected=true;}
  require(rejected&&d.sc().v==0,"tampered M3 must not commit");
  require(d.handle_m3(a,m3)&&!d.handle_m3(a,m3),"once-only commit");require(d.sc().v==1&&d.finish_consistent(),"normal full state");
  require(e.sc().v==0&&e.finish_consistent(),"G does not mutate E");
  auto& t2=e.start("T2");finish(e,t2);require(e.sc().v==1&&d.sc().v==1,"two domains independent");
  std::cout<<"SMOKE PASS: real P-256 ECDSA/ECDH, HKDF-style labels, two domains, and normal state machine\n";
}

void e1(const std::string&out,unsigned repeats){
 Csv csv(out,"sample,event,domain,t_select_to_commit_ms,prepare_ms,authentication_ms,m0_body_B,m1_body_B,m2_body_B,m3_body_B,transfer_reference_B,manager_reference_B,puf_calls,sign_calls,commits,measurement_type");
 require(repeats>=1&&repeats<=10000,"repeats range");
 for(unsigned j=0;j<repeats;j++)for(const std::string event:{"HO_G","Mig_E","GE"}){
   auto time_start=std::chrono::steady_clock::now();
   Domain g('G',seed_for(j+1)),e('E',seed_for(j+1)); // registration pre-initialization is OUTSIDE clock
   time_start=std::chrono::steady_clock::now();
   double prep=0,auth=0;unsigned pu=0,sg=0,cc=0;unsigned m0=0,m1=0,m2=0,m3=0; 
   auto doit=[&](Domain&d){auto p0=std::chrono::steady_clock::now();auto&t=d.start("T1");auto p1=std::chrono::steady_clock::now();auto&a=d.m1(t);auto&b=d.handle_m1(t,a);auto&c=d.handle_m2(t,b);require(d.handle_m3(t,c),"E1 commit");auto p2=std::chrono::steady_clock::now();prep+=std::chrono::duration<double,std::milli>(p1-p0).count();auth+=std::chrono::duration<double,std::milli>(p2-p1).count();pu+=d.puf_calls();sg+=d.signs();cc+=d.commits();m0+=wire_m0(t.m0);m1+=wire_m1(t.m1);m2+=wire_m2(t.m2);m3+=wire_m3(t.m3);};
   if(event=="HO_G"||event=="GE")doit(g);
   if(event=="Mig_E"||event=="GE")doit(e);
   auto t_end=std::chrono::steady_clock::now();double full=std::chrono::duration<double,std::milli>(t_end-time_start).count();
   csv.f<<j<<','<<event<<','<<(event=="GE"?"GE":event=="HO_G"?"G":"E")<<','<<std::setprecision(10)<<full<<','<<prep<<','<<auth<<','<<m0<<','<<m1<<','<<m2<<','<<m3<<','<<((event=="GE")?308:154)<<','<<((event=="GE")?144:72)<<','<<pu<<','<<sg<<','<<cc<<",in_process_crypto_preflight_not_E1_paper_measurement\n";
 }
 std::cout<<"E1 PREFLIGHT PASS: "<<repeats<<" repetitions/event saved "<<out<<" (NO SOCKET, NO NATIVE IoD-Sim, no MES)\n";
}
void e3a(const std::string&out){
 Csv c(out,"delta_clk_over_W,Dnet_over_W,scheme,committed,reason,valid_epoch,valid_SID,measurement_type");
 unsigned passes=0,total=0;
 for(int i=-15;i<=15;i++)for(int j=0;j<=10;j++)for(const std::string scheme:{"P","A-Time"}){
  double offset=i/10.0,delay=j/20.0; bool window=std::abs(i*10+j*5)<=100; // integer scaled 100: i/10 + j/20 = (10i+5j)/100
  Domain g('G',seed_for((unsigned)(i+16)*100+j));auto&t=g.start("T1");
  bool accepted=false;std::string reason="OK";
  try{
    M1 a=g.m1(t,scheme=="A-Time",i*50,j*25);
    g.handle_m1(t,a);g.handle_m2(t,t.m2);
    require(g.handle_m3(t,t.m3),"clock valid commit");
    require(g.finish_consistent(),"clock state");accepted=true;++passes;
  }catch(const std::exception&err){reason=err.what();}
  require(accepted==(scheme=="P"||window),"timestamp boundary inconsistency");
  if(!accepted)require(g.sc().v==0&&!g.pending(),"timestamp reject must not mutate state");
  c.f<<offset<<','<<delay<<','<<scheme<<','<<int(accepted)<<','<<reason<<",1,1,in_process_authenticated_timestamp_preflight\n";
  ++total;
 }
 std::cout<<"E3a PREFLIGHT PASS: "<<total<<" scheme-grid trials; "<<passes<<" complete; "<<out<<"\n";
}
void e3b(const std::string&out){
 Csv c(out,"domain,fault,new_authorization,recovery_enabled,new_target,success,version,commits,puf_calls,branch,measurement_type");
 for(char domain:{'G','E'})for(const std::string fault:{"M2","M3"})for(bool renewed:{false,true})for(bool enable:{false,true})for(const std::string& target : (renewed ? std::vector<std::string>{"T1","T2"} : std::vector<std::string>{"T1"})){
   Domain d(domain,seed_for(5));auto&t=d.start("T1");d.m1(t);d.handle_m1(t,t.m1);
   if(fault=="M3")d.handle_m2(t,t.m2); // lost M3 after UAV activation
   std::string branch;bool success=false;
   if(!renewed){
     if(fault=="M2"){auto m2=d.handle_m1(t,t.m1);d.handle_m2(t,m2);}
     else{auto m3=d.handle_m2(t,t.m2);(void)m3;}
     success=d.handle_m3(t,t.m3);branch="cached_retry";require(d.puf_calls()==1&&d.signs()==1,"retry regenerated root/sign");
   }else{
     // Supersede authorization. A-Retry explicitly has NO new-session recovery.
     if(enable){auto&nt=d.start(target);d.m1(nt);d.handle_m1(nt,nt.m1);branch=fault=="M2"?"M2Recover":"M3Recover";
       require(d.sc().v==(fault=="M2"?0u:1u),"wrong recovery intermediate version");
       d.handle_m2(nt,nt.m2);success=d.handle_m3(nt,nt.m3);
     } else {branch="unsupported_new_authorization";success=false;}
   }
   if(success)require(d.finish_consistent(),"recovery final full state");
   c.f<<domain<<','<<fault<<','<<int(renewed)<<','<<int(enable)<<','<<int(target!="T1")<<','<<int(success)<<','<<d.sc().v<<','<<d.commits()<<','<<d.puf_calls()<<','<<branch<<",in_process_recovery_preflight_not_E3b_paper_measurement\n";
 }
 // Two domains interleave with different loss modes; one domain cannot contaminate the other.
 {
  Domain g('G',seed_for(17)),e('E',seed_for(17));auto&ga=g.start("T1");auto&ea=e.start("T1");
  g.m1(ga);g.handle_m1(ga,ga.m1);e.m1(ea);e.handle_m1(ea,ea.m1);e.handle_m2(ea,ea.m2);
  auto&gn=g.start("T2");auto&en=e.start("T2");g.m1(gn);e.m1(en);
  g.handle_m1(gn,gn.m1);e.handle_m1(en,en.m1);
  g.handle_m2(gn,gn.m2);e.handle_m2(en,en.m2);
  require(g.handle_m3(gn,gn.m3)&&e.handle_m3(en,en.m3),"interleaved commit");
  require(g.sc().v==1&&e.sc().v==2&&g.finish_consistent()&&e.finish_consistent(),"interleaved G/E divergence");
 }
 // State-specific negative tests: expired M3, old SID, replays, cross-domain.
 for(char domain:{'G','E'}){
  Domain d(domain,seed_for(9));auto&t=d.start("T1");d.m1(t);d.handle_m1(t,t.m1);d.handle_m2(t,t.m2);
  d.expire(t);bool rejected=false;try{d.handle_m3(t,t.m3);}catch(const std::exception&){rejected=true;}
  require(rejected&&d.sc().v==0&&d.pending()!=nullptr,"expired M3 changed state");
  auto&n=d.start("T2");d.m1(n);d.handle_m1(n,n.m1);require(d.sc().v==1,"expired M3Recover did not commit old pending");
  rejected=false;try{d.handle_m3(t,t.m3);}catch(const std::exception&){rejected=true;}
  require(rejected&&d.sc().v==1,"late old M3 changed state");
  d.handle_m2(n,n.m2);require(d.handle_m3(n,n.m3)&&d.sc().v==2&&d.finish_consistent(),"late state final");
 }
 std::cout<<"E3b PREFLIGHT PASS: 24 scenario rows + expiry and dual-domain interleaving checks; "<<out<<"\n";
}
int main(int argc,char**argv){
 try{
  require(argc>=2,"usage: auth_preflight smoke | e1 FILE REPEATS | e3a FILE | e3b FILE");std::string cmd=argv[1];
  if(cmd=="smoke")smoke();
  else if(cmd=="e1"){require(argc==4,"e1 FILE REPEATS");e1(argv[2],(unsigned)std::stoul(argv[3]));}
  else if(cmd=="e3a"){require(argc==3,"e3a FILE");e3a(argv[2]);}
  else if(cmd=="e3b"){require(argc==3,"e3b FILE");e3b(argv[2]);}
  else throw std::runtime_error("unknown command");
  return 0;
 }catch(const std::exception&ex){std::cerr<<"FAILED: "<<ex.what()<<'\n';return 1;}
}
