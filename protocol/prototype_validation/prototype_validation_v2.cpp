#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <array>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using Bytes32 = std::array<unsigned char, 32>;

static std::string hex32(const Bytes32& x) {
    std::ostringstream os;
    for (auto b : x) os << std::hex << std::setw(2) << std::setfill('0') << int(b);
    return os.str();
}
static Bytes32 sha256(const std::string& s) {
    Bytes32 out{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, s.data(), s.size());
    unsigned int n = 0;
    EVP_DigestFinal_ex(ctx, out.data(), &n);
    EVP_MD_CTX_free(ctx);
    return out;
}
static Bytes32 mac256(const Bytes32& key, const std::string& s) {
    Bytes32 out{};
    unsigned int n = 0;
    HMAC(EVP_sha256(), key.data(), int(key.size()),
         reinterpret_cast<const unsigned char*>(s.data()), s.size(),
         out.data(), &n);
    return out;
}
static bool eq(const Bytes32& a, const Bytes32& b) {
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
static std::string H(const std::string& tag, const std::string& body) {
    return hex32(sha256(tag + "|" + body));
}
static std::string random_sid() {
    std::array<unsigned char,16> b{};
    RAND_bytes(b.data(), int(b.size()));
    std::ostringstream os;
    for (auto x:b) os << std::hex << std::setw(2) << std::setfill('0') << int(x);
    return os.str();
}

struct State {
    std::uint64_t v{};
    std::string CV, PK, rho;
};
static State make_state(const std::string& d, const std::string& pid,
                        std::uint64_t v, const std::string& cv,
                        const std::string& pk) {
    State s{v,cv,pk,""};
    s.rho = H("STATE", d+"|"+pid+"|"+std::to_string(v)+"|"+cv+"|"+pk);
    return s;
}
struct Pending {
    std::string base;
    State next;
    std::string delta;
    std::string SID;
    std::uint64_t e{};
};
enum class Status { Prepared, AwaitM3, Committed, Expired };
struct Session {
    Status st{Status::Prepared};
    std::uint64_t e{};
    std::string TCTX;
    std::string TH2;
    Bytes32 Kcm{};
    Bytes32 Ks{};
    std::string delta;
    Bytes32 tauT{};
};
struct Transfer {
    std::string d, PID, target;
    std::uint64_t e{};
    State committed;
    std::optional<Pending> pending;
};
struct M0 {
    std::string d, SID, XT, cert, preauth;
};
struct M1 {
    std::string SID, rhoB, XU, PKN, sigmaU;
};
struct M2 {
    std::string SID;
    Bytes32 tauT{};
};
struct M3 {
    std::string SID;
    Bytes32 tauC{};
};

enum class FreshnessMode { Epoch, Timestamp };

struct Trial {
    bool transfer_ok=false, m0_ok=false, m1_ok=false, pending_installed=false;
    bool m2_ok=false, uav_activated=false, m3_ok=false, committed=false;
    std::string reject="NONE";
    std::uint64_t vU_before=0, vC_before=0, vU_after=0, vC_after=0;
    bool pending_after=false;
};


enum class M3GuardCase {
    StaleSid,
    FencedEpoch,
    PendingDigestMismatch,
    OldCommitMac
};

struct GuardResult {
    std::string trial;
    std::string expected_reason;
    std::string observed_reason="NONE";
    bool committed=false;
    std::uint64_t vU_before=0, vC_before=0, vU_after=0, vC_after=0;
    bool pending_before=false, pending_after=false;
    std::string pending_fp_before, pending_fp_after;
    bool passed=false;
};

class Protocol {
public:
    Protocol(FreshnessMode mode, double W, double offset)
      : mode_(mode), W_(W), offset_(offset) {
        d_="G"; pid_="PID-UAV-001"; target_="GS-T";
        SC_=make_state(d_,pid_,0,H("CV","init"),H("PK","state0"));
        SU_=SC_;
        current_epoch_=11;
    }

    Trial run_normal() {
        Trial tr;
        tr.vU_before=SU_.v; tr.vC_before=SC_.v;

        Transfer xfer{d_,pid_,target_,current_epoch_,SC_,Pi_};
        if (!accept_transfer(xfer,tr)) return finish(tr);
        tr.transfer_ok=true;

        M0 m0 = make_m0(xfer);
        if (!uav_accept_m0(m0,tr)) return finish(tr);
        tr.m0_ok=true;

        M1 m1 = make_m1(m0);
        if (!target_accept_m1(m1,tr)) return finish(tr);
        tr.m1_ok=true; tr.pending_installed=Pi_.has_value();

        M2 m2 = make_m2(m1);
        if (!uav_accept_m2(m2,tr)) return finish(tr);
        tr.m2_ok=true; tr.uav_activated=true;

        M3 m3 = make_m3(m2);
        if (!target_accept_m3(m3,tr)) return finish(tr);
        tr.m3_ok=true; tr.committed=true;
        return finish(tr);
    }

    // 四个定点负向测试：
    // 1) 真实旧 SID 重放；
    // 2) 白盒注入旧 epoch，精确触发 epoch fencing；
    // 3) 白盒注入 session/pending digest 不一致；
    // 4) 当前上下文全部合法，仅注入旧事务 commit MAC。
    GuardResult run_m3_guard_case(M3GuardCase which) {
        GuardResult g;

        switch (which) {
        case M3GuardCase::StaleSid:
            g.trial="stale_sid";
            g.expected_reason="M3_SID";
            break;
        case M3GuardCase::FencedEpoch:
            g.trial="fenced_epoch";
            g.expected_reason="M3_EPOCH_FENCED";
            break;
        case M3GuardCase::PendingDigestMismatch:
            g.trial="pending_digest_mismatch";
            g.expected_reason="M3_PENDING_DIGEST";
            break;
        case M3GuardCase::OldCommitMac:
            g.trial="old_commit_mac";
            g.expected_reason="M3_COMMIT_MAC";
            break;
        }

        if (!prepare_guard_case(g))
            return finish_guard(g);

        // 当前会话的正确 commit MAC。除 OldCommitMac 外，
        // 用它确保后续失败不是由 MAC 本身提前造成的。
        Bytes32 current_tauC =
            mac256(sess_->Kcm,H("COMMIT",sess_->TH2));
        M3 injected{sid_,current_tauC};

        switch (which) {
        case M3GuardCase::StaleSid:
            // 真实网络重放：旧事务的 SID 和旧事务的 tauC 原样到达。
            injected.SID=old_sid_;
            injected.tauC=old_tauC_;
            break;

        case M3GuardCase::FencedEpoch:
            // M3 本身没有 epoch 字段。为了越过 SID 检查并定点测试
            // epoch guard，让当前 SID 的 session/pending 保持同一旧 epoch，
            // 而 authoritative current_epoch_ 已经推进到 11。
            sess_->e=current_epoch_-1;
            Pi_->e=current_epoch_-1;
            break;

        case M3GuardCase::PendingDigestMismatch:
            // M3 本身没有 delta 字段。保持 SID/epoch 合法，
            // 只让 Target 保存的 session.delta 与 Pi.delta 不一致。
            sess_->delta += "|FAULT_INJECTED";
            break;

        case M3GuardCase::OldCommitMac:
            // SID、epoch、pending digest 全部保持当前合法值，
            // 只把 tauC 换成上一事务的合法旧 MAC。
            injected.tauC=old_tauC_;
            break;
        }

        // “before” 必须在故障注入之后、调用 target_accept_m3() 之前取样，
        // 这样 passed 检查验证的是：被拒绝的 M3 不会进一步推进/破坏状态。
        snapshot_guard_before(g);

        Trial tr;
        bool accepted=target_accept_m3(injected,tr);
        g.committed=accepted;
        g.observed_reason=accepted ? "ACCEPTED" : tr.reject;

        return finish_guard(g);
    }

private:
    FreshnessMode mode_;
    double W_, offset_;
    std::string d_, pid_, target_;
    std::uint64_t current_epoch_{};
    State SU_, SC_;
    std::optional<Pending> Pi_;
    std::optional<Session> sess_;
    std::string sid_;
    std::string TCTX_, TH0_, TH1_, TH2_;
    State candidate_{};
    Bytes32 Kcf_{}, Kcm_{}, Ks_{};
    std::string old_sid_;
    Bytes32 old_tauC_{};

    Trial finish(Trial tr) {
        tr.vU_after=SU_.v; tr.vC_after=SC_.v;
        tr.pending_after=Pi_.has_value();
        return tr;
    }


    std::string pending_fingerprint() const {
        if (!Pi_) return "NONE";
        const auto& p=*Pi_;
        return H("PENDING-SNAPSHOT",
                 p.base+"|"+
                 std::to_string(p.next.v)+"|"+
                 p.next.CV+"|"+p.next.PK+"|"+p.next.rho+"|"+
                 p.delta+"|"+p.SID+"|"+std::to_string(p.e));
    }

    bool prepare_guard_case(GuardResult& g) {
        // 先完整提交 epoch=10，保留其真实 SID/tauC 作为“旧事务材料”。
        current_epoch_=10;
        Trial warm=run_normal();
        if (!warm.committed) {
            g.observed_reason="SETUP_WARM_"+warm.reject;
            return false;
        }

        // 再建立 epoch=11 的当前 session + pending，但停在 M1 之后。
        // 此时 Target 正处于 AwaitM3，且 SU=SC=1、Pi!=null。
        current_epoch_=11;
        Trial prep;
        Transfer xfer{d_,pid_,target_,11,SC_,Pi_};
        if (!accept_transfer(xfer,prep)) {
            g.observed_reason="SETUP_TRANSFER_"+prep.reject;
            return false;
        }

        auto m0=make_m0(xfer);
        if (!uav_accept_m0(m0,prep)) {
            g.observed_reason="SETUP_M0_"+prep.reject;
            return false;
        }

        auto m1=make_m1(m0);
        if (!target_accept_m1(m1,prep)) {
            g.observed_reason="SETUP_M1_"+prep.reject;
            return false;
        }

        if (!sess_ || sess_->st!=Status::AwaitM3 || !Pi_) {
            g.observed_reason="SETUP_NOT_AWAIT_M3";
            return false;
        }
        return true;
    }

    void snapshot_guard_before(GuardResult& g) const {
        g.vU_before=SU_.v;
        g.vC_before=SC_.v;
        g.pending_before=Pi_.has_value();
        g.pending_fp_before=pending_fingerprint();
    }

    GuardResult finish_guard(GuardResult g) const {
        g.vU_after=SU_.v;
        g.vC_after=SC_.v;
        g.pending_after=Pi_.has_value();
        g.pending_fp_after=pending_fingerprint();

        g.passed =
            (g.observed_reason==g.expected_reason) &&
            !g.committed &&
            (g.vU_after==g.vU_before) &&
            (g.vC_after==g.vC_before) &&
            g.pending_before &&
            g.pending_after &&
            (g.pending_fp_after==g.pending_fp_before);
        return g;
    }

    bool accept_transfer(const Transfer& t, Trial& tr) {
        if (t.d!=d_ || t.PID!=pid_ || t.target!=target_) {
            tr.reject="TRANSFER_CONTEXT"; return false;
        }
        if (t.e!=current_epoch_) {
            tr.reject="TRANSFER_EPOCH"; return false;
        }
        auto check=make_state(t.d,t.PID,t.committed.v,t.committed.CV,t.committed.PK);
        if (check.rho!=t.committed.rho) {
            tr.reject="COMMITTED_STATE_HASH"; return false;
        }
        if (t.pending) {
            if (t.pending->base!=t.committed.rho ||
                t.pending->next.v!=t.committed.v+1) {
                tr.reject="PENDING_INVARIANT"; return false;
            }
        }
        return true;
    }

    M0 make_m0(const Transfer& t) {
        sid_=random_sid();
        std::string XT=H("XT",sid_+"|"+std::to_string(t.e));
        TCTX_=H("TCTX",d_+"|"+sid_+"|"+pid_+"|"+target_+"|"+
                         std::to_string(t.e)+"|"+XT);
        std::string preauth=H("PREAUTH",TCTX_); // 状态机原型中的完整性占位值
        sess_=Session{Status::Prepared,t.e,TCTX_,"",{},{},"",{}};
        TH0_=H("TH0",TCTX_);
        return M0{d_,sid_,XT,"CERT-"+target_,preauth};
    }

    bool uav_accept_m0(const M0& m, Trial& tr) {
        if (m.d!=d_ || m.SID!=sid_ || m.cert!="CERT-"+target_) {
            tr.reject="M0_CONTEXT"; return false;
        }
        std::string expected=H("PREAUTH",TCTX_);
        if (m.preauth!=expected) {
            tr.reject="PREAUTH"; return false;
        }
        return true;
    }

    M1 make_m1(const M0& m0) {
        std::string XU=H("XU",m0.SID+"|"+std::to_string(SU_.v));
        std::uint64_t vN=SU_.v+1;
        std::string cvN=H("NEXT",SU_.rho+"|"+TCTX_+"|"+XU+"|"+std::to_string(vN));
        std::string pkN=H("PK","next|"+m0.SID+"|"+std::to_string(vN));
        candidate_=make_state(d_,pid_,vN,cvN,pkN);
        std::string delta=H("PENDING",TCTX_+"|"+SU_.rho+"|"+std::to_string(vN)+"|"+cvN+"|"+pkN);
        TH1_=H("TH1",TH0_+"|"+XU+"|"+delta);
        std::string sigma=H("UAV-AUTH",SU_.PK+"|"+TH1_); // 签名验证的状态机占位值
        return M1{m0.SID,SU_.rho,XU,pkN,sigma};
    }

    bool target_accept_m1(const M1& m, Trial& tr) {
        if (!sess_ || sess_->st!=Status::Prepared || m.SID!=sid_) {
            tr.reject="M1_SESSION"; return false;
        }

        // 两个实验版本唯一不同的 currentness 判定。
        if (mode_==FreshnessMode::Epoch) {
            if (sess_->e!=current_epoch_) {
                tr.reject="STALE_EPOCH"; return false;
            }
        } else {
            // sender logical time = 0, receiver logical time = offset
            if (std::abs(offset_)>W_) {
                tr.reject="TIMESTAMP_WINDOW"; return false;
            }
        }

        State SV;
        if (!Pi_ && m.rhoB==SC_.rho) {
            SV=SC_;
        } else if (Pi_ && m.rhoB==SC_.rho) {
            SV=SC_; // M2Recover 分支
        } else if (Pi_ && m.rhoB==Pi_->next.rho) {
            SV=Pi_->next; // M3Recover 分支
        } else {
            tr.reject="BASE_STATE"; return false;
        }

        std::uint64_t vN=SV.v+1;
        std::string cvN=H("NEXT",m.rhoB+"|"+TCTX_+"|"+m.XU+"|"+std::to_string(vN));
        State SN=make_state(d_,pid_,vN,cvN,m.PKN);
        std::string delta=H("PENDING",TCTX_+"|"+m.rhoB+"|"+std::to_string(vN)+"|"+cvN+"|"+m.PKN);
        std::string th1=H("TH1",TH0_+"|"+m.XU+"|"+delta);
        std::string expected_sig=H("UAV-AUTH",SV.PK+"|"+th1);
        if (m.sigmaU!=expected_sig) {
            tr.reject="UAV_SIGNATURE"; return false;
        }

        candidate_=SN;
        TH1_=th1;
        Pi_=Pending{m.rhoB,SN,delta,m.SID,current_epoch_};

        // 机制原型：从当前 transcript 确定性派生三把会话用途分离的键。
        Kcf_=sha256("KCONF|"+TCTX_+"|"+TH1_);
        Kcm_=sha256("KCOMMIT|"+TCTX_+"|"+TH1_);
        Ks_ =sha256("SESSKEY|"+TCTX_+"|"+TH1_);
        Bytes32 tauT=mac256(Kcf_,H("TARGET-CONFIRM",TH1_));
        TH2_=H("TH2",TH1_+"|"+hex32(tauT));
        sess_->st=Status::AwaitM3;
        sess_->TH2=TH2_;
        sess_->Kcm=Kcm_;
        sess_->Ks=Ks_;
        sess_->delta=delta;
        sess_->tauT=tauT;
        return true;
    }

    M2 make_m2(const M1&) { return M2{sid_,sess_->tauT}; }

    bool uav_accept_m2(const M2& m, Trial& tr) {
        if (m.SID!=sid_) { tr.reject="M2_SID"; return false; }
        Bytes32 expected=mac256(Kcf_,H("TARGET-CONFIRM",TH1_));
        if (!eq(m.tauT,expected)) { tr.reject="M2_CONFIRM_MAC"; return false; }
        SU_=candidate_;
        return true;
    }

    M3 make_m3(const M2&) {
        Bytes32 tauC=mac256(Kcm_,H("COMMIT",TH2_));
        old_sid_=sid_;
        old_tauC_=tauC;
        return M3{sid_,tauC};
    }

    bool target_accept_m3(const M3& m, Trial& tr) {
        if (!sess_ || sess_->st!=Status::AwaitM3) {
            tr.reject="M3_SESSION_STATE"; return false;
        }
        if (!Pi_) { tr.reject="NO_PENDING"; return false; }
        if (m.SID!=sid_ || Pi_->SID!=m.SID) {
            tr.reject="M3_SID"; return false;
        }
        if (sess_->e!=Pi_->e || Pi_->e!=current_epoch_) {
            tr.reject="M3_EPOCH_FENCED"; return false;
        }
        if (sess_->delta!=Pi_->delta) {
            tr.reject="M3_PENDING_DIGEST"; return false;
        }
        Bytes32 expected=mac256(sess_->Kcm,H("COMMIT",sess_->TH2));
        if (!eq(m.tauC,expected)) {
            tr.reject="M3_COMMIT_MAC"; return false;
        }

        SC_=Pi_->next;
        Pi_.reset();
        sess_->st=Status::Committed;
        return true;
    }
};

static std::vector<double> ratios() {
    return {0,0.25,0.5,0.75,0.9,1.0,1.1,1.25,1.5,2.0};
}
static std::vector<double> windows(int argc,char**argv) {
    if (argc==4) return {std::stod(argv[1]),std::stod(argv[2]),std::stod(argv[3])};
    return {100,500,1000}; // 仅用于程序自检，不是论文参数来源
}
static void write_row(std::ofstream& f,const std::string& scheme,double W,double ratio,
                      const Trial& t) {
    f<<scheme<<','<<W<<','<<ratio<<','<<ratio*W<<','
     <<t.transfer_ok<<','<<t.m0_ok<<','<<t.m1_ok<<','<<t.pending_installed<<','
     <<t.m2_ok<<','<<t.uav_activated<<','<<t.m3_ok<<','<<t.committed<<','
     <<t.vU_before<<','<<t.vC_before<<','<<t.vU_after<<','<<t.vC_after<<','
     <<t.pending_after<<','<<t.reject<<'\n';
}


static void write_guard_row(std::ofstream& f,const GuardResult& g) {
    f<<g.trial<<','<<g.expected_reason<<','<<g.observed_reason<<','
     <<g.committed<<','
     <<g.vU_before<<','<<g.vC_before<<','<<g.vU_after<<','<<g.vC_after<<','
     <<g.pending_before<<','<<g.pending_after<<','<<g.passed<<'\n';
}
int main(int argc,char**argv) {
    auto ws=windows(argc,argv);
    std::ofstream f("clock_offset_full_protocol.csv");
    f<<"scheme,window_ms,offset_ratio,clock_offset_ms,"
      <<"transfer_ok,m0_ok,m1_ok,pending_installed,m2_ok,uav_activated,"
      <<"m3_ok,committed,vU_before,vC_before,vU_after,vC_after,pending_after,reject_reason\n";

    for(double W:ws) for(double r:ratios()) {
        Protocol p1(FreshnessMode::Epoch,W,r*W);
        write_row(f,"epoch",W,r,p1.run_normal());

        Protocol p2(FreshnessMode::Timestamp,W,r*W);
        write_row(f,"timestamp",W,r,p2.run_normal());
    }

    std::ofstream s("stale_m3_fencing.csv");
    s<<"trial,expected_reason,observed_reason,committed,"
       "vU_before,vC_before,vU_after,vC_after,"
       "pending_before,pending_after,passed\n";

    const std::array<M3GuardCase,4> cases{
        M3GuardCase::StaleSid,
        M3GuardCase::FencedEpoch,
        M3GuardCase::PendingDigestMismatch,
        M3GuardCase::OldCommitMac
    };

    for (auto c:cases) {
        Protocol p(FreshnessMode::Epoch,1,0);
        write_guard_row(s,p.run_m3_guard_case(c));
    }

    std::cout<<"Generated clock_offset_full_protocol.csv and stale_m3_fencing.csv\n";
    return 0;
}
