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
#include <algorithm>
#include <chrono>
#include <numeric>
#include <cstdlib>
#include <random>

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


struct RecoveryResult {
    std::string scenario;
    bool fault_injected=false;
    std::uint64_t vU_after_fault=0;
    std::uint64_t vC_after_fault=0;
    bool pending_after_fault=false;
    std::string recovery_branch="NONE";
    int recovery_transactions=0;
    bool recovery_completed=false;
    std::uint64_t vU_final=0;
    std::uint64_t vC_final=0;
    bool pending_final=false;
    std::string reject_reason="NONE";

    // Benchmark fields. These are prototype processing times, not network E2E latency.
    double m1_processing_us=0.0;
    double completion_us=0.0;
};


struct RandomLossEvent {
    int event_index=0;
    double loss_probability=0.0;
    std::string branch="NONE";
    bool m2_lost=false;
    bool m3_lost=false;
    bool committed=false;
    bool clean_after_event=false;
    std::uint64_t vU_after=0;
    std::uint64_t vC_after=0;
    bool pending_after=false;
    std::string reject_reason="NONE";
    double processing_us=0.0;
};

struct RandomLossRun {
    double loss_probability=0.0;
    int events=0;
    int committed_events=0;
    int m2_losses=0;
    int m3_losses=0;
    int normal_branches=0;
    int m2_recover_branches=0;
    int m3_recover_branches=0;
    int rejected_events=0;
    int clean_after_events=0;
    int recovery_invocations=0;
    int recovery_commits=0;
    bool flush_completed=false;
    std::vector<RandomLossEvent> rows;
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


    // Random-loss stream experiment.
    // Each authorized mobility event executes Transfer -> M0 -> M1.
    // M2 and M3 are independently dropped with Bernoulli probability p.
    // Residual state is NOT reset between events: the next fresh epoch must
    // naturally select NORMAL, M2_RECOVER, or M3_RECOVER from protocol state.
    RandomLossRun run_random_loss_stream(
        double p,
        int events,
        std::uint64_t seed)
    {
        RandomLossRun out;
        out.loss_probability=p;
        out.events=events;
        out.rows.reserve(static_cast<std::size_t>(events));

        std::mt19937_64 rng(seed);
        std::bernoulli_distribution drop(p);

        // Start from a clean synchronized state and advance the epoch once
        // per authorized mobility event.
        current_epoch_=1000;

        for (int i=0; i<events; ++i, ++current_epoch_) {
            RandomLossEvent row;
            row.event_index=i+1;
            row.loss_probability=p;

            auto t0=std::chrono::steady_clock::now();
            Trial tr;
            last_branch_="NONE";

            Transfer xfer{d_,pid_,target_,current_epoch_,SC_,Pi_};
            if (!accept_transfer(xfer,tr)) {
                row.reject_reason=tr.reject;
            } else {
                M0 m0=make_m0(xfer);
                if (!uav_accept_m0(m0,tr)) {
                    row.reject_reason=tr.reject;
                } else {
                    M1 m1=make_m1(m0);
                    if (!target_accept_m1(m1,tr)) {
                        row.reject_reason=tr.reject;
                    } else {
                        row.branch=last_branch_;

                        if (row.branch=="NORMAL") ++out.normal_branches;
                        else if (row.branch=="M2_RECOVER") {
                            ++out.m2_recover_branches;
                            ++out.recovery_invocations;
                        } else if (row.branch=="M3_RECOVER") {
                            ++out.m3_recover_branches;
                            ++out.recovery_invocations;
                        }

                        // Fault injection point 1: M2.
                        row.m2_lost=drop(rng);
                        if (row.m2_lost) {
                            ++out.m2_losses;
                        } else {
                            M2 m2=make_m2(m1);
                            if (!uav_accept_m2(m2,tr)) {
                                row.reject_reason=tr.reject;
                            } else {
                                // Fault injection point 2: M3.
                                row.m3_lost=drop(rng);
                                if (row.m3_lost) {
                                    ++out.m3_losses;
                                } else {
                                    M3 m3=make_m3(m2);
                                    if (!target_accept_m3(m3,tr)) {
                                        row.reject_reason=tr.reject;
                                    } else {
                                        row.committed=true;
                                        ++out.committed_events;
                                        if (row.branch=="M2_RECOVER" ||
                                            row.branch=="M3_RECOVER") {
                                            ++out.recovery_commits;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (row.reject_reason!="NONE") ++out.rejected_events;

            row.vU_after=SU_.v;
            row.vC_after=SC_.v;
            row.pending_after=Pi_.has_value();
            row.clean_after_event =
                (SU_.v==SC_.v) && !Pi_.has_value();
            if (row.clean_after_event) ++out.clean_after_events;

            auto t1=std::chrono::steady_clock::now();
            row.processing_us=
                std::chrono::duration<double,std::micro>(t1-t0).count();

            out.rows.push_back(row);
        }

        // Reliable flush event: not included in the p-loss statistics.
        // It checks eventual convergence of whatever bounded residual state
        // the final random event left behind.
        ++current_epoch_;
        Trial flush=run_normal();
        out.flush_completed =
            flush.committed && (SU_.v==SC_.v) && !Pi_.has_value();

        return out;
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


    RecoveryResult run_recovery_scenario(const std::string& scenario) {
        RecoveryResult r;
        r.scenario=scenario;

        auto snapshot_fault = [&]() {
            r.vU_after_fault=SU_.v;
            r.vC_after_fault=SC_.v;
            r.pending_after_fault=Pi_.has_value();
        };

        auto finish_result = [&](const Trial& tr) {
            r.recovery_branch=last_branch_;
            r.m1_processing_us=last_m1_processing_us_;
            r.vU_final=SU_.v;
            r.vC_final=SC_.v;
            r.pending_final=Pi_.has_value();
            r.reject_reason=tr.reject;
            r.recovery_completed =
                tr.committed &&
                (SU_.v==SC_.v) &&
                !Pi_.has_value();
        };

        if (scenario=="normal") {
            // No injected loss. Snapshot the initial synchronized state, then
            // execute one ordinary mobility transaction.
            r.fault_injected=false;
            snapshot_fault();

            current_epoch_=10;
            last_branch_="NONE";
            auto t0 = std::chrono::steady_clock::now();
            Trial tr=run_normal();
            auto t1 = std::chrono::steady_clock::now();
            r.completion_us =
                std::chrono::duration<double,std::micro>(t1-t0).count();
            r.recovery_transactions=0;
            finish_result(tr);
            return r;
        }

        if (scenario=="m2_loss") {
            // Transaction e=10 reaches Target through M1. Target installs Pi,
            // but M2 is intentionally not delivered to the UAV.
            r.fault_injected=true;
            current_epoch_=10;

            Trial fault;
            Transfer xfer{d_,pid_,target_,current_epoch_,SC_,Pi_};
            if (!accept_transfer(xfer,fault)) {
                r.reject_reason=fault.reject;
                snapshot_fault();
                r.vU_final=SU_.v; r.vC_final=SC_.v;
                r.pending_final=Pi_.has_value();
                return r;
            }
            auto m0=make_m0(xfer);
            if (!uav_accept_m0(m0,fault)) {
                r.reject_reason=fault.reject;
                snapshot_fault();
                r.vU_final=SU_.v; r.vC_final=SC_.v;
                r.pending_final=Pi_.has_value();
                return r;
            }
            auto m1=make_m1(m0);
            if (!target_accept_m1(m1,fault)) {
                r.reject_reason=fault.reject;
                snapshot_fault();
                r.vU_final=SU_.v; r.vC_final=SC_.v;
                r.pending_final=Pi_.has_value();
                return r;
            }

            // M2 loss point: SU=SC=0, Pi exists.
            snapshot_fault();

            // A new authorized mobility event arrives. The UAV still presents
            // SC.rho, so target_accept_m1() must take M2Recover.
            current_epoch_=11;
            last_branch_="NONE";
            auto t0 = std::chrono::steady_clock::now();
            Trial recovery=run_normal();
            auto t1 = std::chrono::steady_clock::now();
            r.completion_us =
                std::chrono::duration<double,std::micro>(t1-t0).count();
            r.recovery_transactions=1;
            finish_result(recovery);
            return r;
        }

        if (scenario=="m3_loss") {
            // Transaction e=10 reaches the UAV through M2, so the UAV activates
            // candidate state 1. M3 is intentionally not delivered to Target.
            r.fault_injected=true;
            current_epoch_=10;

            Trial fault;
            Transfer xfer{d_,pid_,target_,current_epoch_,SC_,Pi_};
            if (!accept_transfer(xfer,fault)) {
                r.reject_reason=fault.reject;
                snapshot_fault();
                r.vU_final=SU_.v; r.vC_final=SC_.v;
                r.pending_final=Pi_.has_value();
                return r;
            }
            auto m0=make_m0(xfer);
            if (!uav_accept_m0(m0,fault)) {
                r.reject_reason=fault.reject;
                snapshot_fault();
                r.vU_final=SU_.v; r.vC_final=SC_.v;
                r.pending_final=Pi_.has_value();
                return r;
            }
            auto m1=make_m1(m0);
            if (!target_accept_m1(m1,fault)) {
                r.reject_reason=fault.reject;
                snapshot_fault();
                r.vU_final=SU_.v; r.vC_final=SC_.v;
                r.pending_final=Pi_.has_value();
                return r;
            }
            auto m2=make_m2(m1);
            if (!uav_accept_m2(m2,fault)) {
                r.reject_reason=fault.reject;
                snapshot_fault();
                r.vU_final=SU_.v; r.vC_final=SC_.v;
                r.pending_final=Pi_.has_value();
                return r;
            }

            // M3 loss point: SU=1, SC=0, Pi exists.
            snapshot_fault();

            // A new authorized mobility event arrives. The UAV presents
            // Pi.next.rho, so target_accept_m1() must take M3Recover and
            // continue from state 1 to state 2 rather than rolling back.
            current_epoch_=11;
            last_branch_="NONE";
            auto t0 = std::chrono::steady_clock::now();
            Trial recovery=run_normal();
            auto t1 = std::chrono::steady_clock::now();
            r.completion_us =
                std::chrono::duration<double,std::micro>(t1-t0).count();
            r.recovery_transactions=1;
            finish_result(recovery);
            return r;
        }

        r.reject_reason="UNKNOWN_SCENARIO";
        snapshot_fault();
        r.vU_final=SU_.v;
        r.vC_final=SC_.v;
        r.pending_final=Pi_.has_value();
        return r;
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
    std::string last_branch_="NONE";
    double last_m1_processing_us_=0.0;
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

        auto m1_start = std::chrono::steady_clock::now();

        State SV;
        bool promote_old_pending=false;
        State old_pending_next{};
        if (!Pi_ && m.rhoB==SC_.rho) {
            SV=SC_;
            last_branch_="NORMAL";
        } else if (Pi_ && m.rhoB==SC_.rho) {
            SV=SC_;
            last_branch_="M2_RECOVER";
        } else if (Pi_ && m.rhoB==Pi_->next.rho) {
            // Eq. (43) semantics: authenticate under the old pending successor,
            // then promote that old pending state before installing Pi_new.
            SV=Pi_->next;
            old_pending_next=Pi_->next;
            promote_old_pending=true;
            last_branch_="M3_RECOVER";
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

        // IMPORTANT: preserve the protocol's M3Recover ordering:
        // promote the previously pending successor first, then install Pi_new.
        if (promote_old_pending) {
            SC_=old_pending_next;
        }
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
        auto m1_end = std::chrono::steady_clock::now();
        last_m1_processing_us_ =
            std::chrono::duration<double,std::micro>(m1_end-m1_start).count();
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




static double median(std::vector<double> x) {
    if (x.empty()) return 0.0;
    std::sort(x.begin(),x.end());
    std::size_t n=x.size();
    return (n%2) ? x[n/2] : 0.5*(x[n/2-1]+x[n/2]);
}

static double percentile(std::vector<double> x, double p) {
    if (x.empty()) return 0.0;
    std::sort(x.begin(),x.end());
    double pos=(p/100.0)*(x.size()-1);
    std::size_t lo=static_cast<std::size_t>(std::floor(pos));
    std::size_t hi=static_cast<std::size_t>(std::ceil(pos));
    if (lo==hi) return x[lo];
    double w=pos-lo;
    return x[lo]*(1.0-w)+x[hi]*w;
}

struct RunSummary {
    double p=0.0;
    int run=0;
    int events=0;
    double completion_rate=0.0;
    double clean_state_rate=0.0;
    double recovery_invocation_rate=0.0;
    double recovery_commit_rate=0.0;
    double m2_loss_rate=0.0;
    double m3_loss_rate_conditional=0.0;
    double median_processing_us=0.0;
    double p95_processing_us=0.0;
    int rejects=0;
    bool flush_completed=false;
};

int main(int argc, char** argv) {
    int runs=10;
    int events_per_run=5000;
    std::uint64_t base_seed=20260930ULL;

    if (argc>=2) runs=std::max(1,std::atoi(argv[1]));
    if (argc>=3) events_per_run=std::max(1,std::atoi(argv[2]));
    if (argc>=4) base_seed=std::strtoull(argv[3],nullptr,10);

    const std::array<double,5> probs{
        0.00,0.01,0.05,0.10,0.20
    };

    std::ofstream raw("state_recovery_random_loss_raw.csv");
    raw << "loss_probability,run,event,branch,m2_lost,m3_lost,"
           "committed,clean_after_event,vU_after,vC_after,pending_after,"
           "reject_reason,processing_us\n";

    std::vector<RunSummary> summaries;

    std::cout << "=== Random M2/M3 Loss Experiment ===\n"
              << "runs=" << runs
              << ", events_per_run=" << events_per_run
              << ", base_seed=" << base_seed << "\n\n";

    for (double p: probs) {
        for (int run=1; run<=runs; ++run) {
            std::uint64_t seed =
                base_seed +
                static_cast<std::uint64_t>(p*10000.0)*100000ULL +
                static_cast<std::uint64_t>(run);

            Protocol proto(FreshnessMode::Epoch,1.0,0.0);
            RandomLossRun rr=
                proto.run_random_loss_stream(p,events_per_run,seed);

            std::vector<double> times;
            times.reserve(rr.rows.size());

            for (const auto& e: rr.rows) {
                raw << std::fixed << std::setprecision(4)
                    << p << ',' << run << ',' << e.event_index << ','
                    << e.branch << ','
                    << e.m2_lost << ',' << e.m3_lost << ','
                    << e.committed << ',' << e.clean_after_event << ','
                    << e.vU_after << ',' << e.vC_after << ','
                    << e.pending_after << ','
                    << e.reject_reason << ','
                    << std::setprecision(6) << e.processing_us << '\n';
                times.push_back(e.processing_us);
            }

            RunSummary s;
            s.p=p;
            s.run=run;
            s.events=events_per_run;
            s.completion_rate=
                100.0*rr.committed_events/events_per_run;
            s.clean_state_rate=
                100.0*rr.clean_after_events/events_per_run;
            s.recovery_invocation_rate=
                100.0*rr.recovery_invocations/events_per_run;
            s.recovery_commit_rate=
                rr.recovery_invocations
                ? 100.0*rr.recovery_commits/rr.recovery_invocations
                : 100.0;
            s.m2_loss_rate=
                100.0*rr.m2_losses/events_per_run;

            int m2_delivered=events_per_run-rr.m2_losses;
            s.m3_loss_rate_conditional=
                m2_delivered
                ? 100.0*rr.m3_losses/m2_delivered
                : 0.0;

            s.median_processing_us=median(times);
            s.p95_processing_us=percentile(times,95.0);
            s.rejects=rr.rejected_events;
            s.flush_completed=rr.flush_completed;
            summaries.push_back(s);

            if (rr.rejected_events!=0 || !rr.flush_completed) {
                std::cerr << "FAIL at p=" << p
                          << ", run=" << run
                          << ": rejects=" << rr.rejected_events
                          << ", flush=" << rr.flush_completed << '\n';
                return 2;
            }
        }
    }
    raw.close();

    std::ofstream runout("state_recovery_random_loss_run_summary.csv");
    runout << "loss_probability,run,events,completion_rate_pct,"
              "clean_state_rate_pct,recovery_invocation_rate_pct,"
              "recovery_commit_rate_pct,m2_loss_rate_pct,"
              "m3_loss_rate_conditional_pct,median_processing_us,"
              "p95_processing_us,rejects,flush_completed\n";

    for (const auto& s: summaries) {
        runout << std::fixed << std::setprecision(4)
               << s.p << ',' << s.run << ',' << s.events << ','
               << s.completion_rate << ','
               << s.clean_state_rate << ','
               << s.recovery_invocation_rate << ','
               << s.recovery_commit_rate << ','
               << s.m2_loss_rate << ','
               << s.m3_loss_rate_conditional << ','
               << std::setprecision(6)
               << s.median_processing_us << ','
               << s.p95_processing_us << ','
               << s.rejects << ','
               << s.flush_completed << '\n';
    }
    runout.close();

    std::ofstream finalout("state_recovery_random_loss_summary.csv");
    finalout << "loss_probability,"
                "completion_rate_median_pct,"
                "clean_state_rate_median_pct,"
                "recovery_invocation_rate_median_pct,"
                "recovery_commit_rate_median_pct,"
                "m2_loss_rate_median_pct,"
                "m3_loss_rate_conditional_median_pct,"
                "processing_median_of_run_medians_us,"
                "processing_p95_of_run_medians_us,"
                "all_runs_zero_rejects,"
                "all_runs_flush_completed\n";

    std::cout << std::fixed << std::setprecision(3);
    std::cout << "p_loss  completion  recovery_invocation  recovery_commit"
                 "  proc_median(us)  status\n";

    for (double p: probs) {
        std::vector<double> completion,clean,recovery_inv,recovery_commit;
        std::vector<double> m2rate,m3rate,procmed;
        bool zero_rejects=true;
        bool all_flush=true;

        for (const auto& s: summaries) if (s.p==p) {
            completion.push_back(s.completion_rate);
            clean.push_back(s.clean_state_rate);
            recovery_inv.push_back(s.recovery_invocation_rate);
            recovery_commit.push_back(s.recovery_commit_rate);
            m2rate.push_back(s.m2_loss_rate);
            m3rate.push_back(s.m3_loss_rate_conditional);
            procmed.push_back(s.median_processing_us);
            zero_rejects = zero_rejects && (s.rejects==0);
            all_flush = all_flush && s.flush_completed;
        }

        double cm=median(completion);
        double cl=median(clean);
        double ri=median(recovery_inv);
        double rc=median(recovery_commit);
        double m2=median(m2rate);
        double m3=median(m3rate);
        double pm=median(procmed);
        double pp95=percentile(procmed,95.0);

        finalout << std::fixed << std::setprecision(4)
                 << p << ',' << cm << ',' << cl << ','
                 << ri << ',' << rc << ',' << m2 << ',' << m3 << ','
                 << std::setprecision(6) << pm << ',' << pp95 << ','
                 << zero_rejects << ',' << all_flush << '\n';

        std::cout << std::setw(6) << 100.0*p << "%  "
                  << std::setw(9) << cm << "%  "
                  << std::setw(19) << ri << "%  "
                  << std::setw(15) << rc << "%  "
                  << std::setw(15) << pm << "  "
                  << ((zero_rejects && all_flush) ? "PASS" : "FAIL")
                  << '\n';
    }
    finalout.close();

    std::cout << "\nGenerated:\n"
              << "  state_recovery_random_loss_raw.csv\n"
              << "  state_recovery_random_loss_run_summary.csv\n"
              << "  state_recovery_random_loss_summary.csv\n\n"
              << "Definitions:\n"
              << "  completion_rate = current mobility events reaching M3 commit.\n"
              << "  recovery_invocation_rate = events entering M2_RECOVER or M3_RECOVER.\n"
              << "  recovery_commit_rate = recovery-invoked events that themselves reach M3 commit.\n"
              << "  flush_completed = one final reliable authorized event restores SU=SC and Pi=bottom.\n\n"
              << "IMPORTANT: this is Bernoulli fault injection on protocol M2/M3 delivery\n"
              << "inside the prototype. It is NOT a wireless-channel or network simulation.\n";

    return 0;
}
