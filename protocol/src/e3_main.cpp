// S4 / E3a + E3b: clock-independence grid and M2/M3 loss-recovery matrix.
// E3a compares P against A-Time (both keep epoch/SID/transcript checks); the offset is a
// controlled stress input, not a claim about real oscillator drift.
// E3b compares P against A-Retry (recovery-branch ablation). A-Retry's unsupported
// branches are reported as NOT RECOVERED; no re-registration latency is invented.
#include <cmath>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "uavma/crypto.h"
#include "uavma/experiment_driver.h"
#include "uavma/harness.h"
#include "uavma/protocol_core.h"

using namespace uavma;

namespace {

Bytes seed_for(const std::string& tag) { return sha256(text("uavma-e3-" + tag)); }

// ------------------------------------------------------------------ E3a

int e3a(const std::string& out) {
  CsvWriter csv(out + "/clock_cases.csv",
                {"delta_clk_over_W", "Dnet_over_W", "scheme", "domain", "committed", "reason",
                 "committed_v", "pending_present", "uav_v", "measurement_type"});
  const int64_t W = 500;  // reference window (controlled), milliseconds
  int p_accept = 0, at_accept = 0, total = 0;
  int mismatch = 0;

  for (int i = -15; i <= 15; ++i) {       // delta_clk / W = i / 10  (integer index)
    for (int j = 0; j <= 10; ++j) {        // Dnet / W = j / 20
      const int64_t delta_clk_ms = static_cast<int64_t>(i) * W / 10;
      const int64_t dnet_ms = static_cast<int64_t>(j) * W / 20;
      const double dc = static_cast<double>(i) / 10.0;
      const double dn = static_cast<double>(j) / 20.0;
      // Expected A-Time decision: |Delta_clk + D_net| <= W
      const bool window_ok = std::llabs(delta_clk_ms + dnet_ms) <= W;

      for (const std::string scheme : {"P", "A-Time"}) {
        VariantConfig v;
        v.id = scheme;
        v.a_time = (scheme == "A-Time");
        v.window_ms = W;
        for (Domain d : {Domain::G, Domain::E}) {
          const std::string dom = domain_str(d);
          const std::string tid = (d == Domain::G) ? "GS_T1" : "ES_T1";
          World w(d, tid, seed_for(dom + scheme + std::to_string(i) + "_" + std::to_string(j)), v,
                  "", nullptr);
          std::string err;
          PreparedTx p = prepare_authorization(w, tid, delta_clk_ms);
          bool committed = false;
          std::string reason;
          if (!p.ok) {
            reason = p.err;
          } else {
            M1Outcome oc = w.target->handle_m1(p.m1, p.epoch, now_mono_ms(), dnet_ms, &err);
            if (!oc.ok) {
              reason = oc.reason;
            } else {
              if (w.uav->handle_m2(w.target->m2(), &err)) {
                committed = w.target->handle_m3(w.uav->m3(), p.epoch, now_mono_ms(), &err);
                if (!committed) reason = err;
              } else {
                reason = err;
              }
            }
          }
          if (scheme == "P" && committed) ++p_accept;
          if (scheme == "A-Time" && committed) ++at_accept;
          if (scheme == "A-Time" && committed != window_ok) ++mismatch;
          ++total;
          csv.row({std::to_string(dc), std::to_string(dn), scheme, dom,
                   std::to_string(committed), reason, std::to_string(w.target->sc().v),
                   std::to_string(w.target->pi() ? 1 : 0), std::to_string(w.uav->su().v),
                   "linux_native_clock_grid_E3a"});
        }
      }
    }
  }
  std::cout << "E3a: " << total << " grid points; P accepted " << p_accept << "/"
            << (31 * 11 * 2) << "; A-Time accepted " << at_accept << "/" << (31 * 11 * 2)
            << "; A-Time/window mismatches: " << mismatch << '\n';
  if (p_accept != 31 * 11 * 2) {
    std::cerr << "FAIL: P rejected a valid transaction in the clock grid\n";
    return 1;
  }
  if (mismatch != 0) {
    std::cerr << "FAIL: A-Time acceptance does not match its authenticated window rule\n";
    return 1;
  }
  return 0;
}

// ------------------------------------------------------------------ E3b

struct CaseResult {
  bool success = false;
  std::string branch;
  std::string reason;
  uint32_t committed_v = 0, uav_v = 0;
  uint64_t commits = 0, puf = 0;
  int extra_messages = 0;
  int64_t recovery_ms = 0;
  bool consistent = false;
};

CaseResult run_fault_case(Domain d, const std::string& fault, const std::string& recovery,
                          bool new_target, const std::string& scheme, const std::string& out_dir) {
  VariantConfig v;
  v.id = scheme;
  v.a_retry = (scheme == "A-Retry");
  const std::string dom = domain_str(d);
  const std::string tid = (d == Domain::G) ? "GS_T1" : "ES_T1";
  const std::string tid2 = (d == Domain::G) ? "GS_T2" : "ES_T2";
  const std::string tag = dom + fault + recovery + (new_target ? "NT" : "ST") + scheme;
  World w(d, tid, seed_for(tag), v, "", nullptr);
  std::string err;
  CaseResult r;
  uint64_t commits_override = 0;  // set when the committing node is the NEW target
  OpCounters before = counters();
  int64_t t0 = now_mono_ms();

  auto complete = [&](World& ww, uint64_t epoch) {
    if (!ww.uav->handle_m2(ww.target->m2(), &err)) {
      r.reason = err;
      return false;
    }
    return ww.target->handle_m3(ww.uav->m3(), epoch, now_mono_ms(), &err);
  };

  if (fault == "none") {
    TxReport t = run_transaction(w);
    r.success = t.committed;
    r.branch = t.branch;
    r.reason = t.reason;
  } else if (fault == "M2" && recovery == "same-session") {
    PreparedTx p = prepare_authorization(w, tid);
    M1Outcome oc = w.target->handle_m1(p.m1, p.epoch, now_mono_ms(), 0, &err);
    if (!oc.ok) {
      r.reason = oc.reason;
    } else {
      ++r.extra_messages;  // retransmitted M1
      M1Outcome oc2 = w.target->handle_m1(p.m1, p.epoch, now_mono_ms(), 0, &err);
      r.branch = branch_str(oc2.branch);
      if (oc2.ok) {
        r.success = complete(w, p.epoch);
        if (!r.success) r.reason = err;
      } else {
        r.reason = oc2.reason;
      }
    }
  } else if (fault == "M2" && recovery == "new-authorization") {
    PreparedTx p = prepare_authorization(w, tid);
    w.target->handle_m1(p.m1, p.epoch, now_mono_ms(), 0, &err);
    if (!new_target) {
      TxReport t = run_transaction(w);
      r.success = t.committed;
      r.branch = t.branch;
      r.reason = t.reason;
    } else {
      World w2(d, tid2, seed_for(tag), v, "", nullptr);
      w2.uav->set_su(w.uav->su());
      w2.src->set_committed(w.target->sc());
      if (w.target->pi()) w2.src->set_pending(std::optional<Pending>(*w.target->pi()));
      uint64_t ep = w2.mm.authorize(tid2);
      TransferMsg tr = w2.src->build_transfer(tid2, ep);
      w2.target->accept_transfer(tr);
      M0Msg m0 = w2.target->create_session(w2.uav->pid(), tid2, ep);
      if (!w2.uav->handle_m0(m0, w2.ca.ca_pk(), ep, &err)) {
        r.reason = err;
      } else {
        M1Msg m1 = w2.uav->build_m1(0);
        M1Outcome oc = w2.target->handle_m1(m1, ep, now_mono_ms(), 0, &err);
        r.branch = branch_str(oc.branch);
        if (oc.ok) {
          r.success = complete(w2, ep);
          if (!r.success) r.reason = err;
        } else {
          r.reason = oc.reason;
        }
      }
      commits_override = w2.target->commits();
      w.uav->set_su(w2.uav->su());
      w.target->set_sc(w2.target->sc());
      w.target->set_pi(w2.target->pi() ? std::optional<Pending>(*w2.target->pi()) : std::nullopt);
    }
  } else if (fault == "M3" && recovery == "same-session") {
    PreparedTx p = prepare_authorization(w, tid);
    w.target->handle_m1(p.m1, p.epoch, now_mono_ms(), 0, &err);
    if (!w.uav->handle_m2(w.target->m2(), &err)) {
      r.reason = err;
    } else {
      ++r.extra_messages;  // retransmitted M3
      r.success = w.target->handle_m3(w.uav->m3(), p.epoch, now_mono_ms(), &err);
      if (!r.success) r.reason = err;
      r.branch = "cached-retry";
    }
  } else if (fault == "M3" && recovery == "new-authorization") {
    PreparedTx p = prepare_authorization(w, tid);
    w.target->handle_m1(p.m1, p.epoch, now_mono_ms(), 0, &err);
    w.uav->handle_m2(w.target->m2(), &err);
    TxReport t = run_transaction(w);
    r.success = t.committed;
    r.branch = t.branch;
    r.reason = t.reason;
  } else if (fault == "expiry" && recovery == "new-authorization") {
    PreparedTx p = prepare_authorization(w, tid);
    w.target->handle_m1(p.m1, p.epoch, now_mono_ms(), 0, &err);
    w.uav->handle_m2(w.target->m2(), &err);
    w.target->expire(w.active_sid, &err);
    TxReport t = run_transaction(w);
    r.success = t.committed;
    r.branch = t.branch;
    r.reason = t.reason;
  } else if (fault == "late-old-M3") {
    PreparedTx p = prepare_authorization(w, tid);
    w.target->handle_m1(p.m1, p.epoch, now_mono_ms(), 0, &err);
    w.uav->handle_m2(w.target->m2(), &err);
    M3Msg stale = w.uav->m3();
    TxReport t = run_transaction(w);  // new authorization supersedes the old transaction
    bool rejected = !w.target->handle_m3(stale, w.mm.epoch(), now_mono_ms(), &err);
    r.success = t.committed && rejected;
    r.branch = "late-M3-rejected";
    r.reason = rejected ? err : "stale M3 was accepted";
  } else {
    r.reason = "unsupported case";
  }

  OpCounters delta = counters() - before;
  r.recovery_ms = now_mono_ms() - t0;
  r.committed_v = w.target->sc().v;
  r.uav_v = w.uav->su().v;
  r.commits = commits_override ? commits_override : w.target->commits();
  r.puf = delta.puf;
  std::string why;
  r.consistent = invariants_hold(w.uav->su(), w.target->sc(), w.target->pi(), &why);
  if (!r.consistent) r.reason += " | invariant: " + why;
  (void)out_dir;
  return r;
}

int e3b(const std::string& out) {
  CsvWriter csv(out + "/fault_cases.csv",
                {"domain", "fault", "recovery", "new_target", "scheme", "success", "branch",
                 "committed_v", "uav_v", "commits", "puf_eval", "extra_messages", "recovery_ms",
                 "final_consistent", "reason", "measurement_type"});
  const std::string mt = "linux_native_fault_matrix_E3b";
  int a_retry_recovered = 0;
  for (Domain d : {Domain::G, Domain::E}) {
    const std::string dom = domain_str(d);
    for (const std::string& scheme : {"P", "A-Retry"}) {
      for (const std::string& fault : {"none", "M2", "M3", "expiry", "late-old-M3"}) {
        for (const std::string& rec : {"same-session", "new-authorization"}) {
          if (fault == "none" && rec == "new-authorization") continue;
          if (fault == "expiry" && rec == "same-session") continue;
          if (fault == "late-old-M3" && rec == "same-session") continue;
          for (bool nt : {false, true}) {
            if (nt && !(fault == "M2" && rec == "new-authorization")) continue;
            CaseResult r = run_fault_case(d, fault, rec, nt, scheme, out);
            if (scheme == "A-Retry" && rec == "new-authorization" && fault != "none" &&
                r.success)
              ++a_retry_recovered;
            csv.row({dom, fault, rec, std::to_string(nt), scheme, std::to_string(r.success),
                     r.branch, std::to_string(r.committed_v), std::to_string(r.uav_v),
                     std::to_string(r.commits), std::to_string(r.puf),
                     std::to_string(r.extra_messages), std::to_string(r.recovery_ms),
                     std::to_string(r.consistent), r.reason, mt});
          }
        }
      }
    }
  }
  // A-Retry must NOT recover under a new authorization (that is exactly the ablation).
  if (a_retry_recovered != 0) {
    std::cerr << "FAIL: A-Retry recovered a new-authorization case (" << a_retry_recovered
              << "); it must report NOT RECOVERED\n";
    return 1;
  }
  std::cout << "E3b: fault matrix complete; A-Retry new-authorization recoveries: "
            << a_retry_recovered << " (expected 0)\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "usage: uavma_e3 e3a|e3b <out_dir>\n";
    return 64;
  }
  const std::string cmd = argv[1];
  const std::string out = argv[2];
  ensure_dir(out);
  try {
    int rc = (cmd == "e3a") ? e3a(out) : (cmd == "e3b") ? e3b(out) : 64;
    if (rc == 0) std::cout << "E3 " << cmd << " PASS\n";
    return rc;
  } catch (const std::exception& ex) {
    std::cerr << "FAILED: " << ex.what() << '\n';
    return 1;
  }
}
