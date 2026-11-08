// S2 acceptance test: M2/M3 loss recovery (Sec.V-D), expiry, stale inputs, A-Retry.
// Sources: docs/S0_state_machine_table.md sections 4 and 5.
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "uavma/crypto.h"
#include "uavma/experiment_driver.h"
#include "uavma/harness.h"
#include "uavma/protocol_core.h"

using namespace uavma;

static int g_failures = 0;
#define CHECK(cond, msg)                                                   \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::cerr << "FAIL: " << msg << " (line " << __LINE__ << ")\n";      \
      ++g_failures;                                                        \
    } else {                                                               \
      std::cout << "ok: " << msg << '\n';                                  \
    }                                                                      \
  } while (0)

static Bytes seed_for(const std::string& tag) { return sha256(text("uavma-s2-rec-" + tag)); }

int main(int argc, char** argv) {
  const std::string out = argc > 1 ? argv[1] : ".";
  ensure_dir(out);
  EventLog log(out + "/recovery_events.jsonl", false);
  CsvWriter cases(out + "/fault_cases.csv",
                  {"domain", "fault", "recovery", "scheme", "new_target", "success", "branch",
                   "committed_v", "uav_v", "commits", "final_consistent", "reason",
                   "measurement_type"});
  CsvWriter trans(out + "/state_transitions.csv",
                  {"domain", "stage", "uav_v", "committed_v", "pending_v", "pending_rho",
                   "sess_state", "measurement_type"});

  VariantConfig p;
  p.id = "P";
  VariantConfig aretry;
  aretry.id = "A-Retry";
  aretry.a_retry = true;

  const std::string mt = "linux_native_s2_recovery";

  auto snap = [&](const std::string& dom, const std::string& stage, World& w) {
    std::string pv = "-", prho = "-", st = "-";
    if (w.target->pi()) {
      pv = std::to_string(w.target->pi()->next.v);
      prho = hex_prefix(w.target->pi()->next.rho);
    }
    auto it = w.target->sessions().find(w.active_sid);
    if (it != w.target->sessions().end()) st = sess_state_str(it->second.st);
    trans.row({dom, stage, std::to_string(w.uav->su().v), std::to_string(w.target->sc().v), pv,
               prho, st, mt});
  };

  for (Domain d : {Domain::G, Domain::E}) {
    const std::string dom = domain_str(d);
    const std::string tid = (d == Domain::G) ? "GS_T1" : "ES_T1";
    const std::string tid2 = (d == Domain::G) ? "GS_T2" : "ES_T2";

    // ---------------- 1. M2 lost, same-session retransmission ----------------
    {
      std::string db = out + "/rec_m2_retry_" + dom + ".db";
      std::remove(db.c_str());
      World w(d, tid, seed_for(dom + "-m2retry"), p, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      M1Outcome oc = w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      CHECK(oc.ok && oc.branch == Branch::Normal, dom + ": first M1 installs pending (normal)");
      snap(dom, "M2_lost_after_M1", w);
      CHECK(w.target->sc().v == 0 && w.uav->su().v == 0, dom + ": UAV not activated before M2");
      // M2 is lost; retransmit the identical M1 in the same session.
      OpCounters before = counters();
      M1Outcome oc2 = w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      OpCounters delta = counters() - before;
      CHECK(oc2.ok && oc2.branch == Branch::CachedRetry, dom + ": duplicate M1 -> cached retry");
      CHECK(delta.puf == 0 && delta.sign == 0, dom + ": cached retry repeats no PUF/signature");
      TxReport r = finish_transaction(w, p1.epoch);
      CHECK(r.committed && r.committed_v == 1 && r.uav_v == 1, dom + ": M2 retry commits v=1");
      std::string why;
      CHECK(invariants_hold(w.uav->su(), w.target->sc(), w.target->pi(), &why),
            dom + ": consistent after M2 retry");
      cases.row({dom, "M2", "same-session-retry", "P", "0", "1", "cached-retry",
                 std::to_string(r.committed_v), std::to_string(r.uav_v),
                 std::to_string(r.commits), "1", "", mt});
    }

    // ---------------- 2. M2 lost, NEW authorization, same target: M2Recover ----
    {
      std::string db = out + "/rec_m2rec_" + dom + ".db";
      std::remove(db.c_str());
      World w(d, tid, seed_for(dom + "-m2rec"), p, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      M1Outcome oc = w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      CHECK(oc.ok, dom + ": pending installed before M2 loss");
      Bytes old_rho = w.target->pi()->next.rho;
      uint32_t old_v = w.target->pi()->next.v;
      PreparedTx p2 = prepare_authorization(w, tid);
      CHECK(p2.epoch > p1.epoch, dom + ": new authorization raises the epoch");
      M1Outcome oc2 = w.target->handle_m1(p2.m1, p2.epoch, now_mono_ms(), 0, &err);
      CHECK(oc2.ok && oc2.branch == Branch::M2Recover, dom + ": new M1 recognized as M2Recover");
      CHECK(w.target->sc().v == 0, dom + ": M2Recover does NOT advance committed");
      CHECK(w.target->pi()->next.v == old_v, dom + ": M2Recover keeps the same version number");
      CHECK(hex(w.target->pi()->next.rho) != hex(old_rho),
            dom + ": M2Recover replaces pending with a different CV/PK/rho");
      snap(dom, "M2Recover_pending_replaced", w);
      TxReport r = finish_transaction(w, p2.epoch);
      CHECK(r.committed && r.committed_v == 1, dom + ": M2Recover transaction commits v=1");
      std::string why;
      CHECK(invariants_hold(w.uav->su(), w.target->sc(), w.target->pi(), &why),
            dom + ": consistent after M2Recover");
      cases.row({dom, "M2", "new-authorization", "P", "0", "1", "M2Recover",
                 std::to_string(r.committed_v), std::to_string(r.uav_v),
                 std::to_string(r.commits), "1", "", mt});
    }

    // ---------------- 3. M3 lost, same-session retransmission ----------------
    {
      std::string db = out + "/rec_m3_retry_" + dom + ".db";
      std::remove(db.c_str());
      World w(d, tid, seed_for(dom + "-m3retry"), p, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      M1Outcome oc = w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      CHECK(oc.ok, dom + ": M1 handled");
      CHECK(w.uav->handle_m2(w.target->m2(), &err), dom + ": UAV activated by M2");
      snap(dom, "M3_lost_after_activation", w);
      CHECK(w.uav->su().v == 1 && w.target->sc().v == 0, dom + ": UAV activated, target at S_v");
      // M3 is lost; the UAV resends the stored M3 of the same session.
      CHECK(w.target->handle_m3(w.uav->m3(), p1.epoch, now_mono_ms(), &err),
            dom + ": retransmitted M3 commits");
      CHECK(w.target->sc().v == 1, dom + ": committed advanced by exactly one version");
      CHECK(!w.target->pi(), dom + ": pending cleared after commit");
      // A second identical M3 must not advance anything.
      bool again = w.target->handle_m3(w.uav->m3(), p1.epoch, now_mono_ms(), &err);
      CHECK(!again && w.target->sc().v == 1, dom + ": duplicate M3 does not commit twice");
      cases.row({dom, "M3", "same-session-retry", "P", "0", "1", "cached-retry", "1", "1", "1",
                 "1", "", mt});
    }

    // ---------------- 4. M3 lost, NEW authorization: M3Recover (two commits) ---
    {
      std::string db = out + "/rec_m3rec_" + dom + ".db";
      std::remove(db.c_str());
      World w(d, tid, seed_for(dom + "-m3rec"), p, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      CHECK(w.uav->handle_m2(w.target->m2(), &err), dom + ": UAV activated before M3 loss");
      const uint64_t commits_before = w.target->commits();
      PreparedTx p2 = prepare_authorization(w, tid);
      M1Outcome oc2 = w.target->handle_m1(p2.m1, p2.epoch, now_mono_ms(), 0, &err);
      CHECK(oc2.ok && oc2.branch == Branch::M3Recover, dom + ": new M1 recognized as M3Recover");
      CHECK(w.target->sc().v == 1, dom + ": M3Recover first commits the activated pending");
      CHECK(w.target->pi()->next.v == 2, dom + ": then installs the next candidate v+2");
      snap(dom, "M3Recover_old_pending_committed", w);
      TxReport r = finish_transaction(w, p2.epoch);
      CHECK(r.committed && r.committed_v == 2,
            dom + ": M3Recover ends at v=2 (" + r.reason + ")");
      CHECK(w.target->commits() - commits_before == 2,
            dom + ": M3Recover performs two independent commits (+2, not one jump of 2)");
      std::string why;
      CHECK(invariants_hold(w.uav->su(), w.target->sc(), w.target->pi(), &why),
            dom + ": consistent after M3Recover");
      cases.row({dom, "M3", "new-authorization", "P", "0", "1", "M3Recover",
                 std::to_string(r.committed_v), std::to_string(r.uav_v), "2", "1", "", mt});
    }

    // ---------------- 5. M2 lost, NEW authorization, NEW target ----------------
    {
      std::string db = out + "/rec_newtgt_" + dom + ".db";
      std::string db2 = out + "/rec_newtgt2_" + dom + ".db";
      std::remove(db.c_str());
      std::remove(db2.c_str());
      World w(d, tid, seed_for(dom + "-newtgt"), p, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      CHECK(w.target->pi() != nullptr, dom + ": old target holds a pending migration");
      // A new target receives the protected Transfer carrying the real Pi encoding.
      World w2(d, tid2, seed_for(dom + "-newtgt"), p, db2, &log);
      w2.uav->set_su(w.uav->su());
      w2.src->set_committed(w.target->sc());
      w2.src->set_pending(std::optional<Pending>(*w.target->pi()));
      uint64_t ep = w2.mm.authorize(tid2);
      TransferMsg tr = w2.src->build_transfer(tid2, ep);
      CHECK(tr.has_pi, dom + ": cross-target Transfer really encodes Pi (not a constant 154 B)");
      CHECK(tr.account().body > 154, dom + ": Transfer with Pi exceeds the Pi-empty budget");
      w2.target->accept_transfer(tr);
      M0Msg m0 = w2.target->create_session(w2.uav->pid(), tid2, ep);
      CHECK(w2.uav->handle_m0(m0, w2.ca.ca_pk(), ep, &err), dom + ": UAV accepts M0 from new target");
      M1Msg m1 = w2.uav->build_m1(0);
      M1Outcome oc = w2.target->handle_m1(m1, ep, now_mono_ms(), 0, &err);
      CHECK(oc.ok && oc.branch == Branch::M2Recover, dom + ": new target runs M2Recover");
      CHECK(w2.target->sc().v == 0, dom + ": new target has not advanced committed");
      TxReport r = finish_transaction(w2, ep);
      CHECK(r.committed && r.committed_v == 1, dom + ": cross-target recovery commits v=1");
      cases.row({dom, "M2", "new-authorization", "P", "1", "1", "M2Recover", "1", "1", "1", "1",
                 "", mt});
    }

    // ---------------- 6. AwaitM3 expiry: secrets erased, Pi retained -----------
    {
      std::string db = out + "/rec_expire_" + dom + ".db";
      std::remove(db.c_str());
      World w(d, tid, seed_for(dom + "-expire"), p, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      CHECK(w.uav->handle_m2(w.target->m2(), &err), dom + ": UAV activated");
      CHECK(w.target->expire(w.active_sid, &err), dom + ": AwaitM3 session expires");
      bool late = w.target->handle_m3(w.uav->m3(), p1.epoch, now_mono_ms(), &err);
      CHECK(!late, dom + ": M3 after expiry is rejected");
      CHECK(w.target->sc().v == 0, dom + ": expired M3 does not commit");
      CHECK(w.target->pi() != nullptr, dom + ": Pi is retained for later recovery");
      auto it = w.target->sessions().find(w.active_sid);
      CHECK(it != w.target->sessions().end() && it->second.kcm.empty(),
            dom + ": session secrets erased on expiry");
      snap(dom, "AwaitM3_expired", w);
      // Recovery after expiry still works through M3Recover.
      PreparedTx p2 = prepare_authorization(w, tid);
      M1Outcome oc2 = w.target->handle_m1(p2.m1, p2.epoch, now_mono_ms(), 0, &err);
      CHECK(oc2.ok && oc2.branch == Branch::M3Recover,
            dom + ": M3Recover after expiry (" + oc2.reason + ")");
      TxReport r = finish_transaction(w, p2.epoch);
      CHECK(r.committed && r.committed_v == 2,
            dom + ": recovery after expiry reaches v=2 (" + r.reason + ")");
      cases.row({dom, "expiry", "new-authorization", "P", "0", "1", "M3Recover", "2", "2", "2",
                 "1", "", mt});
    }

    // ---------------- 7. A-Retry: no new-authorization recovery ----------------
    {
      std::string db = out + "/rec_aretry_" + dom + ".db";
      std::remove(db.c_str());
      World w(d, tid, seed_for(dom + "-aretry"), aretry, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      PreparedTx p2 = prepare_authorization(w, tid);
      M1Outcome oc2 = w.target->handle_m1(p2.m1, p2.epoch, now_mono_ms(), 0, &err);
      CHECK(!oc2.ok, dom + ": A-Retry cannot recover under a new authorization");
      CHECK(oc2.reason.find("A-Retry") != std::string::npos,
            dom + ": A-Retry failure is explicitly reported, not fabricated");
      CHECK(w.target->sc().v == 0, dom + ": A-Retry rejection leaves state unchanged");
      cases.row({dom, "M2", "new-authorization", "A-Retry", "0", "0", "reject", "0", "0", "0",
                 "1", oc2.reason, mt});
    }
  }

  // ---------------- 8. stale / cross-domain inputs must be rejected ------------
  {
    std::string err;
    World g(Domain::G, "GS_T1", seed_for("stale-G"), p, out + "/rec_stale_G.db", &log);
    World e(Domain::E, "ES_T1", seed_for("stale-E"), p, out + "/rec_stale_E.db", &log);
    PreparedTx pg = prepare_authorization(g, "GS_T1");
    // Old epoch: present an M1 under a superseded authorization.
    g.mm.authorize("GS_T1");
    M1Outcome oc = g.target->handle_m1(pg.m1, g.mm.epoch(), now_mono_ms(), 0, &err);
    CHECK(!oc.ok && oc.reason == "old epoch (superseded authorization)",
          "old-epoch M1 is rejected");
    CHECK(g.target->sc().v == 0 && !g.target->pi(), "old-epoch M1 changes no state");
    // Domain substitution: the G M1 cannot be accepted by the E target.
    PreparedTx pe = prepare_authorization(e, "ES_T1");
    M1Outcome ocx = e.target->handle_m1(pg.m1, pe.epoch, now_mono_ms(), 0, &err);
    CHECK(!ocx.ok, "cross-domain M1 is rejected (domain binding, Eq.19)");
    CHECK(e.target->sc().v == 0 && !e.target->pi(), "cross-domain attempt changes no E state");
    cases.row({"G", "old-epoch", "n/a", "P", "0", "0", "reject", "0", "0", "0", "1", oc.reason,
               mt});
    cases.row({"E", "domain-substitution", "n/a", "P", "0", "0", "reject", "0", "0", "0", "1",
               ocx.reason, mt});
  }

  std::cout << (g_failures == 0 ? "TEST_RECOVERY PASS\n" : "TEST_RECOVERY FAIL\n");
  return g_failures == 0 ? 0 : 1;
}
