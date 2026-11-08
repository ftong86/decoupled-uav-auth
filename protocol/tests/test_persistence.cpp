// S2 acceptance test: real durable persistence and crash-restart at the three
// mandated persistence points (docs/S0_protocol_message_table.md section 3).
#include <cstdio>
#include <iostream>
#include <string>

#include "uavma/crypto.h"
#include "uavma/experiment_driver.h"
#include "uavma/harness.h"
#include "uavma/protocol_core.h"
#include "uavma/state_store.h"

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

static Bytes seed_for(const std::string& tag) { return sha256(text("uavma-s2-persist-" + tag)); }

int main(int argc, char** argv) {
  const std::string out = argc > 1 ? argv[1] : ".";
  ensure_dir(out);
  EventLog log(out + "/persistence_events.jsonl", false);
  CsvWriter csv(out + "/persistence_points.csv",
                {"domain", "persistence_point", "restart_ok", "uav_v_after", "committed_v_after",
                 "pending_present_after", "pending_v_after", "resume_result", "measurement_type"});

  VariantConfig p;
  p.id = "P";
  const std::string mt = "linux_native_s2_persistence";

  for (Domain d : {Domain::G, Domain::E}) {
    const std::string dom = domain_str(d);
    const std::string tid = (d == Domain::G) ? "GS_T1" : "ES_T1";

    // ---- point 1: target persists Pi BEFORE emitting M2 ------------------------
    {
      std::string db = out + "/persist_p1_" + dom + ".db";
      std::remove(db.c_str());
      std::remove((db + "-wal").c_str());
      std::remove((db + "-shm").c_str());
      World w(d, tid, seed_for(dom + "-p1"), p, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      M1Outcome oc = w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      CHECK(oc.ok, dom + ": pending installed and persisted before M2");
      Bytes pending_rho = w.target->pi()->next.rho;
      uint32_t committed_v = w.target->sc().v;
      w.crash_restart();
      CHECK(w.target->sc().v == committed_v, dom + " P1: committed survives the crash");
      CHECK(w.target->pi() != nullptr, dom + " P1: pending migration survives the crash");
      CHECK(w.target->pi()->next.rho == pending_rho, dom + " P1: pending candidate identical");
      CHECK(w.uav->su().v == 0, dom + " P1: UAV did not activate before M2");
      // Resume with a NEW authorization (M2Recover) and complete the transaction.
      PreparedTx p2 = prepare_authorization(w, tid);
      M1Outcome oc2 = w.target->handle_m1(p2.m1, p2.epoch, now_mono_ms(), 0, &err);
      CHECK(oc2.ok && oc2.branch == Branch::M2Recover,
            dom + " P1: resumes via M2Recover (" + oc2.reason + ")");
      TxReport r = finish_transaction(w, p2.epoch);
      CHECK(r.committed && r.committed_v == 1,
            dom + " P1: transaction completes after restart (" + r.reason + ")");
      csv.row({dom, "P1_pending_before_M2", "1", std::to_string(w.uav->su().v),
               std::to_string(w.target->sc().v), "0", "-", "M2Recover+commit", mt});
    }

    // ---- point 2: UAV persists S^U <- S^N BEFORE emitting M3 -------------------
    {
      std::string db = out + "/persist_p2_" + dom + ".db";
      std::remove(db.c_str());
      std::remove((db + "-wal").c_str());
      std::remove((db + "-shm").c_str());
      World w(d, tid, seed_for(dom + "-p2"), p, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      CHECK(w.uav->handle_m2(w.target->m2(), &err), dom + ": UAV activated by M2");
      uint32_t uav_v = w.uav->su().v;
      CHECK(uav_v == 1, dom + " P2: UAV advanced to the candidate");
      // The UAV keeps (SID, TH_2, K^cm, tau_C) for the bounded retransmission window;
      // that tuple survives the UAV restart because S^U was already persisted.
      M3Msg retained_m3 = w.uav->m3();
      w.crash_restart();
      CHECK(w.uav->su().v == uav_v, dom + " P2: durable S^U survives the UAV crash");
      CHECK(w.target->sc().v == 0, dom + " P2: target has not committed yet");
      CHECK(w.target->handle_m3(retained_m3, p1.epoch, now_mono_ms(), &err),
            dom + " P2: M3 commits after the crash-restart (" + err + ")");
      CHECK(w.target->sc().v == 1, dom + " P2: committed advanced exactly one version");
      csv.row({dom, "P2_uav_before_M3", "1", std::to_string(w.uav->su().v),
               std::to_string(w.target->sc().v), "0", "-", "M3 commit", mt});
    }

    // ---- point 3: target commits atomically after verifying M3 -----------------
    {
      std::string db = out + "/persist_p3_" + dom + ".db";
      std::remove(db.c_str());
      std::remove((db + "-wal").c_str());
      std::remove((db + "-shm").c_str());
      World w(d, tid, seed_for(dom + "-p3"), p, db, &log);
      std::string err;
      PreparedTx p1 = prepare_authorization(w, tid);
      w.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
      w.uav->handle_m2(w.target->m2(), &err);
      CHECK(w.target->handle_m3(w.uav->m3(), p1.epoch, now_mono_ms(), &err),
            dom + ": atomic commit after M3");
      w.crash_restart();
      CHECK(w.target->sc().v == 1, dom + " P3: committed state survives restart");
      CHECK(!w.target->pi(), dom + " P3: pending cleared and stays cleared");
      CHECK(w.uav->su().v == 1, dom + " P3: UAV state survives restart");
      std::string why;
      CHECK(invariants_hold(w.uav->su(), w.target->sc(), w.target->pi(), &why),
            dom + " P3: Eq.(16) holds after restart");
      csv.row({dom, "P3_commit_after_M3", "1", std::to_string(w.uav->su().v),
               std::to_string(w.target->sc().v), "0", "-", "consistent", mt});
    }
  }

  // ---- negative control: a fresh store holds nothing --------------------------
  {
    std::string db = out + "/persist_empty.db";
    std::remove(db.c_str());
    StateStore s(db);
    State st;
    bool present = s.load_committed(Domain::G, st);
    CHECK(!present, "an empty store returns no committed state (no fabricated defaults)");
  }

  std::cout << (g_failures == 0 ? "TEST_PERSISTENCE PASS\n" : "TEST_PERSISTENCE FAIL\n");
  return g_failures == 0 ? 0 : 1;
}
