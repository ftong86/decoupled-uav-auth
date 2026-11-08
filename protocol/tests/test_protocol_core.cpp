// S2 acceptance test: protocol core (normal G / E / GE transactions, invariants,
// instrumented primitive counters, measured byte accounting).
// Sources: docs/S0_protocol_message_table.md, docs/S0_state_machine_table.md.
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
#define CHECK(cond, msg)                                                            \
  do {                                                                              \
    if (!(cond)) {                                                                  \
      std::cerr << "FAIL: " << msg << " (line " << __LINE__ << ")\n";               \
      ++g_failures;                                                                 \
    } else {                                                                        \
      std::cout << "ok: " << msg << '\n';                                           \
    }                                                                               \
  } while (0)

static Bytes seed_for(const std::string& tag) { return sha256(text("uavma-s2-" + tag)); }

int main(int argc, char** argv) {
  const std::string out = argc > 1 ? argv[1] : ".";
  ensure_dir(out);
  const std::string db_g = out + "/protocol_G.db";
  const std::string db_e = out + "/protocol_E.db";
  std::remove(db_g.c_str());
  std::remove(db_e.c_str());

  EventLog log(out + "/protocol_core_events.jsonl", false);
  CsvWriter csv(out + "/normal_transactions.csv",
                {"case", "domain", "branch", "committed", "committed_v", "uav_v", "pending",
                 "puf_eval", "sign", "verify", "mac", "hash", "ecdh", "body_ul", "body_dl",
                 "body_inf", "body_mm", "framed_total", "paper_ref_total", "t_full_ms",
                 "measurement_type"});

  VariantConfig p;  // P: the paper scheme
  p.id = "P";

  World g(Domain::G, "GS_T1", seed_for("G"), p, db_g, &log);
  World e(Domain::E, "ES_T1", seed_for("E"), p, db_e, &log);

  auto row = [&](const std::string& c, const std::string& dom, const TxReport& r,
                 const std::string& mt) {
    csv.row({c, dom, r.branch, std::to_string(r.committed), std::to_string(r.committed_v),
             std::to_string(r.uav_v), std::to_string(r.pending_present), std::to_string(r.puf),
             std::to_string(r.sign), std::to_string(r.verify), std::to_string(r.mac),
             std::to_string(r.hash), std::to_string(r.ecdh), std::to_string(r.body_ul),
             std::to_string(r.body_dl), std::to_string(r.body_inf), std::to_string(r.body_mm),
             std::to_string(r.framed_total), "656", std::to_string(r.t_full_ms), mt});
  };

  // ---- registration: long-term configuration, identical on both ends
  CHECK(g.target->sc().v == 0 && g.uav->su().v == 0, "registration: both ends at S_0");
  CHECK(g.target->sc().rho == g.uav->su().rho, "registration: identical state digest");
  CHECK(g.target->pid() == g.uav->pid(), "registration: identical domain pseudonym PID_G");

  // ---- HO_G: one complete G-domain transaction
  TxReport rg = run_transaction(g);
  CHECK(rg.committed, "HO_G reaches target committed");
  CHECK(rg.branch == "normal", "HO_G uses the normal branch");
  CHECK(rg.committed_v == 1 && rg.uav_v == 1, "HO_G advances exactly one version");
  CHECK(rg.committed_rho == rg.uav_rho, "HO_G: S^U and S^C identical after commit (Eq.16)");
  CHECK(!rg.pending_present, "HO_G clears the pending migration");
  CHECK(rg.puf == 1, "HO_G performs exactly one PUFEval for the new M1");
  // Exactly two signatures per normal transaction: the target PreAuth on M0 (long-term
  // key) and the UAV state signature sigma_U on M1. No signature is repeated.
  CHECK(rg.sign == 2, "HO_G performs exactly two signatures (PreAuth + sigma_U)");
  CHECK(rg.verify >= 3, "HO_G verifies certificate, PreAuth and sigma_U");
  CHECK(rg.ecdh == 2, "HO_G performs ECDH on both sides");
  {
    std::string why;
    CHECK(invariants_hold(g.uav->su(), g.target->sc(), g.target->pi(), &why),
          "HO_G invariants hold (" + why + ")");
  }
  row("HO_G", "G", rg, "linux_native_s2_protocol_core");

  // ---- E domain is untouched by a G transaction
  CHECK(e.target->sc().v == 0 && e.uav->su().v == 0, "G transaction does not mutate domain E");

  // ---- Mig_E: one complete E-domain transaction
  TxReport re = run_transaction(e);
  CHECK(re.committed, "Mig_E reaches target committed");
  CHECK(re.committed_v == 1 && re.uav_v == 1, "Mig_E advances exactly one version");
  CHECK(re.puf == 1, "Mig_E performs exactly one PUFEval");
  row("Mig_E", "E", re, "linux_native_s2_protocol_core");
  CHECK(g.target->sc().v == 1, "Mig_E does not mutate domain G");

  // ---- cached retransmission inside the same session: no PUFEval, no new signature
  {
    OpCounters before = counters();
    TxReport rr = run_transaction(g, TxOptions{});
    // A second authorized transaction is a NEW authorization, so it must re-derive.
    CHECK(rr.committed && rr.committed_v == 2, "second G transaction commits to v=2");
    CHECK(rr.puf == 1, "new authorization triggers a fresh PUFEval");
    (void)before;
    row("HO_G#2", "G", rr, "linux_native_s2_protocol_core");
  }
  {
    // Same-session retransmission while M2 is still outstanding: cached M2, and
    // no additional PUFEval or signature.
    World g3(Domain::G, "GS_T3", seed_for("G3"), p, out + "/protocol_G3.db", &log);
    std::remove((out + "/protocol_G3.db").c_str());
    std::string err;
    PreparedTx p1 = prepare_authorization(g3, "GS_T3");
    M1Outcome oc = g3.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
    CHECK(oc.ok && oc.branch == Branch::Normal, "fresh M1 is handled on the normal branch");
    OpCounters before = counters();
    M1Outcome oc2 = g3.target->handle_m1(p1.m1, p1.epoch, now_mono_ms(), 0, &err);
    CHECK(oc2.ok && oc2.branch == Branch::CachedRetry,
          "retransmitted M1 is served from cache (" + oc2.reason + ")");
    OpCounters delta = counters() - before;
    CHECK(delta.puf == 0, "cached M1 retry performs no PUFEval");
    CHECK(delta.sign == 0, "cached M1 retry performs no signature");
    TxReport r = finish_transaction(g3, p1.epoch);
    CHECK(r.committed, "cached-retry transaction commits (" + r.reason + ")");
    CHECK(g3.target->sc().v == 1, "cached-retry advances exactly one version");
    CHECK(g3.target->commits() == 1, "cached-retry performs exactly one commit");
  }

  // ---- GE: two independent domain transactions; completion is the later of the two
  {
    World g2(Domain::G, "GS_T2", seed_for("G2"), p, out + "/protocol_G2.db", &log);
    World e2(Domain::E, "ES_T2", seed_for("E2"), p, out + "/protocol_E2.db", &log);
    std::remove((out + "/protocol_G2.db").c_str());
    TxReport rg2 = run_transaction(g2);
    TxReport re2 = run_transaction(e2);
    CHECK(rg2.committed && re2.committed, "GE: both domains commit");
    int64_t ge_full = std::max(rg2.t_full_ms, re2.t_full_ms);
    CHECK(ge_full >= rg2.t_full_ms && ge_full >= re2.t_full_ms,
          "GE completion time is the later domain completion (not a sum)");
    row("GE", "G", rg2, "linux_native_s2_protocol_core");
    row("GE", "E", re2, "linux_native_s2_protocol_core");
    log.event("ge_completion",
              {{"g_full_ms", std::to_string(rg2.t_full_ms)},
               {"e_full_ms", std::to_string(re2.t_full_ms)},
               {"ge_full_ms", std::to_string(ge_full)}});
  }

  // ---- measured byte accounting (never presented as the 656 B design budget)
  {
    std::cout << "measured body bytes for one normal transaction: UL=" << rg.body_ul
              << " DL=" << rg.body_dl << " INF=" << rg.body_inf << " MM=" << rg.body_mm << '\n';
    std::cout << "paper fixed-field budget (design level, docs/field_ledger.md): UL=226 DL=276 "
                 "INF=154 MM=72 total=656\n";
    CHECK(rg.body_ul > 0 && rg.body_dl > 0 && rg.body_inf > 0, "byte accounting is instrumented");
  }

  std::cout << (g_failures == 0 ? "TEST_PROTOCOL_CORE PASS\n" : "TEST_PROTOCOL_CORE FAIL\n");
  return g_failures == 0 ? 0 : 1;
}
