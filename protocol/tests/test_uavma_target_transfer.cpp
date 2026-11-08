// ADAPTER integration guard using frozen native core. This does NOT change core.
// Tests source-target Transfer across different target certificates with evolving state.
#include <cassert>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

#include "uavma/crypto.h"
#include "uavma/harness.h"
#include "uavma/protocol_core.h"

using namespace uavma;

static void change_target(World& w, const std::string& destination) {
  assert(w.target->pi() == nullptr);  // do not discard unresolved session
  w.target_id = destination;
  w.src->set_committed(w.target->sc());
  w.src->set_pending(std::nullopt);
  // For this native test we first construct the fresh target from a new CA-issued
  // identity and copy the preserved state. The next run_transaction builds and
  // accepts the paper's protected Transfer message using precisely that state.
  const State copy = w.target->sc();
  Bytes dr = w.root.domain_root(domain_char(w.d));
  auto moved = std::make_unique<TargetCore>(w.d, destination,
       w.ca.target_lt_sk(destination), dr, w.seed, w.v, nullptr, w.log);
  moved->set_cert_sig(w.ca.issue_cert(destination, w.ca.target_lt_pk(destination)));
  moved->set_sc(copy);
  w.target = std::move(moved);
}

static void check_one(World& w, uint32_t expectedVersion) {
  const TxReport r = run_transaction(w);
  if (!r.committed) throw std::runtime_error("native target change rejected: " + r.reason);
  assert(r.branch == "normal" && r.puf == 1);
  assert(r.uav_v == expectedVersion && r.committed_v == expectedVersion);
  assert(w.uav->su() == w.target->sc());
  std::string why;
  assert(invariants_hold(w.uav->su(), w.target->sc(), w.target->pi(), &why));
}

int main() {
  VariantConfig policy;
  policy.id = "P";
  World g(Domain::G, "GS_CELL_1", sha256(text("native-partition-G")), policy, "", nullptr);
  World e(Domain::E, "ES_T1", sha256(text("native-partition-E")), policy, "", nullptr);
  const State untouchedE = e.uav->su();
  change_target(g, "GS_CELL_2");
  check_one(g, 1);
  assert(e.uav->su() == untouchedE);
  check_one(e, 1);  // represent A_JOINT same-target E reauth in a G-only handover
  change_target(e, "ES_T2");
  check_one(e, 2);  // natural GE across partition: E target genuinely changes
  assert(g.uav->su().v == 1);  // preserve G/E domain isolation
  change_target(g, "GS_CELL_3");
  check_one(g, 2);
  change_target(e, "ES_T3");
  check_one(e, 3);
  std::cout << "TEST_UAVMA_TARGET_TRANSFER PASS (frozen native protocol)\n";
}
