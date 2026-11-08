// UAV-Mobility-Auth formal core: shared single-domain harness used by tests and E1.
// It wires CA_d, MM_d, Src_d, T_d and the UAV with one optional durable store, and
// drives one authorized transaction from target selection to commit.
#ifndef UAVMA_HARNESS_H
#define UAVMA_HARNESS_H

#include <memory>
#include <string>

#include "uavma/crypto.h"
#include "uavma/experiment_driver.h"
#include "uavma/protocol_core.h"
#include "uavma/root_provider.h"
#include "uavma/state_store.h"

namespace uavma {

struct World {
  Domain d;
  std::string target_id;
  Bytes seed;
  RootProvider root;
  CaCore ca;
  MobilityManager mm;
  std::unique_ptr<StateStore> store;
  std::unique_ptr<UavCore> uav;
  std::unique_ptr<TargetCore> target;
  std::unique_ptr<SourceCore> src;
  VariantConfig v;
  EventLog* log;
  std::string active_sid;

  World(Domain d, std::string target_id, Bytes seed, VariantConfig v, const std::string& db_path,
        EventLog* log);
  // Simulates a crash: all in-memory role objects are destroyed and rebuilt from
  // the durable store only.
  void crash_restart();
};

struct TxOptions {
  bool drop_m1 = false;
  bool drop_m2 = false;
  bool drop_m3 = false;
  bool duplicate_m1 = false;
  bool duplicate_m2 = false;
  bool expire_after_m2 = false;
  int64_t delta_clk_ms = 0;
  int64_t dnet_ms = 0;
  bool same_session_retry = false;  // resend cached M1/M2, no new authorization
  std::string target_override;      // new-target recovery case
};

struct TxReport {
  bool committed = false;
  std::string branch = "none";
  std::string reason;
  int64_t t_select_ms = 0;
  int64_t t_prepare_ready_ms = 0;
  int64_t t_uav_activate_ms = 0;
  int64_t t_target_commit_ms = 0;
  int64_t t_full_ms = 0;
  uint64_t puf = 0, sign = 0, verify = 0, mac = 0, hash = 0, ecdh = 0;
  uint64_t commits = 0;
  uint32_t committed_v = 0, uav_v = 0;
  bool pending_present = false;
  uint32_t pending_v = 0;
  std::string committed_rho, uav_rho, pending_rho;
  size_t body_ul = 0, body_dl = 0, body_inf = 0, body_mm = 0;
  size_t framed_total = 0;
  std::string sid;
};

// Runs one full transaction. Returns a report; never throws for protocol rejections.
TxReport run_transaction(World& w, const TxOptions& o = {});

// Preparation only: MM authorization, Authz_U/Authz_S, Transfer, M0, M1.
struct PreparedTx {
  uint64_t epoch = 0;
  std::string sid;
  M1Msg m1;
  bool ok = false;
  std::string err;
  size_t body_mm = 0, body_inf = 0, body_dl = 0, body_ul = 0;
};

PreparedTx prepare_authorization(World& w, const std::string& tid, int64_t delta_clk_ms = 0);

// M2 -> UAV activation -> M3 -> commit, for a transaction prepared separately.
TxReport finish_transaction(World& w, uint64_t epoch);

// Instruments: returns counter deltas around a callable.
template <typename F>
OpCounters measure_counters(F&& f) {
  OpCounters before = counters();
  f();
  return counters() - before;
}

}  // namespace uavma

#endif
