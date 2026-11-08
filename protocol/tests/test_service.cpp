// S2 acceptance test: stateful edge service, authorization gate and outage accounting (E4).
// The service logic is shared by every compared scheme; only the gate differs.
#include <iostream>
#include <string>
#include <vector>

#include "uavma/experiment_driver.h"
#include "uavma/service_core.h"

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

int main(int argc, char** argv) {
  const std::string out = argc > 1 ? argv[1] : ".";
  ensure_dir(out);
  CsvWriter csv(out + "/service_requests.csv",
                {"node", "request_id", "t_ms", "authorized", "correct", "duplicate", "reason",
                 "counter_after", "measurement_type"});
  CsvWriter mig(out + "/service_migration.csv",
                {"from", "to", "app_state_bytes", "epoch", "t_ms", "measurement_type"});
  const std::string mt = "linux_native_s2_service";

  ServiceCore src("ES_S1");
  ServiceCore tgt("ES_T1");

  // The source is authorized and serves three requests.
  src.set_authorized(true, 1);
  src.install_state(ServiceState{});
  int64_t t = now_mono_ms();
  std::string resp;
  std::string reason;
  int64_t last_source_ok = 0;
  for (const std::string& rid : {"r1", "r2", "r3"}) {
    bool ok = src.handle_request(rid, t, resp, &reason);
    CHECK(ok, "source serves " + rid);
    if (ok) last_source_ok = t;
    t += 10;
  }
  CHECK(src.state().counter == 3, "source cumulative counter advanced by 3");

  // Duplicate request must be answered correctly but must not be processed twice.
  bool dup = src.handle_request("r2", t, resp, &reason);
  CHECK(dup && src.state().counter == 3, "duplicate request is replayed, not counted twice");

  // The target is NOT authorized before the E-domain commit: it must not answer.
  bool early = tgt.handle_request("r4", t + 5, resp, &reason);
  CHECK(!early, "target refuses to answer before the E domain commits");
  CHECK(reason == "not_authorized_e_domain_not_committed",
        "unauthorized refusal is explicit: " + reason);
  CHECK(tgt.state().counter == 0, "unauthorized target does not advance its state");

  // Migration: application state is transferred separately from the protocol Transfer.
  ServiceState moved = src.state();
  AppMigration am;
  am.from = "ES_S1";
  am.to = "ES_T1";
  am.bytes = moved.bytes();
  am.epoch = 1;
  am.t_ms = t + 20;
  tgt.install_state(moved);
  CHECK(tgt.state().counter == 3, "target inherits the cumulative counter");
  mig.row({am.from, am.to, std::to_string(am.bytes), std::to_string(am.epoch),
           std::to_string(am.t_ms), mt});
  CHECK(am.bytes > 0, "application state bytes B_app are measured separately");

  // Still unauthorized: state is present but the gate is closed.
  bool gated = tgt.handle_request("r5", t + 25, resp, &reason);
  CHECK(!gated && tgt.state().counter == 3,
        "state alone is not sufficient; the E-domain commit gate is required");

  // E-domain commit opens the gate; the first correct authorized response ends the outage.
  tgt.set_authorized(true, 2);
  int64_t first_target_ok = t + 30;
  bool ok5 = tgt.handle_request("r5", first_target_ok, resp, &reason);
  CHECK(ok5, "target answers correctly once the E domain has committed");
  CHECK(tgt.state().counter == 4, "target continues the cumulative business state");

  OutageInterval oi;
  oi.start_ms = last_source_ok;
  oi.end_ms = first_target_ok;
  oi.duration_ms = first_target_ok - last_source_ok;
  oi.cause = "e_domain_commit_and_state_transfer";
  CHECK(oi.duration_ms > 0, "outage interval is measured from the last correct source response");

  // Replay detection: the migrated processed set must recognize old request ids.
  bool replay = tgt.handle_request("r1", first_target_ok + 5, resp, &reason);
  CHECK(replay && tgt.state().counter == 4,
        "replayed request after migration is detected and not processed again");

  {
    std::ofstream f(out + "/outage_intervals.csv");
    f << "start_ms,end_ms,duration_ms,cause,measurement_type\n";
    f << oi.start_ms << ',' << oi.end_ms << ',' << oi.duration_ms << ',' << oi.cause << ',' << mt
      << '\n';
  }

  for (auto& core : {&src, &tgt}) {
    for (const ServiceEvent& ev : core->events())
      csv.row({ev.node, ev.request_id, std::to_string(ev.t_ms), std::to_string(ev.authorized),
               std::to_string(ev.correct), std::to_string(ev.duplicate), ev.reason,
               std::to_string(ev.counter_after), mt});
  }

  std::cout << (g_failures == 0 ? "TEST_SERVICE PASS\n" : "TEST_SERVICE FAIL\n");
  return g_failures == 0 ? 0 : 1;
}
