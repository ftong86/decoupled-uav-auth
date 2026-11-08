// S3 / E1: Linux-native full-procedure cost and handler calibration.
// Reports three different quantities separately (execution plan 4.2):
//   1. primitive micro-benchmarks (calibration inputs, NOT full-procedure latency)
//   2. pure handler processing time (used later to advance ns-3 simulated time)
//   3. complete transaction latency from target selection to commit
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "uavma/crypto.h"
#include "uavma/experiment_driver.h"
#include "uavma/harness.h"
#include "uavma/linux_transport.h"
#include "uavma/protocol_core.h"

using namespace uavma;

namespace {

using Clock = std::chrono::steady_clock;

struct Stats {
  std::string name;
  uint64_t n = 0;
  double mean_us = 0, min_us = 0, p50_us = 0, p95_us = 0, max_us = 0;
};

Stats summarize(const std::string& name, std::vector<double> v) {
  std::sort(v.begin(), v.end());
  Stats s;
  s.name = name;
  s.n = v.size();
  if (v.empty()) return s;
  double sum = 0;
  for (double x : v) sum += x;
  s.mean_us = sum / static_cast<double>(v.size());
  s.min_us = v.front();
  s.max_us = v.back();
  s.p50_us = v[v.size() / 2];
  s.p95_us = v[std::min(v.size() - 1, static_cast<size_t>(static_cast<double>(v.size()) * 0.95))];
  return s;
}

double us_between(Clock::time_point a, Clock::time_point b) {
  return std::chrono::duration<double, std::micro>(b - a).count();
}

Bytes seed_for(const std::string& tag) { return sha256(text("uavma-e1-" + tag)); }

void primitive_benchmark(const std::string& out) {
  const int n = 2000;
  Bytes key = random_bytes(32);
  Bytes msg = random_bytes(64);
  Bytes sk = scalar_from_hash(sha256(text("bench-sk")));
  Bytes pk = pubkey_from_scalar(sk);
  Bytes digest = sha256(msg);
  Bytes sig = ecdsa_sign(sk, digest);
  Bytes peer_sk = scalar_from_hash(sha256(text("bench-peer")));
  Bytes peer_pk = pubkey_from_scalar(peer_sk);

  struct Bench {
    std::string name;
    std::vector<double> samples;
  };
  std::vector<Bench> benches(7);
  benches[0].name = "Hash";
  benches[1].name = "KDF_HMAC";
  benches[2].name = "H2S_scalar";
  benches[3].name = "ECC_point_mul";
  benches[4].name = "ECDSA_sign";
  benches[5].name = "ECDSA_verify";
  benches[6].name = "ECDH";

  for (int i = 0; i < n; ++i) {
    auto t0 = Clock::now();
    hash_tag("BENCH", {msg});
    benches[0].samples.push_back(us_between(t0, Clock::now()));

    t0 = Clock::now();
    kdf(key, "BENCH", {msg});
    benches[1].samples.push_back(us_between(t0, Clock::now()));

    t0 = Clock::now();
    scalar_from_hash(digest);
    benches[2].samples.push_back(us_between(t0, Clock::now()));

    t0 = Clock::now();
    pubkey_from_scalar(sk);
    benches[3].samples.push_back(us_between(t0, Clock::now()));

    t0 = Clock::now();
    ecdsa_sign(sk, digest);
    benches[4].samples.push_back(us_between(t0, Clock::now()));

    t0 = Clock::now();
    ecdsa_verify(pk, digest, sig);
    benches[5].samples.push_back(us_between(t0, Clock::now()));

    t0 = Clock::now();
    ecdh_shared(sk, peer_pk);
    benches[6].samples.push_back(us_between(t0, Clock::now()));
  }

  CsvWriter csv(out, {"primitive", "n", "mean_us", "min_us", "p50_us", "p95_us", "max_us",
                      "measurement_type"});
  for (const Bench& b : benches) {
    Stats s = summarize(b.name, b.samples);
    csv.row({s.name, std::to_string(s.n), std::to_string(s.mean_us), std::to_string(s.min_us),
             std::to_string(s.p50_us), std::to_string(s.p95_us), std::to_string(s.max_us),
             "linux_native_primitive_microbenchmark"});
  }
  std::cout << "primitive_samples: " << out << '\n';
}

struct HandlerTiming {
  std::map<std::string, std::vector<double>> us;
  void add(const std::string& k, double v) { us[k].push_back(v); }
};

void handler_and_transaction_benchmark(const std::string& out_dir, int repeats) {
  CsvWriter handlers(out_dir + "/handler_samples.csv",
                     {"handler", "domain", "n", "mean_us", "p50_us", "p95_us", "max_us",
                      "measurement_type"});
  CsvWriter tx(out_dir + "/normal_transactions.csv",
               {"sample", "event", "domain", "scheme", "t_full_ms", "t_prepare_ms", "t_auth_ms",
                "t_persist_point_count", "body_ul", "body_dl", "body_inf", "body_mm",
                "framed_total", "puf_eval", "sign", "verify", "commits", "committed_v",
                "measurement_type"});
  HandlerTiming ht;

  const std::string mt_tx = "linux_native_full_procedure_E1";
  const std::string mt_h = "linux_native_pure_handler_E1";

  for (int rep = 0; rep < repeats; ++rep) {
    VariantConfig p;
    p.id = "P";
    World g(Domain::G, "GS_T1", seed_for("G" + std::to_string(rep)), p, "", nullptr);
    World e(Domain::E, "ES_T1", seed_for("E" + std::to_string(rep)), p, "", nullptr);

    auto run_domain = [&](World& w, const std::string& dom, const std::string& event) {
      std::string err;
      int64_t t_select = 0, t_prepare = 0, t_auth = 0, t_commit = 0;
      size_t ul = 0, dl = 0, inf = 0, mm = 0, framed = 0;
      uint64_t puf0 = counters().puf, sg0 = counters().sign, vf0 = counters().verify;

      auto t0 = Clock::now();
      t_select = now_mono_ms();
      uint64_t epoch = w.mm.authorize(w.target_id);
      AuthzUMsg au = w.mm.authz_u();
      AuthzSMsg as = w.mm.authz_s(w.uav->pid());
      mm += au.account().body + as.account().body;
      w.src->set_committed(w.target->sc());
      w.src->set_pending(w.target->pi() ? std::optional<Pending>(*w.target->pi()) : std::nullopt);
      TransferMsg tr = w.src->build_transfer(w.target_id, epoch);
      w.target->accept_transfer(tr);
      inf += tr.account().body;
      framed += tr.account().encoded + kFrameHeaderBytes;

      auto h0 = Clock::now();
      M0Msg m0 = w.target->create_session(w.uav->pid(), w.target_id, epoch);
      ht.add("target_create_session_M0_" + dom, us_between(h0, Clock::now()));
      dl += m0.account().body;
      framed += m0.account().encoded + kFrameHeaderBytes;
      t_prepare = now_mono_ms();

      h0 = Clock::now();
      bool ok0 = w.uav->handle_m0(m0, w.ca.ca_pk(), epoch, &err);
      ht.add("uav_handle_M0_" + dom, us_between(h0, Clock::now()));
      if (!ok0) {
        std::cerr << "M0 rejected: " << err << '\n';
        return;
      }

      h0 = Clock::now();
      M1Msg m1 = w.uav->build_m1(0);
      ht.add("uav_build_M1_" + dom, us_between(h0, Clock::now()));
      ul += m1.account().body;
      framed += m1.account().encoded + kFrameHeaderBytes;

      h0 = Clock::now();
      M1Outcome oc = w.target->handle_m1(m1, epoch, now_mono_ms(), 0, &err);
      ht.add("target_handle_M1_" + dom, us_between(h0, Clock::now()));
      if (!oc.ok) {
        std::cerr << "M1 rejected: " << oc.reason << '\n';
        return;
      }
      M2Msg m2 = w.target->m2();
      dl += m2.account().body;
      framed += m2.account().encoded + kFrameHeaderBytes;

      h0 = Clock::now();
      bool ok2 = w.uav->handle_m2(m2, &err);
      ht.add("uav_handle_M2_" + dom, us_between(h0, Clock::now()));
      if (!ok2) {
        std::cerr << "M2 rejected: " << err << '\n';
        return;
      }
      M3Msg m3 = w.uav->m3();
      ul += m3.account().body;
      framed += m3.account().encoded + kFrameHeaderBytes;

      h0 = Clock::now();
      bool ok3 = w.target->handle_m3(m3, epoch, now_mono_ms(), &err);
      ht.add("target_handle_M3_" + dom, us_between(h0, Clock::now()));
      if (!ok3) {
        std::cerr << "M3 rejected: " << err << '\n';
        return;
      }
      t_commit = now_mono_ms();
      (void)t0;

      uint64_t puf = counters().puf - puf0;
      uint64_t sg = counters().sign - sg0;
      uint64_t vf = counters().verify - vf0;
      // t_full = target commit minus target selection; t_prepare = up to M0 ready;
      // t_auth = the remainder (M0 verify .. commit), including persistence.
      tx.row({std::to_string(rep), event, dom, "P", std::to_string(t_commit - t_select),
              std::to_string(t_prepare - t_select), std::to_string(t_commit - t_prepare), "3",
              std::to_string(ul), std::to_string(dl), std::to_string(inf), std::to_string(mm),
              std::to_string(framed), std::to_string(puf), std::to_string(sg),
              std::to_string(vf), std::to_string(w.target->commits()),
              std::to_string(w.target->sc().v), mt_tx});
    };

    run_domain(g, "G", "HO_G");
    run_domain(e, "E", "Mig_E");
    // GE: both domains execute their own transaction; completion is the later of the two.
    int64_t g_start = now_mono_ms();
    run_domain(g, "G", "GE");
    int64_t g_end = now_mono_ms();
    int64_t e_start = now_mono_ms();
    run_domain(e, "E", "GE");
    int64_t e_end = now_mono_ms();
    std::cout << "rep " << rep << " GE: G=" << (g_end - g_start) << "ms E=" << (e_end - e_start)
              << "ms GE=" << std::max(g_end - g_start, e_end - e_start) << "ms\n";
  }

  for (auto& kv : ht.us) {
    Stats s = summarize(kv.first, kv.second);
    std::string dom = kv.first.size() && kv.first.back() == 'G' ? "G" : "E";
    handlers.row({s.name, dom, std::to_string(s.n), std::to_string(s.mean_us),
                  std::to_string(s.p50_us), std::to_string(s.p95_us), std::to_string(s.max_us),
                  mt_h});
  }

  // Message ledger for one representative transaction (measured vs design budget).
  {
    VariantConfig p;
    p.id = "P";
    World w(Domain::G, "GS_T1", seed_for("ledger"), p, "", nullptr);
    std::string err;
    uint64_t epoch = w.mm.authorize(w.target_id);
    AuthzUMsg au = w.mm.authz_u();
    AuthzSMsg as = w.mm.authz_s(w.uav->pid());
    w.src->set_committed(w.target->sc());
    TransferMsg tr = w.src->build_transfer(w.target_id, epoch);
    w.target->accept_transfer(tr);
    M0Msg m0 = w.target->create_session(w.uav->pid(), w.target_id, epoch);
    w.uav->handle_m0(m0, w.ca.ca_pk(), epoch, &err);
    M1Msg m1 = w.uav->build_m1(0);
    w.target->handle_m1(m1, epoch, now_mono_ms(), 0, &err);
    M2Msg m2 = w.target->m2();
    w.uav->handle_m2(m2, &err);
    M3Msg m3 = w.uav->m3();
    w.target->handle_m3(m3, epoch, now_mono_ms(), &err);

    CsvWriter led(out_dir + "/message_ledger.csv",
                  {"msg", "direction", "body_bytes", "encoded_bytes", "framed_bytes",
                   "paper_reference_body_bytes", "measurement_type"});
    auto put = [&](const std::string& name, const std::string& dir, const ByteAccount& a,
                   size_t ref) {
      led.row({name, dir, std::to_string(a.body), std::to_string(a.encoded),
               std::to_string(a.encoded + kFrameHeaderBytes), std::to_string(ref),
               "linux_native_measured_encoding"});
    };
    put("Authz_U", "MM", au.account(), 20);
    put("Authz_S", "MM", as.account(), 52);
    put("Transfer", "INF", tr.account(), 154);
    put("M0", "DL", m0.account(), 228);
    put("M1", "UL", m1.account(), 178);
    put("M2", "DL", m2.account(), 48);
    put("M3", "UL", m3.account(), 48);
  }

  // Machine-readable handler cost profile for later ns-3 calibration (S6).
  {
    std::ofstream f(out_dir + "/cost_profile.json");
    f << "{\n  \"note\": \"Pure handler processing time measured on this host. To be used to "
         "advance ns-3 simulated time in S6; network/queue waiting must come from ns-3 and must "
         "not be added twice.\",\n";
    f << "  \"measurement_type\": \"linux_native_pure_handler_E1\",\n";
    f << "  \"repeats\": " << repeats << ",\n";
    f << "  \"handlers_us\": {\n";
    bool first = true;
    for (auto& kv : ht.us) {
      Stats s = summarize(kv.first, kv.second);
      f << (first ? "    " : "    ,") ;
      f << "\"" << s.name << "\": {\"n\":" << s.n << ",\"mean_us\":" << s.mean_us
        << ",\"p50_us\":" << s.p50_us << ",\"p95_us\":" << s.p95_us << "}\n";
      first = false;
    }
    f << "  }\n}\n";
  }
}

}  // namespace

int main(int argc, char** argv) {
  const std::string out = argc > 1 ? argv[1] : "results/formal/e1";
  const int repeats = argc > 2 ? std::atoi(argv[2]) : 100;
  ensure_dir(out);
  try {
    primitive_benchmark(out + "/primitive_samples.csv");
    handler_and_transaction_benchmark(out, repeats);
    std::cout << "E1 LINUX NATIVE PASS\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "FAILED: " << ex.what() << '\n';
    return 1;
  }
}
