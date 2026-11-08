// UAV-Mobility-Auth formal core: multi-process node backend (S2/S3).
// Independent UAV / Src / Target / MM processes exchange the real serialized protocol
// messages over TCP loopback. The driver only relays frames (it plays the role the
// ns-3 backend will take over in S6) and can drop a frame to inject a loss.
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "uavma/crypto.h"
#include "uavma/experiment_driver.h"
#include "uavma/linux_transport.h"
#include "uavma/protocol_core.h"
#include "uavma/root_provider.h"
#include "uavma/state_store.h"

using namespace uavma;

namespace {

std::vector<std::string> split(const std::string& s) {
  std::istringstream is(s);
  std::vector<std::string> out;
  std::string t;
  while (is >> t) out.push_back(t);
  return out;
}

// ------------------------------------------------------------- driver side

class NodeClient {
 public:
  NodeClient(std::unique_ptr<Socket> s, std::string role) : sock_(std::move(s)), role_(std::move(role)) {}
  // Sends a text command, returns the reply text.
  std::string cmd(const std::string& text, bool* ok = nullptr) {
    if (!sock_->send_frame(MsgKind::CommitNotify, Bytes(text.begin(), text.end()))) {
      if (ok) *ok = false;
      return "TRANSPORT_FAILURE";
    }
    MsgKind kind;
    Bytes payload;
    if (!sock_->recv_frame(kind, payload)) {
      if (ok) *ok = false;
      return "TRANSPORT_FAILURE";
    }
    std::string reply(payload.begin(), payload.end());
    if (ok) *ok = reply.rfind("OK ", 0) == 0;
    return reply;
  }
  const std::string& role() const { return role_; }

 private:
  std::unique_ptr<Socket> sock_;
  std::string role_;
};

// ------------------------------------------------------------- node side

struct NodeCtx {
  Domain d = Domain::G;
  std::string target_id;
  Bytes seed;
  std::unique_ptr<RootProvider> root;
  std::unique_ptr<CaCore> ca;
  std::unique_ptr<MobilityManager> mm;
  std::unique_ptr<StateStore> store;
  std::unique_ptr<UavCore> uav;
  std::unique_ptr<TargetCore> target;
  std::unique_ptr<SourceCore> src;
  VariantConfig v;
};

Bytes domain_root_of(NodeCtx& c) { return c.root->domain_root(domain_char(c.d)); }

std::string handle_node_command(NodeCtx& c, const std::string& role, const std::string& cmdline) {
  std::vector<std::string> a = split(cmdline);
  if (a.empty()) return "ERR empty";
  const std::string& op = a[0];
  std::string err;

  if (role == "mm") {
    if (op == "AUTHORIZE" && a.size() >= 2) return "OK " + std::to_string(c.mm->authorize(a[1]));
    if (op == "EPOCH") return "OK " + std::to_string(c.mm->epoch());
    return "ERR unknown-mm-op";
  }
  if (role == "src") {
    if (op == "SET_STATE" && a.size() >= 2) {
      size_t o = 0;
      c.src->set_committed(state_decode(unhex(a[1]), o));
      return "OK";
    }
    if (op == "SET_PENDING_HEX" && a.size() >= 2) {
      if (a[1] == "none") {
        c.src->set_pending(std::nullopt);
        return "OK";
      }
      Bytes b = unhex(a[1]);
      size_t o = 0;
      Pending p;
      p.base = state_decode(b, o);
      p.next = state_decode(b, o);
      p.delta = Bytes();
      // remaining length-prefixed fields
      auto rd = [&]() -> Bytes {
        uint32_t n = (static_cast<uint32_t>(b[o]) << 24) | (static_cast<uint32_t>(b[o + 1]) << 16) |
                     (static_cast<uint32_t>(b[o + 2]) << 8) | static_cast<uint32_t>(b[o + 3]);
        o += 4;
        Bytes r(b.begin() + o, b.begin() + o + n);
        o += n;
        return r;
      };
      p.delta = rd();
      p.sid = rd();
      Bytes eb = rd();
      p.epoch = 0;
      for (uint8_t x : eb) p.epoch = (p.epoch << 8) | x;
      c.src->set_pending(p);
      return "OK";
    }
    if (op == "TRANSFER" && a.size() >= 3) {
      TransferMsg t = c.src->build_transfer(a[1], std::stoull(a[2]));
      return "OK " + hex(t.to_bytes()) + " " + std::to_string(t.account().body);
    }
    return "ERR unknown-src-op";
  }
  if (role == "tgt") {
    if (op == "TRANSFER" && a.size() >= 2) {
      Bytes b = unhex(a[1]);
      size_t o = 0;
      TransferMsg t = TransferMsg::from_bytes(b, o);
      c.target->accept_transfer(t);
      return "OK";
    }
    if (op == "SESSION" && a.size() >= 4) {
      Bytes pid = unhex(a[1]);
      M0Msg m0 = c.target->create_session(pid, a[2], std::stoull(a[3]));
      return "OK " + hex(m0.to_bytes()) + " " + hex(m0.sid);
    }
    if (op == "M1" && a.size() >= 5) {
      Bytes b = unhex(a[1]);
      size_t o = 0;
      M1Msg m1 = M1Msg::from_bytes(b, o);
      M1Outcome oc = c.target->handle_m1(m1, std::stoull(a[2]), std::stoll(a[3]), std::stoll(a[4]), &err);
      if (!oc.ok) return "ERR " + oc.reason;
      return "OK " + std::string(branch_str(oc.branch)) + " " + hex(c.target->m2().to_bytes());
    }
    if (op == "M3" && a.size() >= 3) {
      Bytes b = unhex(a[1]);
      size_t o = 0;
      M3Msg m3 = M3Msg::from_bytes(b, o);
      if (!c.target->handle_m3(m3, std::stoull(a[2]), now_mono_ms(), &err))
        return "ERR " + (err.empty() ? "m3-rejected" : err);
      return "OK";
    }
    if (op == "STATE") {
      std::ostringstream os;
      os << "OK v=" << c.target->sc().v << " rho=" << hex(c.target->sc().rho)
         << " pending=" << (c.target->pi() ? "1" : "0") << " commits=" << c.target->commits();
      return os.str();
    }
    if (op == "STATE_HEX") {
      return "OK " + hex(state_encode(c.target->sc())) + " " + std::to_string(c.target->sc().v);
    }
    if (op == "PENDING_HEX") {
      if (!c.target->pi()) return "OK none";
      const Pending& p = *c.target->pi();
      Bytes b = enc({state_encode(p.base), state_encode(p.next), p.delta, p.sid,
                     be32(static_cast<uint32_t>(p.epoch))});
      return "OK " + hex(b);
    }
    return "ERR unknown-tgt-op";
  }
  if (role == "uav") {
    if (op == "M0" && a.size() >= 3) {
      Bytes b = unhex(a[1]);
      size_t o = 0;
      M0Msg m0 = M0Msg::from_bytes(b, o);
      if (!c.uav->handle_m0(m0, c.ca->ca_pk(), std::stoull(a[2]), &err))
        return "ERR " + (err.empty() ? "m0-rejected" : err);
      return "OK " + hex(c.uav->session().sid.empty() ? Bytes() : unhex(c.uav->session().sid));
    }
    if (op == "M1" && a.size() >= 2) {
      M1Msg m1 = c.uav->build_m1(std::stoll(a[1]));
      return "OK " + hex(m1.to_bytes());
    }
    if (op == "M2" && a.size() >= 2) {
      Bytes b = unhex(a[1]);
      size_t o = 0;
      M2Msg m2 = M2Msg::from_bytes(b, o);
      if (!c.uav->handle_m2(m2, &err)) return "ERR " + (err.empty() ? "m2-rejected" : err);
      return "OK";
    }
    if (op == "M3") {
      M3Msg m3 = c.uav->m3();
      return "OK " + hex(m3.to_bytes());
    }
    if (op == "STATE") {
      std::ostringstream os;
      os << "OK v=" << c.uav->su().v << " rho=" << hex(c.uav->su().rho);
      return os.str();
    }
    return "ERR unknown-uav-op";
  }
  return "ERR unknown-role";
}

int node_main(const std::string& role, Domain d, const std::string& target_id, const Bytes& seed,
              const std::string& db, uint16_t port) {
  NodeCtx c;
  c.d = d;
  c.target_id = target_id;
  c.seed = seed;
  c.v.id = "P";
  c.root = std::make_unique<RootProvider>(seed);
  c.ca = std::make_unique<CaCore>(d, seed);
  c.mm = std::make_unique<MobilityManager>(d, seed);
  if (!db.empty()) c.store = std::make_unique<StateStore>(db);
  Bytes dr = domain_root_of(c);
  if (role == "uav")
    c.uav = std::make_unique<UavCore>(d, seed, c.v, *c.root, c.store.get(), nullptr);
  if (role == "tgt") {
    Bytes lt_sk = c.ca->target_lt_sk(target_id);
    c.target = std::make_unique<TargetCore>(d, target_id, lt_sk, dr, seed, c.v, c.store.get(),
                                            nullptr);
    c.target->set_cert_sig(c.ca->issue_cert(target_id, c.ca->target_lt_pk(target_id)));
  }
  if (role == "src") c.src = std::make_unique<SourceCore>(d, derive_pid(d, dr));

  Socket s;
  if (!s.connect_to(port)) {
    std::cerr << "node " << role << ": cannot reach driver\n";
    return 2;
  }
  MsgKind kind;
  Bytes payload;
  while (s.recv_frame(kind, payload)) {
    std::string cmd(payload.begin(), payload.end());
    if (cmd == "EXIT") break;
    std::string reply = handle_node_command(c, role, cmd);
    Bytes out(reply.begin(), reply.end());
    if (!s.send_frame(MsgKind::CommitNotify, out)) break;
  }
  return 0;
}

struct Child {
  pid_t pid = -1;
  std::unique_ptr<NodeClient> client;
};

}  // namespace

// Orchestrates one domain transaction across independent processes.
static int run_nodes(const std::string& out_dir, uint16_t port) {
  ensure_dir(out_dir);
  Bytes seed = sha256(text("uavma-s2-nodes"));
  Socket listener;
  if (!listener.listen_on(port)) {
    std::cerr << "cannot listen on port " << port << '\n';
    return 1;
  }

  struct Spec {
    std::string role;
    Domain d;
    std::string target;
    std::string db;
  };
  std::vector<Spec> specs = {
      {"mm", Domain::G, "GS_T1", ""},  {"src", Domain::G, "GS_T1", ""},
      {"tgt", Domain::G, "GS_T1", out_dir + "/node_G_tgt.db"},
      {"uav", Domain::G, "GS_T1", out_dir + "/node_G_uav.db"},
      {"mm", Domain::E, "ES_T1", ""},  {"src", Domain::E, "ES_T1", ""},
      {"tgt", Domain::E, "ES_T1", out_dir + "/node_E_tgt.db"},
      {"uav", Domain::E, "ES_T1", out_dir + "/node_E_uav.db"},
  };
  for (const Spec& s : specs) {
    if (!s.db.empty()) {
      std::remove(s.db.c_str());
      std::remove((s.db + "-wal").c_str());
      std::remove((s.db + "-shm").c_str());
    }
  }

  std::vector<Child> children;
  for (const Spec& sp : specs) {
    pid_t pid = fork();
    if (pid == 0) {
      listener.detach();  // never shutdown(): the description is shared with the driver
      std::string db = sp.db;
      _exit(node_main(sp.role, sp.d, sp.target, seed, db, port));
    }
    auto conn = listener.accept_one(10000);
    if (!conn) {
      std::cerr << "accept failed for role " << sp.role << '\n';
      return 1;
    }
    Child c;
    c.pid = pid;
    c.client = std::make_unique<NodeClient>(std::move(conn), sp.role + std::string(1, domain_char(sp.d)));
    children.push_back(std::move(c));
  }

  auto cli = [&](const std::string& name) -> NodeClient* {
    for (auto& c : children)
      if (c.client->role() == name) return c.client.get();
    return nullptr;
  };

  CsvWriter csv(out_dir + "/node_transactions.csv",
                {"domain", "case", "branch", "committed", "committed_v", "uav_v", "detail",
                 "measurement_type"});
  int failures = 0;
  const std::string mt = "linux_native_multiprocess_s2";

  for (Domain d : {Domain::G, Domain::E}) {
    const std::string ds = domain_str(d);
    NodeClient* mm = cli("mm" + ds);
    NodeClient* src = cli("src" + ds);
    NodeClient* tgt = cli("tgt" + ds);
    NodeClient* uav = cli("uav" + ds);

    // Normal transaction over real sockets.
    bool ok = false;
    std::string tid = (d == Domain::G) ? "GS_T1" : "ES_T1";
    std::string auth = mm->cmd("AUTHORIZE " + tid, &ok);
    if (!ok) {
      std::cerr << "FAIL authorize " << ds << ": " << auth << '\n';
      ++failures;
      continue;
    }
    uint64_t epoch = std::stoull(split(auth)[1]);
    // The source mirrors the state currently held by the target (infrastructure handover).
    std::string sh = tgt->cmd("STATE_HEX", &ok);
    src->cmd("SET_STATE " + split(sh)[1], &ok);
    std::string ph = tgt->cmd("PENDING_HEX", &ok);
    src->cmd("SET_PENDING_HEX " + split(ph)[1], &ok);
    std::string tr = src->cmd("TRANSFER " + tid + " " + std::to_string(epoch), &ok);
    if (!ok) {
      std::cerr << "FAIL transfer " << ds << ": " << tr << '\n';
      ++failures;
      continue;
    }
    tgt->cmd("TRANSFER " + split(tr)[1], &ok);
    Bytes pid = derive_pid(d, RootProvider(seed).domain_root(domain_char(d)));
    std::string sess = tgt->cmd("SESSION " + hex(pid) + " " +
                                (d == Domain::G ? "GS_T1" : "ES_T1") + " " +
                                std::to_string(epoch), &ok);
    if (!ok) {
      std::cerr << "FAIL session " << ds << ": " << sess << '\n';
      ++failures;
      continue;
    }
    uav->cmd("M0 " + split(sess)[1] + " " + std::to_string(epoch), &ok);
    std::string m1 = uav->cmd("M1 0", &ok);
    std::string m1r = tgt->cmd("M1 " + split(m1)[1] + " " + std::to_string(epoch) + " " +
                               std::to_string(now_mono_ms()) + " 0", &ok);
    if (!ok) {
      std::cerr << "FAIL m1 " << ds << ": " << m1r << '\n';
      ++failures;
      continue;
    }
    std::string branch = split(m1r)[1];
    uav->cmd("M2 " + split(m1r)[2], &ok);
    std::string m3 = uav->cmd("M3", &ok);
    std::string c3 = tgt->cmd("M3 " + split(m3)[1] + " " + std::to_string(epoch), &ok);
    std::string st = tgt->cmd("STATE", &ok);
    std::string ust = uav->cmd("STATE", &ok);
    bool committed = split(st)[1] == "v=1" && split(ust)[1] == "v=1";
    if (!ok || !committed) {
      std::cerr << "FAIL commit " << ds << ": " << c3 << " | " << st << " | " << ust << '\n';
      ++failures;
    } else {
      std::cout << "ok: " << ds
                << " domain completed over TCP between independent processes (branch=" << branch
                << ")\n";
    }
    csv.row({ds, "normal", branch, committed ? "1" : "0", split(st)[1], split(ust)[1], c3, mt});
  }

  for (auto& c : children) {
    if (c.client) c.client->cmd("EXIT");
    int status = 0;
    waitpid(c.pid, &status, 0);
  }
  listener.close();
  std::cout << (failures == 0 ? "NODES PASS\n" : "NODES FAIL\n");
  return failures == 0 ? 0 : 1;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage: uavma_formal nodes <out_dir> <port>\n";
    return 64;
  }
  const std::string cmd = argv[1];
  try {
    if (cmd == "nodes") {
      std::string out = argc > 2 ? argv[2] : "results/formal/nodes";
      uint16_t port = static_cast<uint16_t>(argc > 3 ? std::atoi(argv[3]) : 47311);
      return run_nodes(out, port);
    }
    std::cerr << "unknown command: " << cmd << '\n';
    return 64;
  } catch (const std::exception& ex) {
    std::cerr << "FAILED: " << ex.what() << '\n';
    return 1;
  }
}
