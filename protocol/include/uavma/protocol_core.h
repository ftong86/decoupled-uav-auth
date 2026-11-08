// UAV-Mobility-Auth formal core: protocol core (paper Section V).
// Two independent domains G (communication, GS_S -> GS_T) and E (edge service,
// ES_S -> ES_T). Each domain has its own CA, MM, credentials, pseudonym, state and
// sessions. E-domain messages travel over the G infrastructure; no independent E
// radio link is modelled.
//
// Branch set is exactly the four defined by the paper (Sec.V-D):
//   normal, cached-retry (same SID), M2Recover, M3Recover.
// No additional recovery path (e.g. re-registration) is invented.
#ifndef UAVMA_PROTOCOL_CORE_H
#define UAVMA_PROTOCOL_CORE_H

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "uavma/bytes.h"
#include "uavma/root_provider.h"

namespace uavma {

class StateStore;   // forward: durable persistence (state_store.h)
class EventLog;     // forward: experiment logging (experiment_driver.h)

enum class Domain : uint8_t { G = 0x47, E = 0x45 };  // 'G','E'
inline char domain_char(Domain d) { return static_cast<char>(d); }
inline std::string domain_str(Domain d) { return std::string(1, domain_char(d)); }

// ---------------------------------------------------------------- state (Eq.4)

struct State {
  uint32_t v = 0;
  Bytes cv;   // candidate/state commitment
  Bytes pk;   // compressed P-256 state public key
  Bytes rho;  // state digest
};
inline bool operator==(const State& a, const State& b) {
  return a.v == b.v && a.cv == b.cv && a.pk == b.pk && a.rho == b.rho;
}
inline bool operator!=(const State& a, const State& b) { return !(a == b); }

Bytes state_encode(const State& s);
State state_decode(const Bytes& b, size_t& off);
size_t state_body_size(const State& s);

// Pi = <base, next, delta, SID, epoch> (Sec.V-A)
struct Pending {
  State base;
  State next;
  Bytes delta;
  Bytes sid;
  uint64_t epoch = 0;
};

enum class SessState : uint8_t { Prepared = 0, AwaitM3 = 1, Committed = 2, Expired = 3 };
inline const char* sess_state_str(SessState s) {
  switch (s) {
    case SessState::Prepared: return "Prepared";
    case SessState::AwaitM3: return "AwaitM3";
    case SessState::Committed: return "Committed";
    case SessState::Expired: return "Expired";
  }
  return "?";
}

struct Session {
  std::string sid;
  SessState st = SessState::Prepared;
  uint64_t epoch = 0;
  Bytes tctx;
  Bytes xt_sk;   // target-side ephemeral private key x_T
  Bytes xt;      // peer ephemeral public key X_T (UAV side) / X_T (target side)
  Bytes xu_sk;   // UAV-side ephemeral private key x_U
  Bytes th1, th2;
  Bytes kcf, kcm, ks;
  Bytes delta;
  Bytes tau_t, tau_c;
  State base, next;   // verification base actually used, and installed candidate
  int64_t expiry_ms = 0;
  bool m2_sent = false;
  bool m3_sent = false;
  Bytes cached_m1;    // serialized M1 bytes; duplicate detection without re-signing
  std::string target_id;
};

// Theorem 4 / Eqs.(16)-(18): bounded divergence and admissible verification base.
bool invariants_hold(const State& su, const State& sc, const Pending* pi, std::string* why);

// Registration (long-term configuration, excluded from per-transaction timing).
Bytes derive_pid(Domain d, const Bytes& dr);
State registration_state(Domain d, const Bytes& seed, const Bytes& dr, const Bytes& pid);

// Transcript helper exposed for cross-checks in tests.
Bytes compute_tctx(Domain d, const Bytes& sid, const Bytes& pid, const std::string& target,
                   uint64_t epoch, const Bytes& xt);

// ---------------------------------------------------------------- messages

enum class MsgKind : uint8_t {
  AuthzU = 1,
  AuthzS = 2,
  Transfer = 3,
  M0 = 4,
  M1 = 5,
  M2 = 6,
  M3 = 7,
  CommitNotify = 8
};
inline const char* msg_kind_str(MsgKind k) {
  switch (k) {
    case MsgKind::AuthzU: return "AuthzU";
    case MsgKind::AuthzS: return "AuthzS";
    case MsgKind::Transfer: return "Transfer";
    case MsgKind::M0: return "M0";
    case MsgKind::M1: return "M1";
    case MsgKind::M2: return "M2";
    case MsgKind::M3: return "M3";
    case MsgKind::CommitNotify: return "CommitNotify";
  }
  return "?";
}

// Byte accounting: body = logical field bytes (paper fixed-field budget analogue,
// measured not assumed); encoded = canonical Enc output (with 4-byte prefixes).
struct ByteAccount {
  size_t body = 0;
  size_t encoded = 0;
};

struct AuthzUMsg {  // MM_d -> U : (ID_Td, e_d)
  std::string target;
  uint64_t epoch = 0;
  Bytes to_bytes() const;
  static AuthzUMsg from_bytes(const Bytes& b, size_t& off);
  ByteAccount account() const;
};

struct AuthzSMsg {  // MM_d -> Src_d : (PID_d, ID_Td, e_d)
  Bytes pid;
  std::string target;
  uint64_t epoch = 0;
  Bytes to_bytes() const;
  static AuthzSMsg from_bytes(const Bytes& b, size_t& off);
  ByteAccount account() const;
};

struct TransferMsg {  // Src_d -> T_d : {d, PID_d, ID_Td, e_d, S^C_d, Pi_d}
  Domain d = Domain::G;
  Bytes pid;
  std::string target;
  uint64_t epoch = 0;
  State sc;
  bool has_pi = false;
  Pending pi;
  Bytes to_bytes() const;
  static TransferMsg from_bytes(const Bytes& b, size_t& off);
  ByteAccount account() const;  // 154 B reference only applies when Pi is empty
};

struct M0Msg {  // T_d -> U : {d, SID_d, X_T,d, Cert_Td, PreAuth_d}
  Domain d = Domain::G;
  Bytes sid;
  Bytes xt;
  std::string cert_id;
  Bytes cert_pk;
  Bytes cert_sig;
  std::string target;
  uint64_t epoch = 0;
  Bytes preauth;
  bool has_ts = false;   // A-Time only: authenticated timestamp, never mixed into P
  Bytes signed_ts;
  Bytes to_bytes() const;
  static M0Msg from_bytes(const Bytes& b, size_t& off);
  ByteAccount account() const;
};

struct M1Msg {  // U -> T_d : {SID_d, rho^B_d, X_U,d, PK^N_d, sigma_U,d}
  Bytes sid;
  Bytes rho_base;
  Bytes xu;
  Bytes pk_next;
  Bytes sig;
  bool has_ts = false;
  Bytes signed_ts;
  Bytes to_bytes() const;
  static M1Msg from_bytes(const Bytes& b, size_t& off);
  ByteAccount account() const;
};

struct M2Msg {  // T_d -> U : {SID_d, tau_T,d}
  Bytes sid;
  Bytes tau;
  Bytes to_bytes() const;
  static M2Msg from_bytes(const Bytes& b, size_t& off);
  ByteAccount account() const;
};

struct M3Msg {  // U -> T_d : {SID_d, tau_C,d}
  Bytes sid;
  Bytes tau;
  Bytes to_bytes() const;
  static M3Msg from_bytes(const Bytes& b, size_t& off);
  ByteAccount account() const;
};

// ---------------------------------------------------------------- variants

struct VariantConfig {
  std::string id = "P";
  bool a_time = false;        // A-Time: authenticated timestamp + window on top of P
  bool a_retry = false;       // A-Retry: no M2Recover/M3Recover under NEW authorization
  bool joint_trigger = false; // A-Joint: re-authenticate the unchanged domain too
  int64_t window_ms = 500;    // W reference window (A-Time only)
  int64_t session_ttl_ms = 10000;
};

enum class Branch { None = 0, Normal, CachedRetry, M2Recover, M3Recover, Reject };
inline const char* branch_str(Branch b) {
  switch (b) {
    case Branch::None: return "none";
    case Branch::Normal: return "normal";
    case Branch::CachedRetry: return "cached-retry";
    case Branch::M2Recover: return "M2Recover";
    case Branch::M3Recover: return "M3Recover";
    case Branch::Reject: return "reject";
  }
  return "?";
}

// ---------------------------------------------------------------- CA / MM

class CaCore {
 public:
  CaCore(Domain d, Bytes seed);
  Domain domain() const { return d_; }
  Bytes ca_pk() const { return ca_pk_; }
  Bytes target_lt_sk(const std::string& id) const;
  Bytes target_lt_pk(const std::string& id) const;
  Bytes issue_cert(const std::string& id, const Bytes& lt_pk) const;  // Eq.(2)
  bool verify_cert(const std::string& id, const Bytes& lt_pk, const Bytes& sig) const;

 private:
  Domain d_;
  Bytes seed_;
  Bytes ca_sk_, ca_pk_;
};

class MobilityManager {
 public:
  MobilityManager(Domain d, Bytes seed);
  Domain domain() const { return d_; }
  uint64_t epoch() const { return epoch_; }
  // New authorization: strictly increasing epoch; retransmissions keep the old one.
  uint64_t authorize(const std::string& target);
  AuthzUMsg authz_u() const;
  AuthzSMsg authz_s(const Bytes& pid) const;
  const std::string& target() const { return target_; }

 private:
  Domain d_;
  Bytes seed_;
  uint64_t epoch_ = 0;
  std::string target_;
};

// ---------------------------------------------------------------- UAV role

class UavCore {
 public:
  UavCore(Domain d, Bytes seed, VariantConfig v, RootProvider& root, StateStore* store = nullptr,
          EventLog* log = nullptr);

  Domain domain() const { return d_; }
  const Bytes& pid() const { return pid_; }
  const State& su() const { return su_; }
  void set_su(const State& s) { su_ = s; }
  uint64_t puf_calls() const { return root_.puf_calls(); }

  // Registration (S_d,0) is long-term configuration, excluded from per-transaction timing.
  // Receives M0: verifies Cert_Td under CA_d, rebuilds TCTX, verifies PreAuth (Eq.6).
  bool handle_m0(const M0Msg& m, const Bytes& ca_pk, uint64_t authorized_epoch, std::string* err);
  // Builds M1 (Eqs.7-8). A NEW authorization triggers exactly one PUFEval.
  M1Msg build_m1(int64_t delta_clk_ms = 0);
  // Receives M2: verifies tau_T under K^cf (Eq.12), persists S^U <- S^N, builds M3.
  bool handle_m2(const M2Msg& m, std::string* err);
  const M3Msg& m3() const { return m3_; }
  const Session& session() const { return sess_; }
  // Crash-restart recovery of the UAV role from durable storage.
  bool restore_from_store();
  bool active() const { return active_; }
  Branch branch() const { return branch_; }
  void set_variant(VariantConfig v) { v_ = v; }

 private:
  Bytes state_key(const State& s) const;  // H2S(KDF(kappa_d; AUTHKEY, d, PID, v, CV))
  Bytes state_rho(const State& s) const;  // Hash(STATE; d, PID, v, CV, PK)
  State make_candidate(const State& base, const Bytes& tctx, const Bytes& xu) const;

  Domain d_;
  Bytes seed_;
  Bytes pid_;
  Bytes dr_;
  VariantConfig v_;
  RootProvider& root_;
  StateStore* store_;
  EventLog* log_;
  State su_;
  Session sess_;
  bool active_ = false;
  Branch branch_ = Branch::None;
  M3Msg m3_;
};

// ---------------------------------------------------------------- target role

struct M1Outcome {
  bool ok = false;
  Branch branch = Branch::Reject;
  std::string reason;
  bool m2_ready = false;
};

class TargetCore {
 public:
  // dr = domain root kappa_d enrolled at registration (infrastructure side).
  TargetCore(Domain d, std::string id, Bytes lt_sk, Bytes dr, Bytes seed, VariantConfig v,
             StateStore* store = nullptr, EventLog* log = nullptr);

  Domain domain() const { return d_; }
  const std::string& id() const { return id_; }
  const State& sc() const { return sc_; }
  const Pending* pi() const { return pi_ ? &*pi_ : nullptr; }
  const std::map<std::string, Session>& sessions() const { return sessions_; }
  uint64_t commits() const { return commits_; }
  Branch last_branch() const { return last_branch_; }
  void set_sc(const State& s) { sc_ = s; }
  void set_pi(std::optional<Pending> p) { pi_ = std::move(p); }
  void set_variant(VariantConfig v) { v_ = v; }
  void set_cert_sig(Bytes s) { cert_sig_ = std::move(s); }
  const Bytes& pid() const { return pid_; }

  // Source -> target: install S^C and (optionally) the pending migration Pi.
  void accept_transfer(const TransferMsg& t);
  // New session / M0 (Eqs.5-6). Requires an authorized epoch from MM_d.
  M0Msg create_session(const Bytes& pid, const std::string& target, uint64_t epoch,
                       bool with_ts = false);
  // Handles M1: guards, branch selection, key derivation, and Pi installation.
  M1Outcome handle_m1(const M1Msg& m, uint64_t current_epoch, int64_t now_ms, int64_t dnet_ms,
                      std::string* err);
  const M2Msg& m2() const { return m2_; }
  // Handles M3: verifies tau_C under K^cm (Eq.13) and commits atomically.
  bool handle_m3(const M3Msg& m, uint64_t current_epoch, int64_t now_ms, std::string* err);
  // AwaitM3 expiry: erase session secrets, KEEP Pi for later recovery.
  bool expire(const std::string& sid, std::string* err);
  bool has_session(const std::string& sid) const { return sessions_.count(sid) > 0; }
  // Crash-restart recovery: committed state, pending migration and one session.
  bool restore_from_store(const std::string& sid);

 private:
  Bytes state_key(const State& s) const;
  Bytes state_rho(const State& s) const;
  State make_candidate(const State& base, const Bytes& tctx, const Bytes& xu) const;

  Domain d_;
  std::string id_;
  Bytes lt_sk_, lt_pk_, dr_, seed_, pid_, cert_sig_;
  VariantConfig v_;
  StateStore* store_;
  EventLog* log_;
  State sc_;
  std::optional<Pending> pi_;
  std::map<std::string, Session> sessions_;
  std::string active_sid_;
  M2Msg m2_;
  uint64_t commits_ = 0;
  Branch last_branch_ = Branch::None;
};

// ---------------------------------------------------------------- source role

class SourceCore {
 public:
  SourceCore(Domain d, Bytes pid);
  void set_committed(const State& s) { sc_ = s; }
  void set_pending(std::optional<Pending> p) { pi_ = std::move(p); }
  TransferMsg build_transfer(const std::string& target, uint64_t epoch) const;

 private:
  Domain d_;
  Bytes pid_;
  State sc_;
  std::optional<Pending> pi_;
};

}  // namespace uavma

#endif
