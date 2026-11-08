// UAV-Mobility-Auth formal core: protocol core implementation (paper Section V).
#include "uavma/protocol_core.h"

#include <stdexcept>
#include <utility>

#include "uavma/crypto.h"
#include "uavma/experiment_driver.h"
#include "uavma/state_store.h"

namespace uavma {
namespace {

void fail(std::string* err, const std::string& msg) {
  if (err) *err = msg;
}
bool fail_false(std::string* err, const std::string& msg) {
  fail(err, msg);
  return false;
}

// Length-prefixed reader used by every from_bytes().
struct Reader {
  const Bytes& b;
  size_t off;
  Reader(const Bytes& buf, size_t o) : b(buf), off(o) {}
  Bytes next() {
    if (off + 4 > b.size()) throw std::runtime_error("decode: truncated length prefix");
    uint32_t n = (static_cast<uint32_t>(b[off]) << 24) | (static_cast<uint32_t>(b[off + 1]) << 16) |
                 (static_cast<uint32_t>(b[off + 2]) << 8) | static_cast<uint32_t>(b[off + 3]);
    off += 4;
    if (off + n > b.size()) throw std::runtime_error("decode: truncated field");
    Bytes r(b.begin() + off, b.begin() + off + n);
    off += n;
    return r;
  }
  uint8_t u8() {
    Bytes x = next();
    if (x.size() != 1) throw std::runtime_error("decode: bad u8");
    return x[0];
  }
  uint32_t u32() {
    Bytes x = next();
    if (x.size() != 4) throw std::runtime_error("decode: bad u32");
    return (static_cast<uint32_t>(x[0]) << 24) | (static_cast<uint32_t>(x[1]) << 16) |
           (static_cast<uint32_t>(x[2]) << 8) | static_cast<uint32_t>(x[3]);
  }
};

Bytes pending_encode(const Pending& p) {
  return enc({state_encode(p.base), state_encode(p.next), p.delta, p.sid,
              be32(static_cast<uint32_t>(p.epoch))});
}

Pending pending_decode(const Bytes& b) {
  size_t off = 0;
  Reader r(b, off);
  Bytes base_b = r.next();
  Bytes next_b = r.next();
  Pending p;
  size_t o2 = 0;
  p.base = state_decode(base_b, o2);
  o2 = 0;
  p.next = state_decode(next_b, o2);
  p.delta = r.next();
  p.sid = r.next();
  p.epoch = r.u32();
  return p;
}

int64_t be64_to_int(const Bytes& b) {
  uint64_t v = 0;
  for (size_t i = 0; i < b.size() && i < 8; ++i) v = (v << 8) | static_cast<uint64_t>(b[i]);
  return static_cast<int64_t>(v);
}

}  // namespace

// ---------------------------------------------------------------- state codec

Bytes state_encode(const State& s) { return enc({be32(s.v), s.cv, s.pk, s.rho}); }

State state_decode(const Bytes& b, size_t& off) {
  Reader r(b, off);
  State s;
  s.v = r.u32();
  s.cv = r.next();
  s.pk = r.next();
  s.rho = r.next();
  off = r.off;
  return s;
}

size_t state_body_size(const State& s) { return 4 + s.cv.size() + s.pk.size() + s.rho.size(); }

bool invariants_hold(const State& su, const State& sc, const Pending* pi, std::string* why) {
  if (!pi) {
    if (su.v != sc.v || su.rho != sc.rho) {
      fail(why, "Eq.(16) violated: Pi empty but UAV/committed states differ");
      return false;
    }
    return true;
  }
  if (pi->base.rho != sc.rho) {
    fail(why, "structural constraint violated: Pi.base.rho != committed rho");
    return false;
  }
  if (pi->next.v != sc.v + 1) {
    fail(why, "structural constraint violated: Pi.next.v != committed v + 1");
    return false;
  }
  bool ok = (su.v == sc.v && su.rho == sc.rho) || (su.v == pi->next.v && su.rho == pi->next.rho);
  if (!ok) fail(why, "Eq.(17) violated: UAV state outside {committed, Pi.next}");
  return ok;
}

Bytes compute_tctx(Domain d, const Bytes& sid, const Bytes& pid, const std::string& target,
                   uint64_t epoch, const Bytes& xt) {
  return hash_tag("TCTX", {text(domain_str(d)), sid, pid, text(target),
                           be32(static_cast<uint32_t>(epoch)), xt});
}

Bytes derive_pid(Domain d, const Bytes& dr) {
  Bytes eta = kdf(dr, "PIDSEED", {text(domain_str(d))});
  return hash_tag("PID", {text(domain_str(d)), eta});
}

State registration_state(Domain d, const Bytes& seed, const Bytes& dr, const Bytes& pid) {
  State s;
  s.v = 0;
  s.cv = sha256(enc({seed, text(domain_str(d)), text("CV0")}));
  Bytes sk = scalar_from_hash(kdf(dr, "AUTHKEY", {text(domain_str(d)), pid, be32(0), s.cv}));
  s.pk = pubkey_from_scalar(sk);
  s.rho = hash_tag("STATE", {text(domain_str(d)), pid, be32(0), s.cv, s.pk});
  return s;
}

// ---------------------------------------------------------------- messages

Bytes AuthzUMsg::to_bytes() const {
  return enc({text(target), be32(static_cast<uint32_t>(epoch))});
}
AuthzUMsg AuthzUMsg::from_bytes(const Bytes& b, size_t& off) {
  Reader r(b, off);
  AuthzUMsg m;
  m.target = untext(r.next());
  m.epoch = r.u32();
  off = r.off;
  return m;
}
ByteAccount AuthzUMsg::account() const {
  ByteAccount a;
  a.body = target.size() + 4;
  a.encoded = to_bytes().size();
  return a;
}

Bytes AuthzSMsg::to_bytes() const {
  return enc({pid, text(target), be32(static_cast<uint32_t>(epoch))});
}
AuthzSMsg AuthzSMsg::from_bytes(const Bytes& b, size_t& off) {
  Reader r(b, off);
  AuthzSMsg m;
  m.pid = r.next();
  m.target = untext(r.next());
  m.epoch = r.u32();
  off = r.off;
  return m;
}
ByteAccount AuthzSMsg::account() const {
  ByteAccount a;
  a.body = pid.size() + target.size() + 4;
  a.encoded = to_bytes().size();
  return a;
}

Bytes TransferMsg::to_bytes() const {
  std::vector<Bytes> parts{text(domain_str(d)),
                           pid,
                           text(target),
                           be32(static_cast<uint32_t>(epoch)),
                           state_encode(sc),
                           Bytes{static_cast<uint8_t>(has_pi ? 1 : 0)}};
  if (has_pi) parts.push_back(pending_encode(pi));
  return enc_vec(parts);
}
TransferMsg TransferMsg::from_bytes(const Bytes& b, size_t& off) {
  Reader r(b, off);
  TransferMsg m;
  Bytes d = r.next();
  m.d = (!d.empty() && d[0] == 'E') ? Domain::E : Domain::G;
  m.pid = r.next();
  m.target = untext(r.next());
  m.epoch = r.u32();
  Bytes sb = r.next();
  size_t o2 = 0;
  m.sc = state_decode(sb, o2);
  m.has_pi = r.u8() != 0;
  if (m.has_pi) m.pi = pending_decode(r.next());
  off = r.off;
  return m;
}
ByteAccount TransferMsg::account() const {
  ByteAccount a;
  a.body = 1 + pid.size() + target.size() + 4 + state_body_size(sc) + 1;
  if (has_pi) {
    a.body += state_body_size(pi.base) + state_body_size(pi.next) + pi.delta.size() + pi.sid.size() + 4;
  }
  a.encoded = to_bytes().size();
  return a;
}

Bytes M0Msg::to_bytes() const {
  std::vector<Bytes> parts{text(domain_str(d)), sid, xt, text(cert_id), cert_pk, cert_sig,
                           text(target), be32(static_cast<uint32_t>(epoch)), preauth};
  return enc_vec(parts);
}
M0Msg M0Msg::from_bytes(const Bytes& b, size_t& off) {
  Reader r(b, off);
  M0Msg m;
  Bytes d = r.next();
  m.d = (!d.empty() && d[0] == 'E') ? Domain::E : Domain::G;
  m.sid = r.next();
  m.xt = r.next();
  m.cert_id = untext(r.next());
  m.cert_pk = r.next();
  m.cert_sig = r.next();
  m.target = untext(r.next());
  m.epoch = r.u32();
  m.preauth = r.next();
  off = r.off;
  return m;
}
ByteAccount M0Msg::account() const {
  ByteAccount a;
  a.body = 1 + sid.size() + xt.size() + cert_id.size() + cert_pk.size() + cert_sig.size() +
           target.size() + 4 + preauth.size();
  a.encoded = to_bytes().size();
  return a;
}

Bytes M1Msg::to_bytes() const {
  std::vector<Bytes> parts{sid, rho_base, xu, pk_next, sig,
                           Bytes{static_cast<uint8_t>(has_ts ? 1 : 0)}};
  if (has_ts) parts.push_back(signed_ts);
  return enc_vec(parts);
}
M1Msg M1Msg::from_bytes(const Bytes& b, size_t& off) {
  Reader r(b, off);
  M1Msg m;
  m.sid = r.next();
  m.rho_base = r.next();
  m.xu = r.next();
  m.pk_next = r.next();
  m.sig = r.next();
  m.has_ts = r.u8() != 0;
  if (m.has_ts) m.signed_ts = r.next();
  off = r.off;
  return m;
}
ByteAccount M1Msg::account() const {
  ByteAccount a;
  a.body =
      sid.size() + rho_base.size() + xu.size() + pk_next.size() + sig.size() +
      (has_ts ? signed_ts.size() : 0);
  a.encoded = to_bytes().size();
  return a;
}

Bytes M2Msg::to_bytes() const { return enc({sid, tau}); }
M2Msg M2Msg::from_bytes(const Bytes& b, size_t& off) {
  Reader r(b, off);
  M2Msg m;
  m.sid = r.next();
  m.tau = r.next();
  off = r.off;
  return m;
}
ByteAccount M2Msg::account() const {
  ByteAccount a;
  a.body = sid.size() + tau.size();
  a.encoded = to_bytes().size();
  return a;
}

Bytes M3Msg::to_bytes() const { return enc({sid, tau}); }
M3Msg M3Msg::from_bytes(const Bytes& b, size_t& off) {
  Reader r(b, off);
  M3Msg m;
  m.sid = r.next();
  m.tau = r.next();
  off = r.off;
  return m;
}
ByteAccount M3Msg::account() const {
  ByteAccount a;
  a.body = sid.size() + tau.size();
  a.encoded = to_bytes().size();
  return a;
}

// ---------------------------------------------------------------- CA / MM

CaCore::CaCore(Domain d, Bytes seed) : d_(d), seed_(std::move(seed)) {
  ca_sk_ = scalar_from_hash(kdf(seed_, "CA", {text(domain_str(d))}));
  ca_pk_ = pubkey_from_scalar(ca_sk_);
}

Bytes CaCore::target_lt_sk(const std::string& id) const {
  return scalar_from_hash(kdf(seed_, "TARGET", {text(domain_str(d_)), text(id)}));
}
Bytes CaCore::target_lt_pk(const std::string& id) const { return pubkey_from_scalar(target_lt_sk(id)); }

Bytes CaCore::issue_cert(const std::string& id, const Bytes& lt_pk) const {
  return ecdsa_sign(ca_sk_, hash_tag("CERT", {text(domain_str(d_)), text(id), lt_pk}));
}

bool CaCore::verify_cert(const std::string& id, const Bytes& lt_pk, const Bytes& sig) const {
  return ecdsa_verify(ca_pk_, hash_tag("CERT", {text(domain_str(d_)), text(id), lt_pk}), sig);
}

MobilityManager::MobilityManager(Domain d, Bytes seed) : d_(d), seed_(std::move(seed)) {}

uint64_t MobilityManager::authorize(const std::string& target) {
  target_ = target;
  return ++epoch_;
}
AuthzUMsg MobilityManager::authz_u() const {
  AuthzUMsg m;
  m.target = target_;
  m.epoch = epoch_;
  return m;
}
AuthzSMsg MobilityManager::authz_s(const Bytes& pid) const {
  AuthzSMsg m;
  m.pid = pid;
  m.target = target_;
  m.epoch = epoch_;
  return m;
}

// ---------------------------------------------------------------- UAV role

UavCore::UavCore(Domain d, Bytes seed, VariantConfig v, RootProvider& root, StateStore* store,
                 EventLog* log)
    : d_(d), seed_(std::move(seed)), v_(v), root_(root), store_(store), log_(log) {
  dr_ = root_.domain_root(domain_char(d_));
  pid_ = derive_pid(d_, dr_);
  su_ = registration_state(d_, seed_, dr_, pid_);
}

Bytes UavCore::state_key(const State& s) const {
  return scalar_from_hash(kdf(dr_, "AUTHKEY", {text(domain_str(d_)), pid_, be32(s.v), s.cv}));
}
Bytes UavCore::state_rho(const State& s) const {
  return hash_tag("STATE", {text(domain_str(d_)), pid_, be32(s.v), s.cv, s.pk});
}
State UavCore::make_candidate(const State& base, const Bytes& tctx, const Bytes& xu) const {
  State s;
  s.v = base.v + 1;
  s.cv = hash_tag("NEXT", {base.rho, tctx, xu, be32(s.v)});
  Bytes sk = state_key(s);
  s.pk = pubkey_from_scalar(sk);
  s.rho = state_rho(s);
  return s;
}

bool UavCore::handle_m0(const M0Msg& m, const Bytes& ca_pk, uint64_t authorized_epoch,
                        std::string* err) {
  if (m.d != d_) return fail_false(err, "domain binding: M0 belongs to the other domain");
  if (m.epoch != authorized_epoch) return fail_false(err, "old epoch in M0");
  if (!ecdsa_verify(ca_pk, hash_tag("CERT", {text(domain_str(d_)), text(m.cert_id), m.cert_pk}),
                    m.cert_sig)) {
    return fail_false(err, "invalid certificate signature");
  }
  Bytes tctx = compute_tctx(d_, m.sid, pid_, m.target, m.epoch, m.xt);
  if (!ecdsa_verify(m.cert_pk, hash_tag("PREAUTH", {tctx}), m.preauth)) {
    return fail_false(err, "invalid PreAuth signature (Eq.6)");
  }
  sess_ = Session{};
  sess_.sid = hex(m.sid);
  sess_.epoch = m.epoch;
  sess_.tctx = tctx;
  sess_.xt = m.xt;
  sess_.target_id = m.target;
  active_ = false;
  branch_ = Branch::None;
  if (log_) log_->event("m0_received", {{"domain", domain_str(d_)}, {"sid", sess_.sid}});
  return true;
}

M1Msg UavCore::build_m1(int64_t delta_clk_ms) {
  // Same-session retransmission: replay the cached M1. No PUFEval, no new signature.
  if (!sess_.cached_m1.empty()) {
    size_t off = 0;
    return M1Msg::from_bytes(sess_.cached_m1, off);
  }
  // A NEW authorization triggers exactly one PUFEval.
  Bytes kappa_u = root_.puf_eval();
  dr_ = kdf(kappa_u, "DOMAINROOT", {text(domain_str(d_))});
  Bytes x = scalar_from_hash(random_bytes(32));
  Bytes xu = pubkey_from_scalar(x);
  State base = su_;
  State next = make_candidate(base, sess_.tctx, xu);
  Bytes delta = hash_tag("PENDING", {sess_.tctx, base.rho, be32(next.v), next.cv, next.pk});
  Bytes th0 = hash_tag("TH0", {sess_.tctx});
  Bytes th1 = hash_tag("TH1", {th0, xu, delta});
  Bytes sk_base = state_key(base);
  M1Msg m;
  m.sid = unhex(sess_.sid);
  m.rho_base = base.rho;
  m.xu = xu;
  m.pk_next = next.pk;
  if (v_.a_time) {
    // A-Time only: the timestamp is inside the signed digest (not a free header field).
    int64_t ts = now_mono_ms() + delta_clk_ms;
    Bytes hi = be32(static_cast<uint32_t>(static_cast<uint64_t>(ts) >> 32));
    Bytes lo = be32(static_cast<uint32_t>(static_cast<uint64_t>(ts) & 0xffffffffu));
    m.has_ts = true;
    m.signed_ts = hi;
    m.signed_ts.insert(m.signed_ts.end(), lo.begin(), lo.end());
    m.sig = ecdsa_sign(sk_base, hash_tag("UAV-AUTH", {th1, m.signed_ts}));
  } else {
    m.sig = ecdsa_sign(sk_base, hash_tag("UAV-AUTH", {th1}));
  }
  sess_.xu_sk = x;
  sess_.th1 = th1;
  sess_.delta = delta;
  sess_.base = base;
  sess_.next = next;
  sess_.cached_m1 = m.to_bytes();
  if (log_)
    log_->event("m1_built", {{"domain", domain_str(d_)},
                             {"sid", sess_.sid},
                             {"puf_eval", "1"},
                             {"base_v", std::to_string(base.v)}});
  return m;
}

bool UavCore::handle_m2(const M2Msg& m, std::string* err) {
  if (hex(m.sid) != sess_.sid) return fail_false(err, "unknown SID in M2");
  if (active_) return fail_false(err, "duplicate M2 after activation");
  Bytes z = ecdh_shared(sess_.xu_sk, sess_.xt);
  Bytes actx = hash_tag("ACTX", {sess_.tctx, sess_.base.rho});
  Bytes prk = hkdf_extract(actx, enc({z}));
  Bytes kcf = hkdf_expand(prk, hash_tag("KCONF", {sess_.th1}));
  Bytes kcm = hkdf_expand(prk, hash_tag("KCOMMIT", {sess_.th1}));
  Bytes ks = hkdf_expand(prk, hash_tag("SESSKEY", {sess_.th1}));
  Bytes expect = hmac_sha256(kcf, hash_tag("TARGET-CONFIRM", {sess_.th1}));
  if (expect != m.tau) return fail_false(err, "invalid M2 MAC (tau_T)");
  Bytes th2 = hash_tag("TH2", {sess_.th1, m.tau});
  M3Msg m3;
  m3.sid = m.sid;
  m3.tau = hmac_sha256(kcm, hash_tag("COMMIT", {th2}));
  // Persistence point 2 (Sec.V-C, Eq.12): durable S^U <- S^N BEFORE emitting M3.
  su_ = sess_.next;
  if (store_) store_->save_uav(d_, su_);
  sess_.th2 = th2;
  sess_.kcf = kcf;
  sess_.kcm = kcm;
  sess_.ks = ks;
  m3_ = m3;
  active_ = true;
  if (log_)
    log_->event("m2_handled", {{"domain", domain_str(d_)},
                               {"sid", sess_.sid},
                               {"uav_v", std::to_string(su_.v)}});
  return true;
}

bool UavCore::restore_from_store() {
  if (!store_) return false;
  State s;
  if (!store_->load_uav(d_, s)) return false;
  su_ = s;
  return true;
}

// ---------------------------------------------------------------- target role

TargetCore::TargetCore(Domain d, std::string id, Bytes lt_sk, Bytes dr, Bytes seed, VariantConfig v,
                       StateStore* store, EventLog* log)
    : d_(d), id_(std::move(id)), lt_sk_(std::move(lt_sk)), dr_(std::move(dr)),
      seed_(std::move(seed)), v_(v), store_(store), log_(log) {
  lt_pk_ = pubkey_from_scalar(lt_sk_);
  pid_ = derive_pid(d_, dr_);
  sc_ = registration_state(d_, seed_, dr_, pid_);
}

Bytes TargetCore::state_key(const State& s) const {
  return scalar_from_hash(kdf(dr_, "AUTHKEY", {text(domain_str(d_)), pid_, be32(s.v), s.cv}));
}
Bytes TargetCore::state_rho(const State& s) const {
  return hash_tag("STATE", {text(domain_str(d_)), pid_, be32(s.v), s.cv, s.pk});
}
State TargetCore::make_candidate(const State& base, const Bytes& tctx, const Bytes& xu) const {
  State s;
  s.v = base.v + 1;
  s.cv = hash_tag("NEXT", {base.rho, tctx, xu, be32(s.v)});
  Bytes sk = state_key(s);
  s.pk = pubkey_from_scalar(sk);
  s.rho = state_rho(s);
  return s;
}

void TargetCore::accept_transfer(const TransferMsg& t) {
  sc_ = t.sc;
  if (t.has_pi)
    pi_ = t.pi;
  else
    pi_.reset();
  if (store_) {
    store_->save_committed(d_, sc_);
    store_->save_pending(d_, pi_);
  }
}

M0Msg TargetCore::create_session(const Bytes& pid, const std::string& target, uint64_t epoch,
                                 bool with_ts) {
  (void)with_ts;  // A-Time adds its timestamp to M1 only, where it is signature-covered.
  M0Msg m;
  m.d = d_;
  m.sid = random_bytes(16);
  m.target = target;
  m.epoch = epoch;
  m.cert_id = id_;
  m.cert_pk = lt_pk_;
  m.cert_sig = cert_sig_;
  Bytes x = scalar_from_hash(random_bytes(32));
  m.xt = pubkey_from_scalar(x);
  Session s;
  s.sid = hex(m.sid);
  s.st = SessState::Prepared;
  s.epoch = epoch;
  s.target_id = target;
  s.xt_sk = x;
  s.xt = m.xt;
  s.tctx = compute_tctx(d_, m.sid, pid, target, epoch, m.xt);
  m.preauth = ecdsa_sign(lt_sk_, hash_tag("PREAUTH", {s.tctx}));
  sessions_[s.sid] = s;
  active_sid_ = s.sid;
  if (store_) store_->save_session(d_, s);
  if (log_)
    log_->event("session_prepared", {{"domain", domain_str(d_)},
                                     {"sid", s.sid},
                                     {"epoch", std::to_string(epoch)}});
  return m;
}

M1Outcome TargetCore::handle_m1(const M1Msg& m, uint64_t current_epoch, int64_t now_ms,
                                int64_t dnet_ms, std::string* err) {
  M1Outcome oc;
  const std::string sid = hex(m.sid);
  auto it = sessions_.find(sid);
  if (it == sessions_.end()) {
    oc.reason = "unknown SID";
    fail(err, oc.reason);
    return oc;
  }
  Session& s = it->second;
  if (s.epoch != current_epoch) {
    oc.reason = "old epoch (superseded authorization)";
    fail(err, oc.reason);
    return oc;
  }
  if (s.st == SessState::Expired) {
    oc.reason = "expired session";
    fail(err, oc.reason);
    return oc;
  }
  Bytes m1_bytes = m.to_bytes();
  if (s.m2_sent && s.cached_m1 == m1_bytes) {
    // cached-retry: resend the stored M2, no PUFEval, no new signature, no state change
    oc.ok = true;
    oc.branch = Branch::CachedRetry;
    oc.m2_ready = true;
    last_branch_ = oc.branch;
    if (log_)
      log_->event("m1_cached_retry", {{"domain", domain_str(d_)}, {"sid", sid}});
    return oc;
  }

  // Eq.(18): admissible verification base.
  Branch br;
  const State* base = nullptr;
  if (!pi_) {
    if (m.rho_base != sc_.rho) {
      oc.reason = "base rho mismatch for normal branch";
      fail(err, oc.reason);
      return oc;
    }
    base = &sc_;
    br = Branch::Normal;
  } else if (m.rho_base == sc_.rho) {
    base = &sc_;
    br = Branch::M2Recover;  // UAV did NOT activate: replace Pi, do not advance S^C
  } else if (m.rho_base == pi_->next.rho) {
    base = &pi_->next;
    br = Branch::M3Recover;  // UAV already activated: commit old Pi first
  } else {
    oc.reason = "base rho not in admissible set {S^C, Pi.next}";
    fail(err, oc.reason);
    return oc;
  }
  if (v_.a_retry && (br == Branch::M2Recover || br == Branch::M3Recover)) {
    oc.reason = "A-Retry: new-authorization recovery unsupported";
    fail(err, oc.reason);
    return oc;
  }

  State cand = make_candidate(*base, s.tctx, m.xu);
  if (cand.pk != m.pk_next) {
    oc.reason = "candidate PK mismatch";
    fail(err, oc.reason);
    return oc;
  }
  Bytes delta = hash_tag("PENDING", {s.tctx, base->rho, be32(cand.v), cand.cv, cand.pk});
  Bytes th0 = hash_tag("TH0", {s.tctx});
  Bytes th1 = hash_tag("TH1", {th0, m.xu, delta});
  Bytes digest =
      m.has_ts ? hash_tag("UAV-AUTH", {th1, m.signed_ts}) : hash_tag("UAV-AUTH", {th1});
  if (!ecdsa_verify(base->pk, digest, m.sig)) {
    oc.reason = "invalid UAV state signature (Eq.9)";
    fail(err, oc.reason);
    return oc;
  }
  // A-Time window check (|Delta_clk + D_net| <= W) runs only after signature verification.
  if (v_.a_time) {
    if (!m.has_ts) {
      oc.reason = "A-Time requires an authenticated timestamp";
      fail(err, oc.reason);
      return oc;
    }
    int64_t observed = (be64_to_int(m.signed_ts) + dnet_ms) - now_ms;
    if (observed > v_.window_ms || observed < -v_.window_ms) {
      oc.reason = "TIMESTAMP_WINDOW";
      fail(err, oc.reason);
      return oc;
    }
  }

  // Copy the verification base before any pending reset: pi_->next must not be
  // referenced after the pending object is released (dangling state reference).
  State base_copy = *base;

  // M3Recover: commit the already activated pending (ONE version step), then install the new one.
  if (br == Branch::M3Recover) {
    sc_ = pi_->next;
    ++commits_;
    if (store_) store_->save_committed(d_, sc_);
    pi_.reset();
  }
  Pending p;
  p.base = sc_;
  p.next = cand;
  p.delta = delta;
  p.sid = m.sid;
  p.epoch = s.epoch;
  pi_ = p;

  Bytes z = ecdh_shared(s.xt_sk, m.xu);
  Bytes actx = hash_tag("ACTX", {s.tctx, base_copy.rho});
  Bytes prk = hkdf_extract(actx, enc({z}));
  s.th1 = th1;
  s.delta = delta;
  s.base = base_copy;
  s.next = cand;
  s.kcf = hkdf_expand(prk, hash_tag("KCONF", {th1}));
  s.kcm = hkdf_expand(prk, hash_tag("KCOMMIT", {th1}));
  s.ks = hkdf_expand(prk, hash_tag("SESSKEY", {th1}));
  s.tau_t = hmac_sha256(s.kcf, hash_tag("TARGET-CONFIRM", {th1}));
  s.th2 = hash_tag("TH2", {th1, s.tau_t});
  s.cached_m1 = m1_bytes;
  s.m2_sent = true;
  s.m3_sent = false;
  s.st = SessState::AwaitM3;
  m2_.sid = m.sid;
  m2_.tau = s.tau_t;
  // Persistence point 1 (Sec.V-C, Eq.11): durable Pi and session BEFORE emitting M2.
  if (store_) {
    store_->save_pending(d_, pi_);
    store_->save_session(d_, s);
  }
  oc.ok = true;
  oc.branch = br;
  oc.m2_ready = true;
  last_branch_ = br;
  if (log_)
    log_->event("m1_handled", {{"domain", domain_str(d_)},
                               {"sid", sid},
                               {"branch", branch_str(br)},
                               {"pending_v", std::to_string(cand.v)}});
  return oc;
}

bool TargetCore::handle_m3(const M3Msg& m, uint64_t current_epoch, int64_t now_ms,
                           std::string* err) {
  (void)now_ms;
  const std::string sid = hex(m.sid);
  auto it = sessions_.find(sid);
  if (it == sessions_.end()) return fail_false(err, "unknown SID in M3");
  Session& s = it->second;
  if (s.epoch != current_epoch) return fail_false(err, "old epoch in M3");
  if (s.st == SessState::Expired) return fail_false(err, "session expired; M3 rejected, Pi retained");
  if (s.st == SessState::Committed) return fail_false(err, "duplicate M3 after commit");
  if (s.st != SessState::AwaitM3) return fail_false(err, "session not in AwaitM3");
  if (!pi_ || hex(pi_->sid) != sid) return fail_false(err, "no matching pending migration");
  Bytes expect = hmac_sha256(s.kcm, hash_tag("COMMIT", {s.th2}));
  if (expect != m.tau) return fail_false(err, "invalid M3 MAC (tau_C)");
  // Persistence point 3 (Sec.V-C, Eq.13): atomic commit, Pi cleared, K^cm erased.
  sc_ = pi_->next;
  ++commits_;
  pi_.reset();
  s.st = SessState::Committed;
  s.tau_c = m.tau;
  s.kcm.clear();
  s.ks.clear();
  if (store_) {
    store_->save_committed(d_, sc_);
    store_->save_pending(d_, pi_);
    store_->save_session(d_, s);
  }
  if (log_)
    log_->event("committed", {{"domain", domain_str(d_)},
                              {"sid", sid},
                              {"committed_v", std::to_string(sc_.v)}});
  return true;
}

bool TargetCore::expire(const std::string& sid, std::string* err) {
  auto it = sessions_.find(sid);
  if (it == sessions_.end()) return fail_false(err, "unknown SID");
  Session& s = it->second;
  if (s.st != SessState::AwaitM3) return fail_false(err, "only AwaitM3 sessions expire");
  s.st = SessState::Expired;
  s.kcf.clear();
  s.kcm.clear();
  s.ks.clear();  // session secrets erased; Pi is deliberately retained for recovery
  if (store_) store_->save_session(d_, s);
  if (log_) log_->event("session_expired", {{"domain", domain_str(d_)}, {"sid", sid}});
  return true;
}

bool TargetCore::restore_from_store(const std::string& sid) {
  if (!store_) return false;
  State s;
  if (store_->load_committed(d_, s)) sc_ = s;
  std::optional<Pending> p;
  if (store_->load_pending(d_, p)) pi_ = p;
  Session se;
  if (!sid.empty() && store_->load_session(d_, sid, se)) {
    sessions_[se.sid] = se;
    active_sid_ = se.sid;
    m2_.sid = unhex(se.sid);
    m2_.tau = se.tau_t;
  }
  return true;
}

// ---------------------------------------------------------------- source role

SourceCore::SourceCore(Domain d, Bytes pid) : d_(d), pid_(std::move(pid)) {}

TransferMsg SourceCore::build_transfer(const std::string& target, uint64_t epoch) const {
  TransferMsg t;
  t.d = d_;
  t.pid = pid_;
  t.target = target;
  t.epoch = epoch;
  t.sc = sc_;
  t.has_pi = pi_.has_value();
  if (pi_) t.pi = *pi_;
  return t;
}

}  // namespace uavma
