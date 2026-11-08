// UAV-Mobility-Auth formal core: shared single-domain harness.
#include "uavma/harness.h"

#include <utility>

#include "uavma/crypto.h"
#include "uavma/linux_transport.h"

namespace uavma {

World::World(Domain d, std::string target_id, Bytes seed, VariantConfig v,
             const std::string& db_path, EventLog* log)
    : d(d),
      target_id(std::move(target_id)),
      // NOTE: copy, never move-from the parameter here. Member initialisation follows
      // declaration order, so moving first would leave root/ca/mm with an empty seed
      // while later role objects (re)created from the member got the real one.
      seed(seed),
      root(seed),
      ca(d, seed),
      mm(d, seed),
      v(v),
      log(log) {
  if (!db_path.empty()) store = std::make_unique<StateStore>(db_path);
  Bytes dr = root.domain_root(domain_char(d));
  uav = std::make_unique<UavCore>(d, seed, v, root, store.get(), log);
  Bytes lt_sk = ca.target_lt_sk(target_id);
  target = std::make_unique<TargetCore>(d, target_id, lt_sk, dr, seed, v, store.get(), log);
  target->set_cert_sig(ca.issue_cert(target_id, ca.target_lt_pk(target_id)));
  src = std::make_unique<SourceCore>(d, uav->pid());
}

void World::crash_restart() {
  std::string sid = active_sid;
  // Destroy every role object: nothing survives except the durable store.
  uav.reset();
  target.reset();
  src.reset();
  Bytes dr = root.domain_root(domain_char(d));
  uav = std::make_unique<UavCore>(d, seed, v, root, store.get(), log);
  Bytes lt_sk = ca.target_lt_sk(target_id);
  target = std::make_unique<TargetCore>(d, target_id, lt_sk, dr, seed, v, store.get(), log);
  target->set_cert_sig(ca.issue_cert(target_id, ca.target_lt_pk(target_id)));
  src = std::make_unique<SourceCore>(d, uav->pid());
  if (store) {
    uav->restore_from_store();
    target->restore_from_store(sid);
  }
}

TxReport run_transaction(World& w, const TxOptions& o) {
  TxReport r;
  OpCounters before = counters();
  std::string err;

  const std::string tid = o.target_override.empty() ? w.target_id : o.target_override;
  if (!o.same_session_retry) {
    r.t_select_ms = now_mono_ms();
    uint64_t epoch = w.mm.authorize(tid);
    AuthzUMsg au = w.mm.authz_u();
    AuthzSMsg as = w.mm.authz_s(w.uav->pid());
    r.body_mm += au.account().body + as.account().body;
    // Source holds a mirror of the currently committed/pending state of this domain.
    w.src->set_committed(w.target->sc());
    w.src->set_pending(w.target->pi() ? std::optional<Pending>(*w.target->pi()) : std::nullopt);
    TransferMsg tr = w.src->build_transfer(tid, epoch);
    w.target->accept_transfer(tr);
    r.body_inf += tr.account().body;
    r.framed_total += tr.account().encoded + kFrameHeaderBytes;
    M0Msg m0 = w.target->create_session(w.uav->pid(), tid, epoch);
    r.body_dl += m0.account().body;
    r.framed_total += m0.account().encoded + kFrameHeaderBytes;
    r.sid = hex(m0.sid);
    w.active_sid = r.sid;
    r.t_prepare_ready_ms = now_mono_ms();
    if (!w.uav->handle_m0(m0, w.ca.ca_pk(), epoch, &err)) {
      r.reason = "M0 rejected: " + err;
      r.branch = "reject";
      return r;
    }
  } else {
    r.t_select_ms = now_mono_ms();
    r.sid = w.active_sid;
  }

  uint64_t epoch = w.mm.epoch();
  M1Msg m1 = w.uav->build_m1(o.delta_clk_ms);
  r.body_ul += m1.account().body;
  r.framed_total += m1.account().encoded + kFrameHeaderBytes;
  if (o.drop_m1) {
    r.reason = "M1 dropped (injected)";
    r.branch = "injected-loss";
    return r;
  }
  M1Outcome oc = w.target->handle_m1(m1, epoch, now_mono_ms(), o.dnet_ms, &err);
  if (o.duplicate_m1) {
    // Same instance retransmission: identical bytes, must not re-sign or re-derive.
    M1Outcome oc2 = w.target->handle_m1(m1, epoch, now_mono_ms(), o.dnet_ms, &err);
    (void)oc2;
  }
  if (!oc.ok) {
    r.reason = "M1 rejected: " + oc.reason;
    r.branch = branch_str(Branch::Reject);
    return r;
  }
  r.branch = branch_str(oc.branch);
  M2Msg m2 = w.target->m2();
  r.body_dl += m2.account().body;
  r.framed_total += m2.account().encoded + kFrameHeaderBytes;
  if (o.drop_m2) {
    r.reason = "M2 dropped (injected)";
    return r;
  }
  if (o.expire_after_m2) {
    w.target->expire(r.sid, &err);
    if (w.uav->handle_m2(m2, &err)) {
      r.reason = "expired M2 was accepted";
      return r;
    }
    r.reason = "session expired before M3; Pi retained";
    return r;
  }
  if (!w.uav->handle_m2(m2, &err)) {
    r.reason = "M2 rejected: " + err;
    return r;
  }
  r.t_uav_activate_ms = now_mono_ms();
  M3Msg m3 = w.uav->m3();
  r.body_ul += m3.account().body;
  r.framed_total += m3.account().encoded + kFrameHeaderBytes;
  if (o.drop_m3) {
    r.reason = "M3 dropped (injected)";
    return r;
  }
  if (o.duplicate_m2) {
    // Duplicate valid M2 with the same SID: resend the stored M3, no further advance.
    w.uav->handle_m2(m2, &err);
  }
  if (!w.target->handle_m3(m3, epoch, now_mono_ms(), &err)) {
    r.reason = "M3 rejected: " + err;
    return r;
  }
  r.t_target_commit_ms = now_mono_ms();
  r.t_full_ms = r.t_target_commit_ms - r.t_select_ms;
  r.committed = true;

  OpCounters delta = counters() - before;
  r.puf = delta.puf;
  r.sign = delta.sign;
  r.verify = delta.verify;
  r.mac = delta.mac;
  r.hash = delta.hash;
  r.ecdh = delta.ecdh;
  r.commits = w.target->commits();
  r.committed_v = w.target->sc().v;
  r.committed_rho = hex_prefix(w.target->sc().rho);
  r.uav_v = w.uav->su().v;
  r.uav_rho = hex_prefix(w.uav->su().rho);
  if (w.target->pi()) {
    r.pending_present = true;
    r.pending_v = w.target->pi()->next.v;
    r.pending_rho = hex_prefix(w.target->pi()->next.rho);
  }
  return r;
}

PreparedTx prepare_authorization(World& w, const std::string& tid, int64_t delta_clk_ms) {
  PreparedTx p;
  std::string err;
  p.epoch = w.mm.authorize(tid);
  AuthzUMsg au = w.mm.authz_u();
  AuthzSMsg as = w.mm.authz_s(w.uav->pid());
  p.body_mm = au.account().body + as.account().body;
  w.src->set_committed(w.target->sc());
  w.src->set_pending(w.target->pi() ? std::optional<Pending>(*w.target->pi()) : std::nullopt);
  TransferMsg tr = w.src->build_transfer(tid, p.epoch);
  w.target->accept_transfer(tr);
  p.body_inf = tr.account().body;
  M0Msg m0 = w.target->create_session(w.uav->pid(), tid, p.epoch);
  p.body_dl = m0.account().body;
  p.sid = hex(m0.sid);
  w.active_sid = p.sid;
  if (!w.uav->handle_m0(m0, w.ca.ca_pk(), p.epoch, &err)) {
    p.err = "M0 rejected: " + err;
    return p;
  }
  p.m1 = w.uav->build_m1(delta_clk_ms);
  p.body_ul = p.m1.account().body;
  p.ok = true;
  return p;
}

TxReport finish_transaction(World& w, uint64_t epoch) {
  TxReport r;
  std::string err;
  M2Msg m2 = w.target->m2();
  r.body_dl = m2.account().body;
  if (!w.uav->handle_m2(m2, &err)) {
    r.reason = "M2 rejected: " + err;
    return r;
  }
  r.t_uav_activate_ms = now_mono_ms();
  M3Msg m3 = w.uav->m3();
  r.body_ul = m3.account().body;
  if (!w.target->handle_m3(m3, epoch, now_mono_ms(), &err)) {
    r.reason = "M3 rejected: " + err;
    return r;
  }
  r.t_target_commit_ms = now_mono_ms();
  r.committed = true;
  r.branch = branch_str(w.target->last_branch());
  r.committed_v = w.target->sc().v;
  r.committed_rho = hex_prefix(w.target->sc().rho);
  r.uav_v = w.uav->su().v;
  r.uav_rho = hex_prefix(w.uav->su().rho);
  r.commits = w.target->commits();
  if (w.target->pi()) {
    r.pending_present = true;
    r.pending_v = w.target->pi()->next.v;
    r.pending_rho = hex_prefix(w.target->pi()->next.rho);
  }
  return r;
}

}  // namespace uavma
