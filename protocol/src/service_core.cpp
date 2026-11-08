// UAV-Mobility-Auth formal core: stateful edge service implementation.
#include "uavma/service_core.h"

#include <algorithm>

#include "uavma/experiment_driver.h"
#include "uavma/protocol_core.h"

namespace uavma {

Bytes ServiceState::serialize() const {
  Bytes out;
  append_enc(out, be32(static_cast<uint32_t>(counter >> 32)));
  append_enc(out, be32(static_cast<uint32_t>(counter & 0xffffffffu)));
  append_enc(out, be32(static_cast<uint32_t>(cursor >> 32)));
  append_enc(out, be32(static_cast<uint32_t>(cursor & 0xffffffffu)));
  append_enc(out, be32(static_cast<uint32_t>(processed.size())));
  for (const std::string& s : processed) append_enc(out, text(s));
  return out;
}

ServiceState ServiceState::deserialize(const Bytes& b) {
  ServiceState s;
  size_t off = 0;
  auto rd = [&]() -> Bytes {
    if (off + 4 > b.size()) throw std::runtime_error("service state truncated");
    uint32_t n = (static_cast<uint32_t>(b[off]) << 24) | (static_cast<uint32_t>(b[off + 1]) << 16) |
                 (static_cast<uint32_t>(b[off + 2]) << 8) | static_cast<uint32_t>(b[off + 3]);
    off += 4;
    if (off + n > b.size()) throw std::runtime_error("service state short field");
    Bytes r(b.begin() + off, b.begin() + off + n);
    off += n;
    return r;
  };
  auto u64 = [&]() -> uint64_t {
    Bytes hi = rd();
    Bytes lo = rd();
    uint64_t v = 0;
    for (uint8_t x : hi) v = (v << 8) | x;
    for (uint8_t x : lo) v = (v << 8) | x;
    return v;
  };
  s.counter = u64();
  s.cursor = u64();
  Bytes nb = rd();
  uint32_t n = 0;
  for (uint8_t x : nb) n = (n << 8) | x;
  for (uint32_t i = 0; i < n; ++i) s.processed.push_back(untext(rd()));
  return s;
}

ServiceCore::ServiceCore(std::string node_id) : node_(std::move(node_id)) {}

void ServiceCore::set_authorized(bool ok, uint64_t epoch) {
  authorized_ = ok;
  auth_epoch_ = epoch;
}

void ServiceCore::install_state(const ServiceState& s) {
  state_ = s;
  state_installed_ = true;
}

bool ServiceCore::handle_request(const std::string& request_id, int64_t t_ms, std::string& response,
                                 std::string* reason) {
  ServiceEvent ev;
  ev.t_ms = t_ms;
  ev.node = node_;
  ev.request_id = request_id;
  ev.authorized = authorized_;
  ev.auth_epoch = auth_epoch_;

  auto reject = [&](const std::string& why) {
    ev.reason = why;
    ev.correct = false;
    events_.push_back(ev);
    if (reason) *reason = why;
    return false;
  };

  if (!authorized_) return reject("not_authorized_e_domain_not_committed");
  if (!state_installed_) return reject("service_state_not_installed");

  bool dup = std::find(state_.processed.begin(), state_.processed.end(), request_id) !=
             state_.processed.end();
  ev.duplicate = dup;
  if (dup) {
    // Correct behaviour for a retransmitted request: answer from the processed set,
    // do not advance the cumulative counter twice.
    ev.counter_after = state_.counter;
    ev.correct = true;
    ev.reason = "duplicate_replayed";
    response = "ok:" + request_id + ":" + std::to_string(state_.counter);
    events_.push_back(ev);
    return true;
  }
  state_.processed.push_back(request_id);
  ++state_.cursor;
  state_.counter += 1;
  ev.counter_after = state_.counter;
  ev.correct = true;
  response = "ok:" + request_id + ":" + std::to_string(state_.counter);
  events_.push_back(ev);
  return true;
}

std::string ServiceCore::last_correct_response_at() const {
  for (auto it = events_.rbegin(); it != events_.rend(); ++it)
    if (it->correct) return std::to_string(it->t_ms);
  return "";
}

}  // namespace uavma
