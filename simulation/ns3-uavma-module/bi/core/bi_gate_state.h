// SPDX-License-Identifier: MIT
// E2-B development-only gate logic: no authentication is performed here.
#pragma once

#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>

namespace e2b {

enum class GateCode { Created, Duplicate, Replaced, Invalid, Released, Rejected, Expired, Stale };

struct GateRequest {
  std::uint16_t rnti = 0;
  std::uint16_t target = 0;
  std::uint64_t token = 0;
  std::int64_t opportunity_ns = -1;
  std::int64_t deadline_ns = -1;
};

struct GateResult {
  GateCode code = GateCode::Invalid;
  GateRequest request{};
  bool NewOpportunity() const { return code == GateCode::Created || code == GateCode::Replaced; }
  bool MayTriggerHandover() const { return code == GateCode::Released; }
};

class GateState final {
 public:
  GateResult Start(std::uint16_t rnti, std::uint16_t target,
                   std::int64_t now_ns, std::int64_t timeout_ns) {
    if (!rnti || !target || now_ns < 0 || timeout_ns <= 0 ||
        now_ns > std::numeric_limits<std::int64_t>::max() - timeout_ns) {
      return {GateCode::Invalid, {}};
    }
    auto it = pending_.find(rnti);
    if (it != pending_.end() && it->second.target == target &&
        now_ns < it->second.deadline_ns) {
      return {GateCode::Duplicate, it->second};
    }
    if (next_token_ == std::numeric_limits<std::uint64_t>::max()) {
      throw std::overflow_error("Bi gate token sequence exhausted");
    }
    const GateRequest request{rnti, target, ++next_token_, now_ns, now_ns + timeout_ns};
    const bool replaced = it != pending_.end();
    pending_[rnti] = request;
    return {replaced ? GateCode::Replaced : GateCode::Created, request};
  }

  // Called only when a separate Bi authenticator has actually validated preparation.
  GateResult Authorize(std::uint16_t rnti, std::uint16_t target, std::uint64_t token,
                       std::int64_t now_ns, bool preparation_verified) {
    auto it = pending_.find(rnti);
    if (it == pending_.end() || !token || it->second.token != token ||
        it->second.target != target) {
      return {GateCode::Stale, {}};
    }
    GateRequest request = it->second;
    if (now_ns < request.opportunity_ns || now_ns >= request.deadline_ns) {
      pending_.erase(it);
      return {GateCode::Expired, request};
    }
    if (!preparation_verified) {
      // Failed validation is terminal. Never fall back to unauthenticated handover.
      pending_.erase(it);
      return {GateCode::Rejected, request};
    }
    pending_.erase(it);
    return {GateCode::Released, request};
  }

  GateResult Timeout(std::uint16_t rnti, std::uint64_t token, std::int64_t now_ns) {
    auto it = pending_.find(rnti);
    if (it == pending_.end() || !token || it->second.token != token) {
      return {GateCode::Stale, {}};
    }
    if (now_ns < it->second.deadline_ns) {
      return {GateCode::Rejected, it->second}; // early timer: no state change
    }
    const auto request = it->second;
    pending_.erase(it);
    return {GateCode::Expired, request};
  }

  GateResult Abort(std::uint16_t rnti, std::uint64_t token) {
    auto it = pending_.find(rnti);
    if (it == pending_.end() || !token || it->second.token != token) {
      return {GateCode::Stale, {}};
    }
    const auto request = it->second;
    pending_.erase(it);
    return {GateCode::Rejected, request};
  }

  bool Pending(std::uint16_t rnti) const { return pending_.count(rnti) != 0; }
  std::size_t Size() const { return pending_.size(); }
  void Clear() { pending_.clear(); }

 private:
  std::map<std::uint16_t, GateRequest> pending_;
  std::uint64_t next_token_ = 0;
};
} // namespace e2b
