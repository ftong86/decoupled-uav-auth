// SPDX-License-Identifier: MIT
// Metric definitions for the NEW comparison; do not reuse E2's old M0->M3 as Bi latency.
#pragma once

#include <algorithm>
#include <cmath>
#include <limits>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>

namespace e2b {
enum class Scheme { Unset, UavmaP, BiMes };
struct ComparisonMilestones {
  Scheme scheme = Scheme::Unset;
  std::int64_t opportunity_ns = -1;
  std::int64_t preparation_verified_ns = -1;
  std::int64_t ho_command_ns = -1;
  std::int64_t rrc_end_ns = -1;
  std::int64_t dual_authorized_ns = -1;
  std::int64_t p_m0_infrastructure_emission_ns = -1;
  std::int64_t p_m3_infrastructure_commit_ns = -1;

  // Protocol completion: both domain confirmations VERIFIED. Not merely packet received.
  bool Ready() const {
    if (scheme == Scheme::Unset || opportunity_ns < 0 ||
        ho_command_ns < opportunity_ns || rrc_end_ns < ho_command_ns ||
        dual_authorized_ns < opportunity_ns) return false;
    if (scheme == Scheme::BiMes) {
      return preparation_verified_ns >= opportunity_ns &&
             ho_command_ns >= preparation_verified_ns;
    }
    // P did not perform the Bi preparation protocol. Do not invent one.
    return preparation_verified_ns == -1;
  }
  std::int64_t OpportunityToAuthorizationNs() const {
    if (!Ready()) throw std::logic_error("incomplete/misordered common event timeline");
    return dual_authorized_ns - opportunity_ns;
  }
  std::int64_t POnlineM0M3Ns() const {
    if (scheme != Scheme::UavmaP || p_m0_infrastructure_emission_ns < 0 ||
        p_m3_infrastructure_commit_ns < p_m0_infrastructure_emission_ns) {
      throw std::logic_error("P infrastructure-emitted M0 to M3 commit not available");
    }
    return p_m3_infrastructure_commit_ns - p_m0_infrastructure_emission_ns;
  }
  std::int64_t PostRrcWaitNs() const {
    if (!Ready()) throw std::logic_error("incomplete/misordered common event timeline");
    return std::max<std::int64_t>(0, dual_authorized_ns - rrc_end_ns);
  }
};

struct MeasuredCost {
  std::uint64_t framed_sent_bytes = 0;
  std::uint64_t sent_frames = 0;
  double modeled_cpu_us = 0;
  void OnWireSend(std::size_t actual_frame_size) {
    if (!actual_frame_size) throw std::invalid_argument("zero-length frame was not sent");
    if (actual_frame_size > std::numeric_limits<std::uint64_t>::max() - framed_sent_bytes) {
      throw std::overflow_error("framed-byte counter overflow");
    }
    if (sent_frames == std::numeric_limits<std::uint64_t>::max()) {
      throw std::overflow_error("message counter overflow");
    }
    framed_sent_bytes += actual_frame_size;
    ++sent_frames;
  }
  void OnCpuService(double us) {
    if (!std::isfinite(us) || us < 0 || !std::isfinite(modeled_cpu_us + us)) {
      throw std::invalid_argument("invalid modeled cpu cost");
    }
    modeled_cpu_us += us;
  }
};
} // namespace e2b
