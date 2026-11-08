// Adapter-only event and authorization bookkeeping policy.
// No wire message, cryptographic primitive, or protocol-core state is changed.
#ifndef UAVMA_NS3_EVENT_POLICY_H
#define UAVMA_NS3_EVENT_POLICY_H

#include <cstdint>
#include <cmath>
#include <string>

namespace uavma_ns3 {

enum class Variant { P, AJoint };
enum class Event { None, GOnly, EOnly, GE };
struct Plan { bool g; bool e; };

inline bool ParseVariant(const std::string& name, Variant* out) {
  if (!out) return false;
  if (name == "P") { *out = Variant::P; return true; }
  if (name == "A_JOINT") { *out = Variant::AJoint; return true; }
  return false;
}

inline const char* EventName(Event event) {
  switch (event) {
    case Event::None: return "None";
    case Event::GOnly: return "G_only";
    case Event::EOnly: return "E_only";
    case Event::GE: return "GE";
  }
  return "Invalid";
}

inline Plan Select(Variant variant, Event event) {
  if (event == Event::None) return {false, false};
  if (variant == Variant::AJoint) return {true, true};
  switch (event) {
    case Event::GOnly: return {true, false};
    case Event::EOnly: return {false, true};
    case Event::GE: return {true, true};
    case Event::None: return {false, false};
  }
  return {false, false};
}

// AuthzU's paper-defined payload does not contain d. Reject unknown or ambiguous
// target names rather than silently treating them as G. Both configured target
// identities must be distinct when G and E are enabled.
inline char MatchTargetDomain(const std::string& target,
                              const std::string& gTarget,
                              const std::string& eTarget,
                              bool hasG, bool hasE) {
  const bool g = hasG && target == gTarget;
  const bool e = hasE && target == eTarget;
  if (g == e) return '\0';
  return g ? 'G' : 'E';
}

// Process-wide ns-3 registry keys must be domain-qualified: both MM_G and MM_E
// can independently assign epoch 1, 2, ... . A SID is unknown for AuthzU.
inline std::string AuthzKey(char domain, std::uint64_t epoch) {
  return "AuthzU|" + std::string(1, domain) + "|" + std::to_string(epoch);
}

// No unbounded M3 amplification from replayed M2. A valid repeat is permitted
// only during the adapter's finite RTO retry window.
inline bool AllowCachedM3Replay(std::int64_t nowNs, std::int64_t startedNs,
                                double rtoMs, std::uint32_t replayCount,
                                std::uint32_t maxRetrans) {
  if (startedNs < 0 || nowNs < startedNs || !std::isfinite(rtoMs) || rtoMs <= 0.0 ||
      replayCount >= maxRetrans) return false;
  const long double elapsedNs = static_cast<long double>(nowNs) - startedNs;
  const long double budgetNs = (static_cast<long double>(maxRetrans) + 1.0L) * rtoMs * 1e6L;
  return elapsedNs <= budgetNs;
}

}  // namespace uavma_ns3
#endif
