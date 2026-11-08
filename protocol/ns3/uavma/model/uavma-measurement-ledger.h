// Simulation-only accounting; no changes to the frozen UAVMA protocol or wire format.
#ifndef UAVMA_NS3_MEASUREMENT_LEDGER_H
#define UAVMA_NS3_MEASUREMENT_LEDGER_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace uavma_ns3 {

// AuthzU is received before the UAV knows the SID. Its retransmission
// counter must use the domain+epoch alias, not the empty SID.
inline std::string RetransmissionLookupKey(const std::string& sid,
                                           const std::string& msg,
                                           const std::string& receiveKey) {
  return sid.empty() ? receiveKey : sid + "|" + msg;
}

struct WireUsage {
  size_t datagrams = 0;  // accepted socket sends incl. retrans; not delivery counts
  size_t bytes = 0;      // sent UDP payload frame bytes; excludes IP/UDP headers
};

// The sender and receiver share ONE ns-3 process. Attempt timestamps therefore
// require no timestamp field in M0--M3 or AuthzU.
// IMPORTANT: Retransmissions carry identical bytes; when more than one candidate
// emission remains unmatched, there is no defensible single one-way delay.
// Return false in this case rather than mislabeling ARQ waiting as network delay.
class MeasurementLedger {
 public:
  void Reset() {
    pending_.clear();
    wire_.clear();
  }

  void NoteSend(const std::string& key, int64_t ns) {
    pending_[key].push_back(ns);
  }

  bool MatchReceive(const std::string& key, int64_t recvNs, int64_t& sendNs) {
    auto it = pending_.find(key);
    if (it == pending_.end()) return false;
    const std::vector<int64_t> attempts = it->second;
    pending_.erase(it);  // do not reuse a stale emission for a later delivery
    if (attempts.size() != 1 || attempts[0] < 0 || attempts[0] > recvNs) return false;
    sendNs = attempts[0];
    return true;
  }

  void NoteWireSend(const std::string& sid, size_t framedBytes) {
    auto& w = wire_[sid];
    ++w.datagrams;
    w.bytes += framedBytes;
  }

  WireUsage Usage(const std::string& sid) const {
    auto it = wire_.find(sid);
    return it == wire_.end() ? WireUsage{} : it->second;
  }

 private:
  std::map<std::string, std::vector<int64_t>> pending_;
  std::map<std::string, WireUsage> wire_;
};

}  // namespace uavma_ns3
#endif  // UAVMA_NS3_MEASUREMENT_LEDGER_H
