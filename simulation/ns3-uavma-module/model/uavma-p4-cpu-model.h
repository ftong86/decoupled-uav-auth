// P4 CPU processing calibration model (simulation plumbing, not protocol logic).
// Inputs are pure-handler E1 Linux measurements, never wall clock time observed
// while ns-3 is running. Reservation moves scheduled simulation events only.
#ifndef UAVMA_P4_CPU_MODEL_H
#define UAVMA_P4_CPU_MODEL_H

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace uavma_ns3 {

inline const std::vector<std::string>& RequiredE1Handlers() {
  static const std::vector<std::string> keys = {
    "target_create_session_M0_G", "uav_handle_M0_G", "uav_build_M1_G",
    "target_handle_M1_G", "uav_handle_M2_G", "target_handle_M3_G",
    "target_create_session_M0_E", "uav_handle_M0_E", "uav_build_M1_E",
    "target_handle_M1_E", "uav_handle_M2_E", "target_handle_M3_E"
  };
  return keys;
}

inline std::map<std::string, double> ParseE1CostProfile(const std::string& text) {
  if (text.empty()) throw std::invalid_argument("E1 calibrated handler profile missing");
  std::map<std::string, double> result;
  std::size_t start = 0;
  while (start < text.size()) {
    const auto end = text.find(';', start);
    const std::string field = text.substr(start, end == std::string::npos
                                                    ? std::string::npos : end - start);
    const auto eq = field.find('=');
    if (eq == std::string::npos || eq == 0 || eq + 1 >= field.size() ||
        field.find('=', eq + 1) != std::string::npos)
      throw std::invalid_argument("invalid E1 handler cost entry");
    const std::string key = field.substr(0, eq);
    if (std::find(RequiredE1Handlers().begin(), RequiredE1Handlers().end(), key) ==
        RequiredE1Handlers().end() || result.count(key))
      throw std::invalid_argument("unknown/duplicate E1 handler: " + key);
    std::size_t used = 0;
    double us = 0;
    try { us = std::stod(field.substr(eq + 1), &used); }
    catch (const std::exception&) { throw std::invalid_argument("invalid E1 cost number: " + key); }
    if (used != field.size() - eq - 1 || !std::isfinite(us) || us <= 0 || us > 1.0e7)
      throw std::invalid_argument("E1 cost out of bounds: " + key);
    result.emplace(key, us);
    if (end == std::string::npos) break;
    start = end + 1;
    if (start == text.size()) throw std::invalid_argument("trailing E1 field delimiter");
  }
  if (result.size() != RequiredE1Handlers().size())
    throw std::invalid_argument("incomplete E1 handler profile");
  return result;
}

inline std::int64_t HandlerServiceNs(const std::map<std::string, double>& profile,
                                      char domain, const std::vector<std::string>& stages) {
  if (domain != 'G' && domain != 'E') throw std::invalid_argument("invalid CPU domain");
  if (stages.empty()) throw std::invalid_argument("empty handler stage sequence");
  std::int64_t total = 0;
  for (const auto& stage : stages) {
    const auto it = profile.find(stage + "_" + domain);
    if (it == profile.end()) throw std::invalid_argument("missing CPU stage: " + stage);
    const auto nanos = static_cast<std::int64_t>(std::llround(it->second * 1000.0));
    if (nanos <= 0 || nanos > std::numeric_limits<std::int64_t>::max() - total)
      throw std::overflow_error("invalid CPU stage nanoseconds");
    total += nanos;
  }
  return total;
}

struct CpuReservation {
  std::int64_t arrivalNs = 0;
  std::int64_t startNs = 0;
  std::int64_t finishNs = 0;
  std::int64_t serviceNs = 0;
  std::int64_t queueNs = 0;
  std::int64_t delayNs = 0; // wait + calibrated service, NOT real host CPU time
};

class CpuQueueModel {
 public:
  explicit CpuQueueModel(const std::string& mode = "PER_DOMAIN") { SetMode(mode); }
  void SetMode(const std::string& mode) {
    if (mode != "PER_DOMAIN" && mode != "SHARED")
      throw std::invalid_argument("CpuResourceMode must be PER_DOMAIN or SHARED");
    mode_ = mode;
    available_.clear();
  }
  const std::string& Mode() const { return mode_; }
  CpuReservation Reserve(std::int64_t nowNs, char domain, std::int64_t serviceNs) {
    if (nowNs < 0 || serviceNs <= 0 ||
        serviceNs > std::numeric_limits<std::int64_t>::max() - nowNs)
      throw std::invalid_argument("invalid CPU reservation time");
    if (domain != 'G' && domain != 'E') throw std::invalid_argument("invalid CPU domain");
    const char lane = mode_ == "SHARED" ? 'S' : domain;
    const std::int64_t start = std::max(nowNs, available_[lane]);
    if (serviceNs > std::numeric_limits<std::int64_t>::max() - start)
      throw std::overflow_error("CPU reservation overflow");
    const std::int64_t finish = start + serviceNs;
    available_[lane] = finish;
    return {nowNs, start, finish, serviceNs, start - nowNs, finish - nowNs};
  }
 private:
  std::string mode_;
  std::map<char, std::int64_t> available_;
};

} // namespace uavma_ns3
#endif
