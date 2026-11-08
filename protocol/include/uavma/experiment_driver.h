// UAV-Mobility-Auth formal core: experiment driver utilities (logging, clock, run context).
// Every experiment writes its own directory; nothing is overwritten.
#ifndef UAVMA_EXPERIMENT_DRIVER_H
#define UAVMA_EXPERIMENT_DRIVER_H

#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "uavma/bytes.h"

namespace uavma {

// Monotonic clock: used for all latency accounting so wall-clock jumps cannot
// distort measurements. Wall-clock is recorded separately for provenance only.
int64_t now_mono_ms();
int64_t now_mono_us();
std::string utc_now_iso();

// Append-only event log (JSON lines). One file per run.
class EventLog {
 public:
  explicit EventLog(const std::string& path, bool echo = false);
  ~EventLog();
  void event(const std::string& type, const std::map<std::string, std::string>& fields);
  void close();
  const std::string& path() const { return path_; }

 private:
  std::string path_;
  std::ofstream f_;
  bool echo_;
};

// Minimal CSV writer with an explicit header contract.
class CsvWriter {
 public:
  CsvWriter(const std::string& path, const std::vector<std::string>& header);
  ~CsvWriter();
  void row(const std::vector<std::string>& values);
  const std::string& path() const { return path_; }

 private:
  std::string path_;
  std::ofstream f_;
};

// Run context: one directory per run_id under results/formal/<run_id>.
class RunContext {
 public:
  RunContext(const std::string& results_root, const std::string& run_id);
  const std::string& run_id() const { return run_id_; }
  const std::string& dir() const { return dir_; }
  std::string path(const std::string& rel) const;
  EventLog& log() { return log_; }
  void write_meta(const std::map<std::string, std::string>& kv);

 private:
  std::string run_id_;
  std::string dir_;
  EventLog log_;
};

std::string make_run_id(const std::string& prefix);

// Filesystem helpers (create directories recursively).
void ensure_dir(const std::string& path);

}  // namespace uavma

#endif
