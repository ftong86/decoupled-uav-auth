// UAV-Mobility-Auth formal core: experiment driver utilities.
#include "uavma/experiment_driver.h"

#include <sys/stat.h>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace uavma {
namespace {

std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out += c;
    }
  }
  return out;
}

std::string csv_escape(const std::string& s) {
  bool need = s.find_first_of(",\"\n\r") != std::string::npos;
  if (!need) return s;
  std::string out = "\"";
  for (char c : s)
    if (c == '"')
      out += "\"\"";
    else
      out += c;
  out += "\"";
  return out;
}

}  // namespace

int64_t now_mono_us() {
  static const auto t0 = std::chrono::steady_clock::now();
  return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0)
      .count();
}
int64_t now_mono_ms() { return now_mono_us() / 1000; }

std::string utc_now_iso() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&t, &tm);
  std::ostringstream os;
  os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return os.str();
}

void ensure_dir(const std::string& path) {
  std::string cur;
  for (size_t i = 0; i < path.size(); ++i) {
    cur += path[i];
    if (path[i] == '/' || i + 1 == path.size()) {
      if (cur.empty()) continue;
      mkdir(cur.c_str(), 0755);
    }
  }
}

EventLog::EventLog(const std::string& path, bool echo) : path_(path), echo_(echo) {
  if (!path_.empty()) {
    std::string dir = path_.substr(0, path_.find_last_of('/'));
    if (!dir.empty()) ensure_dir(dir);
    f_.open(path_, std::ios::app);
    if (!f_) throw std::runtime_error("cannot open event log: " + path_);
  }
}

EventLog::~EventLog() { close(); }

void EventLog::close() {
  if (f_.is_open()) f_.close();
}

void EventLog::event(const std::string& type, const std::map<std::string, std::string>& fields) {
  std::ostringstream os;
  os << "{\"t_mono_ms\":" << now_mono_ms() << ",\"utc\":\"" << utc_now_iso() << "\",\"event\":\""
     << json_escape(type) << "\"";
  for (const auto& kv : fields)
    os << ",\"" << json_escape(kv.first) << "\":\"" << json_escape(kv.second) << "\"";
  os << "}";
  if (f_.is_open()) f_ << os.str() << '\n';
  if (echo_) std::cout << os.str() << '\n';
}

CsvWriter::CsvWriter(const std::string& path, const std::vector<std::string>& header) : path_(path) {
  std::string dir = path_.substr(0, path_.find_last_of('/'));
  if (!dir.empty()) ensure_dir(dir);
  f_.open(path_, std::ios::out | std::ios::trunc);
  if (!f_) throw std::runtime_error("cannot open csv: " + path_);
  for (size_t i = 0; i < header.size(); ++i) {
    if (i) f_ << ',';
    f_ << csv_escape(header[i]);
  }
  f_ << '\n';
}

CsvWriter::~CsvWriter() {
  if (f_.is_open()) f_.close();
}

void CsvWriter::row(const std::vector<std::string>& values) {
  for (size_t i = 0; i < values.size(); ++i) {
    if (i) f_ << ',';
    f_ << csv_escape(values[i]);
  }
  f_ << '\n';
}

RunContext::RunContext(const std::string& results_root, const std::string& run_id)
    : run_id_(run_id), dir_(results_root + "/" + run_id), log_(dir_ + "/events.jsonl", false) {
  ensure_dir(dir_);
  write_meta({{"run_id", run_id_}, {"created_utc", utc_now_iso()}});
}

std::string RunContext::path(const std::string& rel) const { return dir_ + "/" + rel; }

void RunContext::write_meta(const std::map<std::string, std::string>& kv) {
  std::ofstream f(path("meta.txt"), std::ios::app);
  for (const auto& p : kv) f << p.first << "=" << p.second << '\n';
}

std::string make_run_id(const std::string& prefix) {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&t, &tm);
  std::ostringstream os;
  os << (prefix.empty() ? "run" : prefix) << std::put_time(&tm, "%Y%m%dT%H%M%SZ");
  return os.str();
}

}  // namespace uavma
