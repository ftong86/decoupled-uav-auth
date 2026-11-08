// UAV-Mobility-Auth formal core: stateful edge service and migration engine (E4).
// The service is shared by every compared scheme; only the authorization gate differs.
// Application state transfer (B_app) is recorded separately from the protocol Transfer
// message and must never be counted as the same message.
#ifndef UAVMA_SERVICE_CORE_H
#define UAVMA_SERVICE_CORE_H

#include <cstdint>
#include <string>
#include <vector>

#include "uavma/bytes.h"

namespace uavma {

// Application business state: request_id set, processed set, cumulative counter.
struct ServiceState {
  uint64_t counter = 0;
  uint64_t cursor = 0;
  std::vector<std::string> processed;
  Bytes serialize() const;
  static ServiceState deserialize(const Bytes& b);
  size_t bytes() const { return serialize().size(); }
};

struct ServiceEvent {
  int64_t t_ms = 0;
  std::string node;
  std::string request_id;
  bool authorized = false;
  bool correct = false;
  bool duplicate = false;
  std::string reason;
  uint64_t auth_epoch = 0;
  uint64_t counter_after = 0;
};

struct OutageInterval {
  int64_t start_ms = 0;   // last correct response at the source
  int64_t end_ms = 0;     // first correct authorized response at the target
  int64_t duration_ms = 0;
  std::string cause;
};

class ServiceCore {
 public:
  explicit ServiceCore(std::string node_id);

  const std::string& node() const { return node_; }

  // E-domain commit gate. A target may answer the client only after the E domain
  // has committed AND the application state has been installed.
  void set_authorized(bool ok, uint64_t epoch);
  bool authorized() const { return authorized_; }
  uint64_t auth_epoch() const { return auth_epoch_; }

  void install_state(const ServiceState& s);
  bool state_installed() const { return state_installed_; }
  const ServiceState& state() const { return state_; }

  // Returns true only for a correct, authorized, non-duplicated response.
  bool handle_request(const std::string& request_id, int64_t t_ms, std::string& response,
                      std::string* reason);

  const std::vector<ServiceEvent>& events() const { return events_; }
  std::string last_correct_response_at() const;

 private:
  std::string node_;
  bool authorized_ = false;
  uint64_t auth_epoch_ = 0;
  bool state_installed_ = false;
  ServiceState state_;
  std::vector<ServiceEvent> events_;
};

// Source -> target application state handover (B_app), counted separately.
struct AppMigration {
  std::string from;
  std::string to;
  size_t bytes = 0;
  int64_t t_ms = 0;
  uint64_t epoch = 0;
};

}  // namespace uavma

#endif
