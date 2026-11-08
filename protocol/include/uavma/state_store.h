// UAV-Mobility-Auth formal core: durable state store (SQLite).
// The paper mandates three persistence points:
//   (1) target persists Pi before emitting M2,
//   (2) UAV persists S^U <- S^N before emitting M3,
//   (3) target commits S^C <- Pi.next atomically after verifying M3.
// This store performs real file-backed writes so that a process crash between two
// points leaves exactly the state the protocol guarantees (restart recovers it).
#ifndef UAVMA_STATE_STORE_H
#define UAVMA_STATE_STORE_H

#include <optional>
#include <string>

#include "uavma/protocol_core.h"

struct sqlite3;

namespace uavma {

class StateStore {
 public:
  explicit StateStore(const std::string& path);  // file path or ":memory:"
  ~StateStore();

  StateStore(const StateStore&) = delete;
  StateStore& operator=(const StateStore&) = delete;

  void save_committed(Domain d, const State& s);
  bool load_committed(Domain d, State& out);

  void save_pending(Domain d, const std::optional<Pending>& p);
  bool load_pending(Domain d, std::optional<Pending>& out);

  void save_uav(Domain d, const State& s);
  bool load_uav(Domain d, State& out);

  void save_session(Domain d, const Session& s);
  bool load_session(Domain d, const std::string& sid, Session& out);

  void save_meta(const std::string& k, const std::string& v);
  bool load_meta(const std::string& k, std::string& v);

  void close();
  const std::string& path() const { return path_; }

 private:
  void exec(const std::string& sql);
  void bind_and_step(const std::string& sql, const std::vector<Bytes>& blobs,
                     const std::vector<long long>& ints);

  sqlite3* db_ = nullptr;
  std::string path_;
};

}  // namespace uavma

#endif
