// UAV-Mobility-Auth formal core: Linux transport (real sockets, real framing).
// Framing overhead is accounted separately from message body/encoded bytes so that
// paper fixed-field budgets are never confused with actual wire bytes.
#ifndef UAVMA_LINUX_TRANSPORT_H
#define UAVMA_LINUX_TRANSPORT_H

#include <cstdint>
#include <memory>
#include <string>

#include "uavma/bytes.h"
#include "uavma/protocol_core.h"

namespace uavma {

constexpr size_t kFrameHeaderBytes = 5;  // 4-byte length + 1-byte message kind

class Framing {
 public:
  static Bytes encode(MsgKind kind, const Bytes& payload);
  // Decodes one frame from buf starting at off; advances off. Returns false if incomplete.
  static bool decode(const Bytes& buf, size_t& off, MsgKind& kind, Bytes& payload);
};

class Socket {
 public:
  Socket();
  explicit Socket(int fd);
  ~Socket();
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  bool listen_on(uint16_t port, int backlog = 8);
  bool connect_to(uint16_t port, const std::string& host = "127.0.0.1");
  std::unique_ptr<Socket> accept_one(int timeout_ms = 5000);
  bool send_frame(MsgKind kind, const Bytes& payload);
  bool recv_frame(MsgKind& kind, Bytes& payload);
  bool send_all(const Bytes& b);
  bool recv_exact(size_t n, Bytes& out);
  void shutdown_rd();
  void close();
  // Releases this descriptor WITHOUT shutdown(): after fork() the file description
  // is shared, and shutdown() would also disable the parent's listening socket.
  void detach();
  bool valid() const { return fd_ >= 0; }
  int fd() const { return fd_; }

 private:
  int fd_ = -1;
};

// Deterministic fault injection for E3b (loss of M2/M3, duplicates, delay).
struct FaultPolicy {
  bool drop_m0 = false;
  bool drop_m1 = false;
  bool drop_m2 = false;
  bool drop_m3 = false;
  bool duplicate = false;
  int delay_ms = 0;
  bool should_drop(MsgKind k) const;
  std::string describe() const;
};

// Byte accounting for one transmitted message.
struct WireAccount {
  std::string msg;
  size_t body = 0;         // logical field bytes
  size_t encoded = 0;      // canonical Enc output (with length prefixes)
  size_t framed = 0;       // encoded + framing
  size_t paper_reference = 0;  // fixed-field budget from docs/field_ledger.md (design-level)
};

inline WireAccount account_wire(const std::string& name, const ByteAccount& a,
                                size_t paper_reference = 0) {
  WireAccount w;
  w.msg = name;
  w.body = a.body;
  w.encoded = a.encoded;
  w.framed = a.encoded + kFrameHeaderBytes;
  w.paper_reference = paper_reference;
  return w;
}

}  // namespace uavma

#endif
