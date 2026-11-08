// UAV-Mobility-Auth formal core: Linux transport implementation.
#include "uavma/linux_transport.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <thread>

namespace uavma {

Bytes Framing::encode(MsgKind kind, const Bytes& payload) {
  Bytes out;
  uint32_t n = static_cast<uint32_t>(payload.size() + 1);
  Bytes len = be32(n);
  out.insert(out.end(), len.begin(), len.end());
  out.push_back(static_cast<uint8_t>(kind));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

bool Framing::decode(const Bytes& buf, size_t& off, MsgKind& kind, Bytes& payload) {
  if (off + 4 > buf.size()) return false;
  uint32_t n = (static_cast<uint32_t>(buf[off]) << 24) | (static_cast<uint32_t>(buf[off + 1]) << 16) |
               (static_cast<uint32_t>(buf[off + 2]) << 8) | static_cast<uint32_t>(buf[off + 3]);
  if (n < 1) return false;
  if (off + 4 + n > buf.size()) return false;
  kind = static_cast<MsgKind>(buf[off + 4]);
  payload.assign(buf.begin() + off + 5, buf.begin() + off + 4 + n);
  off += 4 + n;
  return true;
}

bool FaultPolicy::should_drop(MsgKind k) const {
  switch (k) {
    case MsgKind::M0: return drop_m0;
    case MsgKind::M1: return drop_m1;
    case MsgKind::M2: return drop_m2;
    case MsgKind::M3: return drop_m3;
    default: return false;
  }
}

std::string FaultPolicy::describe() const {
  std::string s;
  if (drop_m0) s += "dropM0,";
  if (drop_m1) s += "dropM1,";
  if (drop_m2) s += "dropM2,";
  if (drop_m3) s += "dropM3,";
  if (duplicate) s += "dup,";
  if (delay_ms) s += "delay" + std::to_string(delay_ms) + "ms,";
  return s.empty() ? "none" : s;
}

Socket::Socket() = default;
Socket::Socket(int fd) : fd_(fd) {}

Socket::~Socket() { close(); }

void Socket::close() {
  if (fd_ >= 0) {
    ::shutdown(fd_, SHUT_RDWR);
    ::close(fd_);
    fd_ = -1;
  }
}

void Socket::detach() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

void Socket::shutdown_rd() {
  if (fd_ >= 0) ::shutdown(fd_, SHUT_RD);
}

bool Socket::listen_on(uint16_t port, int backlog) {
  fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd_ < 0) return false;
  int one = 1;
  setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);
  if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
  if (::listen(fd_, backlog) != 0) return false;
  return true;
}

bool Socket::connect_to(uint16_t port, const std::string& host) {
  fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd_ < 0) return false;
  int one = 1;
  setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (host == "127.0.0.1")
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  else
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
  for (int attempt = 0; attempt < 100; ++attempt) {
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

std::unique_ptr<Socket> Socket::accept_one(int timeout_ms) {
  pollfd p{};
  p.fd = fd_;
  p.events = POLLIN;
  int r = ::poll(&p, 1, timeout_ms);
  if (r <= 0) return nullptr;
  int c = ::accept(fd_, nullptr, nullptr);
  if (c < 0) return nullptr;
  int one = 1;
  setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  return std::unique_ptr<Socket>(new Socket(c));
}

bool Socket::send_all(const Bytes& b) {
  size_t sent = 0;
  while (sent < b.size()) {
    ssize_t n = ::send(fd_, b.data() + sent, b.size() - sent, 0);
    if (n <= 0) return false;
    sent += static_cast<size_t>(n);
  }
  return true;
}

bool Socket::recv_exact(size_t n, Bytes& out) {
  out.resize(n);
  size_t got = 0;
  while (got < n) {
    ssize_t r = ::recv(fd_, out.data() + got, n - got, 0);
    if (r <= 0) return false;
    got += static_cast<size_t>(r);
  }
  return true;
}

bool Socket::send_frame(MsgKind kind, const Bytes& payload) {
  return send_all(Framing::encode(kind, payload));
}

bool Socket::recv_frame(MsgKind& kind, Bytes& payload) {
  Bytes hdr;
  if (!recv_exact(4, hdr)) return false;
  uint32_t n = (static_cast<uint32_t>(hdr[0]) << 24) | (static_cast<uint32_t>(hdr[1]) << 16) |
               (static_cast<uint32_t>(hdr[2]) << 8) | static_cast<uint32_t>(hdr[3]);
  if (n < 1 || n > (1u << 20)) return false;
  Bytes body;
  if (!recv_exact(n, body)) return false;
  kind = static_cast<MsgKind>(body[0]);
  payload.assign(body.begin() + 1, body.end());
  return true;
}

}  // namespace uavma
