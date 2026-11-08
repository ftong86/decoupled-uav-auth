// UAV-Mobility-Auth formal core: canonical byte encoding (paper Sec.V-A, Eq.(1)).
// Enc is an injective canonical encoding: every field is length-prefixed (4-byte
// big endian) so that concatenation is unambiguous.
#ifndef UAVMA_BYTES_H
#define UAVMA_BYTES_H

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

namespace uavma {

using Bytes = std::vector<uint8_t>;

inline Bytes text(const std::string& s) { return Bytes(s.begin(), s.end()); }

inline std::string untext(const Bytes& b) { return std::string(b.begin(), b.end()); }

inline Bytes be32(uint32_t n) {
  return Bytes{static_cast<uint8_t>(n >> 24), static_cast<uint8_t>(n >> 16),
               static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n)};
}

// Enc(x1..xn): 4-byte length prefix per field.
inline Bytes enc(std::initializer_list<Bytes> xs) {
  Bytes out;
  for (const Bytes& x : xs) {
    Bytes n = be32(static_cast<uint32_t>(x.size()));
    out.insert(out.end(), n.begin(), n.end());
    out.insert(out.end(), x.begin(), x.end());
  }
  return out;
}

inline Bytes enc_vec(const std::vector<Bytes>& xs) {
  Bytes out;
  for (const Bytes& x : xs) {
    Bytes n = be32(static_cast<uint32_t>(x.size()));
    out.insert(out.end(), n.begin(), n.end());
    out.insert(out.end(), x.begin(), x.end());
  }
  return out;
}

inline void append_enc(Bytes& out, const Bytes& x) {
  Bytes n = be32(static_cast<uint32_t>(x.size()));
  out.insert(out.end(), n.begin(), n.end());
  out.insert(out.end(), x.begin(), x.end());
}

inline std::string hex(const Bytes& b) {
  static const char* hs = "0123456789abcdef";
  std::string s;
  s.reserve(b.size() * 2);
  for (uint8_t v : b) {
    s.push_back(hs[v >> 4]);
    s.push_back(hs[v & 15]);
  }
  return s;
}

inline Bytes unhex(const std::string& s) {
  Bytes out;
  out.reserve(s.size() / 2);
  auto nv = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i + 1 < s.size(); i += 2) {
    int hi = nv(s[i]), lo = nv(s[i + 1]);
    if (hi < 0 || lo < 0) break;
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

inline std::string hex_prefix(const Bytes& b, size_t n = 8) {
  std::string h = hex(b);
  return h.size() > n * 2 ? h.substr(0, n * 2) : h;
}

}  // namespace uavma

#endif
