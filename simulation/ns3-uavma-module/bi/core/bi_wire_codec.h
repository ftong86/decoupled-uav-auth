// SPDX-License-Identifier: MIT
// Development transport framing ONLY. No signature, encryption or Bi authentication.
// Treat all decoded payloads as untrusted until the Bi cryptographic verifier succeeds.
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace e2b {

enum class BiMsg : std::uint8_t {
  PrepM1 = 1, PrepM2, PrepForwardM1, PrepM3, PrepM4, PrepForwardM3,
  PrepC1 = 7, ExecCommand = 8, ExecM5M6 = 9, ExecForwardM5 = 10,
  ExecAck1 = 11, ExecAck12 = 12,
  PrepStart = 13, PrepContext = 14, PrepContextAck = 15, BootstrapHello = 16
};

struct BiFrame {
  BiMsg type = BiMsg::PrepM1;
  std::uint64_t correlation = 0;
  std::uint32_t sequence = 0;
  std::vector<std::uint8_t> payload;
};

class BiWire final {
 public:
  static constexpr std::size_t kHeaderBytes = 24;
  static constexpr std::size_t kMaxPayloadBytes = 16384;

  static bool ValidType(std::uint8_t n) { return n >= 1 && n <= 16; }

  static std::vector<std::uint8_t> Encode(const BiFrame& frame) {
    if (!ValidType(static_cast<std::uint8_t>(frame.type)) || !frame.correlation ||
        frame.payload.size() > kMaxPayloadBytes) {
      throw std::invalid_argument("invalid Bi frame fields");
    }
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderBytes + frame.payload.size());
    out.insert(out.end(), {'B', 'I', 'E', '2'});
    out.push_back(1); // version
    out.push_back(static_cast<std::uint8_t>(frame.type));
    out.push_back(0); // flags reserved
    out.push_back(0); // reserved
    Append(out, frame.correlation, 8);
    Append(out, frame.sequence, 4);
    Append(out, static_cast<std::uint32_t>(frame.payload.size()), 4);
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    return out;
  }

  static BiFrame Decode(const std::vector<std::uint8_t>& input) {
    if (input.size() < kHeaderBytes || input[0] != 'B' || input[1] != 'I' ||
        input[2] != 'E' || input[3] != '2' || input[4] != 1 ||
        !ValidType(input[5]) || input[6] != 0 || input[7] != 0) {
      throw std::invalid_argument("malformed Bi frame header");
    }
    BiFrame result;
    result.type = static_cast<BiMsg>(input[5]);
    result.correlation = Read(input, 8, 8);
    result.sequence = static_cast<std::uint32_t>(Read(input, 16, 4));
    const auto size = static_cast<std::size_t>(Read(input, 20, 4));
    if (!result.correlation || size > kMaxPayloadBytes ||
        size != input.size() - kHeaderBytes) {
      throw std::invalid_argument("invalid Bi frame length or correlation");
    }
    result.payload.assign(input.begin() + kHeaderBytes, input.end());
    return result;
  }
 private:
  static void Append(std::vector<std::uint8_t>& v, std::uint64_t x, std::size_t count) {
    for (std::size_t i = count; i != 0; --i) {
      v.push_back(static_cast<std::uint8_t>((x >> (8 * (i - 1))) & 0xff));
    }
  }
  static std::uint64_t Read(const std::vector<std::uint8_t>& v,
                            std::size_t pos, std::size_t count) {
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < count; ++i) {
      result = (result << 8) | v[pos + i];
    }
    return result;
  }
};
} // namespace e2b
