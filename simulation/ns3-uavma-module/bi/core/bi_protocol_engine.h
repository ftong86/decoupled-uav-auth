// SPDX-License-Identifier: MIT
// Bi (2026) handover message-level protocol mapping for ns-3 LTE sockets.
// Uses real ECDSA, secp256k1 point arithmetic, AEAD and all required
// M1-M6, C1/C2, context and ACK exchanges. It is a behavioral mapping,
// NOT native NR RRC/RACH or proof-equivalent to the authors' implementation.
#pragma once
#include "bi_mapped_crypto.h"
#include "bi_wire_codec.h"
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace e2b {
enum class Role : std::uint8_t { UE, SourceGnb, TargetGnb, SourceMeh, TargetMeh };
std::string RoleName(Role r);
struct Outbound {
  Role to;
  BiFrame frame;
};
struct EngineResult {
  std::vector<Outbound> send;
  bool prepared_and_verified = false;  // only SourceGnb on authenticated UE READY
  bool terminal_failure = false;
  std::string failure;
};

struct BiSession {
  std::uint16_t targetCell = 0;
  std::uint64_t openedNs = 0;
  int stage = 0;
  bool completion = false;
  BiEphemeral ownFirst;
  BiEphemeral ownSecond;
  Bytes ownKey;
  Bytes gatewayKey;
  Bytes serviceKey;
  Bytes messageM1;
  Bytes messageM3;
  Bytes savedM5;
  Bytes peerR1;
  Bytes peerN1;
  Bytes peerN2;
  Bytes peerR2;
  Bytes targetRtMeh;
  Bytes targetNtGnb;
  Bytes sigTargetMeh;
  Bytes sigTargetGnb;
  std::uint64_t targetTimeMeh = 0;
  std::uint64_t targetTimeGnb = 0;
  Bytes context;
  Bytes previousC1;
};

class BiProtocolEngine {
 public:
  BiProtocolEngine(Role role, Identities& ids, std::string bootstrapSeed);
  EngineResult Begin(std::uint64_t correlation, std::uint16_t targetCell,
                     std::uint64_t nowNs);
  EngineResult Handle(const BiFrame& frame,std::uint64_t nowNs);
  bool Completed(std::uint64_t correlation) const;
  std::uint16_t Target(std::uint64_t correlation) const;
  std::size_t SessionCount() const { return sessions_.size(); }
 private:
  Role role_;
  Identities& identities_;
  std::string seed_;
  std::map<std::uint64_t,BiSession> sessions_;
  Bytes OldKey(char domain) const;
  const EcKey& Key() const;
  static Identity IdentityFor(Role role);
  EngineResult Process(BiSession& s,const BiFrame& frame,std::uint64_t nowNs);
};
} // namespace e2b
