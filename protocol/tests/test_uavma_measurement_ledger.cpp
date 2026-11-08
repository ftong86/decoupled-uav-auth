// Native C++17 tests: measurement-only; no ns-3 or frozen protocol dependencies.
#include "uavma-measurement-ledger.h"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>

int main() {
  using uavma_ns3::MeasurementLedger;
  MeasurementLedger d;
  using uavma_ns3::RetransmissionLookupKey;
  assert(RetransmissionLookupKey("", "AuthzU", "authz:G:1") == "authz:G:1");
  assert(RetransmissionLookupKey("", "AuthzU", "authz:E:1") == "authz:E:1");
  assert(RetransmissionLookupKey("sid-1", "M2", "unused") == "sid-1|M2");
  int64_t sent = -1;

  // Ordinary message: exactly one pending on-wire attempt.
  d.NoteSend("G|sid-1|M2", 1000000000LL);
  assert(d.MatchReceive("G|sid-1|M2", 1003000000LL, sent));
  assert(sent == 1000000000LL);
  assert(!d.MatchReceive("G|sid-1|M2", 1004000000LL, sent));

  // Successfully received first M2, later timeout resend has a unique match.
  d.NoteSend("G|sid-1|M2", 1250000000LL);
  assert(d.MatchReceive("G|sid-1|M2", 1253000000LL, sent));
  assert(sent == 1250000000LL);

  // First M3 is deliberately suppressed: no NoteSend; cache retry is first
  // real wire attempt (must not be attributed to the suppressed M3).
  assert(!d.MatchReceive("G|sid-1|M3", 1500000000LL, sent));
  d.NoteSend("G|sid-1|M3", 1503000000LL);
  assert(d.MatchReceive("G|sid-1|M3", 1510000000LL, sent));
  assert(sent == 1503000000LL);

  // Loss/reordering cannot be uniquely attributed when two identical copies
  // are in flight. Do not claim ARQ wait as one-way transport latency.
  d.NoteSend("G|sid-2|M1", 2000000000LL);
  d.NoteSend("G|sid-2|M1", 2250000000LL);
  assert(!d.MatchReceive("G|sid-2|M1", 2253000000LL, sent));
  assert(!d.MatchReceive("G|sid-2|M1", 2254000000LL, sent));
  d.NoteSend("G|sid-2|M1", 2500000000LL);
  assert(d.MatchReceive("G|sid-2|M1", 2503000000LL, sent));
  assert(sent == 2500000000LL);

  // Domain-separated authorization keys (same epoch in G and E).
  d.NoteSend("Authz|G|1", 100);
  d.NoteSend("Authz|E|1", 120);
  assert(d.MatchReceive("Authz|E|1", 180, sent) && sent == 120);
  assert(d.MatchReceive("Authz|G|1", 190, sent) && sent == 100);

  // Invalid timestamps and unknown keys must not create spurious latencies.
  assert(!d.MatchReceive("absent", 10, sent));
  d.NoteSend("time-inversion", 20);
  assert(!d.MatchReceive("time-inversion", 10, sent));
  d.NoteSend("time-zero", 0);
  assert(d.MatchReceive("time-zero", 0, sent) && sent == 0);

  // True UDP payload accounting: 5 logical sends, plus on-wire repeats;
  // controlled loss is absent from the wire count.
  for (size_t n : {22u, 266u, 208u, 61u, 61u}) d.NoteWireSend("G-SID", n);
  auto w = d.Usage("G-SID");
  assert(w.datagrams == 5 && w.bytes == 618);
  d.NoteWireSend("G-SID", 61);  // retry M2
  w = d.Usage("G-SID");
  assert(w.datagrams == 6 && w.bytes == 679);
  d.NoteWireSend("E-SID", 22);
  assert(d.Usage("E-SID").datagrams == 1 && d.Usage("E-SID").bytes == 22);
  assert(d.Usage("missing").bytes == 0);
  d.NoteWireSend("zero-len", 0);
  assert(d.Usage("zero-len").datagrams == 1 && d.Usage("zero-len").bytes == 0);

  d.Reset();
  assert(d.Usage("G-SID").datagrams == 0);
  assert(!d.MatchReceive("G|sid-1|M2", 9999999999LL, sent));
  std::cout << "TEST_UAVMA_MEASUREMENT_LEDGER PASS\\n";
  return 0;
}
