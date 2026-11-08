#include "uavma-event-policy.h"
#include <cassert>
#include <iostream>
#include <string>

using namespace uavma_ns3;
int main() {
  Variant v;
  assert(ParseVariant("P", &v) && v == Variant::P);
  assert(ParseVariant("A_JOINT", &v) && v == Variant::AJoint);
  assert(!ParseVariant("A-Joint", &v));
  assert(!ParseVariant("", &v));
  assert(!ParseVariant("P", nullptr));
  for (auto mode : {Variant::P, Variant::AJoint}) {
    const auto none = Select(mode, Event::None);
    assert(!none.g && !none.e);
    const auto ge = Select(mode, Event::GE);
    assert(ge.g && ge.e);
    const auto g = Select(mode, Event::GOnly);
    const auto e = Select(mode, Event::EOnly);
    if (mode == Variant::P) {
      assert(g.g && !g.e); assert(!e.g && e.e);
    } else {
      assert(g.g && g.e); assert(e.g && e.e);
    }
  }
  assert(std::string(EventName(Event::GE)) == "GE");
  assert(std::string(EventName(Event::GOnly)) == "G_only");
  assert(std::string(EventName(Event::EOnly)) == "E_only");
  assert(AuthzKey('G', 1) != AuthzKey('E', 1));
  assert(AuthzKey('E', 1) != AuthzKey('E', 2));
  assert(MatchTargetDomain("GS_T1", "GS_T1", "ES_T1", true, true) == 'G');
  assert(MatchTargetDomain("ES_T1", "GS_T1", "ES_T1", true, true) == 'E');
  assert(MatchTargetDomain("BAD", "GS_T1", "ES_T1", true, true) == 0);
  assert(MatchTargetDomain("SAME", "SAME", "SAME", true, true) == 0);
  assert(MatchTargetDomain("ES_T1", "GS_T1", "ES_T1", true, false) == 0);
  // A bounded M3 cache with RTO=250 ms and max 3 infra retries.
  assert(AllowCachedM3Replay(0, 0, 250.0, 0, 3));
  assert(AllowCachedM3Replay(750000000, 0, 250.0, 2, 3));
  assert(AllowCachedM3Replay(1000000000, 0, 250.0, 2, 3));
  assert(!AllowCachedM3Replay(1000000001, 0, 250.0, 2, 3));
  assert(!AllowCachedM3Replay(100, 0, 250.0, 3, 3));
  assert(!AllowCachedM3Replay(0, -1, 250.0, 0, 3));
  assert(!AllowCachedM3Replay(0, 10, 250.0, 0, 3));
  assert(!AllowCachedM3Replay(10, 0, 0.0, 0, 3));
  assert(!AllowCachedM3Replay(10, 0, 250.0, 0, 0));
  std::cout << "TEST_UAVMA_EVENT_POLICY PASS\n";
}
