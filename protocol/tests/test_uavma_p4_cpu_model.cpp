#include "uavma-p4-cpu-model.h"
#include <cassert>
#include <cmath>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace uavma_ns3;

template<class F> void rejects(F f) { bool threw = false; try { f(); } catch (const std::exception&) { threw = true; } assert(threw); }
int main() {
  std::string encoded;
  for (const auto& key : RequiredE1Handlers()) {
    if (!encoded.empty()) encoded += ';';
    encoded += key + "=125.25";
  }
  auto profile = ParseE1CostProfile(encoded);
  assert(profile.size() == 12);
  assert(HandlerServiceNs(profile, 'G', {"uav_handle_M0", "uav_build_M1"}) == 250500);
  assert(HandlerServiceNs(profile, 'E', {"target_handle_M3"}) == 125250);
  CpuQueueModel independent("PER_DOMAIN");
  auto a = independent.Reserve(1000000, 'G', 250500);
  auto b = independent.Reserve(1000000, 'E', 125250);
  assert(a.queueNs == 0 && b.queueNs == 0 && a.finishNs == 1250500);
  auto c = independent.Reserve(1000000, 'G', 250500);
  assert(c.queueNs == 250500 && c.finishNs == 1501000);
  CpuQueueModel shared("SHARED");
  auto d = shared.Reserve(1000000, 'G', 250500);
  auto e = shared.Reserve(1000000, 'E', 125250);
  assert(d.finishNs == 1250500 && e.queueNs == 250500 && e.finishNs == 1375750);
  rejects([&]{ ParseE1CostProfile(""); });
  rejects([&]{ ParseE1CostProfile(encoded + ";unknown_G=10"); });
  rejects([&]{ ParseE1CostProfile(encoded + ";"); });
  rejects([&]{ ParseE1CostProfile(encoded.substr(0, encoded.find(';'))); });
  rejects([&]{ ParseE1CostProfile(encoded + ";" + RequiredE1Handlers()[0] + "=5"); });
  rejects([&]{ ParseE1CostProfile(std::string("target_create_session_M0_G=NaN;") + encoded); });
  rejects([&]{ independent.Reserve(-1, 'G', 100); });
  rejects([&]{ independent.Reserve(1, 'G', 0); });
  rejects([&]{ independent.Reserve(1, 'X', 10); });
  rejects([&]{ CpuQueueModel("UNFAIR"); });
  rejects([&]{ HandlerServiceNs(profile, 'G', {"missing_handler"}); });
  std::cout << "TEST_UAVMA_P4_CPU_MODEL PASS\n";
}
