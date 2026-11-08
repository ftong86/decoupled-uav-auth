#include "uavma-cell-partition.h"
#include <cassert>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

using uavma_ns3::Event;
using uavma_ns3::ParseCellToEdge;
using uavma_ns3::DecideHandover;

static void rejected(const std::function<void()>& f) {
  bool threw = false;
  try { f(); } catch (const std::invalid_argument&) { threw = true; }
  assert(threw);
}

int main() {
  const auto same = ParseCellToEdge("1:ES_T1,2:ES_T1,3:ES_T2");
  assert(same.size() == 3);
  auto gOnly = DecideHandover(same, 1, 2);
  assert(gOnly.event == Event::GOnly && !gOnly.edgeChanged);
  assert(gOnly.sourceEdge == "ES_T1" && gOnly.targetEdge == "ES_T1");
  assert(gOnly.targetG == "GS_CELL_2");
  auto ge = DecideHandover(same, 2, 3);
  assert(ge.event == Event::GE && ge.edgeChanged);
  assert(ge.targetG == "GS_CELL_3" && ge.targetEdge == "ES_T2");
  auto reverse = DecideHandover(same, 3, 2);
  assert(reverse.event == Event::GE && reverse.targetEdge == "ES_T1");

  for (auto bad : {"", "1:ES_A,", ",1:ES_A", "1", "1:", "0:ES_A", "65536:ES_A",
                   "-1:ES_A", "01:ES_A", "1:ES_A,1:ES_B", "1:ES_A:invalid",
                   "1:ES A", "1:ES/A", "1:ES_A,2:ES_A,2:ES_B"}) {
    rejected([=] { (void)ParseCellToEdge(bad); });
  }
  rejected([&] { (void)DecideHandover(same, 3, 4); });
  rejected([&] { (void)DecideHandover(same, 0, 1); });
  rejected([&] { (void)DecideHandover(same, 1, 1); });
  rejected([&] { (void)ParseCellToEdge("1:GS_CELL_2,2:ES_T2"); });
  assert(uavma_ns3::Select(uavma_ns3::Variant::P, gOnly.event).g);
  assert(!uavma_ns3::Select(uavma_ns3::Variant::P, gOnly.event).e);
  assert(uavma_ns3::Select(uavma_ns3::Variant::AJoint, gOnly.event).e);
  assert(uavma_ns3::Select(uavma_ns3::Variant::P, ge.event).e);
  std::cout << "TEST_UAVMA_CELL_PARTITION PASS\n";
}
