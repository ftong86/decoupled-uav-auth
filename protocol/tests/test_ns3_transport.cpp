// S6 gate: ns-3 / IoD-Sim transport backend.
// This test does NOT fake ns-3 results. Until IoD-Sim v4.1.0 is cloned and frozen
// (stage S1) it reports BLOCKED_ENV and exits with code 65 (EX_UNAVAILABLE).
#include <sys/stat.h>

#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
  const std::string iodsim = argc > 1 ? argv[1] : std::string(getenv("HOME") ? getenv("HOME") : "") +
                                                      "/uav-iodsim-build/IoD_Sim";
  struct stat st{};
  bool present = (::stat(iodsim.c_str(), &st) == 0);
  if (!present) {
    std::cout << "BLOCKED_ENV: IoD-Sim not present at " << iodsim
              << "; stage S1 (clone v4.1.0 + ns-3.45) must complete first.\n";
    std::cout << "TEST_NS3_TRANSPORT BLOCKED_ENV\n";
    return 65;
  }
  std::cout << "TEST_NS3_TRANSPORT: IoD-Sim found; scenario-level checks are implemented in S6.\n";
  std::cout << "TEST_NS3_TRANSPORT PENDING\n";
  return 0;
}
