// ns-3 / IoD-Sim transport backend check.
// Returns 65 (EX_UNAVAILABLE) when the external IoD-Sim build tree is absent.
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
    std::cout << "IoD-Sim build tree not found at " << iodsim << "\n";
    std::cout << "TEST_NS3_TRANSPORT UNAVAILABLE\n";
    return 65;
  }
  std::cout << "TEST_NS3_TRANSPORT: IoD-Sim found; scenario-level checks are implemented in S6.\n";
  std::cout << "TEST_NS3_TRANSPORT PENDING\n";
  return 0;
}
