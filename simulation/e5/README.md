# E5 ns-3 Module Overlay

The multi-UAV experiments use an extended version of the `uavma` contrib module. Each UAV keeps its own protocol state on the shared infrastructure node, while all target applications reserve modeled CPU lanes through one node-wide pool.

| Path | Purpose |
| --- | --- |
| `model/uavma-ns3-transport.cc`, `model/uavma-ns3-transport.h` | E5 transport with per-session isolation and shared-node CPU reservation |
| `model/uavma-e5-cpu-pool.h` | Node-wide CPU lane pool shared by all target applications |
| `CMakeLists.txt` | E5 build variant that lists `uavma-e5-cpu-pool.h` among the public headers |
| `patches/main.cc.concurrent-ue-streams.patch` | Distinct ns-3 random streams for concurrent UEs |
| `patches/main.cc.three-cell-x2.diff` | X2 mesh kept within each three-cell corridor |

To build these scenes, copy the three files in `model/` into `<IoD-Sim>/ns3/contrib/uavma/model/` and add `model/uavma-e5-cpu-pool.h` to `public_headers` in the module `CMakeLists.txt` (or use the `CMakeLists.txt` in this directory). The remaining headers and the protocol core sources come from `simulation/ns3-uavma-module/`. Apply the two patches to the IoD-Sim `src/main.cc` before reconfiguring the ns-3 build tree.

Scene generation is described in `scripts/e5/README.md`; build and execution commands are listed in `docs/ENVIRONMENT.md`.
