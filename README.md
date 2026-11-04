# Decoupled Authentication for UAV Handover and Edge Service Migration Without Clock Synchronization

This is the official repository for our research paper, which proposes a decoupled authentication protocol for UAV communication handover and edge service migration without requiring clock synchronization. The protocol supports independent authentication across communication and edge service domains, with evolving signing credentials and state recovery mechanisms.

## 📢 Code Release Notice

This repository currently serves as a placeholder. The complete protocol implementation, Tamarin security verification models, ns-3 simulation code, and related experimental scripts are planned to be released upon acceptance of the paper. Thank you for your interest and patience!

## 🌟 Key Contributions

* **Decoupled Authentication:** Establishes independent authentication mechanisms for communication handover and edge service migration, allowing each procedure to execute separately without redundant authentication.
* **Freshness Verification Without Clock Synchronization:** Verifies message freshness using mobility authorization epochs, authenticated session binding, and protocol state, without requiring synchronized clocks.
* **PUF-Based Credential Evolution and State Recovery:** Derives evolving UAV signing credentials using a physical unclonable function (PUF) and introduces state commitment and recovery mechanisms to handle interrupted authentication and message loss.
