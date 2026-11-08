// Deterministic deployment-only mapping from real LTE cell IDs to LOGICAL edge
// authentication targets. No E4 application-state migration is represented here.
// This file is adapter policy, not a change to protocol messages or cryptography.
#ifndef UAVMA_NS3_CELL_PARTITION_H
#define UAVMA_NS3_CELL_PARTITION_H

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>

#include "uavma-event-policy.h"

namespace uavma_ns3 {

using CellToEdge = std::map<std::uint16_t, std::string>;

inline std::uint16_t ParseCellNumber(const std::string& token) {
  if (token.empty()) throw std::invalid_argument("empty LTE cell ID");
  std::uint32_t number = 0;
  for (const char c : token) {
    if (c < '0' || c > '9') throw std::invalid_argument("LTE cell ID must be decimal digits");
    number = number * 10u + static_cast<unsigned>(c - '0');
    if (number > 65535u) throw std::invalid_argument("LTE cell ID exceeds uint16");
  }
  if (number == 0) throw std::invalid_argument("LTE cell ID 0 is not accepted");
  if (token != std::to_string(number))
    throw std::invalid_argument("LTE cell ID must use canonical decimal representation");
  return static_cast<std::uint16_t>(number);
}

inline bool ValidEdgeId(const std::string& id) {
  if (id.empty() || id.size() > 64) return false;
  for (const char c : id) {
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
  }
  return true;
}

// Example "1:ES_T1,2:ES_T1,3:ES_T2"; fully specified, immutable at runtime.
// A mapping does not create an edge host, migrate application state or place jobs.
inline CellToEdge ParseCellToEdge(const std::string& encoded) {
  if (encoded.empty()) throw std::invalid_argument("empty CellToEdgeMap");
  CellToEdge map;
  size_t start = 0;
  while (start < encoded.size()) {
    const size_t comma = encoded.find(',', start);
    const size_t end = comma == std::string::npos ? encoded.size() : comma;
    const std::string entry = encoded.substr(start, end - start);
    const size_t colon = entry.find(':');
    if (colon == std::string::npos || entry.find(':', colon + 1) != std::string::npos)
      throw std::invalid_argument("CellToEdgeMap entries must be cell:edge");
    const auto cell = ParseCellNumber(entry.substr(0, colon));
    const std::string edge = entry.substr(colon + 1);
    if (!ValidEdgeId(edge)) throw std::invalid_argument("invalid E target identity");
    if (!map.emplace(cell, edge).second)
      throw std::invalid_argument("duplicate LTE cell in CellToEdgeMap");
    if (comma == std::string::npos) break;
    start = comma + 1;
    if (start == encoded.size()) throw std::invalid_argument("trailing CellToEdgeMap comma");
  }
  // All E identifiers must differ from ALL potential G target identifiers,
  // not merely the G cell to which that E server was assigned.
  for (const auto& e : map)
    for (const auto& g : map)
      if (e.second == "GS_CELL_" + std::to_string(g.first))
        throw std::invalid_argument("cross-domain E/G target identity collision");
  return map;
}

inline std::string GTargetForCell(std::uint16_t cell) {
  if (cell == 0) throw std::invalid_argument("LTE cell must be positive");
  return "GS_CELL_" + std::to_string(cell);
}

struct PartitionDecision {
  Event event = Event::None;
  std::uint16_t sourceCell = 0;
  std::uint16_t targetCell = 0;
  std::string sourceEdge;
  std::string targetEdge;
  std::string targetG;
  bool edgeChanged = false;
};

inline PartitionDecision DecideHandover(const CellToEdge& mapping, std::uint16_t sourceCell,
                                         std::uint16_t targetCell) {
  auto before = mapping.find(sourceCell);
  auto after = mapping.find(targetCell);
  if (before == mapping.end() || after == mapping.end())
    throw std::invalid_argument("real LTE handover uses unmapped source or target cell");
  if (sourceCell == targetCell) throw std::invalid_argument("handover target equals source cell");
  PartitionDecision out;
  out.sourceCell = sourceCell;
  out.targetCell = targetCell;
  out.sourceEdge = before->second;
  out.targetEdge = after->second;
  out.targetG = GTargetForCell(targetCell);
  for (const auto& e : mapping)
    for (const auto& g : mapping)
      if (e.second == GTargetForCell(g.first))
        throw std::invalid_argument("cross-domain E/G target identity collision");
  out.edgeChanged = out.sourceEdge != out.targetEdge;
  out.event = out.edgeChanged ? Event::GE : Event::GOnly;
  return out;
}

}  // namespace uavma_ns3
#endif
