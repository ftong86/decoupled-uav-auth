# CMakeLists.txt for the ns-3 'uavma' contrib module.
#
# Builds the protocol core and the ns-3 transport application against ns-3.45 so
# that UAV and infrastructure nodes exchange serialized protocol messages over
# ns-3 sockets.
#
# core/src and core/include are copies of protocol/src and protocol/include/uavma,
# kept here so the module builds independently of the standalone protocol tree.

find_package(OpenSSL REQUIRED)
find_library(SQLITE3_LIBRARY NAMES sqlite3 REQUIRED)

message(STATUS "uavma: OpenSSL ${OPENSSL_LIBRARIES}")
message(STATUS "uavma: sqlite3 ${SQLITE3_LIBRARY}")

# Absolute paths: the module is reached through a contrib symlink, so relative
# source paths are avoided entirely.
set(UAVMA_DIR ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${UAVMA_DIR}/core/include)

set(core_sources
    ${UAVMA_DIR}/core/src/crypto.cpp
    ${UAVMA_DIR}/core/src/protocol_core.cpp
    ${UAVMA_DIR}/core/src/state_store.cpp
    ${UAVMA_DIR}/core/src/root_provider.cpp
    ${UAVMA_DIR}/core/src/linux_transport.cpp
    ${UAVMA_DIR}/core/src/experiment_driver.cpp
)

set(sources
    ${UAVMA_DIR}/model/uavma-ns3-transport.cc
    ${core_sources}
)

set(public_headers
    ${UAVMA_DIR}/model/uavma-ns3-transport.h
    ${UAVMA_DIR}/model/uavma-event-policy.h
    ${UAVMA_DIR}/model/uavma-cell-partition.h
    ${UAVMA_DIR}/model/uavma-measurement-ledger.h
    ${UAVMA_DIR}/model/uavma-p4-cpu-model.h
)

foreach(f ${sources})
  if(NOT EXISTS "${f}")
    message(FATAL_ERROR "uavma: missing source ${f}")
  endif()
endforeach()
message(STATUS "uavma: ${CMAKE_CURRENT_SOURCE_DIR} sources=${sources}")

set(dependencies
    ${libcore}
    ${libnetwork}
    ${libinternet}
    ${libmobility}
    ${libapplications}
    ${liblte}
    ${OPENSSL_LIBRARIES}
    ${SQLITE3_LIBRARY}
)

build_lib(
  LIBNAME uavma
  SOURCE_FILES ${sources}
  HEADER_FILES ${public_headers}
  LIBRARIES_TO_LINK
    ${dependencies}
)
