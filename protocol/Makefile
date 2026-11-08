CXX ?= g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pedantic -Wno-deprecated-declarations -Iinclude
LDLIBS = -lcrypto -lsqlite3
PREFLIGHT_LIBS = -lcrypto

CORE_SRC = src/crypto.cpp src/root_provider.cpp src/protocol_core.cpp src/state_store.cpp \
           src/linux_transport.cpp src/service_core.cpp src/experiment_driver.cpp src/harness.cpp
CORE_OBJ = $(CORE_SRC:src/%.cpp=build/%.o)

NS3_INC = -Ins3/uavma/model
HEADER_TESTS = test_uavma_event_policy test_uavma_cell_partition test_uavma_measurement_ledger \
               test_uavma_p4_cpu_model
CORE_TESTS = test_uavma_target_transfer

.PHONY: all clean test preflight formal test-formal nodes test-ns3 run-unit-tests

all: build/auth_preflight build/uavma_formal

build:
	@mkdir -p build

build/%.o: src/%.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/auth_preflight: src/core.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $< -o $@ $(PREFLIGHT_LIBS)

build/uavma_formal: $(CORE_OBJ) src/formal_main.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(CORE_OBJ) src/formal_main.cpp -o $@ $(LDLIBS)

build/test_protocol_core: $(CORE_OBJ) tests/test_protocol_core.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(CORE_OBJ) tests/test_protocol_core.cpp -o $@ $(LDLIBS)

build/test_recovery: $(CORE_OBJ) tests/test_recovery.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(CORE_OBJ) tests/test_recovery.cpp -o $@ $(LDLIBS)

build/test_persistence: $(CORE_OBJ) tests/test_persistence.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(CORE_OBJ) tests/test_persistence.cpp -o $@ $(LDLIBS)

build/uavma_e1: $(CORE_OBJ) src/e1_main.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(CORE_OBJ) src/e1_main.cpp -o $@ $(LDLIBS)

build/uavma_e3: $(CORE_OBJ) src/e3_main.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(CORE_OBJ) src/e3_main.cpp -o $@ $(LDLIBS)

build/test_ns3_transport: $(CORE_OBJ) tests/test_ns3_transport.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(CORE_OBJ) tests/test_ns3_transport.cpp -o $@ $(LDLIBS)

build/test_service: $(CORE_OBJ) tests/test_service.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(CORE_OBJ) tests/test_service.cpp -o $@ $(LDLIBS)

# Header-only ns-3 policy tests (no ns-3 build tree required).
build/test_uavma_%: tests/test_uavma_%.cpp | build
	$(CXX) $(CXXFLAGS) $(NS3_INC) $< -o $@

build/test_uavma_target_transfer: $(CORE_OBJ) tests/test_uavma_target_transfer.cpp | build
	$(CXX) $(CXXFLAGS) $(NS3_INC) $(CORE_OBJ) tests/test_uavma_target_transfer.cpp -o $@ $(LDLIBS)

test-ns3: $(addprefix build/,$(HEADER_TESTS)) build/test_uavma_target_transfer

run-unit-tests: all formal test-ns3
	@for t in test_protocol_core test_recovery test_persistence test_service test_ns3_transport \
	          $(HEADER_TESTS) $(CORE_TESTS); do \
	  echo "== $$t =="; ./build/$$t >/dev/null || exit 1; echo "PASS $$t"; \
	done
	./build/auth_preflight smoke

preflight: build/auth_preflight
	./build/auth_preflight smoke

formal: build/uavma_formal build/uavma_e1 build/uavma_e3 build/test_protocol_core build/test_recovery \
        build/test_persistence build/test_service build/test_ns3_transport

test-formal: formal
	@echo "run scripts/run_s2.sh to execute the S2 acceptance suite with logging"

nodes: build/uavma_formal
	./build/uavma_formal nodes results/formal/nodes 47311

test: preflight

clean:
	rm -rf build
