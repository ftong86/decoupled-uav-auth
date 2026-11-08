CXX ?= g++
CC ?= gcc

CXXFLAGS ?= -O3 -march=native -DNDEBUG -Wno-deprecated-declarations
CFLAGS ?= -O3 -march=native -DNDEBUG

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell pkg-config --libs openssl)

# Override these if PBC is installed outside the default compiler/library path:
# make pairing PBC_CFLAGS="-I/usr/local/include" \
#              PBC_LIBS="-L/usr/local/lib -lpbc -lgmp"
PBC_CFLAGS ?=
PBC_LIBS ?= -lpbc -lgmp

.PHONY: all clean pairing param

all: bench_openssl

bench_openssl: bench_openssl.cpp
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) $< -o $@ $(OPENSSL_LIBS)

pairing: bench_pairing gen_typea_param

bench_pairing: bench_pairing.c
	$(CC) $(CFLAGS) $(PBC_CFLAGS) $< -o $@ $(PBC_LIBS)

gen_typea_param: gen_typea_param.c
	$(CC) $(CFLAGS) $(PBC_CFLAGS) $< -o $@ $(PBC_LIBS)

param: gen_typea_param
	@if [ -f typea_256_1536.param ]; then \
		echo "typea_256_1536.param already exists; not overwriting."; \
	else \
		echo "Generating Type-A parameter file once..."; \
		./gen_typea_param > typea_256_1536.param; \
		echo "Saved typea_256_1536.param"; \
	fi

clean:
	rm -f bench_openssl bench_pairing gen_typea_param
