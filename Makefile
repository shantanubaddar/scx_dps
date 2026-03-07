CLANG   ?= clang
CC      ?= gcc
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

SCX_INCLUDE := ./scx_headers

# vmlinux.h lives in scx_headers/, bpf_helpers live in /usr/include/bpf/
BPF_CFLAGS := -O2 -g -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I$(SCX_INCLUDE) \
              -I/usr/include/bpf \
              -I/usr/include

LOADER_CFLAGS := -O2 -g
LOADER_LIBS   := -lbpf

SCX_RAW := https://raw.githubusercontent.com/sched-ext/scx/main/scheds/include/scx

.PHONY: all clean check fetch-headers load unload

all: democratic.bpf.o democratic_loader dem_analyze

check:
	@echo "Checking..."
	@command -v clang   >/dev/null && echo "  ✓ clang"   || echo "  ✗ clang"
	@command -v gcc     >/dev/null && echo "  ✓ gcc"     || echo "  ✗ gcc"
	@command -v bpftool >/dev/null && echo "  ✓ bpftool" || echo "  ✗ bpftool (sudo pacman -S bpf)"
	@pkg-config --exists libbpf    && echo "  ✓ libbpf"  || echo "  ✗ libbpf"
	@test -f $(SCX_INCLUDE)/vmlinux.h && echo "  ✓ vmlinux.h" || echo "  ✗ vmlinux.h (run make fetch-headers)"
	@test -d /sys/kernel/sched_ext && echo "  ✓ sched_ext active" || echo "  ✗ sched_ext not found"

fetch-headers:
	@echo "Generating vmlinux.h from running kernel..."
	mkdir -p ./scx_headers
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./scx_headers/vmlinux.h
	@echo "  ✓ vmlinux.h ($$(wc -l < ./scx_headers/vmlinux.h) lines)"
	@echo "Done — run: make"

democratic.bpf.o: democratic.bpf.c
	@echo "  Compiling BPF..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  ✓ democratic.bpf.o"

democratic_loader: democratic_loader.c
	@echo "  Compiling loader..."
	$(CC) $(LOADER_CFLAGS) $< -o $@ $(LOADER_LIBS)
	@echo "  ✓ democratic_loader"

dem_analyze: dem_analyze.c
	@echo "  Compiling analyzer..."
	$(CC) $(LOADER_CFLAGS) $< -o $@ $(LOADER_LIBS) -lm
	@echo "  ✓ dem_analyze"

clean:
	rm -f democratic.bpf.o democratic_loader dem_analyze
	rm -rf ./scx_headers

load: democratic.bpf.o
	sudo bpftool struct_ops register democratic.bpf.o /sys/fs/bpf/democratic
	@cat /sys/kernel/sched_ext/state

unload:
	sudo bpftool struct_ops unregister name democratic 2>/dev/null || \
	sudo rm -f /sys/fs/bpf/democratic
	@echo "Reverted to BORE/CFS"
