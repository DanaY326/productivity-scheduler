# focus-sched build.
#
# Needs: clang (>= 17), bpftool, libbpf (>= 1.4) headers + lib, libelf, zlib.
# scx headers and a BTF-generated vmlinux.h are fetched from sched-ext/scx at a
# pinned commit; set VMLINUX_FROM_KERNEL=1 to dump vmlinux.h from the running
# kernel instead.

SCX_REPO   ?= https://github.com/sched-ext/scx
SCX_REF    ?= e7b3a219617472cf78880ac424714e52c932db61   # v1.1.4
SCX_DIR    := third_party/scx
BUILD      := build

CLANG      ?= clang
BPFTOOL    ?= bpftool
CC         ?= cc

UNAME_M    := $(shell uname -m)
ARCH       := $(patsubst x86_64,x86,$(patsubst aarch64,arm64,$(UNAME_M)))

ifeq ($(VMLINUX_FROM_KERNEL),1)
VMLINUX_DIR := $(BUILD)
else
VMLINUX_DIR := $(SCX_DIR)/scheds/vmlinux/arch/$(ARCH)
endif

INCLUDES   := -I$(BUILD) -I. -I$(SCX_DIR)/scheds/include \
	      -I$(SCX_DIR)/scheds/include/bpf-compat -I$(VMLINUX_DIR)

BPF_CFLAGS := -g -O2 -Wall -Wno-compare-distinct-pointer-types \
	      -target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

CFLAGS     ?= -O2 -g -Wall
LIBS       := $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)

.PHONY: all clean distclean scx

all: $(BUILD)/focus-sched

$(SCX_DIR)/.fetched:
	rm -rf $(SCX_DIR)
	git clone --filter=blob:none --no-checkout $(SCX_REPO) $(SCX_DIR)
	cd $(SCX_DIR) && git sparse-checkout set scheds/include scheds/vmlinux && \
		git checkout -q $(SCX_REF)
	touch $@

scx: $(SCX_DIR)/.fetched

$(BUILD):
	mkdir -p $@

$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

ifeq ($(VMLINUX_FROM_KERNEL),1)
VMLINUX_DEP := $(BUILD)/vmlinux.h
endif

$(BUILD)/focus.bpf.o: focus.bpf.c focus.h $(SCX_DIR)/.fetched $(VMLINUX_DEP) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/focus.bpf.skel.h: $(BUILD)/focus.bpf.o
	$(BPFTOOL) gen skeleton $< name focus_bpf > $@

$(BUILD)/focus-sched: focus.c focus.h $(BUILD)/focus.bpf.skel.h
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@ $(LIBS)

clean:
	rm -rf $(BUILD)

distclean: clean
	rm -rf third_party
