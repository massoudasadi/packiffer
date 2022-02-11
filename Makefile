GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I../../.. 

GO_SOURCE := "./src/core/"
GO_BINARY := packiffer

EBPF_SOURCE := src/ebpf/xdp_block_address.c
EBPF_BINARY := xdp_block_address.elf

all: build_bpf build_go

build_bpf: $(EBPF_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(EBPF_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

$(GO_BINARY):
	$(GOBUILD) -v -o $@ $(GO_SOURCE)