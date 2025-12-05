clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I src/bpf -c src/bpf/passible.bpf.c -o build/passible.bpf.o
bpftool gen skeleton build/passible.bpf.o >src/bpf/passible.skel.h
cmake --build build
