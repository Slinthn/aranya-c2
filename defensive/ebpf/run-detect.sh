# NIC program
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -c suspicious_fanning.bpf.c -o suspicious_fanning.bpf.o
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -c suspicious_execution.bpf.c -o suspicious_execution.bpf.o

bpftool gen skeleton suspicious_fanning.bpf.o > suspicious_fanning.skel.h
bpftool gen skeleton suspicious_execution.bpf.o > suspicious_execution.skel.h
clang -g -O2 detect.c -o detect -I. -lbpf -lelf
sudo ./detect $1
