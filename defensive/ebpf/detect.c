#include "suspicious_execution.skel.h"
#include "suspicious_fanning.skel.h"
#include "detect.skel.h"
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "common.h"

int event_handler(void *ctx, void *data, size_t size) {
    struct event *e = (struct event *)data;
    printf("%i %s\n", e->pid, e->cmdline);

    // Optionally kill the process, or just comment out to be passive
    // kill(e->pid, SIGKILL);
    return 0;
}

void xdp_event_handler(void *ctx, int cpu, void *data, unsigned int size) {
    struct event_fanning *e = (struct event_fanning *)data;
    printf("BLOCKING SUSPICIOUS TRAFFIC %u.%u.%u.%u:%i -> %u.%u.%u.%u:%i\n",
        e->srcip & 0xFF,
        (e->srcip >> 8) & 0xFF,
        (e->srcip >> 16) & 0xFF,
        (e->srcip >> 24) & 0xFF,
        ntohs(e->srcport),

        e->dstip & 0xFF,
        (e->dstip >> 8) & 0xFF,
        (e->dstip >> 16) & 0xFF,
        (e->dstip >> 24) & 0xFF,
        ntohs(e->dstport)
    );
}

struct ring_buffer *load_sus_execution() {
    struct suspicious_execution_bpf *skel;

    skel = suspicious_execution_bpf__open();
    suspicious_execution_bpf__load(skel);
    suspicious_execution_bpf__attach(skel);

    struct ring_buffer *buf = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        event_handler,
        0,
        0
    );

    return buf;
}

struct perf_buffer *load_sus_fanning() {
    struct suspicious_fanning_bpf *skel = suspicious_fanning_bpf__open_and_load();
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, if_nametoindex("lo"));
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, if_nametoindex("wlo1"));

    // struct bpf_object *obj = bpf_object__open_file("suspicious_fanning.bpf.o", 0);
    // bpf_object__load(obj);

    int map_fd = bpf_map__fd(skel->maps.events); // bpf_object__find_map_fd_by_name(skel->obj, "events");
    return perf_buffer__new(map_fd, 8, xdp_event_handler, 0, 0, 0);
}

int main() {
    struct ring_buffer *exec_buf = load_sus_execution();
    struct perf_buffer *pb = load_sus_fanning();

    while (1) {
        ring_buffer__poll(exec_buf, 1000);
        // perf_buffer__poll(pb, 100);
    }
}
