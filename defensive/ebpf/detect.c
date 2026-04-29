#include "suspicious_execution.skel.h"
#include "suspicious_fanning.skel.h"
#include "detect.skel.h"
#include <unistd.h>
#include <signal.h>
#include "common.h"

int event_handler(void *ctx, void *data, size_t size) {
    struct event *e = (struct event *)data;
    printf("%i %s\n", e->pid, e->cmdline);

    // Optionally kill the process, or just comment out to be passive
    // kill(e->pid, SIGKILL);
    return 0;
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

struct ring_buffer *load_sus_fanning() {
    struct suspicious_fanning_bpf *skel;

    skel = suspicious_fanning_bpf__open();
    suspicious_fanning_bpf__load(skel);
    suspicious_fanning_bpf__attach(skel);

    struct ring_buffer *buf = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        event_handler,
        0,
        0
    );

    return buf;
}

int main() {
    struct ring_buffer *exec_buf = load_sus_execution();
    struct ring_buffer *fanning_buf = load_sus_fanning();

    while (1) {
        ring_buffer__poll(exec_buf, 1000);
        ring_buffer__poll(fanning_buf, 1000);
    }
}
