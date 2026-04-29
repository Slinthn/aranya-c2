#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// Allowed timespan of events in nanoseconds
#define THRESHOLD_NS 1 * 1000 * 1000 * 1000

// First, check if 'sh' command is hit
#define PFLAG_HIT_SH 1

// Then, check if QUIC packet was sent
#define PFLAG_NETWORK 2

struct procinfo {
    u32 pid;
    u8 flags;
    u64 start_time;
    char cmdline[32];
};

struct {
    // LRU is okay here because our detections are for short-lived actions
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct procinfo);
} processes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024);
} events SEC(".maps");

// get_parent: Whether to get the parent process information or not (boolean)
struct procinfo *get_current_proc_info(int get_parent) {
    // Get pid instead of thread id
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    // For execve, we should get the parent pid
    if (get_parent) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct task_struct *par = (struct task_struct *)BPF_CORE_READ(task, real_parent);
        if (!par)
            return 0;

        pid = BPF_CORE_READ(par, pid);
    }

    // Get process info from ring buffer
    struct procinfo *proc = bpf_map_lookup_elem(&processes, &pid);

    // Create one if non-existent
    if (!proc) {
        struct procinfo def = {0};
        bpf_map_update_elem(&processes, &pid, &def, 0);
        proc = bpf_map_lookup_elem(&processes, &pid);
    }

    if (proc)
        proc->pid = pid;

    return proc;
}

// Adds flags and removes any outdated ones
void submit_flag(struct procinfo *proc, u8 flag) {
    u64 now = bpf_ktime_get_tai_ns();

    if (now - proc->start_time > THRESHOLD_NS) {
        proc->flags = 0;
        proc->start_time = now;
    }

    proc->flags |= flag;
}

void submit_event(struct procinfo *proc) {
    // Process is suspicious, make an event
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return;

    e->pid = proc->pid;

    // Copy cmdline
    for (int i = 0; i < sizeof(e->cmdline) && i < sizeof(proc->cmdline); i++)
        e->cmdline[i] = proc->cmdline[i];

    bpf_ringbuf_submit(e, 0);
}

void check_suspicious_process(struct procinfo *proc) {
    // Check if all suspicious flags are set
    if (!(proc->flags & PFLAG_HIT_SH) || !(proc->flags & PFLAG_NETWORK))
        return;

    submit_event(proc);
}

SEC("tp/syscalls/sys_enter_execve")
int enter_execve(struct trace_event_raw_sys_enter *ctx) {
    // Get process info from ring buffer
    struct procinfo *proc = get_current_proc_info(1);
    if (!proc)
        return 0;

    bpf_probe_read_user_str(
        proc->cmdline,
        sizeof(proc->cmdline),
        (void *)ctx->args[0]
    );

    // Get command execve'd
    char pathname[32];
    bpf_probe_read_user_str(pathname, sizeof(pathname), (void *)ctx->args[0]);

    // Check if it's a shell
    if (bpf_strstr(pathname, "/sh") >= 0) {
        submit_flag(proc, PFLAG_HIT_SH);
        check_suspicious_process(proc);
    }

    return 0;
}

int check_quic_headers(struct sock *sk) {
    struct sk_buff *skb = BPF_CORE_READ(sk, sk_receive_queue.next);
    if (!skb)
        return 0;

    uint32_t datlen = BPF_CORE_READ(skb, len);

    // No data to be read
    if (datlen <= 1)
        return 0;

    unsigned char data[1];
    bpf_probe_read_kernel(data, sizeof(data), BPF_CORE_READ(skb, data));

    // Check for QUIC header
    if (!(data[0] & 0x40))
        return 0;

    // This is a QUIC packet
    return 1;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(receive_skb, struct sock *sk, struct msghdr *msg, size_t len) {
    struct procinfo *proc = get_current_proc_info(0);
    if (!proc)
        return 0;

    if (check_quic_headers(sk)) {
        submit_flag(proc, PFLAG_NETWORK);
        check_suspicious_process(proc);
    }

    return 0;
}
