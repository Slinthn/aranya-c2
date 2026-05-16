#pragma once

struct event {
    uint32_t pid;
    char cmdline[32];
};

struct event_fanning {
    uint32_t srcip;
    uint32_t dstip;
    uint32_t srcport;
    uint32_t dstport;
};
