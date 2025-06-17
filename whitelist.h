#ifndef WHITELIST_H
#define WHITELIST_H
#include <pcap/pcap.h>
#include <stdint.h>
#include <stddef.h>

struct bpf_insn *append_ip_whitelist(const struct bpf_insn *orig,
                                     unsigned orig_len,
                                     const uint32_t *ips,
                                     size_t n_ips,
                                     unsigned *out_len);

#endif
