#include "whitelist.h"
#include <stdlib.h>
#include <string.h>

#define SRC_IP_OFFSET 26

struct bpf_insn *append_ip_whitelist(const struct bpf_insn *orig,
                                     unsigned orig_len,
                                     const uint32_t *ips,
                                     size_t n_ips,
                                     unsigned *out_len)
{
    const unsigned whitelist_insn_count = 1 + n_ips + 1;
    const unsigned total_len = whitelist_insn_count + orig_len;

    struct bpf_insn *prog = malloc(total_len * sizeof(*prog));
    if (!prog)
        return NULL;

    unsigned i = 0;

    prog[i++] = (struct bpf_insn)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SRC_IP_OFFSET);
    for (size_t idx = 0; idx < n_ips; ++idx)
    {
        uint8_t jt = (uint8_t)(n_ips - idx);
        prog[i++] = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                              ips[idx], jt, 0);
    }
    prog[i++] = (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, 0);

    memcpy(&prog[i], orig, orig_len * sizeof(*orig));
    i += orig_len;

    *out_len = i;
    return prog;
}
