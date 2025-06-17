/* build a new BPF program that checks the src ip list and then runs
 * the original program */

#include <arpa/inet.h>
#include <fcntl.h>
#include <pcap/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pcap/pcap.h>

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

#define CHECK(cond) \
    if (!(cond)) {   \
    printf("failed %s\n", #cond); \
    return 1;}

/**
 * return values:
 *  0: packet didn't match
 *  1: packet matched
 *  2: error
 */
int main(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr,
                "usage: %s <pcap-file> <orig-filter> [ip..]\n",
                argv[0]);
        return 1;
    }
    const char *pcap_path = argv[1];
    const char *orig_expr = argv[2];

    struct bpf_program orig = {0};
    pcap_t *pc = pcap_open_dead(DLT_EN10MB, 65535);
    CHECK(pc);
    CHECK(pcap_compile(pc, &orig, orig_expr, 1, 0) == 0);
    pcap_close(pc);

    size_t n_ips = (size_t)(argc - 3);
    uint32_t *ips = malloc(n_ips * sizeof(uint32_t));
    for (size_t i = 0; i < n_ips; ++i)
    {
        struct in_addr a;
        CHECK(inet_aton(argv[3 + i], &a));
        ips[i] = ntohl(a.s_addr);
    }

    unsigned len = 0;
    struct bpf_insn *insns =
        append_ip_whitelist(orig.bf_insns, orig.bf_len,
                            ips, n_ips, &len);
    CHECK(insns);

    struct bpf_program bpf_program = {.bf_len = len,
                                      .bf_insns = insns};

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_path, errbuf);
    CHECK(pcap);

    const u_char *pkt;
    struct pcap_pkthdr *hdr;
    CHECK(pcap_next_ex(pcap, &hdr, &pkt) == 1);

    int rc = !pcap_offline_filter(&bpf_program, hdr, pkt);

    pcap_close(pcap);
    pcap_freecode(&orig);
    free(insns);
    free(ips);
    return rc;
}