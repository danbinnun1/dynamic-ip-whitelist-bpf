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




struct bpf_insn *build_and_filter(const struct bpf_insn *orig,
                                  unsigned orig_len,
                                  const uint32_t *ips,
                                  size_t n_ips,
                                  unsigned *out_len)
{

    const unsigned prelude_len = n_ips ? 1 + n_ips + 1 : 0;
    const unsigned total_len = prelude_len + orig_len;

    struct bpf_insn *prog = calloc(total_len, sizeof(*prog));
    if (!prog)
        return NULL;

    unsigned i = 0;

    if (n_ips) {
        prog[i++] = (struct bpf_insn)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 26);
        for (size_t idx = 0; idx < n_ips; ++idx) {
            uint32_t ip_be = ips[idx];
            uint8_t jt = (uint8_t)(n_ips - idx);
            prog[i++] = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                 ip_be, jt, 0);
        }
        prog[i++] = (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, 0);
    }

    memcpy(&prog[i], orig, orig_len * sizeof(*orig));
    i += orig_len;

    *out_len = i;
    return prog;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <pcap-file> <orig-filter> <out-file> <ip> [ip..]\n",
                argv[0]);
        return 1;
    }
    const char *pcap_path = argv[1];
    const char *orig_expr = argv[2];
    const char *out_path  = argv[3];

    /* ─ 1. קומפילציה של הפילטר המקורי -- libpcap ─ */
    struct bpf_program orig = {0};
    pcap_t *pc = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pc) {
        fprintf(stderr, "pcap_open_dead failed\n");
        return 2;
    }
    if (pcap_compile(pc, &orig, orig_expr, 1, 0) != 0) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pc));
        pcap_close(pc);
        return 2;
    }
    pcap_close(pc);

    /* ─ 2. build white-list (host order) ─ */
    size_t n_ips = (size_t)(argc - 4);
    uint32_t *ips = calloc(n_ips, sizeof(uint32_t));
    for (size_t i = 0; i < n_ips; ++i) {
        struct in_addr a;
        if (!inet_aton(argv[4 + i], &a)) {
            fprintf(stderr, "bad ip '%s'\n", argv[4 + i]);
            return 3;
        }
        ips[i] = ntohl(a.s_addr);
    }

    /* ─ 3. build_and_filter() ─ */
    unsigned new_len = 0;
    struct bpf_insn *new_insns =
        build_and_filter(orig.bf_insns, orig.bf_len,
                         ips, n_ips, &new_len);
    if (!new_insns) {
        fprintf(stderr, "build_and_filter() failed\n");
        return 4;
    }
    struct bpf_program comb = { .bf_len = new_len,
                                .bf_insns = new_insns };

    /* ─ 4. iterate packets and write results ─ */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_path, errbuf);
    if (!pcap) { fprintf(stderr, "%s\n", errbuf); return 5; }
    int exit_code_mode = strcmp(out_path, "-") == 0;
    FILE *out = NULL;
    if (!exit_code_mode) {
        out = fopen(out_path, "wb");
        if (!out) { perror("fopen"); return 6; }
    }

    const u_char *pkt;
    struct pcap_pkthdr *hdr;
    int rc = 1; /* default: packet did not match */
    while (pcap_next_ex(pcap, &hdr, &pkt) == 1) {
        int ok = pcap_offline_filter(&comb, hdr, pkt);
        if (exit_code_mode) {
            rc = ok ? 0 : 1;
            break; /* only first packet is relevant */
        } else {
            unsigned char b = ok ? 1 : 0;
            fwrite(&b, 1, 1, out);
        }
    }
    if (!exit_code_mode)
        fclose(out);

    /* ─ 5. ניקוי ─ */
    pcap_close(pcap);
    pcap_freecode(&orig);
    free(new_insns);
    free(ips);
    return exit_code_mode ? rc : 0;
}