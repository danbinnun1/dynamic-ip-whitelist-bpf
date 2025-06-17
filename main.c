/*
 *  build_and_filter()
 *  ---------------------
 *  Creates a new Classic-BPF program which performs:
 *      1.  src-IP ∈ whitelist  →  continue
 *      2.  otherwise           →  drop
 *      3.  run the original program
 *
 *  Inputs
 *  ──────
 *    orig        : pointer to original bpf_insn array
 *    orig_len    : number of instructions in orig
 *    ips         : array of host-order IPv4 addresses to whitelist
 *    n_ips       : length of ips[]
 *
 *  Output
 *  ──────
 *    *out_len    : filled with new program length
 *    return      : malloc-ed pointer to new bpf_insn[]
 *                  (caller must free)
 *
 *  Notes
 *  ─────
 *    • Classic-BPF limits jumps to 255 instructions; if you pass >255
 *      addresses, split the list or build a small decision tree.
 *    • IP offset 26 assumes Ethernet + IPv4 without options.
 */

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
    if (!orig || !orig_len || !out_len)
        return NULL;

    /* edge-case: no whitelist – just clone the original program */
    if (!n_ips)
    {
        struct bpf_insn *clone = malloc(orig_len * sizeof(*clone));
        if (!clone)
            return NULL;
        memcpy(clone, orig, orig_len * sizeof(*orig));
        *out_len = orig_len;
        return clone;
    }

    /*  layout:
     *    0          LD   [26]               ; src-IP
     *    1..n_ips   JEQ  ip[i] , jt=N-i , jf=0
     *    n_ips+1    RET  0                  ; drop if no match
     *    n_ips+2    ...orig...
     */
    if (n_ips > 255)
    {
        return NULL;
    } /* simple guard */

    const unsigned prelude_len = 1 + n_ips + 1; /* LD + JEQs + RET0 */
    const unsigned total_len = prelude_len + orig_len;

    struct bpf_insn *prog = calloc(total_len, sizeof(*prog));
    if (!prog)
        return NULL;

    unsigned i = 0;

    /* 1. LD src-IP (Ether + IPv4, no options) */
    prog[i++] = (struct bpf_insn)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 26);

    /* 2. Chain of JEQ instructions */
    for (size_t idx = 0; idx < n_ips; ++idx)
    {
        uint32_t ip_be = htonl(ips[idx]);
        uint8_t jt = (uint8_t)(n_ips - idx); /* skip remaining JEQs + RET0 */
        prog[i++] = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ip_be, jt, 0);
    }

    /* 3. Default DROP */
    prog[i++] = (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, 0);

    /* 4. Append the original program verbatim */
    memcpy(&prog[i], orig, orig_len * sizeof(*orig));
    i += orig_len;

    *out_len = i; /* should equal total_len */
    return prog;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr,
            "usage: %s <pcap-file> <orig-filter> <ip1> [ip2 …]\n", argv[0]);
        return 1;
    }
    const char *pcap_path = argv[1];
    const char *orig_expr = argv[2];

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

    /* ─ 2. בניית white-list -- host-order ─ */
    size_t n_ips = (size_t)(argc - 3);
    uint32_t *ips = calloc(n_ips, sizeof(uint32_t));
    for (size_t i = 0; i < n_ips; ++i) {
        struct in_addr a;
        if (!inet_aton(argv[3+i], &a)) {
            fprintf(stderr, "bad ip '%s'\n", argv[3+i]);
            return 3;
        }
        ips[i] = ntohl(a.s_addr);                  /* host-order */
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

    /* ─ 4. מעבר על קובץ pcap והדפסה 0/1 ─ */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_path, errbuf);
    if (!pcap) { fprintf(stderr, "%s\n", errbuf); return 5; }

    const u_char *pkt;
    struct pcap_pkthdr *hdr;
    while (pcap_next_ex(pcap, &hdr, &pkt) == 1) {
        int ok = pcap_offline_filter(&comb, hdr, pkt);
        printf("%d\n", ok ? 1 : 0);
    }

    /* ─ 5. ניקוי ─ */
    pcap_close(pcap);
    pcap_freecode(&orig);
    free(new_insns);
    free(ips);
    return 0;
}