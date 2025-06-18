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

#include "whitelist.h"

#define CHECK(cond) \
    if (!(cond)) {   \
    printf("failed %s\n", #cond); \
    return 2;}

/**
 * return values:
 *  0: packet matched
 *  1: packet didn't match
 *  2: error
 */
int main(int argc, char **argv)
{
    CHECK(argc >= 3)
    
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
