#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define QUEUE_NUM 200
#define TTL_VALUE 64

static volatile int keep_running = 1;

static void handle_sig(int sig) {
    (void)sig;
    keep_running = 0;
}

static void recalc_checksum_v4(struct iphdr *iph) {
    iph->check = 0;
    unsigned int sum = 0;
    unsigned short *p = (unsigned short *)iph;
    int i;
    for (i = 0; i < (int)(iph->ihl * 2); i++) {
        sum += p[i];
        sum = (sum & 0xffff) + (sum >> 16);
    }
    iph->check = (unsigned short)(~sum);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    (void)nfmsg;
    (void)data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    unsigned int id = ph ? ntohl(ph->packet_id) : 0;

    unsigned char *pkt = NULL;
    int len = nfq_get_payload(nfa, &pkt);

    if (len > 0 && pkt) {
        unsigned char version = (pkt[0] >> 4);
        if (version == 4 && len >= (int)sizeof(struct iphdr)) {
            struct iphdr *iph = (struct iphdr *)pkt;
            if (iph->ttl != TTL_VALUE) {
                iph->ttl = TTL_VALUE;
                recalc_checksum_v4(iph);
                return nfq_set_verdict(qh, id, NF_ACCEPT, len, pkt);
            }
        } else if (version == 6 && len >= (int)sizeof(struct ip6_hdr)) {
            struct ip6_hdr *ip6h = (struct ip6_hdr *)pkt;
            if (ip6h->ip6_hlim != TTL_VALUE) {
                ip6h->ip6_hlim = TTL_VALUE;
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    int verbose = 0;
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) verbose = 1;
    }

    signal(SIGTERM, handle_sig);
    signal(SIGINT, handle_sig);
    signal(SIGHUP, handle_sig);

    struct nfq_handle *h = nfq_open();
    if (!h) {
        fprintf(stderr, "ttlq: nfq_open failed: %s\n", strerror(errno));
        return 1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "ttlq: nfq_unbind_pf v4 failed\n");
    }
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "ttlq: nfq_bind_pf v4 failed\n");
        nfq_close(h);
        return 1;
    }
    nfq_unbind_pf(h, AF_INET6);
    nfq_bind_pf(h, AF_INET6);

    struct nfq_q_handle *qh = nfq_create_queue(h, QUEUE_NUM, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "ttlq: nfq_create_queue(%d) failed: %s\n",
                QUEUE_NUM, strerror(errno));
        nfq_close(h);
        return 1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "ttlq: nfq_set_mode failed\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }

    int fd = nfq_fd(h);

    if (verbose) {
        fprintf(stderr, "ttlq: started, queue=%d, ttl=%d\n", QUEUE_NUM, TTL_VALUE);
    }

    char buf[65536] __attribute__((aligned(8)));

    while (keep_running) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000);
                continue;
            }
            fprintf(stderr, "ttlq: recv failed: %s\n", strerror(errno));
            break;
        }
        nfq_handle_packet(h, buf, rv);
    }

    if (verbose) fprintf(stderr, "ttlq: stopping\n");

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
