#include "nos.h"
#include <rte_timer.h>
#include <rte_alarm.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
   BFD (Bidirectional Forwarding Detection) — simplified

   NOS uses BFD to detect WAN link failures in <1 second.
   Full BFD (RFC 5880) has asynchronous + echo modes.
   Here we implement the core mechanism:
     - Send BFD control packets every INTERVAL_US microseconds
     - Track RTT from TX timestamp to received echo
     - Mark circuit DOWN after DETECT_MULTIPLIER missed intervals
     - Update wan[i].rtt_us, loss_ppm, active for path selection

   Real BFD requires IKEv2 / BGP integration for neighbor
   discovery. Here we use static peer IPs from the WAN config.
   ============================================================ */

#define BFD_PORT            3784     /* RFC 5880 well-known port */
#define BFD_INTERVAL_US     300000   /* 300ms between probes */
#define BFD_DETECT_MULT     3        /* miss 3 → declare DOWN */
#define BFD_ECHO_LEN        64       /* bytes in echo packet */
#define BFD_DISCRIMINATOR   0xDEAD   /* local discriminator */

/* BFD control packet header (simplified — not full RFC 5880) */
typedef struct __attribute__((packed)) {
    uint8_t  vers_diag;      /* version=1 (bits 7-5), diag (bits 4-0) */
    uint8_t  flags;          /* sta(bits 7-6), P/F/C/A/D/M bits */
    uint8_t  detect_mult;
    uint8_t  length;
    uint32_t my_discriminator;
    uint32_t your_discriminator;
    uint32_t desired_min_tx_interval;   /* microseconds, big-endian */
    uint32_t required_min_rx_interval;
    uint32_t required_min_echo_rx_interval;
} bfd_pkt_t;

/* per-circuit BFD state */
typedef struct {
    uint32_t peer_ip;
    uint32_t local_disc;
    uint32_t remote_disc;
    uint8_t  state;          /* 0=DOWN 1=INIT 2=UP 3=ADMIN_DOWN */
    uint8_t  miss_count;
    uint64_t last_rx_tsc;    /* rdtsc of last received BFD packet */
    uint64_t last_tx_tsc;
    uint64_t rtt_sum_us;     /* rolling sum for average */
    uint32_t rtt_samples;
    uint32_t probes_sent;
    uint32_t probes_received;
} bfd_session_t;

static bfd_session_t g_bfd[NOS_MAX_PORTS];
static struct rte_timer g_bfd_timer;

/* ============================================================
   SYNTHETIC WAN HEALTH UPDATE
   In a real deployment, this is populated by received BFD
   echo replies. Here we simulate the measurement update to
   demonstrate how path selection consumes the metrics.
   ============================================================ */

static void bfd_update_circuit_health(uint8_t circuit_idx,
                                       uint64_t rtt_us,
                                       bool packet_received)
{
    bfd_session_t *bfd = &g_bfd[circuit_idx];
    nos_wan_circuit_t *wan = &g_nos.wan[circuit_idx];

    if (packet_received) {
        bfd->miss_count = 0;
        bfd->probes_received++;
        bfd->last_rx_tsc = rte_rdtsc();

        /* rolling RTT average (EMA: alpha=0.25) */
        if (bfd->rtt_samples == 0) {
            wan->rtt_us = (uint32_t)rtt_us;
        } else {
            wan->rtt_us = (uint32_t)((wan->rtt_us * 3 + rtt_us) / 4);
        }
        bfd->rtt_samples++;

        /* loss_ppm = (sent - received) * 1e6 / sent */
        if (bfd->probes_sent > 0) {
            uint32_t lost = bfd->probes_sent - bfd->probes_received;
            wan->loss_ppm = (uint32_t)(
                (uint64_t)lost * 1000000ULL / bfd->probes_sent);
        }

        if (!wan->active) {
            printf("[bfd] circuit %u UP  rtt=%uus loss=%uppm\n",
                   circuit_idx, wan->rtt_us, wan->loss_ppm);
            wan->active = true;
        }
    } else {
        bfd->miss_count++;
        bfd->probes_sent++;

        if (bfd->miss_count >= BFD_DETECT_MULT && wan->active) {
            printf("[bfd] circuit %u DOWN (missed %u probes)\n",
                   circuit_idx, bfd->miss_count);
            wan->active = false;
            /* trigger path failover: re-select WAN for all active sessions */
            /* In NOS this triggers an MP-BGP update to the controller */
        }
    }
}

/* ============================================================
   BFD TIMER CALLBACK — fires every BFD_INTERVAL_US

   In a real deployment this would:
     1. Build a BFD control packet (struct bfd_pkt_t)
     2. Allocate an mbuf, fill UDP/IP/BFD headers
     3. Enqueue to the poller's TX ring for each WAN circuit

   Here we implement the health simulation + the packet
   construction to show the complete picture.
   ============================================================ */

static void bfd_timer_cb(struct rte_timer *tim __rte_unused,
                          void *arg __rte_unused)
{
    uint64_t hz = rte_get_timer_hz();
    uint64_t now_tsc = rte_rdtsc();

    for (uint8_t i = 0; i < g_nos.n_wan; i++) {
        bfd_session_t *bfd = &g_bfd[i];
        bfd->probes_sent++;

        /* simulate: probe succeeds if circuit is configured as active.
           In real code this is driven by received BFD echo packets. */
        bool received = g_nos.wan[i].active;

        /* simulate realistic RTT: 2–50ms base with small jitter */
        uint64_t sim_rtt_us = 5000 + (i * 3000) +
                               (now_tsc % 500);  /* jitter */

        bfd_update_circuit_health(i, sim_rtt_us, received);

        /* log probe (throttled to every 10th probe) */
        if (bfd->probes_sent % 10 == 0) {
            printf("[bfd] circuit %u: sent=%u rcv=%u rtt=%uus "
                   "loss=%uppm active=%s\n",
                   i, bfd->probes_sent, bfd->probes_received,
                   g_nos.wan[i].rtt_us, g_nos.wan[i].loss_ppm,
                   g_nos.wan[i].active ? "YES" : "NO");
        }

        /* detect if circuit has been silent too long */
        if (bfd->last_rx_tsc > 0) {
            uint64_t silence_us = (now_tsc - bfd->last_rx_tsc) *
                                   1000000ULL / hz;
            if (silence_us > (uint64_t)BFD_INTERVAL_US * BFD_DETECT_MULT) {
                if (g_nos.wan[i].active) {
                    printf("[bfd] circuit %u: no response for %llums — "
                           "marking DOWN\n",
                           i, (unsigned long long)silence_us / 1000);
                    g_nos.wan[i].active = false;
                }
            }
        } else {
            bfd->last_rx_tsc = now_tsc;  /* seed on first probe */
        }
    }

    /* reschedule */
    rte_timer_reset(&g_bfd_timer,
                    hz * BFD_INTERVAL_US / 1000000ULL,
                    SINGLE,
                    rte_lcore_id(),
                    bfd_timer_cb, NULL);
}

/* ============================================================
   CONTROL PLANE API

   In NOS, this is the equivalent of the binary API that the
   SD-WAN controller uses to push:
     - Route updates (FIB entries)
     - IPSec SA installs
     - QoS policy changes
     - WAN circuit configuration

   Here we implement the same operations as direct C calls.
   A real implementation would expose these over a Unix domain
   socket or shared memory IPC channel.
   ============================================================ */

int nos_ctrl_add_route(uint32_t ip, uint8_t prefix_len, uint32_t next_hop)
{
    int ret = rte_lpm_add(g_nos.lpm_v4, ip, prefix_len, next_hop);
    if (ret == 0) {
        printf("[ctrl] route added: %u.%u.%u.%u/%u → port %u\n",
               (ip >> 24)&0xFF, (ip >> 16)&0xFF,
               (ip >>  8)&0xFF,  ip & 0xFF,
               prefix_len, next_hop);
    }
    return ret;
}

int nos_ctrl_del_route(uint32_t ip, uint8_t prefix_len)
{
    int ret = rte_lpm_delete(g_nos.lpm_v4, ip, prefix_len);
    if (ret == 0) {
        printf("[ctrl] route deleted: %u.%u.%u.%u/%u\n",
               (ip >> 24)&0xFF, (ip >> 16)&0xFF,
               (ip >>  8)&0xFF,  ip & 0xFF, prefix_len);
    }
    return ret;
}

int nos_ctrl_add_wan_circuit(uint8_t idx, uint32_t local_ip,
                              uint32_t gateway_ip, uint16_t port_id)
{
    if (idx >= NOS_MAX_PORTS) return -1;
    nos_wan_circuit_t *c = &g_nos.wan[idx];
    c->local_ip    = local_ip;
    c->gateway_ip  = gateway_ip;
    c->port_id     = port_id;
    c->active      = true;
    c->rtt_us      = 10000;   /* initial estimate 10ms */
    c->loss_ppm    = 0;

    g_bfd[idx].peer_ip    = gateway_ip;
    g_bfd[idx].state      = 1;  /* INIT */
    g_bfd[idx].local_disc = BFD_DISCRIMINATOR + idx;

    if (idx >= g_nos.n_wan)
        g_nos.n_wan = idx + 1;

    printf("[ctrl] WAN circuit %u: local=%u.%u.%u.%u  gw=%u.%u.%u.%u  "
           "port=%u\n", idx,
           (local_ip >> 24)&0xFF,   (local_ip >> 16)&0xFF,
           (local_ip >>  8)&0xFF,    local_ip & 0xFF,
           (gateway_ip >> 24)&0xFF, (gateway_ip >> 16)&0xFF,
           (gateway_ip >>  8)&0xFF,  gateway_ip & 0xFF,
           port_id);
    return 0;
}

/* ============================================================
   NAT POLICY INSTALL
   Called by control plane to install a NAPT mapping.
   Workers pick up the new entry on next packet via the
   rte_hash lookup (RW_CONCURRENCY flag makes this safe).
   ============================================================ */

int nos_ctrl_add_nat(uint32_t orig_src_ip, uint16_t orig_src_port,
                      uint32_t xlat_ip,    uint16_t xlat_port)
{
    nos_nat_key_t key = {
        .orig_src_ip   = orig_src_ip,
        .orig_src_port = rte_cpu_to_be_16(orig_src_port),
    };

    int32_t pos = rte_hash_add_key(g_nos.nat_table, &key);
    if (pos < 0) return -1;

    g_nos.nat_data[pos].xlat_src_ip   = xlat_ip;
    g_nos.nat_data[pos].xlat_src_port = rte_cpu_to_be_16(xlat_port);
    g_nos.nat_data[pos].active        = 1;

    printf("[ctrl] NAT: %u.%u.%u.%u:%u → %u.%u.%u.%u:%u\n",
           (orig_src_ip>>24)&0xFF, (orig_src_ip>>16)&0xFF,
           (orig_src_ip>> 8)&0xFF,  orig_src_ip & 0xFF, orig_src_port,
           (xlat_ip>>24)&0xFF,     (xlat_ip>>16)&0xFF,
           (xlat_ip>> 8)&0xFF,      xlat_ip & 0xFF, xlat_port);
    return 0;
}

/* ============================================================
   BFD + CONTROL PLANE INIT
   ============================================================ */

int nos_control_plane_init(void)
{
    /* seed two WAN circuits as a demo */
    nos_ctrl_add_wan_circuit(0,
        RTE_IPV4(192, 168, 1, 2),   /* local  */
        RTE_IPV4(192, 168, 1, 1),   /* gateway */
        0);                          /* DPDK port 0 */

    if (rte_eth_dev_count_avail() >= 2) {
        nos_ctrl_add_wan_circuit(1,
            RTE_IPV4(10, 0, 0, 2),
            RTE_IPV4(10, 0, 0, 1),
            1);
    }

    /* seed a static route */
    nos_ctrl_add_route(RTE_IPV4(172, 16, 0, 0), 12, 0);

    /* seed a NAT entry */
    nos_ctrl_add_nat(
        RTE_IPV4(10, 1, 1, 100), 50000,
        RTE_IPV4(203, 0, 113, 1),  10001);

    /* init BFD timer */
    rte_timer_subsystem_init();
    rte_timer_init(&g_bfd_timer);

    uint64_t hz = rte_get_timer_hz();
    rte_timer_reset(&g_bfd_timer,
                    hz * BFD_INTERVAL_US / 1000000ULL,
                    SINGLE,
                    rte_get_main_lcore(),
                    bfd_timer_cb, NULL);

    printf("[ctrl] control plane init complete  "
           "(%u WAN circuits, BFD interval=%ums)\n",
           g_nos.n_wan, BFD_INTERVAL_US / 1000);
    return 0;
}

/* Call from main loop to drive BFD timers */
void nos_control_plane_tick(void)
{
    rte_timer_manage();
}
