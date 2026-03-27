#include "nos.h"
#include "nos_crypto.h"
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>


static void nos_signal_handler(int sig)
{
    printf("\n[nos] caught signal %d — stopping\n", sig);
    g_nos.running = false;
}

static void nos_assign_lcore_roles(void)
{
    unsigned lcore_id;
    uint8_t poller_count = 0, worker_count = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        nos_lcore_ctx_t *ctx = &g_nos.lcore[lcore_id];
        memset(ctx, 0, sizeof(*ctx));
        rte_atomic64_init(&ctx->pkts_rx);
        rte_atomic64_init(&ctx->pkts_tx);
        rte_atomic64_init(&ctx->pkts_dropped);
        rte_atomic64_init(&ctx->sessions_created);
        rte_atomic64_init(&ctx->sessions_offloaded);
        ctx->lcore_id = lcore_id;
        if (poller_count < g_nos.n_pollers) {
            ctx->role = NOS_THREAD_POLLER;
            uint16_t p = 0, port_id;
            RTE_ETH_FOREACH_DEV(port_id) {
                if (p >= NOS_MAX_PORTS) break;
                ctx->rx_ports[p] = port_id;
                ctx->rx_queues[p] = 0;
                p++;
            }
            ctx->n_rx_ports = p;
            poller_count++;
            printf("[assign] lcore %u → POLLER (%u ports)\n",
                   lcore_id, ctx->n_rx_ports);
        } else if (worker_count < g_nos.n_workers) {
            ctx->role      = NOS_THREAD_WORKER;
            ctx->work_ring = g_nos.poller_to_worker[worker_count++];
            printf("[assign] lcore %u → WORKER\n", lcore_id);
        } else {
            ctx->role = NOS_THREAD_CONTROL;
            printf("[assign] lcore %u → CONTROL\n", lcore_id);
        }
    }
}

int main(int argc, char **argv)
{
    signal(SIGINT,  nos_signal_handler);
    signal(SIGTERM, nos_signal_handler);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║  NOS-like DPDK Data Plane                ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    if (nos_init(argc, argv) != 0) return 1;
    if (nos_crypto_init()    != 0) return 1;
    nos_control_plane_init();
    nos_assign_lcore_roles();

    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        nos_lcore_ctx_t *ctx = &g_nos.lcore[lcore_id];
        if (ctx->role != NOS_THREAD_CONTROL)
            rte_eal_remote_launch(nos_lcore_dispatch, NULL, lcore_id);
    }

    printf("\n[nos] running — Ctrl-C to stop\n\n");
    while (g_nos.running) {
        nos_control_plane_tick();   /* drive BFD timers */
        sleep(5);
        if (g_nos.running) nos_stats_dump();
    }

    rte_eal_mp_wait_lcore();
    nos_stats_dump();
    uint16_t port_id;
    RTE_ETH_FOREACH_DEV(port_id) {
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }
    rte_eal_cleanup();
    return 0;
}
