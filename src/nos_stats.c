#include "nos.h"
#include "nos_crypto.h"
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <stdio.h>

void nos_stats_dump(void)
{
    printf("\n=== NOS Stats ===\n");
    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        nos_lcore_ctx_t *ctx = &g_nos.lcore[lcore_id];
        const char *role = (ctx->role == NOS_THREAD_POLLER) ? "poller"
                         : (ctx->role == NOS_THREAD_WORKER) ? "worker"
                         : "ctrl";
        printf("  lcore %2u [%-6s] rx=%lu tx=%lu drop=%lu "
               "sess_new=%lu sess_offloaded=%lu\n",
               lcore_id, role,
               rte_atomic64_read(&ctx->pkts_rx),
               rte_atomic64_read(&ctx->pkts_tx),
               rte_atomic64_read(&ctx->pkts_dropped),
               rte_atomic64_read(&ctx->sessions_created),
               rte_atomic64_read(&ctx->sessions_offloaded));
    }
    uint16_t port_id;
    RTE_ETH_FOREACH_DEV(port_id) {
        struct rte_eth_stats stats;
        if (rte_eth_stats_get(port_id, &stats) == 0)
            printf("  port %u: rx=%lu tx=%lu miss=%lu err=%lu\n",
                   port_id, stats.ipackets, stats.opackets,
                   stats.imissed, stats.ierrors);
    }
    printf("  sessions: %u active / %u max\n",
           rte_hash_count(g_nos.session_table), NOS_SESSION_MAX);
    nos_crypto_show_capabilities();
    printf("=================\n\n");
}
