#include "nos.h"
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_cycles.h>
#include <stdio.h>

/* ============================================================
   POLLER THREAD

   NOS design: poller cores own the NIC queues entirely.
   They run at 100% CPU (no sleep, no interrupt) polling
   RX queues with rte_eth_rx_burst(), then distribute
   bursts across worker rings using a hash of the packet's
   RSS hash (already computed by NIC RSS — same hash that
   pins flows to queues).

   Pollers also drain the worker→poller TX ring and call
   rte_eth_tx_burst() to send completed packets.
   ============================================================ */

void nos_poller_loop(nos_lcore_ctx_t *ctx)
{
    struct rte_mbuf *rx_pkts[NOS_BURST_SIZE];
    struct rte_mbuf *tx_pkts[NOS_BURST_SIZE];
    uint16_t n_rx, n_tx, sent;
    unsigned n_workers = g_nos.n_workers;

    printf("[poller lcore %u] starting — polling %u ports\n",
           ctx->lcore_id, ctx->n_rx_ports);

    while (likely(g_nos.running)) {

        /* --- RX: drain all assigned NIC queues --- */
        for (uint8_t p = 0; p < ctx->n_rx_ports; p++) {
            uint16_t port  = ctx->rx_ports[p];
            uint16_t queue = ctx->rx_queues[p];

            n_rx = rte_eth_rx_burst(port, queue, rx_pkts, NOS_BURST_SIZE);
            if (unlikely(n_rx == 0))
                continue;

            rte_atomic64_add(&ctx->pkts_rx, n_rx);

            /* distribute to workers by flow hash.
               NIC RSS already computed rte_mbuf.hash.rss — we use
               that modulo n_workers to select the ring.
               This is the same mechanism NOS uses to achieve
               per-session core affinity without extra hashing. */
            for (uint16_t i = 0; i < n_rx; i++) {
                uint32_t h    = rx_pkts[i]->hash.rss;
                uint32_t wid  = h % n_workers;
                struct rte_ring *ring = g_nos.poller_to_worker[wid];

                if (unlikely(rte_ring_enqueue(ring, rx_pkts[i]) != 0)) {
                    rte_pktmbuf_free(rx_pkts[i]);
                    rte_atomic64_inc(&ctx->pkts_dropped);
                }
            }
        }

        /* --- TX: drain worker→poller ring and send --- */
        n_tx = rte_ring_dequeue_burst(g_nos.worker_to_poller,
                                       (void **)tx_pkts,
                                       NOS_BURST_SIZE, NULL);
        if (n_tx > 0) {
            /* group by output port for efficient tx_burst */
            /* simplified: send all on the port stored in mbuf->port */
            for (uint16_t i = 0; i < n_tx; ) {
                uint16_t port = tx_pkts[i]->port;
                uint16_t j = i;
                while (j < n_tx && tx_pkts[j]->port == port) j++;

                sent = rte_eth_tx_burst(port, 0, &tx_pkts[i], j - i);
                /* free any unsent mbufs */
                for (uint16_t k = i + sent; k < j; k++) {
                    rte_pktmbuf_free(tx_pkts[k]);
                    rte_atomic64_inc(&ctx->pkts_dropped);
                }
                i = j;
            }
        }
    }

    printf("[poller lcore %u] stopping\n", ctx->lcore_id);
}

/* ============================================================
   WORKER THREAD

   Workers own the entire L4-L7 processing pipeline:
     session lookup → AppID → NAT → IPSec → path selection → forward

   Each worker drains its dedicated ring (flow-pinned by RSS hash),
   so all packets of a given session always arrive at the same worker.
   This means:
     - Session state needs no locking (single writer)
     - NAT port allocations are per-core (no contention)
     - IPSec sequence numbers are per-SA per-worker (no contention)

   This is the direct equivalent of NOS's worker thread model
   described in the Versa support documentation.
   ============================================================ */

void nos_worker_loop(nos_lcore_ctx_t *ctx)
{
    struct rte_mbuf *pkts[NOS_BURST_SIZE];
    uint16_t n;

    printf("[worker lcore %u] starting\n", ctx->lcore_id);

    while (likely(g_nos.running)) {
        n = rte_ring_dequeue_burst(ctx->work_ring,
                                    (void **)pkts,
                                    NOS_BURST_SIZE, NULL);
        if (likely(n > 0))
            nos_process_burst(pkts, n, ctx);

        /* yield occasionally to avoid monopolising bus
           (NOS uses isolcpus for true 100% but we're polite here) */
    }

    printf("[worker lcore %u] stopping\n", ctx->lcore_id);
}

/* ============================================================
   LCORE DISPATCH
   Called by rte_eal_remote_launch() for each non-main lcore.
   Reads the pre-assigned role from the global ctx array.
   ============================================================ */

int nos_lcore_dispatch(void *arg)
{
    (void)arg;
    unsigned lcore_id = rte_lcore_id();
    nos_lcore_ctx_t *ctx = &g_nos.lcore[lcore_id];
    ctx->lcore_id = lcore_id;

    switch (ctx->role) {
    case NOS_THREAD_POLLER:
        nos_poller_loop(ctx);
        break;
    case NOS_THREAD_WORKER:
        nos_worker_loop(ctx);
        break;
    default:
        printf("[lcore %u] no role assigned\n", lcore_id);
        break;
    }
    return 0;
}
