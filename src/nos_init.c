#include "nos.h"
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_lpm.h>
#include <rte_jhash.h>
#include <stdio.h>
#include <string.h>

nos_global_t g_nos = {0};

#define RX_RING_SIZE  1024
#define TX_RING_SIZE  1024
#define NUM_RX_QUEUES 1
#define NUM_TX_QUEUES 1

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
    },
    .rx_adv_conf = {
        .rss_conf = {
            /* hash on src+dst IP + src+dst port + proto —
               same 5-tuple as NOS session key */
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
        /* enable hardware checksum offload on TX */
        .offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                    RTE_ETH_TX_OFFLOAD_TCP_CKSUM  |
                    RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
    },
};

int nos_port_init(uint16_t port_id, struct rte_mempool *pool)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf   txconf;
    int ret;

    if (!rte_eth_dev_is_valid_port(port_id)) {
        printf("[nos] port %u is invalid\n", port_id);
        return -1;
    }

    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret) return ret;

    /* configure the port */
    ret = rte_eth_dev_configure(port_id, NUM_RX_QUEUES, NUM_TX_QUEUES,
                                &port_conf);
    if (ret) {
        printf("[nos] rte_eth_dev_configure port %u failed: %d\n",
               port_id, ret);
        return ret;
    }

    /* adjust MTU */
    ret = rte_eth_dev_set_mtu(port_id, 1500);
    if (ret && ret != -ENOTSUP) return ret;

    /* setup RX queue — one per port for simplicity.
       In a real NOS deployment this would be per-poller-core queue */
    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
                                 rte_eth_dev_socket_id(port_id),
                                 NULL, pool);
    if (ret) {
        printf("[nos] rx_queue_setup port %u failed: %d\n", port_id, ret);
        return ret;
    }

    /* setup TX queue with hardware offloads */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE,
                                 rte_eth_dev_socket_id(port_id), &txconf);
    if (ret) {
        printf("[nos] tx_queue_setup port %u failed: %d\n", port_id, ret);
        return ret;
    }

    /* start the port */
    ret = rte_eth_dev_start(port_id);
    if (ret) {
        printf("[nos] dev_start port %u failed: %d\n", port_id, ret);
        return ret;
    }

    rte_eth_promiscuous_enable(port_id);

    printf("[nos] port %u initialized (socket %d, %s)\n",
           port_id,
           rte_eth_dev_socket_id(port_id),
           dev_info.driver_name);
    return 0;
}

static int nos_session_table_init(void)
{
    struct rte_hash_parameters hp = {
        .name       = "nos_sessions",
        .entries    = NOS_SESSION_MAX,
        .key_len    = sizeof(nos_session_key_t),
        /* jhash is DPDK's built-in hash — fast, good distribution.
           In production you'd tune the hash seed for your traffic mix */
        .hash_func  = rte_jhash,
        .hash_func_init_val = 0,
        /* RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY gives lock-free reads,
           single-writer per bucket — exactly what NOS's worker model needs:
           each session is owned by one worker (hash-pinned), so workers
           never contend on the same bucket */
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
        .socket_id  = rte_socket_id(),
    };

    g_nos.session_table = rte_hash_create(&hp);
    if (!g_nos.session_table) {
        printf("[nos] session hash table creation failed\n");
        return -1;
    }

    /* flat session data array — rte_hash stores position → we index here */
    g_nos.session_data = rte_zmalloc("nos_sess_data",
                                      sizeof(nos_session_t) * NOS_SESSION_MAX,
                                      RTE_CACHE_LINE_SIZE);
    if (!g_nos.session_data) return -1;

    printf("[nos] session table: %u max entries\n", NOS_SESSION_MAX);
    return 0;
}

static int nos_fib_init(void)
{
    struct rte_lpm_config lpm_cfg = {
        .max_rules    = NOS_FIB_MAX_RULES,
        .number_tbl8s = 256,
    };

    g_nos.lpm_v4 = rte_lpm_create("nos_fib_v4", rte_socket_id(), &lpm_cfg);
    if (!g_nos.lpm_v4) {
        printf("[nos] LPM FIB creation failed\n");
        return -1;
    }

    /* add a default route: 0.0.0.0/0 → WAN port 0 (next_hop = 0).
       In a real deployment the SD-WAN controller pushes routes via
       the binary API equivalent — here we seed one static default. */
    rte_lpm_add(g_nos.lpm_v4, RTE_IPV4(0,0,0,0), 0, 0);
    /* example LAN subnet: 10.0.0.0/8 → port 1 (next_hop = 1) */
    rte_lpm_add(g_nos.lpm_v4, RTE_IPV4(10,0,0,0), 8, 1);

    printf("[nos] FIB: LPM v4 initialized (%u max rules)\n",
           NOS_FIB_MAX_RULES);
    return 0;
}

static int nos_rings_init(void)
{
    char name[64];
    unsigned n_workers = g_nos.n_workers;

    /* one ring per worker: poller bursts packets in, worker drains */
    for (unsigned i = 0; i < n_workers; i++) {
        snprintf(name, sizeof(name), "nos_p2w_%u", i);
        g_nos.poller_to_worker[i] = rte_ring_create(name, NOS_RING_SIZE,
                                        rte_socket_id(),
                                        RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!g_nos.poller_to_worker[i]) {
            printf("[nos] ring %s creation failed\n", name);
            return -1;
        }
    }

    n_workers = 16;
    /* single TX ring: workers enqueue processed mbufs, pollers dequeue+send */
    g_nos.worker_to_poller = rte_ring_create("nos_w2p", NOS_RING_SIZE * n_workers,
                                              rte_socket_id(),
                                              RING_F_SC_DEQ);
    if (!g_nos.worker_to_poller) {
        printf("[nos] worker_to_poller ring creation failed\n");
        return -1;
    }

    printf("[nos] rings: %u poller→worker rings + 1 worker→poller ring\n",
           n_workers);
    return 0;
}

static int nos_nat_table_init(void)
{
    struct rte_hash_parameters hp = {
        .name       = "nos_nat",
        .entries    = NOS_NAT_TABLE_SIZE,
        .key_len    = sizeof(nos_nat_key_t),
        .hash_func  = rte_jhash,
        .socket_id  = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    g_nos.nat_table = rte_hash_create(&hp);
    if (!g_nos.nat_table) return -1;

    g_nos.nat_data = rte_zmalloc("nos_nat_data",
                                  sizeof(nos_nat_entry_t) * NOS_NAT_TABLE_SIZE,
                                  RTE_CACHE_LINE_SIZE);
    return g_nos.nat_data ? 0 : -1;
}

static int nos_ipsec_table_init(void)
{
    struct rte_hash_parameters hp = {
        .name       = "nos_ipsec_sa",
        .entries    = NOS_MAX_TUNNELS,
        .key_len    = sizeof(uint32_t),   /* keyed on remote_ip */
        .hash_func  = rte_jhash,
        .socket_id  = rte_socket_id(),
    };

    g_nos.ipsec_sa_table = rte_hash_create(&hp);
    if (!g_nos.ipsec_sa_table) return -1;

    memset(g_nos.ipsec_sa, 0, sizeof(g_nos.ipsec_sa));
    printf("[nos] IPSec SA table: %u tunnel capacity\n", NOS_MAX_TUNNELS);
    return 0;
}

int nos_init(int argc, char **argv)
{
    /* --- EAL init --- */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        printf("[nos] EAL init failed: %d\n", ret);
        return -1;
    }

    printf("[nos] EAL initialized. lcores: %u  sockets: %u\n",
           rte_lcore_count(), rte_socket_count());

    /* --- mbuf pool ---
       In NOS this would be one pool per NUMA socket, NUMA-pinned.
       Here we create a single pool for portability. */
    g_nos.pktmbuf_pool = rte_pktmbuf_pool_create(
        "NOS_MBUF_POOL",
        NOS_MEMPOOL_SIZE,
        NOS_MEMPOOL_CACHE,
        0,                            /* private data size */
        NOS_MBUF_DATAROOMSZ,
        rte_socket_id());

    if (!g_nos.pktmbuf_pool) {
        printf("[nos] mbuf pool creation failed: %s\n",
               rte_strerror(rte_errno));
        return -1;
    }
    printf("[nos] mbuf pool: %u mbufs × %u bytes, cache=%u\n",
           NOS_MEMPOOL_SIZE, NOS_MBUF_DATAROOMSZ, NOS_MEMPOOL_CACHE);

    /* determine worker/poller split from available lcores.
       NOS rule: 1 poller per 4 workers; at least 1 of each. */
    unsigned n_lcores = rte_lcore_count();
    g_nos.n_pollers = (n_lcores > 4) ? 2 : 1;
    g_nos.n_workers = n_lcores - g_nos.n_pollers - 1; /* -1 for main */
    if (g_nos.n_workers < 1) g_nos.n_workers = 1;
    printf("[nos] thread model: %u pollers, %u workers\n",
           g_nos.n_pollers, g_nos.n_workers);

    /* --- subsystem init --- */
    if (nos_session_table_init() != 0) return -1;
    if (nos_fib_init()           != 0) return -1;
    if (nos_rings_init()         != 0) return -1;
    if (nos_nat_table_init()     != 0) return -1;
    if (nos_ipsec_table_init()   != 0) return -1;

    /* --- port init --- */
    uint16_t port_id, n_ports = rte_eth_dev_count_avail();
    printf("[nos] found %u Ethernet ports\n", n_ports);

    RTE_ETH_FOREACH_DEV(port_id) {
        if (nos_port_init(port_id, g_nos.pktmbuf_pool) != 0) {
            printf("[nos] skipping port %u\n", port_id);
        }
    }

    g_nos.running = true;
    printf("[nos] init complete\n");
    return 0;
}
