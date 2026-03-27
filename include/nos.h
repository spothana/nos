#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_lpm.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_malloc.h>

/* ---------- tunables ---------- */
#define NOS_MAX_PORTS        8
#define NOS_MAX_WORKERS      16
#define NOS_MAX_POLLERS      4
#define NOS_BURST_SIZE       32
#define NOS_MEMPOOL_SIZE     (1 << 16)  /* 65536 mbufs */
#define NOS_MEMPOOL_CACHE    256
#define NOS_MBUF_DATAROOMSZ  (RTE_MBUF_DEFAULT_BUF_SIZE)
#define NOS_SESSION_MAX      (1 << 18)  /* 256K sessions */
#define NOS_NAT_TABLE_SIZE   (1 << 16)
#define NOS_RING_SIZE        4096
#define NOS_MAX_TENANTS      256
#define NOS_MAX_TUNNELS      8192
#define NOS_FIB_MAX_RULES    65536
#define NOS_ACL_MAX_RULES    4096

/* ---------- thread roles ---------- */
typedef enum {
    NOS_THREAD_POLLER  = 0,
    NOS_THREAD_WORKER  = 1,
    NOS_THREAD_CONTROL = 2,
} nos_thread_role_t;

/* ---------- 5-tuple session key ---------- */
typedef struct __attribute__((packed)) {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pad[3];
} nos_session_key_t;

/* session state */
typedef enum {
    NOS_SESSION_NEW       = 0,
    NOS_SESSION_ACTIVE    = 1,
    NOS_SESSION_OFFLOADED = 2,   /* bypasses DPI after classification */
    NOS_SESSION_CLOSING   = 3,
} nos_session_state_t;

/* AppID classification result */
typedef enum {
    APP_UNKNOWN   = 0,
    APP_HTTP      = 1,
    APP_HTTPS     = 2,
    APP_DNS       = 3,
    APP_IPSEC_ESP = 4,
    APP_VOIP      = 5,
    APP_STREAMING = 6,
    APP_BULK      = 7,
} nos_app_id_t;

/* per-session entry (lives in rte_hash value) */
typedef struct {
    nos_session_key_t   key;
    nos_session_state_t state;
    nos_app_id_t        app_id;
    uint8_t             tenant_id;
    uint8_t             qos_class;      /* forwarding class 0-15 */
    uint8_t             wan_path;       /* selected WAN port */
    uint8_t             flags;
    uint32_t            pkt_count;
    uint64_t            byte_count;
    uint64_t            last_seen_tsc;  /* rte_rdtsc() at last packet */
} nos_session_t;

/* ---------- NAT entry ---------- */
typedef struct __attribute__((packed)) {
    uint32_t orig_src_ip;
    uint16_t orig_src_port;
    uint16_t _pad;
} nos_nat_key_t;

typedef struct {
    uint32_t xlat_src_ip;
    uint16_t xlat_src_port;
    uint8_t  active;
    uint8_t  _pad;
} nos_nat_entry_t;

/* ---------- IPSec tunnel ---------- */
typedef struct {
    uint32_t local_ip;
    uint32_t remote_ip;
    uint8_t  spi[4];
    uint8_t  aes_key[32];    /* AES-256-GCM key */
    uint8_t  auth_key[20];   /* for IKE-less SA distributions */
    uint32_t seq_num;
    bool     active;
    uint8_t  tenant_id;
} nos_ipsec_sa_t;

/* ---------- WAN path / circuit ---------- */
typedef struct {
    uint16_t port_id;        /* DPDK port */
    uint32_t gateway_ip;
    uint32_t local_ip;
    bool     active;
    uint32_t loss_ppm;       /* parts-per-million packet loss */
    uint32_t rtt_us;         /* measured RTT in microseconds */
    uint32_t jitter_us;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t pkts_tx;
    uint64_t pkts_rx;
} nos_wan_circuit_t;

/* ---------- per-lcore context ---------- */
typedef struct {
    unsigned           lcore_id;
    nos_thread_role_t  role;

    /* poller fields */
    uint16_t           rx_ports[NOS_MAX_PORTS];
    uint16_t           rx_queues[NOS_MAX_PORTS];
    uint8_t            n_rx_ports;
    struct rte_ring   *tx_ring;        /* poller → workers */
    struct rte_ring   *rx_ring;        /* workers → poller TX */

    /* worker fields */
    struct rte_ring   *work_ring;      /* receives from poller */

    /* stats */
    rte_atomic64_t     pkts_rx;
    rte_atomic64_t     pkts_tx;
    rte_atomic64_t     pkts_dropped;
    rte_atomic64_t     sessions_created;
    rte_atomic64_t     sessions_offloaded;
} nos_lcore_ctx_t;

/* ---------- global NOS state ---------- */
typedef struct {
    /* memory */
    struct rte_mempool  *pktmbuf_pool;

    /* session table (shared, lock-free rte_hash) */
    struct rte_hash     *session_table;
    nos_session_t       *session_data;     /* flat array indexed by hash pos */

    /* FIB for L3 forwarding */
    struct rte_lpm      *lpm_v4;

    /* NAT table */
    struct rte_hash     *nat_table;
    nos_nat_entry_t     *nat_data;

    /* IPSec SAs */
    nos_ipsec_sa_t       ipsec_sa[NOS_MAX_TUNNELS];
    struct rte_hash     *ipsec_sa_table;   /* dst_ip → SA index */

    /* WAN circuits */
    nos_wan_circuit_t    wan[NOS_MAX_PORTS];
    uint8_t              n_wan;

    /* per-lcore contexts */
    nos_lcore_ctx_t      lcore[RTE_MAX_LCORE];

    /* rings connecting pollers to workers */
    struct rte_ring     *poller_to_worker[NOS_MAX_WORKERS];
    struct rte_ring     *worker_to_poller;

    /* config */
    uint8_t              n_workers;
    uint8_t              n_pollers;
    bool                 running;
} nos_global_t;

extern nos_global_t g_nos;

/* ---------- function declarations ---------- */
int  nos_init(int argc, char **argv);
int  nos_port_init(uint16_t port_id, struct rte_mempool *pool);
void nos_poller_loop(nos_lcore_ctx_t *ctx);
void nos_worker_loop(nos_lcore_ctx_t *ctx);
int  nos_lcore_dispatch(void *arg);

/* packet processing pipeline */
void nos_process_burst(struct rte_mbuf **pkts, uint16_t n,
                       nos_lcore_ctx_t *ctx);
nos_session_t *nos_session_lookup_or_create(nos_session_key_t *key,
                                             nos_lcore_ctx_t *ctx);
int  nos_classify_app(struct rte_mbuf *pkt, nos_session_t *sess);
int  nos_nat_translate(struct rte_mbuf *pkt, nos_session_t *sess);
int  nos_select_wan_path(nos_session_t *sess);
int  nos_forward(struct rte_mbuf *pkt, nos_session_t *sess,
                 nos_lcore_ctx_t *ctx);

/* IPSec */
int  nos_ipsec_encrypt(struct rte_mbuf *pkt, nos_ipsec_sa_t *sa);
int  nos_ipsec_decrypt(struct rte_mbuf *pkt, nos_ipsec_sa_t *sa);

/* telemetry */
void nos_stats_dump(void);

/* crypto engine */
int  nos_crypto_init(void);
void nos_crypto_show_capabilities(void);
int  nos_ipsec_sa_add(uint32_t remote_ip, uint8_t *aes_key,
                       uint8_t *spi, uint8_t tenant_id);

/* control plane */
int  nos_control_plane_init(void);
void nos_control_plane_tick(void);
int  nos_ctrl_add_route(uint32_t ip, uint8_t prefix_len, uint32_t next_hop);
int  nos_ctrl_del_route(uint32_t ip, uint8_t prefix_len);
int  nos_ctrl_add_wan_circuit(uint8_t idx, uint32_t local_ip,
                               uint32_t gateway_ip, uint16_t port_id);
int  nos_ctrl_add_nat(uint32_t orig_src_ip, uint16_t orig_src_port,
                       uint32_t xlat_ip, uint16_t xlat_port);
