/*
 * QEMU rocker switch emulation - SecY support
 *
 * Copyright (c) 2018 lkpdn <den@klaipeden.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "qemu/osdep.h"
#include "net/eth.h"
#include "qapi/error.h"
#include "qemu/iov.h"
#include "qemu/timer.h"
#include "qmp-commands.h"
#include "crypto/aead.h"
#include "crypto/cipher.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_fp.h"
#include "rocker_lp.h"
#include "rocker_tlv.h"
#include "rocker_world.h"
#include "rocker_desc.h"
#include "rocker_secy.h"

#define MACSEC_NUM_AN 4
#define MI_LEN 12

typedef uint64_t sci_t;

typedef struct secy SecY;
typedef struct sc SC;
typedef struct tx_sc TxSC;
typedef struct rx_sc RxSC;
typedef struct sak SAK;

typedef struct ki {
    uint8_t mi[MI_LEN];
    uint32_t kn;
} ki_t;

typedef struct sak {
    ki_t ki;
    bool transmits;
    int64_t created_time;
    QCryptoAead *cipher;
} SAK;

typedef struct sci_table {
    World *world;

    /* Quite a few virtual MACs or layered SecY might be present
     * as noted in IEEE 802.1AE-2006 7.1.2 NOTE 1, however no
     * matter how much there are, the maximum number of SCIs is
     * 2^16 because of logical ports implementation.
     */
    GHashTable *tbl;
    unsigned int tbl_max_size;

    SecY *secys[64];
} SCITable;

typedef struct provided_interface {
    bool mac_enabled;
    bool mac_operational;
    bool oper_point_to_point_mac;
} ProvidedInterface;

typedef struct secy_vport {
    LgPort *lg_port;
} SecYVPort;

typedef struct sa_common {
    uint32_t next_pn;
    SAK sak;
} SACommon;

typedef struct tx_sa {
    SACommon sa_common;
} TxSA;

typedef struct rx_sa {
    SACommon sa_common;
} RxSA;

typedef struct sc_common {
    sci_t sci;
    bool is_tx;

    int64_t created_time;
    int64_t started_time;
    int64_t stopped_time;

    SecY *secy;
} SCCommon;

typedef struct tx_sc {
    SCCommon sc_common;

    bool transmitting;

    uint8_t encoding_sa;
    struct tx_sa *txa[MACSEC_NUM_AN];
} TxSC;

typedef struct rx_sc {
    SCCommon sc_common;

    bool receiving;

    sci_t tx_sci;

    /* IEEE 802.1AE-2006 7.1.3 bounds the maximum
     * time two SAs interleaving to 0.5 sec */
    bool interleaving;
    int64_t last_interleaved_time;

    struct rx_sa *rxa[MACSEC_NUM_AN];

    QLIST_ENTRY(rx_sc) next;
} RxSC;

typedef struct ciphersuite {
    uint64_t id;
    char *name;
    bool integrity_protection;
    bool confidentiality_protection;
    bool changed_data_len;
    int icv_len;
} CipherSuite;

typedef struct secy {
    World *world;
    uint32_t pport;
    SecYVPort vport;

    sci_t sci;
    ProvidedInterface *c_port;
    ProvidedInterface *u_port;

    QLIST_HEAD(, rx_sc) rx_scs;
    TxSC *tx_sc;

    CipherSuite *current_ciphersuite;
    QLIST_HEAD(, CipherSuite) ciphersuites;
} SecY;

#pragma pack(push, 1)
typedef struct sectag {
    uint8_t tci_an;
    uint8_t short_len;
    __be32 pn;
    __be64 sci;
} SecTAG;
#pragma pack(pop)

typedef struct secy_context {
    uint32_t in_pport;
    uint32_t out_pport;
    struct iovec *iov;
    int iovcnt;
    SCITable *sci_table;
    SecY *secy;
    SACommon *sa;
    SecTAG *sectag;
} SecYContext;

/*
 * MACsec Virtual Ports Manipulations
 */
static char *secy_lg_get_name(LgPort *port)
{
    return NULL;
}

static void secy_lg_set_name(LgPort *port, char *name)
{
}

static bool secy_lg_get_link_up(LgPort *port)
{
    return true;
}

static void secy_lg_set_link(LgPort *port, bool up)
{
}

static void secy_lg_get_macaddr(LgPort *port, MACAddr *macaddr)
{
}

static void secy_lg_set_macaddr(LgPort *port, MACAddr *macaddr)
{
}

static uint8_t secy_lg_get_learning(LgPort *port)
{
    return 0;
}

static void secy_lg_set_learning(LgPort *port, uint8_t learning)
{
}

static bool secy_lg_enabled(LgPort *port)
{
    return true;
}

static void secy_lg_enable(LgPort *port)
{
}

static void secy_lg_disable(LgPort *port)
{
}

static void secy_lg_free(LgPort *port)
{
}

static void secy_lg_reset(LgPort *port)
{
}

static LgPortOps secy_lg_ops = {
    .get_name = secy_lg_get_name,
    .set_name = secy_lg_set_name,
    .get_link_up = secy_lg_get_link_up,
    .set_link = secy_lg_set_link,
    .get_macaddr = secy_lg_get_macaddr,
    .set_macaddr = secy_lg_set_macaddr,
    .get_learning = secy_lg_get_learning,
    .set_learning = secy_lg_set_learning,
    .enabled = secy_lg_enabled,
    .enable = secy_lg_enable,
    .disable = secy_lg_disable,
    .free = secy_lg_free,
    .reset = secy_lg_reset,
};

/*
 * For secure frame generation/validation
 */
typedef enum {
    MACSEC_CIPHER_ID_GCM_AES_128,
    MACSEC_CIPHER_ID_GCM_AES_256,
} MACsec_Cipher_Id;

static QCryptoAead *alloc_cipher_context(MACsec_Cipher_Id cipher_id,
                                         uint8_t *key)
{
    Error *err = NULL;
    size_t nkey;
    int alg, mode;

    switch (cipher_id) {
    case MACSEC_CIPHER_ID_GCM_AES_128:
        alg = QCRYPTO_CIPHER_ALG_AES_128;
        mode = QCRYPTO_CIPHER_MODE_GCM;
        break;
    case MACSEC_CIPHER_ID_GCM_AES_256:
        alg = QCRYPTO_CIPHER_ALG_AES_256;
        mode = QCRYPTO_CIPHER_MODE_GCM;
        break;
    }

    nkey = qcrypto_cipher_get_key_len(alg);

    return qcrypto_aead_new(alg, mode, key, nkey, &err);
}

static int set_nonce(SecY *secy, SecYContext *ctx)
{
    uint8_t an;
    uint32_t pn;
    uint8_t iv[12];
    size_t tag_len;
    Error *err = NULL;

    tag_len = 8; /* XXX */
    an = secy->tx_sc->encoding_sa;
    pn = secy->tx_sc->txa[an]->sa_common.next_pn;

    iv[0] = cpu_to_be64(secy->sci);
    iv[8] = cpu_to_be32(pn);

    if (qcrypto_aead_set_nonce(ctx->sa->sak.cipher, iv, 12, ctx->iov[0].iov_len,
                               ctx->iov[1].iov_len, tag_len, &err)) {
        return -ROCKER_SECY_CRYPTO_ERR;
    }

    if (qcrypto_aead_authenticate(ctx->sa->sak.cipher, ctx->iov[0].iov_base,
                                  ctx->iov[0].iov_len, &err)) {
        return -ROCKER_SECY_CRYPTO_ERR;
    }

    return 0;
}

static int do_decrypt(SecYContext *ctx)
{
    int ret;
    uint8_t iv[8]; /* XXX */
    struct iovec out_iovec;
    size_t sec_len, tag_len;
    Error *err = NULL;

    sec_len = ctx->iov[1].iov_len;
    tag_len = ctx->iov[2].iov_len;

    out_iovec.iov_base = g_malloc(sec_len + tag_len);
    out_iovec.iov_len  = sec_len + tag_len;

    ret = qcrypto_aead_decrypt(ctx->sa->sak.cipher, ctx->iov[1].iov_base,
                               sec_len + tag_len, out_iovec.iov_base,
                               sec_len + tag_len, &err);
    if (ret) {
        goto err_out;
    }

    ret = qcrypto_aead_get_tag(ctx->sa->sak.cipher, out_iovec.iov_base + sec_len,
                               tag_len, &err);
    if (ret) {
        goto err_out;
    }

    iv[0] = cpu_to_be64(ctx->secy->sci);
    iv[8] = cpu_to_be32(ctx->sa->next_pn);
    if (memcmp(out_iovec.iov_base + sec_len, iv, 8)) {
        goto err_out;
    }

    g_free(ctx->iov[1].iov_base);
    ctx->iov[1].iov_base = out_iovec.iov_base;
    ctx->iov[1].iov_len = sec_len;

    return -ROCKER_SECY_CRYPTO_OK;

err_out:
    error_report_err(err);
    g_free(out_iovec.iov_base);
    return -ROCKER_SECY_CRYPTO_ERR;
}

static int do_encrypt(SecYContext *ctx)
{
    int ret;
    int sec_len, tag_len;
    struct iovec out_iovec;
    Error *err = NULL;

    sec_len = ctx->iov[1].iov_len;
    tag_len = 8; /* XXX */

    out_iovec.iov_base = g_malloc(sec_len + tag_len);
    out_iovec.iov_len  = sec_len + tag_len;

    ret = qcrypto_aead_encrypt(ctx->sa->sak.cipher, ctx->iov[1].iov_base,
                               sec_len, out_iovec.iov_base,
                               sec_len + tag_len, &err);
    if (ret) {
        goto err_out;
    }

    ret = qcrypto_aead_get_tag(ctx->sa->sak.cipher,
                               out_iovec.iov_base + sec_len, tag_len, &err);
    if (ret) {
        goto err_out;
    }

    g_free(ctx->iov[1].iov_base);
    ctx->iov[1].iov_base = out_iovec.iov_base;

    return ROCKER_SECY_CRYPTO_OK;

err_out:
    error_report_err(err);
    g_free(out_iovec.iov_base);
    return -ROCKER_SECY_CRYPTO_ERR;
}

static int fill_ctx(SecYContext *ctx, const struct iovec *iov, int iovcnt,
                    SecY *secy)
{
    static SecTAG sectag;
    int i, remaining, copy, cur;
    void *pos;

    cur = 0;

    ctx->iov[0].iov_base = g_malloc(sizeof(struct eth_header) +
                                    sizeof(SecTAG));

    /* move DA/SA and append SecTAG including ET */
    pos = ctx->iov[0].iov_base;
    remaining = 12;
    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > remaining)
            copy = remaining;
        else
            copy = iov[i].iov_len;

        memcpy(pos, iov[i].iov_base, copy);
        pos += copy;
        ctx->iov[0].iov_len += copy;
        remaining -= copy;

        if (!remaining)
            break;

        cur += 1;
    }

    if (remaining)
        return -1;

    for (i = 3; cur < iovcnt; cur++) {
        ctx->iov[i].iov_base = iov[cur].iov_base;
        ctx->iov[i].iov_len = iov[cur].iov_len;
    }

    memcpy(pos, &sectag, sizeof(sectag));

    /* vlan tag insertion may occur */
    ctx->iov[1].iov_base = pos + sizeof(sectag);
    ctx->iov[1].iov_len = 0;

    return 0;
}

/*
 * SC manipulations
 */
static TxSC *txsc_find(SCITable *sci_table, sci_t sci)
{
    SCCommon *sc;

    sc = g_hash_table_lookup(sci_table->tbl, (uint64_t *)&sci);
    if (sc && sc->is_tx)
        return (TxSC *)sc;

    return NULL;
}

static RxSC *rxsc_find(SCITable *sci_table, sci_t sci)
{
    SCCommon *sc;

    sc = g_hash_table_lookup(sci_table->tbl, (uint64_t *)&sci);
    if (sc && !sc->is_tx)
        return (RxSC *)sc;

    return NULL;
}

static SecY *secy_find(SCITable *sci_table, sci_t sci)
{
    SCCommon *sc;

    sc = g_hash_table_lookup(sci_table->tbl, (uint64_t *)&sci);
    if (sc)
        return sc->secy;

    return NULL;
}

static int txsc_add(SCITable *sci_table, sci_t sci, SecY *secy)
{
    TxSC *tx_sc;

    tx_sc = txsc_find(sci_table, sci);
    if (tx_sc)
        /* TODO: maybe we better to reset some params to default */
        return 0;

    tx_sc = g_new0(TxSC, 1);
    tx_sc->sc_common.sci = sci;
    tx_sc->sc_common.is_tx = true;

    g_hash_table_insert(sci_table->tbl, &(tx_sc->sc_common.sci), tx_sc);

    tx_sc->sc_common.secy = secy;
    secy->tx_sc = tx_sc;
    return 0;
}

static int rxsc_add(SCITable *sci_table, sci_t sci, sci_t tx_sci, SecY *secy)
{
    RxSC *rx_sc;

    rx_sc = rxsc_find(sci_table, sci);
    if (rx_sc)
        /* TODO: maybe we better to reset some params to default */
        return 0;

    rx_sc = g_new0(RxSC, 1);
    rx_sc->sc_common.sci = sci;
    rx_sc->sc_common.is_tx = false;
    rx_sc->tx_sci = tx_sci;

    g_hash_table_insert(sci_table->tbl, &(rx_sc->sc_common.sci), rx_sc);

    QLIST_INSERT_HEAD(&secy->rx_scs, rx_sc, next);
    rx_sc->sc_common.secy = secy;
    return 0;
}

static void txsc_del(SCITable *sci_table, sci_t sci)
{
    g_free(txsc_find(sci_table, sci));
}

static void rxsc_del(SCITable *sci_table, sci_t sci)
{
    g_free(rxsc_find(sci_table, sci));
}

static SecY *secy_alloc(SCITable *sci_table, sci_t sci, uint32_t pport)
{
    LgPort *port;
    SecY *secy;

    secy = g_new0(SecY, 1);
    secy->world = sci_table->world;
    secy->pport = pport;
    secy->sci = sci;

    port = lg_port_alloc(0, NULL, pport, &secy_lg_ops);
    secy->vport.lg_port = port;

    sci_table->secys[pport] = secy;

    return secy;
}

static void secy_del(SCITable *sci_table, SecY *secy)
{
    RxSC *rxsc;

    QLIST_FOREACH(rxsc, &secy->rx_scs, next) {
        g_free(rxsc);
    }
    g_free(secy->tx_sc);
    g_hash_table_remove(sci_table->tbl, &(secy->sci));
    g_free(secy->vport.lg_port);
    g_free(secy);
}

static void secy_del_sc(SCITable *tbl, sci_t sci)
{
    txsc_del(tbl, sci);
    rxsc_del(tbl, sci);
}

static int secy_add_sa(SCITable *sci_table, sci_t sci, uint8_t an, uint32_t pn,
                       MACsec_Cipher_Id cipher_id, uint8_t *key, uint8_t *ki)
{
    SAK *sak;
    TxSC *tx_sc;
    RxSC *rx_sc;
    TxSA *tx_sa;
    RxSA *rx_sa;

    tx_sc = txsc_find(sci_table, sci);
    rx_sc = rxsc_find(sci_table, sci);
    if (!(!!tx_sc ^ !!rx_sc))
        return 0; /* may i return an error */

    if (tx_sc) {
        tx_sa = g_new0(TxSA, 1);
        tx_sa->sa_common.next_pn = pn;
        tx_sc->txa[an] = tx_sa;
        sak = &tx_sc->txa[an]->sa_common.sak;
    } else {
        rx_sa = g_new0(RxSA, 1);
        rx_sa->sa_common.next_pn = pn;
        rx_sc->rxa[an] = rx_sa;
        sak = &rx_sc->rxa[an]->sa_common.sak;
    }

    sak->cipher = alloc_cipher_context(cipher_id, key);

    return 0;
}

static void secy_del_sa(SCITable *sci_table, sci_t sci, uint8_t an, uint32_t pn)
{
    TxSC *tx_sc;
    RxSC *rx_sc;

    tx_sc = txsc_find(sci_table, sci);
    if (tx_sc && tx_sc->txa[an])
        g_free(tx_sc->txa[an]);

    rx_sc = rxsc_find(sci_table, sci);
    if (rx_sc && rx_sc->rxa[an])
        g_free(rx_sc->rxa[an]);
}

static void notify_stats(struct secy_context *ctx)
{
}

/*
 * Multiplexing/Demultiplexing
 */
static void notify_secy(SecY *secy)
{
}

static void secy_drop(struct secy_context *ctx)
{
}

static int secy_decrypt(struct secy_context *ctx)
{
    return do_decrypt(ctx);
}

static int secy_encrypt(struct secy_context *ctx, SecY *secy)
{
    int ret;

    ret = set_nonce(secy, ctx);

    if (ret)
        return ret;

    return do_encrypt(ctx);
}

static void c_port_rx(struct secy_context *ctx)
{
    if (ctx->out_pport == 0) {
        /* Deliver to the higher layer entities (LLC), which is facing bridge
         * port TX/RX over secure ISS, and the way these packets will be
         * handled in the control plane is symmetrical in virtue of newly
         * introduced world_egress intervention. This design choice enables
         * us to make use of various kinds of higher layer entities over the
         * secure channel, e.g. BPDU to the STP Entity. So, we forcefully set
         * offload_fwd_mark when that processing happen on control plane Linux.
         */
        rx_produce(ctx->sci_table->world, ctx->in_pport, ctx->iov,
                   ctx->iovcnt, 1);
    } else if (ctx->out_pport != ctx->in_pport) {
        /* Maybe SecY protection on out_pport happens later on fp_port_eg. */
        rocker_port_eg(world_rocker(ctx->sci_table->world), ctx->out_pport,
                       ctx->iov, ctx->iovcnt);
    }
}

static void u_port_rx(struct secy_context *ctx, const struct iovec *iov,
                      int iovcnt)
{
    /* This RX takes care of the case where for some reason, we cease to or
     * fail to offload "authorized" forwarding, plus Uncontrolled port-attached
     * higher entity.
     * In the former case, this is okay since it helps CPU-side kernel MACsec
     * processing step forward and recover when the retransmitted packet will
     * be received with its PN (Packet Number) being set to the same.
     */

    /* BIG TODOs:
     * 1). to filter out or not EAPOL frames with group destination MAC.
     * 2). we should provide admin interface which turns on or off the
     *     Unauthorized VLANs (IEEE 802.1X-2010 7.5.3). about the Selective
     *     Relay like WoL, see secy_eg().
     */
    rx_produce(ctx->sci_table->world, ctx->in_pport, iov, iovcnt, 1);
}

static int parse_sectag(struct secy_context *ctx,
                        const struct iovec *iov, int iovcnt)
{
    SecTAG *sectag = ctx->sectag;
    struct eth_header *ethhdr;
    size_t sofar = 0;
    int i;

    sofar += sizeof(struct eth_header);
    if (iov->iov_len < sofar) {
        DPRINTF("parse_sectag underrun on eth_header\n");
        return -1;
    }

    ethhdr = iov->iov_base;
    if (ethhdr->h_proto != ETH_P_MACSEC) {
        return -1;
    }

    sofar += sizeof(SecTAG);
    if (iov->iov_len < sofar) {
        DPRINTF("parse_sectag underrun on SecTAG without SCI\n");
        return -1;
    }

    sectag = (SecTAG *)(ethhdr + 1);

    if (sectag->tci_an & ROCKER_SECY_TCI_BIT_VERSION) {
        return -1;
    }
    if (sectag->tci_an & ROCKER_SECY_TCI_BIT_ES &&
        !(sectag->tci_an & ROCKER_SECY_TCI_BIT_SC)) {
        memcpy(&sectag->sci, ethhdr->h_source, ETH_ALEN);
        if (!(sectag->tci_an & ROCKER_SECY_TCI_BIT_SCB)) {
            sectag->sci[7] = 1; /* port id = 0x01 */
        }
    } else if (iov->iov_len < sofar + 8) {
        DPRINTF("parse_sectag underrun on SecTAG SCI\n");
        return -1;
    } else if (sectag->tci_an & ROCKER_SECY_TCI_BIT_ES ||
               !(sectag->tci_an & ROCKER_SECY_TCI_BIT_SC) ||
               sectag->tci_an & ROCKER_SECY_TCI_BIT_SCB) {
        DPRINTF("parse_sectag invalid TCI\n");
        return -1;
    }

    sofar += 8;

    ctx->iov[2].iov_base = iov[0].iov_base + sofar;
    ctx->iov[2].iov_len = iov[0].iov_len - sofar;

    for (i = 1; i < iovcnt; i++) {
        ctx->iov[i+2] = iov[i];
    }

    ctx->iovcnt = iovcnt + 2;

    return 0;
}

/* 'Common Port' ingress */
static ssize_t secy_ig(World *world, uint32_t pport,
                       const struct iovec *iov, int iovcnt)
{
    SCITable *sci_table = world_private(world);

    struct iovec iov_copy[iovcnt + 2];

    SecYContext ctx = {
        .in_pport = pport,
        .iov = iov_copy,
        .iovcnt = iovcnt + 2,
        .sci_table = sci_table,
    };

    if (parse_sectag(&ctx, iov, iovcnt)) {
        u_port_rx(&ctx, iov, iovcnt);
        return iov_size(iov, iovcnt);
    }

    if (secy_decrypt(&ctx)) {
        secy_drop(&ctx);
        return 0;
    }

    c_port_rx(&ctx);
    notify_stats(&ctx);

    return iov_size(iov, iovcnt);
}

/* 'Controlled Port (Secure Service Access Point)' TX request
 * reception. pport identifies the associated 'Common Port'.
 */
static int secy_eg(World *world, uint32_t pport,
                   const struct iovec *iov, int iovcnt,
                   struct iovec *new_iov, int *new_iovcnt)
{
    SCITable *sci_table = world_private(world);

    /* Two iovecs headroom for ether header + SECTAG and possibly vlan
     * tag which will be not-in-the-clear on wire, and one iovec ICV
     * in tailroom.
     */
    struct iovec iov_copy[iovcnt + 3];

    SecYContext ctx = {
        .out_pport = pport,
        .iov = iov_copy,
        .iovcnt = iovcnt,
        .sci_table = sci_table,
    };

    SecY *secy = sci_table->secys[pport];
    fill_ctx(&ctx, iov, iovcnt, secy);
    secy_encrypt(&ctx, secy);
    return 0;
}

static int secy_install_sak(SCITable *tbl, sci_t sci, int an, uint8_t *key)
{
    SAK *sak;
    TxSC *tx_sc;
    RxSC *rx_sc;

    if ((tx_sc = txsc_find(tbl, sci)) != NULL) {
        sak = &tx_sc->txa[an]->sa_common.sak;
        sak->transmits = true;
    } else if ((rx_sc = rxsc_find(tbl, sci)) != NULL) {
        sak = &rx_sc->rxa[an]->sa_common.sak;
        sak->transmits = false;
    } else {
        return -1;
    }

    sak->cipher = alloc_cipher_context(MACSEC_CIPHER_ID_GCM_AES_128, key);
    return 0;
}

static int secy_sc_cmd(SCITable *tbl, uint16_t cmd, RockerTlv **tlvs)
{
    SecY *secy;
    sci_t sci;
    sci_t tx_sci;

    if (!tlvs[ROCKER_TLV_SECY_PPORT] ||
        !tlvs[ROCKER_TLV_SECY_SCI] ||
        (!tlvs[ROCKER_TLV_SECY_TX] &&
         !tlvs[ROCKER_TLV_SECY_TX_SCI]))
        return -ROCKER_EINVAL;

    sci = (sci_t)rocker_tlv_get_le64(tlvs[ROCKER_TLV_SECY_SCI]);
    if (tlvs[ROCKER_TLV_SECY_TX_SCI])
        tx_sci = (sci_t)rocker_tlv_get_le64(tlvs[ROCKER_TLV_SECY_TX_SCI]);
    else
        tx_sci = sci;

    secy = secy_find(tbl, tx_sci);

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_SECY_ADD_TX_SC:
        secy_del_sc(tbl, sci);
        /* fall through */
    case ROCKER_TLV_CMD_TYPE_SECY_ADD_RX_SC:
        if (!secy)
            secy = secy_alloc(tbl, tx_sci,
                              rocker_tlv_get_le32(tlvs[ROCKER_TLV_SECY_PPORT]));

        if (!secy)
            return -1;
        secy->pport = rocker_tlv_get_le32(tlvs[ROCKER_TLV_SECY_PPORT]);

        if (sci == tx_sci) {
            txsc_add(tbl, sci, secy);
        } else {
            rxsc_add(tbl, sci, tx_sci, secy);
        }
        notify_secy(secy);
        return -ROCKER_OK;
    case ROCKER_TLV_CMD_TYPE_SECY_DEL_TX_SC:
    case ROCKER_TLV_CMD_TYPE_SECY_DEL_RX_SC:
        secy_del_sc(tbl, sci);
        notify_secy(secy);
        return -ROCKER_OK;
    }

    return -ROCKER_ENOTSUP;
}

static int secy_sa_cmd(SCITable *tbl, uint16_t cmd, RockerTlv **tlvs)
{
    sci_t sci;
    uint8_t an;
    uint32_t pn;

    MACsec_Cipher_Id cipher_id;

    if (!tlvs[ROCKER_TLV_SECY_SCI] ||
        !tlvs[ROCKER_TLV_SECY_AN] ||
        !tlvs[ROCKER_TLV_SECY_PN]) {
        return -ROCKER_EINVAL;
    }

    sci = (sci_t)rocker_tlv_get_le64(tlvs[ROCKER_TLV_SECY_SCI]);
    an = (sci_t)rocker_tlv_get_u8(tlvs[ROCKER_TLV_SECY_AN]);
    pn = (sci_t)rocker_tlv_get_le32(tlvs[ROCKER_TLV_SECY_PN]);

    cipher_id = MACSEC_CIPHER_ID_GCM_AES_128;

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_SECY_ADD_TX_SA:
    case ROCKER_TLV_CMD_TYPE_SECY_ADD_RX_SA:
        secy_add_sa(tbl, sci, an, pn, cipher_id, NULL, NULL);
        return -ROCKER_OK;
    case ROCKER_TLV_CMD_TYPE_SECY_DEL_TX_SA:
    case ROCKER_TLV_CMD_TYPE_SECY_DEL_RX_SA:
        secy_del_sa(tbl, sci, an, pn);
        return -ROCKER_OK;
    }

    return -ROCKER_ENOTSUP;
}

static int secy_sak_cmd(SCITable *tbl, uint16_t cmd, RockerTlv **tlvs)
{
    sci_t sci;
    uint8_t *sak;
    int an;

    if (!tlvs[ROCKER_TLV_SECY_SCI] ||
        !tlvs[ROCKER_TLV_SECY_AN] ||
        !tlvs[ROCKER_TLV_SECY_SAK]) {
        return -ROCKER_EINVAL;
    }

    sci = (sci_t)tlvs[ROCKER_TLV_SECY_SCI];
    an = rocker_tlv_get_le32(tlvs[ROCKER_TLV_SECY_AN]);
    sak = (uint8_t *)rocker_tlv_data(tlvs[ROCKER_TLV_SECY_SAK]);

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_SECY_INSTALL_SAK:
        secy_install_sak(tbl, sci, an, sak);
        return -ROCKER_OK;
    }

    return -ROCKER_ENOTSUP;
}

static int secy_cmd(World *world, struct desc_info *info,
                    char *buf, uint16_t cmd, RockerTlv *cmd_info_tlv)
{
    SCITable *sci_table = world_private(world);
    RockerTlv *tlvs[ROCKER_TLV_SECY_MAX + 1];

    rocker_tlv_parse_nested(tlvs, ROCKER_TLV_SECY_MAX, cmd_info_tlv);

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_SECY_ADD_TX_SC:
    case ROCKER_TLV_CMD_TYPE_SECY_ADD_RX_SC:
    case ROCKER_TLV_CMD_TYPE_SECY_DEL_TX_SC:
    case ROCKER_TLV_CMD_TYPE_SECY_DEL_RX_SC:
        return secy_sc_cmd(sci_table, cmd, tlvs);

    case ROCKER_TLV_CMD_TYPE_SECY_ADD_TX_SA:
    case ROCKER_TLV_CMD_TYPE_SECY_ADD_RX_SA:
    case ROCKER_TLV_CMD_TYPE_SECY_DEL_TX_SA:
    case ROCKER_TLV_CMD_TYPE_SECY_DEL_RX_SA:
        return secy_sa_cmd(sci_table, cmd, tlvs);

    case ROCKER_TLV_CMD_TYPE_SECY_INSTALL_SAK:
        return secy_sak_cmd(sci_table, cmd, tlvs);

    case ROCKER_TLV_CMD_TYPE_SECY_DEL:
        if (!tlvs[ROCKER_TLV_SECY_SCI])
            return -ROCKER_EINVAL;

        sci_t sci = (sci_t)rocker_tlv_get_le64(tlvs[ROCKER_TLV_SECY_SCI]);
        SecY *secy = secy_find(sci_table, sci);
        secy_del(sci_table, secy);
        return -ROCKER_OK;
    }

    return -ROCKER_ENOTSUP;
}

static int secy_init(World *world)
{
    SCITable *sci_table = world_private(world);

    sci_table->world = world;

    sci_table->tbl = g_hash_table_new_full(g_int64_hash,
                                           g_int64_equal,
                                           NULL, g_free);
    if (!sci_table->tbl) {
        return -ENOMEM;
    }

    sci_table->tbl_max_size = 32;

    return 0;
}

static void secy_uninit(World *world)
{
    SCITable *sci_table = world_private(world);

    g_hash_table_destroy(sci_table->tbl);
}

static WorldOps secy_ops = {
    .name = "secy",
    .init = secy_init,
    .uninit = secy_uninit,
    .eg = secy_eg,
    .ig = secy_ig,
    .cmd = secy_cmd,
};

World *secy_world_alloc(Rocker *r)
{
    return world_alloc(r, sizeof(SecY), ROCKER_WORLD_TYPE_SECY, &secy_ops);
}
