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

static GHashTable *fdb_table;

typedef struct fdb_key {
    MACAddr addr;
    uint16_t vlan_id;
} FDBKey;

typedef struct fdb_entry {
    bool no_secy;
    sci_t sci;
} FDBEntry;

typedef uint64_t cipher_id_t;

typedef struct secy SecY;
typedef struct sc SC;
typedef struct tx_sc TxSC;
typedef struct rx_sc RxSC;
typedef struct sak SAK;
typedef struct ciphersuite CipherSuite;

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
    struct tx_sa **txa;
} TxSC;

typedef struct rx_sc {
    SCCommon sc_common;

    bool receiving;

    sci_t tx_sci;

    /* IEEE 802.1AE-2006 7.1.3 bounds the maximum
     * time two SAs interleaving to 0.5 sec */
    bool interleaving;
    int64_t last_interleaved_time;

    struct rx_sa **rxa;

    QLIST_ENTRY(rx_sc) next;
} RxSC;

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
    uint8_t an;
    SACommon *sa;
    struct eth_header *eth_header;
    struct vlan_header *vlan_header;
    SecTAG *sectag;
    bool is_eg;
    bool processing_sec;
    bool processing_icv;
    sci_t sci;
} SecYContext;

typedef struct ciphersuite {
    uint64_t id;
    const char *name;
    bool integrity_protection;
    bool confidentiality_protection;
    int icv_len;
    int (*set_nonce)(CipherSuite *cs, SecYContext *ctx);
    int (*decrypt)(CipherSuite *cs, SecYContext *ctx);
    int (*encrypt)(CipherSuite *cs, SecYContext *ctx);
} CipherSuite;

static void secy_context_free(SecYContext *ctx)
{
    int i;

    for (i = 0; i < ctx->iovcnt; i++) {
        g_free(ctx->iov[i].iov_base);
    }
}

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
static int gcm_aes_128_set_nonce(CipherSuite *cs, SecYContext *ctx)
{
    __be32 pn;
    uint8_t iv[12];
    size_t in_len, tag_len;
    Error *err = NULL;

    tag_len = cs->icv_len;
    in_len = ctx->iov[1].iov_len;

    if (ctx->sectag && ctx->sectag->pn) {
        pn = ctx->sectag->pn;
    } else {
        pn = cpu_to_be32(ctx->sa->next_pn);
    }

    memcpy(iv, &ctx->sectag->sci, 8);
    memcpy(&iv[8], &pn, 4);

    if (!ctx->sa->sak.cipher) {
        return -ROCKER_SECY_CRYPTO_ERR;
    }

    if (qcrypto_aead_reset(ctx->sa->sak.cipher, &err)) {
        return -ROCKER_SECY_CRYPTO_ERR;
    }

    if (qcrypto_aead_set_nonce(ctx->sa->sak.cipher, iv, ARRAY_SIZE(iv),
                               ctx->iov[0].iov_len, in_len,
                               tag_len, &err)) {
        return -ROCKER_SECY_CRYPTO_ERR;
    }

    if (qcrypto_aead_authenticate(ctx->sa->sak.cipher, ctx->iov[0].iov_base,
                                  ctx->iov[0].iov_len, &err)) {
        return -ROCKER_SECY_CRYPTO_ERR;
    }

    return 0;
}

static int gcm_aes_128_decrypt(CipherSuite *cs, SecYContext *ctx)
{
    int ret;
    struct iovec out_iovec;
    size_t sec_len, tag_len;
    Error *err = NULL;

    tag_len = cs->icv_len;
    sec_len = ctx->iov[1].iov_len - tag_len;

    out_iovec.iov_base = g_malloc0(sec_len + tag_len);
    out_iovec.iov_len  = sec_len + tag_len;

    ret = qcrypto_aead_decrypt(ctx->sa->sak.cipher, ctx->iov[1].iov_base,
                               sec_len, out_iovec.iov_base,
                               sec_len, &err);
    if (ret) {
        error_report_err(err);
        goto err_out;
    }

    ret = qcrypto_aead_checktag(ctx->sa->sak.cipher,
                                ctx->iov[1].iov_base + sec_len,
                                tag_len, &err);
    if (ret) {
        error_report_err(err);
        goto err_out;
    }

    g_free(ctx->iov[1].iov_base);
    ctx->iov[1].iov_base = out_iovec.iov_base;
    ctx->iov[1].iov_len = sec_len;
    ctx->iov[0].iov_len = ETH_ALEN * 2;
    ctx->iovcnt = 2;

    return -ROCKER_SECY_CRYPTO_OK;

err_out:
    g_free(out_iovec.iov_base);
    return -ROCKER_SECY_CRYPTO_ERR;
}

static int gcm_aes_128_encrypt(CipherSuite *cs, SecYContext *ctx)
{
    int ret;
    int unsec_len, sec_len, tag_len;
    struct iovec out_iovec;
    Error *err = NULL;
    void *buf;

    /* TODO: optimise */

    unsec_len = ctx->iov[1].iov_len;
    sec_len = ROUND_UP(unsec_len, 16);
    tag_len = cs->icv_len;

    out_iovec.iov_len  = sec_len + tag_len;
    out_iovec.iov_base = g_malloc0(sec_len + tag_len);

    buf = g_malloc0(sec_len);
    memcpy(buf, ctx->iov[1].iov_base, unsec_len);

    ret = qcrypto_aead_encrypt(ctx->sa->sak.cipher, buf, sec_len,
                               out_iovec.iov_base, sec_len, &err);
    if (ret) {
        error_report_err(err);
        goto err_out;
    }

    ret = qcrypto_aead_get_tag(ctx->sa->sak.cipher,
                               out_iovec.iov_base + sec_len, tag_len, &err);
    if (ret) {
        error_report_err(err);
        goto err_out;
    }

    g_free(buf);
    g_free(ctx->iov[1].iov_base);
    ctx->iov[1].iov_base = out_iovec.iov_base;
    ctx->iov[1].iov_len = out_iovec.iov_len;

    return ROCKER_SECY_CRYPTO_OK;

err_out:
    g_free(buf);
    g_free(out_iovec.iov_base);
    return -ROCKER_SECY_CRYPTO_ERR;
}

static int gcm_aes_256_set_nonce(CipherSuite *cs, SecYContext *ctx)
{
    return ROCKER_SECY_CRYPTO_OK;
}

static int gcm_aes_256_decrypt(CipherSuite *cs, SecYContext *ctx)
{
    return ROCKER_SECY_CRYPTO_OK;
}

static int gcm_aes_256_encrypt(CipherSuite *cs, SecYContext *ctx)
{
    return ROCKER_SECY_CRYPTO_OK;
}

static int gcm_aes_xpn_128_set_nonce(CipherSuite *cs, SecYContext *ctx)
{
    return ROCKER_SECY_CRYPTO_OK;
}

static int gcm_aes_xpn_128_decrypt(CipherSuite *cs, SecYContext *ctx)
{
    return ROCKER_SECY_CRYPTO_OK;
}

static int gcm_aes_xpn_128_encrypt(CipherSuite *cs, SecYContext *ctx)
{
    return ROCKER_SECY_CRYPTO_OK;
}

static int gcm_aes_xpn_256_set_nonce(CipherSuite *cs, SecYContext *ctx)
{
    return ROCKER_SECY_CRYPTO_OK;
}

static int gcm_aes_xpn_256_decrypt(CipherSuite *cs, SecYContext *ctx)
{
    return ROCKER_SECY_CRYPTO_OK;
}

static int gcm_aes_xpn_256_encrypt(CipherSuite *cs, SecYContext *ctx)
{
    return ROCKER_SECY_CRYPTO_OK;
}

static CipherSuite ciphersuites[] = { {
    .id                         = 0x0080C20001000001,
    .name                       = "GCM-AES-128",
    .integrity_protection       = true,
    .confidentiality_protection = true,
    .icv_len                    = 16,
    .set_nonce                  = gcm_aes_128_set_nonce,
    .decrypt                    = gcm_aes_128_decrypt,
    .encrypt                    = gcm_aes_128_encrypt,
}, {
    .id                         = 0x0080C20001000002,
    .name                       = "GCM-AES-256",
    .integrity_protection       = true,
    .confidentiality_protection = true,
    .icv_len                    = 16,
    .set_nonce                  = gcm_aes_256_set_nonce,
    .decrypt                    = gcm_aes_256_decrypt,
    .encrypt                    = gcm_aes_256_encrypt,
}, {
    .id                         = 0x0080C20001000003,
    .name                       = "GCM-AES-XPN-128",
    .integrity_protection       = true,
    .confidentiality_protection = true,
    .icv_len                    = 16,
    .set_nonce                  = gcm_aes_xpn_128_set_nonce,
    .decrypt                    = gcm_aes_xpn_128_decrypt,
    .encrypt                    = gcm_aes_xpn_128_encrypt,
}, {
    .id                         = 0x0080C20001000004,
    .name                       = "GCM-AES-XPN-256",
    .integrity_protection       = true,
    .confidentiality_protection = true,
    .icv_len                    = 16,
    .set_nonce                  = gcm_aes_xpn_256_set_nonce,
    .decrypt                    = gcm_aes_xpn_256_decrypt,
    .encrypt                    = gcm_aes_xpn_256_encrypt,
} };

static CipherSuite *find_ciphersuite(cipher_id_t cipher_id)
{
    int i, count;
    CipherSuite *cs;

    count = ARRAY_SIZE(ciphersuites);
    for (i = 0; i < count; i++) {
        cs = &ciphersuites[i];
        return cs;
    }
    return NULL;
}

static QCryptoAead *alloc_cipher_context(cipher_id_t cipher_id,
                                         uint8_t *key)
{
    Error *err = NULL;
    size_t nkey;
    int alg, mode;
    CipherSuite *cs;

    cs = find_ciphersuite(cipher_id);
    if (cs) {
        DPRINTF("Cipher Suite \"%s\" is initialised.\n", cs->name);
        alg = QCRYPTO_CIPHER_ALG_AES_128;
        mode = QCRYPTO_CIPHER_MODE_GCM;
        nkey = qcrypto_cipher_get_key_len(alg);
        return qcrypto_aead_new(alg, mode, key, nkey, &err);
    }

    return NULL;
}

static int fill_ctx(SecYContext *ctx, const struct iovec *iov, int iovcnt,
                    SecY *secy, int data_offset)
{
    size_t in_len;

    /* TODO: optimise */
    in_len = iov_size(iov, iovcnt);
    ctx->iov[0].iov_base = g_malloc0(data_offset);
    ctx->iov[0].iov_len = data_offset;
    ctx->iov[1].iov_base = g_malloc0(in_len - data_offset);
    ctx->iov[1].iov_len = in_len - data_offset;

    iov_to_buf(iov, iovcnt, 0, ctx->iov[0].iov_base, data_offset);
    iov_to_buf(iov, iovcnt, data_offset, ctx->iov[1].iov_base,
               in_len - data_offset);

    return 0;
}

/*
 * FDB manipulations
 */
static gboolean rocker_fdb_key_equal(gconstpointer v1, gconstpointer v2)
{
    FDBKey *key1 = (FDBKey *)v1;
    FDBKey *key2 = (FDBKey *)v2;
    return key1->addr.a[0] == key2->addr.a[0] &&
           key1->addr.a[1] == key2->addr.a[1] &&
           key1->addr.a[2] == key2->addr.a[2] &&
           key1->addr.a[3] == key2->addr.a[3] &&
           key1->addr.a[4] == key2->addr.a[4] &&
           key1->addr.a[5] == key2->addr.a[5] &&
           key1->vlan_id == key2->vlan_id;
}

static guint rocker_fdb_hash(gconstpointer v)
{
    return (guint)*(char *)v;
}

static FDBEntry *fdb_find(const FDBKey *key)
{
    FDBEntry *entry;
    entry = g_hash_table_lookup(fdb_table, key);
    if (entry)
        return entry;
    return NULL;
}

static int fdb_del(const FDBKey *key)
{
    g_hash_table_remove(fdb_table, key);

    return 0;
}

static int fdb_add(const FDBKey *key, const FDBEntry *new)
{
    FDBEntry *old = fdb_find(key);
    FDBKey *e_key = g_malloc0(sizeof(FDBKey));
    FDBEntry *e_val = g_malloc0(sizeof(FDBEntry));

    /* for glib <2.4 */
    if (old) {
        fdb_del(key);
    }

    memcpy(e_key, key, sizeof(FDBEntry));
    memcpy(e_val, new, sizeof(FDBEntry));
    g_hash_table_insert(fdb_table, e_key, e_val);

    return 0;
}

static FDBEntry *secy_fdb_find(SecYContext *ctx)
{
    MACAddr mac_addr;
    memcpy(&mac_addr, (uint8_t *)ctx->eth_header->h_dest, ETH_ALEN);
    FDBKey key = {
        .addr = mac_addr,
        .vlan_id = !ctx->vlan_header ? 0 : /* XXX: native */
                   be16_to_cpu(ctx->vlan_header->h_tci) & VLAN_VID_MASK,
    };
    return fdb_find(&key);
}

static void secy_fdb_add(const uint32_t pport, const uint8_t *addr,
                         const uint16_t vlan_id, bool no_secy, sci_t sci)
{
    MACAddr mac_addr;
    memcpy(&mac_addr, addr, ETH_ALEN);
    FDBKey key = {
        .addr = mac_addr,
        .vlan_id = vlan_id,
    };
    FDBEntry entry = {
        .no_secy = no_secy,
        .sci = sci,
    };
    fdb_add(&key, &entry);
}

static int secy_fdb_update(SecYContext *ctx)
{
    secy_fdb_add(ctx->in_pport, (uint8_t *)ctx->eth_header->h_source,
                 0, false, ctx->secy->sci);
    return 0;
}

static int secy_fdb_del(SCITable *sci_table, const FDBKey *key)
{
    return fdb_del(key);
}

/*
 * SC manipulations
 */
static TxSC *txsc_find(SCITable *sci_table, sci_t sci)
{
    SCCommon *sc;

    sc = g_hash_table_lookup(sci_table->tbl, &sci);
    if (sc && sc->is_tx)
        return (TxSC *)sc;

    return NULL;
}

static RxSC *rxsc_find(SCITable *sci_table, sci_t sci)
{
    SCCommon *sc;

    sc = g_hash_table_lookup(sci_table->tbl, &sci);
    if (sc && !sc->is_tx)
        return (RxSC *)sc;

    return NULL;
}

static SecY *secy_find(SCITable *sci_table, sci_t sci)
{
    SCCommon *sc;

    sc = g_hash_table_lookup(sci_table->tbl, &sci);
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

    tx_sc->sc_common.secy = secy;
    tx_sc->txa = g_malloc0_n(MACSEC_NUM_AN, sizeof(TxSA *));
    secy->tx_sc = tx_sc;

    g_hash_table_insert(sci_table->tbl, &(tx_sc->sc_common.sci), tx_sc);
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

    QLIST_INSERT_HEAD(&secy->rx_scs, rx_sc, next);
    rx_sc->rxa = g_malloc0_n(MACSEC_NUM_AN, sizeof(RxSA *));
    rx_sc->sc_common.secy = secy;

    g_hash_table_insert(sci_table->tbl, &(rx_sc->sc_common.sci), rx_sc);
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

    secy->current_ciphersuite = find_ciphersuite(
                    ROCKER_SECY_DEFAULT_CIPHERSUITE);

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
                       uint8_t *key, uint8_t *ki)
{
    SAK *sak;
    SecY *secy;
    TxSC *tx_sc;
    RxSC *rx_sc;
    TxSA *tx_sa;
    RxSA *rx_sa;

    tx_sc = txsc_find(sci_table, sci);
    rx_sc = rxsc_find(sci_table, sci);
    if (!(!!tx_sc ^ !!rx_sc))
        return 0; /* may i return an error */

    /* Currently iproute2 control does not support online sak update,
     * meaning that MKA use is not assumed yet.
     */
    if (tx_sc) {
        secy = tx_sc->sc_common.secy;
        if (tx_sc->txa[an]) {
            tx_sa = tx_sc->txa[an];
        } else {
            tx_sa = g_new0(TxSA, 1);
            tx_sc->txa[an] = tx_sa;
        }
        tx_sa->sa_common.next_pn = pn;
        sak = &tx_sc->txa[an]->sa_common.sak;
    } else {
        secy = rx_sc->sc_common.secy;
        if (rx_sc->rxa[an]) {
            rx_sa = rx_sc->rxa[an];
        } else {
            rx_sa = g_new0(RxSA, 1);
            rx_sc->rxa[an] = rx_sa;
        }
        rx_sa->sa_common.next_pn = pn;
        sak = &rx_sc->rxa[an]->sa_common.sak;
    }
    if (!sak->cipher) {
        sak->cipher = alloc_cipher_context(secy->current_ciphersuite->id, key);
    }

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
    int ret;
    CipherSuite *cs = ctx->secy->current_ciphersuite;

    if (!ctx->sa->sak.cipher) {
        return -1;
    }

    if (cs->set_nonce) {
        ret = cs->set_nonce(cs, ctx);
        if (ret) {
            return ret;
        }
    }

    return cs->decrypt(cs, ctx);
}

static int secy_encrypt(struct secy_context *ctx)
{
    int ret;
    CipherSuite *ciphersuite = ctx->secy->current_ciphersuite;

    if (!ctx->sa->sak.cipher) {
        return -1;
    }

    if (ciphersuite->set_nonce) {
        ret = ciphersuite->set_nonce(ciphersuite, ctx);
        if (ret) {
            return ret;
        }
    }
    return ciphersuite->encrypt(ciphersuite, ctx);
}

static size_t
validate_sectag(const struct eth_header *ethhdr, const SecTAG *sectag,
                size_t remaining, SecYContext *ctx)
{
    size_t sectag_len;

    if (sectag->tci_an & ROCKER_SECY_TCI_BIT_VERSION) {
        return -1;
    }
    if (sectag->tci_an & ROCKER_SECY_TCI_BIT_ES &&
        !(sectag->tci_an & ROCKER_SECY_TCI_BIT_SC)) {
        ctx->sci = (sci_t)ethhdr->h_source[0] << 56 |
                   (sci_t)ethhdr->h_source[1] << 48 |
                   (sci_t)ethhdr->h_source[2] << 40 |
                   (sci_t)ethhdr->h_source[3] << 32 |
                   (sci_t)ethhdr->h_source[4] << 24 |
                   (sci_t)ethhdr->h_source[5] << 16;
        if (!(sectag->tci_an & ROCKER_SECY_TCI_BIT_SCB)) {
            ctx->sci |= 1; /* port id = 0x01 */
        }
        sectag_len = sizeof(SecTAG) - sizeof(sci_t);
    } else if (sizeof(sci_t) > remaining) {
        DPRINTF("parse_sectag underrun on SecTAG SCI\n");
        return -1;
    } else if (sectag->tci_an & ROCKER_SECY_TCI_BIT_ES ||
               !(sectag->tci_an & ROCKER_SECY_TCI_BIT_SC) ||
               sectag->tci_an & ROCKER_SECY_TCI_BIT_SCB) {
        DPRINTF("parse_sectag invalid TCI\n");
        return -1;
    } else {
        memcpy(&ctx->sci, &sectag->sci, sizeof(sci_t));
        sectag_len = sizeof(SecTAG);
    }

    ctx->an = sectag->tci_an & ROCKER_SECY_TCI_AN_MASK;
    switch ((sectag->tci_an &
             (ROCKER_SECY_TCI_BIT_E|ROCKER_SECY_TCI_BIT_C)) >> 2) {
    case 0x00:
        /* Normal case where neighther confidentiality nor integrity are being
         * provided. This potentially includes the case where not the default
         * Cipher Suite may provide integrity with appended ICV. However we do
         * not have such an interface, thus no need to check whether or not
         * the packet has sufficient tailroom for 16 bit ICV.
         */
        break;
    case 0x01:
        /* This indicates not the default Cipher Suite is being used,
         * and requires it to be preconfigured. Currently we do not
         * support that administrative interface. */
        return -1;
    case 0x02:
        /* Reserved for KaY processing, and distinguishable even in multi-access
         * LAN environment with multiple Virtual Ports. See IEEE 802.1AE-2006
         * 11.8. */
        break;
    case 0x03:
        /* Normal case */
        ctx->processing_sec = true;
        ctx->processing_icv = true;
        break;
    }

    return sectag_len;
}

static size_t
parse_sectag(struct secy_context *ctx, const struct iovec *iov)
{
    SecTAG **sectag = &ctx->sectag;
    struct eth_header *ethhdr;
    size_t remaining, sofar = 0;
    int sectag_len;

    sofar += sizeof(struct eth_header);
    if (iov->iov_len < sofar) {
        DPRINTF("parse_sectag underrun on eth_header\n");
        return -1;
    }
    ethhdr = iov->iov_base;
    if (ntohs(ethhdr->h_proto) != ETH_P_MACSEC) {
        return -1;
    }

    remaining = iov->iov_len - sofar;
    if (iov->iov_len < sofar) {
        DPRINTF("parse_sectag underrun on SecTAG without SCI\n");
        return -1;
    }
    *sectag = (SecTAG *)(ethhdr + 1);
    sectag_len = validate_sectag(ethhdr, *sectag, remaining, ctx);
    if (sectag_len < 0) {
        return -1;
    }

    sofar += sectag_len;
    return sofar;
}

static int fill_sectag(SecYContext *ctx, SecTAG *sectag, uint8_t an,
                       uint32_t pn, sci_t sci)
{
    size_t data_len;

    /* no need to explicitly show our ES nor SCB capability.
     * TODO: E/C */
    sectag->tci_an = ROCKER_SECY_TCI_BIT_SC |
                     ROCKER_SECY_TCI_BIT_E |
                     ROCKER_SECY_TCI_BIT_C;
    sectag->tci_an |= an;
    sectag->pn = htonl(pn);
    sectag->sci = sci;

    data_len = ROUND_UP(ctx->iov[1].iov_len, 16);
    if (data_len < 48) {
        sectag->short_len = data_len;
    }

    return 0;
}

static void fill_out_ctx(SecYContext *in_ctx, SecYContext *out_ctx)
{
    SecTAG *sectag;

    out_ctx->iov = g_malloc0_n(2, sizeof(struct iovec));
    size_t headroom_len = sizeof(struct eth_header) + sizeof(SecTAG);

    out_ctx->iov[0].iov_len = headroom_len;
    out_ctx->iov[0].iov_base = g_malloc0(headroom_len);
    out_ctx->iov[1].iov_len = in_ctx->iov[1].iov_len;
    out_ctx->iov[1].iov_base = g_malloc0(out_ctx->iov[1].iov_len);

    memcpy(out_ctx->iov[0].iov_base, in_ctx->iov[0].iov_base,
           ETH_ALEN * 2);
    out_ctx->eth_header = out_ctx->iov[0].iov_base;
    out_ctx->eth_header->h_proto = htons(ETH_P_MACSEC);
    sectag = out_ctx->iov[0].iov_base + sizeof(struct eth_header);
    out_ctx->sectag = sectag;
    fill_sectag(in_ctx, sectag, out_ctx->an, out_ctx->sa->next_pn,
                out_ctx->secy->sci);

    memcpy(out_ctx->iov[1].iov_base, in_ctx->iov[1].iov_base,
           in_ctx->iov[1].iov_len);
}

static void secy_eg(gpointer unused, gpointer value, void *priv)
{
    SCCommon *sc = (SCCommon *)value;
    TxSC *txsc;
    SecY *secy;
    SecYContext *in_ctx, out_ctx;

    in_ctx = (SecYContext *)priv;
    if (!sc->is_tx)
        return;

    txsc = (TxSC *)sc;
    secy = txsc->sc_common.secy;
    if (!secy)
        return;

    if (secy == in_ctx->secy)
        return;

    out_ctx.is_eg = true;
    out_ctx.an = txsc->encoding_sa;
    out_ctx.sa = (SACommon *)txsc->txa[txsc->encoding_sa];
    if (!out_ctx.sa)
        return;

    out_ctx.iovcnt = 2;
    out_ctx.sci_table = in_ctx->sci_table;
    out_ctx.secy = secy;
    out_ctx.out_pport = secy->pport;

    /* This relies on actor's 'active' pariticipation
     * i.e., MKPDU destined to chosen EAPOL group address
     * goes up to the Control Plane, and finally recognises PN
     * exhaustion. Another option would be notifying stat via
     * MSI-X periodically. About 'active' paritipation, see:
     * IEEE 802.1Xbx-2014 12.5.2 */
    out_ctx.sa->next_pn++;

    fill_out_ctx(in_ctx, &out_ctx);

    if (secy_encrypt(&out_ctx)) {
        return;
    }

    rocker_port_eg(world_rocker(out_ctx.sci_table->world),
                   out_ctx.out_pport,
                   out_ctx.iov, out_ctx.iovcnt);
}

static void rocker_flood(SecYContext *ctx)
{
    /* XXX: vlan obj */
    g_hash_table_foreach(ctx->sci_table->tbl, secy_eg, ctx);
}

static void secy_ig(SecY *secy, SecYContext *ctx,
                    const struct iovec *iov, int iovcnt, int data_offset)
{
    FDBEntry *entry;
    struct eth_header *ethhdr;

    /* TODO: we should provide admin interface which turns on or off the
     * Unauthorized VLANs (IEEE 802.1X-2010 7.5.3). about the Selective
     * Relay like WoL, see secy_world_eg().
     */

    if (iov->iov_len < sizeof(struct eth_header)) {
        return;
    }

    ethhdr = iov->iov_base;
    ctx->eth_header = ethhdr;
    if (ntohs(ethhdr->h_proto) != ETH_P_MACSEC) {
        /* As we support multi-access LAN, 'Y' function directs the received
         * packet to the Uncontrolled Port, which is not associated to any SecY.
         *
         * We do not offload EAPOL. All the protocol handling, relevant state
         * management and even basic header validation are up to the control
         * plane, so we bypass SecY selection iff. it will be passed to the
         * Uncontrolled Port of the selected SecY.
         *
         * TODO: we should do the selection here in the case of stacked ISS.
         */
        rx_produce(ctx->sci_table->world, ctx->in_pport, iov, iovcnt, 1);
        return;
    }

    fill_ctx(ctx, iov, iovcnt, secy, data_offset);

    if (secy_decrypt(ctx)) {
        secy_drop(ctx);
        return;
    }

    switch (ntohs(ethhdr->h_proto)) {
    case ETH_P_VLAN:
    case ETH_P_DVLAN:
        ctx->vlan_header = ctx->iov[1].iov_base;
    }

    secy_fdb_update(ctx);

    if (is_broadcast_ether_addr(ctx->eth_header->h_dest)) {
        rocker_flood(ctx);
        rx_produce(ctx->sci_table->world, ctx->in_pport, ctx->iov, ctx->iovcnt, 1);
    } else if (is_multicast_ether_addr(ctx->eth_header->h_dest)) {
        /* XXX: implement snooping */
        rocker_flood(ctx);
        secy_context_free(ctx);
    } else if (is_reserved_ether_addr(ctx->eth_header->h_dest)) {
        /* TODO: Selective forwarding */
        rx_produce(ctx->sci_table->world, ctx->in_pport, ctx->iov, ctx->iovcnt, 1);
    } else if ((entry = secy_fdb_find(ctx)) != NULL) {
        /* CAVEAT: we always have to externally learn, as FDB entry being
         * not found does not mean we have to do locally on upper cpu side.
         * Otherwise every 'Common Port' ingress time we may have to notify for
         * safety, and it is not worth the overhead as the point is not offloading
         * data plane, but just the MACsec protection/validation. Plus, higher layer
         * entity could not distinguish whether tha data would be associated to
         * the secure ISS or insecure ISS,
         */

        SecY *out_secy = secy_find(ctx->sci_table, entry->sci);
        ctx->out_pport = out_secy->pport;
        if (ctx->out_pport != ctx->in_pport) {
            secy_eg(NULL, out_secy->tx_sc, ctx);
        }
    } else {
        rocker_flood(ctx);
        rx_produce(ctx->sci_table->world, ctx->in_pport, ctx->iov, ctx->iovcnt, 1);
    }
}

static ssize_t secy_world_ig(World *world, uint32_t pport,
                             const struct iovec *iov, int iovcnt)
{
    SCITable *sci_table = world_private(world);
    RxSC *rxsc;
    SecY *secy;
    int data_offset;

    struct iovec iov_copy[2];

    SecYContext ctx = {
        .is_eg = false,
        .in_pport = pport,
        .iov = iov_copy,
        .iovcnt = 2,
        .sci_table = sci_table,
    };

    data_offset = parse_sectag(&ctx, iov);

    if (data_offset < 0 || !ctx.processing_sec) {
        goto global_uncontrolled_port;
    }

    rxsc = rxsc_find(sci_table, ctx.sci);
    if (!rxsc) {
        return -1;
    }
    secy = rxsc->sc_common.secy;
    if (!secy) {
        goto global_uncontrolled_port;
    }

    ctx.secy = secy;
    ctx.sa = (SACommon *)rxsc->rxa[ctx.an];
    if (!ctx.sa) {
        return -1;
    }
    secy_ig(secy, &ctx, iov, iovcnt, data_offset);

    notify_stats(&ctx);

    return iov_size(iov, iovcnt);

global_uncontrolled_port:
    rx_produce(world, pport, iov, iovcnt, 1);
    return iov_size(iov, iovcnt);
}

/* 'Common Port' egress
 *
 * Note: Not only 'Controlled Port (Secure Service Access Point)' TX request
 * reception, but also includes 'Uncontrolled Port' TX. Control plane Linux
 * iproute2 utility may transparently deploy Virtual Ports and we handle them
 * to achieve multi-Access LAN interface stack transparently, thus we cannot
 * permit SecTAG-omitted frame transmitted by 'Uncontrolled Port'. To permit
 * bi-directional unicast communication with SecTAG being omitted only while
 * just one SecY Virtual Port is present for a front-panel port would probably
 * confuse the peer station.
 *
 * pport identifies the associated 'Common Port'.
 */
static int secy_world_eg(World *world, uint32_t pport,
                         const struct iovec *iov, int iovcnt,
                         struct iovec *new_iov, int *new_iovcnt)
{
    SCITable *sci_table = world_private(world);
    int data_offset;

    /* Two iovecs headroom for ether header + SECTAG and possibly vlan
     * tag which will be not-in-the-clear on wire, and one iovec ICV
     * in tailroom.
     */
    struct iovec iov_copy[2];

    SecYContext ctx = {
        .is_eg = true,
        .out_pport = pport,
        .iov = iov_copy,
        .iovcnt = iovcnt,
        .sci_table = sci_table,
    };

    data_offset = parse_sectag(&ctx, iov);

    if (data_offset > 0) {
        if (iov->iov_len < sizeof(struct eth_header)) {
            return -ROCKER_EINVAL;
        }
        return ROCKER_OK;
    }

    /* via Uncontrolled Port not associated with any SecY entity */
    return ROCKER_OK;
}

static int secy_install_sak(SCITable *tbl, sci_t sci, int an, uint8_t *key)
{
    SAK *sak;
    SecY *secy;
    TxSC *tx_sc;
    RxSC *rx_sc;
    QCryptoAead *cipher;

    if ((tx_sc = txsc_find(tbl, sci)) != NULL) {
        secy = tx_sc->sc_common.secy;
        sak = &tx_sc->txa[an]->sa_common.sak;
        sak->transmits = true;
    } else if ((rx_sc = rxsc_find(tbl, sci)) != NULL) {
        secy = rx_sc->sc_common.secy;
        sak = &rx_sc->rxa[an]->sa_common.sak;
        sak->transmits = false;
    } else {
        return -1;
    }

    cipher = alloc_cipher_context(secy->current_ciphersuite->id, key);
    if (!cipher) {
        return -1;
    }

    sak->cipher = cipher;
    return 0;
}

static int secy_fdb_cmd(SCITable *tbl, uint16_t cmd, RockerTlv **tlvs)
{
    FDBKey key;
    uint8_t addr[ETH_ALEN];
    uint32_t pport;
    uint64_t u64_addr;
    __be16 vlan_id = 0;
    sci_t sci;

    if (!tlvs[ROCKER_TLV_SECY_PPORT] ||
        !tlvs[ROCKER_TLV_SECY_DST_ADDR])
        return -ROCKER_EINVAL;

    pport = rocker_tlv_get_le32(tlvs[ROCKER_TLV_SECY_PPORT]);
    u64_addr = rocker_tlv_get_u64(tlvs[ROCKER_TLV_SECY_DST_ADDR]);
    memcpy(addr, &u64_addr, ETH_ALEN);

    if (tlvs[ROCKER_TLV_SECY_VLAN_ID]) {
        vlan_id = rocker_tlv_get_u16(tlvs[ROCKER_TLV_SECY_VLAN_ID]);
    }

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_SECY_FDB_ADD:
        if (!tlvs[ROCKER_TLV_SECY_TX_SCI]) {
            secy_fdb_add(pport, addr, vlan_id, true, 0);
        } else {
            sci = (sci_t)rocker_tlv_get_le64(tlvs[ROCKER_TLV_SECY_TX_SCI]);
            secy_fdb_add(pport, addr, vlan_id, false, sci);
        }
        return -ROCKER_OK;
    case ROCKER_TLV_CMD_TYPE_SECY_FDB_DEL:
        secy_fdb_del(tbl, &key);
        return -ROCKER_OK;
    }

    return -ROCKER_ENOTSUP;
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
    uint8_t* sak;
    uint8_t ki = 0x01;

    if (!tlvs[ROCKER_TLV_SECY_SCI] ||
        !tlvs[ROCKER_TLV_SECY_AN] ||
        !tlvs[ROCKER_TLV_SECY_PN] ||
        !tlvs[ROCKER_TLV_SECY_SAK] ||
        !tlvs[ROCKER_TLV_SECY_SAK_LEN]) {
        return -ROCKER_EINVAL;
    }

    sci = (sci_t)rocker_tlv_get_le64(tlvs[ROCKER_TLV_SECY_SCI]);
    an = (sci_t)rocker_tlv_get_u8(tlvs[ROCKER_TLV_SECY_AN]);
    pn = (sci_t)rocker_tlv_get_le32(tlvs[ROCKER_TLV_SECY_PN]);
    sak = (uint8_t *)rocker_tlv_data(tlvs[ROCKER_TLV_SECY_SAK]);

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_SECY_ADD_TX_SA:
    case ROCKER_TLV_CMD_TYPE_SECY_ADD_RX_SA:
        secy_add_sa(tbl, sci, an, pn, sak, &ki);
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
    case ROCKER_TLV_CMD_TYPE_SECY_FDB_ADD:
    case ROCKER_TLV_CMD_TYPE_SECY_FDB_DEL:
        return secy_fdb_cmd(sci_table, cmd, tlvs);
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
    fdb_table = g_hash_table_new_full(rocker_fdb_hash,
                                      rocker_fdb_key_equal,
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
    .eg = secy_world_eg,
    .ig = secy_world_ig,
    .cmd = secy_cmd,
};

World *secy_world_alloc(Rocker *r)
{
    return world_alloc(r, sizeof(SecY), ROCKER_WORLD_TYPE_SECY, &secy_ops);
}
