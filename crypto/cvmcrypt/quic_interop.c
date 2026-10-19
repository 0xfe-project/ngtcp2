/*
 * crypto/cvmcrypt/quic_interop.c
 *
 * A minimal QUIC client, built to answer one question: does the cvmcrypt
 * backend actually complete a handshake against another implementation?
 *
 * Everything here exists for that. There is no congestion control tuning, no
 * qlog, no migration, one stream, and it exits after the echo. The transport
 * is ngtcp2's; the crypto is cvmcrypt's; the peer is quic-go.
 *
 *	quic_interop <host> <port>
 *
 * Wire format matches tests/e2e/gointerop in cvmsockets: 4 bytes big-endian
 * length, then the payload; the server echoes it back on the same stream.
 *
 * Exit 0 on a byte-exact echo.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_cvmcrypt.h>

#include "rt.h"

#include <cvmcrypt/cvmcrypt.h>

#include "tls/tls.h"

#define ALPN "cvmsockets-echo"
#define PAYLOAD_LEN 4096
#define HANDSHAKE_TIMEOUT_MS 10000
#define ECHO_TIMEOUT_MS 10000

static uint8_t rng_state[1];

static void tls_random(CvmTlsRandomBytes *self, void *buf, usize len);

static void fill_random(uint8_t *out, size_t len, void *user) {
    (void)user;
    /* Deterministic is fine for a test that only cares whether the handshake
     * completes; ngtcp2 uses these for CIDs and nonces, and a fixed peer and
     * a fixed run make failures reproducible. */
    static uint32_t s = 0x12345678u;
    for (size_t i = 0; i < len; i++) {
        s = s * 1664525u + 1013904223u;
        out[i] = (uint8_t)(s >> 24);
    }
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    fill_random(dest, destlen, rng_state);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                                    size_t cidlen, void *user_data) {
    (void)conn;
    (void)user_data;
    fill_random(cid->data, cidlen, rng_state);
    cid->datalen = cidlen;
    fill_random(token, NGTCP2_STATELESS_RESET_TOKENLEN, rng_state);
    return 0;
}

/* ------------------------------------------------------------------ */
/* connection state                                                     */
/* ------------------------------------------------------------------ */

struct client {
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_conn *conn;
    CvmTls *tls;
    int handshake_done;
    int64_t stream_id;
    /* The echo carries the 4-byte length prefix too. */
    uint8_t echo[4 + PAYLOAD_LEN];
    size_t echo_len;
    size_t echo_want;
};

static struct client g_client;

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    return ((struct client *)conn_ref->user_data)->conn;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    struct client *c = user_data;
    (void)conn;
    printf("[client] handshake completed\n");
    c->handshake_done = 1;
    c->stream_id = 0;
    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                               uint64_t offset, const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data) {
    struct client *c = user_data;
    (void)conn;
    (void)flags;
    (void)stream_id;
    (void)stream_user_data;

    if (offset + datalen > sizeof(c->echo)) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    memcpy(c->echo + offset, data, datalen);
    if (offset + datalen > c->echo_len) {
        c->echo_len = offset + datalen;
    }
    return 0;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;
    (void)stream_id;
    (void)user_data;
    return 0;
}

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                           uint64_t app_error_code, void *user_data,
                           void *stream_user_data) {
    (void)conn;
    (void)flags;
    (void)stream_id;
    (void)app_error_code;
    (void)user_data;
    (void)stream_user_data;
    return 0;
}

/* ------------------------------------------------------------------ */
/* transport                                                           */
/* ------------------------------------------------------------------ */

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sockaddr_to_path(ngtcp2_path *path, struct sockaddr_in *sa) {
    /* ngtcp2 asserts on a zero-length address, so the local side has to be a
     * real sockaddr even though the client never binds a specific one. */
    static struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;

    memset(path, 0, sizeof(*path));
    path->local.addr = (ngtcp2_sockaddr *)&local;
    path->local.addrlen = sizeof(local);
    path->remote.addr = (ngtcp2_sockaddr *)sa;
    path->remote.addrlen = sizeof(*sa);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <host> <port>\n", argv[0]);
        return 2;
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);

    /* --- socket ------------------------------------------------------- */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &peer.sin_addr) != 1) {
        fprintf(stderr, "bad address: %s\n", host);
        return 1;
    }
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != 0) {
        perror("connect");
        return 1;
    }

    /* --- TLS ---------------------------------------------------------- */
    CvmTlsContext tls_ctx;
    cvm_tls_context_defaults(&tls_ctx);
    if (ngtcp2_crypto_cvmcrypt_configure_client_context(&tls_ctx) != 0) {
        fprintf(stderr, "configure_client_context failed\n");
        return 1;
    }

    /* cvmcrypt's random source is a hook installed by the embedder; the TLS
     * layer reaches it through ctx.random_bytes. */
    static CvmTlsRandomBytes random_bytes = {.cb = tls_random};
    tls_ctx.random_bytes = &random_bytes;

    CvmTls *tls = cvm_tls_new(&tls_ctx, false, host);
    if (tls == NULL) {
        fprintf(stderr, "tls_new failed\n");
        return 1;
    }

    static CvmTlsVec alpns[1];
    alpns[0] = (CvmTlsVec){(u8 const *)ALPN, strlen(ALPN)};
    cvm_tls_set_alpn(tls, alpns, 1);

    /* --- connection --------------------------------------------------- */
    ngtcp2_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.rand = rand_cb;
    callbacks.get_new_connection_id = get_new_connection_id_cb;
    callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.recv_stream_data = recv_stream_data_cb;
    callbacks.stream_open = stream_open_cb;
    callbacks.stream_close = stream_close_cb;
    callbacks.handshake_completed = handshake_completed_cb;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = (ngtcp2_tstamp)now_ms() * NGTCP2_MILLISECONDS;
    settings.handshake_timeout = 10 * NGTCP2_SECONDS;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 1 << 20;
    params.initial_max_stream_data_bidi_remote = 1 << 20;
    params.initial_max_stream_data_uni = 1 << 20;
    params.initial_max_data = 1 << 20;
    params.initial_max_streams_bidi = 4;
    params.initial_max_streams_uni = 0;
    params.max_idle_timeout = 10 * NGTCP2_SECONDS;

    ngtcp2_cid dcid, scid;
    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    fill_random(dcid.data, dcid.datalen, rng_state);
    scid.datalen = 8;
    fill_random(scid.data, scid.datalen, rng_state);

    ngtcp2_path path;
    sockaddr_to_path(&path, &peer);

    g_client.conn_ref.get_conn = get_conn;
    g_client.conn_ref.user_data = &g_client;
    cvm_tls_set_app_data(tls, &g_client.conn_ref);
    g_client.tls = tls;

    int rv = ngtcp2_conn_client_new(&g_client.conn, &dcid, &scid, &path,
                                    NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params,
                                    NULL, &g_client);
    if (rv != 0) {
        fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
        return 1;
    }
    ngtcp2_conn_set_tls_native_handle(g_client.conn, tls);

    /* --- drive -------------------------------------------------------- */
    int64_t const deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
    int sent_request = 0;
    uint8_t pkt[1500];

    while (now_ms() < deadline) {
        int64_t const ts = now_ms() * NGTCP2_MILLISECONDS;
        ngtcp2_conn_handle_expiry(g_client.conn, (ngtcp2_tstamp)ts);

        /* One or more packets out. */
        for (;;) {
            ngtcp2_ssize n = ngtcp2_conn_write_pkt(g_client.conn, &path, NULL, pkt,
                                                   sizeof(pkt), (ngtcp2_tstamp)ts);
            if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED || n == NGTCP2_ERR_STREAM_SHUT_WR) {
                break;
            }
            if (n < 0) {
                if (n == NGTCP2_ERR_STREAM_NOT_FOUND) {
                    break;
                }
                fprintf(stderr, "write_pkt: %s\n", ngtcp2_strerror((int)n));
                return 1;
            }
            if (n == 0) {
                break;
            }
            if (send(fd, pkt, (size_t)n, 0) < 0) {
                perror("send");
                return 1;
            }
        }

        /* Ask for the echo once the handshake is done. */
        if (g_client.handshake_done && !sent_request) {
            /* A stream must be opened before anything can be written on it. */
            int64_t sid = -1;
            if (ngtcp2_conn_open_bidi_stream(g_client.conn, &sid, NULL) != 0) {
                fprintf(stderr, "open_bidi_stream failed\n");
                return 1;
            }
            g_client.stream_id = sid;
            uint8_t payload[PAYLOAD_LEN];
            for (size_t i = 0; i < sizeof(payload); i++) {
                payload[i] = (uint8_t)(i * 7 + 1);
            }
            uint8_t framed[4 + PAYLOAD_LEN];
            framed[0] = (uint8_t)(PAYLOAD_LEN >> 24);
            framed[1] = (uint8_t)(PAYLOAD_LEN >> 16);
            framed[2] = (uint8_t)(PAYLOAD_LEN >> 8);
            framed[3] = (uint8_t)PAYLOAD_LEN;
            memcpy(framed + 4, payload, sizeof(payload));

            /*
             * writev_stream reports how many *stream* bytes it consumed in
             * pdatalen; the vector itself is not advanced. Tracking the
             * offset by hand is the only way to avoid resending or skipping.
             */
            size_t off = 0;
            while (off < sizeof(framed)) {
                ngtcp2_vec vec = {framed + off, sizeof(framed) - off};
                ngtcp2_ssize datalen = 0;
                ngtcp2_ssize n = ngtcp2_conn_writev_stream(
                    g_client.conn, &path, NULL, pkt, sizeof(pkt), &datalen,
                    NGTCP2_WRITE_STREAM_FLAG_NONE, g_client.stream_id, &vec, 1,
                    (ngtcp2_tstamp)ts);
                if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                    break;
                }
                if (n < 0) {
                    fprintf(stderr, "writev_stream: %s\n", ngtcp2_strerror((int)n));
                    return 1;
                }
                if (n > 0) {
                    send(fd, pkt, (size_t)n, 0);
                }
                off += (size_t)datalen;
                if (datalen == 0) {
                    break; /* nothing fit; try again next iteration */
                }
            }
            sent_request = off == sizeof(framed);
            g_client.echo_want = 4 + PAYLOAD_LEN;
            printf("[client] request sent\n");
        }

        /* Inbound. */
        uint8_t in[65536];
        struct timeval tv = {0, 20000}; /* 20 ms */
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ssize_t n = recv(fd, in, sizeof(in), 0);
        if (n > 0) {
            ngtcp2_path p;
            sockaddr_to_path(&p, &peer);
            rv = ngtcp2_conn_read_pkt(g_client.conn, &p, NULL, in, (size_t)n,
                                      (ngtcp2_tstamp)ts);
            if (rv != 0) {
                fprintf(stderr, "read_pkt: %s\n", ngtcp2_strerror(rv));
                return 1;
            }
        }

        if (g_client.echo_want > 0 && g_client.echo_len >= g_client.echo_want) {
            printf("[client] echoed %zu bytes\n", g_client.echo_len);
            uint8_t expect[PAYLOAD_LEN];
            for (size_t i = 0; i < sizeof(expect); i++) {
                expect[i] = (uint8_t)(i * 7 + 1);
            }
            if (g_client.echo_len != g_client.echo_want ||
                memcmp(g_client.echo + 4, expect, PAYLOAD_LEN) != 0) {
                for (size_t i = 0; i < PAYLOAD_LEN; i++) {
                    if (g_client.echo[4 + i] != expect[i]) {
                        fprintf(stderr,
                                "FAIL: echo mismatch at %zu: got %02x want %02x "
                                "(echo_len %zu)\n",
                                i, g_client.echo[4 + i], expect[i], g_client.echo_len);
                        break;
                    }
                }
                return 1;
            }
            printf("OK handshake + echo against quic-go\n");
            ngtcp2_conn_del(g_client.conn);
            cvm_tls_free(tls);
            close(fd);
            return 0;
        }
    }

    fprintf(stderr, "FAIL: timed out (handshake_done=%d echo=%zu/%zu)\n",
            g_client.handshake_done, g_client.echo_len, g_client.echo_want);
    ngtcp2_conn_del(g_client.conn);
    cvm_tls_free(tls);
    close(fd);
    return 1;
}

static void tls_random(CvmTlsRandomBytes *self, void *buf, usize len) {
    (void)self;
    fill_random(buf, len, rng_state);
}
