#include "nrc.h"

#include "ev.h"
#include "nacl.h"

#define __MINIZ_C__
#include "miniz.c"
#undef __MINIZ_C__

#define CHUNK_SIZE 4096

#define NRC_TIMEOUT         (5.)
#define NRC_RETRY_COUNT     (5)
#define NRC_RECONNECT_COUNT (2)

#include <stdint.h>
#include <sys/socket.h>

static void incr_nonce(unsigned char *nonce) {
    int i = 0;
    if(++nonce[i] || ++i != crypto_box_NONCEBYTES) {
        return;
    }
}

static int nrc_connect(nrc_t nrc);

/** In-memory inflate/deflate implementation */
typedef int (*zlib_op)(mz_streamp strm, int flush);

static int init_stream(z_stream *strm,
        const void *src, int srclen) {
    strm->total_in = strm->avail_in = srclen;
    strm->avail_out = CHUNK_SIZE;
    strm->next_in = (Bytef*) src;
    strm->next_out = (Bytef*) malloc(CHUNK_SIZE);

    return !strm->next_out;
}


static int zlib_loop(z_stream *strm, zlib_op op_func, char **buf, int *buflen) {
    char *out = (char *)strm->next_out;
    int outlen = strm->avail_out;

    int err, op = Z_NO_FLUSH;
    while((err = op_func(strm, op)) != Z_STREAM_END) {
        if(err != Z_OK) {
            goto err;
        }

        if(strm->avail_out == 0) {
            if(!(out = (char *)realloc(out, outlen << 1)))
                goto err;

            strm->next_out = (Bytef*)(out + outlen);
            strm->avail_out = outlen;
            outlen <<= 1;
            continue;
        }

        if(strm->avail_in == 0) {
            op = Z_FINISH;
            continue;
        }
    }

    *buf = out;
    *buflen = strm->total_out;
    return 0;

err:
    free(out);
    *buf = NULL;
    *buflen = 0;
    return err;
}


int inflate_data(const void *src, int srclen, char **dest_out, int *destlen_out) {
    z_stream strm = {0};
    if(init_stream(&strm, src, srclen))
        return -1;

    if(inflateInit(&strm) != Z_OK) {
        inflateEnd(&strm);
        return -1;
    }

    int err = zlib_loop(&strm, inflate, dest_out, destlen_out);
    inflateEnd(&strm);
    if(err) {
        return err;
    }

    return 0;
}

int deflate_data(const void *src, int srclen,
        char ** dest_out, int *destlen_out) {
    z_stream strm = {0};
    if(init_stream(&strm, src, srclen))
        return -1;

    if(deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
        deflateEnd(&strm);
        return -1;
    }

    int err = zlib_loop(&strm, deflate, dest_out, destlen_out);
    deflateEnd(&strm);
    if(err) {
        return err;
    }

    return 0;
}

/** Packet generation with inflate/deflate & nacl_box(_open)
 * TODO: handle malloc failure
 * TODO: Eliminate Redundant memory copies
 */
static int pack_data(const unsigned char *nonce,
        const unsigned char *pk, const unsigned char *sk,
        const unsigned char *data, int data_len,
        unsigned char ** out, uint32_t *out_len) {
    // Deflate & box
    int deflated_len;
    unsigned char *deflated;
    if(deflate_data(data, data_len, (char **)&deflated, &deflated_len)) {
        printf("Failed to deflate\n");
        return -1;
    }
    printf("deflated: %d -> %d\n", data_len, deflated_len);

    int encrypted_len = deflated_len + crypto_box_ZEROBYTES;
    unsigned char *encrypted = malloc(encrypted_len);

    deflated = realloc(deflated, encrypted_len);
    memmove(deflated + crypto_box_ZEROBYTES, deflated, deflated_len);
    memset(deflated, 0, crypto_box_ZEROBYTES);

    if(crypto_box(encrypted, deflated, encrypted_len,
            nonce, pk, sk)) {
        free(deflated);
        fprintf(stderr, "Failed to box\n");
        return -1;
    }
    free(deflated);

    int encrypted_nopad_len = encrypted_len - crypto_box_BOXZEROBYTES;
    unsigned char *encrypted_nopad = malloc(encrypted_nopad_len);
    memcpy(encrypted_nopad, encrypted + crypto_box_BOXZEROBYTES, encrypted_nopad_len);
    free(encrypted);

    *out = encrypted_nopad;
    *out_len = encrypted_nopad_len;
    return 0;
}

static int unpack_data(const unsigned char *nonce,
        const unsigned char *pk, const unsigned char *sk,
        const unsigned char *data, int data_len,
        unsigned char ** out, int *out_len) {
    // box_oepn & inflate
    int data_pad_len = data_len + crypto_box_BOXZEROBYTES;
    unsigned char *data_pad = malloc(data_pad_len);
    memset(data_pad, 0, crypto_box_BOXZEROBYTES);
    memcpy(data_pad + crypto_box_BOXZEROBYTES, data, data_len);

    unsigned char *decrypted = malloc(data_pad_len);

    if(crypto_box_open(decrypted, data_pad, data_pad_len,
            nonce, pk, sk)) {
        free(data_pad);
        free(decrypted);
        fprintf(stderr, "Failed to box_open\n");
        return -1;
    }
    free(data_pad);

    int inflated_len;
    unsigned char *inflated;
    if(inflate_data(decrypted + crypto_box_ZEROBYTES,
            data_pad_len - crypto_box_ZEROBYTES,
            (char **)&inflated, &inflated_len)) {
        free(decrypted);
        printf("Failed to inflate\n");
        return -1;
    }
    free(decrypted);
    printf("inflated: %d -> %d\n", data_pad_len - crypto_box_ZEROBYTES, inflated_len);

    *out = inflated;
    *out_len = inflated_len;
    return 0;
}


#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "queue.h"

typedef struct nrc_req_s* nrc_req_t;
struct nrc_req_s {
    TAILQ_ENTRY(nrc_req_s) entries;
    int boxed, callbacked;

    unsigned char *req_buf;
    int req_len;

    int send_len_count, send_count, send_total;
    int recv_len_count, recv_count, recv_total;
    char len_buf[4];
    unsigned char *send_buf, *recv_buf;

    int retry_count;

    nrc_callback cb;
    const void* privdata;
};

static nrc_req_t nrc_req_new(unsigned char *buf, int buflen,
        nrc_callback cb, const void* privdata) {
    nrc_req_t req = malloc(sizeof(struct nrc_req_s));
    if(!req) {
        return NULL;
    }
    memset(req, 0, sizeof(struct nrc_req_s));

    req->req_buf = malloc(buflen);
    if(!req->req_buf) {
        free(req);
        return NULL;
    }
    memcpy(req->req_buf, buf, buflen);

    req->req_len = buflen;
    req->cb = cb;
    req->privdata = privdata;

    return req;
}

// Cleanup aborted request:
// If there is an error while handling request, NRC
// will automatically retry the request. nrc_req_t object
// changes as request goes (e.g. store received data, store
// encryped data, ...), so nrc_req_t need to be cleaned up
// before reused.
static int nrc_req_cleanup(nrc_req_t req) {
    if(++req->retry_count >= NRC_RETRY_COUNT) {
        return -1;
    }

    req->boxed = 0;
    req->callbacked = 0;
    if(req->send_buf) {
        free(req->send_buf);
        req->send_len_count = req->send_count = req->send_total = 0;
    }
    if(req->recv_buf) {
        free(req->recv_buf);
        req->recv_len_count = req->recv_count = req->recv_total = 0;
    }

    return 0;
}

static void nrc_req_delete(nrc_req_t req) {
    if(!req) {
        return;
    }
    if(!req->callbacked) {
        req->callbacked = 1;
        req->cb(NRC_FAILED, NULL, 0, req->privdata);
    }

    if(req->req_buf) {
        free(req->req_buf);
    }
    if(req->send_buf) {
        free(req->send_buf);
    }
    if(req->recv_buf) {
        free(req->recv_buf);
    }
    free(req);
}

struct nrc_s {
    struct ev_loop * loop;
    struct ev_timer timer;
    ev_signal signal;
    struct ev_io fdio;

    char *ip;
    int port;

    int fd;
    int status;

    nrc_req_t cur_req;
    TAILQ_HEAD(listhead_wait, nrc_req_s) req_list;

    int nonce_len_read_len, nonce_read_len;
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char nonce[crypto_box_NONCEBYTES];

    int reconnect_count;
};

#define get_parent(type, argname, arg) ((type *)((void*)(arg) - \
    ((size_t)(&((type*)0)->argname))))

static int parse_int32_be(unsigned char *bytes) {
    return (bytes[0] << 24) + (bytes[1] << 16) +
        (bytes[2] << 8) + bytes[3];
}

static void fill_int32_be(uint32_t val, unsigned char *out) {
    out[3] = (val) & 0xFF;
    out[2] = (val >> 8) & 0xFF;
    out[1] = (val >> 16) & 0xFF;
    out[0] = (val >> 24) & 0xFF;
}

static int pop_req(nrc_t nrc) {
    if(!nrc->cur_req && !TAILQ_EMPTY(&nrc->req_list)) {
        nrc_req_t req = TAILQ_FIRST(&nrc->req_list);
        TAILQ_REMOVE(&nrc->req_list, req, entries);

        unsigned char *boxed;
        uint32_t boxed_len;
        if(pack_data(nrc->nonce, nrc->pk, nrc->sk, req->req_buf, req->req_len,
                &boxed, &boxed_len)) {
            printf("Failed to pack data\n");
            return -1;
        }
        incr_nonce(nrc->nonce);
        req->boxed = 1;
        req->send_buf = boxed;
        req->send_total = boxed_len;
        nrc->cur_req = req;

        return 0;
    }
    return -1;
}

void dump_hex(const unsigned char *data, int len) {
    int i;
    for(i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


// reutrns 1 if more data need to be read
// returns 0 if done
// returns -1 if error
static int handle_read(nrc_t nrc) {
    int readlen = 0;
    if(nrc->nonce_len_read_len < 4) {
        unsigned char nonce_len[4];
        readlen = read(nrc->fd, nonce_len, 4);
        if(readlen != 4) {
            return -1;
        }

        nrc->nonce_len_read_len = 4;
        dump_hex(nonce_len, 4);
    } else if(nrc->nonce_read_len < crypto_box_NONCEBYTES) {
        readlen = read(nrc->fd, nrc->nonce + nrc->nonce_read_len,
            crypto_box_NONCEBYTES - nrc->nonce_read_len);
        printf("Read nonce: %d\n", readlen);
        if(readlen <= 0) {
            return -1;
        }
        nrc->nonce_read_len += readlen;

        if(nrc->nonce_read_len == crypto_box_NONCEBYTES) {
            incr_nonce(nrc->nonce);
        }
        return 0;
    } else {
        nrc_req_t req = nrc->cur_req;
        if(!req) {
            return 0;
        }

        if(req->recv_len_count < 4) {
            readlen = read(nrc->fd, req->len_buf, 4 - req->recv_len_count);
            printf("Read resp length: %d\n", readlen);
            if(readlen <= 0) {
                return -1;
            }

            req->recv_len_count += readlen;
        } else {
            if(!req->recv_total) {
                req->recv_total = parse_int32_be((unsigned char *)req->len_buf);
                req->recv_buf = malloc(req->recv_total);
                //TODO: handle failure
            }
            printf("Total len: %d\n", req->recv_total);

            readlen = read(nrc->fd, req->recv_buf + req->recv_count,
                    req->recv_total - req->recv_count);
            printf("Read resp body: %d\n", readlen);
            if(readlen < 0) {
                return -1;
            }
            req->recv_count += readlen;

            if(req->recv_count == req->recv_total) {
                printf("Success: unpacking\n");
                unsigned char *unboxed;
                int unboxed_len;
                if(unpack_data(nrc->nonce, nrc->pk, nrc->sk, req->recv_buf, req->recv_total,
                        &unboxed, &unboxed_len)) {
                    printf("Failed to unpack data\n");
                    return -1;
                }
                incr_nonce(nrc->nonce);

                req->callbacked = 1;
                req->cb(NRC_SUCCESS, unboxed, unboxed_len, req->privdata);

                free(unboxed);
                nrc_req_delete(req);
                nrc->cur_req = NULL;

                return 0;
            }

            return 0;
        }
    }
    return EV_READ;
}

static int handle_write(nrc_t nrc) {
    if(!nrc->cur_req) {
        return 0;
    }
    int writelen = 0;
    nrc_req_t req = nrc->cur_req;
    if(req->send_len_count != 4) {
        unsigned char len_buf[4];
        fill_int32_be(req->send_total, len_buf);

        writelen = write(nrc->fd, len_buf + req->send_len_count,
            4 - req->send_len_count);
        printf("Write req length: %d\n", writelen);
        if(writelen <= 0) {
            return -1;
        }
        req->send_len_count += writelen;
        return EV_WRITE;
    }

    writelen = write(nrc->fd, req->send_buf + req->send_count,
        req->send_total - req->send_count);
    printf("Write req: %d\n", writelen);

    if(writelen <= 0) {
        return -1;
    }
    req->send_count += writelen;
    if(req->send_count == req->send_total) {
        return EV_READ;
    }

    return EV_WRITE;
}

static int nrc_ready(nrc_t nrc) {
    return nrc->nonce_read_len == crypto_box_NONCEBYTES;
}

static void nrc_reconnect(nrc_t nrc) {
    if(++nrc->reconnect_count >= NRC_RECONNECT_COUNT) {
        printf("Too many reconnect: sleeping: %d\n", nrc->reconnect_count);

        nrc->reconnect_count = 0;
        ev_timer_again(nrc->loop, &nrc->timer);
        return;
    }

    // Enqueue pending request for retry
    nrc_req_t req = nrc->cur_req;
    if(req) {
        printf("req: %p\n", nrc->cur_req);
        if(nrc_req_cleanup(req)) {
            printf("Failed to retry pending request: retry count out %.*s\n",
                req->req_len, req->req_buf);
            nrc_req_delete(req);
        } else {
            TAILQ_INSERT_HEAD(&nrc->req_list, req, entries);
        }
    }
    nrc->cur_req = NULL;

    nrc_connect(nrc);
    return;
}

static void sig_handler(struct ev_loop *loop, struct ev_signal *watcher, int events) {
    // Handle SIGPIPE: Do nothing
}

static void timeout_handler(struct ev_loop *loop, struct ev_timer *watcher, int events) {
    nrc_t nrc = get_parent(struct nrc_s, timer, watcher);
    printf("Timeout: try to reconnect\n");

    ev_timer_stop(nrc->loop, &nrc->timer);
    nrc_reconnect(nrc);
}

static void io_handler(struct ev_loop *loop, struct ev_io *watcher, int events) {
    nrc_t nrc = get_parent(struct nrc_s, fdio, watcher);
    ev_io_stop(loop, watcher);

    int ev = 0;
    if(events & EV_READ) {
        ev = handle_read(nrc);
        if(ev < 0) {
            printf("Error while reading: %s(%d)\n",
                strerror(errno), errno);
            nrc_reconnect(nrc);
            return;
        }

        nrc->status &= ~EV_READ;
        nrc->status |= ev;
    }

    if(events & EV_WRITE) {
        ev = handle_write(nrc);
        if(ev < 0) {
            printf("Error while writing: %s(%d)\n",
                strerror(errno), errno);
            nrc_reconnect(nrc);
            return;
        }

        nrc->status &= ~EV_WRITE;
        nrc->status |= ev;
    }

    // nrc->status != 0 when if there is at least one
    // sent/received packet. Reset reconnect timer
    if(nrc->status) {
        ev_io_set(watcher, nrc->fd, nrc->status);
        ev_io_start(nrc->loop, watcher);

        nrc->reconnect_count = 0;
        ev_timer_again(nrc->loop, &nrc->timer);
    } else {
        ev_timer_stop(nrc->loop, &nrc->timer);
    }
}

static int nrc_connect(nrc_t nrc) {
    if(nrc->fd) {
        ev_io_stop(nrc->loop, &nrc->fdio);
        close(nrc->fd);
        nrc->fd = 0;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = PF_INET;
    server_addr.sin_addr.s_addr = inet_addr(nrc->ip);
    server_addr.sin_port = htons(nrc->port);

    if((nrc->fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Failed to create socket\n");
        goto failed;
    }

    int flags = fcntl(nrc->fd, F_GETFL);
    flags |= O_NONBLOCK;

    if(fcntl(nrc->fd, F_SETFL, flags) < 0) {
        printf("Failed to set socket opt");
        goto failed;
    }
    int err = connect(nrc->fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
    if(err && errno != EINPROGRESS) {
        printf("Failed to connect: (%s)%d\n", strerror(errno), errno);
        goto failed;
    }

#ifdef __APPLE__
    /**
     * In iOS, signal() does not work on debug mode because
     * debugger always break on signal while the signal does not
     * exis the program, so add SO_NOSIGPIPE to socket.
     */
    int set = 1;
    setsockopt(nrc->fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
#endif

    ev_io_init(&nrc->fdio, io_handler, nrc->fd, EV_READ);
    ev_io_start(nrc->loop, &nrc->fdio);

    // Initial timeout: server should send nonce to client
    // when connection established. If server does not respond
    // client should try to re-connect.
    ev_timer_again(nrc->loop, &nrc->timer);

    nrc->nonce_len_read_len = nrc->nonce_read_len = 0;
    nrc->cur_req = NULL;
    nrc->status = EV_READ;

    return 0;

failed:
    if(nrc->fd) {
        close(nrc->fd);
        nrc->fd = 0;
    }
    ev_timer_again(nrc->loop, &nrc->timer);
    return -1;
}

nrc_t nrc_new(const char *ip, int port,
        const unsigned char *pk, const unsigned char *sk) {
    nrc_t nrc = malloc(sizeof(struct nrc_s));
    if(!nrc) {
        return NULL;
    }
    memset(nrc, 0, sizeof(struct nrc_s));

    nrc->loop = ev_loop_new(0);

    nrc->ip = strdup(ip);
    nrc->port = port;
    nrc->fd = -1;

    memcpy(nrc->pk, pk, crypto_box_PUBLICKEYBYTES);
    memcpy(nrc->sk, sk, crypto_box_SECRETKEYBYTES);

    TAILQ_INIT(&nrc->req_list);

    if(nrc_connect(nrc)) {
        printf("Failed to connect\n");
    }

    ev_init(&nrc->timer, &timeout_handler);
    nrc->timer.repeat = NRC_TIMEOUT;
    ev_timer_start(nrc->loop, &nrc->timer);

    signal(SIGPIPE, SIG_IGN);
    ev_signal_init(&nrc->signal, &sig_handler, SIGPIPE);
    ev_signal_start(nrc->loop, &nrc->signal);

    return nrc;
}

void nrc_stop(nrc_t nrc) {
    if(nrc->loop) {
        ev_break(nrc->loop, EVBREAK_ALL);
    }

    if(nrc->cur_req) {
        nrc_req_delete(nrc->cur_req);
        nrc->cur_req = NULL;
    }

    nrc_req_t req;
    while((req = TAILQ_FIRST(&nrc->req_list))) {
        TAILQ_REMOVE(&nrc->req_list, req, entries);
        nrc_req_delete(req);
    }
}

void nrc_delete(nrc_t nrc) {
    if(!nrc) {
        return;
    }
    if(nrc->loop) {
        ev_loop_destroy(nrc->loop);
    }
    if(nrc->ip) {
        free(nrc->ip);
    }

    free(nrc);
}

void nrc_update(nrc_t nrc) {
    if(nrc->status == 0 && nrc_ready(nrc)) {
        // There is a pending request
        if(!pop_req(nrc)) {
            printf("pop req\n");
            nrc->status |= EV_WRITE;

            ev_io_stop(nrc->loop, &nrc->fdio);
            ev_io_set(&nrc->fdio, nrc->fd, nrc->status);
            ev_io_start(nrc->loop, &nrc->fdio);
        }
    }

    ev_run(nrc->loop, EVRUN_NOWAIT);
}

int nrc_request(nrc_t nrc, unsigned char *jsonreq, int jsonreqlen,
        nrc_callback callback, const void* privdata) {
    nrc_req_t req = nrc_req_new(jsonreq, jsonreqlen, callback, privdata);
    if(!req) {
        return -1;
    }

    TAILQ_INSERT_TAIL(&nrc->req_list, req, entries);
    return 0;
}
