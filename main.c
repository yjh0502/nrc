#ifdef __MAIN__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "yajl.h"
#include "nacl.h"
#include "nrc.h"

#include "key.h"

#include "helper.h"

static int init_key(void) {
    if(hex_to_bin(sk_client_hex, sk, crypto_box_SECRETKEYBYTES)) {
        return -1;
    }
    if(hex_to_bin(pk_server_hex, pk, crypto_box_PUBLICKEYBYTES)) {
        return -1;
    }
    return 0;
}

const char *SERVER_HOST = "127.0.0.1";
const int SERVER_PORT = 11013;

static int recv = 500;
unsigned char *msg_str;
size_t msg_str_len;
static void callback(int status, const unsigned char *jsonresp, int jsonresplen,
        const void *privdata) {
    --recv;
    nrc_t nrc = (nrc_t)privdata;
    if(status != NRC_SUCCESS) {
        printf("Failed to request: maybe server is down\n");
    }

    printf("%.*s\n", jsonresplen, jsonresp);

    if(recv > 0) {
        if(nrc_request(nrc, msg_str, msg_str_len, callback, nrc)) {
            printf("Failed to send request\n");
            return;
        }
    }
}

#define JSON_ADD(req, str) do { \
    yajl_gen_string(req, \
        (unsigned char *)str, \
        strlen(str)); } while(0)

int main(void) {
    if(init_key()) {
        return -1;
    }

    nrc_t nrc = nrc_new(SERVER_HOST, SERVER_PORT, pk, sk, 5);
    if(!nrc)
        return -1;

    yajl_gen req = yajl_gen_alloc(NULL);
    yajl_gen_map_open(req);
    JSON_ADD(req, "req");
    JSON_ADD(req, "/v1/user_get");

    JSON_ADD(req, "id");
    JSON_ADD(req, "dqkxdnblrl");
    yajl_gen_map_close(req);

    yajl_gen_get_buf(req, &msg_str, &msg_str_len);

    if(nrc_request(nrc, msg_str, msg_str_len, callback, nrc)) {
        printf("Failed to send request");
        exit(-1);
    }

    while(recv) {
        nrc_update(nrc);
        usleep(10 * 1000);
    }

    yajl_gen_free(req);
    nrc_delete(nrc);

    return 0;
}

#endif
