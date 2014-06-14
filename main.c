#ifdef __MAIN__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "yajl.h"
#include "nacl.h"
#include "nrc.h"

const char * sk_client_hex = "0a9511481c1965c8cfcf2baa57ed3976e9d90e9404071660ab782bed23966868";
const char * pk_server_hex = "242ddcd49f796d7e8f13a70e7e92661533df38847d2826792ae6f0810ead8b28";

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

const char *SERVER_HOST = "115.68.131.49";
const int SERVER_PORT = 11003;

static int recv = 5;
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

    nrc_t nrc = nrc_new(SERVER_HOST, SERVER_PORT, pk, sk);
    if(!nrc)
        return -1;

    yajl_gen req = yajl_gen_alloc(NULL);
    yajl_gen_map_open(req);
    JSON_ADD(req, "req");
    JSON_ADD(req, "/v1/playlog_mylist");

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
    }

    yajl_gen_free(req);
    nrc_delete(nrc);

    return 0;
}

#endif
