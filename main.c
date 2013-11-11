
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "yajl.h"
#include "nacl.h"
#include "nrc.h"

const char * sk_client_hex = "e30ecd8f566dade8d62f680dbf79bf46dbe3d4d2a2b692fcb3723286bac906c2";
const char * pk_server_hex = "41b8271e9f8a1f27f5cdb57ba45dae7d9a58ef5104b57106cfc88f025d1d4b59";

static int decode_hex(const char ch, unsigned char *out) {
    if(ch >= '0' && ch <= '9') {
        *out = (unsigned char)(ch - '0');
    } else if(ch >= 'a' && ch <= 'f') {
        *out = (unsigned char)(ch + 10 - 'a');
    } else if(ch >= 'A' && ch <= 'F') {
        *out = (unsigned char)(ch + 10 - 'A');
    } else {
        return -1;
    }
    return 0;
}

static int hex_to_bin(const char * hex, unsigned char * bin, int length) {
    int i;
    unsigned char ch_lower = 0, ch_upper = 0,
        *hex_pos = (unsigned char *)hex - 1,
        *bin_pos = bin - 1;

    for(i = 0; i < length; i++) {
        if(decode_hex(*(++hex_pos), &ch_upper) ||
                decode_hex(*(++hex_pos), &ch_lower)) {
            return -1;
        }
        *(++bin_pos) = (ch_upper << 4) + ch_lower;
    }
    return 0;
}

unsigned char sk[crypto_box_SECRETKEYBYTES];
unsigned char pk[crypto_box_PUBLICKEYBYTES];

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
const int SERVER_PORT = 50002;

static int i = 5;
unsigned char *msg_str;
size_t msg_str_len;
static void callback(int status, const unsigned char *jsonresp, int jsonresplen,
        const void *privdata) {
    nrc_t nrc = (nrc_t)privdata;
    if(status != NRC_SUCCESS) {
        printf("Failed to request: maybe server is down\n");
        return;
    }

    printf("%.*s\n", jsonresplen, jsonresp);

    if(i != 0) {
        if(nrc_request(nrc, msg_str, msg_str_len, callback, nrc)) {
            printf("Failed to send request\n");
            return;
        }
        --i;
    }
}

int main(void) {
    if(init_key()) {
        return -1;
    }

    nrc_t nrc = nrc_new(SERVER_HOST, SERVER_PORT, pk, sk);
    if(!nrc)
        return -1;

    yajl_gen req = yajl_gen_alloc(NULL);
    yajl_gen_map_open(req);
    yajl_gen_string(req, (unsigned char *)"req", 3);
    yajl_gen_string(req, (unsigned char *)"/v1/hello", 9);
    yajl_gen_map_close(req);

    yajl_gen_get_buf(req, &msg_str, &msg_str_len);

    if(nrc_request(nrc, msg_str, msg_str_len, callback, nrc)) {
        printf("Failed to send request");
        exit(-1);
    }

    nrc_update(nrc);

    yajl_gen_free(req);
    nrc_delete(nrc);

    return 0;
}
