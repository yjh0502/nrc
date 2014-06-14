
#include <stddef.h>

#define NRC_SUCCESS 0
#define NRC_FAILED  1

typedef struct nrc_s* nrc_t;
typedef void (*nrc_callback)(int status, const unsigned char *jsonresp, int jsonresplen,
        const void *privdata);

nrc_t nrc_new(const char *ip, int port,
        const unsigned char *pk, const unsigned char *sk);
void nrc_stop(nrc_t nrc);
void nrc_delete(nrc_t nrc);

void nrc_update(nrc_t nrc);
int nrc_request(nrc_t nrc, unsigned char *jsonreq, int jsonreqlen,
        nrc_callback callback, const void* privdata);

int pack_data(const unsigned char *nonce,
        const unsigned char *pk, const unsigned char *sk,
        const unsigned char *data, size_t data_len,
        unsigned char ** out, size_t *out_len);

int unpack_data(const unsigned char *nonce,
        const unsigned char *pk, const unsigned char *sk,
        const unsigned char *data, size_t data_len,
        unsigned char ** out, size_t *out_len);
