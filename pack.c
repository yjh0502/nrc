#ifdef __MAIN__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "nacl.h"
#include "nrc.h"

#include "helper.h"

unsigned char nonce[crypto_box_NONCEBYTES];

static int
usage() {
    puts("usage: pack pk sk nonce");
    exit(EXIT_FAILURE);
}

static void
decode_hexarg(const char *from, unsigned char *to, size_t len) {
    if(strlen(from) != (len * 2))
        exit(EXIT_FAILURE);
    if(hex_to_bin(from, to, len) == -1)
        exit(EXIT_FAILURE);
}

int
main(int argc, char * argv[])
{
    if(argc != 4) usage();

    size_t size;
    size_t out_size;
    unsigned char *data, *out_data;

    decode_hexarg(argv[1], pk, sizeof pk);
    decode_hexarg(argv[2], sk, sizeof sk);
    decode_hexarg(argv[3], nonce, sizeof nonce);

    if(read_to_eof(0, &data, &size))
        return EXIT_FAILURE;

    if(pack_data(nonce, pk, sk, data, size, &out_data, &out_size) != NRC_SUCCESS)
        return EXIT_FAILURE;

    if(write(1, nonce, sizeof nonce) != sizeof nonce)
        return EXIT_FAILURE;

    if(write(1, out_data, out_size) != out_size)
        return EXIT_FAILURE;

    fprintf(stderr, "%ld -> %ld, %ld\n", size, out_size, sizeof nonce + out_size);

    return 0;
}

#endif
