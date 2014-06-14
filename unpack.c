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

static int
usage() {
    puts("usage: unpack pk sk");
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
    if(argc != 3) usage();

    decode_hexarg(argv[1], pk, sizeof pk);
    decode_hexarg(argv[2], sk, sizeof sk);

    unsigned char *data, *nonce, *out_data;
    size_t data_size, out_size;

    if(read_to_eof(0, &data, &data_size))
        return EXIT_FAILURE;

    nonce = data;
    data += crypto_box_NONCEBYTES;
    data_size -= crypto_box_NONCEBYTES;

    if(unpack_data(nonce, pk, sk, data, data_size, &out_data, &out_size) != NRC_SUCCESS) {
        return EXIT_FAILURE;
    }

    if(write(1, out_data, out_size) != out_size)
        return EXIT_FAILURE;

    return 0;
}

#endif
