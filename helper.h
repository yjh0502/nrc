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
