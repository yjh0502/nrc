#!/usr/bin/env sh

NONCE_PREFIX=`cat nonce_prefix`

make pack unpack
cat pack.c | ./pack `cat pk_c` `cat sk_s` `nonce.sh $NONCE_PREFIX` > pack.c.enc
wc -c pack.c.enc
cat pack.c.enc | ./unpack `cat pk_s` `cat sk_c` > pack.c.dec
