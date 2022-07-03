#!/bin/sh

docker run -it --rm --name strongswan-$1 \
    -v $PWD/ipsec.$1.conf:/etc/ipsec.conf \
    -v $PWD/ipsec.$1.secrets:/etc/ipsec.secrets \
    --cap-add=NET_ADMIN strongswan
