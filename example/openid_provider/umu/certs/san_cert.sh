#!/bin/bash

#san_cert.sh

# defaults =====================================================================
DOM=catalogix.se
O=Catalogix\ AB
C=SE
EMAIL=certalert

#basic checks and strings ======================================================
if [ -z "$1" ];then
    echo usage: $0 name1 optionalname optionalname ...
    echo example: san_cert.sh www web w3 exch mail
    exit
else
    CN=$1
    SUBJ="/C=$C/O=$O/emailAddress=$EMAIL.$DOM"
fi

#clearing old files
rm $DOM.ssl_csr $DOM.ssl_key

#create private key ============================================================
openssl genrsa -out $DOM.ssl_key 2048


if [ $# -gt 1 ];then #test for arg count
    #build SAN string ==================
    A=($@)
    I=1
    while [ $I -lt ${#A[@]} ]
    do
        SAN="DNS:${A[I]}.$DOM$CMA${SAN}"
        CMA=","
        I=$[$I+1]
    done
    SAN="\n[SAN]\nsubjectAltName=${SAN}"
    #===================================

    #create SAN certificate signing request ====================================
    openssl req -new -sha256 \
    -subj "$SUBJ" \
    -key   $DOM.ssl_key \
    -out   $DOM.ssl_csr \
    -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "$SAN"))
else
    #create Single certificate signing request =================================
    openssl req -new -sha256 \
    -subj "$SUBJ" \
    -key   $DOM.ssl_key \
    -out   $DOM.ssl_csr
fi

#verification ==================================================================
openssl req -text -noout -verify -in $DOM.ssl_csr