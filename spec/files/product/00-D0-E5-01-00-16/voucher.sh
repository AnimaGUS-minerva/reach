#!/bin/sh

prod=$(basename $(/bin/pwd))
(
    cd $(dirname $0)/../../../..
bundle exec rake reach:enroll_http_pledge PRODUCTID=spec/files/product/${prod} JRC=https://fountain-test.sandelman.ca:8443/
)

mv ../../../../tmp/csr* .
mv ../../../../tmp/voucher_${prod}.pkcs .
mv ../../../../tmp/vr_${prod}.pkcs .
mv ../../../../tmp/certificate.der ldevid.crt




