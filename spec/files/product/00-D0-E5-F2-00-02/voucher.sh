#!/bin/sh

(cd $(dirname $0)/../../../..
 bundle exec rake reach:enroll_http_pledge PRODUCTID=spec/files/product/00-D0-E5-F2-00-02 JRC=https://fountain-test.example.com:8443/
)

mv ../../../../tmp/csr* .
mv ../../../../tmp/voucher_00-D0-E5-F2-00-02.pkcs .
mv ../../../../tmp/vr_00-D0-E5-F2-00-02.pkcs .

