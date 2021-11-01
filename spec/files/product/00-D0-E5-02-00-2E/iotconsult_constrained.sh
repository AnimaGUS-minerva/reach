#!/bin/sh

cd $(dirname $0)/../../../..
export CIPHER_LIST='ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-CCM8'
rake reach:send_constrained_request PRODUCTID=spec/files/product/00-D0-E5-02-00-2E JRC=coaps://masa.iotconsultancy.nl:5684/



