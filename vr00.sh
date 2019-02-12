#!/bin/sh

# use a product definition from co-located highway MASA, to avoid confusion.

rake reach:send_voucher_request PRODUCTID=../highway/spec/files/product/00-D0-E5-F2-00-01 JRC=https://fountain-test.example.com/
