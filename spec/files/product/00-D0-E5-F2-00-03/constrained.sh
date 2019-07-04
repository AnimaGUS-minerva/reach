#!/bin/sh

cd $(dirname $0)/../../../..
rake reach:send_constrained_request PRODUCTID=spec/files/product/00-D0-E5-F2-00-03 JRC=coaps://fountain-test.sandelman.ca/



