#!/bin/sh

cd $(dirname $0)/../../../..
rake reach:send_constrained_request PRODUCTID=spec/files/product/00-D0-E5-02-00-2E JRC=coaps://fountain-test.example.com/



