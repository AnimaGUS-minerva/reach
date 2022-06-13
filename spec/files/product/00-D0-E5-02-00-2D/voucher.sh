#!/bin/sh

cd $(dirname $0)/../../../..
bundle exec rake reach:enroll_http_pledge PRODUCTID=spec/files/product/00-D0-E5-02-00-2D JRC=https://fountain-test.sandelman.ca:8443/


