#!/bin/sh

cd $(dirname $0)/../../../..
bundle exec rake reach:enroll_http_pledge PRODUCTID=spec/files/product/00-D0-E5-F2-00-0E JRC=https://fountain-test.sandelman.ca:8443/


