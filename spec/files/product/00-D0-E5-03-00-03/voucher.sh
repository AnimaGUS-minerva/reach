#!/bin/sh

cd $(dirname $0)/../../../..
bundle exec rake reach:enroll_http_pledge PRODUCTID=spec/files/product/00-D0-E5-03-00-03 JRC=https://fountain-test.example.com:8443/


