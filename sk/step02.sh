#!/bin/sh

rake reach:sk1_rvr JRC=https://fountain-test.example.com:8443/.well-known/brski/requestvoucherrequest PRODUCTID=spec/files/product/Smarkaklink-1502449999 DPPFILE=../fountain/spec/files/product/Smarkaklink-n3ce618/dpp1.txt $*
