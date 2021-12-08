#!/bin/sh

# note that: spec/files/product/Smarkaklink-n3ce618/dpp1.txt
# is produced by highway, but stored into fountain.

rake reach:sk0_dpp_manu_enroll PRODUCTID=spec/files/product/Smarkaklink-1502449999 DPPFILE=../fountain/spec/files/product/Smarkaklink-n3ce618/dpp1.txt $*
