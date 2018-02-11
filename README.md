# README

This is a test application that uses the Chariwt library to simulate a pledge
for the IETF ANIMA BRSKI protocol.

It performs a BRSKI enrollment.

Using it is described fully at: https://minerva.sandelman.ca/reach/
and also at: https://minerva.sandelman.ca/jokeshop/

For example, given files in the directory 00-D0-E5-02-00-0A/
one can run:

    rake reach:send_voucher_request PRODUCTID=00-D0-E5-02-00-0A JRC=https://fountain-test.sandelman.ca/

