#!/bin/bash
openssl rsautl -decrypt -inkey private.pem -in msg.enc
#echo "Enter pass phrase for private.pem:"
#read $REPLY
