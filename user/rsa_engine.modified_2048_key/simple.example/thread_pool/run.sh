#!/bin/bash
sudo openssl rsautl -decrypt -inkey private.pem -in msg.enc -engine rsa-engine-new
#echo "Enter pass phrase for private.pem:"
#read $REPLY
#exit
#read $REPLY
