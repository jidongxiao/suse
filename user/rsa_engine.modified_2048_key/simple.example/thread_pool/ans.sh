#!/usr/bin/expect -f
#https://likegeeks.com/expect-command/
set timeout -1

spawn ./run.sh

#expect "Enter pass phrase for private.pem:\r"
#send -- "3250\r"
send -- "1234\r"

expect eof