#!/bin/sh

server=localhost
port=7000

pattern_list="NN NK NX XN IN IX"

echo "Please ensure that you have disabled the interactive portion of the echo-client"

for pattern in $pattern_list
do
out=`./echo-client Noise_"$pattern"_448_ChaChaPoly_SHA256 -c ../keys/client_key_448 -s ../keys/server_key_448.pub $server $port`
echo $pattern':'$out
done
