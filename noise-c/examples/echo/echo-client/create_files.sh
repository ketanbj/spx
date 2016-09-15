#!/bin/bash

sizes="1 10 100 200 400 800 1200 1600"

for size in $sizes
do
dd if=/dev/zero of=files/file_$size bs=1K count=$size
done
