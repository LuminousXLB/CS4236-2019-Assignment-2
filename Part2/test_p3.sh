#! /bin/bash

for file in ./ciphertext/*.txt
do
    # echo $file
    python p3_e0446373.py `cat $file`
done