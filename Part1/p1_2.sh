#!/bin/bash

# Input file
PICTURE=../../picture/pic_original.bmp

# Output file
PIC_ECB=pic_ecb.bmp
PIC_CBC=pic_cbc.bmp

################################################################################
echo "(1) Encrypt the picture using AES-128-ECB"
################################################################################

head -c 54 $PICTURE > $PIC_ECB

openssl enc -aes-128-ecb \
    -K 00112233445566778889aabbccddeeff -e \
    -in $PICTURE | tail -c +55 >> $PIC_ECB

################################################################################
echo "(2) Encrypt the picture using AES-128-CBC"
################################################################################

head -c 54 $PICTURE > $PIC_CBC
openssl enc -aes-128-cbc \
    -K 00112233445566778889aabbccddeeff \
    -iv 01020304050607080102030405060708 -e \
    -in $PICTURE | tail -c +55 >> $PIC_CBC
