#!/bin/bash

# Constants
MESSAGE="Hello, world"

# Auxiliary file
MSG_FILE=message.hex
ENC_FILE=encrypt.hex
DEC_FILE=decrypt.hex

# Output file
KEY=`openssl rand -hex 16`
IV=`openssl rand -hex 16`


################################################################################
echo ""
echo "(1) Prepare a plaintext file"
################################################################################

echo -n $MESSAGE > $MSG_FILE

hexdump -C $MSG_FILE

################################################################################
echo ""
echo "(2) Encrypt the file using AES-256-CFB"
################################################################################

echo ">>> ENCRYPT"
openssl enc -aes-256-cfb -K $KEY$KEY -iv $IV -e -in $MSG_FILE -out $ENC_FILE
hexdump -C $ENC_FILE

echo ">>> DECRYPT"
openssl enc -aes-256-cfb -K $KEY$KEY -iv $IV -d -in $ENC_FILE -out $DEC_FILE
hexdump -C $DEC_FILE

################################################################################
echo ""
echo "(3) Encrypt the file using SM4-CTR"
################################################################################

echo ">>> ENCRYPT"
openssl enc -sm4-ctr -K $KEY -iv $IV -e -in $MSG_FILE -out $ENC_FILE
hexdump -C $ENC_FILE

echo ">>> DECRYPT"
openssl enc -sm4-ctr -K $KEY -iv $IV -d -in $ENC_FILE -out $DEC_FILE
hexdump -C $DEC_FILE

################################################################################
echo ""
echo "(4) Encrypt the file using RC4"
################################################################################

echo ">>> ENCRYPT"
openssl enc -rc4 -K $KEY -e -in $MSG_FILE -out $ENC_FILE
hexdump -C $ENC_FILE

echo ">>> DECRYPT"
openssl enc -rc4 -K $KEY -d -in $ENC_FILE -out $DEC_FILE
hexdump -C $DEC_FILE

################################################################################
echo ""
echo "(5) Clean auxiliary files"
################################################################################

rm $MSG_FILE $ENC_FILE $DEC_FILE