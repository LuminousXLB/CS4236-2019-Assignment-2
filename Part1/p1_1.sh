#!/bin/bash

# Constants
MESSAGE="Hello, world"
KEY=00112233445566778889aabbccddeeff
IV=0102030405060708

# Auxiliary Files
MSG_FILE=message.hex
ENC_FILE=encrypt.hex
DEC_FILE=decrypt.hex

################################################################################
echo "    (1) Prepare a plaintext file"
################################################################################

# output the message into the file `$MSG_FILE`
echo -n $MESSAGE > $MSG_FILE

# show the message
hexdump -C $MSG_FILE

################################################################################
echo "    (2) Encrypt and decrypt a file using AES-128-CBC"
################################################################################

echo ">>> ENCRYPT"
# encrypt the file `MSG_FILE`, save the ciphertext into `$ENC_FILE`
openssl enc -aes-128-cbc -K $KEY -iv $IV -e -p -in $MSG_FILE -out $ENC_FILE
# hexdump the ciphertext
hexdump -C $ENC_FILE

echo ">>> DECRYPT"
# decrypt the file `$ENCFILE`, save the plaintext into `$DEC_FILE`
openssl enc -aes-128-cbc -K $KEY -iv $IV -d -in $ENC_FILE -out $DEC_FILE
# hexdump the plaintext
hexdump -C $DEC_FILE

################################################################################
echo "    (3) Encrypt and decrypt a file using AES-128-CFB"
################################################################################

echo ">>> ENCRYPT"
openssl enc -aes-128-cfb -K $KEY -iv $IV$IV -e -p -in $MSG_FILE -out $ENC_FILE
hexdump -C $ENC_FILE

echo ">>> DECRYPT"
openssl enc -aes-128-cfb -K $KEY -iv $IV$IV -d -in $ENC_FILE -out $DEC_FILE
hexdump -C $DEC_FILE

################################################################################
echo "    (4) Encrypt and decrypt a file using SM4-CTR"
################################################################################

echo ">>> ENCRYPT"
openssl enc -sm4-ctr -K $KEY -iv $IV$IV -e -p -in $MSG_FILE -out $ENC_FILE
hexdump -C $ENC_FILE

echo ">>> DECRYPT"
openssl enc -sm4-ctr -K $KEY -iv $IV$IV -d -in $ENC_FILE -out $DEC_FILE
hexdump -C $DEC_FILE

################################################################################
echo "    (5) Encrypt and decrypt a file using RC4"
# In this part, I encrypted the message twice using the same key, in order to
# confirm that RC4 is a deterministic encryption scheme.
################################################################################

echo ">>> ENCRYPT"
openssl enc -rc4 -K $KEY -e -p -in $MSG_FILE -out $ENC_FILE
hexdump -C $ENC_FILE

echo ">>> ENCRYPT"
openssl enc -rc4 -K $KEY -e -p -in $MSG_FILE -out $ENC_FILE
hexdump -C $ENC_FILE

echo ">>> DECRYPT"
openssl enc -rc4 -K $KEY -d -in $ENC_FILE -out $DEC_FILE
hexdump -C $DEC_FILE

################################################################################
echo "    (6) Clean auxiliary files"
################################################################################

rm $MSG_FILE $ENC_FILE $DEC_FILE