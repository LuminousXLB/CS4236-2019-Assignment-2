#!/bin/bash

# Auxiliary File
MESSAGE=message.hex

CIPTXT_NEQ1=ciphertext_neq_1.hex
CIPTXT_NEQ2=ciphertext_neq_2.hex
CIPTXT_EQ1=ciphertext_eq_1.hex
CIPTXT_EQ2=ciphertext_eq_2.hex

# Constant
BLOCKSIZE=128
KEY=`openssl rand -hex 16`
IV1=`openssl rand -hex 16`
IV2=`openssl rand -hex 16`

################################################################################
echo "******** Generate dummy message ********"
################################################################################

head -c $(( $BLOCKSIZE / 8 * 2 )) /dev/urandom >> $MESSAGE

hexdump -C $MESSAGE

################################################################################
echo ""
echo "(1) Encrypt the message using different IVs"
################################################################################

openssl enc -aes-128-cbc -K $KEY -iv $IV1 -e -in $MESSAGE -out $CIPTXT_NEQ1
openssl enc -aes-128-cbc -K $KEY -iv $IV2 -e -in $MESSAGE -out $CIPTXT_NEQ2

cmp $CIPTXT_NEQ1 $CIPTXT_NEQ2 -s

if [ $? -eq 0 ]
then
    echo "The two ciphertext files are identical."
else
    echo "The two ciphertext files are different: (only first 10 different bytes listed)"
    cmp $CIPTXT_NEQ1 $CIPTXT_NEQ2 -l | head
fi

################################################################################
echo ""
echo "(2) Encrypt the message using the same IV"
################################################################################

openssl enc -aes-128-cbc -K $KEY -iv $IV1 -e -in $MESSAGE -out $CIPTXT_EQ1
openssl enc -aes-128-cbc -K $KEY -iv $IV1 -e -in $MESSAGE -out $CIPTXT_EQ2

cmp $CIPTXT_EQ1 $CIPTXT_EQ2 -s

if [ $? -eq 0 ]
then
    echo "The two ciphertext files are identical."
else
    echo "The two ciphertext files are different: (only first 10 different bytes listed)"
    cmp $CIPTXT_EQ1 $CIPTXT_EQ2 -l | head
fi

################################################################################
echo ""
echo "******** Clean auxiliary files ********"
################################################################################

rm $MESSAGE
rm $CIPTXT_NEQ1
rm $CIPTXT_NEQ2
rm $CIPTXT_EQ1
rm $CIPTXT_EQ2