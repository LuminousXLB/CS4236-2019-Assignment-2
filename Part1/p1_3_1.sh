#!/bin/bash

# Auxiliary File
MESSAGE=message.hex

CIPTXT_NEQ1=ciphertext_neq_1.hex
CIPTXT_NEQ2=ciphertext_neq_2.hex
CIPTXT_EQ1=ciphertext_eq_1.hex
CIPTXT_EQ2=ciphertext_eq_2.hex

# Constant
BLOCKSIZE=$(( 128 / 8 ))

# Generate key and iv randomly
KEY=`openssl rand -hex $BLOCKSIZE`
IV1=`openssl rand -hex $BLOCKSIZE`
IV2=`openssl rand -hex $BLOCKSIZE`

################################################################################
echo "    (1) Generate a dummy message"
################################################################################
# Randomly generate a message
openssl rand $(( $BLOCKSIZE*2 )) >> $MESSAGE
# show the message
hexdump -C $MESSAGE

################################################################################
echo ""
echo "    (2) Encrypt the message using two different IVs"
################################################################################
echo ">>> First"
openssl enc -aes-128-cbc -K $KEY -iv $IV1 -e -p -in $MESSAGE -out $CIPTXT_NEQ1

echo ">>> Second"
openssl enc -aes-128-cbc -K $KEY -iv $IV2 -e -p -in $MESSAGE -out $CIPTXT_NEQ2

# Compare the two ciphertext
cmp $CIPTXT_NEQ1 $CIPTXT_NEQ2 -s

if [ $? -eq 0 ]
then
    echo "The two ciphertext files are identical."
else
    echo "The two ciphertext files are different: (Here are only first 10 different bytes)"
    cmp $CIPTXT_NEQ1 $CIPTXT_NEQ2 -l | head
fi

################################################################################
echo ""
echo "    (3) Encrypt the message using the same IV"
################################################################################

echo ">>> First"
openssl enc -aes-128-cbc -K $KEY -iv $IV1 -e -p -in $MESSAGE -out $CIPTXT_EQ1

echo ">>> Second"
openssl enc -aes-128-cbc -K $KEY -iv $IV1 -e -p -in $MESSAGE -out $CIPTXT_EQ2

# Compare the two ciphertext
cmp $CIPTXT_EQ1 $CIPTXT_EQ2 -s

if [ $? -eq 0 ]
then
    echo "The two ciphertext files are identical."
else
    echo "The two ciphertext files are different: (Here are only first 10 different bytes)"
    cmp $CIPTXT_EQ1 $CIPTXT_EQ2 -l | head
fi

################################################################################
echo ""
echo "    (4) Clean auxiliary files"
################################################################################

rm $MESSAGE
rm $CIPTXT_NEQ1
rm $CIPTXT_NEQ2
rm $CIPTXT_EQ1
rm $CIPTXT_EQ2