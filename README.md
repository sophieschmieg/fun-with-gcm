# Introduction

This is a repository to play with various basic cryptographic attacks for
myself.

# CBC Padding Oracle Attack

The CBC padding oracle attack is an attack that can be run against any endpoint
that uses unauthenticated CBC. All that is needed is that the endpoint attempts
to decrypt a message and failing on invalid padding. The attack allows for
recovery of the plaintext.

## How it works

### CBC Mode

In order to avoid encrypting a repeated plaintext block to the same ciphertext,
CBC mode ranodmizes the input into AES by xoring the plaintext block with the
previous ciphertext block, using the IV for the first plaintext block.

This avoids the problem of ECB mode, as for all intents and purposes, the input
into the AES block function will always be random: For the first block, as the
IV for CBC mode is chosen randomly, and for all subsequent blocks because the
ouput of AES without knowledge of the key is indistinguishable from random
numbers. If any block or IV ever repeats, information is leaked to the attacker.
As this is a random collision chance, the number of messages that can be safely
encrypted with CBC mode is bound by the birthday paradox on the block size.

In order for CBC mode to work, the plaintext has to be a multiple of the
blocksize, as we need a full block to encrypt or decrypt with the block cipher.

### Padding

In order to achieve this multiple of the block size requirement, we have to pad
the ciphertext. Any bijective mapping between plaintext and padded plaintexts
works, but we will focus on the PKCS 5 padding here. This padding works by
taking the number of bytes missing to a full multiple of 16 bytes

### Attack

The attacker takes the ciphertext they want to decrypt and tries to flip bits
so that the last byte forms a valid padding byte for a ciphertext one shorter
than the original.

The padding used (PKCS5) adds n bytes of value n to the end of the plaintext
with n between 1 and 16 chosen so that the padded plaintext has a size that is
a multiple of 16.
CBC mode xors the preceeding ciphertext block (or the IV) with the plaintext
before encrypting it. So changing the corresponding byte in the preceeding
ciphertext block changes what the decrypted byte looks like.

EXAMPLE: Suppose the plaintext has 31 characters with the last having the value
s. In order to obtain a 32 byte padded plaintext, a single byte with value 0x01
is appended. If we change byte 15 of the ciphertext (indexing with 0) by xoring
with 0x03 (binary 11) than the padding byte is changed to 0x02. The decryption
will only be successful if s happens to be 0x02 and otherwise 

## The code

# GCM Key Commitment Attack
