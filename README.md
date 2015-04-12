mDES
====

Implementation of a mini-DES (mDES) encryption algorithm.


Usage
-----

mDES takes 4 command line arguments (only tested in this order):

|Argument   |Description|
|--------   |-----------|
|-e / -d    | Tells the program to encrypt or decrypt |
|hex chars  | The plaintext or ciphertext |
|-k			| Indicates the next argument is the 8-bit key to use |
|key		| Khe 8-bit encryption key used to generate the round keys, as two hex characters|

Note that the input is assumed to be multiples of 8-bit blocks (two hex characters) and already padded if necessary.


Examples:
---------

Encryption

    $ ./mDES -e 0123456789abcdef -k 4d
    Set to encrypt
    Plaintext:		0x0123456789abcdef
    Key: 			0x4d 				
    Ciphertext: 	0x231404152de00222

Decryption

    $./mDES -d 231404152de00222 -k 4d	
    Set to decrypt
    Ciphertext:	0x231404152de00222
    Key: 		0x4d 
    Plaintext: 	0x0123456789abcdef	
