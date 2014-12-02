#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <specstrings.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h> /* Include default random engine */
/* We should change the randomness source to be something cool, like the screen */
#include <openssl\sha.h>
#include <openssl\evp.h>
#include <openssl\hmac.h>
#include <ctype.h>

/* this defines hold the selected algorithms to use */
#define ENC_ALGO EVP_aes_256_cbc()
#define ENC_BLOCKSIZE EVP_CIPHER_block_size(ENC_ALGO)
#define DIGEST EVP_sha256()
#define BLOCKSIZE EVP_MD_block_size(DIGEST)

/* Function declarations */

/* Enc receives two file pointers (source and destination) and a key filename
 *	as a string. The contents of inFilePoiinter are encrypted using the key in filename and
 *  the result is written to outFilePointer.
 */
void enc(FILE *inFilePointer, FILE *outFilePointer, unsigned char * realkey);

/* generate_file_key produces a filename from an hmac key (oftentimes a string), 
 *   the length of the resulting key (in bytes) is written to file_key_length.
 *	 The with_digest flag forces an extra hashing round...
 */
unsigned char* generate_file_key(const unsigned char *filename, unsigned char* key,
	unsigned int keylength, unsigned int *file_key_length);

/*  binary_to_string produces a hex-encoded printable string from an input
 *  binary stream (data), the result is written to char* filename. Filename must be 2xlength+1 
 *  long in order to hold the result of the data input. 
 */
void binary_to_string(char *filename, unsigned char *data, unsigned int
length);

/*  string_to_binary produces a binary representation of an hex-encoded string.
 *  In other words, is the inverse operation of the previous function. 
 */
void string_to_binary(unsigned char *binary, char *string, unsigned int length);