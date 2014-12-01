#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl\sha.h>
#include <openssl\evp.h>
#include <openssl\hmac.h>

#define DEFAULT_DIGEST "sha256"

// function declarations
unsigned char* generate_file_key(const unsigned char *filename, unsigned char* key, 
	unsigned int keylength, unsigned int *file_key_length);