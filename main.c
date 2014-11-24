#include "crypto_defines.h"



main(int argc, char *argv[])
 {

 unsigned char *filename, *key;
 unsigned int i, key_length;
 OpenSSL_add_all_digests();

 filename = generate_file_key((unsigned char *)"file.txt", (unsigned char *)"Secret", 
	 strlen("Secret"), &key_length);

 puts("Encrypted Filename:" );
 for (i = 0; i < key_length; i++)
	 printf("%02x", filename[i]);

 printf("\n");

 key = generate_file_key(filename, (unsigned char *)"Secret", strlen("Secret"), &key_length);

 puts("Encryption key:");
 for ( i = 0; i < key_length; i++)
	 printf("%02x", key[i]);

 printf("\n");

 free(key);
 getchar();
 exit(0);

 }


unsigned char* generate_file_key(const unsigned char *filename, unsigned char* key, 
	unsigned int keylength, unsigned int *file_key_length)
{

	unsigned char* file_key = (unsigned char *)malloc(sizeof(*file_key) * EVP_MAX_MD_SIZE);
	unsigned int len;
	const EVP_MD *md;
	HMAC_CTX ctx;

	md = EVP_get_digestbyname(DEFAULT_DIGEST);
	


	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, keylength, md, NULL);
	HMAC_Update(&ctx, filename, strlen((char *)filename));
	HMAC_Final(&ctx, file_key, file_key_length); 

	return file_key;
}