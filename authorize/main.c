#include "crypto_defines.h"
#include "c99_code.h"


void binary_to_string(char *filename, unsigned char *data, unsigned int
length)
{

    unsigned int i;
	
    for (i = 0; i < length; i++) {
        snprintf(filename + 2*i, 3, "%02x", data[i]);
    }
    filename[2*length + 1] = '\0';

}

void string_to_binary(unsigned char *binary, char *string, unsigned int length)
{

    unsigned int i;
    char bytevalue[3];
    bytevalue[2] = '\0';

    for (i = 0; i < length; i+=2) {
        memcpy(bytevalue, string + i, 2);
        sscanf(bytevalue, "%02hhx", binary+ i/2);
    }
}

unsigned char* generate_file_key(const unsigned char *filename, unsigned char* key,
	unsigned int keylength, unsigned int *file_key_length)
{
	unsigned char* file_key = (unsigned char *)malloc(sizeof(*file_key) * BLOCKSIZE);
	HMAC_CTX ctx;

	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, keylength, DIGEST, NULL);
	HMAC_Update(&ctx, filename, strlen((char *)filename));
	HMAC_Final(&ctx, file_key, file_key_length);

	return file_key;
}




int main(int argc, char * argv[]){
	
	unsigned char *binary_filename; 
	unsigned char *realkey;
	unsigned char *keyfromfile;
	unsigned int i, key_length;
	size_t blocksize = BLOCKSIZE;
	char *filename, *encryption_key, *key_filename;

	FILE *FileIN;
	FILE *FileOUT;
	FILE *KeyFilePointer;
	FILE *realkeyfile;

	int keyFileSize;

	if (argc != 3){
		printf("[Error] Usage Must be: 'authorize.exe key.txt filename'\n ");
		return -1;
	}

	KeyFilePointer = fopen(argv[1], "rb"); /* Key file to be read */
	
	/* Get Size of Key File */
	fseek(KeyFilePointer, 0L, SEEK_END);
	keyFileSize = ftell(KeyFilePointer) + 1;
	/* Put it back to the Beginning */
	fseek(KeyFilePointer, 0L, SEEK_SET);

	// READ KEYFILE
	//Initialize space in Key with zero's using calloc and read the secret from the keyfile into it
	printf("[Key derivation] reading secret key...");
	keyfromfile = (unsigned char *)calloc(sizeof(*keyfromfile), keyFileSize);
	i = fread(keyfromfile, sizeof(*keyfromfile), keyFileSize, KeyFilePointer);
	keyfromfile[i] = '\0'; /* This isn't going to be on release, but we shouldn't be reading text
						    * as binary and pretend things won't break later */
	printf("done!\n");

	
	printf("[Key derivation] Calculating filename...");
	binary_filename = generate_file_key(argv[2], keyfromfile, keyFileSize, &key_length);
	filename = (char *)malloc(sizeof(*filename) * 2* (key_length+1));
	binary_to_string(filename, binary_filename, key_length);
	key_filename = (char *)malloc(sizeof(*key_filename) * strlen(filename) + 5);
	sprintf(key_filename, "%s.key", filename);
	printf("done!\n");

	printf("[Key derivation] Calculating encryption key...");
	realkey = generate_file_key(binary_filename, keyfromfile, keyFileSize, &key_length);
	encryption_key = (char *)malloc(sizeof(*encryption_key) * 2 * (key_length + 1));
	binary_to_string(encryption_key, realkey, key_length);
	printf("done!\n");



	/* open sessame */
	printf("[Authorize] Opening files...");
	realkeyfile = fopen(key_filename, "wt");
	if (FileIN == NULL) {
		printf("\n\t [ERROR] Error opening input file!\n");
		goto terminate;
	}
	fwrite(encryption_key, sizeof(char), strlen(encryption_key), realkeyfile);
	printf("done!\n");

	/* Output the result */
	printf("[Authorize] Key generated for file: %s\n", filename);
	printf("[Authorize] Key is located at %s\n", key_filename);

	/* cleanup our mess */
	fclose(FileIN);
	fclose(FileOUT);

terminate:
	fclose(KeyFilePointer);
	free(realkey);
	free(filename);
	free(binary_filename);
	free(encryption_key);
	free(key_filename);

	return 0;

}