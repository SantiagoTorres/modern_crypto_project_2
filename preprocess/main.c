#include "crypto_defines.h"
#include "c99_code.h"

void enc(FILE *inFilePointer, FILE *outFilePointer, unsigned char * realkey)
{

	int inFileSize;
	int outputLength1 = 0;
	int outputLength2 = 0;
	EVP_CIPHER_CTX ctx; /*Encryption Object/Context */
	unsigned char *inputData;
	unsigned char *outputData;
	unsigned int blocksize;
	unsigned int length;
	unsigned char *initVector;

	/*Get Size of Input File */
	fseek(inFilePointer, 0L, SEEK_END);
	inFileSize = ftell(inFilePointer);
	/*Put it back to the Beginning*/
	fseek(inFilePointer, 0L, SEEK_SET);

	// we need the blocksize for a bunch of operations around here...
	blocksize = ENC_BLOCKSIZE;

	// we need to include the length bytes into the equation here...
	inputData = (unsigned char *)malloc((sizeof(*inputData) * inFileSize) + sizeof(length));

	// ugly kluges here, we need to allocate a rounded-up blocksized buffer. 
	// So we divide by blocksize, add 1 and then multiply by blocksize
	outputData = (unsigned char *)malloc(((sizeof(*inputData) * inFileSize) + sizeof(length) / blocksize + 1 * blocksize));


	// calculate the length like this, also write it
	length = inFileSize;
	printf("\t[Encryption] filesize: %u\n", length);
	memcpy(inputData, &length, sizeof(length));

	/*Read the Input File*/
	printf("\t[Encryption] Reading input data...");
	fread(inputData + sizeof(length), sizeof(char), inFileSize, inFilePointer);
	printf("done!\n", inputData + sizeof(length));

	inFileSize += sizeof(length);

	/* Generate an initialization vector */
	initVector = (unsigned char *)malloc(sizeof(*initVector) * blocksize);

	/* populate the IV and write it to the file */
	printf("\t[Encryption] Calculating IV and writing it to file...");
	RAND_bytes(initVector, blocksize);
	fwrite(initVector, sizeof(unsigned char), blocksize, outFilePointer);
	printf("done!\n");

	/*Setup and execute Encryption*/
	printf("\t[Encryption] Encrypting data...");
	EVP_EncryptInit(&ctx, ENC_ALGO, realkey, initVector);       /*Init the Context*/
	EVP_EncryptUpdate(&ctx, outputData, &outputLength1, inputData, inFileSize);  /*Encrypt*/
	EVP_EncryptFinal(&ctx, outputData + outputLength1, &outputLength2);  /*Final Ouput and length */
	printf("done!\n");

	printf("\t[Encryption] Writing data to file...");
	fwrite(outputData, sizeof(char), outputLength1 + outputLength2, outFilePointer);
	printf("done!\n");

	/*Cleanup! Necessary since were not using _ex version of above functions*/
	EVP_CIPHER_CTX_cleanup(&ctx);


	free(initVector);
	

}

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
		printf("[Error] Usage Must be: 'preprocess.exe key.txt File'\n ");
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

	realkeyfile = fopen(key_filename, "wt");
	fwrite(encryption_key, sizeof(char), strlen(encryption_key), realkeyfile);


	/* open sessame */
	printf("[Preprocess] Opening files...");
	FileIN = fopen(argv[2], "rb");  /* plain text file to be encrypted; */
	if (FileIN == NULL) {
		printf("\n\t [ERROR] Error opening input file!\n");
		goto terminate;
	}

	FileOUT = fopen(filename, "wb");/* cipher text File to be written to */
	if (FileOUT == NULL) {
		printf("\n\t [ERROR] Error opening output file!\n");
		fclose(FileIN);
		goto terminate;
	}

	printf("done!\n");


	/*Encrypt the File*/
	printf("[Preprocess] Encrypting data...\n");
	enc(FileIN, FileOUT, realkey);
	printf("[Preprocess] done!\n");

	/* Output the result */
	printf("[Preprocess] Wrote the file to: %s\n", filename);
	printf("[Preprocess] Encryption key is located at %s\n", key_filename);

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