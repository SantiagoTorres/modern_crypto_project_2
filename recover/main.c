#include "crypto_defines.h"
#include "c99_code.h"



void dec(FILE *inFilePointer, FILE *outFilePointer, unsigned char* key){

	int inFileSize;
	EVP_CIPHER_CTX ctx; /*Decryption Object/context*/
	int outputLength1 = 0;
	int outputLength2 = 0;
	unsigned char *inputData;
	unsigned char *outputData;
	unsigned int length;
	unsigned int blocksize;
	unsigned char *initVector;
	int i, keyFileSize;



	/*Get Size of Input File*/
	fseek(inFilePointer, 0L, SEEK_END);
	inFileSize = ftell(inFilePointer);
	/*Put it back to the Beginning*/
	fseek(inFilePointer, 0L, SEEK_SET);

	/* blocksize is handy all around :) */
	blocksize = ENC_BLOCKSIZE;
	
	/* append a buffer of blocksize as per the spec */
	inputData = (unsigned char *)malloc(sizeof(*inputData) * (inFileSize + blocksize));
	outputData = (unsigned char *)malloc(((sizeof(*inputData) * inFileSize) + sizeof(length) / blocksize + 1 * blocksize));

	/* populate the IV and write it to the file */
	printf("\t[Decrypt] Reading IV...");
	initVector = (unsigned char *)malloc(sizeof(*initVector) * blocksize);
	fread(initVector, sizeof(unsigned char), blocksize, inFilePointer);
	printf("done!\n");

	/*Read the input File*/
	printf("\t[Decrypt] Reading encrypted data...");
	fread(inputData, sizeof(char), inFileSize - blocksize, inFilePointer);
	printf("done!\n");

	/*Setup and Execute decryption*/
	printf("\t[Decrypt] Decrypting...");
	EVP_DecryptInit(&ctx, ENC_ALGO, key, initVector);   /*Init the Context */
	EVP_DecryptUpdate(&ctx, outputData, &outputLength1, inputData, inFileSize); /*Decrypt */
	EVP_DecryptFinal(&ctx, outputData + outputLength1, &outputLength2);  /*Final Output and length */
	printf("done!\n");

	/* obtain the original file's length */
	printf("\t[Decrypt] Obtaining file length...");
	memcpy(&length, outputData, sizeof(length));
	printf("Obtained length %u...", outputLength1);
	printf("done!\n");

	/* write the file... */
	printf("\t[Decrypt] Writing out the file...");
	fwrite(outputData + sizeof(length), sizeof(char), length, outFilePointer); /*write the truncated output data to file*/
	printf("done!\n");

	/*Cleanup! Necessary since were not using _ex version of above functions*/
	EVP_CIPHER_CTX_cleanup(&ctx);

	free(initVector);
	free(inputData);
	free(outputData);
	return;
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
        sscanf(bytevalue, "%02hhx", binary + (i/2));
    }

	return;
}

unsigned char* generate_file_key(const unsigned char *filename, unsigned char* key,
	unsigned int keylength, unsigned int *file_key_length)
{
	unsigned char* file_key = (unsigned char *)malloc(sizeof(*file_key) * EVP_MAX_MD_SIZE);
	unsigned int len;
	HMAC_CTX ctx;

	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, keylength, DIGEST, NULL);
	HMAC_Update(&ctx, filename, strlen((char *)filename));
	HMAC_Final(&ctx, file_key, file_key_length);

	return file_key;
}

/* load_key loads a key from an ascii-encoded file and returns it's binary 
 * equivalent.
 */
unsigned char *load_key(char *filename)
{
	FILE *fp;
	unsigned char *key;
	char *text;

	fp = fopen(filename, "rt");
	if (!fp) {
		return NULL;
	}

	text = (char *)malloc(sizeof(*text) * (BLOCKSIZE * 2) + 1);
	fgets(text, BLOCKSIZE, fp);

	key = (unsigned char *)malloc(sizeof(*key) * BLOCKSIZE);
	string_to_binary(key, text, strlen(text));

	fclose(fp);
	free(text);
	return key;

}

int main(int argc, char * argv[]){


	FILE *FileIN;
	FILE *FileOUT;
	unsigned char *key;

	if (argc != 3){
		printf("[ERROR] Usage Must be: 'recover.exe Key File'\n");
		return -1;
	}

	/*Decrypt the file*/
	FileIN = fopen(argv[2], "rb");/*Cipher text file to be Decrypted*/
	FileOUT = fopen("decrypted", "wb");/*Decrypted ciphertext will be written here*/
	printf("[Key derivation] Loading key....");
	key = load_key((char *)argv[1]);  /* Key file to be read */
	printf("done!\n");

	printf("[Recover] Preparing for decryption...\n");
	dec(FileIN, FileOUT, key);
	printf("done!\n");

	printf("[Revocer] Success! The file was recovered and placed under the filename \"decrypted\"\n");
	fclose(FileIN);
	fclose(FileOUT);
	free(key);

	return 0;
}