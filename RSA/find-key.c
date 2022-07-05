/* ***********************************************
* Author: T. Briggs (c) 2019
* Date: 2019-02-25
* 
* Brute-force attach against an RSA key.
*
* Reads the public key files and iterates through
* all of the odd numbers from 3 to 2^key_len
************************************************ */ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>

// GNU Multi-Precision Math
// apt-get install libgmp-dev, gcc ... -lgmp
#include <gmp.h>

// My RSA library - don't use for NSA work
#include "rsa.h"

int found = 0;

//Struct being shared with threads
typedef struct {
	int keylen;
	char *encrypted;
	unsigned long start, end;
	int bytes;
	clock_t starttime;
} work_struct_t;

//Stops the time, finds a difference, and prints
void stop_time(clock_t before) {
	clock_t dif = clock() - before;
	long difference =  (dif * 1000) / CLOCKS_PER_SEC;
	printf("It has been %ld s %ld ms\n", difference/1000, difference%1000);
}

// Print a block of bytes as hexadecimal
void print_buff(int len, char *buf)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x", (unsigned char) buf[i]);
	}
}

//Prompt the user to enter a keylength to find (Easier than hard coding)
int get_key_len() {
	int len;
	printf("Enter a keylength: ");
	while(scanf("%d", &len) == 0) {
		printf("Enter a correct number\n");
	}
	
	return len;
}

void *thread_crack(void *param) {
	rsa_keys_t keys;
	work_struct_t *in = (work_struct_t *)param;
	char *decrypted = malloc(1024*2);

	// read the public keys from the file
	//printf("Reading Alice's public keys\n");
	char *fname = malloc(1024);
	sprintf(fname,"../intercepted_messages/public-%d.txt", in->keylen);
	rsa_read_public_keys(&keys, fname);

	unsigned long i;
	for(i = in->start; i < in->end; i+=2) {
		mpz_set_ui(keys.d, i);

		// decrypt the message using our current guess
		rsa_decrypt(in->encrypted, decrypted, in->bytes, &keys);
		
		// check to see if it starts with "<h1>"
		if (!strncmp(decrypted,"<h1>",4)) {	
			printf("Found key: %lu %lx\n", i, i);
			printf("Message: %s\n", decrypted);
				
			free(decrypted);
			found++;
			return NULL;
			// this may actually be garbage.  so, don't quit.
			// break
		}

		if(found != 0) {
			free(decrypted);
			return NULL;
		}
	}

	free(decrypted);
	return NULL;
}

//Set the number of threads to use
#define THRD_NUM 6

// Set the expected key length (in bits)
//#define KEY_LEN 34

// Set the maximum number of characters 
// in a message (in bytes)
#define BLOCK_LEN 32

int main(int argc, char **argv)
{
	int KEY_LEN = get_key_len();

	clock_t starttime = clock();
	pthread_t threads[THRD_NUM];
	pthread_attr_t threadattrs[THRD_NUM];
	work_struct_t works[THRD_NUM];

	rsa_keys_t keys;						// the RSA keys
	
	// a block of text for the encrypted and decrypted messages
	// it has to be large enough to handle the padding we might
	// get back from the encrypted/decrypted functions
	char *encrypted = malloc(1024*2);
	char *decrypted = malloc(1024*2);

 	// read the public keys from the file
	printf("Reading Alice's public keys\n");
	char *fname = malloc(1024);
	sprintf(fname,"../intercepted_messages/public-%d.txt", KEY_LEN);
	//rsa_read_public_keys(&keys, fname);
	
	printf("Reading encrypted message\n");
	sprintf(fname,"../intercepted_messages/encrypted-%d.dat", KEY_LEN);
	FILE *fp = fopen(fname,"r+");
	if (fp == NULL) {
		perror("could not open encrypted text");
		exit(-1);
	}
	
	int bytes = fread(encrypted, 1, BLOCK_LEN*(KEY_LEN/8), fp);
	printf("Read %d bytes\n", bytes);
	fclose(fp);

	// Initialize the RSA key (candidate private key)
	mpz_init(keys.d);
	
	//unsigned long i;
	unsigned long end = (1L << KEY_LEN) - 3;
	//int count = 0;

	//Amount of keys each thread should cover
	unsigned long step = end/THRD_NUM;

	//Populate the working structs, attributes, and start the threads.
	int i;
	for(i = 0; i < THRD_NUM; i++) {
		pthread_attr_init(&threadattrs[i]);
		works[i].bytes = bytes;
		works[i].encrypted = encrypted;
		works[i].keylen = KEY_LEN;
		works[i].start = (i*step) + 3;
		works[i].end = (works[i].start + step)-1;
		printf("start: %ld\n", works[i].start);
		printf("end: %ld\n", works[i].end);
		pthread_create(&threads[i], &threadattrs[i], thread_crack, &works[i]);
	}

	//Join the threads back
	for(i = 0; i < THRD_NUM; i++) {
		pthread_join(threads[i], NULL);
	}
	stop_time(starttime);
	
/* 	for (i = 3; i < end; i+=2) {
	
		// print some progress out to the screen
		if (count++ == 50000) {
			printf("\r%lx/%lx %0.1f%%", i, end, ((double)i/(double)end)*100.0);
			fflush(stdout);
			count = 0;
		}
		
	}
	if(i >= end) {
		printf("did not find key\n");
	} */

	// free up the memory we gobbled up
	free(encrypted);
	//free(decrypted);
	free(fname);
	
	mpz_clear(keys.d);
	mpz_clear(keys.n);
	mpz_clear(keys.e);
	mpz_clear(keys.p);
	mpz_clear(keys.q);
}
