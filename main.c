/***************************************************************************
 * Implementation of Protected n-share AES-128 in C
 * 
 * This code is an implementation of a protected n-share AES-128 using 
 * compiled gadgets with the expanding circuit compiler introduced in:
 * 
 * "Random Probing Security: Verification, Composition, Expansion and New 
 * Constructions"
 * By Sonia Belaïd, Jean-Sébastien Coron, Emmanuel Prouff, Matthieu Rivain, 
 * and Abdul Rahman Taleb
 * In the proceedings of CRYPTO 2020.
 * 
 * Copyright (C) 2020 CryptoExperts
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * 
 *  Modifications date: December 2024
 * 
 * Description of modifications:
 * - Enhanced `gadgets.c` by implementing an iterable gadget to improve functionality.
 * - Updated the implementation of the `void exp254_sharing(uint8_t *x, uint8_t * out)` function in `aes128_sharing.c` to change the order of the addition chain.

***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "./aes_files/gf256.h"
#include "./aes_files/gadgets.h"
#include "./aes_files/aes128_sharing.h"

double my_gettimeofday(){
  struct timeval tmp_time;
  gettimeofday(&tmp_time, NULL);
  return tmp_time.tv_sec + (tmp_time.tv_usec * 1.0e-6L);
}

int main(int argc, char ** argv){
	
	for(int i=0; i<NB_SHARES; i++){
		const_s[i] = 0;
	}
	
	srand(time(NULL));
	
	double start, end, aes_enc, aes_dec, aes_sharing_enc, aes_sharing_dec;
	

	uint8_t i, r;
	uint8_t key[] = {
		0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 
		0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98,
	};

	uint8_t plaintext[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	
	const uint8_t const_cipher[AES_BLOCK_SIZE] = {
		0xff, 0x0b, 0x84, 0x4a, 0x08, 0x53, 0xbf, 0x7c,
		0x69, 0x34, 0xab, 0x43, 0x64, 0x14, 0x8f, 0xb9,
	};
	
	uint8_t ciphertext[AES_BLOCK_SIZE];
	uint8_t roundkeys[AES_ROUND_KEY_SIZE];
	
	uint8_t plaintext_res[AES_BLOCK_SIZE];
	
	
	/*************************** Generating Sharings of texts and keys ***************************/
	uint8_t ** plaintext_sharing = (uint8_t **)malloc(AES_BLOCK_SIZE * sizeof(uint8_t *));
	uint8_t ** plaintext_res_sharing = (uint8_t **)malloc(AES_BLOCK_SIZE * sizeof(uint8_t *));
	uint8_t ** ciphertext_sharing = (uint8_t **)malloc(AES_BLOCK_SIZE * sizeof(uint8_t *));
	for(i =0; i< AES_BLOCK_SIZE; i++){
		plaintext_sharing[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
		plaintext_res_sharing[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
		ciphertext_sharing[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
	}
	uint8_t ** roundkeys_sharing = (uint8_t **)malloc(AES_ROUND_KEY_SIZE * sizeof(uint8_t *));
	for(i=0; i<AES_ROUND_KEY_SIZE; i++){
		roundkeys_sharing[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
	}
	
	for(i =0; i<AES_BLOCK_SIZE; i++){
		generate_n_sharing(plaintext[i], plaintext_sharing[i]);
		generate_n_sharing(0, ciphertext_sharing[i]);
	}
	for(i =0; i<AES_ROUND_KEY_SIZE; i++){
		generate_n_sharing(roundkeys[i], roundkeys_sharing[i]);
	}
	
	
	/*************************** AES-128 Sharing Secure Encryption / Decryption ***************************/
	start = my_gettimeofday();
	aes_encrypt_128_sharing(roundkeys_sharing, plaintext_sharing, ciphertext_sharing);
	end = my_gettimeofday();
	aes_sharing_enc = end - start;
	
	start = my_gettimeofday();
	aes_decrypt_128_sharing(roundkeys_sharing, ciphertext_sharing, plaintext_res_sharing);
	end = my_gettimeofday();
	aes_sharing_dec = end - start;
	
	
	/*************************** Verifying that sharing AES decryption gives back the original plaintext ***************************/
	for(i=0; i<AES_BLOCK_SIZE; i++){
		if(compress_n_sharing(plaintext_sharing[i]) != compress_n_sharing(plaintext_res_sharing[i])){
			printf("DECRYPT ERROR\n");
			exit(EXIT_FAILURE);
		}
	}
	printf("SHARING ENCRYPTION SUCCESS\n");


	/*************************** Printing Ciphertext ***************************/
	printf("\nCipher text:\n");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%2x ", compress_n_sharing(ciphertext_sharing[i]));
	}
	printf("\n");
	
	
	printf("\n\nTimings: \n");
	
	printf("\n\nAES sharing enc took %lf ms\n", aes_sharing_enc * 1000);
	printf("\nAES sharing dec took %lf ms\n", aes_sharing_dec * 1000);

	for(i =0; i< AES_BLOCK_SIZE; i++){
		free(plaintext_sharing[i]);
		free(ciphertext_sharing[i]);
	}
	for(i=0; i<AES_ROUND_KEY_SIZE; i++){
		free(roundkeys_sharing[i]);
	}
	free(plaintext_sharing);
	free(ciphertext_sharing);
	free(roundkeys_sharing);
	
	return 0;
	
	
}
