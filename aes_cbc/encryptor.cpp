#include <iostream> 
#include <fstream>
#include <string>
#include <stdlib.h>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
using namespace std;

/* Generate the IV used for AES-128 in CBC mode */
unsigned char *generate_iv(int iv_size) {

   int ret;

   /* Seed OpenSSL PRNG */
   RAND_poll();

   unsigned char *iv = (unsigned char *)malloc(iv_size);

   /* Generates 16 random bytes for my IV */
   ret = RAND_bytes((unsigned char*)&iv[0], iv_size);
   if(ret != 1){
      cerr << "Error: RAND_bytes failed\n";
      exit(1);
   }

   return iv;

}

/* Encrypt the text in f_in and writes it in f_out */
void encrypt(FILE *f_in, FILE *f_out, int size, unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, unsigned char *iv) {

   int ret, read, written;

   /* Create and initialise the context */
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
   if(!ctx) {
     cerr << "Error: EVP_CIPHER_CTX_new returns NULL\n";
     exit(1);
   }

   /* Encrypt init, it must be done only once */
   ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);
   if(!ret) {
     cerr << "Error: EVP_EncryptInit failed\n";
     exit(1);
   }

   /* Loop where text is read from f_in, encrypted and written into f_out */
   for(read = fread(plaintext, 1, size , f_in); read > 0; read = fread(plaintext, 1, size, f_in)) {
      /* Encrypt that bytes */
      ret = EVP_EncryptUpdate(ctx, ciphertext, &written, plaintext, read);
      if(!ret) {
         cerr << "Error: EVP_EncryptUpdate failed\n";
         exit(1);
      }

      /* Write ciphertext to file */
      fwrite(ciphertext, 1, written, f_out);
   }

   if (!feof(f_in)) {
      cerr << "Error: while reading in encrypt function\n";
      exit(EXIT_FAILURE);
   }

   /* Encrypt Final, finalize the encryption and adds the padding */
   ret = EVP_EncryptFinal(ctx, ciphertext, &written);
   if(!ret) {
     cerr << "Error: EVP_EncryptFinal failed\n";
     exit(1);
   }

   ret = fwrite(ciphertext, 1, written, f_out);
   if(ret < written) {
      cerr << "Error: while writing the ciphertext in encrypt function\n";
      exit(1);
   }   

   /* MUST ALWAYS BE CALLED!!!!!!!!!!
    * EVP_CIPHER_CTX_new calls a malloc under the hood, moreover the context contains the key, which tracks should be removed once used.
    */
   EVP_CIPHER_CTX_free(ctx);

}

/* Remember to compile the code using the flag -lcrypto */
int main() {

   int ret;
   int block_size = EVP_CIPHER_block_size(EVP_aes_128_cbc());
   int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

   /* Open files */
   FILE* f_in = fopen("file.txt", "rb");
   FILE* f_out = fopen("file.txt.enc", "wb");

   if(!f_in) {
      cerr << "Error: cannot open file 'file.txt' \n";
      exit(1);
   }

   if(!f_out) {
      cerr << "Error: cannot open file 'file.txt.enc' \n";
      exit(1);
   }

   /* Get the size of the file */
   fseek(f_in, 0, SEEK_END);
   long int size = ftell(f_in);
   if(size > INT_MAX - block_size) {
      cerr << "Error: integer overflow\n";
      exit(1);
   }
   fseek(f_in, 0, SEEK_SET);

   /* Allocate buffer for plaintext and ciphertext */
   unsigned char* plaintext = (unsigned char*)malloc(size);
   if(!plaintext) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

   unsigned char* ciphertext = (unsigned char*)malloc(size + block_size);
   if(!ciphertext) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

   /* Key and IV generation */
   unsigned char *key = (unsigned char *)"0123456789012345"; /* ASSUMPTION FOR NOW: key is hardcoded (not good in general) */
   unsigned char *iv = generate_iv(iv_len);
   
   /* Write the IV */
   ret = fwrite(iv, 1, iv_len, f_out); 
   if(ret < iv_len) {
      cerr << "Error: while writing the IV \n";
      exit(1);
   }

   encrypt(f_in, f_out, size, ciphertext, plaintext, key, iv);

   cout << "File 'file.txt' encrypted into file 'file.txt.enc' \n"; 

/* Disable the compiler optimization to make sure the compiler won't skip memset instruction, which could be skipped due to the following free */
#pragma optimize("", off)
   memset(iv, 0, iv_len);
   memset(plaintext, 0, size);
   memset(ciphertext, 0, (size + block_size));
#pragma optimize("", on)
   free(iv);
   free(plaintext);
   free(ciphertext);

   fclose(f_in);
   fclose(f_out);

   return 0;
}
