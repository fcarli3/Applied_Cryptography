#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

void decrypt(FILE *f_in, FILE *f_out, int size, unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key, unsigned char *iv) {

   int ret, read, written;

   /* Create and initialise the context */
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
   if(!ctx) {
     cerr << "Error: EVP_CIPHER_CTX_new returns NULL\n";
     exit(1);
   }

   /* Decrypt init, it must be done only once */
   ret = EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);
   if(!ret) {
     cerr << "Error: EVP_DecryptInit failed\n";
     exit(1);
   }

   /* Loop where text is read from f_in, decrypted and written into f_out */
   for(read = fread(ciphertext, 1, size , f_in); read > 0; read = fread(ciphertext, 1, size, f_in)) {
      /* Decrypt that bytes */
      ret = EVP_DecryptUpdate(ctx, plaintext, &written, ciphertext, read);
      if(!ret) {
         cerr << "Error: EVP_DecryptUpdate failed\n";
         exit(1);
      }

      /* Write plaintext to file */
      fwrite(plaintext, 1, written, f_out);
   }

   if (!feof(f_in)) {
      cerr << "Error: while reading in decrypt function\n";
      exit(EXIT_FAILURE);
   }

   /* Decrypt Final, finalize the decryption and removes the padding */
   ret = EVP_DecryptFinal(ctx, plaintext, &written);
   if(!ret) {
     cerr << "Error: EVP_DecryptFinal failed\n";
     exit(1);
   }

   ret = fwrite(plaintext, 1, written, f_out);
   if(ret < written) {
      cerr << "Error: while writing the plaintext in decrypt function\n";
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
   FILE* f_in = fopen("file.txt.enc", "rb");
   FILE* f_out = fopen("file.txt.enc.dec", "wb");

   if(!f_in) {
      cerr << "Error: cannot open file 'file.txt.enc' \n";
      exit(1);
   }

   if(!f_out) {
      cerr << "Error: cannot open file 'file.txt.enc.dec' \n";
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

   /* Allocate buffer for ciphertext, IV and plaintext */
   unsigned char* ciphertext = (unsigned char*)malloc(size);
   if(!ciphertext) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

   unsigned char* iv = (unsigned char*)malloc(iv_len);
   if(!iv) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

   unsigned char* plaintext = (unsigned char*)malloc(size);
   if(!plaintext) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

   /* Key */
   unsigned char *key = (unsigned char *)"0123456789012345"; /* ASSUMPTION FOR NOW: key is hardcoded (not good in general) */
   
   /* Read the IV */
   ret = fread(iv, 1, iv_len, f_in); 
   if(ret < iv_len) {
      cerr << "Error: while reading the IV \n";
      exit(1);
   }

   decrypt(f_in, f_out, size, ciphertext, plaintext, key, iv);

   cout << "File 'file.txt.enc' decrypted into file 'file.txt.enc.dec' \n"; 

/* Disable the compiler optimization to make sure the compiler won't skip memset instruction, which could be skipped due to the following free */
#pragma optimize("", off)
   memset(iv, 0, iv_len);
   memset(plaintext, 0, size);
   memset(ciphertext, 0, size);
#pragma optimize("", on)
   free(iv);
   free(plaintext);
   free(ciphertext);

   fclose(f_in);
   fclose(f_out);

   return 0;
}

