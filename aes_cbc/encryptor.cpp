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

//Remember to compile the code using the flag -lcrypto
int main() {

   int ret;

   /* Read plaintext from file */
   string filename = "file.txt";

   /* Open the file to encrypt */
   FILE* file = fopen(filename.c_str(), "rb");
   if(!file) {
      cerr << "Error: cannot open file '" << filename << " \n";
      exit(1);
   }

   /* Get the size of the file */
   fseek(file, 0, SEEK_END);
   long int size = ftell(file);
   fseek(file, 0, SEEK_SET);

   /* Read the plaintext from the file */
   unsigned char* buf = (unsigned char*)malloc(size);
   if(!buf) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }
   ret = fread(buf, 1, size, file);
   if(ret < size) {
      cerr << "Error: while reading file '" << filename << "'\n";
      exit(1);
   }
   fclose(file);

   /* Declare some useful variables, that way I will able in the future to change cipher just changing the specific var */
   const EVP_CIPHER* cipher = EVP_aes_128_cbc();
   int iv_len = EVP_CIPHER_iv_length(cipher);
   int block_size = EVP_CIPHER_block_size(cipher);

   EVP_CIPHER_CTX *ctx; //context
   int update_len = 0; /* bytes encrypted at each cycle of EVP_EncryptUpdate */
   int total_len = 0; /* total bytes encrypted */

   /* Key and IV generation */
   unsigned char *key = (unsigned char *)"0123456789012345"; /* ASSUMPTION FOR NOW: key is hardcoded (not good in general) */
   unsigned char *iv = (unsigned char *)malloc(iv_len);

   /* Seed OpenSSL PRNG */
   RAND_poll();

   /* Generates 16 random bytes for my IV */
   ret = RAND_bytes((unsigned char*)&iv[0], iv_len);
   if(ret != 1){
      cerr << "Error: RAND_bytes failed\n";
      exit(1);
   }

   if(size > INT_MAX - block_size) {
      cerr << "Error: integer overflow\n";
      exit(1);
   }

   /* Allocate a buffer for the ciphertext */
   int enc_buffer_size = size + block_size;
   unsigned char* cipher_buf = (unsigned char*)malloc(enc_buffer_size);
   if(!cipher_buf){
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  if(!ctx) {
     cerr << "Error: EVP_CIPHER_CTX_new returns NULL\n";
     exit(1);
  }

  /* Encrypt init, it must be done only once */
  ret = EVP_EncryptInit(ctx, cipher, key, iv);
  if(!ret) {
     cerr << "Error: EVP_EncryptInit failed\n";
     exit(1);
  }

  /* Encrypt Update: in this case one call is enough because our message is very short. */
  ret = EVP_EncryptUpdate(ctx, cipher_buf, &update_len, buf, size);
  if(!ret) {
     cerr << "Error: EVP_EncryptUpdate failed\n";
     exit(1);
  }
  total_len += update_len;

  /* Encrypt Final. Finalize the encryption and adds the padding */
  ret = EVP_EncryptFinal(ctx, cipher_buf + total_len, &update_len);
  if(!ret) {
     cerr << "Error: EVP_EncryptFinal failed\n";
     exit(1);
  }
  total_len += update_len;
  int cipher_size = total_len; /* size of the ciphertext */

  /* MUST ALWAYS BE CALLED!!!!!!!!!!
   * EVP_CIPHER_CTX_new calls a malloc under the hood, moreover the context contains the key, which tracks should be removed once used.
   */
  EVP_CIPHER_CTX_free(ctx);

/* Disable the compiler optimization to make sure the compiler won't skip memset instruction, which could be skipped due to the following free */
#pragma optimize("", off)
   memset(buf, 0, size);
#pragma optimize("", on)
   free(buf);

   /* File to write the ciphertext and the IV */
   string cipher_filename = filename + ".enc";

   /* Open the file to write the ciphertext and IV */
   FILE* cipher_file = fopen(cipher_filename.c_str(), "wb");
   if(!cipher_file) {
      cerr << "Error: cannot open file '" << cipher_filename << " \n";
      exit(1);
   }

   /* Write the IV */
   ret = fwrite(iv, 1, iv_len, cipher_file); 
   if(ret < iv_len) {
      cerr << "Error: while writing the IV to file '" << cipher_filename << "' \n";
      exit(1);
   }

   /* Write the ciphertext */
   ret = fwrite(cipher_buf, 1, cipher_size, cipher_file); 
   if(ret < cipher_size) {
      cerr << "Error: while writing the ciphertext to file '" << cipher_filename << "' \n";
      exit(1);
   }

   fclose(cipher_file);

   cout << "File '" << filename << "' encrypted into file '" << cipher_filename << "' \n"; 

   free(cipher_buf);
   free(iv);

   return 0;
}
