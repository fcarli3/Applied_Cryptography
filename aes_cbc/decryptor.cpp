#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

//Remember to compile the code using the flag -lcrypto
int main() {

   int ret;
   
   /* Declare some useful variables, that way I will able in the future to change cipher just changing the specific var */
   const EVP_CIPHER* cipher = EVP_aes_128_cbc();
   int iv_len = EVP_CIPHER_iv_length(cipher);
   int block_size = EVP_CIPHER_block_size(cipher);
   EVP_CIPHER_CTX *ctx; //context
   int update_len = 0; /* bytes decrypted at each cycle of EVP_DecryptUpdate */
   int total_len = 0; /* total bytes decrypted */
   
   /* Key --> ASSUMPTION FOR NOW: key is hardcoded (not good in general) */
   unsigned char *key = (unsigned char *)"0123456789012345"; 

   /* Read IV and ciphertext from file */
   string ct_filename = "file.txt.enc";

   /* Open the file to encrypt */
   FILE* ct_file = fopen(ct_filename.c_str(), "rb");
   if(!ct_file) {
      cerr << "Error: cannot open file '" << ct_file << " \n";
      exit(1);
   }

   /* Get the size of the file */
   fseek(ct_file, 0, SEEK_END);
   long int size = ftell(ct_file);
   long int ct_size = size - iv_len;
   fseek(ct_file, 0, SEEK_SET);

   /* Read the IV and the ciphertext from the file */
   unsigned char* iv = (unsigned char*)malloc(iv_len);
   unsigned char* ciphertext = (unsigned char*)malloc(ct_size);
   if(!iv) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }
   if(!ciphertext) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }
   ret = fread(iv, 1, iv_len, ct_file); /* read IV */
   if(ret < iv_len) {
      cerr << "Error: while reading IV from file '" << ct_filename << "'\n";
      exit(1);
   }
   ret = fread(ciphertext, 1, ct_size, ct_file); /* read ciphertext */
   if(ret < (size - iv_len)) {
      cerr << "Error: while reading ct from file '" << ct_filename << "'\n";
      exit(1);
   }
   fclose(ct_file);

   /* Allocate a buffer for the plaintext */
   unsigned char* plaintext = (unsigned char*)malloc(ct_size);
   if(!plaintext){
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  if(!ctx) {
     cerr << "Error: EVP_CIPHER_CTX_new returns NULL\n";
     exit(1);
  }

  /* Decrypt init, it must be done only once */
  ret = EVP_DecryptInit(ctx, cipher, key, iv);
  if(!ret) {
     cerr << "Error: EVP_DecryptInit failed\n";
     exit(1);
  }

  /* Decrypt Update: in this case one call is enough because our message is very short. */
  ret = EVP_DecryptUpdate(ctx, plaintext, &update_len, ciphertext, ct_size);
  if(!ret) {
     cerr << "Error: EVP_DecryptUpdate failed\n";
     exit(1);
  }
  total_len += update_len;

  /* Decrypt Final */
  ret = EVP_DecryptFinal(ctx, plaintext + total_len, &update_len);
  if(!ret) {
     cerr << "Error: EVP_DecryptFinal failed\n";
     exit(1);
  }
  total_len += update_len;
  int pt_size = total_len; /* size of the plaintext */

  /* MUST ALWAYS BE CALLED!!!!!!!!!!
   * EVP_CIPHER_CTX_new calls a malloc under the hood, moreover the context contains the key, which tracks should be removed once used.
   */
  EVP_CIPHER_CTX_free(ctx);

/* Disable the compiler optimization to make sure the compiler won't skip memset instruction, which could be skipped due to the following free */
#pragma optimize("", off)
   memset(ciphertext, 0, ct_size);
#pragma optimize("", on)
   free(ciphertext);

   /* File to write the plaintext */
   string pt_filename = ct_filename + ".dec";

   /* Open the file to write the plaintext */
   FILE* pt_file = fopen(pt_filename.c_str(), "wb");
   if(!pt_file) {
      cerr << "Error: cannot open file '" << pt_filename << " \n";
      exit(1);
   }

   /* Write the plaintext */
   ret = fwrite(plaintext, 1, ct_size, pt_file); 
   if(ret < ct_size) {
      cerr << "Error: while writing the plaintext to file '" << pt_filename << "' \n";
      exit(1);
   }

   fclose(pt_file);

   cout << "File '" << ct_filename << "' decrypted into file '" << pt_filename << "' \n"; 

   free(plaintext);
   free(iv); 

   return 0;
}
