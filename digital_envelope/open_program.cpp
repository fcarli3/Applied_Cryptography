#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
using namespace std;


int main() {

   int ret;
   const EVP_CIPHER* cipher = EVP_aes_128_cbc();
   int block_size = EVP_CIPHER_block_size(cipher);
   int iv_len = EVP_CIPHER_iv_length(cipher);
   int outlen = 0; /* bytes decrypted at each chunk */
   int ptlen = 0; /* total decrypted bytes */


   /* Reading the private key from .pem file */
   EVP_PKEY* privkey;
   FILE* f_privkey = fopen("private_key.pem", "r");

   if(!f_privkey) {
      cerr << "Error: cannot open file 'private_key.pem' \n";
      exit(1);
   }

   privkey = PEM_read_PrivateKey(f_privkey, NULL, NULL, NULL);

   if(!privkey) {
      cerr << "Error: read of the private key from file 'private_key.pem' \n";
      exit(1);
   }

   /* Open files */
   FILE* f_ct = fopen("ciphertext.txt", "rb");
   FILE* f_pt = fopen("decrypted_text.txt", "wb");

   if(!f_ct) {
      cerr << "Error: cannot open file 'ciphertext.txt' \n";
      exit(1);
   }

   if(!f_pt) {
      cerr << "Error: cannot open file 'decrypted_text.txt' \n";
      exit(1);
   }

   /* Get the size of the file 'ciphertext.txt' */
   fseek(f_ct, 0, SEEK_END);
   long int size = ftell(f_ct);
   if(size > INT_MAX - block_size) {
      cerr << "Error: integer overflow\n";
      exit(1);
   }
   fseek(f_ct, 0, SEEK_SET);

   /* Allocate buffer for ciphertext, IV, encrypted symmetric key and plaintext */
   int encrypted_key_len = EVP_PKEY_size(privkey);
   unsigned char* encrypted_key_buf = (unsigned char*)malloc(encrypted_key_len);
   int size_ct = size - encrypted_key_len - iv_len;

   unsigned char* ct_buf = (unsigned char*)malloc(size_ct);
   if(!ct_buf) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

   unsigned char* iv = (unsigned char*)malloc(iv_len);
   if(!iv) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

   unsigned char* pt_buf = (unsigned char*)malloc(size_ct);
   if(!pt_buf) {
      cerr << "Error: malloc returned NULL\n";
      exit(1);
   }

   /* Read the encrypted symmetric key */
   ret = fread(encrypted_key_buf, 1, encrypted_key_len, f_ct); 
   if(ret < encrypted_key_len) {
      cerr << "Error: while reading the encrypted symmetric key\n";
      exit(1);
   }
   
   /* Read the IV */
   ret = fread(iv, 1, iv_len, f_ct); 
   if(ret < iv_len) {
      cerr << "Error: while reading the IV \n";
      exit(1);
   }

   /* Reading ciphertext from file 'ciphertext.txt' */
   ret = fread(ct_buf, 1, size_ct, f_ct); 
   if(ret < size_ct) {
      cerr << "Error: while reading the ciphertext\n";
      exit(1);
   }

   /* Create and initialise the context */
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
   if(!ctx) {
      cerr << "Error: EVP_CIPHER_CTX_new returns NULL\n";
      exit(1);
   }

   /* Decrypt the ciphertext and the symmetric key */ 
   ret = EVP_OpenInit(ctx, cipher, encrypted_key_buf, encrypted_key_len, iv, privkey);
   if(ret == 0) {
      cerr << "Error: EVP_OpenInit returns " << ret << "\n";
      exit(1);
   }

   ret = EVP_OpenUpdate(ctx, pt_buf, &outlen, ct_buf, size_ct);
   if(ret == 0) {
      cerr << "Error: EVP_OpenUpdate returns " << ret << "\n";
      exit(1);
   }
   ptlen += outlen;

   ret = EVP_OpenFinal(ctx, pt_buf + ptlen, &outlen);
   if(ret == 0) {
      cerr << "Error: EVP_OpenFinal returns " << ret << "\n";
      exit(1);
   }
   ptlen += outlen;
   int pt_size = ptlen;

   EVP_CIPHER_CTX_free(ctx);
   EVP_PKEY_free(privkey);

   /* Writing the plaintext into 'decrypted_text.txt' file */
   ret = fwrite(pt_buf, 1, pt_size, f_pt); 
   if(ret < pt_size) {
      cerr << "Error: while writing the plaintext\n";
      exit(1);
   }

   cout << "File 'ciphertext.txt' decrypted into file 'decrypted_text.txt' \n"; 

/* Disable the compiler optimization to make sure the compiler won't skip memset instruction, which could be skipped due to the following free */
#pragma optimize("", off)
   memset(iv, 0, iv_len);
   memset(pt_buf, 0, pt_size);
   memset(ct_buf, 0, size_ct);
#pragma optimize("", on)
   free(iv);
   free(pt_buf);
   free(ct_buf);

   fclose(f_ct);
   fclose(f_pt);
   fclose(f_privkey);

   return 0;
}

