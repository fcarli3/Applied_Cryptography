#include <iostream> 
#include <fstream>
#include <string>
#include <stdlib.h>
#include <stdio.h> 
#include <limits.h> 
#include <string.h> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
using namespace std;


int main() {

    int ret;
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int block_size = EVP_CIPHER_block_size(cipher);
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int outlen = 0; /* bytes encrypted at each chunk */
    int cipherlen = 0; /* total encrypted bytes */

    /* Reading the public key from .pem file */
    EVP_PKEY* pubkey;
    FILE* f_pubkey = fopen("public_key.pem", "r");

    if(!f_pubkey) {
        cerr << "Error: cannot open file 'public_key.pem' \n";
        exit(1);
    }

    pubkey = PEM_read_PUBKEY(f_pubkey, NULL, NULL, NULL);

    if(!pubkey) {
        cerr << "Error: read of the public key from file 'public_key.pem' \n";
        exit(1);
    }

    /* Open plaintext file and ciphertext file */
    FILE* f_plaintext = fopen("plaintext.txt", "rb");
    FILE* f_out = fopen("ciphertext.txt", "wb");

    if(!f_plaintext) {
        cerr << "Error: cannot open file 'plaintext.txt' \n";
        exit(1);
    }

    if(!f_out) {
        cerr << "Error: cannot open file 'ciphertext.txt' \n";
        exit(1);
    }

    /* Get the size of the file 'plaintext.txt' */
    fseek(f_plaintext, 0, SEEK_END);
    long int pt_size = ftell(f_plaintext);
    if(pt_size > INT_MAX - block_size) {
      cerr << "Error: integer overflow\n";
      exit(1);
    }
    fseek(f_plaintext, 0, SEEK_SET);

    /* Allocate buffer for IV that will be generated in the encryption process */
    unsigned char *iv = (unsigned char*)malloc(iv_len);

    /* Allocate buffer for encrypted simmetric key that will be generated in the encryption process */
    int encrypted_key_len = EVP_PKEY_size(pubkey);
    unsigned char* encrypted_key_buf = (unsigned char*)malloc(encrypted_key_len);

    /* Allocate buffer for plaintext and ciphertext */
    unsigned char* pt_buf = (unsigned char*)malloc(pt_size);
    if(!pt_buf) {
        cerr << "Error: malloc returned NULL\n";
        exit(1);
    }

    unsigned char* ct_buf = (unsigned char*)malloc(pt_size + block_size);
    if(!ct_buf) {
        cerr << "Error: malloc returned NULL\n";
        exit(1);
    }

    /* Reading plaintext from file 'plaintext.txt' */
    ret = fread(pt_buf, 1, pt_size, f_plaintext); 
    if(ret < pt_size) {
        cerr << "Error: while reading file 'plaintext.txt'\n";
        exit(1);
    }

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
    if(!ctx) {
        cerr << "Error: EVP_CIPHER_CTX_new returns NULL\n";
        exit(1);
    }

    /* Generate the IV and the symmetric key and encrypt the symmetric key */ 
    ret = EVP_SealInit(ctx, cipher, &encrypted_key_buf, &encrypted_key_len, iv, &pubkey, 1);
    if(ret <= 0) {
        cerr << "Error: EVP_SealInit returns " << ret << "\n";
        exit(1);
    }

    /* Encrypt the plaintext */
    ret = EVP_SealUpdate(ctx, ct_buf, &outlen, (unsigned char*)pt_buf, pt_size);
    if(ret == 0) {
        cerr << "Error: EVP_SealUpdate returns " << ret << "\n";
        exit(1);
    }
    cipherlen = outlen;

    ret = EVP_SealFinal(ctx, ct_buf + cipherlen, &outlen);
    if(ret == 0) {
        cerr << "Error: EVP_SealFinal returns " << ret << "\n";
        exit(1);
    }
    cipherlen += outlen;
    int ct_size = cipherlen;

    EVP_CIPHER_CTX_free(ctx);

    /* Write encrypted symmetric key, iv and ciphertext into 'ciphertext.txt' file */
    ret = fwrite(encrypted_key_buf, 1, encrypted_key_len, f_out); /* write the encrypted symmetric key */
    if(ret < encrypted_key_len) {
        cerr << "Error: while writing the encrypted symmetric key\n";
        exit(1);
    }

    ret = fwrite(iv, 1, iv_len, f_out); /* write the IV */
    if(ret < iv_len) {
        cerr << "Error: while writing the IV\n";
        exit(1);
    }

    ret = fwrite(ct_buf, 1, ct_size, f_out); /* write the ciphertext */
    if(ret < ct_size) {
        cerr << "Error: while writing the ciphertext\n";
        exit(1);
    }

    cout << "File 'plaintext.txt' is encrypted into file 'ciphertext.txt' \n"; 

/* Disable the compiler optimization to make sure the compiler won't skip memset instruction, which could be skipped due to the following free */
#pragma optimize("", off)
    memset(iv, 0, iv_len);
    memset(pt_buf, 0, pt_size);
    memset(ct_buf, 0, ct_size);
#pragma optimize("", on)
    free(iv);
    free(pt_buf);
    free(ct_buf);

    /* Close files */
    fclose(f_plaintext);
    fclose(f_pubkey);
    fclose(f_out);

    return 0;

}
