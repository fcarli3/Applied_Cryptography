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

    /* READING THE PRIVATE KEY FROM .pem FILE */
    EVP_PKEY* private_key;
    FILE* f_privkey = fopen("server_private_key", "r");

    if(!f_privkey) {
        cerr << "ERROR: cannot open file 'server_private_key' \n";
        exit(1);
    }

    private_key = PEM_read_PrivateKey(f_privkey, NULL, NULL, NULL);

    if(!private_key) {
        cerr << "ERROR: read of the private key from file 'server_private_key' \n";
        exit(1);
    }

    /* ************************************************** */

    /* OPEN AND READ THE FILE TO SIGN */
    FILE* file_to_sign = fopen("file.txt", "rb");

    if(!file_to_sign) {
        cerr << "ERROR: cannot open file 'file.txt' \n";
        exit(1);
    }

    /* Get the size of the file */
    fseek(file_to_sign, 0, SEEK_END);
    long int file_size = ftell(file_to_sign);
    fseek(file_to_sign, 0, SEEK_SET);

    /* Allocate buffer for the text of the file */
    unsigned char* buff = (unsigned char*)malloc(file_size);
    if(!buff) {
        cerr << "ERROR: malloc of buff returns NULL\n";
        exit(1);
    }

    ret = fread(buff, 1, file_size, file_to_sign); 
    if(ret < file_size) {
        cerr << "ERROR: while reading file 'file.txt'\n";
        exit(1);
    }

    /* ************************************************** */


    /* SIGNING THE FILE */
    unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(private_key));
    unsigned int signature_len;

    /* Create the context for digital signature */
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx) {
        cerr << "ERROR: EVP_MD_CTX_new fails!\n";
        exit(1);
    }

    /* Initialize the context for digital signature */ 
    ret = EVP_SignInit(ctx, EVP_sha256());
    if(ret == 0){
        cerr << "ERROR: EVP_SignInit fails!\n";
        exit(1);
    }

    /* Update the context */
    ret = EVP_SignUpdate(ctx, (unsigned char*)buff, sizeof(buff)); 
    if(ret == 0){
        cerr << "ERROR: EVP_SignUpdate fails!\n";
        exit(1);
    }

    /* Finalize the context and compute the signature */
    ret = EVP_SignFinal(ctx, signature, &(signature_len), private_key);
    if(ret == 0){
        cerr << "ERROR: EVP_SignFinal fails!\n";
        exit(1);
    }

    cout << "\nSignature: \n";
    BIO_dump_fp(stdout, (const char*)signature, signature_len);
    cout << "\nSignature size: " << signature_len << "\n";

    /* Delete the context and the private key */
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(private_key);

    /* ************************************************** */

    /* WRITE THE SIGNATURE IN A FILE */
    FILE* f_out = fopen("file.txt.sgn", "wb");

    if(!f_out) {
        cerr << "ERROR: cannot open file 'file.txt.sgn' \n";
        exit(1);
    }

    ret = fwrite(signature, 1, signature_len, f_out); /* write the signature */
    if(ret < signature_len) {
        cerr << "ERROR: while writing the signature\n";
        exit(1);
    }

    cout << "\nThe signature of file 'file.txt' is written into file 'file.txt.sgn' \n"; 

    return 0;
}