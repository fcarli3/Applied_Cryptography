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
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
using namespace std;


int main() {

    int ret;

    /* LOAD THE CA'S CERTIFICATE */
    FILE* f_cert = fopen("CA_certificate", "r");
    if(!f_cert) {
        cerr << "ERROR: while open the CA's certificate \n";
        exit(1);
    }

    X509* ca_cert = PEM_read_X509(f_cert, NULL, NULL, NULL);
    if(!ca_cert) {
        cerr << "ERROR: PEM_read_X509 of CA's certificate fails!\n";
        fclose(f_cert);
        exit(1);
    }

    fclose(f_cert);

    /* ******************************* */

    /* LOAD THE CERTIFICATE REVOCATION LIST */
    FILE* f_crl = fopen("CA_crl", "r");
    if(!f_crl) {
        cerr << "ERROR: while open the CA's CRL \n";
        exit(1);
    }

    X509_CRL* crl = PEM_read_X509_CRL(f_crl, NULL, NULL, NULL);
    if(!crl) {
        cerr << "ERROR: PEM_read_X509_CRL fails!\n";
        fclose(f_crl);
        exit(1);
    }

    fclose(f_crl);

    /* ********************************* */

    /* BUILD THE STORE OF THE CLIENT */
    X509_STORE* store = X509_STORE_new();
    if(!store) {
        cerr << "ERROR: X509_STORE_new fails!\n";
        X509_STORE_free(store);
        exit(1);
    }

    ret = X509_STORE_add_cert(store, ca_cert); /* add the certificate to the store */
    if(ret != 1) {
        cerr << "ERROR: X509_STORE_add_cert fails!\n";
        X509_STORE_free(store);
        exit(1);
    }

    ret = X509_STORE_add_crl(store, crl); /* add the CRL to the store */
    if(ret != 1) {
        cerr << "ERROR: X509_STORE_add_crl fails!\n";
        X509_STORE_free(store);
        exit(1);
    }

    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK); /* tells the store to use the CRL */

    /* ********************************* */

    /* LOAD THE SERVER'S CERTIFICATE */
    FILE* f_server_cert = fopen("server_certificate", "r");
    if(!f_server_cert) {
        cerr << "ERROR: while open the server's certificate \n";
        exit(1);
    }

    X509* srv_cert = PEM_read_X509(f_server_cert, NULL, NULL, NULL);
    if(!ca_cert) {
        cerr << "ERROR: PEM_read_X509 of server's certificate fails!\n";
        fclose(f_server_cert);
        exit(1);
    }

    fclose(f_server_cert);

    /* ********************************* */

    /* VERIFIY THE SERVER'S CERTIFICATE INSIDE THE STORE */
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if(!ctx) {
        cerr << "ERROR: X509_STORE_CTX_new fails!";
        exit(1);
    }

    ret = X509_STORE_CTX_init(ctx, store, srv_cert, NULL);
    if(ret != 1) {
        cerr << "ERROR: X509_STORE_CTX_init fails!\n";
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        exit(1);
    }

    ret = X509_verify_cert(ctx);
    if(ret == 0) {
        cout << "ERROR: the certificate can't be verified!\n";
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        exit(1);
    } else if (ret < 0) {
        cerr << "ERROR: X509_verify_cert fails!\n";
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        exit(1);
    } else {
        cout << "The certificate has been verified successfully!\n";
    }

    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);

    /* ********************************* */

    /* PARSING THE SERVER'S CERTIFICATE */
    X509_NAME* subject_name = X509_get_subject_name(srv_cert); /* subject name */
    X509_NAME* issuer_name = X509_get_issuer_name(srv_cert); /* issuer name (CA) */

    char* str_subject = X509_NAME_oneline(subject_name, NULL, 0);
    char* str_issuer = X509_NAME_oneline(issuer_name, NULL, 0);

    cout << "\nSUBJECT: " << str_subject << "\n";
    cout << "\nCERTIFICATION AUTHORITY: " << str_issuer << "\n";

    free(subject_name);
    free(issuer_name);

    /* ********************************* */

    /* OPEN FILES AND READ THE TEXT AND THE SIGNATURE TO VERIFY */
    FILE* f_txt = fopen("./../server/file.txt", "rb");
    if(!f_txt) {
        cerr << "ERROR: cannot open file 'file.txt' \n";
        fclose(f_txt);
        exit(1);
    }

    /* Get the size of the file */
    fseek(f_txt, 0, SEEK_END);
    long int file_size = ftell(f_txt);
    fseek(f_txt, 0, SEEK_SET);

    /* Allocate buffer for the text of the file */
    unsigned char* buff = (unsigned char*)malloc(file_size);
    if(!buff) {
        cerr << "ERROR: malloc of buff returns NULL\n";
        exit(1);
    }

    ret = fread(buff, 1, file_size, f_txt); 
    if(ret < file_size) {
        cerr << "ERROR: while reading file 'file.txt'\n";
        exit(1);
    }

    fclose(f_txt);

    FILE* f_sign = fopen("./../server/file.txt.sgn", "rb");
    if(!f_sign) {
        cerr << "ERROR: cannot open file 'file.txt.sgn' \n";
        fclose(f_sign);
        exit(1);
    }

    /* Get the size of the signature to verify */
    fseek(f_sign, 0, SEEK_END);
    long int sign_size = ftell(f_sign);
    fseek(f_sign, 0, SEEK_SET);

    /* Allocate buffer for the signature to verify */
    unsigned char* sign_buf = (unsigned char*)malloc(sign_size);
    if(!sign_buf) {
        cerr << "ERROR: malloc of sign_buf returns NULL\n";
        exit(1);
    }

    ret = fread(sign_buf, 1, sign_size, f_sign); 
    if(ret < sign_size) {
        cerr << "ERROR: while reading file 'file.txt.sgn'\n";
        exit(1);
    }

    cout << "\nSignature to verify: \n";
    BIO_dump_fp(stdout, (const char*)sign_buf, sign_size);

    fclose(f_sign);

    /* ***************************************** */

    /* GET THE PUBLIC KEY OF THE SERVER FROM ITS CERTIFICATE */
    EVP_PKEY* server_public_key = X509_get_pubkey(srv_cert);
    if(!server_public_key) {
        cerr << "ERROR: X509_get_pubkey fails!";
        exit(1);
    }

    /* ****************************************** */

    /* VERIFY THE SIGNATURE */

    /* Create the context for verifying the digital signature */
    EVP_MD_CTX* verify_ctx = EVP_MD_CTX_new();
    if(!ctx) {
        cerr << "ERROR: EVP_MD_CTX_new fails!\n";
        exit(1);
    }

    /* Initialize the context for verifying the digital signature */ 
    ret = EVP_VerifyInit(verify_ctx, EVP_sha256());
    if(ret == 0){
        cerr << "ERROR: EVP_VerifyInit fails!\n";
        EVP_MD_CTX_free(verify_ctx);
        exit(1);
    }

    /* Update the context */
    ret = EVP_VerifyUpdate(verify_ctx, (unsigned char*)buff, file_size); 
    if(ret == 0){
        cerr << "ERROR: EVP_VerifyUpdate fails!\n";
        EVP_MD_CTX_free(verify_ctx);
        exit(1);
    }

    /* Finalize the context and verify the signature */
    ret = EVP_VerifyFinal(verify_ctx, sign_buf, sign_size, server_public_key);
    if(ret == 0){
        cout << "\nVERIFICATION OF THE SIGNATURE IS FAILED!\n";
    } else if(ret == 1){
        cout << "\nVERIFICATION OF THE SIGNATURE IS OK!\n";
    } else if (ret == -1) {
        cout << "ERROR: EVP_VerifyFinal fails!";
    }

    EVP_MD_CTX_free(verify_ctx);

    /* ********************************* */

    return 0;
}