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

/* Function that generates DH parameters p and g */
static DH *get_dh2048(void) {

    static unsigned char dhp_2048[] = {
        0x8F, 0x5B, 0x18, 0x02, 0x65, 0xD4, 0x0D, 0x32, 0x65, 0xFD,
        0x54, 0x6E, 0x74, 0x88, 0xBD, 0xFF, 0x57, 0x47, 0x51, 0x89,
        0x6B, 0x3F, 0x6C, 0x24, 0xEF, 0x45, 0x63, 0x45, 0xDC, 0x6F,
        0x33, 0x9B, 0x26, 0xCE, 0x98, 0xCE, 0xE9, 0xE2, 0x20, 0x9C,
        0x9E, 0xA3, 0x83, 0xB9, 0x15, 0x05, 0x3E, 0xAD, 0x80, 0x3B,
        0x39, 0xBA, 0x90, 0x99, 0xF5, 0x02, 0x38, 0xD8, 0xDE, 0x59,
        0x7A, 0xA8, 0x33, 0x0F, 0xB5, 0x5B, 0x77, 0x18, 0xA5, 0x9F,
        0x9F, 0xFC, 0x73, 0x1F, 0x91, 0x7C, 0x5B, 0xEA, 0x45, 0xCD,
        0xAC, 0xF4, 0x79, 0x84, 0xC7, 0xD1, 0x5B, 0xFB, 0xC5, 0x95,
        0xCC, 0x27, 0xFB, 0xC9, 0xA2, 0xA7, 0x51, 0xD2, 0x9B, 0x72,
        0xF5, 0x08, 0xA6, 0x04, 0xD8, 0x43, 0x6B, 0x80, 0x5A, 0x96,
        0x31, 0xE5, 0x83, 0x9F, 0x98, 0x97, 0x9C, 0x2C, 0xCB, 0x6A,
        0x71, 0xC3, 0x94, 0x23, 0x50, 0x9A, 0x61, 0xF9, 0x45, 0xAF,
        0xD5, 0x67, 0xCD, 0x40, 0x52, 0x68, 0x0D, 0x3E, 0xE4, 0xA4,
        0xA6, 0xF2, 0xE4, 0x30, 0x4E, 0x79, 0xA2, 0x0B, 0xB7, 0x3A,
        0xFA, 0x0A, 0xA7, 0x73, 0xFF, 0x6F, 0x21, 0x8A, 0xE2, 0x81,
        0x2B, 0x4C, 0xC6, 0xDB, 0x67, 0xF1, 0x19, 0xD8, 0x9A, 0xEB,
        0x87, 0x1A, 0xE0, 0x7E, 0xA6, 0x09, 0xE8, 0xB3, 0x27, 0x10,
        0xBA, 0x90, 0x25, 0xA9, 0x5D, 0x54, 0xFE, 0x97, 0x90, 0x00,
        0xA2, 0xFD, 0x4B, 0xEF, 0x45, 0x87, 0xD3, 0xCC, 0xC7, 0xD2,
        0x2D, 0xED, 0xD4, 0xBD, 0x0D, 0xC2, 0x8B, 0xE7, 0x0F, 0x00,
        0xC2, 0x26, 0x05, 0xC6, 0x99, 0xD7, 0x3B, 0x47, 0x8A, 0x6B,
        0x45, 0xF7, 0x07, 0xC6, 0xE8, 0xDB, 0x81, 0x81, 0xA3, 0x29,
        0x31, 0x10, 0x38, 0x7D, 0xAA, 0x1F, 0xB8, 0x16, 0xFA, 0xEC,
        0x10, 0x72, 0x3C, 0xBD, 0xB8, 0x35, 0x75, 0x8C, 0xBE, 0xB4,
        0x8C, 0x50, 0x0F, 0xDE, 0x84, 0x6B
    };

    static unsigned char dhg_2048[] = {
        0x02
    };

    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;

    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);

    if (p == NULL || g == NULL || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }

    return dh;
}


/* Generate the IV used for AES-128 in CBC mode */
unsigned char *generate_iv(int iv_size) {

   int ret;

   /* Seed OpenSSL PRNG */
   RAND_poll();

   unsigned char *iv = (unsigned char *)malloc(iv_size);

   /* Generates 16 random bytes for my IV */
   ret = RAND_bytes((unsigned char*)&iv[0], iv_size);
   if(ret != 1){
      cerr << "ERROR: RAND_bytes fails!\n";
      exit(1);
   }

   return iv;

}


/* Encrypt the text in f_in and writes it in f_out */
void encrypt(FILE *f_in, FILE *f_out, int block_size, unsigned char *key, unsigned char *iv) {

    int ret;
    int read; /* bytes read at each chunk */
    int written; /* total bytes */
    int size_pt = -1;
    unsigned char* pt_buf;
    unsigned char* ct_buf;

    /* Get the size of the file */
    fseek(f_in, 0, SEEK_END);
    size_pt = ftell(f_in);
    if(size_pt > INT_MAX - block_size) {
        cerr << "ERROR: integer overflow! \n";
        exit(1);
    }
    fseek(f_in, 0, SEEK_SET);

    pt_buf = (unsigned char*)malloc(size_pt);
    if(!pt_buf) {
      cerr << "ERROR: malloc of plaintext buffer returns NULL\n";
      exit(1);
    }

    ct_buf = (unsigned char*)malloc(size_pt + block_size);
    if(!ct_buf) {
      cerr << "ERROR: malloc of ciphertext buffer returns NULL\n";
      exit(1);
    }

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
    if(!ctx) {
        cerr << "ERROR: EVP_CIPHER_CTX_new returns NULL\n";
        exit(1);
    }

    /* Encrypt init, it must be done only once */
    ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);
    if(!ret) {
        cerr << "ERROR: EVP_EncryptInit fails!\n";
        exit(1);
    }

    /* Loop where text is read from f_in, encrypted and written into f_out */
    for(read = fread(pt_buf, 1, size_pt , f_in); read > 0; read = fread(pt_buf, 1, size_pt, f_in)) {
        /* Encrypt that bytes */
        ret = EVP_EncryptUpdate(ctx, ct_buf, &written, pt_buf, read);
        if(!ret) {
            cerr << "ERROR: EVP_EncryptUpdate fails!\n";
            exit(1);
        }

        /* Write ciphertext to file */
        fwrite(ct_buf, 1, written, f_out);
    }

    if (!feof(f_in)) {
        cerr << "ERROR: while reading in encrypt function\n";
        exit(EXIT_FAILURE);
    }

    /* Encrypt Final, finalize the encryption and adds the padding */
    ret = EVP_EncryptFinal(ctx, ct_buf, &written);
    if(!ret) {
        cerr << "ERROR: EVP_EncryptFinal fails!\n";
        exit(1);
    }

    ret = fwrite(ct_buf, 1, written, f_out);
    if(ret < written) {
        cerr << "ERROR: while writing the ciphertext in encrypt function\n";
        exit(1);
    }   

    /* MUST ALWAYS BE CALLED!!!!!!!!!!
     * EVP_CIPHER_CTX_new calls a malloc under the hood, moreover the context contains the key, which tracks should be removed once used.
     */
    EVP_CIPHER_CTX_free(ctx);
    free(pt_buf);
    free(ct_buf);

}


void decrypt(FILE *f_in, FILE *f_out, int block_size, unsigned char *key, unsigned char *iv) {

    int ret;
    int read;
    int written;
    int size_ct = -1;
    unsigned char* pt_buf;
    unsigned char* ct_buf;

    /* Get the size of the file */
    fseek(f_in, 0, SEEK_END);
    size_ct = ftell(f_in);
    if(size_ct > INT_MAX - block_size) {
        cerr << "ERROR: integer overflow! \n";
        exit(1);
    }
    fseek(f_in, 0, SEEK_SET);

    pt_buf = (unsigned char*)malloc(size_ct);
    if(!pt_buf) {
      cerr << "ERROR: malloc of plaintext buffer returns NULL\n";
      exit(1);
    }

    ct_buf = (unsigned char*)malloc(size_ct);
    if(!ct_buf) {
      cerr << "ERROR: malloc of ciphertext buffer returns NULL\n";
      exit(1);
    }

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
    if(!ctx) {
        cerr << "ERROR: EVP_CIPHER_CTX_new returns NULL\n";
        exit(1);
    }

    /* Decrypt init, it must be done only once */
    ret = EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);
    if(!ret) {
        cerr << "ERROR: EVP_DecryptInit fails!\n";
        exit(1);
    }

    /* Loop where text is read from f_in, decrypted and written into f_out */
    for(read = fread(ct_buf, 1, size_ct , f_in); read > 0; read = fread(ct_buf, 1, size_ct, f_in)) {
        /* Decrypt that bytes */
        ret = EVP_DecryptUpdate(ctx, pt_buf, &written, ct_buf, read);
        if(!ret) {
            cerr << "ERROR: EVP_DecryptUpdate fails!\n";
            exit(1);
        }

        /* Write plaintext to file */
        fwrite(pt_buf, 1, written, f_out);
    }

    if (!feof(f_in)) {
        cerr << "ERROR: while reading in decrypt function\n";
        exit(EXIT_FAILURE);
    }

    /* Decrypt Final, finalize the decryption and removes the padding */
    ret = EVP_DecryptFinal(ctx, pt_buf, &written);
    if(!ret) {
        cerr << "ERROR: EVP_DecryptFinal fails!\n";
        exit(1);
    }

    ret = fwrite(pt_buf, 1, written, f_out);
    if(ret < written) {
        cerr << "ERROR: while writing the plaintext in decrypt function\n";
        exit(1);
    }   

    /* MUST ALWAYS BE CALLED!!!!!!!!!!
     * EVP_CIPHER_CTX_new calls a malloc under the hood, moreover the context contains the key, which tracks should be removed once used.
     */
    EVP_CIPHER_CTX_free(ctx);
    free(ct_buf);
    free(pt_buf);
}



int main() {

    int ret;

    /* DH PARAMETERS GENERATION */

    DH* tmp = get_dh2048(); /* parameters p and g of DH protocol */
    EVP_PKEY* dh_params = EVP_PKEY_new(); /* declare an high level struct for DH paramaters */
    ret = EVP_PKEY_set1_DH(dh_params, tmp); /* copies the low-level DH parameters into the high-level DH parameters */

    if(ret != 1) {
        cerr << "ERROR: EVP_PKEY_set1_DH fails!\n";
        DH_free(tmp);
        exit(1);
    }

    DH_free(tmp);

    /* *************************** */


    /* KEY GENERATION */ 

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, NULL); /* context creation */
    EVP_PKEY* private_key = NULL; /* data struct where I will insert the private key */
    
    ret = EVP_PKEY_keygen_init(ctx); /* initialize the context for DH key generation */
    if(ret != 1) {
        cerr << "ERROR: EVP_PKEY_keygen_init fails!\n";
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }

    ret = EVP_PKEY_keygen(ctx, &private_key); /* allocates memory and generates a DH key pair  and stores it in **pkey */
    if(ret != 1) {
        cerr << "ERROR: EVP_PKEY_keygen fails!\n";
        EVP_PKEY_CTX_free(ctx);
        exit(1);
    }

    EVP_PKEY_CTX_free(ctx);

    /* *************************** */

    
    /* WRITE PUBLIC KEY IN .pem FILE */

    string user1 = "";
    cout << "Name: ";
    getline(cin, user1);

    string filename1 = user1 + "_public_key.pem";

    FILE* f_pubkey_usr1 = fopen(filename1.c_str(), "w");
    if(!f_pubkey_usr1) {
        cerr << "ERROR: fopen of " << filename1 << " \n"; 
        fclose(f_pubkey_usr1);
        exit(1);
    }

    ret = PEM_write_PUBKEY(f_pubkey_usr1, private_key); /* saves a DH public key on a PEM file */
    if(ret != 1) {
        cerr << "ERROR: PEM_write_PUBKEY fails!\n";
        fclose(f_pubkey_usr1);
        exit(1);
    }

    fclose(f_pubkey_usr1);

    /* *************************** */


    /* READING PEER'S PUBLIC KEY FROM .pem FILE */

    string user2 = "";
    cout << "Name of the user you want to talk to: ";
    getline(cin, user2);

    string filename2 = user2 + "_public_key.pem";

    FILE* f_pubkey_usr2 = fopen(filename2.c_str(), "r");
    if(!f_pubkey_usr2) {
        cerr << "ERROR: fopen of " << filename2 << " \n"; 
        fclose(f_pubkey_usr2);
        exit(1);
    }

    EVP_PKEY* pubkey_usr2 = PEM_read_PUBKEY(f_pubkey_usr2, NULL, NULL, NULL); /* read the peer's public key from the .pem file */
    if(!pubkey_usr2) {
        cerr << "ERROR: PEM_read_PUBKEY fails!\n";
        fclose(f_pubkey_usr2);
        exit(1);
    }

    fclose(f_pubkey_usr2);


    /* *************************** */


    /* DERIVE A SHARED SECRET FROM THE PRIVATE KEY AND THE PEER'S PUBLIC KEY */

    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(private_key, NULL); /* create the context for secret derivation */ 
    
    ret = EVP_PKEY_derive_init(ctx_drv); /* initialize the context for secret derivation */
    if(ret != 1) {
        cerr << "ERROR: EVP_PKEY_derive_init fails!\n";
        EVP_PKEY_CTX_free(ctx_drv);
        exit(1);
    }

    ret = EVP_PKEY_derive_set_peer(ctx_drv, pubkey_usr2); /* set the peer’s public key for DH secret derivation */ 
    if(ret != 1) {
        cerr << "ERROR: EVP_PKEY_derive_set_peer fails!\n";
        EVP_PKEY_CTX_free(ctx_drv);
        exit(1);
    }

    unsigned char* secret;
    size_t secretlen; 

    ret = EVP_PKEY_derive(ctx_drv, NULL, &secretlen); /* save the size of the secret in the variable secretlen */
    if(ret != 1) {
        cerr << "ERROR: EVP_PKEY_derive fails!\n";
        EVP_PKEY_CTX_free(ctx_drv);
        exit(1);
    }

    secret = (unsigned char*)malloc(secretlen); /* allocate the buffer for the shared secret key (256 bit) */

    ret = EVP_PKEY_derive(ctx_drv, secret, &secretlen); /* derive the shared secret --> compute g^(ab) mod p */
    if(ret != 1) {
        cerr << "ERROR: EVP_PKEY_derive fails!\n";
        EVP_PKEY_CTX_free(ctx_drv);
        exit(1);
    }

    /* *************************** */


    /* ENCRYPT A FILE */ 

    unsigned char* shared_secret_key = (unsigned char*)malloc(secretlen / 2);
    
    /* Take the first 16 bytes from the secret to create the shared secret key */
    for(int i = 0; i < 128; i++) {
        shared_secret_key[i] = secret[i];
    }

    int block_size = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

    /* Open files */
    string file_pt = user1 + "_pt.txt";
    string file_ct = user1 + "_ct.txt.enc";
    FILE* f_pt = fopen(file_pt.c_str(), "rb");
    FILE* f_ct = fopen(file_ct.c_str(), "wb");

    if(!f_pt) {
        cerr << "ERROR: fopen of " << file_pt << "\n";
        fclose(f_pt);
        fclose(f_ct);
        exit(1);
    }

    if(!f_ct) {
        cerr << "ERROR: fopen of " << file_ct << "\n";
        fclose(f_pt);
        fclose(f_ct);
        exit(1);
    }

    /* IV generation */
    unsigned char *iv = generate_iv(iv_len);

    /* Encrypt the plaintext into the ciphertext */
    encrypt(f_pt, f_ct, block_size, shared_secret_key, iv);

    cout << "File '" << file_pt << "' encrypted into file '" << file_ct << "'.\n"; 

    fclose(f_pt);
    fclose(f_ct);

    /* *************************** */


    /* DECRYPT THE FILE OF THE PEER */ 

    /* Open files */
    string file_ct2 = user2 + "_ct.txt.enc";
    string file_pt2 = user2 + "_pt.txt.enc.dec";
    FILE* f_ct2 = fopen(file_ct2.c_str(), "rb");
    FILE* f_pt2 = fopen(file_pt2.c_str(), "wb");

    if(!f_ct2) {
        cerr << "ERROR: fopen of " << file_ct2 << "\n";
        fclose(f_pt2);
        fclose(f_ct2);
        exit(1);
    }

    if(!f_pt2) {
        cerr << "ERROR: fopen of " << file_pt2 << "\n";
        fclose(f_pt2);
        fclose(f_ct2);
        exit(1);
    }

    /* Decrypt the peer's ciphertext */
    decrypt(f_ct2, f_pt2, block_size, shared_secret_key, iv);

    cout << "File '" << file_ct2 << "' decrypted into file '" << file_pt2 << "'.\n"; 

    fclose(f_pt2);
    fclose(f_ct2);

    /* *************************** */

}
