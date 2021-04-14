# DIGITAL ENVELOPE

## How it works
First of all, the user should generate a pair of 2048-bit RSA keys and the private key must be protected by password.
The "seal" program reads the public key (from a .pem file) and some plaintext from a file called *plaintext.txt* and encrypts it with AES_128 in CBC mode. 
The IV is randomly generated using OpenSSL library and the symmetric key is known and hardcoded.
Finally, the seal program writes the encrypted symmetric key, the IV and the ciphertext into a file called *ciphertext.txt*.

The "open" program reads the private key (from a .pem file) and the encrypted symmetric key, the IV and the cipertext from *ciphertext.txt* file, decrypts it and writes it to a file called *decrypted_text.txt*.

## Prerequisites 
The programs needs the installation of [OpenSSL](https://github.com/openssl/openssl), a TLS/SSL and crypto library.

### Install on Ubuntu/Debian
First of all, install build dependencies, then clone OpenSSL and configure it.

```bash
sudo apt-get -y install build-essential checkinstall git zlib1g-dev
git clone --depth 1 --branch OpenSSL_1_1_1g https://github.com/openssl/openssl.git
cd openssl
./config zlib '-Wl,-rpath,$(LIBRPATH)'
```

After you have built and tested, install OpenSSL and configure the shared libs.

```bash
make
make test
sudo make install
sudo ldconfig -v
```
Finally, check the OpenSSL version to make sure you have successfully completed all the steps.

```bash
openssl version
```

## 2048-bit RSA Generation
Before running the program , the user should generate a pair of 2048-bit RSA keys using OpenSSL command-line tools. 

* **RSA private key**: the following command generate a .pem file containing a 2048-bit key.

```bash
openssl genrsa -aes128 -out private_key.pem 2048
```
* **RSA public key**: a private key in OpenSSL is represented with a strcuture that contains also the public key, so the following command extract the public key from the private key.
```bash
openssl rsa -pubout -aes128 -in private_key.pem -out public_key.pem
```

## Usage
Before running the programs, you have first to compile them with `-lcrypto` flag in order to include crypto features of OpenSSL.

```bash
g++ seal_program.cpp -lcrypto -o seal_program.out
g++ open_program.cpp -lcrypto -o open_program.out
./seal_program.out
./open_program.out
```
