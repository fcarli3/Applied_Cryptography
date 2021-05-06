# Diffie-Hellman Key Exchange Protocol

## How it works 
First of all, the user should generate 2048-bit DH parameters using the command line tool. The command shows on stdout a C source code of a function called **get_dh2048()**
that has been included in the code. After that, the program executes the following steps: 

1. Generates an ephemeral DH pair using the parameters previously generated
2. Writes the public key into a .pem file
3. Loads the peer's public key from a .pem file
4. Derives a shared secret from the generated private key and the peer's public key
5. Gets the session key from the first 16 bytes of the digest of the previous shared secret, using SHA-256 hashing algorithm
6. Encypts an existing .txt file using the first 16 bytes of the shared secret key using AES-128 in CBC mode
7. Decrypts the .txt file encrypted by the peer

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

## 2048-bit DH parameters Generation
Before running the program , the user should generate 2048-bit DH parameters using the OpenSSL command-line tool. 

```bash
openssl dhparam -C 2048
```
This command creates parameters **p** and **g** 
with public keys of 2048 bits and shows on stdout the C source code of a function called **get_dh2048()** that allocates and return a low-level DH structure for such parameters.
The code of this function is already included in the source code of the program.

## Usage
Before running the programs, you have first to compile them with `-lcrypto` flag in order to include crypto features of OpenSSL.

```bash
g++ dh.cpp -lcrypto -o dh.out
./dh.out
```
