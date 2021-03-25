## AES-128_CBC ENCRYPTER-DECRYPTER

# How it works
The program reads some text from a file called *file.txt* and encrypts it using the following specifications:
* AES-128 in CBC mode
* The symmetric key is known and hard-coded
* IV is randomly chosen using OpenSSL libs

The encryptor writes IV and the ciphertext into a new file called *file.txt.enc*. The decryptor reads from *file.txt.enc* and writes the decrypted text into a new file called *file.txt.enc.dec*.
It has been used the approach of defensive programming to write the code: programs are memory safe and no memory leaks are possible.

# Prerequisites
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

# Usage
Before running the programs, you have first to compile them with `-lcrypto` flag in order to include crypto features of OpenSSL.

```bash
g++ encryptor.cpp -lcrypto -o encryptor.out
g++ decryptor.cpp -lcrypto -o decryptor.out
./encryptor.out
./decryptor.out
```
