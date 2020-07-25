# SnowHaze Zero-Knowledge Verification

SnowHaze VPN is fully anonymous thanks to Zero-Knowledge Auth (ZKA) technology. Privacy by desing in every step guarantees the highest possible anonymity. This is not just a promise but you can verify for yourself that the code running on our servers it the same that we open sourced.

There is a dedicated process, which is in charge of generating and distributing the tokens. This process runs inside an enclave that is isolated and cannot be read or altered from outside. This is achieved using a technology by Intel called Software Guard Extensions (SGX), which provides a guarantee for the integrity of the code in this enclave.

You can find more on SGX at [Intel](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html).

This repository hosts the verification script that you can run to check the integrity of the token generation for our ZKA VPN.

<hr>

## Background
You can verify that the code used to generate the tokens has not been altered and is exactly the same as we open sourced. For the verification, you need a piece of data called *verification blob*. The *verification blob* is the data, which the server sends when your device requests new access tokens. The *verification blob* consists of the encrypted concatenation of your access tokens, followed by the signature of this data.

The server signs the encrypted tokens with the private key and then destroys the private key. The public key is then published on our server along with an attestaation from Intel which confirms the integrity of the enclave.

The verification script gets the published public key and verifies the signature in the blob.

## Runnning the Verification

Python 3 has to be installed on your machine. The verification script runs with Python and takes a *verification blob* as input.

> You'll find the *verification blob* in Settings &rarr; Subscription &rarr; Verification Blob.

Clone the repository

```
$ git clone https://github.com/snowhaze/zka-sgx.git
$ cd zka-sgx
```

Then run the following command:

**macOS**

```
% python3 verify.py -o apple-compat -a <verification blob>
```

`-o` specifies the location of OpenSSL

`apple-compat` uses the Apple library because OpenSSL is not installed by default on macOS and iOS.

**Linux**

```
$ python3 verify.py -a <verification blob>
```

**Windows**

```
> .\python.exe .\verify.py -o <openssl path> <verification blob>
```

`-o` specifies the path to the OpenSSL installation
> OpenSSL needs to be installed on your Windows machine


## Interpreting the Output
Let's look at an example output line by line:

```
RESULT:  Verification Blob Signed with Primary Signature Key
```
The first result is the successful verification of the signature. The blob was signed using the primary key, which was destroyed. If you verify the blob shortly after successfully subscribing, the server did not yet generate tokens for your public key since it didn't exist before. You therefore get tokens from the reserve set. These are signed with the secondary key. Your tokens will be signed with the primary key the next time they are updated.

```
RESULT:  Enclave Config: 546 Public Keys, 1000 Reserve Sets, 20 Tokens Each, 4.0x Oversized
```
The second result states

1. The number of public keys for which a set of token was generated (here 546)
2. The number of reserve sets that were generated for users which are not yet registered (here 1000)
3. The number of tokens in each set (here 20)
4. How many more tokens that were generated, thus reducing the number of tokens that are assigned to multiple users (here 4 times)

```
RESULT:
  Output Types:
  - hashes
ERROR:   <error>
WARNING: <warning>
NOTE:
  For more, see
  - INTEL-SA-00220
  - INTEL-SA-00270
  at https://security-center.intel.com
```
The third result described the output that the server gets from the token generation. In the present case, the server gets the `hashes` of the valid tokens. When you will use a token to request a connection to the VPN server, the server will hash the token and compare that hash to the hashes of valid tokens.

In case an `error` occurs, the error message will appear.
In case a `warning` is raised, the warning will appear. Additionally, the implication of the warning will be listed under `NOTE`.

```
RESULT:  Verified Chain for Enclave db156b322ac5e8814d03f02c5154bed5cc9706ae22af69c1f1f4bdad3ee8be7a
NOTE:
  Tool Versions:
  - zkacli: 0.6 (8d499c446398a9b42f4e59b986c5ba11c13a8ae4)
  - libsodium: 'stable' Branch (e6d0a57061bc06fa0bb0ebb2214955ab39cfa1fa)
  - SGX SDK: 2.9.101.2
  - Compiler: cc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
  - Build Date: 2020-06-17T13:18:47+00:00
  - Unsigned Enclave: aa6810377e67404ba2df759f28945e094008a4baff6852d7f0d4bb85687a2641
  - Signed Enclave: 76dcb287fc4a94c71aacc0b70eb90444786a4934ac39095c18b807b50b7407c7
  - enclave.signdata.sig: bfe9cbf258d1e262c350eb4c51e11658b1289bd7753ae716c24f8f7eeddf4f54
  - sign.pem: 715c09fd9aa1815f20a9733422c8d46894637330ae5d13b5c36fddcf6ab53777
```
The last result is the confirmation from Intel that the hash of the enclave has not been altered and that the enclave therefore still contains the same code. The tools needed to build the enclave are listed under `NOTE`.

## Building the Enclave

To build the enclave, you will need to run the following code on an Ubuntu 18.04 machine (same as where we built the enclave for reproducibility).

Clone the repository

```
$ git clone https://github.com/snowhaze/zka-sgx.git
```

Install the SGX SDK and SGX PSW by running the following code and type `yes` to install it in the current directory.

```
$ ./zka-sgx/sgx_install.sh
$ chown -R <user> sgxsdk/
$ source sgxsdk/environment
```

Clone the latest libsodium and change directory

```
$ git clone https://github.com/jedisct1/libsodium --branch stable
$ cd zka-sgx/zkacli
```

Continue by running the script `verify.py` with the `-b` flag specifying the path in which the signature and public key should be stored, e.g.

```
$ python3 ../verify.py -b .. <verification blob>
```

> Make sure you have the same tool versions as we used to compile the enclace and check out the same commit. The tool versions and commit hash are given in the result from above.

```
$ make release-1 SODIUM_PATH=../../libsodium
```

Run make again

```
$ cp ../enclave.signdata.sig ../enclave.signdata ../sign.pem .
$ make release-2 SODIUM_PATH=../../libsodium
```

You have now build the same enclave as we did to generate your tokens. Check this by comparing the `enclave_hash` in the file `enclave_dumpfile` with the hash of the `Verified Chain for Enclave` resulting from the `verify.py` script.

To print the enclave hash from `enclave_dumpfile`, run

```
awk -f get_enclave_hash.awk enclave_dumpfile
```

Congratulations, you verified the integrity of the enclave!

## License

This code is licensed under the GPL v3 license.

Disclaimer: The GPL license is *not* a free license and GPL licensed software is *not* free software. The GPL license restricts your rights to use software heavily. It is designed specifically to be incompatible with many other licenses and because of this we are bound to use the GPL license. Since the GPL license confines you to the GPL ecosystem, it contradicts the very essence of free software and thus we do not endorse it.

Important: The use of Intel SGX products requires consent to Intel’s terms and conditions and imposes various restrictions on possible usage. Depending on the circumstances and the use case, Intel’s terms might not be compatible with the GPL license. Before using this code, make sure that the GPL license is compatible with your intended usage.

## Questions
Get in touch with us if you'd like to know more or have questions about SnowHaze VPN. [Contact Us](https://snowhaze.com/en/support-contact.html)