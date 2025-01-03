# Protected n-share AES-128

This project is an implementation in C of a protected n-share AES-128 introduced in the following publication :

> [Random Probing Security: Verification, Composition, Expansion and New Constructions](https://eprint.iacr.org/2020/786)  
> By Sonia Belaïd, Jean-Sébastien Coron, Emmanuel Prouff, Matthieu Rivain and Abdul Rahman Taleb 
> In the proceedings of CRYPTO 2020.

### Modifications and Extensions

- Implemented an iterable gadget in `gadgets.c` to enhance functionality. 
- Updated the `exp254_sharing` function in `aes128_sharing.c` to alter the order of the addition chain for better efficiency.

This project can implement an arbitrary order of gadget-based masking by adjusting the value of NB_SHARES in the `gadgets.h` file.

## Content

This repository contains the code of the protected AES-128 implemented in C:

* __main.c:__ contains the main function that executes the AES-128 encryption and decryption algorithms.

In **aes_files** folder:

* __aes128_sharing.h, aes128_sharing.c:__ contains the protected implementation of the n-share AES-128 algorithm.
* __gadgets.h, gadgets.c:__ contains the three n-share gadgets functions (add, copy, mult), as well as the n-share variables generation and compression functions.
* __gf256.h, gf256.c:__ contains the functions for addition and multiplication in the field GF(256).
* __Makefile:__ to compile the program

## Usage

Using the program requires having a gcc compiler with the standard math library (uses the flag `-lm`).

To compile the program :

```
make
```

To clean :

```
make clean
```

To run AES-128 algorithm :

```
./main
```

Plaintext and key values should be specified in the file `main.c` 

## Gadgets Specification

When changing number of shares, and gadgets, only one files have to be modified : `gadgets.h` 

In the file `gadget.h`, the user should specify the value for the macro NB_SHARES : 

```
#define NB_SHARES 5
```

for example for a 5-share execution.

## Output Format (Example)

An execution example outputs the following on the standard output :

```
$ ./main
SHARING ENCRYPTION SUCCESS

Cipher text:
fd 9f f6 46 75 36 60 4e 42 3d  a e1 d0 c6 aa 9b 


Timings: 

AES sharing enc took 1.809120 ms

AES sharing dec took 1.873970 ms
```

The program runs the secure n-share  AES-128 encryption/decryption, and if the decryption of the ciphertext outputs the original plaintext, and the recombination of the ciphertext shares gives the same ciphertext as the one with the regular AES-128 encryption,  the program outputs :

```
SHARING ENCRYPTION SUCCESS
```

Finally, the program outputs the resulting ciphertext:

```
Cipher text:
ff  b 84 4a  8 53 bf 7c 69 34 ab 43 64 14 8f b9 
```

And timings for each of the n-share AES-128 encryption/decryption :

```
Timings: 

AES sharing enc took 291.994095 ms

AES sharing dec took 235.274792 ms
```

If any of the outputs is incorrect, the program specifies an error (this shouldn't occur).

