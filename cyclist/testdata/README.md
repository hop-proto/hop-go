This contains inputs and outputs for Absorb, Squeeze, Encrypt, and Decrypt in a parseable format. This is effectively a transcript of actions to Cyclist. Files of this format are used to test the Go implementation against a reference implementation, such as XKCP.

Note that while decrypt calls are usually paired with an encrypt call by a responder / initiator, a single party can generate a transcript file simply by outputing the ciphertext and plaintext for both an encrypt and the would-be corresponding decrypt call.

Example program to output a transcript in C, using the XKCP implementation with the prefix `CyclistSHA3`:

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "Cyclist_SHA3.h"

static uint8_t* alloc_key() {
    uint8_t* k = malloc(sizeof(uint8_t)*32);
    for (size_t i = 0; i < 32; i++) {
        k[i] = i;
    }
    return k;
}

static void displayByteString(FILE *f, const char* synopsis, const uint8_t *data, unsigned int length)
{
    unsigned int i;

    fprintf(f, "%s:", synopsis);
    for(i=0; i<length; i++)
        fprintf(f, " %02x", (unsigned int)data[i]);
    fprintf(f, "\n");
}

int main(int argc, char *argv[]) {
    CyclistSHA3_Instance cyclist;
    uint8_t *k = alloc_key();
    uint8_t y[16];
    uint8_t p[200];
    uint8_t c[200];
    CyclistSHA3_Initialize(&cyclist, k, 32, NULL, 0, NULL, 0);
    cyclist.file = stderr;
    CyclistSHA3_Absorb(&cyclist, "let me absorb", 13);
    displayByteString(stdout, "absorb[13]", "let me absorb", 13);
    CyclistSHA3_Squeeze(&cyclist, y, 16);
    displayByteString(stdout, "squeeze[16]", y, 16);
    displayByteString(stdout, "encrypt-ir[39]", "we own things, but we have hidden them.", 39);
    CyclistSHA3_Encrypt(&cyclist, "we own things, but we have hidden them.", c, 39);
    displayByteString(stdout, "decrypt-ir[39]", c, 39);
    CyclistSHA3_Squeeze(&cyclist, y, 16);
    displayByteString(stdout, "squeeze[16]", y, 16);
    fflush(stdout);
    free(k);
    return 0;
}
```

To actually run the test, save the transcript file as a `.txt` and add it to the list of implementations in `TestCyclistAgainstReference` in `cyclist_test.go`.
