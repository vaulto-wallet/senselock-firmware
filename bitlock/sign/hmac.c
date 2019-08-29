#include <string.h>
#include "hmac.h"
#include "sha512.h"

/*
unsigned char*  text;                pointer to data stream
int             text_len;            length of data stream
unsigned char*  key;                 pointer to authentication key
int             key_len;             length of authentication key
unsigned char*  digest;              caller digest to be filled in
*/
#define KEY_IOPAD_SIZE 64
#define KEY_IOPAD_SIZE128 128
void hmac_sha512(unsigned char *key, int key_len,
    unsigned char *text, int text_len, unsigned char *hmac) {
    SHA512_State context;
    unsigned char k_ipad[KEY_IOPAD_SIZE128];    /* inner padding - key XORd with ipad  */
    unsigned char k_opad[KEY_IOPAD_SIZE128];    /* outer padding - key XORd with opad */
    int i;

    /* start out by storing key in pads */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    /* XOR key with ipad and opad values */
    for (i = 0; i < KEY_IOPAD_SIZE128; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    // perform inner SHA512
    SHA512_Init(&context);                    /* init context for 1st pass */
    SHA512_Bytes(&context, k_ipad, KEY_IOPAD_SIZE128);      /* start with inner pad */
    SHA512_Bytes(&context, text, text_len); /* then text of datagram */
    SHA512_Final(&context, hmac);             /* fnish up 1st pass */

    // perform outer SHA512
    SHA512_Init(&context);                   /* init context for 2nd pass */
    SHA512_Bytes(&context, k_opad, KEY_IOPAD_SIZE128);     /* start with outer pad */
    SHA512_Bytes(&context, hmac, SHA512_DIGEST_SIZE);     /* then results of 1st hash */
    SHA512_Final(&context, hmac);          /* finish up 2nd pass */
}

