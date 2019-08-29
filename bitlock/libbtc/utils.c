#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void utils_bin_to_hex(unsigned char* bin_in, size_t inlen, char* hex_out)
{
    static char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < inlen; i++) {
        hex_out[i * 2] = digits[(bin_in[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = digits[bin_in[i] & 0xF];
    }
    hex_out[inlen * 2] = '\0';
}


void assert(unsigned int res){
	return;
}

void *btc_mem_zero(volatile void *dst, size_t len){
	memset(dst, 0, len);
}

void btc_random_init(void){
	return;
}

unsigned int  btc_random_bytes(uint8_t* buf, uint32_t len, const uint8_t update_seed){
	memset(buf, 1, len);
	return 1;
}


