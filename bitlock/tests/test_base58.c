#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h5ses.h"
#include "encoding/libbase58.h"

void test_base58(){
	static const unsigned char binary[]={ 0x00,0x5a,0x1f,0xc5,0xdd,0x9e,0x6f,0x03,0x81,0x9f,0xca,0x94,0xa2,0xd8,0x96,0x69,0x46,0x96,0x67,0xf9,0xa0,0x74,0x65,0x59,0x46 };
	static const char testString[]="19DXstMaV43WpYg4ceREiiTv2UntmoiA9j";
	unsigned char stringOut[50];
	char outBuffer[100];
	size_t xstringOutSize;
	size_t outBufferSize;


	xstringOutSize = (size_t)sizeof(stringOut);
	
	b58tobin(&stringOut[0], &xstringOutSize, &testString, sizeof(testString));
	
	outBufferSize = (size_t)sizeof(outBuffer);
	
	
	//char binary[]="005a1fc5dd9e6f03819fca94a2d89669469667f9a074655946";
	b58enc(&outBuffer[0], &outBufferSize, &binary[0], sizeof(binary));
	
	//19DXstMaV43WpYg4ceREiiTv2UntmoiA9j
	return;
}
