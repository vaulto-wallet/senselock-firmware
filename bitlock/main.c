#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h5ses.h"


#include "secp256k1/sb_sw_curves.h"
#include "secp256k1/sb_sw_lib.h"
#include "libbtc/btc/bip32.h"


typedef struct {
	UINT16 code;
	UINT8  buffer[1];
}IO_HDR;

UINT8 outBuf[1024];
uint8_t retCode;





int main(void)
{
	UINT16 retval  = SES_SUCCESS;
	UINT16 inLen   = _get_input_len();
	IO_HDR* inHdr  = (IO_HDR*)_get_input();
	UINT16 outLen  = 0;
	IO_HDR* outHdr = (IO_HDR*)outBuf;


	/*
    sb_sha256_state_t ctx;
    sb_byte_t hash[SB_SHA256_SIZE];
	
	sb_sha256_init(&ctx);
    sb_sha256_update(&ctx, TEST_M2, sizeof(TEST_M2) - 1);
    sb_sha256_finish(&ctx, hash);
	_set_output((UINT8 *)&hash, sizeof(hash));
	*/
	
 
    
//	sb_sw_valid_public_key(&ct, &p, SB_SW_CURVE_SECP256K1,SB_DATA_ENDIAN_BIG);
    //sb_sw_compute_public_key(&ct, &pub_out, &d, NULL, SB_SW_CURVE_SECP256K1,SB_DATA_ENDIAN_BIG);
    /*
    sb_sw_context_t ct;
    sb_sw_signature_t out;
	sb_sw_sign_message_digest(&ct, &out, &d, &m, NULL,
                                     SB_SW_CURVE_SECP256K	1,
                                     SB_DATA_ENDIAN_BIG);
    sb_sw_verify_signature(&ct, &out, &p, &m, NULL,
                                  SB_SW_CURVE_SECP256K1,
                                  SB_DATA_ENDIAN_BIG);
	*/
	
	
	//test1();
	//test2();
	//sb_test_sign_k256();
    //test_sha512();
	//test_base58();
	//const sb_sw_curve_t* const s = sb_sw_curve_from_id(SB_SW_CURVE_SECP256K1);
	//_set_output((UINT8 *)s, sizeof(sb_sw_curve_t));
	
	//_set_output((UINT8 *)&SB_CURVE_P256_P, sizeof(SB_CURVE_P256_P));
	
	//_set_output((UINT8 *)&SB_CURVE_SECP256K1, sizeof(SB_CURVE_SECP256K1));
	//_set_output((UINT8 *)&SB_CURVE_P256, sizeof(SB_CURVE_P256));
 
	//test_bip44_0();
	
	
	
	test_bip44_1();
	
	//outHdr->code = retval;
	_set_output((UINT8 *)&retCode, sizeof(retCode));
	return 0;
}


