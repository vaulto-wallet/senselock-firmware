#ifndef _HEADER_H5SES_RSA_H_
#define _HEADER_H5SES_RSA_H_

#include "h5ses_common.h"

#define HASH_SHA1  		              1
#define HASH_SHA256		              2

#define RSA_PAD_MODE_NO_PAD           0
#define RSA_PAD_MODE_PKCS             1

#define RSA_KEY_BITS_1024							1024
#define RSA_KEY_BITS_2048							2048

// RSA functions
UINT16 _rsa_enc (UINT8 u8PadMode, UINT8 *pu8RsaKey, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _rsa_dec (UINT8 u8PadMode, UINT8 *pu8RsaKey, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _rsa_sign (UINT8 u8PadMode, UINT8 u8HashAlgo, UINT8 *pu8PriKey, UINT8 *pu8Message, UINT32 u32MessageLen, UINT8 *pu8SignatureBuf, UINT32 u32SignatureBufLen, UINT32 *pulSignatureLen);

UINT16 _rsa_verify (UINT8 u8PadMode, UINT8 u8HashAlgo, UINT8 *pu8PubKey, UINT8 *pu8Message, UINT32 u32MessageLen, UINT8 *pu8Signature, UINT32 u32SignatureLen);

UINT16 _rsa_enc_keyfile  (UINT8 u8PadMode, HANDLE hFile, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _rsa_dec_keyfile  (UINT8 u8PadMode, HANDLE hFile, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _rsa_sign_keyfile  (UINT8 u8PadMode, UINT8 u8HashAlgo, HANDLE hFile, UINT8 *pu8Message, UINT32 u32MessageLen, UINT8 *pu8SignatureBuf, UINT32 u32SignatureBufLen, UINT32 *pulSignatureLen);

UINT16 _rsa_verify_keyfile  (UINT8 u8PadMode, UINT8 u8HashAlgo, HANDLE hFile, UINT8 *pu8Message, UINT32 u32MessageLen, UINT8 *pu8Signature, UINT32 u32SignatureLen);

UINT16 _rsa_gen_keypair (UINT32 u32KeyBitLen, UINT8 *pu8PubKey, UINT32 u32PubKeyBufLen, UINT32 *pu32PubKeyLen, UINT8 *pu8PriKey, UINT32 u32PriKeyBufLen, UINT32 *pu32PriKeyLen);

#endif // _HEADER_H5SES_RSA_H_
