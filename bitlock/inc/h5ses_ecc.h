#ifndef _HEADER_H5SES_ECC_H_
#define _HEADER_H5SES_ECC_H_

#include "h5ses_common.h"

#define HASH_SHA1  		              1
#define HASH_SHA256		              2

// ECC functions
UINT16 _ecc_sign (UINT8 u8HashAlgo, UINT8 *pu8PriKey, UINT8 *pu8Message, UINT32 u32MessageLen, UINT8 *pu8SignatureBuf, UINT32 u32SignatureBufLen, UINT32 *pu32SignatureLen);

UINT16 _ecc_verify (UINT8 u8HashAlgo, UINT8 *pu8PubKey, UINT8 *pu8Message, UINT32 u32MessageLen, UINT8 *pu8Signature, UINT32 u32SignatureLen);

UINT16 _ecc_sign_keyfile  (UINT8 u8HashAlgo, HANDLE hFile, UINT8 *pu8Message, UINT32 u32MessageLen, UINT8 *pu8SignatureBuf, UINT32 u32SignatureBufLen, UINT32 *pu32SignatureLen);

UINT16 _ecc_verify_keyfile  (UINT8 u8HashAlgo, HANDLE hFile, UINT8 *pu8Message, UINT32 u32MessageLen, UINT8 *pu8Signature, UINT32 u32SignatureLen);


#endif // _HEADER_H5SES_ECC_H_
