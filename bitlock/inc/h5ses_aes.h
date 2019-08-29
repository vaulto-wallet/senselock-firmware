#ifndef _HEADER_H5SES_AES_H_
#define _HEADER_H5SES_AES_H_

#include "h5ses_common.h"

#define ALGORITHM_MODE_ECB            0
#define ALGORITHM_MODE_CBC            1

#define AES_KEY_BITS_128							128
#define AES_KEY_BITS_192							192
#define AES_KEY_BITS_256							256

// AES functions
UINT16 _aes_enc (UINT8 u8Mode, UINT8 *pu8AesKey, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _aes_dec (UINT8 u8Mode, UINT8 *pu8AesKey, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _aes_enc_keyfile  (UINT8 u8Mode, HANDLE hFile, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _aes_dec_keyfile  (UINT8 u8Mode, HANDLE hFile, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _aes_enc_raw (UINT8 u8Mode, UINT8 *pu8Key, UINT32 u32KeyBitLen, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _aes_dec_raw (UINT8 u8Mode, UINT8 *pu8Key, UINT32 u32KeyBitLen, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _aes_cmac_raw (UINT8 *pu8AesKey, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8Mac, UINT32 u32MacBufLen, UINT32 *pu32MacLen);

#endif // _HEADER_H5SES_AES_H_
