#ifndef _HEADER_H5SES_DES_H_
#define _HEADER_H5SES_DES_H_

#include "h5ses_common.h"

#define ALGORITHM_MODE_ECB            0
#define ALGORITHM_MODE_CBC            1

// DES functions
UINT16 _des_enc (UINT8 u8Mode, UINT8 *pu8DesKey, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _des_dec (UINT8 u8Mode, UINT8 *pu8DesKey, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _des_enc_keyfile  (UINT8 u8Mode, HANDLE hFile, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _des_dec_keyfile  (UINT8 u8Mode, HANDLE hFile, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _des_enc_raw (UINT8 u8Mode, UINT8 *pu8Key, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _des_dec_raw (UINT8 u8Mode, UINT8 *pu8Key, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

// TDES functions
UINT16 _tdes_enc (UINT8 u8Mode, UINT8 *pu8TdesKey, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _tdes_dec (UINT8 u8Mode, UINT8 *pu8TdesKey, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _tdes_enc_keyfile  (UINT8 u8Mode, HANDLE hFile, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _tdes_dec_keyfile  (UINT8 u8Mode,HANDLE hFile, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _tdes_enc_raw (UINT8 u8Mode, UINT8 *pu8Key, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

UINT16 _tdes_dec_raw (UINT8 u8Mode, UINT8 *pu8Key, UINT8 *pu8Iv, UINT8 *pu8Data, UINT32 u32DataLen, UINT8 *pu8OutBuf, UINT32 u32OutBufLen, UINT32 *pu32OutDataLen);

#endif // _HEADER_H5SES_DES_H_
