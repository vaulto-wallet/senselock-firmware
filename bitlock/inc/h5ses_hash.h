#ifndef _HEADER_H5SES_HASH_H_
#define _HEADER_H5SES_HASH_H_

#include "h5ses_common.h"

typedef struct
{
  UINT32 u32Total[2];
  UINT32 u32State[5];
  UINT8 au8Buffer[64];
}SHA1_CONTEXT;

typedef struct
{
  UINT32 au32TotalLength[2];
  UINT32 u32Hash[8];
  UINT32 u32BufferLength;
  UINT8 au8Buffer[64];
}SHA256_CONTEXT;

#define SHA1_HASH_LEN              24
#define SHA256_HASH_LEN            32

// HASH functions
UINT16 _sha1_init (SHA1_CONTEXT *pContext);

UINT16 _sha1_update (SHA1_CONTEXT *pContext, UINT8 *pu8Data, UINT32 u32DataLen);

UINT16 _sha1_final (SHA1_CONTEXT *pContext, UINT8 *pu8Hash);

UINT16 _sha256_init (SHA256_CONTEXT *pContext);

UINT16 _sha256_update (SHA256_CONTEXT *pContext, UINT8 *pu8Data, UINT32 u32DataLen);

UINT16 _sha256_final (SHA256_CONTEXT *pContext, UINT8 *pu8Hash);

#endif // _HEADER_H5SES_HASH_H_
