#ifndef _HEADER_H5SES_SM_H_
#define _HEADER_H5SES_SM_H_

#include "h5ses_common.h"

// share momory functions
UINT16 _get_sharemem_size(void);

UINT16 _sharemem_write(void *pData, UINT16 u16Offset, UINT16 u16Len);

UINT16 _sharemem_read(void *pData, UINT16 u16Offset, UINT16 u16Len);


#endif // _HEADER_H5SES_SM_H_
