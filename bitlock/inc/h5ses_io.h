#ifndef _HEADER_H5SES_IO_H_
#define _HEADER_H5SES_IO_H_

#include "h5ses_common.h"

// I/O functions
UINT16 _set_output (UINT8 *pu8Data, UINT16 u16Length);

UINT8 * _get_input (void);

UINT16 _get_input_len (void);


#endif // _HEADER_H5SES_IO_H_
