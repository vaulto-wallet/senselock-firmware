#ifndef _HEADER_H5SES_DEVICE_H_
#define _HEADER_H5SES_DEVICE_H_

#include "h5ses_common.h"

// device info param
#define DEVICE_INFO_SERIAL                          0x03                // 获取设备序列号
#define DEVICE_INFO_DEVELOPER_ID                    0x04                // 获取开发商ID

// device info functions
UINT16 _get_device_info(UINT8 u8Info, UINT8 *pu8Data, UINT16 *pu16Length);
 
UINT16 _get_time (UINT32 *pu32Time);

UINT16 _tick (UINT32 *pu32TickCount);


#endif // _HEADER_H5SES_DEVICE_H_
