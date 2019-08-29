#ifndef _HEADER_H5SES_FILE_H_
#define _HEADER_H5SES_FILE_H_

#include "h5ses_common.h"

#define FILE_TYPE_BINARY              0
#define FILE_TYPE_EXECUTIVE           1
#define FILE_TYPE_KEY                 2

#define FSC_FILE_NAME_LEN             16

typedef struct _FILE_PROPERTY
{
    UINT8 u8Validate;               // ��־��Щ����Ч�����������ļ�������ʹ��
	UINT8 u8Type;                   // �ļ����ͣ������޸�
    UINT16 u16Privilege;             // �ļ�����Ȩ��
    UINT32 u32Size;                 // �ļ���С
    UINT32 u32Time;                 // �ļ��޸�ʱ��
    CHAR acName[FSC_FILE_NAME_LEN]; // �ļ���
}FILE_PROPERTY;

// u8Validate
#define FILE_PROPERTY_VALIDATE_SIZE                 2
#define FILE_PROPERTY_VALIDATE_TIME                 4
#define FILE_PROPERTY_VALIDATE_NAME                 8
#define FILE_PROPERTY_VALIDATE_ENABLE_EXE           16

// FILE functions
UINT16 _file_list (UINT16 u16Index, CHAR *pcName);

UINT16 _file_create (CHAR *pcName, UINT8 u8Type, UINT32 u32Size, UINT32 u32Time, HANDLE *phFile);

UINT16 _file_open (CHAR *pcName, HANDLE *phFile);

UINT16 _file_close (HANDLE hFile);

UINT16 _file_delete (CHAR *pcName);

UINT16 _file_read (HANDLE hFile, UINT32 u32Offset, UINT16 u16Length, UINT8 *pu8Data);

UINT16 _file_write (HANDLE hFile, UINT32 u32Offset, UINT16 u16Length, UINT8 *pu8Data);

UINT16 _file_get_property (HANDLE hFile, FILE_PROPERTY *pfpProperty);

UINT16 _file_set_property (HANDLE hFile, FILE_PROPERTY *pfpProperty);

#endif // _HEADER_H5SES_FILE_H_
