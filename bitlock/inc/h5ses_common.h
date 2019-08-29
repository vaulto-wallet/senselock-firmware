#ifndef _HEADER_H5SES_COMMON_H_
#define _HEADER_H5SES_COMMON_H_

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned long UINT32;

typedef char CHAR;
typedef unsigned long HANDLE;

// Error Code
#define SES_SUCCESS                                 0x0000L             // �ɹ�
#define SES_ERROR_INSUFFICIENT_BUFFER               0x0003L             // ��������С����

#define SES_ERROR_NO_SPACE                          0x0012L             // �ռ�����
#define SES_ERROR_FILE_NOT_FOUND                    0x0014L             // δ�ҵ�ָ���ļ�
#define SES_ERROR_FILE_OUT_RANGE                    0x0016L             // ��д�����ļ���Χ
#define SES_ERROR_FILE_EXIST                        0x0017L             // �ļ��Ѿ�����(����)
#define SES_ERROR_INVALID_FLAG                      0x001BL             // �Ƿ���flag �����ļ�����ʱָ���˴����Flag
#define SES_ERROR_INVALID_FILE_TYPE                 0x001CL             // �Ƿ����ļ�����
#define SES_ERROR_WRITE_OFFSET_WRONG                0x001EL             // д��Կ�ļ�ʱ��ƫ�Ʊ���Ϊ0

#define SES_ERROR_OPEN_TOO_MANY                     0x0020L             // ͬʱ�򿪵��ļ��ﵽ�������
#define SES_ERROR_INVALID_HANDLE                    0x0021L             // �Ƿ����ļ����
#define SES_ERROR_WRONG_FILE_NAME_LEN               0x0023L             // ������ļ����Ƴ���

#define SES_ERROR_INVALID_MEM_ADDR                  0x0048L             // �Ƿ����ڴ��ַ
#define SES_ERROR_INVALID_MEM_LENGTH                0x0049L             // �Ƿ����ڴ泤��
#define SES_ERROR_SHAREMEM_OUT_RANGE                0x004EL             // ���������ڴ淶Χ

#define SES_ERROR_BAD_DEVICE_INFO                   0x005FL             // ������豸��Ϣ

#define SES_ERROR_AES_LENGTH                        0x0070L             // AES�㷨���볤�ȴ���
#define SES_ERROR_AES_MODE_UNSUPPORTED              0x0071L             // ��֧�ֵ�AES�㷨ģʽ
#define SES_ERROR_DES_LENGTH                        0x0078L             // DES�㷨���볤�ȴ���
#define SES_ERROR_DES_MODE_UNSUPPORTED              0x0079L             // ��֧�ֵ�DES�㷨ģʽ

#define SES_ERROR_NO_PRIVILEGE                      0x0080L             // û��Ȩ�޷���

#define SES_ERROR_ECC_UNSUPPORTED_CURVE             0x00A0L             // ��֧�ֵ�ECC����
#define SES_ERROR_ECC_SIGN                          0x00A1L             // ECDSAǩ������
#define SES_ERROR_ECC_VERIFY                        0x00A2L             // ECDSAǩ����֤����

#define SES_ERROR_RSA_UNSUPPORTED_PAD_MODE          0x00A3L             // ��֧�ֵ�RSA���ģʽ
#define SES_ERROR_RSA_UNSUPPORTED_ALGO              0x00A4L 			// ��֧�ֵ�RSA�㷨λ��
#define SES_ERROR_RSA_LENGTH                        0x00A5L 			// RSA�㷨���볤�ȴ���
#define SES_ERROR_RSA_BAD_KEY                       0x00A6L 		    // �����RSA��Կ
#define SES_ERROR_RSA_BAD_DATA                      0x00A7L 			// RSA�������ݴ���
#define SES_ERROR_RSA_SIGN                          0x00A8L 		    // RSAǩ������
#define SES_ERROR_RSA_VERYIFY                       0x00A9L 		    // RSAǩ����֤����

#define SES_ERROR_UNSUPPORTED_HASH_ALGO       	    0x00B0L             // ��֧�ֵĹ�ϣ�㷨

#define SES_ERROR_BAD_PRIVATE_KEY                   0x00C0L             // �����˽Կ����
#define SES_ERROR_BAD_PUBLIC_KEY                    0x00C1L             // ����Ĺ�Կ����
#define SES_ERROR_BAD_SYMMETRIC_KEY                 0x00C2L		        // ����ĶԳ���Կ����
#define SES_ERROR_BAD_SIGNATURE                     0x00C3L		        // �����ǩ������

#define SES_ERROR_BAD_ALGO                          0x00D0L	            // �������Կ�㷨
#define SES_ERROR_BAD_VERSION                       0x00D1L             // �������Կ��ʽ�汾
#define SES_ERROR_BAD_TYPE                          0x00D2L             // �������Կ����
#define SES_ERROR_BAD_BITS                          0x00D3L             // �������Կλ��

#define SES_ERROR_RU_BAD_DATA_LENGTH       					0x00F0L             // ������������ݳ���
#define SES_ERROR_RU_FAILED                					0x00F1L             // ����ʧ��
#define SES_ERROR_RU_BAD_STATE             					0x00F2L             // �����Զ������״̬��û�г�ʼ����
#define SES_ERROR_RU_KEY_NOT_ENABLE        					0x00F3L             // û������Զ��������Կ
#define SES_ERROR_RU_UNSUPPORTED_OBJTYPE						0x00F4L							// ��֧�ֵ���������
#define SES_ERROR_RU_BLOCK_LENGTH										0x00F5L							// ���ݿ鳤�ȴ���

#define SES_ERROR_CERT_FORMAT												0x0140L							// ֤���ʽ����ȷ
#define SES_ERROR_CERT_VALIDITY											0x0141L							// ֤�鲻����Ч����
#define SES_ERROR_CERT_UNSUPPORTED_ALGO							0x0142L							// ��֧�ֵ�֤���㷨
#define SES_ERROR_CERT_SIGNATURE										0x0143L							// ֤��ǩ������
#define SES_ERROR_CERT_UNKNOWN_OID									0x0144L							// ��ʶ���OID
#define SES_ERROR_CERT_UNSUPPORTED_NAMESTRING				0x0145L					// ��֧�ֵ������ַ�������

#define SES_ERROR_CERT_NOT_SPEC_CERT								0x0146L							// ������ϵ֤��
#define SES_ERROR_CERT_NOT_DEVICE_CERT							0x0147L							// �����豸֤��

#define SES_ERROR_SM_HEAP_CRUSHED                   0x0161L							// ϵͳ���쳣
#define SES_ERROR_SM_NOT_ENOUTH_MEMORY              0x0162L							// ���ڴ治��
#define SES_ERROR_SM_INVALID_HANDLE                 0x0163L							// �Ƿ����ڴ���
#define SES_ERROR_SM_OUT_OF_RANGE                   0x0164L							// �������ڴ淶Χ
#define SES_ERROR_SM_INVALID_LENGTH                 0x0165L             // �Ƿ����ڴ泤��
#define SES_ERROR_SM_ERR_TAB1_FULL                  0x0166L             // 1������
#define SES_ERROR_SM_ERR_INVALID_SLOT               0x0167L             // �Ƿ���slot
#define SES_ERROR_SM_ERR_INVALID_EXCHDATA           0x0168L             // �Ƿ��Ľ�������
#define SES_ERROR_SM_ERR_WRONG_VERSION              0x0169L             // �������ݰ汾����

#define SES_ERROR_LIC_NO_LIC							          0x8003L             // û�а󶨴���Ȩ
#define SES_ERROR_DEVELOPER_NOT_EXIST               0x8008L             // ��֧�ֵĿ�����
#define SES_ERROR_LIC_EMPTY_LIC                     0x800CL             // û�а��κ���Ȩ

#endif // _HEADER_H5SES_COMMON_H_
