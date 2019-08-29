#ifndef _HEADER_H5SES_COMMON_H_
#define _HEADER_H5SES_COMMON_H_

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned long UINT32;

typedef char CHAR;
typedef unsigned long HANDLE;

// Error Code
#define SES_SUCCESS                                 0x0000L             // 成功
#define SES_ERROR_INSUFFICIENT_BUFFER               0x0003L             // 缓冲区大小不足

#define SES_ERROR_NO_SPACE                          0x0012L             // 空间已满
#define SES_ERROR_FILE_NOT_FOUND                    0x0014L             // 未找到指定文件
#define SES_ERROR_FILE_OUT_RANGE                    0x0016L             // 读写超出文件范围
#define SES_ERROR_FILE_EXIST                        0x0017L             // 文件已经存在(重名)
#define SES_ERROR_INVALID_FLAG                      0x001BL             // 非法的flag 设置文件属性时指定了错误的Flag
#define SES_ERROR_INVALID_FILE_TYPE                 0x001CL             // 非法的文件类型
#define SES_ERROR_WRITE_OFFSET_WRONG                0x001EL             // 写密钥文件时，偏移必须为0

#define SES_ERROR_OPEN_TOO_MANY                     0x0020L             // 同时打开的文件达到最大数量
#define SES_ERROR_INVALID_HANDLE                    0x0021L             // 非法的文件句柄
#define SES_ERROR_WRONG_FILE_NAME_LEN               0x0023L             // 错误的文件名称长度

#define SES_ERROR_INVALID_MEM_ADDR                  0x0048L             // 非法的内存地址
#define SES_ERROR_INVALID_MEM_LENGTH                0x0049L             // 非法的内存长度
#define SES_ERROR_SHAREMEM_OUT_RANGE                0x004EL             // 超出共享内存范围

#define SES_ERROR_BAD_DEVICE_INFO                   0x005FL             // 错误的设备信息

#define SES_ERROR_AES_LENGTH                        0x0070L             // AES算法输入长度错误
#define SES_ERROR_AES_MODE_UNSUPPORTED              0x0071L             // 不支持的AES算法模式
#define SES_ERROR_DES_LENGTH                        0x0078L             // DES算法输入长度错误
#define SES_ERROR_DES_MODE_UNSUPPORTED              0x0079L             // 不支持的DES算法模式

#define SES_ERROR_NO_PRIVILEGE                      0x0080L             // 没有权限访问

#define SES_ERROR_ECC_UNSUPPORTED_CURVE             0x00A0L             // 不支持的ECC曲线
#define SES_ERROR_ECC_SIGN                          0x00A1L             // ECDSA签名错误
#define SES_ERROR_ECC_VERIFY                        0x00A2L             // ECDSA签名验证错误

#define SES_ERROR_RSA_UNSUPPORTED_PAD_MODE          0x00A3L             // 不支持的RSA填充模式
#define SES_ERROR_RSA_UNSUPPORTED_ALGO              0x00A4L 			// 不支持的RSA算法位数
#define SES_ERROR_RSA_LENGTH                        0x00A5L 			// RSA算法输入长度错误
#define SES_ERROR_RSA_BAD_KEY                       0x00A6L 		    // 错误的RSA密钥
#define SES_ERROR_RSA_BAD_DATA                      0x00A7L 			// RSA输入数据错误
#define SES_ERROR_RSA_SIGN                          0x00A8L 		    // RSA签名错误
#define SES_ERROR_RSA_VERYIFY                       0x00A9L 		    // RSA签名验证错误

#define SES_ERROR_UNSUPPORTED_HASH_ALGO       	    0x00B0L             // 不支持的哈希算法

#define SES_ERROR_BAD_PRIVATE_KEY                   0x00C0L             // 错误的私钥编码
#define SES_ERROR_BAD_PUBLIC_KEY                    0x00C1L             // 错误的公钥编码
#define SES_ERROR_BAD_SYMMETRIC_KEY                 0x00C2L		        // 错误的对称密钥编码
#define SES_ERROR_BAD_SIGNATURE                     0x00C3L		        // 错误的签名编码

#define SES_ERROR_BAD_ALGO                          0x00D0L	            // 错误的密钥算法
#define SES_ERROR_BAD_VERSION                       0x00D1L             // 错误的密钥格式版本
#define SES_ERROR_BAD_TYPE                          0x00D2L             // 错误的密钥类型
#define SES_ERROR_BAD_BITS                          0x00D3L             // 错误的密钥位数

#define SES_ERROR_RU_BAD_DATA_LENGTH       					0x00F0L             // 错误的升级数据长度
#define SES_ERROR_RU_FAILED                					0x00F1L             // 升级失败
#define SES_ERROR_RU_BAD_STATE             					0x00F2L             // 错误的远程升级状态（没有初始化）
#define SES_ERROR_RU_KEY_NOT_ENABLE        					0x00F3L             // 没有启用远程升级密钥
#define SES_ERROR_RU_UNSUPPORTED_OBJTYPE						0x00F4L							// 不支持的升级对象
#define SES_ERROR_RU_BLOCK_LENGTH										0x00F5L							// 数据块长度错误

#define SES_ERROR_CERT_FORMAT												0x0140L							// 证书格式不正确
#define SES_ERROR_CERT_VALIDITY											0x0141L							// 证书不在有效期内
#define SES_ERROR_CERT_UNSUPPORTED_ALGO							0x0142L							// 不支持的证书算法
#define SES_ERROR_CERT_SIGNATURE										0x0143L							// 证书签名错误
#define SES_ERROR_CERT_UNKNOWN_OID									0x0144L							// 不识别的OID
#define SES_ERROR_CERT_UNSUPPORTED_NAMESTRING				0x0145L					// 不支持的名称字符串类型

#define SES_ERROR_CERT_NOT_SPEC_CERT								0x0146L							// 不是体系证书
#define SES_ERROR_CERT_NOT_DEVICE_CERT							0x0147L							// 不是设备证书

#define SES_ERROR_SM_HEAP_CRUSHED                   0x0161L							// 系统堆异常
#define SES_ERROR_SM_NOT_ENOUTH_MEMORY              0x0162L							// 堆内存不足
#define SES_ERROR_SM_INVALID_HANDLE                 0x0163L							// 非法堆内存句柄
#define SES_ERROR_SM_OUT_OF_RANGE                   0x0164L							// 超出堆内存范围
#define SES_ERROR_SM_INVALID_LENGTH                 0x0165L             // 非法的内存长度
#define SES_ERROR_SM_ERR_TAB1_FULL                  0x0166L             // 1级表满
#define SES_ERROR_SM_ERR_INVALID_SLOT               0x0167L             // 非法¨slot
#define SES_ERROR_SM_ERR_INVALID_EXCHDATA           0x0168L             // 非法的交换数据
#define SES_ERROR_SM_ERR_WRONG_VERSION              0x0169L             // 交换数据版本错误

#define SES_ERROR_LIC_NO_LIC							          0x8003L             // 没有绑定此授权
#define SES_ERROR_DEVELOPER_NOT_EXIST               0x8008L             // 不支持的开发商
#define SES_ERROR_LIC_EMPTY_LIC                     0x800CL             // 没有绑定任何授权

#endif // _HEADER_H5SES_COMMON_H_
