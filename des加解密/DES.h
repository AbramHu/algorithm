

#ifndef _Included_jni_security_DES
#define _Included_jni_security_DES


#define KEY							"$k6d)*@8"   //密钥

class CDesCode
{
public:
	// 文件加密
	static int EncryptForFile(char *plainFile, char *keyStr,char *cipherFile);
	// 文件解密
	static int DecryptForFile(char *cipherFile, char *keyStr,char *plainFile);
	// 数据加密
	static int EncryptForByte(char *srcStr,  unsigned int size, char *keyStr, char *encodeStr);
	// 数据解密
	static int DecryptForByte(char *srcStr,  unsigned int size, char *keyStr, char *decodeStr);

};
#endif
